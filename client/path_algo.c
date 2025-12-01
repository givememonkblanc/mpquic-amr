#include "path_algo.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>

/* ---- 브랜치 차 가드 ---- */
#ifndef HAS_SET_DEFAULT_PATH
#define picoquic_set_default_path(cnx, pth) ((void)(cnx),(void)(pth),0)
#endif
#ifndef HAS_RETIRE_CID
#define picoquic_retire_connection_id(cnx, cid_seq) ((void)(cnx),(void)(cid_seq),0)
#endif

#ifndef PATH_ALGO_TAG
#define PATH_ALGO_TAG "PATH_ALGO v1 " __DATE__ " " __TIME__
#endif

/* ===== 파라미터 ===== */
#define MAX_PATHS 8
#define ACTIVE_PROBE_RATIO           0.02   /* 평시 Wi-Fi 워밍업 전송 비율 */
#define MIGRATE_IMPROVE_FACTOR       1.25   /* 스코어 개선 배율(이상일 때만 선제 전환) */
#define MIGRATE_UNDER_TARGET_FACTOR  0.80   /* 프라이머리 전달율이 타깃의 80% 미만이면 열화 */
#define MIGRATE_MIN_HOLD_US          800000 /* 열화 지속 최소 시간(마진) */
#define TARGET_APP_Mbps              45.0   /* 앱이 요구하는 목표 Mbps */
#define DUALSEND_US                  1000000/* 전환 직후 중복 전송 윈도우 */
#define DUALSEND_DUP_RATIO           0.25   /* 윈도우 내 중복 전송 확률 */
#define DRAIN_TIMEOUT_US             2000000/* 드레인 최대 대기 */
#define NO_ACK_DEADLINE_US           4000000/* ACK 무응답이면 죽은 경로로 간주 */
#define ACTIVE_PROBE_INTERVAL_US     1500000/* Wi-Fi 워밍업 간격 */

/* ===== 로깅/디버그 ===== */
static int PATH_DEBUG = -1;
static void dbg_log(const char* tag, const char* fmt, ...) {
    if (PATH_DEBUG != 1) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[PATHDBG] %s: ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
#ifndef DBG
#define DBG(fmt, ...)  do{ if (PATH_DEBUG==1) fprintf(stderr, "[PATH] " fmt "\n", ##__VA_ARGS__); }while(0)
#endif
#ifndef ERR
#define ERR(fmt, ...)  fprintf(stderr, "[PATH-ERR] " fmt "\n", ##__VA_ARGS__)
#endif

/* ===== 내부 타입 ===== */
typedef enum {
    PATH_DISABLED = 0,
    PATH_CANDIDATE,
    PATH_PRIMARY,
    PATH_SECONDARY,
    PATH_ACTIVE_PROBING,
    PATH_DRAINING,
    PATH_DELETED
} path_state_t;

typedef struct {
    picoquic_path_t* p;
    int     valid;
    int     is_wifi;
    uint8_t cid_seq;
    char    ifname[16];
    path_state_t state;

    double   rtt_ms_ema;
    double   loss_ewma;
    double   dr_bps_ewma;
    double   weight;
    double   score;
    uint64_t inflight_bytes;
    uint64_t last_rx_ack_us;
    uint64_t last_probe_us;
    uint64_t drain_deadline_us;
    uint64_t tx_selects;
} path_slot_t;

typedef struct {
    int inited;
    int wt_ready_once;
    int data_stream_once;
    int migrating;
    int primary_idx;
    uint64_t degrade_since_us;
    uint64_t dualsend_until_us;
    uint64_t last_switch_us;
    path_slot_t slots[MAX_PATHS];
} path_algo_state_t;

/* ===== 내부 유틸 ===== */
static inline double ema(double prev, double now, double a){
    if (now <= 0.0) return prev;
    return (prev <= 0.0) ? now : prev*(1.0 - a) + now*a;
}

static path_algo_state_t* state(app_ctx_t* app) {
    if (!app) return NULL;
    if (!app->path_algo) {
        app->path_algo = calloc(1, sizeof(path_algo_state_t));
    }
    return (path_algo_state_t*)app->path_algo;
}

static void bump_tx_select(path_algo_state_t* st, picoquic_path_t* p){
    if (!st || !p) return;
    for (int i=0;i<MAX_PATHS;i++){
        if (st->slots[i].valid && st->slots[i].p == p){
            st->slots[i].tx_selects++;
            return;
        }
    }
}

static int find_slot_by_path(path_algo_state_t* st, picoquic_path_t* p) {
    if (!st || !p) return -1;
    for (int i=0;i<MAX_PATHS;i++)
        if (st->slots[i].valid && st->slots[i].p == p) return i;
    return -1;
}

static int find_wifi_idx(path_algo_state_t* st) {
    if (!st) return -1;
    for (int i=0;i<MAX_PATHS;i++)
        if (st->slots[i].valid && st->slots[i].is_wifi &&
            st->slots[i].state!=PATH_DELETED && st->slots[i].state!=PATH_DISABLED)
            return i;
    return -1;
}

/* primary 캐시 보정 + 유효 인덱스 반환 */
static int ensure_primary_idx(path_algo_state_t* st) {
    if (!st) return -1;

    if (st->primary_idx>=0 && st->primary_idx<MAX_PATHS) {
        path_slot_t* s = &st->slots[st->primary_idx];
        if (s->valid && s->state!=PATH_DELETED && s->state!=PATH_DISABLED) {
            s->state = PATH_PRIMARY;
            return st->primary_idx;
        }
    }
    for (int i=0;i<MAX_PATHS;i++) {
        path_slot_t* s = &st->slots[i];
        if (s->valid && s->state==PATH_PRIMARY) {
            st->primary_idx = i;
            return i;
        }
    }
    for (int i=0;i<MAX_PATHS;i++) {
        path_slot_t* s = &st->slots[i];
        if (s->valid && !s->is_wifi && s->state!=PATH_DELETED && s->state!=PATH_DISABLED) {
            s->state = PATH_PRIMARY;
            st->primary_idx = i;
            return i;
        }
    }
    for (int i=0;i<MAX_PATHS;i++) {
        path_slot_t* s = &st->slots[i];
        if (s->valid && s->state!=PATH_DELETED && s->state!=PATH_DISABLED) {
            s->state = PATH_PRIMARY;
            st->primary_idx = i;
            return i;
        }
    }
    st->primary_idx = -1;
    return -1;
}

static void make_primary(path_algo_state_t* st, int idx) {
    if (!st || idx<0 || idx>=MAX_PATHS) return;
    for (int i=0;i<MAX_PATHS;i++) if (st->slots[i].state==PATH_PRIMARY) st->slots[i].state=PATH_SECONDARY;
    st->primary_idx = idx;
    st->slots[idx].state = PATH_PRIMARY;
}

/* ===== Public 구현 ===== */

void path_algo_init(app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st) return;
    memset(st, 0, sizeof(*st));
    st->inited = 1;
    st->primary_idx = -1;

    if (PATH_DEBUG < 0) {
        const char* e = getenv("PATH_DEBUG");
        PATH_DEBUG = (e && *e=='1') ? 1 : 0;
    }
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(ts.tv_nsec ^ ts.tv_sec));

    fprintf(stderr, "%s (linked)\n", PATH_ALGO_TAG);
    dbg_log("init", "ACTIVE_PROBE_RATIO=%.3f", (double)ACTIVE_PROBE_RATIO);
}

void path_algo_on_wt_ready(picoquic_cnx_t* cnx, app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited || st->wt_ready_once) return;
    st->wt_ready_once = 1;
    (void)cnx;
    DBG("WT ready once");
}

void path_algo_on_first_data_stream(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t stream_id) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited || st->data_stream_once) return;
    st->data_stream_once = 1;
    (void)cnx; (void)stream_id;
    DBG("first data stream observed");
}

void path_algo_on_path_created(picoquic_cnx_t* cnx, app_ctx_t* app,
                               picoquic_path_t* p, const char* ifname,
                               bool is_wifi, uint8_t cid_seq)
{
    path_algo_state_t* st = state(app);
    if (!st || !p) return;

    int i=-1; for (int k=0;k<MAX_PATHS;k++) if (!st->slots[k].valid){ i=k; break; }
    if (i<0) { ERR("no free slot"); return; }

    path_slot_t* s = &st->slots[i];
    memset(s, 0, sizeof(*s));
    s->p = p;
    s->is_wifi = is_wifi;
    s->cid_seq = cid_seq;
    s->state = PATH_CANDIDATE;
    s->valid = 1;

    if (ifname && *ifname) {
        strncpy(s->ifname, ifname, sizeof(s->ifname)-1);
        s->ifname[sizeof(s->ifname)-1] = '\0';
        if (strstr(ifname, "wlan") || strstr(ifname, "wifi")) s->is_wifi = 1;
        if (strstr(ifname, "eth")) s->is_wifi = 0;
    } else {
        s->ifname[0] = '\0';
    }

    if (!s->is_wifi) {
        make_primary(st, i);
        (void)picoquic_set_default_path(cnx, p);
        dbg_log("created", "PRIMARY on %s (cid=%u, slot=%d)", s->ifname, s->cid_seq, i);
    } else {
        s->state = PATH_ACTIVE_PROBING;  /* Warm-Standby */
        s->last_probe_us = 0;
        dbg_log("created", "WIFI Warm-Standby on %s (cid=%u, slot=%d)", s->ifname, s->cid_seq, i);
    }
}

void path_algo_on_metrics(app_ctx_t* app, picoquic_path_t* p,
                          double rtt_ms, double loss, double delivery_bps,
                          uint64_t inflight_bytes, uint64_t now_us)
{
    path_algo_state_t* st = state(app);
    if (!st) return;
    int i = find_slot_by_path(st, p);
    if (i<0) return;
    path_slot_t* s = &st->slots[i];

    s->rtt_ms_ema  = ema(s->rtt_ms_ema,  rtt_ms,        0.2);
    s->loss_ewma   = ema(s->loss_ewma,   loss,          0.2);
    s->dr_bps_ewma = ema(s->dr_bps_ewma, delivery_bps,  0.2);
    s->inflight_bytes = inflight_bytes;

    if (rtt_ms > 0 || delivery_bps > 0) s->last_rx_ack_us = now_us;

    double rtt_eff  = (s->rtt_ms_ema  > 0 ? s->rtt_ms_ema  : 50.0);
    double loss_eff = (s->loss_ewma   > 0 ? s->loss_ewma   : 0.0);

    double mbps   = s->dr_bps_ewma / 1e6;
    double under  = (mbps < TARGET_APP_Mbps) ? (TARGET_APP_Mbps - mbps) : 0.0;
    s->score = rtt_eff + (loss_eff * 400.0) + (under * 80.0);
}

void path_algo_on_wifi_moved(app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st) return;
    int wi = find_wifi_idx(st);
    if (wi<0) return;
    path_slot_t* w = &st->slots[wi];
    if (!w->valid || w->state==PATH_DELETED) return;

    w->state = PATH_DRAINING;
    w->drain_deadline_us = 0;
    DBG("wifi moved -> DRAINING (if=%s)", w->ifname);
}

void path_algo_probe_once(picoquic_cnx_t* cnx, app_ctx_t* app) {
    (void)cnx; (void)app;
}

void path_algo_tick(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t now_usec) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited) return;

    /* Wi-Fi 드레이닝/워밍업 */
    int wi = find_wifi_idx(st);
    if (wi>=0) {
        path_slot_t* w = &st->slots[wi];

        if (w->state==PATH_DRAINING) {
            if (w->drain_deadline_us==0) w->drain_deadline_us = now_usec + DRAIN_TIMEOUT_US;
            int drained = (w->inflight_bytes==0) || (now_usec >= w->drain_deadline_us);
            if (drained) {
                picoquic_retire_connection_id(cnx, w->cid_seq);
                w->state = PATH_DELETED;
                w->valid = 0;
                DBG("Wi-Fi retired (cid=%u, if=%s)", w->cid_seq, w->ifname);
            }
        } else if (w->state==PATH_ACTIVE_PROBING) {
            if (w->last_probe_us==0 || now_usec - w->last_probe_us >= ACTIVE_PROBE_INTERVAL_US) {
                w->last_probe_us = now_usec;
                DBG("schedule WiFi probe if=%s", w->ifname);
            }
            if (w->last_rx_ack_us>0 && now_usec - w->last_rx_ack_us > NO_ACK_DEADLINE_US) {
                w->state = PATH_DRAINING;
                w->drain_deadline_us = now_usec + DRAIN_TIMEOUT_US;
                DBG("Wi-Fi NO_ACK -> DRAINING (if=%s)", w->ifname);
            }
        }
    }

    /* Primary 앵커 유지 */
    int pi = ensure_primary_idx(st);
    if (pi>=0) {
        st->primary_idx = pi;
        st->slots[pi].state = PATH_PRIMARY;
        (void)picoquic_set_default_path(cnx, st->slots[pi].p);
    }

    /* 선제 전환 판단 */
    if (pi>=0 && wi>=0) {
        path_slot_t* pr = &st->slots[pi];
        path_slot_t* wb = &st->slots[wi];

        double pr_mbps = pr->dr_bps_ewma / 1e6;
        int pr_under = (pr_mbps < TARGET_APP_Mbps * MIGRATE_UNDER_TARGET_FACTOR);
        int wb_valid = (wb->valid && wb->state!=PATH_DELETED);
        int wb_better = (wb_valid && wb->score>0 && pr->score>0 &&
                         (pr->score / wb->score) >= MIGRATE_IMPROVE_FACTOR);

        if (pr_under && wb_better) {
            if (st->degrade_since_us==0) st->degrade_since_us = now_usec;
            if (!st->migrating && (now_usec - st->degrade_since_us) >= MIGRATE_MIN_HOLD_US) {
                make_primary(st, wi);
                (void)picoquic_set_default_path(cnx, wb->p);
                st->migrating = 1;
                st->dualsend_until_us = now_usec + DUALSEND_US;
                st->last_switch_us = now_usec;
                DBG("Preemptive migrate: Wi-Fi -> PRIMARY (if=%s)", wb->ifname);
            }
        } else {
            st->degrade_since_us = 0;
        }
    }

    if (st->migrating && now_usec >= st->dualsend_until_us) {
        st->migrating = 0;
    }
}

/* 라벨/속성 */
static int _path_is_wifi_from_slots(path_algo_state_t* st, picoquic_path_t* p){
    if (!st || !p) return 0;
    for (int i=0;i<MAX_PATHS;i++)
        if (st->slots[i].valid && st->slots[i].p == p)
            return st->slots[i].is_wifi ? 1 : 0;
    return 0;
}
int path_is_wifi(app_ctx_t* app, picoquic_path_t* p){
    path_algo_state_t* st = state(app);
    return _path_is_wifi_from_slots(st, p);
}
const char* path_label(app_ctx_t* app, picoquic_path_t* p){
    return path_is_wifi(app, p) ? "WiFi" : "LAN";
}

/* 경로 선택(송신 직전): PRIMARY 유지 + Wi-Fi 워밍업 소량 선택 */
picoquic_path_t* path_algo_choose_path(app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited) return NULL;

    int pi = ensure_primary_idx(st);
    picoquic_path_t* primary = (pi>=0)? st->slots[pi].p : NULL;

    int wi = find_wifi_idx(st);
    if (wi>=0) {
        path_slot_t* w = &st->slots[wi];
        if (w->state==PATH_ACTIVE_PROBING && ACTIVE_PROBE_RATIO > 0.0) {
            double r = (double)rand() / (double)RAND_MAX;
            if (r < ACTIVE_PROBE_RATIO) {
                bump_tx_select(st, w->p);
                dbg_log("choose", "WiFi PROBE select if=%s ratio=%.3f", w->ifname, (double)ACTIVE_PROBE_RATIO);
                return w->p;
            }
        }
    }

    if (primary) {
        bump_tx_select(st, primary);
        dbg_log("choose", "PRIMARY selected");
        return primary;
    }

    for (int i=0;i<MAX_PATHS;i++) {
        if (st->slots[i].valid && st->slots[i].state!=PATH_DELETED && st->slots[i].state!=PATH_DISABLED) {
            bump_tx_select(st, st->slots[i].p);
            dbg_log("choose", "FALLBACK selected if=%s", st->slots[i].ifname);
            return st->slots[i].p;
        }
    }
    return NULL;
}

/* 전환 창에서 중복 전송 */
int path_algo_wants_dup_now(app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited) return 0;
    if (!st->migrating) return 0;
    double r = (double)rand() / (double)RAND_MAX;
    return (r < DUALSEND_DUP_RATIO) ? 1 : 0;
}
picoquic_path_t* path_algo_get_dup_target(app_ctx_t* app) {
    path_algo_state_t* st = state(app);
    if (!st || !st->inited) return NULL;
    int pi = ensure_primary_idx(st);
    for (int i=0;i<MAX_PATHS;i++) {
        if (!st->slots[i].valid) continue;
        if (i==pi) continue;
        if (st->slots[i].state==PATH_DELETED || st->slots[i].state==PATH_DISABLED) continue;
        return st->slots[i].p;
    }
    return NULL;
}
