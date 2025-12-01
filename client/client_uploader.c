// client_uploader.c — picoquic raw-stream MP Uploader (Wi-Fi + Hotspot)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <pthread.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "qlog.h"
#include "picoquic_binlog.h"
#include "autoqlog.h"
#include "camera.h"   // camera_create, camera_capture_jpeg, camera_destroy
#include <sys/stat.h>
#include <sys/types.h>

static void ensure_dir(const char* path){
    if (!path || !*path) return;
    mkdir(path, 0777); /* 이미 있으면 조용히 실패 */
}
#define MTU_CHUNK    (16*1024)
#define ONE_SEC_US   1000000ULL

// ───────── 로그/유틸 ─────────
#define LOGF(fmt, ...)  fprintf(stderr, "[CLI] " fmt "\n", ##__VA_ARGS__)

/* ready/client_ready_start/server_false_start 등 포괄 */
static inline int cnx_is_ready_like(picoquic_cnx_t* c) {
    if (!c) return 0;
    picoquic_state_enum s = picoquic_get_cnx_state(c);
    if (s == picoquic_state_ready) return 1;
#ifdef picoquic_state_client_ready
    if (s == picoquic_state_client_ready) return 1;
#endif
#ifdef picoquic_state_client_ready_start
    if (s == picoquic_state_client_ready_start) return 1;
#endif
#ifdef picoquic_state_server_ready
    if (s == picoquic_state_server_ready) return 1;
#endif
#ifdef picoquic_state_server_false_start
    if (s == picoquic_state_server_false_start) return 1;
#endif
    return 0;
}

/* 1-RTT AEAD 키 존재 여부(가능하면 내부 필드 이름 맞춰서) */
static inline int cnx_has_1rtt_keys(picoquic_cnx_t* c) {
#ifdef crypto_context
    return c && (c->crypto_context[picoquic_epoch_1rtt].aead_encrypt != NULL);
#else
    /* 내부 구조체 접근이 안 되면 상태로만 판단 */
    return cnx_is_ready_like(c);
#endif
}
static inline picoquic_path_t* px_get_path(picoquic_cnx_t* c, int i) {
#if defined(HAVE_PICOQUIC_GET_PATH) /* 네 프로젝트에서 정의해도 됨 */
    return picoquic_get_path(c, i);
#else
    return (c && i >= 0 && i < (int)c->nb_paths) ? c->path[i] : NULL; /* 내부필드 직접 접근 */
#endif
}



static const char* cbmode_str(picoquic_packet_loop_cb_enum m){
    switch(m){
        case picoquic_packet_loop_ready:         return "ready";
        case picoquic_packet_loop_after_receive: return "after_recv";
        case picoquic_packet_loop_after_send:    return "after_send";
        case picoquic_packet_loop_wake_up:       return "wake_up";
        default:                                  return "other";
    }
}


__attribute__((unused))
static void print_sockaddr(const char* tag, const struct sockaddr* sa){
    char buf[128] = {0};
    uint16_t port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* v4 = (const struct sockaddr_in*)sa;
        inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf));
        port = ntohs(v4->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* v6 = (const struct sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf));
        port = ntohs(v6->sin6_port);
    } else {
        snprintf(buf, sizeof(buf), "fam=%d", sa->sa_family);
    }
    LOGF("%s: %s:%u", tag, buf, port);
}
__attribute__((unused))
static int sockaddr_equal(const struct sockaddr* a, const struct sockaddr* b){
    if (a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in* x = (const struct sockaddr_in*)a;
        const struct sockaddr_in* y = (const struct sockaddr_in*)b;
        return x->sin_addr.s_addr == y->sin_addr.s_addr && x->sin_port == y->sin_port;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6* x = (const struct sockaddr_in6*)a;
        const struct sockaddr_in6* y = (const struct sockaddr_in6*)b;
        return (memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0) &&
               (x->sin6_port == y->sin6_port);
    }
    return 0;
}

// ───────── 상태/헬퍼 ─────────
#ifdef HAVE_CAMERA_H
#include "camera.h"
#endif

/* camera_handle_t 가 아직 안 보인다면 안전한 전방선언(임시) */

typedef struct { uint64_t sid; int ready; } bind_t;
#ifndef MAX_PATHS
#define MAX_PATHS 16
#endif

typedef struct {
    bind_t b[MAX_PATHS];            /* 경로별 바인딩/상태 */

    picoquic_cnx_t* cnx;

    int peer_close_seen;            /* peer close 기록 (조기 종료 방지) */

    /* Path A (기본 서버 주소) */
    struct sockaddr_storage peerA;
    int hasA;

    /* Path B (동일 서버여도 OK; 로컬 소스만 다르면 새 경로) */
    struct sockaddr_storage peerB;
    int hasB;

    /* 보조 NIC의 로컬 소스 주소(예: wlan0) */
    struct sockaddr_storage local_alt;
    int has_local_alt;

    struct sockaddr_storage local_usb;
    int has_local_usb;  // usb0
    int didA, didB, didC;
    int is_ready, closing;

    uint64_t ready_ts_us;
    uint64_t last_keepalive_us;
    uint64_t seq;

    size_t   frame_bytes;
    int      rr;
    uint64_t send_interval_us;

    /* 카메라 캡처 버퍼 (TX용) */
    camera_handle_t cam;
    size_t   cap_cap;
    size_t   pending_off;           /* 초기 0 */
    int      last_pi;               /* 초기 -1 */
    uint8_t* cap_buf;

    /* 프레임 길이 varint 인코딩용 버퍼 */
    uint8_t  lenb[8];

    /* ★ 경로별 전용 스트림 ID (0이면 아직 미개설) */
    uint64_t sid_per_path[MAX_PATHS];
    uint32_t primary_local_ip; /* 네트워크 바이트오더(=inet_addr 결과) */

    /* ===== 카메라 전용 스레드/공유 버퍼 ===== */
    pthread_t       cam_thread;
    pthread_mutex_t cam_mtx;
    int             cam_thread_started;
    int             cam_stop;       /* 1이면 스레드 종료 */

    uint8_t*  cam_buf;              /* 캡처 스레드가 쓰는 버퍼 */
    size_t    cam_cap;              /* cam_buf capacity */
    int       cam_len;              /* 마지막 캡처된 프레임 길이 */
    uint64_t  cam_seq;              /* 프레임 시퀀스 번호 */
    uint64_t  last_sent_seq;        /* loop_cb에서 마지막으로 보낸 seq */
    uint64_t hs_done_ts;   /* handshake 완료 timestamp */
    int last_primary_idx;
    uint64_t last_switch_ts;
    uint32_t ip_wlan_be;
    uint32_t ip_usb_be;
    int last_verified;

} tx_t;

typedef struct {
    int idx;
    int sid;
    picoquic_path_t* p;
    uint32_t ip_be;
    uint64_t rtt;
    uint64_t loss;
    uint64_t delivered;
} pathsel_t;

static int pick_primary_idx(
    picoquic_cnx_t* c,
    pathsel_t* sel, int sc,
    uint32_t ip_wlan_be,
    uint32_t ip_lte_be,
    int* last_primary,
    uint64_t now,
    uint64_t* last_switch_time);


static void on_cb_event(picoquic_call_back_event_t ev, tx_t* st, picoquic_cnx_t* cnx)
{
    (void)cnx;

    switch (ev) {
    case picoquic_callback_ready:
        st->is_ready = 1;
        st->ready_ts_us = picoquic_current_time();
        st->hs_done_ts = picoquic_current_time();
        LOGF("[CB] handshake complete → ready");
        break;

    case picoquic_callback_close:
    case picoquic_callback_application_close:
        // ❌ 예전: st->closing = 1;  // ← 이게 조기 종료 유발
        // ✔️ 바꿈: 일단 기록만 하고 무시 (테스트/검증 완료 전엔 절대 닫지 않음)
        st->peer_close_seen = 1;   // 필요 시 상태만 기록 (루프는 종료하지 않음)
        LOGF("[CB] closing (IGNORED for test; keeping loop alive)");
        break;

    default:
        break;
    }
}

static inline int verified(picoquic_cnx_t* c, int i){
    if(!c || i<0 || i>= (int)c->nb_paths) return 0;
    picoquic_path_t* p = px_get_path(c, i);               // ← 변경
    return (p && p->first_tuple && p->first_tuple->challenge_verified);
}
static inline void wait_pace(picoquic_cnx_t* c, picoquic_path_t* p){
    if(!c || !p) return;
    uint64_t now=picoquic_current_time(), next=now;
    while(!picoquic_is_sending_authorized_by_pacing(c,p,now,&next)){
        if(next>now){
            useconds_t us = (useconds_t)(next-now);
            if(us>0) usleep(us);
        }
        now=picoquic_current_time();
    }
}

static size_t varint_enc(uint64_t v, uint8_t* o){
    if(v < (1ull<<6))   { o[0] = (uint8_t)v; return 1; }
    if(v < (1ull<<14))  { o[0]=0x40|(v>>8); o[1]=v; return 2; }
    if(v < (1ull<<30))  { o[0]=0x80|(v>>24); o[1]=v>>16; o[2]=v>>8; o[3]=v; return 4; }
    o[0]=0xC0|(v>>56); o[1]=v>>48; o[2]=v>>40; o[3]=v>>32;
    o[4]=v>>24; o[5]=v>>16; o[6]=v>>8; o[7]=v; return 8;
}

static int resolve_ip(const char* host, int port, struct sockaddr_storage* out){
    if (!host || !out) return -1;
    char port_s[16]; snprintf(port_s, sizeof(port_s), "%d", port);
    struct addrinfo hints, *ai=NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    int r = getaddrinfo(host, port_s, &hints, &ai);
    if (r != 0 || !ai) return -1;
    memcpy(out, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    return 0;
}

static int ensure_bind(picoquic_cnx_t* c, tx_t* st, int i){
    if(!c || !st) return -1;
    if(!verified(c,i)) return -1;
    if(st->b[i].ready) return 0;

    uint64_t sid = picoquic_get_next_local_stream_id(c, /*unidir=*/1);
    picoquic_path_t* path = px_get_path(c, i);
    if(!path) return -1;

    picoquic_set_stream_path_affinity(c, sid, path->unique_path_id);
    st->b[i].sid = sid;
    st->b[i].ready = 1;
    LOGF("bind: path[%d] uid=%" PRIu64 " -> sid=%" PRIu64, i, path->unique_path_id, sid);
    return 0;
}

static const char* FORBID_LOCAL_IP = "192.168.0.5";  // 절대 쓰지 않을 eth0 IP
static int str_to_sockaddr4(const char* ip, struct sockaddr_in* out){
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1 ? 0 : -1;
}

static int path_is_local_ip(const picoquic_path_t* p, const char* ip4){
    if (!p || !p->first_tuple || !ip4) return 0;

    struct sockaddr_in ban;
    if (str_to_sockaddr4(ip4, &ban) != 0) return 0;

    /* local_addr가 sockaddr_storage 여서 &로 주소를 취한다 */
    const struct sockaddr* la =
        (const struct sockaddr*)&p->first_tuple->local_addr;

    if (!la || la->sa_family != AF_INET) return 0;

    const struct sockaddr_in* la4 = (const struct sockaddr_in*)la;
    return la4->sin_addr.s_addr == ban.sin_addr.s_addr;
}

static int pick_rr(picoquic_cnx_t* c, int* rr){
    if(!c || !rr) return -1;
    int n=(int)c->nb_paths; if(n<=0) return -1;
    for(int k=0;k<n;k++){
        *rr = (*rr + 1) % n;
        if(verified(c,*rr)) return *rr;
    }
    return -1;
}

static int client_cb(picoquic_cnx_t* cnx, uint64_t stream_id,
                     uint8_t* bytes, size_t length,
                     picoquic_call_back_event_t ev, void* ctx,
                     void* stream_ctx)
{
    (void)stream_id; (void)bytes; (void)length; (void)stream_ctx;
    tx_t* st = (tx_t*)ctx;
    if (st) on_cb_event(ev, st, cnx);
    return 0;
}

static int store_local_ip(const char* ip, uint16_t port, struct sockaddr_storage* out) {
    if (!ip || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct in_addr v4;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        struct sockaddr_in* sa = (struct sockaddr_in*)out;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = v4;
        return 0;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)out;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        sa6->sin6_addr = v6;
        return 0;
    }
    return -1; // not an IP literal
}

static inline int hs_done(picoquic_cnx_t* cnx) {
    if (!cnx) return 0;

    /* 1) 가장 확실한 상태값: ready 계열 */
    picoquic_state_enum s = picoquic_get_cnx_state(cnx);
    if (s == picoquic_state_client_ready_start || s == picoquic_state_ready)
        return 1;

    /* 2) 구버전/과도기 대비: 플래그 기반 보수적 판정
       - 초기/핸드셰이크 암호화 컨텍스트 work 끝났고
       - 1-RTT 패킷을 한 번이라도 받았거나(키 존재), 혹은 우리가 보낸 1-RTT가 ACK 됐을 때 */
    if (cnx->is_handshake_finished && (cnx->is_1rtt_received || cnx->is_1rtt_acked))
        return 1;

    /* 3) (선택) 더 보수적으로 가려면 peer가 HANDSHAKE_DONE을 ack한 뒤에만 허용
       if (cnx->is_handshake_done_acked) return 1; */

    return 0;
}

/* 전송 직전에 기본 경로를 해당 path로 전환 */
static inline void use_path(picoquic_cnx_t* c, picoquic_path_t* p){
    static picoquic_path_t* last = NULL;
    if (p && p != last){
        //picoquic_set_default_path(c, p);
        last = p;
    }
}

/* (권장) 경로별 고유 uni-stream sid = 2 + 4*i */
static inline uint64_t make_client_uni_sid_from_index(int i){
    return 2ull + 4ull * (uint64_t)i;
}

/* 경로 i용 스트림을 실제로 열어둔다(0바이트는 드롭될 수 있으니 1바이트 송신) */
int ensure_stream_for_path(picoquic_cnx_t* c, void* app_ctx,
                           uint64_t* p_sid, int path_idx)
{
    if (!p_sid) return -1;

    /* 스트림이 아직 없으면 새로 만듦 */
    if (*p_sid == 0) {
        *p_sid = make_client_uni_sid_from_index(path_idx);
    }

    picoquic_path_t* p = c->path[path_idx];
    if (!p) return -1;

    /* ★★★ 첫 패킷 보내기 전에 affinity 설정 ★★★ */
    picoquic_set_stream_path_affinity(c, *p_sid, p->unique_path_id);

    /* 더미 바이트라도 하나 보내서 path 활성화 */
    uint8_t dummy = 0xEE;
    return picoquic_add_to_stream_with_ctx(c, *p_sid, &dummy, 1, 0, app_ctx);
}

static inline int path_verified_idx(picoquic_cnx_t* c, int i){
    if (!c || i < 0 || i >= c->nb_paths) return 0;
    picoquic_path_t* p = c->path[i];
    if (!p) return 0;

    /* 0) 최소 준비물: 튜플 존재 */
    if (p->first_tuple == NULL) return 0;

    /* 1) 증폭 완화: 초기 경로 검증이 끝났는지(연결 레벨) */
    if (!c->initial_validated) return 0;

    /* 2) RTT나 수신 흔적이 있어야 "살아있다" 가정 */
    if (!p->rtt_is_initialized && p->last_packet_received_at == 0) return 0;

    /* 3) 비활성/폐기/강등 상태는 제외 */
    if (p->path_is_demoted) return 0;
    if (p->path_abandon_sent || p->path_abandon_received) return 0;

    /* 4) PTO 강제 탐침만 예정된 경로는 일단 제외(필요시 허용) */
    if (p->is_pto_required && p->bytes_in_transit == 0) {
        return 0;
    }

    return 1;
}
static inline int set_affinity_by_index(picoquic_cnx_t* c, uint64_t sid, int i){
    if (!c || i < 0 || i >= (int)c->nb_paths) return -1;
    picoquic_path_t* p = c->path[i];
    if (!p) return -1;
    /* picoquic_set_stream_path_affinity(c, stream_id, unique_path_id) */
    return picoquic_set_stream_path_affinity(c, sid, p->unique_path_id);
}
/* 포인터로 받는 버전도 필요하면 */
static inline int path_verified_ptr(picoquic_path_t* p){
    return (p && p->first_tuple && p->first_tuple->challenge_verified);
}

static int g_rr_idx = 0;  /* 다음 프레임에 사용할 시작 path 인덱스 */

static int pick_verified_rr(picoquic_cnx_t* c, int* rr_idx_io) {
    if (!c || c->nb_paths <= 0) return -1;
    int nb = c->nb_paths;
    int start = (rr_idx_io && *rr_idx_io >= 0) ? *rr_idx_io : 0;
    for (int k = 0; k < nb; k++) {
        int j = (start + k) % nb;
        picoquic_path_t* p = c->path[j];
        if (!p) continue;
        if (!path_verified_ptr(p)) continue;
        if (rr_idx_io) *rr_idx_io = j;
        return j;
    }
    return -1;
}
int path_is_bad(picoquic_path_t* p)
{
    if (!p) return 1;

    uint64_t rtt     = p->smoothed_rtt;
    uint64_t rtt_min = p->rtt_min;
    uint64_t bw      = p->receive_rate_estimate;

    if (bw < 50000) return 1;                 // 50KB/s 미만 = bad
    if (rtt > rtt_min * 13 / 10) return 1;    // RTT 30%만 올라가도 bad
    return 0;
}

static int path_is_recovered(picoquic_path_t* p)
{
    if (!p) return 0;

    if (p->rtt_is_initialized &&
        p->smoothed_rtt < p->rtt_min + 10000 && /* +10ms 이내 */
        p->delivered_last > 16384 &&            /* >16KB */
        p->nb_losses_found < 2 &&
        p->bandwidth_estimate > 200 * 1024) {   /* 200KB/s 이상 */
        return 1;
    }

    return 0;
}
/* ============================================================
 * Path Metrics 구조 및 계산 함수 (파일 상단에 배치할 것)
 * ============================================================ */

typedef struct {
    int grade;              // 0=GOOD, 1=WARN, 2=BAD
    uint64_t rtt;           // smoothed RTT
    double loss_rate;       // %
    double goodput;         // Mbps
    uint64_t score;           // smoothed RTT
    double rtt_ms;       // 추가
    double rtt_var_ms;   // (선택)
} path_metric_t;

static inline int path_sane_for_send(picoquic_cnx_t* c, int i) {
    if (!c || i < 0 || i >= (int)c->nb_paths) return 0;
    picoquic_path_t* p = c->path[i];
    if (!p || !p->first_tuple) return 0;

    /* 반드시 검증 끝난 경로만 사용 */
    if (!p->first_tuple->challenge_verified) return 0;

    /* 폐기/강등 상태는 피함 */
    if (p->path_abandon_sent || p->path_abandon_received) return 0;
    if (p->path_is_demoted) return 0;

    /* RTT/수신 힌트 하나도 없으면 skip (초기화 안 된 path 보호) */
    if (!p->rtt_is_initialized && p->last_packet_received_at == 0) return 0;

    return 1;
}


static inline path_metric_t compute_metric_safe(picoquic_path_t* p)
{
    path_metric_t M = {0};
    if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) {
        M.grade = 2; // 검증 전/무효 path는 BAD
        return M;
    }

    // RTT (usec → ms), EWMA
    double rtt_ms = (p->smoothed_rtt > 0 ? p->smoothed_rtt / 1000.0 : 9999.0);
    static double ewma[16] = {0};
    double a = 0.2;
    int pid = (int)(p->unique_path_id % 16);

    if (ewma[pid] < 0.5) ewma[pid] = rtt_ms;
    else ewma[pid] = a*rtt_ms + (1-a)*ewma[pid];

    M.rtt_ms = ewma[pid];

    // Loss (bytes 기준 → 단순 근사치)
    uint64_t delivered = (p->delivered > 0 ? p->delivered : 1);
    double loss_pct = 0.0;
    if (p->total_bytes_lost > 0 && p->total_bytes_lost < delivered)
        loss_pct = (double)p->total_bytes_lost * 100.0 / (double)delivered;
    else if (p->total_bytes_lost >= delivered)
        loss_pct = 50.0; // outlier 가드

    M.loss_rate = loss_pct;

    // 등급
    if (M.rtt_ms > 250.0 || M.loss_rate > 10.0)      M.grade = 2;
    else if (M.rtt_ms > 120.0 || M.loss_rate > 3.0)  M.grade = 1;
    else                                             M.grade = 0;

    return M;
}

static inline path_metric_t compute_metric(picoquic_path_t* p)
{
    path_metric_t M = {0};

    /* 0) 샘플 유효성: RTT 초기화 안됐으면 BAD 주지 말고 WARN */
    if (!p || !p->first_tuple || !p->rtt_is_initialized) {
        M.rtt_ms    = 999.0;
        M.loss_rate = 0.0;
        M.grade     = 1;   // WARN
        return M;
    }

    /* 1) RTT (usec → ms) + EWMA + 이상치 클램프 */
    double raw_ms = (p->smoothed_rtt > 0 ? p->smoothed_rtt / 1000.0 : 999.0);
    if (raw_ms < 0.1) raw_ms = 0.1;
    if (raw_ms > 2000.0) raw_ms = 2000.0;

    const int pid = p->unique_path_id % 16;
    static double ewma_ms[16] = {0};
    const double a = 0.2;

    if (ewma_ms[pid] < 0.1) ewma_ms[pid] = raw_ms;
    else                    ewma_ms[pid] = a*raw_ms + (1.0-a)*ewma_ms[pid];

    M.rtt_ms = ewma_ms[pid];

    /* 2) Loss: 사용할 수 있는 카운터가 없으면 0으로 두고 진행 */
    M.loss_rate = 0.0;

    /* 3) (선택) 용량/구현 필드가 있으면 보조 신호로 사용 */
    double mbps_hint = 0.0;
#if defined(HAVE_RECEIVE_RATE_ESTIMATE)
    if (p->receive_rate_estimate > 0) {
        mbps_hint = p->receive_rate_estimate / (1000.0 * 1000.0 * 8.0);
    }
#elif defined(HAVE_BANDWIDTH_ESTIMATE)
    if (p->bandwidth_estimate > 0) {
        mbps_hint = p->bandwidth_estimate / (1000.0 * 1000.0 * 8.0);
    }
#endif

    /* 4) Grade 규칙: 단순·보수적으로. RTT 우선, 필요시 용량 힌트로 BAD 업그레이드 */
    if (M.rtt_ms > 250.0) {
        M.grade = 2; // BAD
    } else if (M.rtt_ms > 120.0) {
        M.grade = 1; // WARN
    } else {
        M.grade = 0; // GOOD
    }

    /* 보조 패널티: RTT가 좋더라도 추정 대역폭이 너무 낮으면 WARN ↑ */
    if (M.grade < 2 && mbps_hint > 0.0 && mbps_hint < 1.0) {
        if (M.grade == 0) M.grade = 1;
    }

    return M;
}

static int fsm_pick(
    const path_metric_t* WLAN,
    const path_metric_t* USB,
    int wlan_id, int usb_id,
    int* last_primary,
    uint64_t now,
    uint64_t* last_switch_time
){
    /* Dwell (usec) */
    const uint64_t DWELL_FAILOVER = 200000;  // 200 ms
    const uint64_t DWELL_FAILBACK = 400000;  // 400 ms
    const double   RTT_MARGIN_MS  = 20.0;    // 스위칭 최소 이득

    int lp = *last_primary;
    uint64_t dt = now - *last_switch_time;

    /* 1) 초기: WLAN 선호 */
    if (lp < 0) {
        *last_primary   = wlan_id;
        *last_switch_time = now;
        return wlan_id;
    }

    /* 2) 둘 다 없는 예외 */
    if (wlan_id < 0 && usb_id < 0) return lp;

    /* 3) 둘 다 BAD면 → WLAN 고정 (전환할 이유 없음) */
    int both_bad = (WLAN && USB && (WLAN->grade==2 && USB->grade==2));

    /* ---- A) 현재 WLAN ---- */
    if (lp == wlan_id) {
        if (dt < DWELL_FAILOVER) return wlan_id;

        if (both_bad) return wlan_id;

        /* FAILOVER 조건: WLAN 나쁜데 USB 덜 나쁠 때 */
        if (WLAN->grade == 2 && USB && USB->grade != 2) {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }
        /* 또는 WLAN WARN, USB GOOD */
        if (WLAN->grade == 1 && USB && USB->grade == 0) {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }
        /* 동급이면 RTT 마진으로만 스위칭 (너무 민감하지 않게) */
        if (USB && WLAN->grade == USB->grade &&
            (WLAN->rtt_ms - USB->rtt_ms) > RTT_MARGIN_MS)
        {
            *last_primary = usb_id; *last_switch_time = now;
            return usb_id;
        }
        return wlan_id;
    }

    /* ---- B) 현재 USB ---- */
    if (lp == usb_id) {
        if (dt < DWELL_FAILBACK) return usb_id;

        /* FAILBACK: WLAN이 BAD가 아니면 복귀 */
        if (WLAN && WLAN->grade <= 1) {
            *last_primary = wlan_id; *last_switch_time = now;
            return wlan_id;
        }
        /* 동급이면 RTT 마진으로 WLAN 쪽이 충분히 이득일 때만 복귀 */
        if (WLAN && USB &&
            WLAN->grade == USB->grade &&
            (USB->rtt_ms - WLAN->rtt_ms) > (RTT_MARGIN_MS + 10.0))
        {
            *last_primary = wlan_id; *last_switch_time = now;
            return wlan_id;
        }
        return usb_id;
    }

    /* ---- C) lp가 둘 다 아닐 때: WLAN 우선 ---- */
    *last_primary = (wlan_id >= 0 ? wlan_id : usb_id);
    *last_switch_time = now;
    return *last_primary;
}
/* ============================================================
 * Warm-up traffic
 * ============================================================ */

static inline void warmup_path(picoquic_cnx_t* c, int sid, int bytes)
{
    static uint8_t warmbuf[8192];
    picoquic_add_to_stream_with_ctx(c, sid, warmbuf, bytes, 0, NULL);
}


/* ============================================================
 * FAILOVER / RECOVERY 상태머신
 * ============================================================ */



/* ============================================================
 * COST-BASED 선택
 * ============================================================ */




/* ============================================================
 * 최종 Primary 선택기
 * ============================================================ */
int pick_primary_idx(
    picoquic_cnx_t* c,
    pathsel_t* sel,
    int sc,
    uint32_t ip_wlan_be,
    uint32_t ip_usb_be,
    int* last_primary,
    uint64_t now,
    uint64_t* last_switch_time
){
    if (sc <= 0) return -1;
    /*
    LOGF("[PICK] ---- pick_primary_idx called ---- now=%.3f",
         now/1e6);
    LOGF("[PICK] last_primary=%d sc=%d", *last_primary, sc);
*/
    int wlan_idx=-1, usb_idx=-1;
    uint32_t wlan_ip = ntohl(ip_wlan_be);
    uint32_t usb_ip  = ntohl(ip_usb_be);
    uint32_t ip_wlan = ntohl(ip_wlan_be);
    uint32_t ip_usb  = ntohl(ip_usb_be);
        
    LOGF("[CFG] WLAN local ip = %u.%u.%u.%u",
        (wlan_ip>>24)&0xff, (wlan_ip>>16)&0xff,
        (wlan_ip>>8)&0xff, (wlan_ip)&0xff);

    LOGF("[CFG] USB  local ip = %u.%u.%u.%u",
        (usb_ip>>24)&0xff, (usb_ip>>16)&0xff,
        (usb_ip>>8)&0xff, (usb_ip)&0xff);
        
for (int i=0; i<sc; i++) {
    picoquic_path_t* p = sel[i].p;
    picoquic_tuple_t* t = p->first_tuple;

    struct sockaddr_in* la = (struct sockaddr_in*)&t->local_addr;

    uint32_t local_ip_be = la->sin_addr.s_addr;       // 그대로 사용 (BE)
    uint32_t local_ip    = ntohl(local_ip_be);

    LOGF("[PICK] path[%d] LOCAL NIC IP = %u.%u.%u.%u",
         i,
         (local_ip>>24)&0xff, (local_ip>>16)&0xff,
         (local_ip>>8)&0xff, (local_ip)&0xff);

    if (local_ip_be == ip_wlan_be)
        wlan_idx = i;

    if (local_ip_be == ip_usb_be)
        usb_idx = i;}
    picoquic_path_t* WLAN = (wlan_idx>=0 ? sel[wlan_idx].p : NULL);
    picoquic_path_t* USB  = (usb_idx>=0 ? sel[usb_idx].p : NULL);

    if (!WLAN && !USB) {
        LOGF("[PICK] No WLAN/USB -> keep last=%d", *last_primary);
        return *last_primary;
    }

    /* metric 계산 */
    path_metric_t Mwlan = WLAN ? compute_metric_safe(WLAN) : (path_metric_t){ .grade = 2 };
    path_metric_t Musb  = USB  ? compute_metric_safe(USB)  : (path_metric_t){ .grade = 2 };
        
    LOGF("[PICK] METRIC WLAN grade=%d", Mwlan.grade);
    LOGF("[PICK] METRIC USB  grade=%d", Musb.grade);
        
    int wlan_id = (wlan_idx>=0 ? sel[wlan_idx].idx : -1);
    int usb_id  = (usb_idx>=0 ? sel[usb_idx].idx : -1);

    int pr = fsm_pick(&Mwlan, &Musb, wlan_id, usb_id,
                      last_primary, now, last_switch_time);

    LOGF("[PICK] fsm_pick -> primary=%d", pr);

    return pr;
}

static int choose_verified_or_fallback(picoquic_cnx_t* c, int want_idx)
{
    if (want_idx >= 0 && want_idx < c->nb_paths) {
        picoquic_path_t* p = c->path[want_idx];
        if (p && p->first_tuple && p->first_tuple->challenge_verified)
            return want_idx;
    }
    /* 임의 폴백: 아무 검증된 path */
    for (int i=0; i<c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (p && p->first_tuple && p->first_tuple->challenge_verified)
            return i;
    }
    /* 마지막 안전망: 0 번이 살아있으면 */
    if (c->nb_paths > 0 && c->path[0] && c->path[0]->first_tuple &&
        c->path[0]->first_tuple->challenge_verified)
        return 0;

    return -1; // 정말 아무 것도 없음
}

/* 안전 체킹: 경로 인덱스가 유효하고 first_tuple도 존재해야 “쓸 수 있는 경로” */
static inline int path_ok(picoquic_cnx_t* c, int i){
    return (c && i >= 0 && i < (int)c->nb_paths && c->path[i] && c->path[i]->first_tuple);
}

/* 0번이 NULL이면, 살아있는 첫 경로를 0번으로 스왑.
   (구조체 포인터만 스왑하므로 매우 얕은 동작) */
static inline void ensure_path0_alive(picoquic_cnx_t* c){
    if (c == NULL) return;
    if (path_ok(c, 0)) return;              // 이미 정상
    for (int i = 1; i < (int)c->nb_paths; i++){
        if (path_ok(c, i)) {
            picoquic_path_t* tmp = c->path[0];
            c->path[0] = c->path[i];
            c->path[i] = tmp;
            /* (선택) 기본 경로로 승격됐다고 로그 */
            // LOGF("[SAFE] promote path[%d] -> path[0]", i);
            return;
        }
    }
    /* 모두 죽었으면 할 수 있는 게 없음 — loop가 계속 돌되, 앱은 바로 리턴 */
}

static int pick_verified_primary(picoquic_cnx_t* c,
                                 uint32_t prefer_ip_be /*network byte order, 0=don’t care*/)
{
    int best = -1;
    for (int i=0; i<(int)c->nb_paths; i++){
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;
        if (!p->first_tuple->challenge_verified) continue;  // ★ verified only

        if (prefer_ip_be != 0) {
            const struct sockaddr_in* la = (const struct sockaddr_in*)&p->first_tuple->local_addr;
            if (la->sin_family == AF_INET && la->sin_addr.s_addr == prefer_ip_be) {
                return i; // 선호 IP와 정확히 일치하면 즉시 선택
            }
        }
        if (best < 0) best = i;
    }
    return best;
}
static void build_unique_verified_paths(picoquic_cnx_t* c, pathsel_t* sel, int* sc_io)
{
    int sc = 0;

    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;
        if (!path_verified_ptr(p)) continue;

        struct sockaddr_in* la =
            (struct sockaddr_in*)&p->first_tuple->local_addr;

        if (la->sin_family != AF_INET) continue;

        /* RAW big-endian local address */
        uint32_t ip_be = la->sin_addr.s_addr;

        /* ---- duplicate check ---- */
        int is_dup = 0;
        for (int k = 0; k < sc; k++) {
            if (sel[k].ip_be == ip_be) {
                is_dup = 1;
                break;
            }
        }
        if (is_dup) continue;

        /* ---- insert path ---- */
        sel[sc].idx   = i;
        sel[sc].ip_be = ip_be;
        sel[sc].p     = p;
        sc++;
    }

    *sc_io = sc;
}

static void kick_path_verification(picoquic_cnx_t* c, tx_t* st, int i)
{
    picoquic_path_t* p = c->path[i];
    if (!p || !p->first_tuple) return;

    /* 단순 challenge kick만 수행 */
    picoquic_set_path_challenge(c, i, picoquic_current_time());
}


static void* camera_thread_main(void* arg)
{
    tx_t* st = (tx_t*)arg;
    LOGF("[CAM] thread started");

    while (!st->cam_stop) {
        if (!st->cam) {
            usleep(10000);  // 카메라 아직 준비 안 됐으면 잠깐 쉼
            continue;
        }

        /* 1) 캡처용 버퍼 용량 확보 (최소 1MB) */
        if (st->cam_cap < (1u << 20)) {
            uint8_t* tmp = (uint8_t*)realloc(st->cam_buf, 1u << 20);
            if (!tmp) {
                LOGF("[CAM] realloc failed");
                usleep(10000);
                continue;
            }
            st->cam_buf = tmp;
            st->cam_cap = 1u << 20;
        }

        /* 2) 실제 캡처 (블로킹) */
        int n = camera_capture_jpeg(st->cam, st->cam_buf, (int)st->cam_cap);
        if (n <= 0 || (size_t)n > st->cam_cap) {
            // 실패했으면 다음 루프로
            continue;
        }

        /* 3) 메타데이터만 락 걸어서 업데이트 */
        pthread_mutex_lock(&st->cam_mtx);
        st->cam_len = n;
        st->cam_seq++;
        pthread_mutex_unlock(&st->cam_mtx);
        // 여기서 loop_cb는 cam_len / cam_seq를 보고 최신 프레임만 가져간다.
    }

    LOGF("[CAM] thread exit");
    return NULL;
}


int make_bound_socket(const char* ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    LOGF("[SOCK] bound %s:%d fd=%d", ip, port, fd);
    return fd;
}

/* ===== Path가 지금 당장 송신에 써도 되는지 검사 ===== */


/* ===== 특정 경로로 안전하게 전송 (affinity 재보증 포함) ===== */
static int send_on_path_safe(picoquic_cnx_t* c, tx_t* st, int k,
                             const uint8_t* hdr, size_t hlen,
                             const uint8_t* payload, size_t plen)
{
    if (!path_sane_for_send(c, k)) return -1;

    picoquic_path_t* p = c->path[k];

    /* per-index SID: 루프마다 affinity 재적용(교체/재배치 보호) */
    uint64_t sid = st->sid_per_path[k];
    if (sid == 0) {
        sid = make_client_uni_sid_from_index(k);
        ensure_stream_for_path(c, st, &sid, k);
        st->sid_per_path[k] = sid;
    }

    if (picoquic_set_stream_path_affinity(c, sid, p->unique_path_id) != 0) {
        return -2; /* 경로 교체 중일 수 있음 */
    }

    /* 실제 송신 */
    int r1 = picoquic_add_to_stream_with_ctx(c, sid, hdr, hlen, 0, st);
    int r2 = (r1 == 0) ? picoquic_add_to_stream_with_ctx(c, sid, payload, plen, 0, st) : r1;
    return r2; /* 0이면 성공 */
}


// ───────── packet loop 콜백 (핫스팟 + 실시간 모니터링) ─────────
static int loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx,
                   void* callback_return)
{
    (void)callback_return;
    tx_t* st = (tx_t*)cb_ctx;
    picoquic_cnx_t* c = st->cnx;
    uint64_t now = picoquic_get_quic_time(quic);

    /* =====================================================
     * 0. 기본 조건 검사
     * ===================================================== */
    if (!st || !c) return 0;

    picoquic_state_enum cs = picoquic_get_cnx_state(c);
    if (cs >= picoquic_state_disconnecting || st->closing)
        return 0;

    /* 콜백 타이밍 아닌 경우 스킵 */
    if (cb_mode != picoquic_packet_loop_after_receive &&
        cb_mode != picoquic_packet_loop_after_send &&
        cb_mode != picoquic_packet_loop_ready)
        return 0;

    /* =====================================================
     * 1. unreached path의 RTT/LOSS 등을 무효화 (보호)
     * ===================================================== */
    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;

        if (!p->first_tuple->challenge_verified) {
            p->smoothed_rtt = UINT64_MAX/2;
            p->rtt_min      = UINT64_MAX/2;
            p->receive_rate_estimate = 0;
            p->total_bytes_lost      = 0;
        }
    }

    /* =====================================================
     * 2. 핸드셰이크 전이면 잠깐 쉼
     * ===================================================== */
    if (!hs_done(c)) {
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* 기본 path 살아있게 유지 */
    ensure_path0_alive(c);

    /* =====================================================
     * 3. 핸드셰이크 이후 경로 probing 시작
     * ===================================================== */
    if (st->has_local_alt && !st->didB && now - st->hs_done_ts > 200000) {
        LOGF("[PROBE] probing ALT...");
        picoquic_probe_new_path(c,
            (struct sockaddr*)&st->peerA,
            (struct sockaddr*)&st->local_alt,
            now);
        st->didB = 1;
    }

    if (st->has_local_usb && !st->didC && now - st->hs_done_ts > 400000) {
        LOGF("[PROBE] probing USB...");
        picoquic_probe_new_path(c,
            (struct sockaddr*)&st->peerA,
            (struct sockaddr*)&st->local_usb,
            now);
        st->didC = 1;
    }

    /* =====================================================
     * 4. keep-alive 송신 (verified path에만)
     * ===================================================== */
    if (now - st->last_keepalive_us > ONE_SEC_US) {
        static const uint8_t ka = 0;
        for (int i = 0; i < c->nb_paths; i++) {
            picoquic_path_t* p = c->path[i];
            if (!path_verified_ptr(p)) continue;
            picoquic_add_to_stream_with_ctx(c, 0, &ka, 1, 0, st);
        }
        st->last_keepalive_us = now;
    }

    /* =====================================================
     * 5. 카메라 프레임 수신 처리 (논블로킹)
     * ===================================================== */
    int cam_len = 0;
    uint64_t cam_seq = 0;

    pthread_mutex_lock(&st->cam_mtx);
    cam_len = st->cam_len;
    cam_seq = st->cam_seq;
    if (cam_seq == st->last_sent_seq || cam_len <= 0) {
        pthread_mutex_unlock(&st->cam_mtx);
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    /* cap_buf 크기 확보 */
    if (st->cap_cap < (size_t)cam_len) {
        uint8_t* tmp = realloc(st->cap_buf, cam_len);
        if (!tmp) { pthread_mutex_unlock(&st->cam_mtx); return 0; }
        st->cap_buf = tmp;
        st->cap_cap = cam_len;
    }

    memcpy(st->cap_buf, st->cam_buf, cam_len);
    st->last_sent_seq = cam_seq;
    pthread_mutex_unlock(&st->cam_mtx);

    /* header encoding */
    size_t hlen = varint_enc(cam_len, st->lenb);

    /* =====================================================
     * 6. verified path 수집 + 미검증 path 재검증 킥
     * ===================================================== */
    pathsel_t sel[MAX_PATHS];
    int sc = 0;
    build_unique_verified_paths(c, sel, &sc);

    if (sc == 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }

    /* 미검증 path는 지속적으로 킥 */
    for (int i = 0; i < c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;

        int in_sel = 0;
        for (int t = 0; t < sc; t++)
            if (sel[t].idx == i) { in_sel = 1; break; }

        if (!in_sel && !p->first_tuple->challenge_verified) {
            kick_path_verification(c, st, i);
        }
    }
    /* =====================================================
     * 7. 보조 path warm-up probe (부드러운 failback)
     * ===================================================== */
    static const uint8_t warm = 0xEE;
    for (int i = 0; i < sc; i++) {
        picoquic_path_t* p = sel[i].p;
        if (!p || !p->first_tuple) continue;

        if (p->first_tuple->challenge_verified &&
            sel[i].idx != st->last_primary_idx)
        {
            picoquic_add_to_stream_with_ctx(c, 0, &warm, 1, 0, st);
        }
    }

    /* =====================================================
     * 8. PRIMARY path 선택 (wlan 우선, usb fallback)
     * ===================================================== */
 int k = pick_primary_idx(
    c, sel, sc,
    st->ip_wlan_be, st->ip_usb_be,
    &st->last_primary_idx,
    now,
    &st->last_switch_ts);
k = choose_verified_or_fallback(c, k);
if (k < 0) { picoquic_set_app_wake_time(c, now + 20000); return 0; }

/* 후보 리스트 구성: 1) primary 우선 2) 나머지 usable 경로 */
int candidates[MAX_PATHS];
int cc = 0;
if (k >= 0) candidates[cc++] = k;

/* sel[] 순회하며 usable한 다른 경로를 후보에 추가 (중복 제거) */
for (int i = 0; i < sc; i++) {
    int idx = sel[i].idx;
    if (idx == k) continue;
    if (path_sane_for_send(c, idx)) {
        candidates[cc++] = idx;
    }
}

/* 마지막 안전망: verified만 골라서라도 하나 넣기 */
if (cc == 0) {
    for (int i = 0; i < sc; i++) {
        if (sel[i].idx != k) candidates[cc++] = sel[i].idx;
    }
}

/* 후보가 없으면 다음 루프 */
if (cc == 0) {
    picoquic_set_app_wake_time(c, now + 20000);
    return 0;
}

/* =====================================================
 * 9~11. 프라이머리 → 실패 시 즉시 대체 경로로 송신
 * ===================================================== */
int sent_ok = -1;
for (int t = 0; t < cc; t++) {
    int try_idx = candidates[t];

    /* 미검증이면 한번 툭 치고 다음 후보로 */
    if (!path_sane_for_send(c, try_idx)) {
        static const uint8_t poke = 0x01;
        picoquic_add_to_stream_with_ctx(c, 0, &poke, 1, 0, st);
        continue;
    }

    /* 전송 시도 (affinity 재보증 포함) */
    int sr = send_on_path_safe(c, st, try_idx, st->lenb, hlen, st->cap_buf, cam_len);
    if (sr == 0) {
        /* 성공: last_primary 유지/갱신 */
        st->last_primary_idx = try_idx;
        sent_ok = 0;
        break;
    }
}

/* 모두 실패했으면 다음 루프에서 재시도 */
if (sent_ok != 0) {
    picoquic_set_app_wake_time(c, now + 20000);
    return 0;
}
    /* =====================================================
    * 12. 모니터링 로그 (1 sec bandwidth report)
    * ===================================================== */
    static uint64_t last_log_us = 0;
    static size_t bytes_accum[MAX_PATHS] = {0};

    bytes_accum[k] += cam_len;

    if (now - last_log_us > ONE_SEC_US) {
        LOGF("[MON] time=%.2fs paths=%d", now / 1e6, c->nb_paths);
            for (int i = 0; i < c->nb_paths; i++) {
                picoquic_path_t* pp = c->path[i];
                if (!pp || !pp->first_tuple) continue;

            char lip[32];
            inet_ntop(AF_INET,
                &((struct sockaddr_in*)&pp->first_tuple->local_addr)->sin_addr,
                lip, sizeof lip);

            double mbps = (bytes_accum[i] * 8.0) / 1e6;
            LOGF("  path[%d] %s verified=%d %.2f Mb/s",
                 i, lip, pp->first_tuple->challenge_verified, mbps);

            bytes_accum[i] = 0;
            }
        last_log_us = now;
    }

    /* =====================================================
     * 13. wake time 설정
     * ===================================================== */
    picoquic_set_app_wake_time(c, now + 20000);
    return 0;
}


#ifndef picoquic_is_handshake_complete
#define picoquic_is_handshake_complete(cnx) \
    ((cnx) && ((cnx)->cnx_state == picoquic_state_client_ready_start || \
               (cnx)->cnx_state == picoquic_state_ready))
#endif
int main(int argc, char** argv)
{
    /* =====================================================
     * 0. 인자 파싱
     * ===================================================== */
    const char* server_ip     = " ";
    const char* local_alt_ip  = " ";      // eth1 (핫스팟)
    const char* local_usb_ip  = " ";     // wlan0 (집 AP)
    int port = 4433;

    if (argc > 1 && argv[1][0]) server_ip     = argv[1];
    if (argc > 2 && argv[2][0]) local_alt_ip  = argv[2];
    if (argc > 3 && argv[3][0]) port          = atoi(argv[3]);
    if (argc > 4 && argv[4][0]) local_usb_ip  = argv[4];

    LOGF("[MAIN] args: server=%s port=%d alt=%s usb=%s",
         server_ip, port, local_alt_ip, local_usb_ip);

    /* =====================================================
     * 1. QUIC Context 생성
     * ===================================================== */
    LOGF("[MAIN] creating QUIC ctx...");
    picoquic_quic_t* q = picoquic_create(
        32, NULL, NULL, NULL, "hq",
        NULL, NULL, NULL, NULL, NULL,
        picoquic_current_time(),
        NULL, NULL, NULL,
        1 /* use_pmtud */
    );
    if (!q) {
        LOGF("[ERR] picoquic_create failed");
        return -1;
    }

    /* --- MP/TP 설정 --- */
    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp, 0);
    tp.is_multipath_enabled = 3;
    tp.initial_max_path_id  = 2;
    tp.active_connection_id_limit = 8;
    tp.enable_time_stamp = 3;
    tp.initial_max_data  = 64 * 1024 * 1024;
    tp.initial_max_stream_data_uni = 8 * 1024 * 1024;
    tp.initial_max_stream_data_bidi_local  = 8 * 1024 * 1024;
    tp.initial_max_stream_data_bidi_remote = 8 * 1024 * 1024;
    tp.max_datagram_frame_size = 1280;
    picoquic_set_default_tp(q, &tp);

    /* =====================================================
     * 2. 서버 주소 resolve
     * ===================================================== */
    struct sockaddr_storage peerA = {0};
    if (resolve_ip(server_ip, port, &peerA) != 0) {
        LOGF("[ERR] resolve server failed");
        return -1;
    }

    /* =====================================================
     * 3. Connection 생성
     * ===================================================== */
    picoquic_cnx_t* cnx = picoquic_create_cnx(
        q,
        picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&peerA,
        picoquic_current_time(),
        0, server_ip, "hq",
        1
    );
    if (!cnx) {
        LOGF("[ERR] create_cnx failed");
        picoquic_free(q);
        return -1;
    }
    picoquic_enable_keep_alive(cnx, 1);

    /* =====================================================
     * 4. 업로더 상태 초기화
     * ===================================================== */
    tx_t st;
    memset(&st, 0, sizeof(st));

    st.cnx = cnx;
    st.rr  = -1;
    st.frame_bytes = 1200;
    st.peerA = peerA;

    st.ip_wlan_be = inet_addr(local_usb_ip); // wlan0
    st.ip_usb_be  = inet_addr(local_alt_ip); // hotspot
    st.last_primary_idx = -1;
    st.last_switch_ts   = 0;
    pthread_mutex_init(&st.cam_mtx, NULL);

    /* === 로컬 주소 저장 (path probe 용 tuple) === */
    if (!store_local_ip(local_alt_ip, 0, &st.local_alt)) {
        st.has_local_alt = 1;
        ((struct sockaddr_in*)&st.local_alt)->sin_port = htons(55001);
    }
    if (!store_local_ip(local_usb_ip, 0, &st.local_usb)) {
        st.has_local_usb = 1;
        ((struct sockaddr_in*)&st.local_usb)->sin_port = htons(55002);
    }

    /* =====================================================
     * 5. Callback 설정 + handshake 시작
     * ===================================================== */
    picoquic_set_callback(cnx, client_cb, &st);

    if (picoquic_start_client_cnx(cnx) != 0) {
        LOGF("[ERR] start_client_cnx failed");
        picoquic_free(q);
        return -1;
    }

    /* =====================================================
     * 6. 카메라 스레드 시작
     * ===================================================== */
    st.cam = camera_create();
    if (!st.cam) {
        LOGF("[ERR] camera_create failed");
        picoquic_free(q);
        return -1;
    }

    if (pthread_create(&st.cam_thread, NULL, camera_thread_main, &st) == 0) {
        st.cam_thread_started = 1;
    } else {
        LOGF("[ERR] camera thread failed");
    }

    /* =====================================================
     * ★ 7. NIC 바인딩: wlan0 에 소켓 바인딩 (정공법)
     * ===================================================== */
    LOGF("[MAIN] binding main socket to Wi-Fi NIC (wlan0)...");

    int sock_wlan = make_bound_socket(local_usb_ip, 55002);
    if (sock_wlan < 0) {
        LOGF("[ERR] make_bound_socket failed");
        return -1;
    }
    LOGF("[MAIN] Wi-Fi socket bound OK: %s:55002", local_usb_ip);

    /* =====================================================
     * 8. 패킷 루프 설정
     * ===================================================== */
    picoquic_packet_loop_param_t lp;
    memset(&lp, 0, sizeof(lp));

    /* 메인 소켓 = wlan0 소켓 */
    lp.local_af = AF_INET;
    lp.local_port = 0;

    lp.extra_socket_required = 1;
    lp.do_not_use_gso = 1;

    LOGF("[MAIN] entering packet loop...");

    /* =====================================================
     * 9. 패킷 루프 실행
     * ===================================================== */
    int ret = picoquic_packet_loop_v2(q, &lp, loop_cb, &st);

    LOGF("[MAIN] packet loop exit: ret=%d", ret);

    /* =====================================================
     * 10. 종료 정리
     * ===================================================== */
    if (st.cam_thread_started) {
        st.cam_stop = 1;
        pthread_join(st.cam_thread, NULL);
    }

    pthread_mutex_destroy(&st.cam_mtx);

    if (st.cam) camera_destroy(st.cam);
    if (st.cam_buf) free(st.cam_buf);
    if (st.cap_buf) free(st.cap_buf);

    if (sock_wlan > 0) close(sock_wlan);
    picoquic_free(q);

    LOGF("[MAIN] freed all, exit=%d", ret);
    return ret;
}
