// server_recv.c — picoquic raw-stream receiver (MP OK, no WebTransport)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>  // getnameinfo, NI_MAXHOST, NI_MAXSERV

#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "qlog.h"
#include "picoquic_binlog.h"
#include "autoqlog.h"
#include <sys/stat.h>
#include <sys/types.h>
#include "app_ctx.h"
#include "frame_assembler.h"
#include <pthread.h>    // pthread_mutex_* / pthread_cond_*

#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>

#define USE_IO_QUEUE 1
/* ---- log levels ---- */
#ifndef LOG_LEVEL
#define LOG_LEVEL 2  /* 0=ERR,1=WARN,2=INFO,3=DBG */
#endif

#define LOG_ERR(fmt, ...) do{ if (LOG_LEVEL>=0){ LOGF("[ERR] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_WRN(fmt, ...) do{ if (LOG_LEVEL>=1){ LOGF("[WRN] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_INF(fmt, ...) do{ if (LOG_LEVEL>=2){ LOGF("[INF] " fmt, ##__VA_ARGS__);} }while(0)
#define LOG_DBG(fmt, ...) do{ if (LOG_LEVEL>=3){ LOGF("[DBG] " fmt, ##__VA_ARGS__);} }while(0)


typedef struct {
    app_ctx_t* app;
    uint8_t*   buf;
    size_t     len;
} job_t;


static pthread_mutex_t qmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  qcv  = PTHREAD_COND_INITIALIZER;

// 매우 단순 스텁(원 구현 대체용)


/* cnx state → 문자열 */
static const char* cnx_state_str(picoquic_state_enum s){
    switch(s){
        case picoquic_state_client_init: return "client_init";
        case picoquic_state_client_init_sent: return "client_init_sent";
        case picoquic_state_server_init: return "server_init";
        case picoquic_state_server_handshake: return "server_hs";
        case picoquic_state_client_handshake_start: return "cli_hs_start";
        case picoquic_state_handshake_failure: return "hs_fail";
        case picoquic_state_ready: return "ready";
        case picoquic_state_disconnecting: return "disconnecting";
        case picoquic_state_draining: return "draining";
        case picoquic_state_disconnected: return "disconnected";
        default: return "other";
    
}
}
/* addr → host:port */
static void addr_to_str(const struct sockaddr* sa, char* out, size_t cap){
    if (!sa || !out || cap==0){ return; }
    char host[NI_MAXHOST]={0}, serv[NI_MAXSERV]={0};
    socklen_t slen = (sa->sa_family==AF_INET)? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (getnameinfo(sa, slen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV)==0){
        if (sa->sa_family==AF_INET6) snprintf(out, cap, "[%s]:%s", host, serv);
        else snprintf(out, cap, "%s:%s", host, serv);
    } else {
        snprintf(out, cap, "(unknown)");
    }
}



/* ---- tiny logging helpers ---- */
#ifndef LOGF
static inline void logf_ts_prefix(FILE* fp){
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm; localtime_r(&ts.tv_sec, &tm);
    char buf[32];
    strftime(buf, sizeof(buf), "%m-%d %H:%M:%S", &tm);
    // millisecond precision
    fprintf(fp, "[%s.%03ld] ", buf, ts.tv_nsec/1000000L);
}
static inline void LOGF(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    logf_ts_prefix(stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}
#endif

static void ensure_dir(const char* path){
    if (!path || !*path) return;
    mkdir(path, 0777); /* 이미 있으면 조용히 실패 */
}

/* qlog/binlog 경로 쓰기 가능 여부 점검 */
static int dir_writable(const char* d){
    if (!d || !*d) return 0;
    ensure_dir(d);
    char testp[512]; snprintf(testp, sizeof(testp), "%s/.probe", d);
    FILE* f = fopen(testp, "wb");
    if (!f) return 0;
    fputs("ok", f);
    fclose(f);
    remove(testp);
    return 1;
}
/* ===== Config ===== */
#define DEFAULT_CERT "cert.pem"
#define DEFAULT_KEY  "key.pem"
#define DEFAULT_PORT 4433
#define ONE_SEC_US   1000000ULL
#define MAX_FRAME (8*1024*1024)
#define MAX_PRINTED 128

typedef struct { picoquic_cnx_t* cnx; int printed; } printed_t;

static char      g_outdir[256] = "frames_out";  /* --out로 변경 가능 */
static int       g_max_frames  = 0;             /* 0 = 무제한, --max-frames */
static uint64_t  g_saved_frames = 0;            /* 저장된 총 프레임 수 */
static uint64_t g_last_rx_log_us = 0;
static printed_t g_printed[MAX_PRINTED];

static int cnx_marked_printed(picoquic_cnx_t* c){
    for (int i = 0; i < MAX_PRINTED; i++){
        if (g_printed[i].printed && g_printed[i].cnx == c) return 1;
    }
    return 0;
}
static void cnx_mark_set(picoquic_cnx_t* c){
    for (int i = 0; i < MAX_PRINTED; i++){
        if (!g_printed[i].printed){
            g_printed[i].printed = 1;
            g_printed[i].cnx = c;
            return;
        }
    }
}

static int save_bytes_as_file(const char* dir, uint64_t idx,
                              const uint8_t* data, size_t len)
{
    if (!dir || !*dir || !data || len == 0) return -1;

    ensure_dir(dir);

    char path[512];
    snprintf(path, sizeof(path), "%s/frame_%06" PRIu64 ".jpg", dir, idx);

    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[SVR] fopen fail: %s\n", path);
        return -1;
    }

    size_t w = fwrite(data, 1, len, f);
    /* 실험 중 SD 카드 지연 방지: fsync 생략 권장
       fflush(f);
       int fd = fileno(f);
       if (fd >= 0) fsync(fd);
    */
    fclose(f);

    if (w != len) {
        fprintf(stderr, "[SVR] partial write: %s (%zu/%zu)\n", path, w, len);
        return -1;
    }
    return 0;
}

static int jobq_push(job_t j) {
    // 즉시 저장으로 처리(큐 없이)
    int rc = save_bytes_as_file(g_outdir, j.app->frame_idx++, j.buf, j.len);
    free(j.buf);
    return rc;
}
/* ===== Per-stream RX state ===== */
typedef struct {
    uint8_t  hbuf[8];
    size_t   hgot;     /* header bytes collected */
    int      hdone;    /* header parsed */
    uint64_t plen;     /* payload length */
    uint64_t pgot;     /* payload collected */
    uint8_t* payload;
    size_t   cap;
    uint64_t frames;   /* delivered frames count */
} rx_stream_ctx_t;

/* ===== Session table (no picoquic_get_app_stream_ctx in this branch) ===== */
typedef struct {
    int used;
    uint64_t sid;
    rx_stream_ctx_t* ctx;
} sid_slot_t;

typedef struct {
    sid_slot_t slot[MAX_STREAMS];
} rx_session_t;

/* ===== Small helpers ===== */
static void rx_ctx_free(rx_stream_ctx_t* s){
    if(!s) return;
    free(s->payload);
    free(s);
}

static rx_stream_ctx_t* rx_ctx_new(void){
    rx_stream_ctx_t* s = (rx_stream_ctx_t*)calloc(1, sizeof(rx_stream_ctx_t));
    return s;
}

static rx_stream_ctx_t* session_get_or_make(rx_session_t* ss, uint64_t sid){
    if (!ss) return NULL;
    /* find existing */
    for (int i=0;i<MAX_STREAMS;i++){
        if (ss->slot[i].used && ss->slot[i].sid == sid) return ss->slot[i].ctx;
    }
    /* find empty */
    for (int i=0;i<MAX_STREAMS;i++){
        if (!ss->slot[i].used){
            ss->slot[i].used = 1;
            ss->slot[i].sid  = sid;
            ss->slot[i].ctx  = rx_ctx_new();
            return ss->slot[i].ctx;
        }
    }
    return NULL;
}

static void session_close_sid(rx_session_t* ss, uint64_t sid){
    if (!ss) return;
    for (int i=0;i<MAX_STREAMS;i++){
        if (ss->slot[i].used && ss->slot[i].sid == sid){
            rx_ctx_free(ss->slot[i].ctx);
            memset(&ss->slot[i], 0, sizeof(ss->slot[i]));
            return;
        }
    }
}

/* ===== QUIC varint decode (header = length prefix) ===== */
static int varint_decode(const uint8_t* b, size_t blen, uint64_t* val, size_t* used){
    if (blen == 0) return 0;
    uint8_t fb = b[0];
    if ((fb & 0xC0) == 0x00){ /* 1 byte */
        *val = (uint64_t)(fb & 0x3F);
        *used = 1;
        return 1;
    } else if ((fb & 0xC0) == 0x40){ /* 2 bytes */
        if (blen < 2) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 8) | b[1];
        *used = 2;
        return 1;
    } else if ((fb & 0xC0) == 0x80){ /* 4 bytes */
        if (blen < 4) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 24) | ((uint64_t)b[1] << 16) | ((uint64_t)b[2] << 8) | b[3];
        *used = 4;
        return 1;
    } else { /* 8 bytes */
        if (blen < 8) return 0;
        *val = ((uint64_t)(fb & 0x3F) << 56) |
               ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
               ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | b[7];
        *used = 8;
        return 1;
    }
}


#include <sys/uio.h>
#include <fcntl.h>

typedef struct {
    uint8_t* buf;
    size_t   len;
    uint64_t seq_hint;  // 선택(인덱싱용)
    double   ts_hint;   // 선택
} rx_item_t;

#define RXQ_CAP  512   // 여유있게(라즈베리면 256~1024 권장)
typedef struct {
    rx_item_t q[RXQ_CAP];
    int head, tail;
    int closed;
    pthread_mutex_t m;
    pthread_cond_t  cv;
} rx_queue_t;

static rx_queue_t g_rxq = { .head=0, .tail=0, .closed=0,
    .m=PTHREAD_MUTEX_INITIALIZER, .cv=PTHREAD_COND_INITIALIZER };

static int rxq_push_nolock(rx_queue_t* rq, rx_item_t it) {
    int next = (rq->head + 1) % RXQ_CAP;
    if (next == rq->tail) {
        // 가득 찼으면 가장 오래된 것 drop (영상은 드랍이 stop보다 낫다)
        free(rq->q[rq->tail].buf);
        rq->tail = (rq->tail + 1) % RXQ_CAP;
    }
    rq->q[rq->head] = it;
    rq->head = next;
    return 0;
}
static int rxq_push(rx_queue_t* rq, rx_item_t it) {
    pthread_mutex_lock(&rq->m);
    int r = rxq_push_nolock(rq, it);
    pthread_cond_signal(&rq->cv);
    pthread_mutex_unlock(&rq->m);
    return r;
}
static int rxq_pop(rx_queue_t* rq, rx_item_t* out) {
    pthread_mutex_lock(&rq->m);
    while (rq->head == rq->tail && !rq->closed)
        pthread_cond_wait(&rq->cv, &rq->m);
    if (rq->head == rq->tail && rq->closed) { pthread_mutex_unlock(&rq->m); return -1; }
    *out = rq->q[rq->tail];
    rq->tail = (rq->tail + 1) % RXQ_CAP;
    pthread_mutex_unlock(&rq->m);
    return 0;
}
static void rxq_close(rx_queue_t* rq){
    pthread_mutex_lock(&rq->m); rq->closed=1; pthread_cond_broadcast(&rq->cv); pthread_mutex_unlock(&rq->m);
}

static int ensure_cap(uint8_t** buf, size_t* cap, size_t need, size_t max_cap){
    if (*cap >= need) return 0;
    size_t grow = (*cap ? *cap : 4096);
    while (grow < need) {
        if (grow >= max_cap/2) { grow = need; break; } /* 마지막 점프 */
        grow <<= 1;
    }
    if (grow > max_cap) return -1;
    uint8_t* np = (uint8_t*)realloc(*buf, grow);
    if (!np) return -1;
    *buf = np; *cap = grow;
    return 0;
}

static void on_frame_copy(rx_stream_ctx_t* s, app_ctx_t* app){
    if (!s || !s->payload || s->plen == 0 || !app) return;
    uint8_t* cp = (uint8_t*)malloc(s->plen);
    if (!cp) return;
    memcpy(cp, s->payload, s->plen);
    rx_item_t it = { .buf=cp, .len=(size_t)s->plen, .seq_hint=0, .ts_hint=0.0 };
    rxq_push(&g_rxq, it);
    app->frame_count++;
    app->bytes_saved_total += s->plen;
}

/* 선택: 무복사(소유권 이전) — 큐 소비자가 free() 책임 */
static void on_frame_take(rx_stream_ctx_t* s, app_ctx_t* app){
    if (!s || !s->payload || s->plen == 0 || !app) return;
    rx_item_t it = { .buf=s->payload, .len=(size_t)s->plen, .seq_hint=0, .ts_hint=0.0 };
    rxq_push(&g_rxq, it);
    s->payload = NULL; s->cap = 0;   /* 소유권 이전 */
    app->frame_count++;
    app->bytes_saved_total += s->plen;
}


/* Feed bytes into one stream context */
static int feed_bytes(rx_stream_ctx_t* s, app_ctx_t* app,
                      const uint8_t* buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        if (!s->hdone) {
            /* 1) 헤더 누적 */
            size_t room = sizeof(s->hbuf) - s->hgot;
            size_t to = (len - off < room) ? (len - off) : room;
            memcpy(s->hbuf + s->hgot, buf + off, to);
            s->hgot += to;
            off     += to;

            /* 2) VarInt 파싱 시도 */
            uint64_t plen = 0;
            size_t   used = 0;
            int ok = varint_decode(s->hbuf, s->hgot, &plen, &used); /* ok=1성공,0부족,<0에러 가정 */

            if (ok < 0) {
                /* 형식 에러 → 헤더 버림(강경 정책) */
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }
            if (!ok) {
                /* 아직 부족 */
                continue;
            }

            /* 3) 길이 결정 */
            if (plen == 0 || plen > MAX_FRAME) {
                /* 불량 길이 → 이번 헤더 폐기 */
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }
            s->hdone = 1;
            s->plen  = (size_t)plen;
            s->pgot  = 0;

            /* 4) 헤더 뒤에 붙은 초기 페이로드 처리(remain) */
            size_t remain = s->hgot - used; /* hbuf 안에 이미 붙어 들어온 payload */
            const uint8_t* p_payload0 = (remain ? (s->hbuf + used) : NULL);

            /* payload capacity 보증 (헤더 뒤 첫 덩어리용) */
            if (ensure_cap(&s->payload, &s->cap, s->plen, MAX_FRAME) != 0) {
                /* 메모리 부족 → 프레임 드롭 */
                s->hgot = 0; s->hdone = 0; s->plen = s->pgot = 0;
                continue;
            }

            if (remain) {
                size_t first = (remain < s->plen) ? remain : s->plen;
                memcpy(s->payload, p_payload0, first);
                s->pgot = first;
            }

            /* 헤더 버퍼는 소비한 만큼 정리 */
            s->hgot = 0;

            /* 만약 remain이 이미 프레임을 완성해버렸다면 즉시 완료 */
            if (s->pgot == s->plen) {
                on_frame_copy(s, app); /* 또는 on_frame_take(s,app) */
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }
        } else {
            /* ==== 페이로드 수신 ==== */

            size_t   avail  = len - off;
            uint64_t left64 = (s->plen > s->pgot) ? (s->plen - s->pgot) : 0;
            if (left64 == 0) {
                /* 이상 상태 → 리셋 */
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }
            size_t left = (left64 > SIZE_MAX) ? SIZE_MAX : (size_t)left64;

            size_t to = (avail < left) ? avail : left;
            if (to == 0) break;

            /* capacity 보증: pgot+to 까지 */
            if (ensure_cap(&s->payload, &s->cap, s->pgot + to, MAX_FRAME) != 0) {
                /* 메모리 부족 → 프레임 드롭 */
                s->hdone = 0; s->plen = 0; s->pgot = 0;
                continue;
            }

            memcpy(s->payload + s->pgot, buf + off, to);
            s->pgot += to;
            off     += to;

            if (s->pgot == s->plen) {
                on_frame_copy(s, app); /* 또는 on_frame_take(s,app) */
                s->hdone = 0; s->plen = 0; s->pgot = 0;
            }
        }
    }
    return 0;
}
/* ===== 간단 헬퍼: hexdump N바이트 ===== */
static void dump_prefix(const uint8_t* p, size_t len, size_t n) {
    size_t m = (len < n) ? len : n;
    fprintf(stderr, "[SVR][dump] ");
    for (size_t i=0;i<m;i++) fprintf(stderr, "%02x", p[i]);
    if (len > n) fprintf(stderr, "...(+%zu)", len - n);
    fprintf(stderr, "\n");
}


// append-only 세그먼트 라이터
typedef struct {
    int fd;
    size_t bytes_in_seg;
    char dir[256];
} seg_writer_t;

static int seg_open_new(seg_writer_t* w){
    time_t t=time(NULL); struct tm tm; localtime_r(&t,&tm);
    char stamp[32]; strftime(stamp,sizeof(stamp),"%Y%m%d-%H%M%S",&tm);
    char path[512]; snprintf(path,sizeof(path),"%s/frames_%s.seg", w->dir, stamp);
    w->fd = open(path, O_CREAT|O_WRONLY|O_APPEND, 0644);
    w->bytes_in_seg = 0;
    return (w->fd>=0)?0:-1;
}
static void* writer_thread(void* arg){
    seg_writer_t* w = (seg_writer_t*)arg;
    const size_t ROLL = (size_t)1<<30; // 1GB마다 롤링(원하면 더 작게)
    if (seg_open_new(w)!=0) return NULL;

    while (1){
        rx_item_t it;
        if (rxq_pop(&g_rxq, &it)!=0) break;

        // 헤더(4B len + 8B seq + 8B ts)는 선택. 최소 4B len만 써도 됨.
        uint32_t body_len = (uint32_t)it.len;
        uint8_t  hdr[4];
        hdr[0]=(body_len>>24)&0xFF; hdr[1]=(body_len>>16)&0xFF; hdr[2]=(body_len>>8)&0xFF; hdr[3]=body_len&0xFF;
        struct iovec iov[2] = { {hdr,4}, {(void*)it.buf, it.len} };
        (void)writev(w->fd, iov, 2);
        w->bytes_in_seg += 4 + it.len;

        free(it.buf);

        if (w->bytes_in_seg >= ROLL){ close(w->fd); seg_open_new(w); }
        // flush는 전원보호가 필요할 때만 주기적으로 fdatasync(w->fd);
    }
    close(w->fd);
    return NULL;
}

/* app_ctx_t에 아래 두 필드를 권장(없어도 동작함):
   size_t backlog_bytes; // 대충의 저장 대기량 추정
   uint64_t bytes_rx_total; // 총 수신 바이트
*/

#define LOG_EVERY_BYTES  (1*1024*1024ULL)  /* 1MB마다 진행 로그 */
#define BACKLOG_SOFTCAP  (8*1024*1024ULL)  /* 8MB 넘게 밀리면 소비-only */

static int stream_cb(picoquic_cnx_t* cnx, uint64_t sid, uint8_t* bytes, size_t len,
                     picoquic_call_back_event_t ev, void* cb_ctx, void* v_stream_ctx)
{
    (void)v_stream_ctx;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;

    /* 최소 이벤트 헤더 로그 (rate-limit: 64KB 마다 한 줄) */
    static uint64_t log_accum = 0;
    log_accum += len;
    if (log_accum >= (64*1024)){
        LOG_INF("[RX] ev=%d sid=%" PRIu64 " chunk=%zuB (accum+=%" PRIu64 ")", ev, sid, len, log_accum);
        log_accum = 0;
    }

    switch (ev) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin: {
        if (len > 0) {
            static uint64_t last_log_bytes = 0;
            if (app) app->bytes_rx_total += len;
            if (app && app->bytes_rx_total - last_log_bytes >= LOG_EVERY_BYTES) {
                LOG_INF("[RX] sid=%" PRIu64 " +%zuB (total=%" PRIu64 ")", sid, len, app->bytes_rx_total);
                dump_prefix(bytes, len, 16);
                last_log_bytes = app->bytes_rx_total;
            }

            /* I/O backlog softcap → drop 모드 */
            int drop_mode = 0;
            if (app && app->backlog_bytes > BACKLOG_SOFTCAP) drop_mode = 1;
            const char* dm = getenv("SVR_DROP_MODE");
            if (!drop_mode && dm && *dm=='1') drop_mode = 1;

            int r = 0;
            if (!drop_mode) {
                r = fa_on_bytes(cnx, app, sid, bytes, len);
                if (r != 0) {
                    LOG_WRN("[RX] fa_on_bytes ret=%d (sid=%" PRIu64 ", len=%zu)", r, sid, len);
                }
            }

        }

        if (ev == picoquic_callback_stream_fin) {
            fa_stream_close(app, sid);
            LOG_INF("[STREAM] FIN sid=%" PRIu64, sid);
        }

        if (app && app->max_frames > 0 && app->frame_count >= app->max_frames) {
            LOG_INF("[LIMIT] reached max_frames=%d → connection close", app->max_frames);
            picoquic_close(cnx, 0);
        }
        return 0;
    }

    case picoquic_callback_stream_reset:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] RESET sid=%" PRIu64, sid);
        return 0;

    case picoquic_callback_stop_sending:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] STOP_SENDING sid=%" PRIu64, sid);
        return 0;

    default:
        return 0;
    }
}


/* ===== loop callback (packet loop v2) ===== */
static int loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx, void* callback_return)
{
    (void)callback_return;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;

    static uint64_t last_paths_dump_us = 0;
    static picoquic_state_enum last_state = (picoquic_state_enum)-1;

    if (cb_mode == picoquic_packet_loop_ready) {
        LOG_INF("[LOOP] QUIC ready, waiting for connections...");
    }

    /* 1) 모든 연결 순회: 상태/콜백/경로 로그 */
    for (picoquic_cnx_t* c = picoquic_get_first_cnx(quic);
         c != NULL; c = picoquic_get_next_cnx(c))
    {
        if (picoquic_get_callback_context(c) == NULL) {
            picoquic_set_callback(c, stream_cb, app);
        }

        picoquic_state_enum cs = picoquic_get_cnx_state(c);
        if (cs != last_state){
            struct sockaddr* sa = NULL; picoquic_get_peer_addr(c, &sa);
            char hp[128]={0}; addr_to_str(sa, hp, sizeof(hp));
            LOG_INF("[CNX] state=%s nb_paths=%d peer=%s",
                    cnx_state_str(cs), (int)c->nb_paths, hp);
            last_state = cs;
        }

        if (!cnx_marked_printed(c) && cs == picoquic_state_ready) {
            struct sockaddr* sa = NULL; picoquic_get_peer_addr(c, &sa);
            char hp[128]={0}; addr_to_str(sa, hp, sizeof(hp));
            LOG_INF("[CNX] READY peer=%s (paths=%d)", hp, (int)c->nb_paths);
            cnx_mark_set(c);
        }

        uint64_t now = picoquic_current_time();
        if (now - last_paths_dump_us > 2*1000000ULL) {
            /* nb_paths는 보통 int 이므로 인덱스도 int로 맞춰 경고 제거 */
            for (int i = 0; i < (int)c->nb_paths; i++){
                picoquic_path_t* p = c->path[i];
                if (!p) continue;
                /* 버전 중립: 존재 보장되는 필드만 사용 */
                LOG_DBG("[PATH] i=%d present=1", i);
            }
            last_paths_dump_us = now;
        }
    }

    /* 2) after_{receive,send} 에서 2ms 주기로 깨워주기 */
    if (cb_mode == picoquic_packet_loop_after_receive ||
        cb_mode == picoquic_packet_loop_after_send)
    {
        for (picoquic_cnx_t* c = picoquic_get_first_cnx(quic);
             c != NULL; c = picoquic_get_next_cnx(c))
        {
            picoquic_set_app_wake_time(c, picoquic_current_time() + 2000);
        }
    }

    return 0;
}

/* ===== CLI ===== */
static void usage(const char* argv0){
    fprintf(stderr,
        "Usage: %s [--port N] [--cert path] [--key path] [--qlog] [--binlog]\n"
        "          [--out DIR] [--max-frames N]\n", argv0);
}

/* ===== main ===== */
int main(int argc, char** argv)
{
    int port = DEFAULT_PORT;
    const char* cert = DEFAULT_CERT;
    const char* key  = DEFAULT_KEY;
    int enable_qlog = 0, enable_binlog = 0;

    app_ctx_t app; memset(&app, 0, sizeof(app));
    snprintf(app.out_dir, sizeof(app.out_dir), "%s", "frames_out"); /* 기본값 */
    app.max_frames = 0; /* 0 = 무제한 */

    /* ── 1) 인자 파싱 + 로그 ── */
    for (int i=1; i<argc; i++){
        if (!strcmp(argv[i], "--port") && i+1<argc){
            port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--cert") && i+1<argc){
            cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i+1<argc){
            key = argv[++i];
        } else if (!strcmp(argv[i], "--qlog")){
            enable_qlog = 1;
        } else if (!strcmp(argv[i], "--binlog")){
            enable_binlog = 1;
        } else if (!strcmp(argv[i], "--out") && i+1<argc){
            snprintf(app.out_dir, sizeof(app.out_dir), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--max-frames") && i+1<argc){
            app.max_frames = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return -1;
        }
    }
    LOGF("[SVR][MAIN] args: port=%d cert=%s key=%s qlog=%d binlog=%d out=%s max_frames=%d",
         port, cert, key, enable_qlog, enable_binlog, app.out_dir, app.max_frames);

    /* ── 2) QUIC 컨텍스트 생성 ── */
    LOGF("[SVR][MAIN] creating QUIC ctx (ALPN=h3)...");
    picoquic_quic_t* quic = picoquic_create(
        64, cert, key, NULL, "hq",
        stream_cb, /* default_cb_ctx */ &app, NULL, NULL, NULL,
        picoquic_current_time(), NULL, NULL, NULL, 1);
    if (!quic){
        LOGF("[SVR][ERR] picoquic_create failed");
        return -1;
    }
    LOGF("[SVR][MAIN] QUIC ctx created: %p", (void*)quic);

    /* ── 3) TP 설정 ── */
    picoquic_tp_t tp; memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp, 1); // is_server=1

    tp.is_multipath_enabled    = 0;
    tp.initial_max_path_id     = 3;
    tp.enable_time_stamp       = 3;
    tp.max_datagram_frame_size = 1200;
    tp.active_connection_id_limit = 4;
    /* 수신/커넥션 윈도우 넉넉히 */
    tp.initial_max_data = 8*1024*1024; // 64MB
    tp.initial_max_stream_data_bidi_local  = 128*1024*1024;
    tp.initial_max_stream_data_bidi_remote = 128*1024*1024;
    tp.initial_max_stream_data_uni         = 128*1024*1024;

    /* 동시 스트림 수 */
    tp.initial_max_stream_id_bidir  = 64;
    tp.initial_max_stream_id_unidir = 64;
    tp.max_ack_delay      = 0;  // ms (기본 25ms보다 작게)
    tp.ack_delay_exponent = 3;

    picoquic_set_default_tp(quic, &tp);
    LOGF("[SVR][MAIN] TP set:"
         " mp=%d path_id=%u ts=%d max_data=%u"
         " uni=%u bidi_loc=%u bidi_rem=%u"
         " sid_bi=%u sid_uni=%u dgram=%u",
         tp.is_multipath_enabled, tp.initial_max_path_id, tp.enable_time_stamp,
         (unsigned)tp.initial_max_data,
         (unsigned)tp.initial_max_stream_data_uni,
         (unsigned)tp.initial_max_stream_data_bidi_local,
         (unsigned)tp.initial_max_stream_data_bidi_remote,
         tp.initial_max_stream_id_bidir, tp.initial_max_stream_id_unidir,
         (unsigned)tp.max_datagram_frame_size);

/* ── 4) qlog / binlog ── 
    if (enable_qlog){
        const char* qdir = (getenv("SVR_QLOG_DIR") && *getenv("SVR_QLOG_DIR"))
                            ? getenv("SVR_QLOG_DIR") : "qlogs_svr";
        if (!dir_writable(qdir)){
            LOG_WRN("[SVR][MAIN] qlog dir not writable: %s → disabling", qdir);
            enable_qlog = 0;
        } else {
            ensure_dir(qdir);
            picoquic_set_qlog(quic, qdir);
            LOG_INF("[SVR][MAIN] qlog enabled: dir=%s", qdir);
        }
    } else {
        LOG_INF("[SVR][MAIN] qlog disabled");
    }
    if (enable_binlog){
        const char* bdir = (getenv("SVR_BINLOG_DIR") && *getenv("SVR_BINLOG_DIR"))
                            ? getenv("SVR_BINLOG_DIR") : "binlog_svr";
        if (!dir_writable(bdir)){
            LOG_WRN("[SVR][MAIN] binlog dir not writable: %s → disabling", bdir);
            enable_binlog = 0;
        } else {
            ensure_dir(bdir);
            picoquic_set_binlog(quic, bdir);
            LOG_INF("[SVR][MAIN] binlog enabled: dir=%s", bdir);
        }
    } else {
        LOG_INF("[SVR][MAIN] binlog disabled");
    }
    picoquic_use_unique_log_names(quic, 1);
    */
    /* ── 5) 패킷 루프 파라미터 ── */
    seg_writer_t w = { .fd=-1, .bytes_in_seg=0 };
    snprintf(w.dir, sizeof(w.dir), "%s", app.out_dir);
    ensure_dir(w.dir);
    pthread_t wth; pthread_create(&wth, NULL, writer_thread, &w);
    picoquic_packet_loop_param_t lp = (picoquic_packet_loop_param_t){0};
    lp.local_port = port;
    lp.extra_socket_required = 1;  // 필수
    lp.socket_buffer_size = 4*1024*1024; // 소켓 버퍼 크게
    lp.do_not_use_gso = 0;
    LOGF("[SVR][MAIN] listen UDP :%d (raw streams, MP enabled)", port);
    LOGF("[SVR][MAIN] out_dir=%s max_frames=%d", app.out_dir, app.max_frames);

    /* ── 6) 패킷 루프 진입 ── */
    int ret = picoquic_packet_loop_v2(quic, &lp, loop_cb, &app);
    LOGF("[SVR][MAIN] loop end ret=%d", ret);

    rxq_close(&g_rxq);
    pthread_join(wth, NULL);

    /* ── 7) 종료 정리 ── */
    picoquic_free(quic);
    LOGF("[SVR][MAIN] quic freed, exit ret=%d", ret);
    return ret;
}