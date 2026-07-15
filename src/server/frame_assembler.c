// frame_assembler.c — MP-QUIC Safe RX Assembler + Async Disk Writer + Depth preview
//
// Supports both JPEG (RGB camera) and PNG (16-bit depth camera) input.
// PNG depth frames are converted to a jet-colormap JPEG for the preview sink.

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <dirent.h>
#include <png.h>
#include <jpeglib.h>

#include "picoquic.h"
#include "frame_assembler.h"
#include "depth_preview.h"
#include "frame_writer.h"

/* Scan out_dir for the highest existing frame serial (files named
 * frame_%06d_{d,r}.{png,jpg}). Returns 0 if the dir is empty/absent.
 * Ported from mp-quic-go jetson_handler.maxSerialOnDisk so a server restart
 * resumes the serial ABOVE what is already recorded instead of overwriting
 * frame_000001. */
int fa_max_frame_idx_on_disk(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return 0;
    int max_idx = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        int idx = 0;
        if (sscanf(e->d_name, "frame_%d_", &idx) == 1 && idx > max_idx) {
            max_idx = idx;
        }
    }
    closedir(d);
    return max_idx;
}
#include "app_ctx.h"

/* ============================================================
 * [1] 로깅 및 시스템 튜닝 파라미터
 * ============================================================ */

#ifndef LOG_INF
#  define LOG_INF(fmt, ...) fprintf(stderr, "[INF] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_WRN
#  define LOG_WRN(fmt, ...) fprintf(stderr, "[WRN] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_ERR
#  define LOG_ERR(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#endif

/* Receiver-side per-frame arrival log (goodput + interruption ground truth).
 * Enabled by env MPQUIC_RX_QLOG=<path>; appends "t_us,type,bytes" per delivered
 * frame (monotonic clock). Off when the env is unset. */
#include <time.h>
#include <inttypes.h>
/* mkdir -p the parent directories of a file path (so MPQUIC_RX_QLOG can point
 * into a not-yet-existing run folder without silently failing to open). */
static void mkdir_parents(const char* path) {
    char tmp[512]; size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) return;
    memcpy(tmp, path, n + 1);
    for (char* q = tmp + 1; *q; q++) {
        if (*q == '/') { *q = '\0'; mkdir(tmp, 0755); *q = '/'; }
    }
}
static void fa_rx_qlog(char ftype, size_t slen) {
    static FILE* f = NULL; static int init = 0;
    if (!init) {
        init = 1;
        const char* p = getenv("MPQUIC_RX_QLOG");
        if (p && *p) {
            mkdir_parents(p);
            f = fopen(p, "a");
            if (!f) LOG_ERR("[RX-QLOG] cannot open %s (logging disabled)", p);
            else if (ftell(f) == 0) fprintf(f, "t_us,type,bytes\n");
        }
    }
    if (!f) return;
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t t = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
    fprintf(f, "%" PRIu64 ",%c,%zu\n", t, ftype ? ftype : '?', slen);
    fflush(f);
}

/* 프레임 및 수신 처리 제한 설정 */
#ifndef MAX_FRAME_SIZE
#  define MAX_FRAME_SIZE (10*1024*1024)
#endif
#ifndef MAX_STREAMS
#  define MAX_STREAMS 128
#endif
#ifndef FA_MAX_RX_STEPS
#  define FA_MAX_RX_STEPS 65536
#endif
#ifndef FA_MAX_RX_BYTES
#  define FA_MAX_RX_BYTES (4*1024*1024)
#endif
#ifndef FA_MAX_FRAMES_CB
#  define FA_MAX_FRAMES_CB 16
#endif
#ifndef FA_MAX_TIME_US
#  define FA_MAX_TIME_US 20000
#endif


/* ============================================================
 * [2] 수신 뱅크 및 저장 큐 구조
 * ============================================================ */

typedef struct {
    rx_stream_t rx[MAX_STREAMS];
} rx_bank_t;

static rx_bank_t g_bank;

/* Disk-save worker subsystem (save queue + worker thread + preview sinks
 * + save_frame/save_frame_take) moved to frame_writer.c. */



/* ============================================================
 * [5] 수신 스트림 상태 관리
 * ============================================================ */

void rx_clear(rx_stream_t* rx){
    rx->st = RX_WANT_MAGIC;
    rx->magic_matched = 0;
    rx->len_got = 0;
    rx->frame_size = 0;
    rx->received = 0;
    rx->frame_type = 0;
}

static rx_stream_t* rx_get(app_ctx_t* app, uint64_t sid){
    (void)app;
    /* 기존 사용 중인 스트림 찾기 */
    for (int i = 0; i < MAX_STREAMS; i++){
        if (g_bank.rx[i].in_use && g_bank.rx[i].sid == sid)
            return &g_bank.rx[i];
    }
    /* 빈 슬롯에 새 스트림 등록 */
    for (int i = 0; i < MAX_STREAMS; i++){
        if (!g_bank.rx[i].in_use){
            rx_stream_t* rx = &g_bank.rx[i];
            memset(rx, 0, sizeof(*rx));
            rx->in_use = 1;
            rx->sid = sid;
            rx->st = RX_WANT_MAGIC;
            return rx;
        }
    }
    return NULL;
}

static int ensure_cap(rx_stream_t* rx, size_t need){
    if (need > MAX_FRAME_SIZE) return -1;
    if (rx->cap >= need) return 0;

    size_t nc = (rx->cap ? rx->cap : 4096);
    while (nc < need){
        if (nc > MAX_FRAME_SIZE / 2){ nc = need; break; }
        nc <<= 1;
    }

    uint8_t* nb = realloc(rx->buf, nc);
    if (!nb) return -1;
    rx->buf = nb; 
    rx->cap = nc;
    return 0;
}


/* ============================================================
 * [6] Magic + fixed-width length framing
 * ============================================================
 *
 * Frame format (9-byte header):
 *   [4 bytes: magic "MPQ1"]
 *   [1 byte:  frame type — 'd' = depth (16-bit PNG), 'r' = RGB (JPEG)]
 *   [4 bytes: frame_len (big-endian uint32)]
 *   [frame_len bytes: payload]
 */

static const uint8_t FRAME_MAGIC[4] = {FRAME_MAGIC_B0, FRAME_MAGIC_B1,
                                       FRAME_MAGIC_B2, FRAME_MAGIC_B3};

static int g_tun_init=0;
static size_t T_MAX_RX_STEPS=FA_MAX_RX_STEPS;
static size_t T_MAX_RX_BYTES=FA_MAX_RX_BYTES;
static size_t T_MAX_FRAMES_CB=FA_MAX_FRAMES_CB;
static size_t T_MAX_TIME_US=FA_MAX_TIME_US;

static void fa_tunables_init_once(void){
    if (g_tun_init) return;
    const char* s;
    if((s=getenv("FA_MAX_RX_STEPS"))) T_MAX_RX_STEPS=strtoul(s,NULL,10);
    if((s=getenv("FA_MAX_RX_BYTES"))) T_MAX_RX_BYTES=strtoul(s,NULL,10);
    if((s=getenv("FA_MAX_FRAMES_CB"))) T_MAX_FRAMES_CB=strtoul(s,NULL,10);
    if((s=getenv("FA_MAX_TIME_US"))) T_MAX_TIME_US=strtoul(s,NULL,10);
    g_tun_init=1;
}

static inline void fc_bump(picoquic_cnx_t* cnx, uint64_t sid, uint64_t used){
#ifdef picoquic_add_to_stream_window
    picoquic_add_to_stream_window(cnx, sid, used);
#else
    (void)cnx; (void)sid; (void)used;
#endif
}


/* ============================================================
 * [8] 공개 API 구현
 * ============================================================ */

void fa_stream_close(app_ctx_t* app, uint64_t sid){
    (void)app;
    for (int i = 0; i < MAX_STREAMS; i++){
        rx_stream_t* rx = &g_bank.rx[i];
        if (rx->in_use && rx->sid == sid){
            if (rx->buf) free(rx->buf);
            memset(rx, 0, sizeof(*rx));
            return;
        }
    }
}

void fa_reset(app_ctx_t* app){
    (void)app;
    for (int i = 0; i < MAX_STREAMS; i++){
        rx_stream_t* rx = &g_bank.rx[i];
        if (rx->buf) free(rx->buf);
    }
    memset(&g_bank, 0, sizeof(g_bank));
}

/**
 * @brief Main byte-stream → frame reassembly logic.
 *
 * Frame format: [4B magic "MPQ1"] [1B type 'd'/'r'] [4B big-endian length] [payload]
 */
int fa_on_bytes(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t sid,
                const uint8_t* bytes, size_t length)
{
    fa_tunables_init_once();

    const uint8_t* p = bytes;
    const uint8_t* pmax = bytes + length;

    rx_stream_t* rx = rx_get(app, sid);
    if (!rx) return -1;

    picoquic_quic_t* quic = cnx ? picoquic_get_quic_ctx(cnx) : NULL;
    uint64_t start_us = quic ? picoquic_get_quic_time(quic) : 0;

    size_t steps = 0, copied = 0, frames = 0;

    while (p < pmax) {
        if (steps++ >= T_MAX_RX_STEPS) break;
        if (copied >= T_MAX_RX_BYTES) break;
        if (frames >= T_MAX_FRAMES_CB) break;
        if (quic) {
            uint64_t now = picoquic_get_quic_time(quic);
            if (T_MAX_TIME_US > 0 && now - start_us >= T_MAX_TIME_US) break;
        }

        int progressed = 0;

        /* ----- 1) Magic scan: find "MPQ1" header ----- */
        if (rx->st == RX_WANT_MAGIC) {
            while (p < pmax) {
                uint8_t c = *p++; progressed = 1;
                if (c == FRAME_MAGIC[rx->magic_matched]) {
                    rx->magic_matched++;
                    if (rx->magic_matched == 4) {
                        rx->st = RX_WANT_TYPE;
                        break;
                    }
                } else {
                    rx->magic_matched = (c == FRAME_MAGIC[0]) ? 1 : 0;
                }
            }
            continue;
        }

        /* ----- 2) Frame type: read 1 byte ('d'=depth, 'r'=RGB) ----- */
        if (rx->st == RX_WANT_TYPE) {
            if (p < pmax) {
                rx->frame_type = (char)*p++; progressed = 1;
                rx->st = RX_WANT_LEN;
                rx->len_got = 0;
            }
            continue;
        }

        /* ----- 3) Length: read 4-byte big-endian frame size ----- */
        if (rx->st == RX_WANT_LEN) {
            while (rx->len_got < 4 && p < pmax) {
                rx->len_buf[rx->len_got++] = *p++; progressed = 1;
            }
            if (rx->len_got < 4) break;

            uint32_t sz = ((uint32_t)rx->len_buf[0] << 24)
                        | ((uint32_t)rx->len_buf[1] << 16)
                        | ((uint32_t)rx->len_buf[2] << 8)
                        | (uint32_t)rx->len_buf[3];

            if (sz == 0 || sz > MAX_FRAME_SIZE) {
                LOG_WRN("[FA] bad frame_len=%u — resyncing", sz);
                rx_clear(rx);
                continue;
            }

            rx->frame_size = sz;
            rx->received = 0;
            if (ensure_cap(rx, sz) != 0) { rx_clear(rx); continue; }
            rx->st = RX_WANT_PAYLOAD;
            continue;
        }

        /* ----- 4) Payload: copy frame data ----- */
        if (rx->st == RX_WANT_PAYLOAD) {
            uint64_t left64 = rx->frame_size - rx->received;
            if (left64 == 0) { rx_clear(rx); continue; }

            size_t avail = (size_t)(pmax - p);
            size_t left = (size_t)((left64 > SIZE_MAX) ? SIZE_MAX : left64);
            size_t to_do = (avail < left ? avail : left);
            if (to_do == 0) break;

            if (ensure_cap(rx, rx->received + to_do) != 0) { rx_clear(rx); continue; }
            memcpy(rx->buf + rx->received, p, to_do);
            rx->received += to_do;
            p += to_do;
            copied += to_do;
            progressed = 1;
            if (cnx) fc_bump(cnx, sid, to_do);

            if (rx->received >= rx->frame_size) {
                uint8_t* stolen = rx->buf;
                size_t slen = rx->frame_size;
                char ftype = rx->frame_type;
                rx->buf = NULL;
                rx->cap = 0;
                int is_jpeg = (slen >= 2 && stolen[0] == 0xFF && stolen[1] == 0xD8);
                int is_png  = (slen >= 8 && stolen[0] == 0x89 && stolen[1] == 0x50
                               && stolen[2] == 0x4E && stolen[3] == 0x47);
                LOG_INF("[FA] frame type=%c size=%zu %s first4=0x%02x%02x%02x%02x",
                        ftype ? ftype : '?', slen,
                        is_jpeg ? "JPEG" : is_png ? "PNG " : "INVALID",
                        stolen[0],stolen[1],stolen[2],stolen[3]);
                /* Receiver-side ground truth: arrival time + size per delivered
                 * frame. goodput = Σbytes/time; interruption = gaps in t_us.
                 * Send-side qlog over-counts frames pushed into a dead path
                 * during a coverage gap; this counts only what actually arrived. */
                fa_rx_qlog(ftype, slen);
                if (is_jpeg || is_png) save_frame_take(app, stolen, slen, ftype);
                else free(stolen);
                rx_clear(rx);
                frames++;
                continue;
            }
        }

        if (!progressed) break;
    }

    return 0;
}
