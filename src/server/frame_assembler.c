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

/* [저장 작업 큐 설정] */
#ifndef SAVEQ_MAX
#  define SAVEQ_MAX 4096      /* 큐 최대 크기 (메모리 상황에 따라 조절) */
#endif
#ifndef SAVE_POP_BATCH
#  define SAVE_POP_BATCH 128   /* 한 번에 처리할 최대 프레임 수 */
#endif

typedef struct {
    app_ctx_t* app;
    uint8_t* buf;
    size_t len;
    char frame_type;     /* 'd'=depth PNG, 'r'=RGB JPEG */
} save_job_t;

typedef struct {
    save_job_t q[SAVEQ_MAX];
    int h, t, n;              /* head, tail, count */
    pthread_mutex_t m;
    pthread_cond_t cv;
    int inited;
    int started;
} saveq_t;

static saveq_t g_saveq;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static FILE* g_preview_fp = NULL;
static int g_preview_enabled = 0;
static int g_save_frames_enabled = 1;

static int env_flag_enabled(const char* name, int default_value){
    const char* v = getenv(name);
    if (!v || !*v) return default_value;
    if (strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "off") == 0) return 0;
    return 1;
}


/* ============================================================
 * [3] 내부 유틸리티 및 초기화 함수
 * ============================================================ */

static void* save_worker(void*);
static int saveq_push_take(app_ctx_t*, uint8_t*, size_t, char);

static void ensure_dir(const char* d){
    if (!d || !*d) return;
    struct stat st;
    if (stat(d, &st) == 0) return;
    mkdir(d, 0755);
}

static void saveq_init_once(void){
    memset(&g_saveq, 0, sizeof(g_saveq));
    pthread_mutex_init(&g_saveq.m, NULL);
    pthread_cond_init(&g_saveq.cv, NULL);
    g_saveq.inited = 1;

    g_save_frames_enabled = env_flag_enabled("SVR_SAVE_FRAMES", 1);
    g_preview_enabled = env_flag_enabled("SVR_PREVIEW", 0);

    if (g_preview_enabled) {
        const char* cmd = getenv("SVR_PREVIEW_CMD");
        if (!cmd || !*cmd) {
            cmd = "ffplay -loglevel warning -fflags nobuffer -flags low_delay -framedrop -window_title MPQUIC-Preview -f mjpeg -i -";
        }

        signal(SIGPIPE, SIG_IGN);
        g_preview_fp = popen(cmd, "w");
        if (!g_preview_fp) {
            LOG_ERR("[PREVIEW] failed to start preview command: %s", cmd);
            g_preview_enabled = 0;
        } else {
            setvbuf(g_preview_fp, NULL, _IONBF, 0);
            LOG_INF("[PREVIEW] enabled via command: %s", cmd);
        }
    }

    if (!g_save_frames_enabled) {
        LOG_INF("[PREVIEW] disk frame saving disabled (SVR_SAVE_FRAMES=0)");
    }
}

/**
 * @brief 디스크 저장 전담 워커 스레드를 시작합니다.
 */
static void maybe_start_worker(void){
    if (!g_saveq.inited) pthread_once(&g_once, saveq_init_once);
    if (!g_saveq.started) {
        g_saveq.started = 1;
        pthread_t th;
        if (pthread_create(&th, NULL, save_worker, NULL) == 0)
            pthread_detach(th);
    }
}


/* ============================================================
 * [4] Depth PNG → colormap JPEG 변환 (preview sink 용)
 * ============================================================ */

static int is_png_data(const uint8_t* buf, size_t len){
    static const unsigned char png_sig[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (len < 8) return 0;
    return memcmp(buf, png_sig, 8) == 0;
}

/* ── PNG read callback (libpng memory I/O) ──────────────────── */
struct png_mem_io { const uint8_t* d; size_t s; size_t p; };
static void png_mem_read_fn(png_structp p, png_bytep o, png_size_t n){
    struct png_mem_io* m = (struct png_mem_io*)png_get_io_ptr(p);
    size_t avail = m->s - m->p;
    if (n > avail) n = avail;
    memcpy(o, m->d + m->p, n);
    m->p += n;
}

/* ── qsort comparator for uint16_t ──────────────────────────── */
static int cmp_u16(const void* a, const void* b){
    uint16_t va = *(const uint16_t*)a;
    uint16_t vb = *(const uint16_t*)b;
    return (va > vb) - (va < vb);
}

/**
 * Parse a 16-bit grayscale PNG from memory, apply a jet colormap,
 * and JPEG-encode the result into a heap buffer.
 *
 * Returns a malloc'd buffer holding the JPEG data (set *out_len),
 * or NULL on failure. Caller must free().
 */
static uint8_t* depth_png_to_preview_jpeg(const uint8_t* png_data, size_t png_len,
                                           size_t* out_len) {
    *out_len = 0;

    /* ── libpng: read from memory ──────────────────────── */
    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                              NULL, NULL, NULL);
    if (!png) return NULL;
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); return NULL; }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        return NULL;
    }

    struct png_mem_io io = {png_data, png_len, 0};
    png_set_read_fn(png, &io, png_mem_read_fn);

    png_read_info(png, info);
    int w = (int)png_get_image_width(png, info);
    int h = (int)png_get_image_height(png, info);
    int bit_depth = png_get_bit_depth(png, info);
    int color_type = png_get_color_type(png, info);

    /* Convert to 16-bit grayscale if needed */
    if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
        color_type == PNG_COLOR_TYPE_RGB_ALPHA)
        png_set_strip_alpha(png);
    if (bit_depth < 8) png_set_packing(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 16) png_set_expand_gray_1_2_4_to_8(png);
    /* If it's already 16-bit gray, keep it — we want the full precision */
    png_read_update_info(png, info);

    int row_bytes = (int)png_get_rowbytes(png, info);
    int channels = (int)png_get_channels(png, info);

    /* Allocate rows and read */
    uint8_t** rows = (uint8_t**)malloc(sizeof(uint8_t*) * (size_t)h);
    for (int y = 0; y < h; y++) rows[y] = (uint8_t*)malloc((size_t)row_bytes);
    png_read_image(png, rows);
    png_read_end(png, NULL);
    png_destroy_read_struct(&png, &info, NULL);

    /* ── Normalize 16-bit → 8-bit (robust percentile) ──── */
    int is_16bit = (bit_depth == 16 && channels == 1);
    uint8_t* gray8 = (uint8_t*)malloc((size_t)(w * h));
    uint16_t vmin = 0, vmax = 65535;

    if (is_16bit) {
        /* Gather all valid (>0) samples */
        uint16_t* samples = (uint16_t*)malloc(sizeof(uint16_t) * (size_t)(w * h));
        int n_valid = 0;
        for (int y = 0; y < h; y++) {
            uint16_t* row = (uint16_t*)rows[y];
            for (int x = 0; x < w; x++) {
                uint16_t v = row[x];
                if (v > 0) samples[n_valid++] = v;
            }
        }
        if (n_valid > 0) {
            qsort(samples, (size_t)n_valid, sizeof(uint16_t), cmp_u16);
            vmin = samples[n_valid / 50];       /*  2nd percentile */
            vmax = samples[(n_valid * 49) / 50]; /* 98th percentile */
            if (vmax <= vmin) vmax = vmin + 1;
            /* Normalize */
            float scale = 255.0f / (float)(vmax - vmin);
            for (int i = 0; i < w * h; i++) {
                uint16_t v = samples[i];
                int u8 = (v <= vmin) ? 0 : (int)((v - vmin) * scale);
                if (u8 > 255) u8 = 255;
                gray8[i] = (uint8_t)u8;
            }
        }
        free(samples);
    } else {
        /* 8-bit gray — direct copy */
        for (int y = 0; y < h; y++)
            memcpy(gray8 + y * w, rows[y], (size_t)w);
    }

    /* Free PNG rows */
    for (int y = 0; y < h; y++) free(rows[y]);
    free(rows);

    /* ── Apply jet colormap ────────────────────────────── */
    static uint8_t jet_r[256], jet_g[256], jet_b[256];
    static int jet_init = 0;
    if (!jet_init) {
        for (int i = 0; i < 256; i++) {
            float x = i / 255.0f;
            if (x < 0.125f) {
                jet_r[i] = 0;
                jet_g[i] = 0;
                jet_b[i] = (uint8_t)((x / 0.125f) * 255.0f);
            } else if (x < 0.375f) {
                float t = (x - 0.125f) / 0.25f;
                jet_r[i] = (uint8_t)(t * 255.0f);
                jet_g[i] = (uint8_t)(t * 255.0f);
                jet_b[i] = 255;
            } else if (x < 0.625f) {
                float t = (0.625f - x) / 0.25f;
                jet_r[i] = 255;
                jet_g[i] = 255;
                jet_b[i] = (uint8_t)(t * 255.0f);
            } else if (x < 0.875f) {
                float t = (0.875f - x) / 0.25f;
                jet_r[i] = (uint8_t)(t * 255.0f);
                jet_g[i] = (uint8_t)(t * 255.0f);
                jet_b[i] = 0;
            } else {
                jet_r[i] = 0;
                jet_g[i] = 0;
                jet_b[i] = 0;
            }
        }
        jet_init = 1;
    }

    uint8_t* rgb = (uint8_t*)malloc(sizeof(uint8_t) * (size_t)(w * h * 3));
    for (int i = 0; i < w * h; i++) {
        int idx = gray8[i];
        rgb[i * 3 + 0] = jet_r[idx];
        rgb[i * 3 + 1] = jet_g[idx];
        rgb[i * 3 + 2] = jet_b[idx];
    }
    free(gray8);

    /* ── libjpeg: encode RGB → JPEG in memory ─────────── */
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);

    unsigned long jpg_size = 0;
    uint8_t* jpg_data = NULL;
    jpeg_mem_dest(&cinfo, &jpg_data, &jpg_size);

    cinfo.image_width = w;
    cinfo.image_height = h;
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 85, TRUE);
    jpeg_start_compress(&cinfo, TRUE);

    uint8_t* row_ptrs[1];
    for (int y = 0; y < h; y++) {
        row_ptrs[0] = rgb + y * w * 3;
        jpeg_write_scanlines(&cinfo, row_ptrs, 1);
    }
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    free(rgb);

    *out_len = (size_t)jpg_size;
    return jpg_data;  /* caller must free */
}


/* ============================================================
 * [5] 디스크 저장 워커 로직
 * ============================================================ */

static void* save_worker(void* arg){
    (void)arg;
    save_job_t batch[SAVE_POP_BATCH];

    for(;;){
        int k = 0;

        /* 1) 큐에서 일괄(Batch)로 작업 뽑기 */
        pthread_mutex_lock(&g_saveq.m);
        while (g_saveq.n == 0) {
            pthread_cond_wait(&g_saveq.cv, &g_saveq.m);
        }

        while (g_saveq.n > 0 && k < SAVE_POP_BATCH) {
            batch[k++] = g_saveq.q[g_saveq.h];
            g_saveq.h = (g_saveq.h + 1) % SAVEQ_MAX;
            g_saveq.n--;
        }
        pthread_mutex_unlock(&g_saveq.m);

        /* 2) 뽑힌 작업들을 디스크에 순차 기록 */
        for (int i = 0; i < k; i++) {
            save_job_t job = batch[i];

            if (!job.app || !job.buf || job.len == 0) {
                if (job.buf) free(job.buf);
                continue;
            }

            ensure_dir(job.app->out_dir);

            /* Monotonic per-frame serial. The old scheme (frame_pair_idx+1,
             * advanced only on RGB completion) overwrote frame_000001_d every
             * time RGB stalled/starved — depth got clobbered. Every completed
             * frame now gets its own serial. */
            int idx = job.app->frame_count + 1;
            int frame_completed = 0;

            int is_png = is_png_data(job.buf, job.len);
            char type_char = job.frame_type ? job.frame_type : (is_png ? 'd' : 'r');

            if (g_preview_enabled && g_preview_fp) {
                /* For PNG (depth) data, convert to colormap JPEG for preview */
                size_t preview_len = 0;
                uint8_t* preview_buf = NULL;
                if (is_png) {
                    preview_buf = depth_png_to_preview_jpeg(job.buf, job.len, &preview_len);
                }

                const void* write_buf = preview_buf ? preview_buf : job.buf;
                size_t write_len = preview_buf ? preview_len : job.len;

                size_t nw = fwrite(write_buf, 1, write_len, g_preview_fp);
                if (preview_buf) free(preview_buf);

                if (nw == write_len) {
                    frame_completed = 1;
                } else {
                    LOG_WRN("[PREVIEW] preview sink write failed; disabling preview");
                    pclose(g_preview_fp);
                    g_preview_fp = NULL;
                    g_preview_enabled = 0;
                }
            }

            if (g_save_frames_enabled) {
                char tmp[512], dst[512];

                const char* ext = (type_char == 'd') ? "png" : "jpg";
                snprintf(tmp, sizeof(tmp), "%s/frame_%06d_%c.part", job.app->out_dir, idx, type_char);
                snprintf(dst, sizeof(dst), "%s/frame_%06d_%c.%s",  job.app->out_dir, idx, type_char, ext);

                FILE* f = fopen(tmp, "wb");
                if (!f) {
                    free(job.buf);
                    continue;
                }

                size_t nw = fwrite(job.buf, 1, job.len, f);
                fclose(f);

                if (nw == job.len && rename(tmp, dst) == 0) {
                    frame_completed = 1;
                    job.app->bytes_saved_total += job.len;
                }
            }

            if (frame_completed) {
                job.app->frame_count = idx;      /* advance monotonic serial */
                job.app->frame_pair_idx = idx;   /* kept in sync for any readers */
            }
            free(job.buf);
        }
    }
    return NULL;
}

/**
 * @brief 버퍼의 소유권을 가져와 저장 큐에 추가합니다.
 */
static int saveq_push_take(app_ctx_t* app, uint8_t* buf, size_t len, char frame_type){
    if (!g_saveq.inited) pthread_once(&g_once, saveq_init_once);

    pthread_mutex_lock(&g_saveq.m);
    
    /* 큐가 가득 찼다면 가장 오래된 데이터 드랍 */
    if (g_saveq.n == SAVEQ_MAX) {
        save_job_t old = g_saveq.q[g_saveq.h];
        g_saveq.h = (g_saveq.h + 1) % SAVEQ_MAX;
        g_saveq.n--;
        if (old.buf) free(old.buf);
    }

    g_saveq.q[g_saveq.t] = (save_job_t){app, buf, len, frame_type};
    g_saveq.t = (g_saveq.t + 1) % SAVEQ_MAX;
    g_saveq.n++;
    
    pthread_cond_signal(&g_saveq.cv);
    pthread_mutex_unlock(&g_saveq.m);
    return 0;
}

int save_frame(app_ctx_t* app, const uint8_t* data, size_t len, char frame_type){
    if (!app || !data || len == 0) return -1;
    maybe_start_worker();

    uint8_t* cp = malloc(len);
    if (!cp) return -1;
    memcpy(cp, data, len);
    return saveq_push_take(app, cp, len, frame_type);
}

static int save_frame_take(app_ctx_t* app, uint8_t* take, size_t len, char frame_type){
    if (!app || !take || len == 0) return -1;
    maybe_start_worker();
    return saveq_push_take(app, take, len, frame_type);
}


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
 * Frame format:
 *   [4 bytes: magic "MPQ1"]
 *   [4 bytes: frame_len (big-endian uint32)]
 *   [frame_len bytes: JPEG data]
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
 * @brief 수신된 바이트 열을 프레임으로 조립하는 메인 로직입니다.
 *
 * Frame format: [4B magic "MPQ1"] [4B big-endian length] [length B JPEG data]
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
