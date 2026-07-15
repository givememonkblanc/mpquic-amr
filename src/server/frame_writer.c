#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include "app_ctx.h"
#include "frame_assembler.h"
#include "depth_preview.h"
#include "frame_writer.h"

/*
 * Disk-save worker subsystem — async save queue + writer thread + optional
 * live preview sinks (depth colormap JPEG / RGB JPEG). Moved verbatim out of
 * frame_assembler.c (behaviour preserving). The RX core enqueues completed
 * frames via save_frame()/save_frame_take().
 */

#ifndef LOG_INF
#  define LOG_INF(fmt, ...) fprintf(stderr, "[INF] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_WRN
#  define LOG_WRN(fmt, ...) fprintf(stderr, "[WRN] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_ERR
#  define LOG_ERR(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#endif

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

static FILE* g_preview_fp = NULL;       /* depth sink (colormap JPEG) */
static FILE* g_preview_fp_rgb = NULL;   /* separate RGB sink (raw JPEG) — for dual HLS */
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
            LOG_INF("[PREVIEW] depth sink via command: %s", cmd);
        }

        /* Optional separate RGB sink. When set (e.g. a second ffmpeg→HLS encoder),
         * RGB frames go here instead of sharing the depth pipe, so depth and RGB
         * become two independent HLS streams. */
        const char* cmd_rgb = getenv("SVR_PREVIEW_CMD_RGB");
        if (cmd_rgb && *cmd_rgb) {
            g_preview_fp_rgb = popen(cmd_rgb, "w");
            if (!g_preview_fp_rgb) {
                LOG_ERR("[PREVIEW] failed to start RGB sink command: %s", cmd_rgb);
            } else {
                setvbuf(g_preview_fp_rgb, NULL, _IONBF, 0);
                LOG_INF("[PREVIEW] RGB sink via command: %s", cmd_rgb);
            }
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

/* Depth PNG→preview-JPEG conversion moved to depth_preview.c. */
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

            if (g_preview_enabled) {
                /* Route by type: RGB → its own sink if present, else the depth
                 * sink (backward compatible single-pipe preview). Depth PNG is
                 * converted to a colormap JPEG; RGB is already JPEG. */
                FILE* sink = (type_char == 'r' && g_preview_fp_rgb)
                                 ? g_preview_fp_rgb : g_preview_fp;
                if (sink) {
                    size_t preview_len = 0;
                    uint8_t* preview_buf = NULL;
                    if (is_png) {
                        preview_buf = depth_png_to_preview_jpeg(job.buf, job.len, &preview_len);
                    }

                    const void* write_buf = preview_buf ? preview_buf : job.buf;
                    size_t write_len = preview_buf ? preview_len : job.len;

                    size_t nw = fwrite(write_buf, 1, write_len, sink);
                    if (preview_buf) free(preview_buf);

                    if (nw == write_len) {
                        frame_completed = 1;
                    } else {
                        LOG_WRN("[PREVIEW] sink write failed (type=%c); disabling it", type_char);
                        pclose(sink);
                        if (sink == g_preview_fp_rgb) {
                            g_preview_fp_rgb = NULL;
                        } else {
                            g_preview_fp = NULL;
                            /* depth sink gone; RGB-only preview may still run */
                            if (!g_preview_fp_rgb) g_preview_enabled = 0;
                        }
                    }
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

int save_frame_take(app_ctx_t* app, uint8_t* take, size_t len, char frame_type){
    if (!app || !take || len == 0) return -1;
    maybe_start_worker();
    return saveq_push_take(app, take, len, frame_type);
}
