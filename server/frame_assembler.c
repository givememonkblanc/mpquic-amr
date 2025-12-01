// frame_assembler.c — Drop-in: MP-QUIC Safe RX Assembler + Async Disk Writer

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>

#include "picoquic.h"
#include "frame_assembler.h"
#include "app_ctx.h"

// ===== Logging =====
#ifndef LOG_INF
#  define LOG_INF(fmt, ...) fprintf(stderr, "[INF] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_WRN
#  define LOG_WRN(fmt, ...) fprintf(stderr, "[WRN] " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef LOG_ERR
#  define LOG_ERR(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#endif

// ===== Tunables =====
#ifndef MAX_FRAME_SIZE
#  define MAX_FRAME_SIZE (10*1024*1024)
#endif
#ifndef MAX_STREAMS
#  define MAX_STREAMS 128
#endif
#ifndef HDR_MAX
#  define HDR_MAX 8
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



// ===== RX bank =====
typedef struct {
    rx_stream_t rx[MAX_STREAMS];
} rx_bank_t;

static rx_bank_t g_bank;

// ===== save queue =====

#ifndef SAVEQ_MAX
#  define SAVEQ_MAX 4096      // 2048보다 조금 더 여유, Pi 메모리 보면서 조절
#endif

#ifndef SAVE_POP_BATCH
#  define SAVE_POP_BATCH 128   // 한 번에 최대 32프레임씩 처리
#endif

typedef struct {
    app_ctx_t* app;
    uint8_t* buf;
    size_t len;
} save_job_t;

typedef struct {
    save_job_t q[SAVEQ_MAX];
    int h, t, n;
    pthread_mutex_t m;
    pthread_cond_t cv;
    int inited;
    int started;
} saveq_t;

static saveq_t g_saveq;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

// ===== Forward decl =====
static void* save_worker(void*);
static int saveq_push_take(app_ctx_t*, uint8_t*, size_t);

// ===== Utility =====
static void ensure_dir(const char* d){
    if (!d || !*d) return;
    struct stat st;
    if (stat(d, &st) == 0) return;
    mkdir(d, 0755);
}

static void saveq_init_once(void){
    memset(&g_saveq, 0, sizeof(g_saveq));
    pthread_mutex_init(&g_saveq.m,NULL);
    pthread_cond_init(&g_saveq.cv,NULL);
    g_saveq.inited = 1;
}

static void maybe_start_worker(void){
    if (!g_saveq.inited) pthread_once(&g_once, saveq_init_once);
    if (!g_saveq.started) {
        g_saveq.started = 1;
        pthread_t th;
        if (pthread_create(&th, NULL, save_worker, NULL)==0)
            pthread_detach(th);
    }
}

static void* save_worker(void* arg){
    (void)arg;

    save_job_t batch[SAVE_POP_BATCH];

    for(;;){
        int k = 0;

        // ---- 1) 큐에서 최대 SAVE_POP_BATCH개까지 뽑기 ----
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

        // ---- 2) 잡들 실제로 디스크 쓰기 ----
        for (int i = 0; i < k; i++) {
            save_job_t job = batch[i];

            if (!job.app || !job.buf || job.len == 0) {
                if (job.buf) free(job.buf);
                continue;
            }

            ensure_dir(job.app->out_dir);

            int idx = job.app->frame_count + 1;
            char tmp[512], dst[512];

            // 굳이 .part/rename이 필요없으면 이 부분 간소화도 가능
            snprintf(tmp, sizeof(tmp), "%s/frame_%06d.part", job.app->out_dir, idx);
            snprintf(dst, sizeof(dst), "%s/frame_%06d.jpg",  job.app->out_dir, idx);

            FILE* f = fopen(tmp, "wb");
            if (!f) {
                free(job.buf);
                continue;
            }

            // 배치 처리하므로 setvbuf는 오히려 안 써도 됨 (Pi 환경이면 이 부분은 취향)
            size_t w = fwrite(job.buf, 1, job.len, f);
            fclose(f);

            if (w == job.len && rename(tmp, dst) == 0) {
                job.app->frame_count = idx;
                job.app->bytes_saved_total += job.len;
            }
            free(job.buf);
        }
    }
    return NULL;
}

static int saveq_push_take(app_ctx_t* app, uint8_t* buf, size_t len){
    if (!g_saveq.inited) pthread_once(&g_once, saveq_init_once);

    pthread_mutex_lock(&g_saveq.m);
    if (g_saveq.n == SAVEQ_MAX) {
        save_job_t old = g_saveq.q[g_saveq.h];
        g_saveq.h = (g_saveq.h + 1) % SAVEQ_MAX;
        g_saveq.n--;
        if (old.buf) free(old.buf);
    }

    g_saveq.q[g_saveq.t] = (save_job_t){app,buf,len};
    g_saveq.t = (g_saveq.t + 1) % SAVEQ_MAX;
    g_saveq.n++;
    pthread_cond_signal(&g_saveq.cv);
    pthread_mutex_unlock(&g_saveq.m);
    return 0;
}

int save_frame(app_ctx_t* app, const uint8_t* data, size_t len){
    if (!app||!data||len==0) return -1;
    maybe_start_worker();

    uint8_t* cp = malloc(len);
    if (!cp) return -1;
    memcpy(cp,data,len);
    return saveq_push_take(app,cp,len);
}

static int save_frame_take(app_ctx_t* app, uint8_t* take, size_t len){
    if (!app||!take||len==0) return -1;
    maybe_start_worker();
    return saveq_push_take(app,take,len);
}

// ===== RX helpers =====
void rx_clear(rx_stream_t* rx){
    rx->st = RX_WANT_LEN;
    rx->len_got = 0;
    rx->frame_size = 0;
    rx->received = 0;
    rx->in_jpeg = 0;
    rx->last_b = 0;
}

static rx_stream_t* rx_get(app_ctx_t* app, uint64_t sid){
    (void)app;
    for (int i=0;i<MAX_STREAMS;i++){
        if (g_bank.rx[i].in_use && g_bank.rx[i].sid==sid)
            return &g_bank.rx[i];
    }
    for (int i=0;i<MAX_STREAMS;i++){
        if (!g_bank.rx[i].in_use){
            rx_stream_t* rx=&g_bank.rx[i];
            memset(rx,0,sizeof(*rx));
            rx->in_use=1;
            rx->sid=sid;
            rx->st=RX_WANT_LEN;
            return rx;
        }
    }
    return NULL;
}

static int ensure_cap(rx_stream_t* rx, size_t need){
    if (need > MAX_FRAME_SIZE) return -1;
    if (rx->cap >= need) return 0;

    size_t nc = (rx->cap?rx->cap:4096);
    while (nc < need){
        if (nc > MAX_FRAME_SIZE/2){ nc = need; break; }
        nc <<= 1;
    }

    uint8_t* nb = realloc(rx->buf,nc);
    if (!nb) return -1;
    rx->buf=nb; rx->cap=nc;
    return 0;
}

// ===== varint decode =====
static size_t quic_varint_decode(const uint8_t* in, size_t len, uint64_t* v){
    if (!in||!v||len==0) return 0;
    uint8_t b0=in[0];
    uint8_t pf=b0>>6;
    size_t n=1ull<<pf;
    if (len<n) return 0;

    uint64_t x=0;
    switch (n){
        case 1: x = (b0 & 0x3F); break;
        case 2: x = ((uint64_t)(b0&0x3F)<<8)|in[1]; break;
        case 4: x = ((uint64_t)(b0&0x3F)<<24)|((uint64_t)in[1]<<16)
                   |((uint64_t)in[2]<<8)|in[3]; break;
        case 8:
            x=((uint64_t)(b0&0x3F)<<56)|((uint64_t)in[1]<<48)|((uint64_t)in[2]<<40)
             |((uint64_t)in[3]<<32)|((uint64_t)in[4]<<24)|((uint64_t)in[5]<<16)
             |((uint64_t)in[6]<<8)|in[7];
            break;
        default: return 0;
    }

    if ((n==2 && x<(1ull<<6))||(n==4&&x<(1ull<<14))||(n==8&&x<(1ull<<30)))
        return 0;

    *v=x;
    return n;
}

static int rx_try_parse_len(rx_stream_t* rx, const uint8_t** pp, const uint8_t* pmax){
    const uint8_t* p=*pp;

    while (rx->len_got < HDR_MAX && p<pmax){
        rx->len_buf[rx->len_got++] = *p++;
        uint64_t dummy; size_t used = quic_varint_decode(rx->len_buf,rx->len_got,&dummy);
        if (used>0) break;
    }

    uint64_t sz=0; size_t used=quic_varint_decode(rx->len_buf,rx->len_got,&sz);
    if (used==0){ *pp=p; return 0; }

    if (sz==0 || sz>MAX_FRAME_SIZE){
        if (p<pmax) p++;
        *pp=p;
        rx_clear(rx);
        rx->st=RX_RESYNC_JPEG;
        return -2;
    }

    rx->frame_size = sz;

    size_t over = rx->len_got - used;
    p -= over;
    *pp=p;

    rx->len_got=0;
    return 1;
}

// ===== Tunables load =====
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

// ===== FC bump =====
static inline void fc_bump(picoquic_cnx_t* cnx, uint64_t sid, uint64_t used){
#ifdef picoquic_add_to_stream_window
    picoquic_add_to_stream_window(cnx,sid,used);
#else
    (void)cnx; (void)sid; (void)used;
#endif
}

// ===== API =====
void fa_stream_close(app_ctx_t* app, uint64_t sid){
    (void)app;
    for (int i=0;i<MAX_STREAMS;i++){
        rx_stream_t* rx=&g_bank.rx[i];
        if (rx->in_use && rx->sid==sid){
            if (rx->buf) free(rx->buf);
            memset(rx,0,sizeof(*rx));
            return;
        }
    }
}

void fa_reset(app_ctx_t* app){
    (void)app;
    for (int i=0;i<MAX_STREAMS;i++){
        rx_stream_t* rx=&g_bank.rx[i];
        if (rx->buf) free(rx->buf);
    }
    memset(&g_bank,0,sizeof(g_bank));
}

// ===== Core RX Logic =====
int fa_on_bytes(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t sid,
                const uint8_t* bytes, size_t length)
{
    fa_tunables_init_once();

    const uint8_t* p=bytes;
    const uint8_t* pmax=bytes+length;

    rx_stream_t* rx=rx_get(app,sid);
    if (!rx) return -1;

    picoquic_quic_t* quic= cnx ? picoquic_get_quic_ctx(cnx):NULL;
    uint64_t start_us= quic ? picoquic_get_quic_time(quic) : 0;

    size_t steps=0,copied=0,frames=0;

    while (p<pmax){
        if (steps++ >= T_MAX_RX_STEPS) break;
        if (copied >= T_MAX_RX_BYTES) break;
        if (frames >= T_MAX_FRAMES_CB) break;

        if (quic){
            uint64_t now=picoquic_get_quic_time(quic);
            if (T_MAX_TIME_US>0 && now-start_us >= T_MAX_TIME_US) break;
        }

        int progressed=0;

        // ----- 1) parse length -----
        if (rx->st==RX_WANT_LEN){
            int r=rx_try_parse_len(rx,&p,pmax);
            if (r==0) break;
            if (r==-2){ progressed=1; continue; }

            if (ensure_cap(rx,rx->frame_size)!=0){
                rx_clear(rx);
                continue;
            }
            rx->received=0;
            rx->st=RX_WANT_PAYLOAD;
            progressed=1;
            continue;
        }

        // ----- 2) copy payload -----
        if (rx->st==RX_WANT_PAYLOAD){
            uint64_t left64 = rx->frame_size - rx->received;
            if (left64==0){
                rx_clear(rx);
                rx->st=RX_WANT_LEN;
                continue;
            }

            size_t avail=(size_t)(pmax-p);
            size_t left=(size_t)((left64>SIZE_MAX)?SIZE_MAX:left64);
            size_t to_do = (avail<left?avail:left);
            if (to_do==0) break;

            if (ensure_cap(rx, rx->received+to_do)!=0){
                rx_clear(rx);
                continue;
            }

            memcpy(rx->buf + rx->received, p,to_do);
            rx->received += to_do;
            p += to_do;
            copied += to_do;
            progressed=1;

            if (cnx) fc_bump(cnx,sid,to_do);

            if (rx->received >= rx->frame_size){
                uint8_t* stolen=rx->buf;
                size_t slen=rx->frame_size;
                rx->buf=NULL; rx->cap=0;
                rx_clear(rx);

                save_frame_take(app,stolen,slen);
                frames++;
                continue;
            }
        }

        // ----- 3) JPEG resync -----
        if (rx->st==RX_RESYNC_JPEG){
            size_t scanned=0,limit=4096;
            while (p<pmax && scanned<limit){
                uint8_t c=*p++; scanned++; progressed=1;

                if (!rx->in_jpeg){
                    if (rx->last_b==0xFF && c==0xD8){
                        rx->in_jpeg=1;
                        rx->received=0;
                        ensure_cap(rx,2);
                        rx->buf[0]=0xFF; rx->buf[1]=0xD8;
                        rx->received=2;
                        rx->last_b=0;
                        continue;
                    }
                    rx->last_b=c;
                } else {
                    ensure_cap(rx,rx->received+1);
                    rx->buf[rx->received++] = c;

                    if (rx->last_b==0xFF && c==0xD9){
                        save_frame_take(app,rx->buf,rx->received);
                        rx->buf=NULL; rx->cap=0;
                        rx_clear(rx);
                        rx->st=RX_WANT_LEN;
                        frames++;
                        break;
                    }
                    rx->last_b=c;
                }
            }
        }

        if (!progressed) break;
    }

    return 0;
}
