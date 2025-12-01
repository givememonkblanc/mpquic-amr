#ifndef APP_CTX_SERVER_H
#define APP_CTX_SERVER_H

#include <stddef.h>

#ifndef OUT_DIR_MAX
#define OUT_DIR_MAX 512
#endif

/* ---- Limits ---- */
#ifndef MAX_STREAMS
#define MAX_STREAMS 16
#endif
#ifndef MAX_FRAME_SIZE
#define MAX_FRAME_SIZE ((size_t)(10ULL * 1024ULL * 1024ULL))
#endif
#ifndef OUT_DIR_MAX
#define OUT_DIR_MAX 512
#endif
#ifndef AUTHORITY_MAX
#define AUTHORITY_MAX 128
#endif
#ifndef PATH_MAX_WT
#define PATH_MAX_WT 256
#endif
#ifndef MAX_APP_PATHS
#define MAX_APP_PATHS 16
#endif

typedef enum {
    RX_WANT_LEN = 0,
    RX_WANT_PAYLOAD = 1,
    RX_RESYNC_JPEG = 2,
} rx_state_e;


typedef struct rx_stream_s {
    int      in_use;
    uint64_t sid;
    rx_state_e st;
    uint8_t  len_buf[8];
    size_t   len_got;
    uint64_t frame_size;
    uint64_t received;
    uint8_t* buf;
    size_t   cap;
    int      frame_no;
    int      in_jpeg;
    uint8_t  last_b;
    uint64_t seq;
    uint8_t   hdr_buf[16];   /* VarInt는 최대 8바이트지만 여유있게 */
    size_t    hdr_len;       /* 현재까지 누적된 헤더 바이트 수 */
} rx_stream_t;

typedef struct {
    char     out_dir[256];
    int      frame_count;
    int      max_frames;           /* 0이면 무제한 */
    rx_stream_t rx[MAX_STREAMS];   /* 스트림별 수신 상태 */
    /* ▼ 진행/백로그 관찰용(새 필드) */
    uint64_t   bytes_rx_total;       /* 총 수신 바이트 */
    uint64_t   backlog_bytes;        /* 대략적 저장 대기용 추적(원하면 사용) */
    uint64_t frame_idx;
    uint64_t bytes_saved_total;
} app_ctx_t;





#endif /* APP_CTX_SERVER_H */

