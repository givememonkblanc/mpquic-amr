#ifndef APP_CTX_SERVER_H
#define APP_CTX_SERVER_H

#include <stddef.h>

/* ============================================================
 * [1] 시스템 제한 및 설정 상수
 * ============================================================ */

#ifndef OUT_DIR_MAX
#define OUT_DIR_MAX 512
#endif

#ifndef MAX_STREAMS
#define MAX_STREAMS 128  /* max concurrent reassembly slots (dual-stream × paths).
                          * Single source of truth — frame_assembler.c's g_bank
                          * relies on this; a smaller value silently drops streams. */
#endif

#ifndef MAX_FRAME_SIZE
#define MAX_FRAME_SIZE ((size_t)(10ULL * 1024ULL * 1024ULL)) /* 최대 프레임 크기 (10MB) */
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


/* ============================================================
 * [2] 데이터 수신 상태 머신 (State Machine) 정의
 * ============================================================ */

/**
 * @brief 스트림으로부터 바이트를 읽을 때 현재 어떤 부분을 기다리는지 나타냅니다.
 */
typedef enum {
    RX_WANT_MAGIC = 0,    /* 4-byte magic "MPQ1" 찾는 중 */
    RX_WANT_TYPE = 1,     /* 1-byte frame type ('d'=depth, 'r'=RGB) 읽는 중 */
    RX_WANT_LEN = 2,      /* 4-byte frame length 읽는 중 */
    RX_WANT_PAYLOAD = 3,  /* 프레임 데이터(Payload)를 읽는 중 */
} rx_state_e;

/* 매직 바이트: "MPQ1" */
#define FRAME_MAGIC_B0 0x4D  /* 'M' */
#define FRAME_MAGIC_B1 0x50  /* 'P' */
#define FRAME_MAGIC_B2 0x51  /* 'Q' */
#define FRAME_MAGIC_B3 0x31  /* '1' */

/* ============================================================
 * [3] 스트림 및 애플리케이션 컨텍스트 구조체
 * ============================================================ */

/**
 * @brief 개별 스트림(sid)별 수신 상태를 관리하는 구조체입니다.
 */
typedef struct rx_stream_s {
    int      in_use;         /* 현재 이 슬롯이 사용 중인지 여부 */
    uint64_t sid;            /* QUIC 스트림 ID */
    rx_state_e st;           /* 현재 수신 상태 */
    
    /* Magic 검출 상태 */
    int      magic_matched;  /* 지금까지 일치한 매직 바이트 수 (0-4) */
    
    /* 길이 파싱용 버퍼 */
    uint8_t  len_buf[4];     /* 4-byte 빅엔디안 프레임 길이 */
    int      len_got;        /* len_buf에 채워진 바이트 수 */
    
    /* 프레임 조립 정보 */
    uint64_t frame_size;     /* 파싱된 현재 프레임의 전체 크기 */
    uint64_t received;       /* 현재까지 수신 완료된 데이터 크기 */
    uint8_t* buf;            /* 데이터가 저장되는 실제 버퍼 포인터 */
    size_t   cap;            /* 현재 할당된 버퍼의 총 용량 */
    
    /* 프레임 타입 ('d'=depth PNG, 'r'=RGB JPEG) */
    char     frame_type;

    /* 통계 */
    int      frame_no;       /* 스트림 내 프레임 순번 */
} rx_stream_t;

/**
 * @brief 서버 애플리케이션의 전체 상태를 관리하는 최상위 구조체입니다.
 */
typedef struct {
    /* 파일 저장 및 출력 설정 */
    char     out_dir[256];   /* 프레임이 저장될 디렉토리 경로 */
    int      frame_count;    /* 현재까지 수신 완료된 총 프레임 수 */
    int      max_frames;     /* 수신할 최대 프레임 제한 (0이면 무제한) */
    
    /* 스트림별 상태 배열 */
    rx_stream_t rx[MAX_STREAMS];   

    /* 통계 및 모니터링 필드 */
    uint64_t   bytes_rx_total;     /* 네트워크로 수신한 총 바이트 수 */
    uint64_t   backlog_bytes;      /* 디스크 저장을 대기 중인 추정 데이터량 */
    uint64_t   frame_idx;          /* 저장 시 사용할 프레임 인덱스 (legacy) */
    uint64_t   bytes_saved_total;  /* 실제로 디스크에 기록 완료된 총 바이트 수 */
    int        frame_pair_idx;     /* 듀얼 스트림(frame_N_d/frame_N_r) 페어 인덱스 */


    // 벤치 마킹을 위해 추가한 변수들
    uint64_t start_time_us;      // 벤치마킹 시작 시간
    uint64_t last_frame_ts;      // 직전 프레임 수신 시간
    uint32_t dropped_frames;     // 드랍된 프레임 수

} app_ctx_t;




#endif /* APP_CTX_SERVER_H */