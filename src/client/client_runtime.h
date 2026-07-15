#ifndef CLIENT_RUNTIME_H
#define CLIENT_RUNTIME_H

#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "autoqlog.h"
#include "camera.h"
#include "picoquic.h"
#include "picoquic_binlog.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_utils.h"
#include "qlog.h"

#define LOGF(fmt, ...) fprintf(stderr, "[CLI] " fmt "\n", ##__VA_ARGS__)

#ifndef MAX_PATHS
#define MAX_PATHS 16
#endif

/* Camera type indices for dual-stream */
#define CAM_DEPTH 0
#define CAM_RGB   1
#define NUM_CAMS  2

/* Forward declaration — qlog_t defined in client_qlogger.h */
typedef struct qlog_t qlog_t;

typedef struct {
    uint64_t sid;
    int ready;
} bind_t;

typedef enum {
    scheduler_mode_pqi = 0,              /* legacy/compared: PQI composite cost      */
    scheduler_mode_rssi = 1,             /* PROPOSED: RSSI-aware (clean, PQI-free)    */
    scheduler_mode_default = 2,          /* baseline: min-RTT (picoquic native)       */
    scheduler_mode_spquic_migration = 3, /* baseline: SP-QUIC + connection migration   */
    scheduler_mode_round_robin = 4,      /* baseline: round-robin                      */
    scheduler_mode_ecf = 5,              /* baseline (optional): Earliest Completion First */
    scheduler_mode_blest = 6,            /* baseline (optional): Blocking Estimation    */
    scheduler_mode_tof = 7               /* baseline (optional): Time-in-Flight         */
} scheduler_mode_t;

typedef struct {
    char server_ip[128];
    char primary_local_ip[64];
    char backup_local_ip[64];
    int port;
    scheduler_mode_t scheduler_mode;   /* parsed from MPQUIC_SCHED_MODE in client_options.c */
} client_options_t;

/*
 * Scheduler modes:
 *   scheduler_mode_pqi             = 0  — Proposed PQI-based scheduler
 *   scheduler_mode_rssi            = 1  — RSSI-aware variant (adds Wi-Fi RSSI penalty)
 *   scheduler_mode_default         = 2  — Baseline: picoquic default path selection (minRTT heuristic)
 *   scheduler_mode_spquic_migration = 3 — Baseline: single-path + QUIC connection migration (RFC 9000 §9)
 *
 * REVIEWER MAPPING:
 *   R1-#10 (missing baseline comparisons)   → modes 2 & 3
 *   R3-#4  (no comparison with std MP-QUIC) → mode 2
 *   R3-#5  (which MP-QUIC implementation)   → picoquic native default
 *   R2-#3  (handover vs failover clarity)   → mode 3 isolates SP-QUIC migration behavior
 */
/* scheduler_mode_t is defined above client_options_t (which now carries it). */

typedef struct {
    bind_t b[MAX_PATHS];
    picoquic_cnx_t* cnx;

    int peer_close_seen;
    int handshake_done;
    struct sockaddr_storage peerA;
    /* Optional distinct server address for the BACKUP path (env
     * MPQUIC_SERVER_IP2). Rationale (2026-07-13): the Jetson kernel is built
     * without CONFIG_IP_ADVANCED_ROUTER (no policy routing), so two paths to
     * ONE server address cannot be split by source IP — backup traffic slid
     * onto the Wi-Fi route and the "5G" path was never physically independent.
     * With per-path destinations, plain destination routing does the split:
     * primary → server LAN addr (connected route on Wi-Fi), backup → server
     * public addr (default route via the cellular tether). */
    struct sockaddr_storage peerB;
    int has_peerB;
    uint64_t ready_ts_us;

    struct sockaddr_storage primary_local;
    int has_primary_local;
    struct sockaddr_storage backup_local;
    int has_backup_local;

    camera_handle_t cam;
    uint8_t* cap_buf;
    size_t cap_cap;

    /* ── Dual-stream: RGB camera (depth uses generic `cam` above) ── */
    camera_handle_t cam_rgb;
    uint8_t* cap_buf_rgb;
    size_t cap_cap_rgb;

    uint8_t frame_hdr[9];           /* Extended header: 4B magic + 1B type + 4B len */
    uint8_t frame_hdr_rgb[9];       /* RGB frame header (type='r') */
    uint64_t sid_per_path[MAX_PATHS];
    uint64_t path_last_progress_us[MAX_PATHS];
    uint64_t path_last_delivered[MAX_PATHS];
    uint64_t path_last_received[MAX_PATHS];
    uint64_t path_last_packet_received_at[MAX_PATHS];

    /* PQI / RSSI state (used by scheduler_mode_pqi and scheduler_mode_rssi) */
    uint64_t pqi_score[MAX_PATHS];
    uint64_t pqi_rtt_ewma[MAX_PATHS];
    uint64_t pqi_loss_bp_ewma[MAX_PATHS];
    uint64_t pqi_bw_ewma[MAX_PATHS];
    uint64_t pqi_last_bytes_sent[MAX_PATHS];
    uint64_t pqi_last_bytes_lost[MAX_PATHS];
    /* Loss sampling window: per-tick deltas are accumulated here and the loss
     * EWMA only updates once enough bytes were sent for a meaningful ratio
     * (tiny/cumulative samples used to poison the EWMA → permanent grade 1). */
    uint64_t pqi_acc_sent[MAX_PATHS];
    uint64_t pqi_acc_lost[MAX_PATHS];
    uint8_t pqi_grade[MAX_PATHS];
    int path_rssi_dbm[MAX_PATHS];
    int path_rssi_ewma_dbm[MAX_PATHS];
    int wifi_last_rssi_dbm;
    scheduler_mode_t scheduler_mode;
    int pqi_last_choice;
    uint64_t pqi_last_switch_us;
    uint64_t pqi_choice_since_us;
    /* Anti-ping-pong: debounce doubles (up to a cap) each time a switch
     * reverses the previous one, and resets after a stable period. */
    uint64_t pqi_dyn_debounce_us;
    uint64_t last_rssi_sample_us;
    char wifi_ifname[32];

    /* QoS Logger (reviewer-required metrics collection) */
    qlog_t* qlog;

    /* Experiment control */
    uint64_t exp_start_wall_us;
    uint64_t exp_duration_us;
    int      exp_finished;   /* set when the experiment duration elapses = clean stop (no reconnect) */
    uint64_t total_frames_submitted;
    uint64_t frames_dropped_backpressure;  /* frames dropped by real-time backpressure guard */

    /* Verbose per-tick state logging is rate-limited to 1 Hz (the packet loop
     * ticks at kHz rates under load, which used to produce multi-GB logs). */
    uint64_t last_verbose_log_us;
    int      log_verbose;    /* 1 on the ticks where per-tick state may be logged */

    /* Connection creation time — drives the handshake watchdog (a dial that
     * cannot complete its handshake must fail fast so the supervisor retries). */
    uint64_t conn_created_us;

    /* ── Depth camera capture state (generic cam) ── */
    pthread_t cam_thread;
    pthread_mutex_t cam_mtx;
    int cam_thread_started;
    int cam_stop;

    uint8_t* cam_buf;
    size_t cam_cap;
    int cam_len;
    uint64_t cam_seq;
    uint64_t last_sent_seq;

    /* ── RGB camera capture state ── */
    pthread_t cam_thread_rgb;
    pthread_mutex_t cam_mtx_rgb;
    int cam_thread_rgb_started;

    uint8_t* cam_buf_rgb;
    size_t cam_cap_rgb;
    int cam_len_rgb;
    uint64_t cam_seq_rgb;
    uint64_t last_sent_seq_rgb;

    /* ── Frame pair counter (increments when both depth+RGB sent) ── */
    uint64_t frame_pair_idx;

    /* ── Per-path stream IDs for RGB stream ── */
    uint64_t sid_per_path_rgb[MAX_PATHS];

    uint32_t ip_primary_be;
    uint32_t ip_backup_be;

    uint64_t last_primary_probe_us;
    uint64_t last_backup_probe_us;
} tx_t;

int client_options_parse(int argc, char** argv, client_options_t* opts);

int resolve_ip(const char* host, int port, struct sockaddr_storage* out);
int store_local_ip(const char* ip, uint16_t port, struct sockaddr_storage* out);
int hs_done(picoquic_cnx_t* cnx, tx_t* st);

uint64_t make_client_uni_sid_from_index(int i);
int ensure_stream_for_path(picoquic_cnx_t* c, void* app_ctx, uint64_t* p_sid, int i);
int set_affinity_by_index(picoquic_cnx_t* c, uint64_t sid, int i);
void ensure_path0_alive(picoquic_cnx_t* c);
void kick_path_verification(picoquic_cnx_t* c, tx_t* st, int i);
int maybe_probe_desired_path(picoquic_cnx_t* c,
                             const struct sockaddr_storage* peer,
                             const struct sockaddr_storage* local,
                             int has_local,
                             uint64_t* last_probe_us,
                             uint64_t now);

int path_is_healthy(picoquic_cnx_t* c, tx_t* st, int i, uint64_t now);
uint64_t path_silence_us(const tx_t* st, int i, uint64_t now);

int client_cb(picoquic_cnx_t* cnx, uint64_t stream_id,
              uint8_t* bytes, size_t length,
              picoquic_call_back_event_t ev, void* ctx,
              void* stream_ctx);

#endif
