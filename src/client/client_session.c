#include "client_capture.h"
#include "client_session.h"
#include "client_qlogger.h"
#include <time.h>

/*
 * Scheduler mode selection via environment variable MPQUIC_SCHED_MODE.
 *
 * Values:
 *   "pqi"          — Proposed PQI-based scheduler (RTT/loss/BW EWMA + min-max normalization + hysteresis)
 *   "rssi"         — RSSI-aware variant (adds Wi-Fi RSSI penalty to PQI)
 *   "default"      — Baseline: picoquic native path selection (lowest-RTT-first among verified paths)
 *   "spquic"       — Baseline: single-path + QUIC connection migration (RFC 9000 §9)
 *                    Forces single-path usage; falls back to migration on primary path failure.
 *
 * Reviewer mapping:
 *   R1-#10 (baseline comparisons)  → "default" and "spquic" modes
 *   R3-#4  (std MP-QUIC compare)   → "default" mode uses picoquic's built-in scheduler
 *   R3-#5  (impl details)          → picoquic 1.1.50.3, MP-QUIC draft-ietf-quic-multipath-20
 */

static const char* sched_mode_name(scheduler_mode_t mode) {
    switch (mode) {
    case scheduler_mode_pqi:              return "pqi";
    case scheduler_mode_rssi:             return "rssi";
    case scheduler_mode_default:          return "default";
    case scheduler_mode_spquic_migration: return "spquic";
    case scheduler_mode_round_robin:      return "round-robin";
    case scheduler_mode_ecf:              return "ecf";
    case scheduler_mode_blest:            return "blest";
    case scheduler_mode_tof:              return "tof";
    default:                              return "unknown";
    }
}

static uint64_t now_wall_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

int client_init_tx_state(tx_t* st,
                         picoquic_cnx_t* cnx,
                         const struct sockaddr_storage* peerA,
                         const client_options_t* opts) {
    char run_id[256];
    struct timespec ts;

    if (!st || !cnx || !peerA || !opts) return -1;

    memset(st, 0, sizeof(*st));
    st->cnx = cnx;
    st->peerA = *peerA;
    /* Backup-path server address (see peerB rationale in client_runtime.h). */
    {
        const char* ip2 = getenv("MPQUIC_SERVER_IP2");
        if (ip2 && *ip2) {
            struct sockaddr_in* b = (struct sockaddr_in*)&st->peerB;
            memset(&st->peerB, 0, sizeof(st->peerB));
            b->sin_family = AF_INET;
            b->sin_port = htons((uint16_t)opts->port);
            if (inet_pton(AF_INET, ip2, &b->sin_addr) == 1) {
                st->has_peerB = 1;
                LOGF("[MAIN] backup-path server addr: %s:%d (MPQUIC_SERVER_IP2)",
                     ip2, opts->port);
            } else {
                LOGF("[WARN] MPQUIC_SERVER_IP2='%s' unparsable; backup uses primary addr", ip2);
            }
        }
    }
    st->conn_created_us = picoquic_current_time();
    st->ip_primary_be = inet_addr(opts->primary_local_ip);
    st->ip_backup_be = inet_addr(opts->backup_local_ip);

    st->scheduler_mode = opts->scheduler_mode;   /* parsed in client_options.c */
    st->pqi_last_choice = -1;
    st->wifi_last_rssi_dbm = INT_MIN;
    snprintf(st->wifi_ifname, sizeof(st->wifi_ifname), "%s", "wlP1p1s0");
    for (int i = 0; i < MAX_PATHS; i++) {
        st->path_rssi_dbm[i] = INT_MIN;
        st->path_rssi_ewma_dbm[i] = INT_MIN;
    }

    LOGF("[MAIN] scheduler_mode=%s", sched_mode_name(st->scheduler_mode));

    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* Per-drive unique qlog naming: MPQUIC_RUN_LABEL (e.g. a run number) is
     * appended so repeated drives of the same scheduler don't overwrite each
     * other. Unset → legacy "<mode>_<server>" name. */
    {
        const char* run_label = getenv("MPQUIC_RUN_LABEL");
        if (run_label && *run_label)
            snprintf(run_id, sizeof(run_id), "%s_%s_%s",
                     sched_mode_name(st->scheduler_mode), opts->server_ip, run_label);
        else
            snprintf(run_id, sizeof(run_id), "%s_%s",
                     sched_mode_name(st->scheduler_mode), opts->server_ip);
    }
    st->qlog = (qlog_t*)calloc(1, sizeof(qlog_t));
    if (st->qlog) {
        if (qlog_init(st->qlog, run_id, sched_mode_name(st->scheduler_mode),
                      now_wall_us(), (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL) != 0) {
            free(st->qlog);
            st->qlog = NULL;
        }
    }

    {
        const char* dur_env = getenv("MPQUIC_EXP_DURATION_US");
        st->exp_duration_us = dur_env ? (uint64_t)atoll(dur_env) : 30000000ULL;
        st->exp_start_wall_us = now_wall_us();
        LOGF("[MAIN] exp_duration_us=%" PRIu64, st->exp_duration_us);
    }

    pthread_mutex_init(&st->cam_mtx, NULL);
    pthread_mutex_init(&st->cam_mtx_rgb, NULL);

    if (store_local_ip(opts->primary_local_ip, 0, &st->primary_local) == 0) {
        st->has_primary_local = 1;
        LOGF("[MAIN] primary_local stored OK: %s", opts->primary_local_ip);
    } else {
        LOGF("[WARN] primary_local store failed: %s", opts->primary_local_ip);
    }

    if (store_local_ip(opts->backup_local_ip, 0, &st->backup_local) == 0) {
        st->has_backup_local = 1;
        LOGF("[MAIN] backup_local stored OK: %s", opts->backup_local_ip);
    } else {
        LOGF("[WARN] backup_local store failed: %s", opts->backup_local_ip);
    }

    return 0;
}

void client_cleanup_tx_state(tx_t* st) {
    if (!st) return;

    client_stop_camera(st);
    client_stop_camera_rgb(st);

    if (st->qlog) {
        qlog_finalize(st->qlog, st->total_frames_submitted);
        free(st->qlog);
        st->qlog = NULL;
    }

    pthread_mutex_destroy(&st->cam_mtx);
    pthread_mutex_destroy(&st->cam_mtx_rgb);

    free(st->cam_buf);
    st->cam_buf = NULL;
    st->cam_cap = 0;

    free(st->cam_buf_rgb);
    st->cam_buf_rgb = NULL;
    st->cam_cap_rgb = 0;

    free(st->cap_buf);
    st->cap_buf = NULL;
    st->cap_cap = 0;

    free(st->cap_buf_rgb);
    st->cap_buf_rgb = NULL;
    st->cap_cap_rgb = 0;
}
