#ifndef CLIENT_QLOGGER_H
#define CLIENT_QLOGGER_H

#include "client_runtime.h"
#include <stdio.h>
#include <time.h>

/*
 * QoS Logger — CSV-based metrics collection
 * ==========================================
 *
 * PURPOSE:
 *   Records per-frame and periodic QoS metrics for post-experiment analysis.
 *   Supports reviewer-required statistical reporting (mean, variance, CI)
 *   by producing structured CSV data amenable to pandas/scipy processing.
 *
 * OUTPUT FILES (created in ./qlogs_client/):
 *   {run_id}_events.csv   — Per-frame delivery + scheduler events
 *   {run_id}_snap.csv     — Periodic path-state snapshots (every SNAP_INTERVAL_US)
 *
 * REVIEWER MAPPING:
 *   R3-#8  (repeated experiments, stats)     -> structured CSV amenable to batch analysis
 *   R3-#9  (throughput comparison)            -> goodput/bytes columns
 *   R1-#10 (baseline comparison methodology)  -> switch_count + path_utilization columns
 *   R3-#7  (hesitation = reactive failover)   -> outage_duration_us tracks true gap
 */

/* ──────────────────────────────────────────────
 *  Configuration
 * ────────────────────────────────────────────── */

/* Snapshot interval for periodic path-state logging (default 1 second) */
#define QLOG_SNAP_INTERVAL_US  1000000ULL

/* Max CSV line length */
#define QLOG_LINE_MAX  512

/* ──────────────────────────────────────────────
 *  Data structures
 * ────────────────────────────────────────────── */

typedef struct qlog_t {
    /* run metadata */
    char        run_id[64];
    char        scheduler_mode_name[16];
    uint64_t    start_wall_us;
    uint64_t    start_mono_us;

    /* CSV file handles */
    FILE*       f_events;
    FILE*       f_snap;
    char        path_events[256];
    char        path_snap[256];

    /* counters (reset at run start) */
    uint64_t    frame_count;
    uint64_t    frame_bytes_total;
    uint64_t    switch_count;           /* mode-agnostic: send-path changes between frames */
    int         last_path_i;            /* path of the previous frame (-1 = none), for switch detection */
    uint64_t    last_frame_ts_us;       /* monotonic timestamp of last frame */
    uint64_t    total_outage_us;        /* sum of REAL outages (inter-frame gap > threshold) */
    uint64_t    outage_events;          /* number of real outages (gap > threshold) */

    /* last snap timestamp */
    uint64_t    last_snap_us;

    /* per-path byte accumulators (for utilization %) */
    uint64_t    path_bytes_sent[MAX_PATHS];

    int         initialized;
} qlog_t;

/* ──────────────────────────────────────────────
 *  API
 * ────────────────────────────────────────────── */

/* Initialize logger: creates output directory, opens CSV files, writes headers.
 * Returns 0 on success, -1 on failure. */
int qlog_init(qlog_t* q, const char* run_id, const char* sched_mode_name,
              uint64_t start_wall_us, uint64_t start_mono_us);

/* Log a frame delivery event. Called AFTER picoquic_add_to_stream.
 *   path_i      — index of path used
 *   frame_bytes — payload bytes (excluding MPQ1 header)
 *   now_us      — current monotonic time (picoquic_get_quic_time)
 *   rtt_us      — smoothed_rtt of selected path
 *   choice_reason — string reason from scheduler (e.g. "degrade_failover") */
void qlog_frame_event(qlog_t* q, int path_i, uint64_t frame_bytes,
                      uint64_t now_us, uint64_t rtt_us,
                      const char* choice_reason);

/* Log a periodic path-state snapshot. Call from the main loop at will;
 *   internal timer throttles to QLOG_SNAP_INTERVAL_US.
 *   c — picoquic connection (to read path[] state) */
void qlog_snapshot(qlog_t* q, picoquic_cnx_t* c, uint64_t now_us);

/* Log scheduler switch explicitly (in addition to what frame_event captures) */
void qlog_switch_event(qlog_t* q, uint64_t now_us, int from_path, int to_path,
                       const char* reason);

/* Finalize: write summary stats row, close files, flush.
 *   total_frames_sent — total frames submitted to picoquic (for delivery ratio) */
void qlog_finalize(qlog_t* q, uint64_t total_frames_sent);

/* Check if enough wall-clock time has elapsed to stop the experiment.
 * Returns 1 if duration_us has passed since start_wall_us. */
int qlog_time_elapsed(qlog_t* q, uint64_t now_wall_us, uint64_t duration_us);

#endif /* CLIENT_QLOGGER_H */
