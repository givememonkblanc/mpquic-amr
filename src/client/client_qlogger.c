#include "client_qlogger.h"
#include <sys/stat.h>
#include <inttypes.h>

/* ──────────────────────────────────────────────
 *  Helpers
 * ────────────────────────────────────────────── */

static void ensure_dir(const char* path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        mkdir(path, 0755);
    }
}

static void write_events_csv_header(FILE* f) {
    fprintf(f, "t_us,path_i,frame_bytes,rtt_us,choice_reason,"
               "switch_count,outage_us,cum_bytes\n");
}

static void write_snap_csv_header(FILE* f) {
    fprintf(f, "t_us,path_i,verified,demoted,healthy,"
               "srtt_us,loss_bytes,sent_bytes,in_flight\n");
}

/* ──────────────────────────────────────────────
 *  Public API
 * ────────────────────────────────────────────── */

int qlog_init(qlog_t* q, const char* run_id, const char* sched_mode_name,
              uint64_t start_wall_us, uint64_t start_mono_us) {
    if (!q || !run_id || !sched_mode_name) return -1;

    memset(q, 0, sizeof(*q));
    snprintf(q->run_id, sizeof(q->run_id), "%s", run_id);
    snprintf(q->scheduler_mode_name, sizeof(q->scheduler_mode_name), "%s", sched_mode_name);
    q->start_wall_us = start_wall_us;
    q->start_mono_us = start_mono_us;
    q->last_frame_ts_us = 0;
    q->last_path_i = -1;
    q->last_snap_us = 0;

    for (int i = 0; i < MAX_PATHS; i++) {
        q->path_bytes_sent[i] = 0;
    }

    ensure_dir("qlogs_client");

    snprintf(q->path_events, sizeof(q->path_events),
             "qlogs_client/%s_events.csv", run_id);
    snprintf(q->path_snap, sizeof(q->path_snap),
             "qlogs_client/%s_snap.csv", run_id);

    /* APPEND, not truncate: the supervised reconnect loop re-inits tx state (and
     * thus calls qlog_init) on every reconnection. A drive that reconnects at the
     * coverage boundary would otherwise LOSE all data before the last connection.
     * With "a" + header-only-when-empty, all connections of one drive accumulate
     * into a single continuous file (picoquic's monotonic clock keeps t_us in
     * order across reconnects). Per-drive uniqueness comes from MPQUIC_RUN_LABEL
     * in the run_id, so different drives never share a file. */
    q->f_events = fopen(q->path_events, "a");
    if (!q->f_events) {
        LOGF("[QLOG] ERROR: cannot open %s", q->path_events);
        return -1;
    }
    if (ftell(q->f_events) == 0) write_events_csv_header(q->f_events);

    q->f_snap = fopen(q->path_snap, "a");
    if (!q->f_snap) {
        LOGF("[QLOG] ERROR: cannot open %s", q->path_snap);
        fclose(q->f_events);
        q->f_events = NULL;
        return -1;
    }
    if (ftell(q->f_snap) == 0) write_snap_csv_header(q->f_snap);

    q->initialized = 1;
    LOGF("[QLOG] initialized → qlogs_client/%s_{events,snap}.csv", run_id);
    return 0;
}

/* A stream gap longer than this counts as a real outage (a normal ~5 fps
 * inter-frame cadence gap does NOT). Env override: MPQUIC_OUTAGE_THRESHOLD_US. */
static uint64_t qlog_outage_threshold_us(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_OUTAGE_THRESHOLD_US");
        v = (s && *s) ? strtoull(s, NULL, 10) : 500000ULL; }  /* default 500 ms */
    return v;
}

void qlog_frame_event(qlog_t* q, int path_i, uint64_t frame_bytes,
                      uint64_t now_us, uint64_t rtt_us,
                      const char* choice_reason) {
    uint64_t outage_us = 0;

    if (!q || !q->initialized || !q->f_events) return;

    /* Real outage = inter-frame gap EXCEEDING the threshold (a stream stall,
     * e.g. a path failover or coverage gap). Normal cadence gaps log 0 so
     * sum(outage_us) is the true stalled time, not the run duration. */
    if (q->last_frame_ts_us != 0 && now_us > q->last_frame_ts_us) {
        uint64_t gap_us = now_us - q->last_frame_ts_us;
        if (gap_us > qlog_outage_threshold_us()) {
            outage_us = gap_us;
            q->total_outage_us += outage_us;
            q->outage_events++;
        }
    }
    q->last_frame_ts_us = now_us;

    /* Mode-agnostic path-switch count: the chosen send path changed from the
     * previous frame. Works for EVERY scheduler (rssi/pqi/minrtt/spquic); the
     * PQI-only qlog_switch_event no longer drives this count. */
    if (q->last_path_i >= 0 && path_i != q->last_path_i) {
        q->switch_count++;
    }
    q->last_path_i = path_i;

    q->frame_count++;
    q->frame_bytes_total += frame_bytes;
    if (path_i >= 0 && path_i < MAX_PATHS) {
        q->path_bytes_sent[path_i] += frame_bytes;
    }

    fprintf(q->f_events,
            "%" PRIu64 ",%d,%" PRIu64 ",%" PRIu64 ",%s,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            now_us, path_i, frame_bytes, rtt_us,
            choice_reason ? choice_reason : "",
            q->switch_count, outage_us, q->frame_bytes_total);
    fflush(q->f_events);
}

void qlog_switch_event(qlog_t* q, uint64_t now_us, int from_path, int to_path,
                       const char* reason) {
    (void)now_us;
    if (!q || !q->initialized) return;
    /* switch_count is now owned by qlog_frame_event (mode-agnostic path-change
     * detection); this remains PQI-path telemetry only — no increment here. */
    LOGF("[QLOG-SWITCH] path[%d] → path[%d] reason=%s  (frame_count=%" PRIu64 ", switches=%" PRIu64 ")",
         from_path, to_path, reason ? reason : "?", q->frame_count, q->switch_count);
}

void qlog_snapshot(qlog_t* q, picoquic_cnx_t* c, uint64_t now_us) {
    if (!q || !q->initialized || !q->f_snap || !c) return;

    if (q->last_snap_us != 0 && now_us - q->last_snap_us < QLOG_SNAP_INTERVAL_US) {
        return;
    }
    q->last_snap_us = now_us;

    for (int i = 0; i < (int)c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;

        /* read fresh pqi fields from tx_t — we don't have tx_t here, so
         * we rely on the caller to have updated state before calling.
         * For now, log only picoquic-native fields. */
        fprintf(q->f_snap,
                "%" PRIu64 ",%d,%d,%d,%d,"
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                now_us, i,
                p->first_tuple->challenge_verified,
                p->path_is_demoted,
                1,
                p->smoothed_rtt,
                p->total_bytes_lost,
                p->bytes_sent,
                p->bytes_in_transit);
    }
    fflush(q->f_snap);
}

void qlog_finalize(qlog_t* q, uint64_t total_frames_sent) {
    if (!q || !q->initialized) return;

    if (q->f_events) {
        double outage_avg = (q->outage_events > 0)
            ? (double)q->total_outage_us / (double)q->outage_events
            : 0.0;
        fprintf(q->f_events,
                "\n# SUMMARY: frames=%" PRIu64 " sent=%" PRIu64
                " bytes=%" PRIu64 " switches=%" PRIu64
                " outage_events=%" PRIu64 " outage_total_us=%" PRIu64
                " outage_avg_us=%.0f\n",
                q->frame_count, total_frames_sent,
                q->frame_bytes_total, q->switch_count,
                q->outage_events, q->total_outage_us, outage_avg);
    }

    if (q->f_events) {
        fclose(q->f_events);
        q->f_events = NULL;
    }
    if (q->f_snap) {
        fclose(q->f_snap);
        q->f_snap = NULL;
    }

    LOGF("[QLOG] finalized: frames=%" PRIu64 " sent=%" PRIu64
         " switches=%" PRIu64 " avg_outage=%.0f us",
         q->frame_count, total_frames_sent,
         q->switch_count,
         (q->outage_events > 0)
            ? (double)q->total_outage_us / (double)q->outage_events
            : 0.0);
    q->initialized = 0;
}

int qlog_time_elapsed(qlog_t* q, uint64_t now_wall_us, uint64_t duration_us) {
    if (!q || q->start_wall_us == 0) return 0;
    return (now_wall_us >= q->start_wall_us + duration_us) ? 1 : 0;
}
