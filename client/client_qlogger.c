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
    q->last_snap_us = 0;

    for (int i = 0; i < MAX_PATHS; i++) {
        q->path_bytes_sent[i] = 0;
    }

    ensure_dir("qlogs_client");

    snprintf(q->path_events, sizeof(q->path_events),
             "qlogs_client/%s_events.csv", run_id);
    snprintf(q->path_snap, sizeof(q->path_snap),
             "qlogs_client/%s_snap.csv", run_id);

    q->f_events = fopen(q->path_events, "w");
    if (!q->f_events) {
        LOGF("[QLOG] ERROR: cannot open %s", q->path_events);
        return -1;
    }
    write_events_csv_header(q->f_events);

    q->f_snap = fopen(q->path_snap, "w");
    if (!q->f_snap) {
        LOGF("[QLOG] ERROR: cannot open %s", q->path_snap);
        fclose(q->f_events);
        q->f_events = NULL;
        return -1;
    }
    write_snap_csv_header(q->f_snap);

    q->initialized = 1;
    LOGF("[QLOG] initialized → qlogs_client/%s_{events,snap}.csv", run_id);
    return 0;
}

void qlog_frame_event(qlog_t* q, int path_i, uint64_t frame_bytes,
                      uint64_t now_us, uint64_t rtt_us,
                      const char* choice_reason) {
    uint64_t outage_us = 0;

    if (!q || !q->initialized || !q->f_events) return;

    if (q->last_frame_ts_us != 0 && now_us > q->last_frame_ts_us) {
        outage_us = now_us - q->last_frame_ts_us;
        q->total_outage_us += outage_us;
        if (outage_us > 0) q->outage_events++;
    }
    q->last_frame_ts_us = now_us;

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
    q->switch_count++;
    LOGF("[QLOG-SWITCH] #%" PRIu64 "  path[%d] → path[%d] reason=%s  (frame_count=%" PRIu64 ")",
         q->switch_count, from_path, to_path, reason ? reason : "?", q->frame_count);
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
