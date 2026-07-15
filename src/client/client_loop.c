#include "client_loop.h"
#include "client_qlogger.h"
#include "scheduler/sched_pqi.h"   /* PQI/RSSI constants + types (moved out of here) */

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  PQI (Path Quality Index) — Parameter Definitions
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * These constants define the PQI scheduler behavior. They are declared here
 * (not in a config file) so that every parameter is visible inline with its
 * usage, addressing reviewer reproducibility requirements (R3-#3).
 *
 * ─── PQI Composite Score Weights ──────────────────────────────────────────
 * PQI = α · norm(RTT) + β · norm(loss) + γ · (1 − norm(BW)) + ω_rssi · norm(RSSI_penalty)
 *
 *   α  (PQI_ALPHA)   = 0.45  — RTT contribution weight
 *   β  (PQI_BETA)    = 0.35  — Loss contribution weight
 *   γ  (PQI_GAMMA)   = 0.20  — Bandwidth contribution weight
 *   ω_rssi (PQI_RSSI_WEIGHT) = 0.30  — RSSI penalty weight (RSSI mode only)
 *
 * Normalization: min-max across two active paths, per decision cycle.
 *   norm(x) = clamp((x − x_min) / (x_max − x_min))  scaled to [0, 1000]
 *
 * ─── EWMA Smoothing Factors ──────────────────────────────────────────────
 * S_t = λ · M_t + (1 − λ) · S_{t-1}
 *
 *   λ_rtt (EWMA_RTT_ALPHA)   = 0.45  — RTT EWMA factor
 *   λ_loss (EWMA_LOSS_BETA)  = 0.35  — Loss EWMA factor
 *   λ_bw (EWMA_BW_GAMMA)     = 0.20  — Bandwidth EWMA factor
 *
 * ─── Path Grade Thresholds ────────────────────────────────────────────────
 *   Grade 0 (good):      RTT ≤ 250ms  AND  loss ≤ 3%  AND  RSSI > BAD
 *   Grade 1 (degraded):  RTT > 250ms  OR   loss > 3%  OR   RSSI ≤ BAD
 *   Grade 2 (unusable):  verified==0 & silence > 8s  OR  RSSI ≤ UNUSABLE
 *
 * ─── PQI State Machine Thresholds ─────────────────────────────────────────
 *   PQI_DEGRADE_SCORE     = 650  — Trigger failover when primary score exceeds this
 *   PQI_RECOVER_SCORE     = 450  — Trigger failback when primary score falls below this
 *   PQI_SWITCH_MARGIN     = 120  — Hysteresis margin (prevents ping-pong)
 *   PQI_FAILBACK_STABLE_US = 3s  — Minimum time on backup before failback
 *   PQI_SWITCH_DEBOUNCE_US = 2s  — Minimum interval between switches
 *   PQI_PATH_SILENCE_US   = 8s  — Path considered stale if no progress for this long
 *
 * ─── RSSI Thresholds (dBm) ────────────────────────────────────────────────
 *   RSSI_GOOD_DBM     = −55   —  ≥ −55 dBm → link_state = good
 *   RSSI_DEGRADE_DBM  = −67   —  ≤ −67 dBm → link_state = degrading
 *   RSSI_BAD_DBM      = −75   —  ≤ −75 dBm → link_state = bad
 *   RSSI_UNUSABLE_DBM = −82   —  ≤ −82 dBm → link_state = unusable
 */

/* PQI composite/EWMA/state-machine constants moved to scheduler/sched_pqi.h. */

/* ─── Blackout watchdog ───
 * When EVERY path has been silent longer than this, the connection is a
 * zombie (e.g. the robot drove through a spot with neither Wi-Fi nor hotspot
 * coverage, or the server restarted). Without this, the client held the dead
 * connection forever — observed in the 2026-07-12 drive test: 5+ minutes
 * stuck in both_unusable_hold_backup with both links healthy again. The
 * watchdog exits the packet loop so the supervised reconnect in main()
 * dials a fresh connection (0.5–5 s backoff, retries until reachable).
 * Env override: MPQUIC_BLACKOUT_US. */
#define BLACKOUT_TIMEOUT_US_DEFAULT 12000000ULL  /* 12 s = PATH_SILENCE + 4 s */

static uint64_t blackout_timeout_us(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_BLACKOUT_US");
        v = (s && *s && strtoull(s, NULL, 10) > 0)
            ? strtoull(s, NULL, 10) : BLACKOUT_TIMEOUT_US_DEFAULT; }
    return v;
}

/* ─── Loss sampling window ───
 * Minimum bytes sent before a loss ratio sample is considered meaningful.
 * Enlarged 64KB→256KB (2026-07-13): a 64KB window (~0.25 s at the AMR stream
 * rate) is small enough that one burst-loss event reads ~30%, poisoning the
 * grade/score; 256KB (~1 s) averages the ratio to the true ~1.3% while still
 * reacting within a second. See update_pqi_metrics_for_path.
 * PQI_LOSS_MIN_SAMPLE_BYTES now lives in scheduler/sched_pqi.h. */

/* Debounce/RSSI constants, wifi_link_state_t and pqi_choice_t moved to
 * scheduler/sched_pqi.h. */

/* EWMA/normalization, grade tunables and Wi-Fi RSSI helpers moved to
 * scheduler/sched_pqi.c (declared in scheduler/sched_pqi.h). */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Path State Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* path_silence_us() moved to client_paths.c (shared with the scheduler modules). */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Frame Capture — Dual-stream: depth + RGB
 * ═══════════════════════════════════════════════════════════════════════════ */

static int copy_latest_frame(tx_t* st, int* len, uint64_t* seq, uint64_t now) {
    if (!st || !len || !seq) return 0;

    pthread_mutex_lock(&st->cam_mtx);
    *len = st->cam_len;
    *seq = st->cam_seq;
    if (*seq == st->last_sent_seq || *len <= 0) {
        pthread_mutex_unlock(&st->cam_mtx);
        picoquic_set_app_wake_time(st->cnx, now + 5000);
        return 0;
    }
    if (st->cap_cap < (size_t)*len) {
        uint8_t* tmp = realloc(st->cap_buf, (size_t)*len);
        if (!tmp) {
            pthread_mutex_unlock(&st->cam_mtx);
            return 0;
        }
        st->cap_buf = tmp;
        st->cap_cap = (size_t)*len;
    }
    memcpy(st->cap_buf, st->cam_buf, (size_t)*len);
    st->last_sent_seq = *seq;
    pthread_mutex_unlock(&st->cam_mtx);
    return 1;
}

static int copy_latest_frame_rgb(tx_t* st, int* len, uint64_t* seq, uint64_t now) {
    if (!st || !len || !seq) return 0;

    pthread_mutex_lock(&st->cam_mtx_rgb);
    *len = st->cam_len_rgb;
    *seq = st->cam_seq_rgb;
    if (*seq == st->last_sent_seq_rgb || *len <= 0) {
        pthread_mutex_unlock(&st->cam_mtx_rgb);
        picoquic_set_app_wake_time(st->cnx, now + 5000);
        return 0;
    }
    if (st->cap_cap_rgb < (size_t)*len) {
        uint8_t* tmp = realloc(st->cap_buf_rgb, (size_t)*len);
        if (!tmp) {
            pthread_mutex_unlock(&st->cam_mtx_rgb);
            return 0;
        }
        st->cap_buf_rgb = tmp;
        st->cap_cap_rgb = (size_t)*len;
    }
    memcpy(st->cap_buf_rgb, st->cam_buf_rgb, (size_t)*len);
    st->last_sent_seq_rgb = *seq;
    pthread_mutex_unlock(&st->cam_mtx_rgb);
    return 1;
}

/* PQI core (metrics/scoring/state machine) moved to scheduler/sched_pqi.c. */


/* ═══════════════════════════════════════════════════════════════════════════
 *  Path Tracking
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─── helper: find the verified path with the most delivered data ─── */
static int best_verified_path(picoquic_cnx_t* c, tx_t* st, uint64_t now,
                              int exclude_i) {
    int best_i = -1;
    uint64_t best_delivered = 0;
    for (int i = 0; i < (int)c->nb_paths; i++) {
        if (i == exclude_i) continue;
        if (!path_is_healthy(c, st, i, now)) continue;
        if (c->path[i]->delivered > best_delivered) {
            best_delivered = c->path[i]->delivered;
            best_i = i;
        }
    }
    return best_i;
}

static void update_path_tracking(tx_t* st, picoquic_cnx_t* c, uint64_t now,
                                 int* primary_i, int* backup_i) {
    *primary_i = -1;
    *backup_i = -1;

    for (int i = 0; i < (int)c->nb_paths; i++) {
        uint32_t local_ip;
        int healthy;
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple) continue;

        if (p->delivered > st->path_last_delivered[i]
            || p->received > st->path_last_received[i]
            || p->last_packet_received_at > st->path_last_packet_received_at[i]) {
            st->path_last_progress_us[i] = now;
        }
        st->path_last_delivered[i] = p->delivered;
        st->path_last_received[i] = p->received;
        st->path_last_packet_received_at[i] = p->last_packet_received_at;

        local_ip = ((struct sockaddr_in*)&p->first_tuple->local_addr)->sin_addr.s_addr;
        if (local_ip == st->ip_primary_be) *primary_i = i;
        if (local_ip == st->ip_backup_be) *backup_i = i;

        healthy = path_is_healthy(c, st, i, now);
        update_pqi_metrics_for_path(st, p, i, now, healthy);
        if (st->log_verbose) {
            char lip[32];
            inet_ntop(AF_INET, &local_ip, lip, sizeof(lip));
            LOGF("[PATH-LS] path[%d] local=%s verified=%d hv=%d healthy=%d"
                 " retran=%" PRIu64 " inflight=%" PRIu64 " srtt=%" PRIu64
                 " delivered=%" PRIu64 " received=%" PRIu64
                 " last_prog=%" PRIu64 " pqi_grade=%u pqi_score=%" PRIu64,
                 i, lip,
                 p->first_tuple->challenge_verified,
                 p->path_is_demoted, healthy,
                 p->nb_retransmit, p->bytes_in_transit,
                 p->smoothed_rtt, p->delivered, p->received,
                 st->path_last_progress_us[i],
                 (unsigned)st->pqi_grade[i], st->pqi_score[i]);
        }
    }

    /* ── Fallback: if IP-matched primary is unusable, pick best verified ── */
    if (*primary_i < 0 || !path_is_healthy(c, st, *primary_i, now)) {
        int ip_match = *primary_i;
        int fallback = best_verified_path(c, st, now, -1);
        if (fallback >= 0) {
            if (st->log_verbose)
                LOGF("[PATH-LS] primary fallback: IP-match=path[%d] → best-verified=path[%d]",
                     ip_match, fallback);
            *primary_i = fallback;
        }
    }

    /* ── Fallback: if IP-matched backup is unusable or same as primary ── */
    if (*backup_i < 0 || !path_is_healthy(c, st, *backup_i, now)
        || *backup_i == *primary_i) {
        int ip_match_bk = *backup_i;
        int fallback = best_verified_path(c, st, now, *primary_i);
        if (fallback >= 0) {
            if (st->log_verbose)
                LOGF("[PATH-LS] backup fallback: IP-match=path[%d] → alt=path[%d]",
                     ip_match_bk, fallback);
            *backup_i = fallback;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Path Probing Strategy
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Path probing follows a reactive + proactive strategy:
 *
 *  Reactive probing:
 *    - Primary path: probed immediately when primary_i < 0 (not yet discovered)
 *    - Backup path: probed after 3s from ready, or immediately in RSSI mode
 *      when Wi-Fi state is degrading
 *
 *  Proactive probing (RSSI mode):
 *    - When wifi_state ≥ degrading, backup path is probed preemptively
 *      even if no failure has occurred yet
 *
 *  Reviewer mapping (R1-#8): The probing interval is 1s between probes
 *  (see maybe_probe_desired_path in client_paths.c).
 * ═══════════════════════════════════════════════════════════════════════════ */

static void maybe_probe_missing_paths(tx_t* st, picoquic_cnx_t* c,
                                      int primary_i, int backup_i, uint64_t now) {
    wifi_link_state_t wifi_state = wifi_link_state_from_rssi(st->wifi_last_rssi_dbm);

    if (primary_i < 0) {
        (void)maybe_probe_desired_path(c, &st->peerA, &st->primary_local,
                                       st->has_primary_local,
                                       &st->last_primary_probe_us, now);
    }

    if (backup_i < 0 && st->ready_ts_us != 0
        && (primary_i >= 0 || now - st->ready_ts_us >= 3000000ULL
            || (st->scheduler_mode == scheduler_mode_rssi
                && wifi_state >= wifi_link_degrading))) {
        if (st->scheduler_mode == scheduler_mode_rssi && wifi_state >= wifi_link_degrading
            && st->log_verbose) {
            LOGF("[RSSI] proactive backup probe due to wifi_state=%s",
                 wifi_link_state_name(wifi_state));
        }
        /* Backup path targets its own server address when configured
         * (destination-based path split — see peerB in client_runtime.h). */
        (void)maybe_probe_desired_path(c,
                                       st->has_peerB ? &st->peerB : &st->peerA,
                                       &st->backup_local,
                                       st->has_backup_local,
                                       &st->last_backup_probe_us, now);
    }
}

/* Baseline selectors select_default_path()/select_spquic_path() removed:
 * now provided by scheduler/sched_minrtt.c and scheduler/sched_spquic.c,
 * reached through sched_dispatch() in select_send_path(). */


/* ═══════════════════════════════════════════════════════════════════════════
 *  Main Path Selection Dispatch
 * ═══════════════════════════════════════════════════════════════════════════ */

static int select_send_path(tx_t* st, picoquic_cnx_t* c,
                            int primary_i, int backup_i, uint64_t now,
                            char* reason, size_t reason_sz) {
    int use_i = -1;

    if (reason && reason_sz > 0) reason[0] = '\0';

    /* Central modular dispatch (scheduler/). Routes on st->scheduler_mode:
     *   pqi→PQI core, rssi→clean RSSI-aware (PQI-free), default→minRTT,
     *   spquic→SP-migration, rr/ecf/blest/tof→their modules.
     * Each module owns its scoring/state-machine + qlog switch events; the
     * per-tick metric EWMAs are still fed by update_pqi_metrics_for_path(). */
    {
        sched_choice_t choice = sched_dispatch(st, c, primary_i, backup_i, now);
        if (choice.use_i >= 0) {
            use_i = choice.use_i;
            if (reason && reason_sz > 0 && choice.reason)
                snprintf(reason, reason_sz, "%s", choice.reason);

            /* Log at 1 Hz, plus immediately whenever the reason changes
             * (reason strings are literals → pointer compare suffices). */
            static const char* last_logged_reason = NULL;
            if (st->log_verbose || choice.reason != last_logged_reason) {
                last_logged_reason = choice.reason;
                LOGF("[SEL] mode=%d path[%d] reason=%s score=%" PRIu64,
                     (int)st->scheduler_mode, use_i,
                     choice.reason ? choice.reason : "?",
                     (use_i < MAX_PATHS) ? st->pqi_score[use_i] : 0);
            }
        }
    }

    /* Fallback: any healthy path if primary selection failed */
    if (use_i < 0) {
        for (int i = 0; i < (int)c->nb_paths; i++) {
            picoquic_path_t* p;
            if (i == primary_i || i == backup_i) continue;
            p = c->path[i];
            if (p && path_is_healthy(c, st, i, now)) {
                use_i = i;
                if (st->log_verbose)
                    LOGF("[SEL] fallback path[%d] verified=%d", use_i,
                         p->first_tuple->challenge_verified);
                snprintf(reason, reason_sz, "fallback");
                break;
            }
        }
        if (use_i < 0 && primary_i >= 0) {
            kick_path_verification(c, st, primary_i);
        }
    }

    return use_i;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Frame Transmission (dual-stream: depth='d', rgb='r')
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Build a 9-byte frame header: [4B magic "MPQ1"] [1B type] [4B BE length]
 */
static void build_frame_hdr(uint8_t* hdr, char frame_type, int len) {
    hdr[0] = 0x4D;
    hdr[1] = 0x50;
    hdr[2] = 0x51;
    hdr[3] = 0x31;
    hdr[4] = (uint8_t)frame_type;
    hdr[5] = (uint8_t)(len >> 24);
    hdr[6] = (uint8_t)(len >> 16);
    hdr[7] = (uint8_t)(len >> 8);
    hdr[8] = (uint8_t)(len);
}

static int send_frame_on_path(tx_t* st, picoquic_cnx_t* c,
                               int use_i, int len, char frame_type,
                               const uint8_t* payload, uint64_t* sid_ptr,
                               uint8_t* hdr_buf, char* lip, size_t lip_len) {
    int ret;
    uint64_t sid;
    picoquic_path_t* p;

    p = c->path[use_i];
    if (!p || !p->first_tuple) return 0;

    sid = *sid_ptr;
    if (sid == 0) {
        if (frame_type == FRAME_TYPE_RGB) {
            /* RGB uses offset SIDs to avoid collision with depth */
            sid = make_client_uni_sid_from_index(use_i + MAX_PATHS);
        } else {
            sid = make_client_uni_sid_from_index(use_i);
        }
        if (ensure_stream_for_path(c, st, &sid, use_i) != 0) return 0;
        *sid_ptr = sid;
        set_affinity_by_index(c, sid, use_i);
    }

    build_frame_hdr(hdr_buf, frame_type, len);

    ret = picoquic_add_to_stream_with_ctx(c, sid, hdr_buf, FRAME_HDR_SIZE, 0, st);
    if (ret != 0) {
        LOGF("[ERR] add_to_stream hdr failed sid=%" PRIu64 " ret=%d", sid, ret);
        return 0;
    }
    ret = picoquic_add_to_stream_with_ctx(c, sid, payload, (size_t)len, 0, st);
    if (ret != 0) {
        LOGF("[ERR] add_to_stream payload failed sid=%" PRIu64 " ret=%d", sid, ret);
        return 0;
    }
    picoquic_mark_active_stream(c, sid, 1, st);

    inet_ntop(AF_INET,
              &((struct sockaddr_in*)&p->first_tuple->local_addr)->sin_addr,
              lip, lip_len);
    LOGF("[PATH-SELECT] type=%c %dB via path[%d] local=%s sid=%" PRIu64,
         frame_type, len, use_i, lip, sid);
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Main Packet Loop Callback
 * ═══════════════════════════════════════════════════════════════════════════
 *  This is the primary entry point called by picoquic_packet_loop_v2()
 *  on every packet event (ready/after_send/after_receive).
 * ═══════════════════════════════════════════════════════════════════════════ */

int client_loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum mode,
                   void* ctx,
                   void* unused) {
    tx_t* st = (tx_t*)ctx;
    picoquic_cnx_t* c;
    uint64_t now;
    int len;
    uint64_t seq;
    int primary_i = -1, backup_i = -1;
    int use_i;
    char lip[32] = {0};

    (void)unused;
    if (!st || !st->cnx) return 0;

    c = st->cnx;
    now = picoquic_get_quic_time(quic);

    if (mode != picoquic_packet_loop_ready
        && mode != picoquic_packet_loop_after_send
        && mode != picoquic_packet_loop_after_receive) {
        return 0;
    }

    /* Per-tick state logging at 1 Hz — the loop callback fires at kHz rates
     * under load; unthrottled logging produced multi-GB session logs. */
    st->log_verbose = (st->last_verbose_log_us == 0
                       || now - st->last_verbose_log_us >= 1000000ULL);
    if (st->log_verbose) st->last_verbose_log_us = now;

    /* Connection-level close (from the peer or the local stack) means this
     * connection is finished — exit so the supervisor dials a fresh one.
     * (Previously the close event was ignored "for test", which left the
     * loop spinning on a dead connection.) */
    if (st->peer_close_seen) {
        LOGF("[CLOSE] connection closed → exit loop for supervised reconnect");
        return 1;
    }

    /* Experiment auto-stop: if experiment duration has elapsed, signal shutdown */
    if (st->qlog && st->qlog->initialized) {
        uint64_t now_wall = 0;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        now_wall = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
        if (qlog_time_elapsed(st->qlog, now_wall, st->exp_duration_us)) {
            LOGF("[EXP] duration elapsed (%" PRIu64 " us), shutting down", st->exp_duration_us);
            st->exp_finished = 1;  /* clean stop → supervisor must NOT reconnect */
            return 1;  /* signal loop exit */
        }
    }

    if (!hs_done(c, st)) {
        uint64_t wait_now = picoquic_current_time();
        /* Handshake watchdog: a dial made while the server is unreachable
         * used to hang forever in the handshake (close events were ignored
         * and the blackout watchdog only arms after hs completes) — the
         * blackout drill exposed this as a second zombie mode. Fail fast so
         * the supervisor redials with backoff. */
        if (st->conn_created_us != 0
            && wait_now - st->conn_created_us > 10000000ULL) {
            LOGF("[HS-TIMEOUT] handshake not complete after %.1fs → abandon dial, retry",
                 (wait_now - st->conn_created_us) / 1e6);
            return 1;  /* exit packet loop; supervisor reconnects */
        }
        if (st->log_verbose
            && st->ready_ts_us != 0 && wait_now - st->ready_ts_us < 10000000ULL) {
            LOGF("[WAIT] hs_done=0 handshake_done=%d nb_paths=%d",
                 st->handshake_done, c->nb_paths);
        }
        picoquic_set_app_wake_time(c, now + 5000);
        return 0;
    }

    ensure_path0_alive(c);
    refresh_wifi_rssi(st, now);

    update_path_tracking(st, c, now, &primary_i, &backup_i);
    if (primary_i >= 0 && backup_i == primary_i) {
        backup_i = -1;
    }
    if (st->log_verbose) {
        LOGF("[PATH-LS] primary_i=%d backup_i=%d nb_paths=%d",
             primary_i, backup_i, c->nb_paths);
    }

    /* ── Blackout watchdog: if NO path has made progress for the blackout
     * window, the connection is a zombie — exit the packet loop (return 1)
     * with exp_finished=0 so the supervised reconnect in main() dials fresh.
     * (2026-07-12 drive: both links went dark simultaneously; on return the
     * client sat in both_unusable_hold_backup for 5+ min, never recovering.) */
    {
        uint64_t last_prog = st->ready_ts_us;
        for (int i = 0; i < (int)c->nb_paths && i < MAX_PATHS; i++) {
            if (st->path_last_progress_us[i] > last_prog)
                last_prog = st->path_last_progress_us[i];
        }
        if (last_prog != 0 && now > last_prog
            && now - last_prog > blackout_timeout_us()) {
            LOGF("[BLACKOUT] no progress on any path for %.1fs (limit %.1fs)"
                 " → tearing down connection for supervised reconnect",
                 (now - last_prog) / 1e6, blackout_timeout_us() / 1e6);
            return 1;  /* exit packet loop; supervisor reconnects (not a clean stop) */
        }
    }

    maybe_probe_missing_paths(st, c, primary_i, backup_i, now);
    if (primary_i < 0 && backup_i < 0) {
        picoquic_set_app_wake_time(c, now + 20000);
        return 0;
    }

    {
        char reason[64] = "";
        use_i = select_send_path(st, c, primary_i, backup_i, now,
                                 reason, sizeof(reason));
        if (use_i < 0) {
            picoquic_set_app_wake_time(c, now + 20000);
            return 0;
        }

        /* ───── Real-time backpressure (2026-07-13) ─────
         * Drop this tick's frames instead of queueing them when the chosen
         * path already holds more than ~BACKPRESSURE_TARGET_MS of data. Without
         * this the sender piled depth+RGB into the stream faster than a
         * constrained path drained it, so in-flight grew to ~9 MB and per-path
         * RTT ballooned to 3.8 s (self-inflicted bufferbloat, drive 2026-07-13).
         * Dropping keeps the LATEST frame flowing at bounded latency — the
         * correct trade for real-time AMR video. Cap = bandwidth × target-delay
         * (floor one frame). Tunable via MPQUIC_BP_TARGET_MS. */
        {
            picoquic_path_t* pp = c->path[use_i];
            int have_new = (st->cam_seq != st->last_sent_seq)
                        || (st->cam_seq_rgb != st->last_sent_seq_rgb);
            uint64_t bw = pp ? (pp->receive_rate_estimate ? pp->receive_rate_estimate
                                                          : pp->bandwidth_estimate) : 0;
            uint64_t cap = bw ? (bw * backpressure_target_ms() / 1000ULL) : 131072ULL;
            if (cap < 65536ULL) cap = 65536ULL;
            if (have_new && pp && pp->bytes_in_transit > cap) {
                /* Discard the stale pending frame(s): real-time keeps only the
                 * latest, so advance the sent-seq without transmitting. Counts
                 * once per dropped frame-pair (not per kHz tick). */
                pthread_mutex_lock(&st->cam_mtx);
                st->last_sent_seq = st->cam_seq;
                pthread_mutex_unlock(&st->cam_mtx);
                pthread_mutex_lock(&st->cam_mtx_rgb);
                st->last_sent_seq_rgb = st->cam_seq_rgb;
                pthread_mutex_unlock(&st->cam_mtx_rgb);
                st->frames_dropped_backpressure++;
                if (st->log_verbose)
                    LOGF("[BP] drop frame: path[%d] in_flight=%" PRIu64
                         " > cap=%" PRIu64 " (dropped=%" PRIu64 ")",
                         use_i, pp->bytes_in_transit, cap,
                         st->frames_dropped_backpressure);
                picoquic_set_app_wake_time(c, now + 5000);
                st->frame_pair_idx++;
                return 0;   /* skip both depth+RGB this tick */
            }
        }

        /* ───── 1) Send DEPTH frame ───── */
        if (copy_latest_frame(st, &len, &seq, now)) {
            if (send_frame_on_path(st, c, use_i, len, FRAME_TYPE_DEPTH,
                                   st->cap_buf, &st->sid_per_path[use_i],
                                   st->frame_hdr, lip, sizeof(lip))) {
                st->total_frames_submitted++;
                {
                    picoquic_path_t* used_path = c->path[use_i];
                    uint64_t rtt_us = used_path ? used_path->smoothed_rtt : 0;
                    qlog_frame_event(st->qlog, use_i, (uint64_t)len, now, rtt_us,
                                     reason[0] ? reason : NULL);
                    qlog_snapshot(st->qlog, c, now);
                }
            }
        }

        /* ───── 2) Send RGB frame ───── */
        if (copy_latest_frame_rgb(st, &len, &seq, now)) {
            if (send_frame_on_path(st, c, use_i, len, FRAME_TYPE_RGB,
                                   st->cap_buf_rgb, &st->sid_per_path_rgb[use_i],
                                   st->frame_hdr_rgb, lip, sizeof(lip))) {
                st->total_frames_submitted++;

                /* Log RGB frame event as well */
                {
                    picoquic_path_t* used_path = c->path[use_i];
                    uint64_t rtt_us = used_path ? used_path->smoothed_rtt : 0;
                    qlog_frame_event(st->qlog, use_i, (uint64_t)len, now, rtt_us,
                                     reason[0] ? reason : NULL);
                }
            }
        }

        /* Track frame pair (both depth+RGB sent successfully) */
        st->frame_pair_idx++;
    }

    picoquic_set_app_wake_time(c, now + 20000);
    return 0;
}
