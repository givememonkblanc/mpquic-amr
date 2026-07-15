#include "sched_pqi.h"
#include "../client_qlogger.h"   /* qlog_switch_event() used by update_pqi_choice_state */

/*
 * PQI / RSSI scheduler helpers moved verbatim from client_loop.c (behaviour
 * preserving). Now non-static so the PQI core (still calling them during the
 * transition) and the other scheduler modules can share them.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 *  EWMA & Normalization Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

uint64_t ewma_u64(uint64_t prev, uint64_t raw, uint64_t weight_pct) {
    if (prev == 0) return raw;
    return (weight_pct * raw + (100ULL - weight_pct) * prev) / 100ULL;
}

int ewma_i32(int prev, int raw, uint64_t weight_pct) {
    int64_t w, inv_w;
    if (prev == INT_MIN) return raw;
    w = (int64_t)weight_pct;
    inv_w = 100LL - w;
    return (int)((w * (int64_t)raw + inv_w * (int64_t)prev) / 100LL);
}

/*
 * Min-max normalization to [0, 1000].
 *   norm(x) = ((x − x_min) / (x_max − x_min)) × 1000, clamped to [0, 1000]
 */
uint64_t clamp_norm_u64(uint64_t value, uint64_t min_v, uint64_t max_v) {
    if (max_v <= min_v) return 0;
    if (value <= min_v) return 0;
    if (value >= max_v) return 1000;
    return ((value - min_v) * 1000ULL) / (max_v - min_v);
}

/*
 * Gray-zone proactive grade thresholds — env-tunable for parameter sweeps
 * (reviewer R#3-3). See the 2026-07-10 real drive note: RSSI alone missed the
 * boundary, so the link-quality grade trips early on RTT.
 *   MPQUIC_GRADE_RTT_US   (default 180000 = 180 ms)
 *   MPQUIC_GRADE_LOSS_BP  (default 0 = DISABLED; loss advisory only)
 */
uint64_t grade_rtt_us(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_GRADE_RTT_US");
        v = (s && *s) ? strtoull(s, NULL, 10) : 180000ULL; }
    return v;
}
uint64_t grade_loss_bp(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_GRADE_LOSS_BP");
        v = (s && *s) ? strtoull(s, NULL, 10) : 0ULL; }  /* 0 = loss not a grade gate */
    return v;
}
/* Real-time backpressure target buffering (ms). Env MPQUIC_BP_TARGET_MS. */
uint64_t backpressure_target_ms(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_BP_TARGET_MS");
        v = (s && *s) ? strtoull(s, NULL, 10) : 200ULL; }
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Wi-Fi RSSI Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

int is_wifi_ipv4(uint32_t local_ip_be) {
    uint32_t ip = ntohl(local_ip_be);
    return (ip & 0xFFFF0000U) == 0xC0A80000U; /* 192.168.x.x */
}

uint64_t rssi_penalty_from_dbm(int rssi_dbm) {
    /* Linear mapping: RSSI_GOOD_DBM → penalty=0, RSSI_UNUSABLE_DBM → penalty=1000 */
    if (rssi_dbm == INT_MIN) return 0;
    if (rssi_dbm >= RSSI_GOOD_DBM) return 0;
    if (rssi_dbm <= RSSI_UNUSABLE_DBM) return 1000;
    return (uint64_t)((RSSI_GOOD_DBM - rssi_dbm) * 1000ULL)
         / (uint64_t)(RSSI_GOOD_DBM - RSSI_UNUSABLE_DBM);
}

wifi_link_state_t wifi_link_state_from_rssi(int rssi_dbm) {
    if (rssi_dbm == INT_MIN) return wifi_link_unknown;
    if (rssi_dbm <= RSSI_UNUSABLE_DBM) return wifi_link_unusable;
    if (rssi_dbm <= RSSI_BAD_DBM) return wifi_link_bad;
    if (rssi_dbm <= RSSI_DEGRADE_DBM) return wifi_link_degrading;
    return wifi_link_good;
}

const char* wifi_link_state_name(wifi_link_state_t s) {
    switch (s) {
    case wifi_link_good:     return "good";
    case wifi_link_degrading: return "degrading";
    case wifi_link_bad:      return "bad";
    case wifi_link_unusable: return "unusable";
    default:                 return "unknown";
    }
}

static int sample_wifi_rssi_dbm(const char* ifname) {
    char cmd[128];
    char line[256];
    FILE* fp;
    int rssi = INT_MIN;

    /* Deterministic scenarios: MPQUIC_RSSI_FILE overrides the live `iw` sample
     * with a scripted dBm value (reproducible RSSI ramps). The file holds one int. */
    {
        const char* rssi_file = getenv("MPQUIC_RSSI_FILE");
        if (rssi_file && *rssi_file) {
            FILE* rf = fopen(rssi_file, "r");
            if (rf) {
                int dbm = INT_MIN;
                int ok = (fscanf(rf, "%d", &dbm) == 1);
                fclose(rf);
                if (ok) return dbm;
            }
            return INT_MIN;
        }
    }

    if (!ifname || !*ifname) return INT_MIN;
    snprintf(cmd, sizeof(cmd), "iw dev %s link 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (!fp) return INT_MIN;

    while (fgets(line, sizeof(line), fp) != NULL) {
        int dbm;
        if (sscanf(line, " signal: %d dBm", &dbm) == 1) {
            rssi = dbm;
            break;
        }
    }
    (void)pclose(fp);
    return rssi;
}

void refresh_wifi_rssi(tx_t* st, uint64_t now) {
    int rssi;
    if (!st) return;
    /* Only sample in RSSI-aware mode */
    if (st->scheduler_mode != scheduler_mode_rssi) return;
    if (st->last_rssi_sample_us != 0
        && now - st->last_rssi_sample_us < RSSI_SAMPLE_INTERVAL_US) return;

    st->last_rssi_sample_us = now;
    rssi = sample_wifi_rssi_dbm(st->wifi_ifname);
    if (rssi != INT_MIN) {
        LOGF("[RSSI] if=%s sample=%d dBm state=%s", st->wifi_ifname, rssi,
             wifi_link_state_name(wifi_link_state_from_rssi(rssi)));
    }
    st->wifi_last_rssi_dbm = rssi;
    for (int i = 0; i < MAX_PATHS; i++) {
        st->path_rssi_dbm[i] = INT_MIN;
    }
}

/* ═══ PQI core — moved verbatim from client_loop.c ═══ */

/* ═══════════════════════════════════════════════════════════════════════════
 *  PQI Metrics Update
 * ═══════════════════════════════════════════════════════════════════════════
 *  Updates per-path EWMA (RTT, loss, bandwidth) and computes path grade.
 *  Called for every packet loop callback iteration.
 * ═══════════════════════════════════════════════════════════════════════════ */

void update_pqi_metrics_for_path(tx_t* st, picoquic_path_t* p, int i,
                                        uint64_t now, int healthy) {
    uint64_t sent_delta, lost_delta, bw_raw, rssi_penalty, silence_us;

    sent_delta = (p->bytes_sent >= st->pqi_last_bytes_sent[i])
        ? (p->bytes_sent - st->pqi_last_bytes_sent[i]) : 0;
    lost_delta = (p->total_bytes_lost >= st->pqi_last_bytes_lost[i])
        ? (p->total_bytes_lost - st->pqi_last_bytes_lost[i]) : 0;

    /* Windowed loss sampling (2026-07-12 fix). The old per-tick estimator had
     * two poisoning modes: (a) tiny sent_delta windows (1-2 packets) make a
     * single loss read as 50-100% loss; (b) on idle ticks (sent_delta == 0,
     * i.e. MOST ticks) it fed the CUMULATIVE lifetime loss ratio into the
     * EWMA, locking loss_bp at the historical average (~3%) and pinning both
     * paths at grade 1 forever. Now deltas accumulate until enough bytes were
     * sent for a statistically meaningful ratio; between samples the EWMA
     * simply holds its last value. */
    st->pqi_acc_sent[i] += sent_delta;
    st->pqi_acc_lost[i] += lost_delta;
    if (st->pqi_acc_sent[i] >= PQI_LOSS_MIN_SAMPLE_BYTES) {
        uint64_t loss_bp_raw = (st->pqi_acc_lost[i] * 10000ULL) / st->pqi_acc_sent[i];
        if (loss_bp_raw > 10000ULL) loss_bp_raw = 10000ULL;
        st->pqi_loss_bp_ewma[i] = ewma_u64(st->pqi_loss_bp_ewma[i], loss_bp_raw, EWMA_LOSS_BETA);
        st->pqi_acc_sent[i] = 0;
        st->pqi_acc_lost[i] = 0;
    }

    bw_raw = p->receive_rate_estimate != 0 ? p->receive_rate_estimate : p->bandwidth_estimate;

    st->pqi_rtt_ewma[i]    = ewma_u64(st->pqi_rtt_ewma[i],    p->smoothed_rtt,    EWMA_RTT_ALPHA);
    st->pqi_bw_ewma[i]     = ewma_u64(st->pqi_bw_ewma[i],     bw_raw,             EWMA_BW_GAMMA);
    st->pqi_last_bytes_sent[i] = p->bytes_sent;
    st->pqi_last_bytes_lost[i] = p->total_bytes_lost;

    /* RSSI tracking for Wi-Fi paths */
    if (is_wifi_ipv4(((struct sockaddr_in*)&p->first_tuple->local_addr)->sin_addr.s_addr)) {
        int sampled = st->wifi_last_rssi_dbm;
        if (sampled != INT_MIN) {
            st->path_rssi_dbm[i] = sampled;
            st->path_rssi_ewma_dbm[i] = ewma_i32(st->path_rssi_ewma_dbm[i], sampled, EWMA_RTT_ALPHA);
        }
    } else {
        st->path_rssi_dbm[i] = INT_MIN;
        st->path_rssi_ewma_dbm[i] = INT_MIN;
    }

    /*
     * Path Grade Assignment (loss demoted to advisory, 2026-07-13)
     *   Grade 0 (good):      verified, healthy, RTT ≤ threshold, RSSI > BAD
     *   Grade 1 (degraded):  unverified OR unhealthy OR RTT > threshold OR RSSI ≤ BAD
     *   Grade 2 (unusable):  stale (silence > 8s) OR RSSI ≤ UNUSABLE
     *
     * The measured loss rate is NOT used to gate the grade. Under MP-QUIC the
     * per-path loss counter (bytes in packets declared lost) conflates genuine
     * loss with cross-path reordering, reading 6-12% on demonstrably healthy
     * paths (verified via snap.csv, 2026-07-13). Gating on it pinned BOTH paths
     * at grade 1, so the scheduler could not hold Wi-Fi in steady state and
     * ping-ponged on noise. The proposed scheme is RSSI- (proactive) and RTT-
     * (reactive) driven; loss is retained only as an advisory term in the PQI
     * composite score (β·norm(loss) in fill_pqi_scores), not as a grade gate.
     * Tune back with MPQUIC_GRADE_LOSS_BP>0 (default 0 = disabled).
     */
    silence_us = path_silence_us(st, i, now);
    rssi_penalty = rssi_penalty_from_dbm(st->path_rssi_ewma_dbm[i]);

    if (!p->first_tuple->challenge_verified) {
        st->pqi_grade[i] = (silence_us > PQI_PATH_SILENCE_US) ? 2 : 1;
    } else if (!healthy || silence_us > PQI_PATH_SILENCE_US) {
        st->pqi_grade[i] = 2;
    } else if (st->path_rssi_ewma_dbm[i] != INT_MIN
               && st->path_rssi_ewma_dbm[i] <= RSSI_UNUSABLE_DBM) {
        st->pqi_grade[i] = 2;
    } else if (st->path_rssi_ewma_dbm[i] != INT_MIN
               && st->path_rssi_ewma_dbm[i] <= RSSI_BAD_DBM) {
        st->pqi_grade[i] = 1;
    } else if (st->pqi_rtt_ewma[i] > grade_rtt_us()
               || (grade_loss_bp() > 0 && st->pqi_loss_bp_ewma[i] > grade_loss_bp())) {
        st->pqi_grade[i] = 1;
    } else {
        st->pqi_grade[i] = 0;
    }

    if (st->pqi_grade[i] == 0 && rssi_penalty >= 600ULL) {
        st->pqi_grade[i] = 1;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PQI Score Computation
 * ═══════════════════════════════════════════════════════════════════════════
 *  fill_pqi_scores() applies min-max normalization across two paths and
 *  computes the composite PQI score per path.
 *
 *  PQI = α · norm(RTT) + β · norm(loss) + γ · (1 − norm(BW)) + ω · norm(RSSI)
 *
 *  where norm() is min-max normalization to [0, 1000] across the two paths.
 *  Grade 2 (unusable) paths bypass scoring and get score = 1000.
 *  Single usable path gets score = 0 (grade 0) or 500 (grade 1).
 *
 *  Scoring algorithm (R1-#6, R1-#7, R3-#3):
 *    1. Collect min/max of RTT, loss, BW across grade-0/1 paths
 *    2. If < 2 usable paths → use fill_single_or_unusable_scores()
 *    3. Else for each path:
 *         nrtt   = clamp_norm(rtt_ewma, min_rtt, max_rtt)
 *         nloss  = clamp_norm(loss_bp_ewma, min_loss, max_loss)
 *         nbw    = clamp_norm(bw_ewma, min_bw, max_bw)
 *         nrssi  = rssi_penalty (if RSSI mode)
 *         score  = (α·nrtt + β·nloss + γ·(1000−nbw) + ω·nrssi) / (1000 + ω)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void fill_single_or_unusable_scores(tx_t* st, int primary_i, int backup_i) {
    if (primary_i >= 0) {
        st->pqi_score[primary_i] = (st->pqi_grade[primary_i] >= 2) ? 1000ULL
            : (st->pqi_grade[primary_i] == 0 ? 0ULL : 500ULL);
    }
    if (backup_i >= 0) {
        st->pqi_score[backup_i] = (st->pqi_grade[backup_i] >= 2) ? 1000ULL
            : (st->pqi_grade[backup_i] == 0 ? 0ULL : 500ULL);
    }
}

void fill_pqi_scores(tx_t* st, int primary_i, int backup_i) {
    int usable_count = 0;
    int ids[2] = { primary_i, backup_i };
    uint64_t min_rtt = UINT64_MAX, max_rtt = 0;
    uint64_t min_loss = UINT64_MAX, max_loss = 0;
    uint64_t min_bw = UINT64_MAX, max_bw = 0;

    for (int j = 0; j < 2; j++) {
        int i = ids[j];
        if (i < 0) continue;
        st->pqi_score[i] = 1000ULL;
        if (st->pqi_grade[i] >= 2) continue;
        usable_count++;
        if (st->pqi_rtt_ewma[i] < min_rtt) min_rtt = st->pqi_rtt_ewma[i];
        if (st->pqi_rtt_ewma[i] > max_rtt) max_rtt = st->pqi_rtt_ewma[i];
        if (st->pqi_loss_bp_ewma[i] < min_loss) min_loss = st->pqi_loss_bp_ewma[i];
        if (st->pqi_loss_bp_ewma[i] > max_loss) max_loss = st->pqi_loss_bp_ewma[i];
        if (st->pqi_bw_ewma[i] < min_bw) min_bw = st->pqi_bw_ewma[i];
        if (st->pqi_bw_ewma[i] > max_bw) max_bw = st->pqi_bw_ewma[i];
    }

    if (usable_count < 2) {
        fill_single_or_unusable_scores(st, primary_i, backup_i);
        return;
    }

    for (int j = 0; j < 2; j++) {
        uint64_t nrtt, nloss, nbw, nrssi;
        int i = ids[j];
        if (i < 0 || st->pqi_grade[i] >= 2) continue;

        nrtt  = clamp_norm_u64(st->pqi_rtt_ewma[i],    min_rtt,  max_rtt);
        nloss = clamp_norm_u64(st->pqi_loss_bp_ewma[i], min_loss, max_loss);
        nbw   = clamp_norm_u64(st->pqi_bw_ewma[i],     min_bw,   max_bw);
        nrssi = (st->scheduler_mode == scheduler_mode_rssi)
            ? rssi_penalty_from_dbm(st->path_rssi_ewma_dbm[i]) : 0;

        /* Normalize by the sum of the ACTIVE weights. In pure-PQI mode the RSSI
         * term is inactive (nrssi==0), so dividing by (1000+ω) would scale every
         * score to ~77% of [0,1000] and make the absolute thresholds
         * (PQI_DEGRADE_SCORE/PQI_RECOVER_SCORE) inconsistent with RSSI mode. */
        uint64_t denom = (st->scheduler_mode == scheduler_mode_rssi)
            ? (1000ULL + PQI_RSSI_WEIGHT) : 1000ULL;
        st->pqi_score[i] = (PQI_ALPHA * nrtt + PQI_BETA * nloss
                            + PQI_GAMMA * (1000ULL - nbw)
                            + PQI_RSSI_WEIGHT * nrssi)
                         / denom;
    }
}

void log_pqi_state(tx_t* st, int primary_i, int backup_i) {
    int ids[2] = { primary_i, backup_i };
    const char* role[2] = { "primary", "backup" };

    if (!st->log_verbose) return;   /* per-tick state → 1 Hz */
    for (int j = 0; j < 2; j++) {
        int i = ids[j];
        if (i < 0) continue;
        LOGF("[PQI] %s path[%d] grade=%u score=%" PRIu64
             " rtt_ewma=%" PRIu64 " loss_bp_ewma=%" PRIu64
             " bw_ewma=%" PRIu64 " rssi=%d rssi_ewma=%d",
             role[j], i,
             (unsigned)st->pqi_grade[i], st->pqi_score[i],
             st->pqi_rtt_ewma[i], st->pqi_loss_bp_ewma[i],
             st->pqi_bw_ewma[i],
             st->path_rssi_dbm[i], st->path_rssi_ewma_dbm[i]);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Scheduler Choice Logic
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  choose_path_via_pqi() implements the PQI state machine:
 *
 *    last_choice = primary (0):
 *      if primary.grade ≥ 1 (absolute degradation)
 *        AND primary.score ≥ DEGRADE AND backup.score + margin < primary.score
 *        → switch to backup (degrade_failover)
 *      if RSSI mode AND wifi_state ≥ bad
 *        → switch to backup (rssi_preemptive_handover)
 *      else → hold primary
 *
 *    last_choice = backup (1):
 *      if RSSI mode AND wifi_state = good AND primary.grade = 0
 *        AND primary.score ≤ backup.score + margin
 *        AND time_on_backup ≥ FAILBACK_STABLE
 *        → switch to primary (rssi_recover_primary)
 *      if primary.grade = 0 AND primary.score ≤ RECOVER
 *        AND primary.score + margin < backup.score
 *        AND time_on_backup ≥ FAILBACK_STABLE
 *        → switch to primary (stable_failback)
 *      else → hold backup
 *
 *    NOTE: switches are gated on the ABSOLUTE path grade because the min-max
 *    normalized score is relative — with two healthy paths, the marginally
 *    worse one still scores high (ping-pong root cause, 2026-07-12 drive).
 *
 *    no prior choice:
 *      primary.score ≤ backup.score + margin → primary (prefer_primary)
 *      else → backup (better_backup)
 *
 *    single usable path → use that path
 *    both unusable → hold last choice
 *    debounce active (≤2s since last switch) → hold last choice
 *
 *  Reviewer mapping (R3-#1): Novelty is in the hysteresis FSM + EWMA smoothing
 *  + min-max normalization applied specifically to AMR handover scenarios.
 * ═══════════════════════════════════════════════════════════════════════════ */

pqi_choice_t choose_path_via_pqi(tx_t* st, int primary_i, int backup_i,
                                        uint64_t now) {
    int primary_usable = (primary_i >= 0 && st->pqi_score[primary_i] < 1000ULL);
    int backup_usable  = (backup_i  >= 0 && st->pqi_score[backup_i]  < 1000ULL);
    wifi_link_state_t wifi_state = wifi_link_state_from_rssi(st->wifi_last_rssi_dbm);
    pqi_choice_t choice = { .use_i = -1, .choice_kind = -1, .reason = "no_usable_path" };

    if (!primary_usable && !backup_usable) {
        if (st->pqi_last_choice == 0 && primary_i >= 0) {
            choice.use_i = primary_i;
            choice.choice_kind = 0;
            choice.reason = "both_unusable_hold_primary";
        } else if (st->pqi_last_choice == 1 && backup_i >= 0) {
            choice.use_i = backup_i;
            choice.choice_kind = 1;
            choice.reason = "both_unusable_hold_backup";
        }
        return choice;
    }

    if (primary_usable && !backup_usable) {
        choice.use_i = primary_i;
        choice.choice_kind = 0;
        choice.reason = "primary_only";
        return choice;
    }

    if (!primary_usable && backup_usable) {
        choice.use_i = backup_i;
        choice.choice_kind = 1;
        choice.reason = "backup_only";
        return choice;
    }

    /* Preemptive handover escapes the debounce: a collapsing Wi-Fi link must
     * not sit out a hold timer (the timer exists to damp ping-pong between
     * two HEALTHY paths, not to delay an emergency exit). */
    if (st->pqi_last_choice == 0
        && st->scheduler_mode == scheduler_mode_rssi
        && wifi_state >= wifi_link_bad && backup_usable) {
        choice.use_i = backup_i;
        choice.choice_kind = 1;
        choice.reason = "rssi_preemptive_handover";
        return choice;
    }

    {
        uint64_t debounce = st->pqi_dyn_debounce_us ? st->pqi_dyn_debounce_us
                                                    : PQI_SWITCH_DEBOUNCE_US;
        if (st->pqi_last_choice >= 0 && st->pqi_last_switch_us != 0
            && now - st->pqi_last_switch_us <= debounce) {
            choice.choice_kind = st->pqi_last_choice;
            choice.use_i = (st->pqi_last_choice == 0) ? primary_i : backup_i;
            choice.reason = "debounce_hold";
            return choice;
        }
    }

    if (st->pqi_last_choice < 0) {
        if (st->pqi_score[primary_i] <= st->pqi_score[backup_i] + PQI_SWITCH_MARGIN) {
            choice.use_i = primary_i;
            choice.choice_kind = 0;
            choice.reason = "prefer_primary";
        } else {
            choice.use_i = backup_i;
            choice.choice_kind = 1;
            choice.reason = "better_backup";
        }
        return choice;
    }

    if (st->pqi_last_choice == 0) {
        /* (RSSI preemptive handover is checked earlier — before debounce.) */
        /* Absolute-quality gate (2026-07-12 drive fix): min-max normalization
         * is RELATIVE — with two healthy paths the marginally-worse one still
         * scores ≥650, which used to fire degrade_failover ping-pongs at rest
         * (67 switches in one session). Only fail over when the primary is
         * ALSO degraded by absolute thresholds (grade ≥ 1: RTT/loss/RSSI). */
        if (st->pqi_grade[primary_i] >= 1
            && st->pqi_score[primary_i] >= PQI_DEGRADE_SCORE
            && st->pqi_score[backup_i] + PQI_SWITCH_MARGIN < st->pqi_score[primary_i]) {
            choice.use_i = backup_i;
            choice.choice_kind = 1;
            choice.reason = "degrade_failover";
        } else {
            choice.use_i = primary_i;
            choice.choice_kind = 0;
            choice.reason = "hold_primary";
        }
        return choice;
    }

    /* last_choice == 1 (backup) */
    /* RSSI-driven failback: Wi-Fi recovered.
     * Grade gate mirrors degrade_failover: only return to a primary that is
     * healthy by ABSOLUTE thresholds, not merely better in relative terms —
     * an idle primary's EWMA metrics look deceptively good right after a
     * failover, which used to cause immediate failback→failover ping-pong. */
    if (st->scheduler_mode == scheduler_mode_rssi
        && wifi_state == wifi_link_good && primary_usable
        && st->pqi_grade[primary_i] == 0
        && st->pqi_choice_since_us != 0
        && now - st->pqi_choice_since_us >= PQI_FAILBACK_STABLE_US
        && st->pqi_score[primary_i] <= st->pqi_score[backup_i] + PQI_SWITCH_MARGIN) {
        choice.use_i = primary_i;
        choice.choice_kind = 0;
        choice.reason = "rssi_recover_primary";
        return choice;
    }

    /* Standard PQI failback (same absolute grade gate as above) */
    if (st->pqi_choice_since_us != 0
        && now - st->pqi_choice_since_us >= PQI_FAILBACK_STABLE_US
        && st->pqi_grade[primary_i] == 0
        && st->pqi_score[primary_i] <= PQI_RECOVER_SCORE
        && st->pqi_score[primary_i] + PQI_SWITCH_MARGIN < st->pqi_score[backup_i]) {
        choice.use_i = primary_i;
        choice.choice_kind = 0;
        choice.reason = "stable_failback";
    } else {
        choice.use_i = backup_i;
        choice.choice_kind = 1;
        choice.reason = "hold_backup";
    }
    return choice;
}

void update_pqi_choice_state(tx_t* st, const pqi_choice_t* choice,
                                    uint64_t now) {
    /* Switch + ping-pong telemetry (ported from mp-quic-go rssi_aware
     * Switches()/PingPongs()). A ping-pong is a switch that reverses the
     * immediately-preceding one (A→B→A) — a stability metric for the paper. */
    static int prev_switch_from = -1;
    static uint64_t prev_switch_us = 0;
    static int total_switches = 0;
    static int ping_pongs = 0;
    if (!st || !choice || choice->choice_kind < 0) return;

    /* Long stability resets the dynamic debounce back to the base value. */
    if (st->pqi_dyn_debounce_us > PQI_SWITCH_DEBOUNCE_US
        && st->pqi_last_switch_us != 0
        && now - st->pqi_last_switch_us >= PQI_DEBOUNCE_RESET_US) {
        st->pqi_dyn_debounce_us = PQI_SWITCH_DEBOUNCE_US;
    }

    if (st->pqi_last_choice != choice->choice_kind) {
        if (st->pqi_last_choice >= 0) {
            int from = st->pqi_last_choice, to = choice->choice_kind;
            total_switches++;
            if (prev_switch_from == to) {   /* reversed the last switch */
                ping_pongs++;
                /* Ping-pong in a short window → escalate the debounce so the
                 * pair can't keep oscillating (2026-07-12 drive: 67 switches). */
                if (prev_switch_us != 0 && now - prev_switch_us <= PQI_PINGPONG_WINDOW_US) {
                    uint64_t d = st->pqi_dyn_debounce_us ? st->pqi_dyn_debounce_us
                                                         : PQI_SWITCH_DEBOUNCE_US;
                    d *= 2;
                    if (d > PQI_DEBOUNCE_MAX_US) d = PQI_DEBOUNCE_MAX_US;
                    st->pqi_dyn_debounce_us = d;
                    LOGF("[PQI-STAB] ping-pong detected → debounce %.1fs", d / 1e6);
                }
            }
            prev_switch_from = from;
            prev_switch_us = now;
            qlog_switch_event(st->qlog, now, from, to, choice->reason);
            LOGF("[PQI-STAB] switch #%d %d->%d reason=%s ping_pongs=%d",
                 total_switches, from, to, choice->reason ? choice->reason : "", ping_pongs);
        }
        st->pqi_last_choice = choice->choice_kind;
        st->pqi_last_switch_us = now;
        st->pqi_choice_since_us = now;
    } else if (st->pqi_choice_since_us == 0) {
        st->pqi_choice_since_us = now;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module entry point — mirrors the PQI/RSSI branch of select_send_path().
 * ═══════════════════════════════════════════════════════════════════════════
 *  Wraps the PQI core (fill → log → choose → commit) into the sched_choice_t
 *  interface for sched_dispatch(). Behaviour-identical to the inline `default:`
 *  branch in client_loop.c's select_send_path (this is the Chunk-5 target; not
 *  yet the live path).
 */
sched_choice_t sched_pqi_select(tx_t* st, picoquic_cnx_t* c,
                                int primary_i, int backup_i, uint64_t now) {
    sched_choice_t ch = { .use_i = -1, .choice_kind = 0, .reason = "no_path" };
    (void)c;

    fill_pqi_scores(st, primary_i, backup_i);
    log_pqi_state(st, primary_i, backup_i);

    if (primary_i >= 0 || backup_i >= 0) {
        pqi_choice_t pc = choose_path_via_pqi(st, primary_i, backup_i, now);
        if (pc.use_i >= 0) {
            update_pqi_choice_state(st, &pc, now);
            ch.use_i       = pc.use_i;
            ch.choice_kind = pc.choice_kind;
            ch.reason      = pc.reason;
        }
    }
    return ch;
}