#include "client_loop.h"
#include "client_qlogger.h"

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

/* ─── PQI Composite Score Weights (α, β, γ) ─── */
#define PQI_ALPHA 450ULL   /* RTT weight      (0.45) — see PQI formula above */
#define PQI_BETA 350ULL    /* Loss weight     (0.35) */
#define PQI_GAMMA 200ULL   /* Bandwidth weight (0.20) */

/* ─── EWMA Smoothing Factors (λ) ─── */
#define EWMA_RTT_ALPHA 45ULL   /* RTT EWMA factor      (0.45) */
#define EWMA_LOSS_BETA 35ULL   /* Loss EWMA factor     (0.35) */
#define EWMA_BW_GAMMA 20ULL    /* Bandwidth EWMA factor (0.20) */

/* ─── PQI State Machine Thresholds ─── */
#define PQI_DEGRADE_SCORE 650ULL       /* Score ≥ 650 on current path triggers failover */
#define PQI_RECOVER_SCORE 450ULL       /* Score ≤ 450 on primary triggers failback */
#define PQI_SWITCH_MARGIN 120ULL       /* Hysteresis margin */
#define PQI_FAILBACK_STABLE_US 3000000ULL  /* 3 s — minimum backup tenure */
#define PQI_PATH_SILENCE_US 8000000ULL     /* 8 s — path stale timeout */
#define PQI_SWITCH_DEBOUNCE_US 2000000ULL  /* 2 s — min inter-switch interval */

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
 * Minimum bytes sent before a loss ratio sample is considered meaningful
 * (~46 full packets). See update_pqi_metrics_for_path. */
#define PQI_LOSS_MIN_SAMPLE_BYTES 65536ULL

/* ─── Anti-ping-pong dynamic debounce ───
 * A switch that reverses the previous one within PINGPONG_WINDOW doubles the
 * debounce (up to the cap); a stable period resets it to the base value. */
#define PQI_PINGPONG_WINDOW_US 10000000ULL   /* 10 s */
#define PQI_DEBOUNCE_MAX_US    60000000ULL   /* 60 s cap — safe: hard failures
                                              * (grade-2 path death, RSSI-bad
                                              * preemptive handover) bypass the
                                              * debounce entirely; only benign
                                              * score-based switching is damped */
#define PQI_DEBOUNCE_RESET_US  90000000ULL   /* 90 s stable → reset to base */

/* ─── RSSI Weight and Thresholds ─── */
#define PQI_RSSI_WEIGHT 300ULL         /* RSSI penalty weight (0.30 relative to 1000) */
#define RSSI_SAMPLE_INTERVAL_US 500000ULL  /* 500 ms between Wi-Fi RSSI samples */

/* RSSI thresholds (dBm) — based on typical 5 GHz Wi-Fi behavior */
#define RSSI_GOOD_DBM (-55)       /* ≥ −55 dBm: excellent link */
#define RSSI_DEGRADE_DBM (-67)    /* ≤ −67 dBm: noticeable degradation */
#define RSSI_BAD_DBM (-75)        /* ≤ −75 dBm: poor link, high retransmit risk */
#define RSSI_UNUSABLE_DBM (-82)   /* ≤ −82 dBm: connection likely to drop */

/* ─── Wi-Fi link state machine ─── */
typedef enum {
    wifi_link_unknown = 0,
    wifi_link_good,
    wifi_link_degrading,
    wifi_link_bad,
    wifi_link_unusable
} wifi_link_state_t;

/* ─── Scheduler choice result ─── */
typedef struct {
    int use_i;           /* path index to use, or -1 */
    int choice_kind;     /* 0 = primary, 1 = backup */
    const char* reason;  /* human-readable reason string (logged to CSV) */
} pqi_choice_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  EWMA & Normalization Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint64_t ewma_u64(uint64_t prev, uint64_t raw, uint64_t weight_pct) {
    if (prev == 0) return raw;
    return (weight_pct * raw + (100ULL - weight_pct) * prev) / 100ULL;
}

static int ewma_i32(int prev, int raw, uint64_t weight_pct) {
    int64_t w, inv_w;
    if (prev == INT_MIN) return raw;
    w = (int64_t)weight_pct;
    inv_w = 100LL - w;
    return (int)((w * (int64_t)raw + inv_w * (int64_t)prev) / 100LL);
}

/*
 * Min-max normalization to [0, 1000].
 *   norm(x) = ((x − x_min) / (x_max − x_min)) × 1000, clamped to [0, 1000]
 * Applied per decision cycle to RTT, loss, and bandwidth across the two active paths.
 */
static uint64_t clamp_norm_u64(uint64_t value, uint64_t min_v, uint64_t max_v) {
    if (max_v <= min_v) return 0;
    if (value <= min_v) return 0;
    if (value >= max_v) return 1000;
    return ((value - min_v) * 1000ULL) / (max_v - min_v);
}

/*
 * Gray-zone proactive grade thresholds — env-tunable for parameter sweeps
 * (reviewer R#3-3) and set more aggressively than the old 250ms/3% defaults
 * because the 2026-07-10 real drive showed Wi-Fi degrading (RTT 62→188→375 ms,
 * fps 9→4) while RSSI still read a healthy −46 dBm: RSSI alone missed it, so the
 * link-quality grade must trip early to hand over BEFORE the path dies.
 *   MPQUIC_GRADE_RTT_US   (default 180000 = 180 ms)
 *   MPQUIC_GRADE_LOSS_BP  (default 200 = 2.0 %)
 */
static uint64_t grade_rtt_us(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_GRADE_RTT_US");
        v = (s && *s) ? strtoull(s, NULL, 10) : 180000ULL; }
    return v;
}
static uint64_t grade_loss_bp(void) {
    static uint64_t v = 0; static int init = 0;
    if (!init) { init = 1; const char* s = getenv("MPQUIC_GRADE_LOSS_BP");
        v = (s && *s) ? strtoull(s, NULL, 10) : 200ULL; }
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Wi-Fi RSSI Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static int is_wifi_ipv4(uint32_t local_ip_be) {
    uint32_t ip = ntohl(local_ip_be);
    return (ip & 0xFFFF0000U) == 0xC0A80000U; /* 192.168.x.x */
}

static uint64_t rssi_penalty_from_dbm(int rssi_dbm) {
    /* Linear mapping: RSSI_GOOD_DBM → penalty=0, RSSI_UNUSABLE_DBM → penalty=1000 */
    if (rssi_dbm == INT_MIN) return 0;
    if (rssi_dbm >= RSSI_GOOD_DBM) return 0;
    if (rssi_dbm <= RSSI_UNUSABLE_DBM) return 1000;
    return (uint64_t)((RSSI_GOOD_DBM - rssi_dbm) * 1000ULL)
         / (uint64_t)(RSSI_GOOD_DBM - RSSI_UNUSABLE_DBM);
}

static wifi_link_state_t wifi_link_state_from_rssi(int rssi_dbm) {
    if (rssi_dbm == INT_MIN) return wifi_link_unknown;
    if (rssi_dbm <= RSSI_UNUSABLE_DBM) return wifi_link_unusable;
    if (rssi_dbm <= RSSI_BAD_DBM) return wifi_link_bad;
    if (rssi_dbm <= RSSI_DEGRADE_DBM) return wifi_link_degrading;
    return wifi_link_good;
}

static const char* wifi_link_state_name(wifi_link_state_t s) {
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
     * with a scripted dBm value (ported from mp-quic-go's RSSI file source, for
     * reproducible RSSI ramps in evaluation runs). The file holds one integer. */
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

static void refresh_wifi_rssi(tx_t* st, uint64_t now) {
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

/* ═══════════════════════════════════════════════════════════════════════════
 *  Path State Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint64_t path_silence_us(const tx_t* st, int i, uint64_t now) {
    if (!st || i < 0 || i >= MAX_PATHS
        || st->path_last_progress_us[i] == 0 || now <= st->path_last_progress_us[i]) {
        return 0;
    }
    return now - st->path_last_progress_us[i];
}

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

/* ═══════════════════════════════════════════════════════════════════════════
 *  PQI Metrics Update
 * ═══════════════════════════════════════════════════════════════════════════
 *  Updates per-path EWMA (RTT, loss, bandwidth) and computes path grade.
 *  Called for every packet loop callback iteration.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void update_pqi_metrics_for_path(tx_t* st, picoquic_path_t* p, int i,
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
     * Path Grade Assignment
     *   Grade 0 (good):      verified, healthy, RTT ≤ 250ms, loss ≤ 3%, RSSI > BAD
     *   Grade 1 (degraded):  unverified OR unhealthy OR RTT > 250ms OR loss > 3% OR RSSI ≤ BAD
     *   Grade 2 (unusable):  stale (silence > 8s) OR RSSI ≤ UNUSABLE
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
    } else if (st->pqi_rtt_ewma[i] > grade_rtt_us() || st->pqi_loss_bp_ewma[i] > grade_loss_bp()) {
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

static void fill_pqi_scores(tx_t* st, int primary_i, int backup_i) {
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

        st->pqi_score[i] = (PQI_ALPHA * nrtt + PQI_BETA * nloss
                            + PQI_GAMMA * (1000ULL - nbw)
                            + PQI_RSSI_WEIGHT * nrssi)
                         / (1000ULL + PQI_RSSI_WEIGHT);
    }
}

static void log_pqi_state(tx_t* st, int primary_i, int backup_i) {
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

static pqi_choice_t choose_path_via_pqi(tx_t* st, int primary_i, int backup_i,
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

static void update_pqi_choice_state(tx_t* st, const pqi_choice_t* choice,
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
        (void)maybe_probe_desired_path(c, &st->peerA, &st->backup_local,
                                       st->has_backup_local,
                                       &st->last_backup_probe_us, now);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Baseline Scheduler: Default MP-QUIC (minRTT)
 * ═══════════════════════════════════════════════════════════════════════════
 *  Selects the verified path with the lowest smoothed RTT.
 *  This approximates picoquic's internal default scheduler behavior
 *  (lowest-RTT-first among verified paths).
 *
 *  Reviewer mapping: R1-#10, R3-#4
 */

static int select_default_path(picoquic_cnx_t* c, uint64_t now) {
    (void)now;
    int best_i = -1;
    uint64_t best_rtt = UINT64_MAX;

    for (int i = 0; i < (int)c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) continue;
        if (p->path_is_demoted) continue;
        if (p->smoothed_rtt < best_rtt) {
            best_rtt = p->smoothed_rtt;
            best_i = i;
        }
    }
    return best_i;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Baseline Scheduler: SP-QUIC + Connection Migration
 * ═══════════════════════════════════════════════════════════════════════════
 *  Uses only the primary local IP. If the primary path fails (no verified
 *  paths remain), triggers path probing for any available path.
 *
 *  This models QUIC connection migration (RFC 9000 §9):
 *  single-path communication with reactive migration on path failure.
 *
 *  Reviewer mapping: R1-#10, R2-#3
 */

static int select_spquic_path(picoquic_cnx_t* c, tx_t* st, uint64_t now) {
    /* R1.10 fairness fix (2026-07-12): the old selector only checked
     * challenge_verified, which is sticky — a Wi-Fi path whose interface just
     * went down still counts as "verified", so SP-QUIC kept sending into the
     * dead link and NEVER migrated (reviewer: "SP-QUIC cannot exploit the 5G
     * umbrella → unfair comparison"). Per RFC 9000 §9 semantics, migrate to
     * another (pre-validated) path when the current one fails; return to the
     * preferred primary once it is healthy again. Failure detection is
     * REACTIVE (path health / silence), as connection migration is. */
    /* 1) Preferred: the primary local IP, while it is actually healthy */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) continue;
        uint32_t local_ip = ((struct sockaddr_in*)&p->first_tuple->local_addr)->sin_addr.s_addr;
        if (local_ip == st->ip_primary_be && path_is_healthy(c, st, i, now)
            && path_silence_us(st, i, now) <= PQI_PATH_SILENCE_US) {
            return i;
        }
    }
    /* 2) Primary failed → reactive migration to any healthy validated path */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) continue;
        if (path_is_healthy(c, st, i, now)
            && path_silence_us(st, i, now) <= PQI_PATH_SILENCE_US) {
            return i;
        }
    }
    /* 3) Nothing healthy: fall back to any verified path (old behavior) */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        picoquic_path_t* p = c->path[i];
        if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) continue;
        return i;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Main Path Selection Dispatch
 * ═══════════════════════════════════════════════════════════════════════════ */

static int select_send_path(tx_t* st, picoquic_cnx_t* c,
                            int primary_i, int backup_i, uint64_t now,
                            char* reason, size_t reason_sz) {
    int use_i = -1;

    if (reason && reason_sz > 0) reason[0] = '\0';

    switch (st->scheduler_mode) {

    case scheduler_mode_default:
        /* Baseline: picoquic native (minRTT) */
        use_i = select_default_path(c, now);
        if (use_i >= 0) {
            if (st->log_verbose) LOGF("[SEL] default mode: path[%d] (minRTT)", use_i);
            snprintf(reason, reason_sz, "minRTT");
        }
        break;

    case scheduler_mode_spquic_migration:
        /* Baseline: SP-QUIC + connection migration */
        use_i = select_spquic_path(c, st, now);
        if (use_i >= 0) {
            if (st->log_verbose) LOGF("[SEL] spquic mode: path[%d] (primary/migrated)", use_i);
            snprintf(reason, reason_sz,
                     use_i == 0 ? "primary" : "migrated");
        }
        break;

    default:
        /* PQI or RSSI-aware: full PQI scoring + state machine */
        fill_pqi_scores(st, primary_i, backup_i);
        log_pqi_state(st, primary_i, backup_i);

        if (primary_i >= 0 || backup_i >= 0) {
            pqi_choice_t choice = choose_path_via_pqi(st, primary_i, backup_i, now);
            if (choice.use_i >= 0) {
                /* Log at 1 Hz, plus immediately whenever the reason changes
                 * (reason strings are literals → pointer compare suffices). */
                static const char* last_logged_reason = NULL;
                use_i = choice.use_i;
                update_pqi_choice_state(st, &choice, now);
                if (st->log_verbose || choice.reason != last_logged_reason) {
                    last_logged_reason = choice.reason;
                    LOGF("[PQI] choose path[%d] reason=%s score=%" PRIu64,
                         use_i, choice.reason, st->pqi_score[use_i]);
                }
                snprintf(reason, reason_sz, "%s", choice.reason);
            }
        }
        break;
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
