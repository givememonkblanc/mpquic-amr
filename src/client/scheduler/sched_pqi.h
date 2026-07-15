#ifndef MPQUIC_SCHED_PQI_H
#define MPQUIC_SCHED_PQI_H

/*
 * Shared parameters and types for the PQI / RSSI scheduler machinery being moved
 * out of client_loop.c into the scheduler/ modules. Values are unchanged (this is
 * a behaviour-preserving relocation); see docs/pqi_parameters.md for the rationale
 * and reviewer mapping.
 */

#include "scheduler.h"   /* -> client_runtime.h : tx_t, picoquic types, MAX_PATHS */

/* ─── PQI composite score weights (α, β, γ) ─── */
#define PQI_ALPHA 450ULL   /* RTT weight       (0.45) */
#define PQI_BETA  350ULL   /* Loss weight      (0.35) */
#define PQI_GAMMA 200ULL   /* Bandwidth weight (0.20) */

/* ─── EWMA smoothing factors (λ) ─── */
#define EWMA_RTT_ALPHA 45ULL   /* RTT EWMA factor       (0.45) */
#define EWMA_LOSS_BETA 15ULL   /* Loss EWMA factor      (0.15) */
#define EWMA_BW_GAMMA  20ULL   /* Bandwidth EWMA factor (0.20) */

/* ─── PQI state-machine thresholds ─── */
#define PQI_DEGRADE_SCORE      650ULL       /* score ≥ this on current path → failover */
#define PQI_RECOVER_SCORE      450ULL       /* score ≤ this on primary → failback       */
#define PQI_SWITCH_MARGIN      120ULL       /* hysteresis margin                        */
#define PQI_FAILBACK_STABLE_US 3000000ULL   /* 3 s — minimum backup tenure              */
#define PQI_PATH_SILENCE_US    8000000ULL   /* 8 s — path stale timeout                 */
#define PQI_SWITCH_DEBOUNCE_US 2000000ULL   /* 2 s — min inter-switch interval          */

/* ─── Loss sampling window ─── */
#define PQI_LOSS_MIN_SAMPLE_BYTES 262144ULL  /* 256 KB before a loss ratio is meaningful */

/* ─── Anti-ping-pong dynamic debounce ─── */
#define PQI_PINGPONG_WINDOW_US 10000000ULL   /* 10 s */
#define PQI_DEBOUNCE_MAX_US    60000000ULL   /* 60 s cap */
#define PQI_DEBOUNCE_RESET_US  90000000ULL   /* 90 s stable → reset to base */

/* ─── RSSI weight and thresholds (dBm) ─── */
#define PQI_RSSI_WEIGHT 300ULL              /* RSSI penalty weight (0.30 rel. to 1000) */
#define RSSI_SAMPLE_INTERVAL_US 500000ULL   /* 500 ms between Wi-Fi RSSI samples        */
#define RSSI_GOOD_DBM     (-55)             /* ≥ −55 dBm: excellent link                */
#define RSSI_DEGRADE_DBM  (-67)             /* ≤ −67 dBm: noticeable degradation        */
#define RSSI_BAD_DBM      (-75)             /* ≤ −75 dBm: poor link                     */
#define RSSI_UNUSABLE_DBM (-82)             /* ≤ −82 dBm: connection likely to drop     */

/* ─── Wi-Fi link state machine ─── */
typedef enum {
    wifi_link_unknown = 0,
    wifi_link_good,
    wifi_link_degrading,
    wifi_link_bad,
    wifi_link_unusable
} wifi_link_state_t;

/* ─── Scheduler choice result (legacy name; identical to sched_choice_t) ─── */
typedef struct {
    int         use_i;        /* path index to use, or -1        */
    int         choice_kind;  /* 0 = primary, 1 = backup         */
    const char* reason;       /* reason string (logged to CSV)   */
} pqi_choice_t;

/* ─── Helpers implemented in sched_pqi.c (moved from client_loop.c) ─── */
uint64_t          ewma_u64(uint64_t prev, uint64_t raw, uint64_t weight_pct);
int               ewma_i32(int prev, int raw, uint64_t weight_pct);
uint64_t          clamp_norm_u64(uint64_t value, uint64_t min_v, uint64_t max_v);
uint64_t          grade_rtt_us(void);
uint64_t          grade_loss_bp(void);
uint64_t          backpressure_target_ms(void);
int               is_wifi_ipv4(uint32_t local_ip_be);
uint64_t          rssi_penalty_from_dbm(int rssi_dbm);
wifi_link_state_t wifi_link_state_from_rssi(int rssi_dbm);
const char*       wifi_link_state_name(wifi_link_state_t s);
void              refresh_wifi_rssi(tx_t* st, uint64_t now);

/* ─── PQI core: metrics / scoring / state machine (moved from client_loop.c) ─── */
void         update_pqi_metrics_for_path(tx_t* st, picoquic_path_t* p, int i,
                                         uint64_t now, int healthy);
void         fill_pqi_scores(tx_t* st, int primary_i, int backup_i);
void         log_pqi_state(tx_t* st, int primary_i, int backup_i);
pqi_choice_t choose_path_via_pqi(tx_t* st, int primary_i, int backup_i, uint64_t now);
void         update_pqi_choice_state(tx_t* st, const pqi_choice_t* choice, uint64_t now);

#endif /* MPQUIC_SCHED_PQI_H */
