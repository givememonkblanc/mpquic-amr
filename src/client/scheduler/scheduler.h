#ifndef MPQUIC_SCHEDULER_H
#define MPQUIC_SCHEDULER_H

/*
 * Modular path schedulers for the MP-QUIC AMR client.
 *
 * Each scheduler is one translation unit implementing a `select()` with the
 * signature below. `select_send_path()` in client_loop.c dispatches to the module
 * selected by MPQUIC_SCHED_MODE (via sched_dispatch). See README.md for the list
 * and the algorithm each module implements.
 *
 * `sched_choice_t` intentionally mirrors the old inline `pqi_choice_t` so the QoS
 * CSV columns (reason, choice_kind) and the offline metrics stay unchanged.
 */

#include <stdint.h>
#include "../client_runtime.h"   /* tx_t, scheduler_mode_t, picoquic_cnx_t, MAX_PATHS */

typedef struct {
    int         use_i;        /* chosen path index, or -1 = no usable path        */
    int         choice_kind;  /* 0 = primary (Wi-Fi), 1 = backup (5G/cellular)    */
    const char* reason;       /* short reason string, logged to the QoS CSV       */
} sched_choice_t;

/*
 * One select() per scheduler.
 *   st         : client state (per-path metric arrays + switch/hysteresis state)
 *   c          : picoquic connection (for native path metrics / cwnd)
 *   primary_i  : resolved Wi-Fi path index
 *   backup_i   : resolved 5G/cellular path index (-1 if none)
 *   now        : picoquic monotonic time (microseconds)
 */
typedef sched_choice_t (*sched_select_fn)(tx_t* st, picoquic_cnx_t* c,
                                          int primary_i, int backup_i, uint64_t now);

/* --- baselines --- */
sched_choice_t sched_minrtt_select    (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);
sched_choice_t sched_roundrobin_select(tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);
sched_choice_t sched_spquic_select    (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);

/* --- proposed --- */
sched_choice_t sched_rssi_aware_select(tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);

/* --- legacy / extra baselines (compared, not proposed) --- */
sched_choice_t sched_pqi_select       (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);
sched_choice_t sched_ecf_select       (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);
sched_choice_t sched_blest_select     (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);
sched_choice_t sched_tof_select       (tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);

/* Central dispatch on st->scheduler_mode; called from select_send_path(). */
sched_choice_t sched_dispatch(tx_t* st, picoquic_cnx_t* c, int primary_i, int backup_i, uint64_t now);

#endif /* MPQUIC_SCHEDULER_H */
