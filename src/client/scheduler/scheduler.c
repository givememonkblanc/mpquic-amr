#include "scheduler.h"

/*
 * Central dispatch: route to the module selected by st->scheduler_mode. This is
 * meant to replace the inline switch in select_send_path() (client_loop.c).
 *
 * The current enum (client_runtime.h) has only pqi/rssi/default/spquic. NOTE the
 * mapping decision: scheduler_mode_rssi now routes to the CLEAN, PQI-free
 * sched_rssi_aware (the proposed method), and scheduler_mode_default routes to
 * min-RTT.
 *
 * TODO: extend scheduler_mode_t with round-robin, an explicit min-rtt (distinct
 * from `default`), ecf, blest, tof; extend the MPQUIC_SCHED_MODE parser; add cases.
 */
sched_choice_t sched_dispatch(tx_t* st, picoquic_cnx_t* c,
                              int primary_i, int backup_i, uint64_t now) {
    switch (st->scheduler_mode) {
    case scheduler_mode_pqi:
        return sched_pqi_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_rssi:
        return sched_rssi_aware_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_default:
        return sched_minrtt_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_spquic_migration:
        return sched_spquic_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_round_robin:
        return sched_roundrobin_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_ecf:
        return sched_ecf_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_blest:
        return sched_blest_select(st, c, primary_i, backup_i, now);
    case scheduler_mode_tof:
        return sched_tof_select(st, c, primary_i, backup_i, now);
    default: {
        sched_choice_t ch = { .use_i = primary_i, .choice_kind = 0, .reason = "unknown_mode" };
        return ch;
    }
    }
}
