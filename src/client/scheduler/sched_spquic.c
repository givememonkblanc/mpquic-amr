#include "sched_common.h"

/*
 * SP-QUIC + migration (baseline). Single active path: prefer the primary local IP
 * (Wi-Fi) while it is healthy; on primary failure, reactively migrate to any other
 * healthy validated path (5G) — RFC 9000 sec.9 connection migration. Failure
 * detection is reactive (challenge_verified + not demoted + not silent), which is
 * the R1.10 fairness fix: a Wi-Fi path whose interface just went down is "verified"
 * but silent, so we must migrate rather than keep sending into the dead link.
 * Reimplements select_spquic_path() self-contained.
 */
sched_choice_t sched_spquic_select(tx_t* st, picoquic_cnx_t* c,
                                   int primary_i, int backup_i, uint64_t now) {
    (void)primary_i; (void)backup_i;

    /* 1) Preferred: the primary local IP, while it is actually live. */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        if (!sched_path_live(c, st, i, now)) continue;
        if (sched_path_local_ip_be(c, i) == st->ip_primary_be) {
            sched_choice_t ch = { .use_i = i, .choice_kind = 0, .reason = "primary" };
            return ch;
        }
    }
    /* 2) Primary failed -> reactive migration to any live validated path. */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        if (sched_path_live(c, st, i, now)) {
            sched_choice_t ch = { .use_i = i, .choice_kind = 1, .reason = "migrated" };
            return ch;
        }
    }
    /* 3) Nothing live: fall back to any verified path. */
    for (int i = 0; i < (int)c->nb_paths; i++) {
        if (sched_path_ok(c, i)) {
            sched_choice_t ch = { .use_i = i, .choice_kind = 1, .reason = "verified_fallback" };
            return ch;
        }
    }
    sched_choice_t ch = { .use_i = -1, .choice_kind = -1, .reason = "no_path" };
    return ch;
}
