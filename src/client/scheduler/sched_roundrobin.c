#include "sched_common.h"

/*
 * round-robin (baseline, NEW). Cycle evenly through the verified, non-demoted
 * paths regardless of quality. Quality-blind: on heterogeneous paths it causes
 * reordering / HoL blocking and keeps feeding a dying Wi-Fi path at the boundary.
 *
 * The rotating index is a file-static: the AMR client runs one connection, so a
 * per-process counter is sufficient. (If multi-connection is ever needed, move it
 * to a tx_t field.)
 */
sched_choice_t sched_roundrobin_select(tx_t* st, picoquic_cnx_t* c,
                                       int primary_i, int backup_i, uint64_t now) {
    (void)st; (void)backup_i; (void)now;
    static unsigned rr = 0;

    int cand[MAX_PATHS];
    int n = 0;
    for (int i = 0; i < (int)c->nb_paths && n < MAX_PATHS; i++) {
        if (sched_path_ok(c, i)) cand[n++] = i;
    }
    if (n == 0) {
        sched_choice_t ch = { .use_i = -1, .choice_kind = -1, .reason = "no_path" };
        return ch;
    }
    int use = cand[rr++ % n];
    sched_choice_t ch = {
        .use_i = use,
        .choice_kind = (use == primary_i) ? 0 : 1,
        .reason = "round_robin",
    };
    return ch;
}
