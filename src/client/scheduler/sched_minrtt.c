#include "sched_common.h"

/*
 * min-RTT (baseline). Send on the verified, non-demoted path with the lowest
 * smoothed RTT (picoquic's native lowest-RTT heuristic). RTT lags loss, so this
 * reacts late at the Wi-Fi boundary (see the paper's algorithmic comparison).
 * Reimplements select_default_path() self-contained.
 */
sched_choice_t sched_minrtt_select(tx_t* st, picoquic_cnx_t* c,
                                   int primary_i, int backup_i, uint64_t now) {
    (void)st; (void)backup_i; (void)now;
    int best = -1;
    uint64_t best_rtt = UINT64_MAX;
    for (int i = 0; i < (int)c->nb_paths; i++) {
        if (!sched_path_ok(c, i)) continue;
        if (c->path[i]->smoothed_rtt < best_rtt) {
            best_rtt = c->path[i]->smoothed_rtt;
            best = i;
        }
    }
    sched_choice_t ch = {
        .use_i = best,
        .choice_kind = (best >= 0 && best == primary_i) ? 0 : 1,
        .reason = (best >= 0) ? "minRTT" : "no_path",
    };
    return ch;
}
