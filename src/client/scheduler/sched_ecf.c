#include "scheduler.h"

/*
 * ECF - Earliest Completion First (optional baseline; deterministic).
 * Pick the path that makes the current data COMPLETE soonest, using RTT and the
 * congestion window (not RTT alone). If sending on the slower path would delay
 * completion versus waiting for the faster path to free cwnd, WAIT for the fast
 * path instead. Reduces head-of-line blocking on heterogeneous paths.
 * Ref: Lim et al., ACM CoNEXT 2017.
 *
 * TODO: implement the completion-time estimate: for each schedulable path,
 * est = (bytes_queued / cwnd_or_rate) scaled by RTT; choose min; apply the wait
 * rule when the low-RTT path will free up before the high-RTT path would deliver.
 */
sched_choice_t sched_ecf_select(tx_t* st, picoquic_cnx_t* c,
                                int primary_i, int backup_i, uint64_t now) {
    (void)st; (void)c; (void)backup_i; (void)now;
    sched_choice_t ch = { .use_i = primary_i, .choice_kind = 0, .reason = "TODO_ecf" };
    return ch;
}
