#include "scheduler.h"

/*
 * BLEST - Blocking-Estimation-based scheduler (optional baseline; deterministic).
 * Before using a higher-RTT path, estimate whether doing so would block the
 * receiver's in-order delivery (send window / meta-buffer would fill before the
 * low-RTT path's data arrives). If blocking is predicted, WAIT for the low-RTT
 * path instead of sending on the slow one. Minimises out-of-order HoL blocking.
 * Ref: Ferlin et al., IFIP Networking 2016.
 *
 * TODO: implement the blocking estimate from send-window occupancy, the RTT
 * ratio between paths, and in-flight bytes; skip the slow path when it would block.
 */
sched_choice_t sched_blest_select(tx_t* st, picoquic_cnx_t* c,
                                  int primary_i, int backup_i, uint64_t now) {
    (void)st; (void)c; (void)backup_i; (void)now;
    sched_choice_t ch = { .use_i = primary_i, .choice_kind = 0, .reason = "TODO_blest" };
    return ch;
}
