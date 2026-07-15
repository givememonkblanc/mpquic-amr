#include "scheduler.h"

/*
 * ToF - Time-in-Flight scheduler (optional baseline; deterministic).
 * Rank paths by an estimated in-flight time (how long the last sends have been
 * outstanding without progress) instead of smoothed RTT, so it detects SUDDEN
 * mobile-network quality drops faster than SRTT-based schemes. Closest in spirit
 * to our AMR uplink use case (remote monitoring of autonomous driving).
 * Ref: Iwasawa et al., IEEE CCNC 2025.
 *
 * TODO: compute in-flight time per path from st->path_last_progress_us[] /
 * path_last_delivered[] (bytes sent but not yet acked * age); prefer the path
 * with the lowest in-flight time; trip fast when the primary's in-flight inflates.
 */
sched_choice_t sched_tof_select(tx_t* st, picoquic_cnx_t* c,
                                int primary_i, int backup_i, uint64_t now) {
    (void)st; (void)c; (void)backup_i; (void)now;
    sched_choice_t ch = { .use_i = primary_i, .choice_kind = 0, .reason = "TODO_tof" };
    return ch;
}
