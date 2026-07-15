#include "sched_common.h"

/*
 * RSSI-aware (PROPOSED). Signal-anticipation policy, PQI-free. It reads the Wi-Fi
 * RSSI EWMA and hands over to the cellular path as the coverage boundary is
 * approached, exploiting the AMR's predictable mobility, rather than waiting for
 * the path metrics (RTT/loss) to degrade. Decision uses ONLY the RSSI grade and
 * path liveness -- no pqi_score, no RTT/loss/bw cost.
 *
 * Hysteresis (anti ping-pong), using the thresholds in sched_common.h:
 *   Wi-Fi -> 5G  when the grade reaches BAD (RSSI <= -75 dBm).
 *   5G -> Wi-Fi  when the grade returns to GOOD (RSSI > -67 dBm) AND has held for
 *                RSSI_FAILBACK_HOLD_US (damps oscillation at the boundary).
 * The switch state (pqi_last_choice / pqi_last_switch_us) is persisted by the
 * caller (update_pqi_choice_state); this function only reads it.
 *
 * Known limitation (future work): RSSI anticipates the geometric boundary but
 * misses the "gray-failure" zone (loss at still-good RSSI, seen on the 2026-07-10
 * drive). Combining the RSSI trend with an in-band signal (delay/loss) is left to
 * future work; it is deliberately NOT a PQI cost here.
 */

#define RSSI_FAILBACK_HOLD_US 1000000ULL   /* 1 s stable-GOOD before returning to Wi-Fi */

sched_choice_t sched_rssi_aware_select(tx_t* st, picoquic_cnx_t* c,
                                       int primary_i, int backup_i, uint64_t now) {
    int prim_live = sched_path_live(c, st, primary_i, now);
    int back_live = sched_path_live(c, st, backup_i, now);
    sched_choice_t ch = { .use_i = -1, .choice_kind = -1, .reason = "no_path" };

    /* Only one path live -> use it (this is the reactive fail-over safety net). */
    if (prim_live && !back_live) { ch.use_i = primary_i; ch.choice_kind = 0; ch.reason = "primary_only"; return ch; }
    if (!prim_live && back_live) { ch.use_i = backup_i;  ch.choice_kind = 1; ch.reason = "backup_only";  return ch; }
    if (!prim_live && !back_live) {
        if (st->pqi_last_choice == 1 && backup_i >= 0)      { ch.use_i = backup_i;  ch.choice_kind = 1; }
        else if (primary_i >= 0)                            { ch.use_i = primary_i; ch.choice_kind = 0; }
        ch.reason = "both_down_hold";
        return ch;
    }

    /* Both live: decide by the Wi-Fi RSSI trend with hysteresis. */
    int rssi = (primary_i >= 0 && st->path_rssi_ewma_dbm[primary_i] != 0)
                 ? st->path_rssi_ewma_dbm[primary_i]
                 : st->wifi_last_rssi_dbm;
    sched_wifi_t grade = sched_wifi_from_rssi(rssi);
    int on_backup = (st->pqi_last_choice == 1);
    uint64_t held_us = (st->pqi_last_switch_us && now >= st->pqi_last_switch_us)
                         ? (now - st->pqi_last_switch_us) : UINT64_MAX;

    if (!on_backup) {
        /* On Wi-Fi: pre-emptively hand over to 5G once the link is BAD or worse. */
        if (grade >= SCHED_WIFI_BAD) { ch.use_i = backup_i; ch.choice_kind = 1; ch.reason = "rssi_handover_5g"; return ch; }
        ch.use_i = primary_i; ch.choice_kind = 0; ch.reason = "rssi_wifi";
        return ch;
    }

    /* On 5G: return to Wi-Fi only when it has recovered to GOOD and held. */
    if (grade == SCHED_WIFI_GOOD && held_us >= RSSI_FAILBACK_HOLD_US) {
        ch.use_i = primary_i; ch.choice_kind = 0; ch.reason = "rssi_failback_wifi"; return ch;
    }
    ch.use_i = backup_i; ch.choice_kind = 1; ch.reason = "rssi_hold_5g";
    return ch;
}
