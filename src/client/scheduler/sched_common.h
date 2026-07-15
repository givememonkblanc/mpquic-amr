#ifndef MPQUIC_SCHED_COMMON_H
#define MPQUIC_SCHED_COMMON_H

/*
 * Shared helpers for the scheduler modules.
 *
 * Path liveness is NOT reimplemented here: the canonical health check is
 * path_is_healthy() (defined in client_paths.c, declared in client_runtime.h),
 * which also accounts for retransmits / bytes-in-transit / a stall window. The
 * modules use it (and path_silence_us) via sched_path_live() below. The only
 * local helper is the "verified + not demoted" schedulability gate for the dumb
 * min-RTT / round-robin baselines (matching select_default_path).
 *
 * The RSSI thresholds MUST stay in sync with client_loop.c's RSSI_*_DBM.
 */

#include <limits.h>
#include <netinet/in.h>
#include "scheduler.h"   /* -> client_runtime.h : tx_t, picoquic_path_t, MAX_PATHS,
                          *    path_is_healthy() */

/* Wi-Fi RSSI grade thresholds (dBm); keep in sync with client_loop.c. */
#define SCHED_RSSI_GOOD_DBM     (-55)
#define SCHED_RSSI_DEGRADE_DBM  (-67)
#define SCHED_RSSI_BAD_DBM      (-75)   /* Wi-Fi->5G down-threshold */
#define SCHED_RSSI_UNUSABLE_DBM (-82)
#define SCHED_PATH_SILENCE_US   8000000ULL   /* 8 s: path considered stale/dead */

/* Verified by the handshake challenge and not demoted (dumb schedulability gate,
 * matching select_default_path — for the min-RTT / round-robin baselines). */
static inline int sched_path_ok(picoquic_cnx_t* c, int i) {
    if (i < 0 || i >= (int)c->nb_paths) return 0;
    picoquic_path_t* p = c->path[i];
    return p && p->first_tuple && p->first_tuple->challenge_verified && !p->path_is_demoted;
}

/* Path i is usable right now. Delegates to the canonical path_is_healthy() and
 * path_silence_us() (both in client_paths.c) plus the same 8 s silence gate that
 * SP-QUIC migration uses, so a just-downed interface still counts as unusable. */
static inline int sched_path_live(picoquic_cnx_t* c, tx_t* st, int i, uint64_t now) {
    return path_is_healthy(c, st, i, now)
        && path_silence_us(st, i, now) <= SCHED_PATH_SILENCE_US;
}

/* Coarse Wi-Fi grade from an RSSI EWMA (dBm). Larger enum value = worse link. */
typedef enum {
    SCHED_WIFI_GOOD = 0,
    SCHED_WIFI_DEGRADING,
    SCHED_WIFI_BAD,
    SCHED_WIFI_UNUSABLE,
    SCHED_WIFI_UNKNOWN
} sched_wifi_t;

static inline sched_wifi_t sched_wifi_from_rssi(int dbm) {
    if (dbm == INT_MIN) return SCHED_WIFI_UNKNOWN;
    if (dbm <= SCHED_RSSI_UNUSABLE_DBM) return SCHED_WIFI_UNUSABLE;
    if (dbm <= SCHED_RSSI_BAD_DBM)      return SCHED_WIFI_BAD;
    if (dbm <= SCHED_RSSI_DEGRADE_DBM)  return SCHED_WIFI_DEGRADING;
    return SCHED_WIFI_GOOD;
}

/* Local IPv4 (big-endian) of path i, or 0. */
static inline uint32_t sched_path_local_ip_be(picoquic_cnx_t* c, int i) {
    if (!sched_path_ok(c, i)) return 0;
    return ((struct sockaddr_in*)&c->path[i]->first_tuple->local_addr)->sin_addr.s_addr;
}

#endif /* MPQUIC_SCHED_COMMON_H */
