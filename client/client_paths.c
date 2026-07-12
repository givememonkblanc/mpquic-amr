#include "client_runtime.h"

static inline picoquic_path_t* px_get_path(picoquic_cnx_t* c, int i) {
#if defined(HAVE_PICOQUIC_GET_PATH)
    return picoquic_get_path(c, i);
#else
    return (c && i >= 0 && i < (int)c->nb_paths) ? c->path[i] : NULL;
#endif
}

static void on_cb_event(picoquic_call_back_event_t ev, tx_t* st) {
    switch (ev) {
    case picoquic_callback_ready:
        st->ready_ts_us = picoquic_current_time();
        st->handshake_done = 1;
        LOGF("[CB] handshake complete → ready");
        break;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        st->peer_close_seen = 1;
        LOGF("[CB] closing (IGNORED for test; keeping loop alive)");
        break;
    default:
        break;
    }
}

static int verified(picoquic_cnx_t* c, int i) {
    picoquic_path_t* p;
    if (!c || i < 0 || i >= (int)c->nb_paths) return 0;
    p = px_get_path(c, i);
    return (p && p->first_tuple && p->first_tuple->challenge_verified);
}

static int ensure_bind(picoquic_cnx_t* c, tx_t* st, int i) {
    picoquic_path_t* path;
    uint64_t sid;

    if (!c || !st || !verified(c, i)) return -1;
    if (st->b[i].ready) return 0;

    sid = picoquic_get_next_local_stream_id(c, 1);
    path = px_get_path(c, i);
    if (!path) return -1;

    picoquic_set_stream_path_affinity(c, sid, path->unique_path_id);
    st->b[i].sid = sid;
    st->b[i].ready = 1;
    LOGF("bind: path[%d] uid=%" PRIu64 " -> sid=%" PRIu64, i, path->unique_path_id, sid);
    return 0;
}

static int path_ok(picoquic_cnx_t* c, int i) {
    return c && i >= 0 && i < (int)c->nb_paths && c->path[i] && c->path[i]->first_tuple;
}

int resolve_ip(const char* host, int port, struct sockaddr_storage* out) {
    char port_s[16];
    struct addrinfo hints;
    struct addrinfo* ai = NULL;
    int r;

    if (!host || !out) return -1;
    snprintf(port_s, sizeof(port_s), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    r = getaddrinfo(host, port_s, &hints, &ai);
    if (r != 0 || !ai) return -1;
    memcpy(out, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    return 0;
}

int store_local_ip(const char* ip, uint16_t port, struct sockaddr_storage* out) {
    struct in_addr v4;
    struct in6_addr v6;

    if (!ip || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        struct sockaddr_in* sa = (struct sockaddr_in*)out;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = v4;
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)out;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        sa6->sin6_addr = v6;
        return 0;
    }
    return -1;
}

int hs_done(picoquic_cnx_t* cnx, tx_t* st) {
    picoquic_state_enum s;
    int i;

    if (!cnx) return 0;

    /* If handshake was completed at least once, keep sending even if
     * picoquic internally transitions to closing due to a dead path.
     * MP-QUIC failover requires the app to outlive picoquic's state machine. */
    if (st && st->handshake_done) {
        for (i = 0; i < (int)cnx->nb_paths; i++) {
            if (cnx->path[i] && cnx->path[i]->first_tuple &&
                cnx->path[i]->first_tuple->challenge_verified) {
                return 1;
            }
        }
        /* No verified paths left – connection is truly dead */
        return 0;
    }

    s = picoquic_get_cnx_state(cnx);
    if (s == picoquic_state_client_ready_start || s == picoquic_state_ready) {
        return 1;
    }
    if (cnx->is_handshake_finished && (cnx->is_1rtt_received || cnx->is_1rtt_acked)) {
        return 1;
    }
    return 0;
}

uint64_t make_client_uni_sid_from_index(int i) {
    return 2ull + 4ull * (uint64_t)i;
}

int ensure_stream_for_path(picoquic_cnx_t* c, void* app_ctx, uint64_t* p_sid, int i) {
    static const uint8_t ka = 0;
    (void)i;
    if (!p_sid) return -1;
    if (*p_sid == 0) *p_sid = make_client_uni_sid_from_index(i);
    return picoquic_add_to_stream_with_ctx(c, *p_sid, &ka, 1, 0, app_ctx);
}

int set_affinity_by_index(picoquic_cnx_t* c, uint64_t sid, int i) {
    picoquic_path_t* p;
    if (!c || i < 0 || i >= (int)c->nb_paths) return -1;
    p = c->path[i];
    if (!p) return -1;
    return picoquic_set_stream_path_affinity(c, sid, p->unique_path_id);
}

void ensure_path0_alive(picoquic_cnx_t* c) {
    int i;
    picoquic_path_t* tmp;

    if (!c || path_ok(c, 0)) return;
    for (i = 1; i < (int)c->nb_paths; i++) {
        if (!path_ok(c, i)) continue;
        tmp = c->path[0];
        c->path[0] = c->path[i];
        c->path[i] = tmp;
        return;
    }
}

int path_is_healthy(picoquic_cnx_t* c, tx_t* st, int i, uint64_t now) {
    picoquic_path_t* p;
    uint64_t stall_window;

    if (!c || !st || i < 0 || i >= (int)c->nb_paths) return 0;
    p = c->path[i];
    if (!p || !p->first_tuple || !p->first_tuple->challenge_verified) return 0;
    if (p->path_is_demoted) return 0;
    if (p->nb_retransmit > 2 && p->bytes_in_transit > 0) return 0;

    stall_window = p->smoothed_rtt;
    if (stall_window < 500000ULL) {
        stall_window = 500000ULL;
    }
    stall_window *= 3;

    if (p->nb_retransmit > 0 &&
        st->path_last_progress_us[i] != 0 &&
        p->last_sent_time != 0 &&
        now > st->path_last_progress_us[i] &&
        now - st->path_last_progress_us[i] > stall_window &&
        now > p->last_sent_time &&
        now - p->last_sent_time <= stall_window) {
        return 0;
    }

    return 1;
}

void kick_path_verification(picoquic_cnx_t* c, tx_t* st, int i) {
    picoquic_path_t* p;
    struct sockaddr* peer;
    struct sockaddr* local;
    uint64_t sid;
    uint8_t b = 0xAA;

    p = px_get_path(c, i);
    if (!p || !p->first_tuple) return;

    peer = (struct sockaddr*)&st->peerA;
    local = (struct sockaddr*)&p->first_tuple->local_addr;
    picoquic_probe_new_path(c, peer, local, 0);

    if (ensure_bind(c, st, i) != 0) return;

    sid = st->sid_per_path[i];
    if (sid == 0) {
        sid = make_client_uni_sid_from_index(i);
        if (ensure_stream_for_path(c, st, &sid, i) == 0) {
            st->sid_per_path[i] = sid;
            (void)set_affinity_by_index(c, sid, i);
        }
    }
    (void)picoquic_add_to_stream_with_ctx(c, sid, &b, 1, 0, st);
    picoquic_mark_active_stream(c, sid, 1, st);
}

int maybe_probe_desired_path(picoquic_cnx_t* c,
                             const struct sockaddr_storage* peer,
                             const struct sockaddr_storage* local,
                             int has_local,
                             uint64_t* last_probe_us,
                             uint64_t now) {
    const uint64_t probe_interval_us = 1000000ULL;

    if (!c || !peer || !local || !has_local || !last_probe_us) return -1;
    if (*last_probe_us != 0 && now - *last_probe_us < probe_interval_us) return 0;

    /* Dedupe (2026-07-12 fix): a transiently-unhealthy path made the caller
     * see backup_i < 0 and probe again, piling up duplicate paths to the SAME
     * local IP (observed: 3 hotspot paths) until the path-id budget
     * (initial_max_path_id) was exhausted. If a non-demoted path with this
     * local IP already exists, re-challenge it instead of creating another. */
    if (((const struct sockaddr*)local)->sa_family == AF_INET) {
        uint32_t want_ip = ((const struct sockaddr_in*)local)->sin_addr.s_addr;
        for (int i = 0; i < (int)c->nb_paths; i++) {
            picoquic_path_t* p = px_get_path(c, i);
            if (!p || !p->first_tuple || p->path_is_demoted) continue;
            if (((struct sockaddr_in*)&p->first_tuple->local_addr)->sin_addr.s_addr == want_ip) {
                *last_probe_us = now;
                if (!p->first_tuple->challenge_verified) {
                    /* nudge re-verification of the existing path */
                    picoquic_probe_new_path(c, (const struct sockaddr*)peer,
                                            (struct sockaddr*)&p->first_tuple->local_addr, 0);
                }
                return 0;
            }
        }
    }

    *last_probe_us = now;
    int r = picoquic_probe_new_path(c,
        (const struct sockaddr*)peer,
        (const struct sockaddr*)local,
        now);
    LOGF("[PROBE] probe_new_path ret=%d peer=%s", r, 
         local ? "has_local" : "no_local");
    (void)r;
    return r;
}

int client_cb(picoquic_cnx_t* cnx, uint64_t stream_id,
              uint8_t* bytes, size_t length,
              picoquic_call_back_event_t ev, void* ctx,
              void* stream_ctx) {
    tx_t* st = (tx_t*)ctx;
    (void)cnx;
    (void)stream_id;
    (void)bytes;
    (void)length;
    (void)stream_ctx;
    if (st) on_cb_event(ev, st);
    return 0;
}
