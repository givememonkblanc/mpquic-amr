#include "client_capture.h"
#include "client_loop.h"
#include "client_session.h"
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    client_options_t opts;
    picoquic_quic_t* q;
    picoquic_cnx_t* cnx;
    picoquic_tp_t tp;
    struct sockaddr_storage peerA;
    picoquic_packet_loop_param_t lp = {0};
    tx_t st;
    int ret = 0;
    /* Supervised reconnect loop (ported from mp-quic-go cmd/jetson/main.go Fix A):
     * on a real drive a wedged/dead connection must self-recover. picoquic's
     * native multipath already routes around a single dead path, so this only
     * fires when the whole connection dies; disable with MPQUIC_NO_RECONNECT. */
    int reconnect_enabled = (getenv("MPQUIC_NO_RECONNECT") == NULL);
    int attempt = 0;

    if (client_options_parse(argc, argv, &opts) != 0) {
        return 1;
    }

    LOGF("[MAIN] args set: server=%s port=%d primary_local=%s backup_local=%s (reconnect=%d)",
         opts.server_ip, opts.port, opts.primary_local_ip, opts.backup_local_ip, reconnect_enabled);

    for (;;) {
        uint64_t conn_start_us, conn_elapsed_us;
        int clean_stop;

        LOGF("[MAIN] creating QUIC ctx... (attempt %d)", attempt);
        q = picoquic_create(32, NULL, NULL, NULL, "h3",
                            NULL, NULL, NULL, NULL, NULL,
                            picoquic_current_time(), NULL, NULL, NULL, 1);
        if (!q) {
            LOGF("[ERR] picoquic_create failed");
            return -1;
        }
        /* CC default switched cubic → bbr (2026-07-12). CUBIC is loss-based:
         * on these short-RTT paths (~10 ms) it probes until packets drop, so
         * the client's own CC generated a constant 5-25% "loss" that pinned
         * both paths at grade 1 (degraded) and confused the PQI scheduler.
         * BBR is rate-based → near-zero self-induced loss, lower queueing
         * delay (better for live robot video), and the loss signal becomes a
         * genuine indicator of link trouble again.
         * Env MPQUIC_CC (bbr|cubic|newreno|...) keeps cubic available as a
         * paper baseline. */
        const char* cc_name = getenv("MPQUIC_CC");
        if (!cc_name || !*cc_name) cc_name = "bbr";
        picoquic_set_default_congestion_algorithm_by_name(q, cc_name);
        LOGF("[MAIN] congestion control: %s", cc_name);

        memset(&tp, 0, sizeof(tp));
        picoquic_init_transport_parameters(&tp);
        /* draft-20: multipath enabled by advertising initial_max_path_id (>0);
         * the old tp.is_multipath_enabled field was removed. */
        tp.initial_max_path_id = 3;
        tp.enable_time_stamp = 3;
        tp.active_connection_id_limit = 8;
        tp.initial_max_data = 64 * 1024 * 1024;
        tp.initial_max_stream_data_uni = 8 * 1024 * 1024;
        tp.initial_max_stream_data_bidi_local = 8 * 1024 * 1024;
        tp.initial_max_stream_data_bidi_remote = 8 * 1024 * 1024;
        tp.max_datagram_frame_size = 1280;
        picoquic_set_default_tp(q, &tp);

        if (resolve_ip(opts.server_ip, opts.port, &peerA) != 0) {
            LOGF("[ERR] resolve server failed: %s:%d", opts.server_ip, opts.port);
            picoquic_free(q);
            return -1;   /* a bad server address will never resolve — do not spin */
        }
        cnx = picoquic_create_cnx(q, picoquic_null_connection_id, picoquic_null_connection_id,
                                  (struct sockaddr*)&peerA, picoquic_current_time(),
                                  0, opts.server_ip, "hq", 1);
        if (!cnx) {
            LOGF("[ERR] picoquic_create_cnx failed");
            picoquic_free(q);
            goto reconnect;
        }
        picoquic_set_congestion_algorithm(cnx, picoquic_get_congestion_algorithm(cc_name));
        picoquic_enable_keep_alive(cnx, 1);

        if (client_init_tx_state(&st, cnx, &peerA, &opts) != 0) {
            LOGF("[ERR] tx state init failed");
            picoquic_free(q);
            goto reconnect;
        }

        picoquic_set_callback(cnx, client_cb, &st);
        LOGF("[MAIN] starting client connection...");
        if (picoquic_start_client_cnx(cnx) != 0) {
            LOGF("[ERR] picoquic_start_client_cnx failed");
            client_cleanup_tx_state(&st);
            picoquic_free(q);
            goto reconnect;
        }

        if (client_start_camera(&st) != 0) {
            LOGF("[ERR] camera start failed");
            client_cleanup_tx_state(&st);
            picoquic_free(q);
            goto reconnect;
        }
        /* Start RGB camera (second stream) — non-fatal if unavailable */
        client_start_camera_rgb(&st);

        LOGF("[MAIN] entering packet loop: server=%s port=%d, primary_local=%s backup_local=%s",
             opts.server_ip, opts.port, opts.primary_local_ip, opts.backup_local_ip);
        lp.local_af = AF_INET;
        lp.local_port = 0;
        lp.socket_buffer_size = 0;
        lp.do_not_use_gso = 0;
        lp.extra_socket_required = 0;

        conn_start_us = picoquic_current_time();
        ret = picoquic_packet_loop_v2(q, &lp, client_loop_cb, &st);
        conn_elapsed_us = picoquic_current_time() - conn_start_us;

        LOGF("[MAIN] packet loop end: ret=%d (up %.1fs)", ret, conn_elapsed_us / 1e6);
        clean_stop = st.exp_finished;   /* experiment duration elapsed = intentional */
        client_cleanup_tx_state(&st);
        picoquic_free(q);

        if (clean_stop || !reconnect_enabled) {
            LOGF("[MAIN] quic ctx freed, exit ret=%d", ret);
            return ret;
        }
        /* A connection that stayed up a while is a fresh failure, not a flap —
         * reset the backoff so recovery is fast again. */
        if (conn_elapsed_us > 10000000ULL) attempt = 0;

    reconnect:
        {
            int backoff_ms = 500 << (attempt < 4 ? attempt : 4);  /* 500,1000,2000,4000,8000 */
            if (backoff_ms > 5000) backoff_ms = 5000;             /* cap 5s */
            LOGF("[MAIN] connection ended; reconnecting in %d ms", backoff_ms);
            usleep((useconds_t)backoff_ms * 1000);
            attempt++;
        }
    }
}
