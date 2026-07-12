// server_recv.c — picoquic raw-stream receiver entrypoint

#include "server_runtime.h"

int main(int argc, char** argv) {
    server_options_t opts;
    app_ctx_t app;
    picoquic_quic_t* quic;
    picoquic_packet_loop_param_t lp = {0};
    int ret;

    server_options_init(&opts);
    server_app_init(&app);

    if (server_parse_args(argc, argv, &opts, &app) != 0) {
        return -1;
    }

    LOGF("[SVR][MAIN] args: port=%d cert=%s key=%s out=%s max_frames=%d",
         opts.port, opts.cert, opts.key, app.out_dir, app.max_frames);

    LOGF("[SVR][MAIN] creating QUIC ctx (ALPN=hq)...");
    quic = picoquic_create(64, opts.cert, opts.key, NULL, "hq",
                           server_stream_cb, &app, NULL, NULL, NULL,
                           picoquic_current_time(), NULL, NULL, NULL, 1);
    if (!quic) {
        LOGF("[SVR][ERR] picoquic_create failed");
        return -1;
    }

    server_configure_tp(quic);
    ensure_dir(app.out_dir);

    /* Resume the frame serial above the highest already on disk so a server
     * restart never overwrites previously recorded frames (ported from
     * mp-quic-go jetson_handler.maxSerialOnDisk). */
    app.frame_pair_idx = fa_max_frame_idx_on_disk(app.out_dir);
    app.frame_count = app.frame_pair_idx;
    LOGF("[SVR][MAIN] frame serial seeded from disk: next=%d", app.frame_pair_idx + 1);

    lp.local_port = opts.port;
    lp.local_af = AF_INET;
    lp.extra_socket_required = 0;
    lp.socket_buffer_size = 4 * 1024 * 1024;
    lp.do_not_use_gso = 0;

    LOGF("[SVR][MAIN] listen UDP :%d (raw streams, MP enabled)", opts.port);
    ret = picoquic_packet_loop_v2(quic, &lp, server_loop_cb, &app);

    LOGF("[SVR][MAIN] loop end ret=%d", ret);
    picoquic_free(quic);
    LOGF("[SVR][MAIN] quic freed, exit ret=%d", ret);
    return ret;
}
