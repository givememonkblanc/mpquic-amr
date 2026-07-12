#include "server_runtime.h"

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [--port N] [--cert path] [--key path] [--qlog] [--binlog]\n"
            "          [--out DIR] [--max-frames N]\n",
            argv0);
}

void server_options_init(server_options_t* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->port = DEFAULT_PORT;
    opts->cert = DEFAULT_CERT;
    opts->key = DEFAULT_KEY;
}

void server_app_init(app_ctx_t* app) {
    memset(app, 0, sizeof(*app));
    snprintf(app->out_dir, sizeof(app->out_dir), "%s", "frames_out");
}

int server_parse_args(int argc, char** argv, server_options_t* opts, app_ctx_t* app) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            opts->port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
            opts->cert = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            opts->key = argv[++i];
        } else if (!strcmp(argv[i], "--qlog")) {
            opts->enable_qlog = 1;
        } else if (!strcmp(argv[i], "--binlog")) {
            opts->enable_binlog = 1;
        } else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
            snprintf(app->out_dir, sizeof(app->out_dir), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--max-frames") && i + 1 < argc) {
            app->max_frames = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

void server_configure_tp(picoquic_quic_t* quic) {
    picoquic_tp_t tp;

    memset(&tp, 0, sizeof(tp));
    picoquic_init_transport_parameters(&tp);

    /* draft-20: multipath is enabled purely by advertising initial_max_path_id
     * (>0); the old tp.is_multipath_enabled field was removed. */
    tp.initial_max_path_id = 16;
    tp.enable_time_stamp = 3;
    tp.max_datagram_frame_size = 1200;
    tp.active_connection_id_limit = 8;
    tp.initial_max_data = 8 * 1024 * 1024;
    tp.initial_max_stream_data_bidi_local = 128 * 1024 * 1024;
    tp.initial_max_stream_data_bidi_remote = 128 * 1024 * 1024;
    tp.initial_max_stream_data_uni = 128 * 1024 * 1024;
    tp.initial_max_stream_id_bidir = 64;
    tp.initial_max_stream_id_unidir = 64;
    tp.max_ack_delay = 0;
    tp.ack_delay_exponent = 3;

    picoquic_set_default_tp(quic, &tp);
}

static void maybe_log_benchmark(app_ctx_t* app) {
    static uint64_t last_bench_log_us = 0;
    uint64_t now = picoquic_current_time();

    if (now - last_bench_log_us <= 500000) return;
    if (app->start_time_us == 0) return;

    {
        double duration = (now - app->start_time_us) / 1000000.0;
        if (duration > 0.1) {
            double mbps = (app->bytes_rx_total * 8.0) / (1024.0 * 1024.0 * duration);
            fprintf(stderr,
                    "[BENCH] Duration: %.2fs | Recv: %.2fMB | Current Rate: %.2fMbps\n",
                    duration,
                    (double)app->bytes_rx_total / 1024.0 / 1024.0,
                    mbps);
        }
    }

    last_bench_log_us = now;
}

static int should_drop_stream_data(app_ctx_t* app) {
    const char* dm = getenv("SVR_DROP_MODE");
    if (app && app->backlog_bytes > BACKLOG_SOFTCAP) {
        app->dropped_frames++;
        return 1;
    }
    return dm && *dm == '1';
}

static void maybe_log_drop(app_ctx_t* app) {
    static uint64_t last_drop_log = 0;
    uint64_t now = picoquic_current_time();

    if (now - last_drop_log <= 1000000) return;
    LOG_WRN("[BENCH] Backlog high! Dropping data. Total drops: %u", app->dropped_frames);
    last_drop_log = now;
}

int server_stream_cb(picoquic_cnx_t* cnx, uint64_t sid, uint8_t* bytes, size_t len,
                     picoquic_call_back_event_t ev, void* cb_ctx, void* v_stream_ctx) {
    static uint64_t log_accum = 0;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;

    (void)v_stream_ctx;

    log_accum += len;
    if (log_accum >= (64 * 1024)) {
        LOG_INF("[RX] ev=%d sid=%" PRIu64 " chunk=%zuB (accum+=%" PRIu64 ")", ev, sid, len, log_accum);
        log_accum = 0;
    }

    switch (ev) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (len > 0) {
            if (app && app->start_time_us == 0) app->start_time_us = picoquic_current_time();
            if (app) app->bytes_rx_total += len;
            if (app) maybe_log_benchmark(app);

            if (!should_drop_stream_data(app)) {
                int r = fa_on_bytes(cnx, app, sid, bytes, len);
                if (r != 0) {
                    LOG_WRN("[RX] fa_on_bytes ret=%d (sid=%" PRIu64 ", len=%zu)", r, sid, len);
                }
            } else {
                maybe_log_drop(app);
            }
        }

        if (ev == picoquic_callback_stream_fin) {
            fa_stream_close(app, sid);
            LOG_INF("[STREAM] FIN sid=%" PRIu64, sid);
        }

        if (app && app->max_frames > 0 && app->frame_count >= app->max_frames) {
            LOG_INF("[LIMIT] reached max_frames=%d → connection close", app->max_frames);
            picoquic_close(cnx, 0);
        }
        return 0;

    case picoquic_callback_stream_reset:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] RESET sid=%" PRIu64, sid);
        return 0;

    case picoquic_callback_stop_sending:
        fa_stream_close(app, sid);
        LOG_WRN("[STREAM] STOP_SENDING sid=%" PRIu64, sid);
        return 0;

    default:
        return 0;
    }
}



static uint64_t last_stats_write_us = 0;
static uint64_t last_received_per_path[16] = {0};
static int current_active_path = -1;

#define MAX_EVENTS 8
static char event_log[MAX_EVENTS][128] = {{0}};
static int event_log_count = 0;
static int event_log_head = 0;

static void add_event_log(uint64_t now, const char* msg) {
    time_t t = now / 1000000;
    struct tm* tm_info = localtime(&t);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    char full_msg[128];
    snprintf(full_msg, sizeof(full_msg), "[%s] %s", time_str, msg);
    
    strncpy(event_log[event_log_head], full_msg, sizeof(event_log[0]));
    event_log_head = (event_log_head + 1) % MAX_EVENTS;
    if (event_log_count < MAX_EVENTS) event_log_count++;
}

static void write_stats_json(picoquic_quic_t* quic, app_ctx_t* app, uint64_t now) {
    if (last_stats_write_us == 0) {
        last_stats_write_us = now;
        return;
    }
    
    uint64_t dt = now - last_stats_write_us;
    if (dt < 500000ULL) return; /* 0.5초마다 업데이트 */
    
    double dt_sec = dt / 1000000.0;
    last_stats_write_us = now;

    char path[512], tmp_path[512];
    snprintf(path, sizeof(path), "%s/stats.json", app->out_dir);
    snprintf(tmp_path, sizeof(tmp_path), "%s/stats.json.tmp", app->out_dir);

    FILE* f = fopen(tmp_path, "w");
    if (!f) return;

    picoquic_cnx_t* c = picoquic_get_first_cnx(quic);

    fprintf(f, "{\n");
    fprintf(f, "  \"timestamp\": %" PRIu64 ",\n", now);
    fprintf(f, "  \"frame_count\": %d,\n", app->frame_count);
    fprintf(f, "  \"frame_pair_idx\": %d,\n", app->frame_pair_idx);
    fprintf(f, "  \"bytes_saved\": %" PRIu64 ",\n", app->bytes_saved_total);
    fprintf(f, "  \"active_path\": %d,\n", current_active_path);
    
    fprintf(f, "  \"events\": [\n");
    for (int e = 0; e < event_log_count; e++) {
        int idx = (event_log_head - event_log_count + e + MAX_EVENTS) % MAX_EVENTS;
        fprintf(f, "    \"%s\"%s\n", event_log[idx], (e == event_log_count - 1) ? "" : ",");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"connections\": [\n");
    if (c) {
        fprintf(f, "    {\n");
        fprintf(f, "      \"state\": \"%s\",\n", cnx_state_str(picoquic_get_cnx_state(c)));
        fprintf(f, "      \"paths\": [\n");
        
        int best_path = -1;
        uint64_t max_rx_delta = 0;

        for (int i = 0; i < (int)c->nb_paths && i < 16; i++) {
            picoquic_path_t* p = c->path[i];
            if (!p) continue;
            
            uint64_t rx_delta = (p->received >= last_received_per_path[i]) ? (p->received - last_received_per_path[i]) : 0;
            double mbps = (rx_delta * 8.0) / dt_sec / 1000000.0;
            last_received_per_path[i] = p->received;
            
            if (rx_delta > max_rx_delta) {
                max_rx_delta = rx_delta;
                best_path = i;
            }
            
            char loc[64] = "unknown", rem[64] = "unknown";
            if (p->first_tuple) {
                addr_to_str((struct sockaddr*)&p->first_tuple->local_addr, loc, sizeof(loc));
                addr_to_str((struct sockaddr*)&p->first_tuple->peer_addr, rem, sizeof(rem));
            }

            fprintf(f, "        {\n");
            fprintf(f, "          \"id\": %d,\n", i);
            fprintf(f, "          \"local_ip\": \"%s\",\n", loc);
            fprintf(f, "          \"remote_ip\": \"%s\",\n", rem);
            fprintf(f, "          \"rtt_ms\": %.1f,\n", p->smoothed_rtt / 1000.0);
            fprintf(f, "          \"throughput_mbps\": %.2f,\n", mbps);
            fprintf(f, "          \"bytes_delivered\": %" PRIu64 ",\n", p->delivered);
            fprintf(f, "          \"bytes_received\": %" PRIu64 ",\n", p->received);
            fprintf(f, "          \"verified\": %s\n", (p->first_tuple && p->first_tuple->challenge_verified) ? "true" : "false");
            fprintf(f, "        }%s\n", (i == c->nb_paths - 1) ? "" : ",");
        }
        
        /* 50KB 이상 수신되었으면 Active 상태로 인정 (약 0.8Mbps) */
        if (best_path >= 0 && max_rx_delta > 50000) {
            if (current_active_path != best_path) {
                char msg[128];
                if (current_active_path == -1) {
                    snprintf(msg, sizeof(msg), "Data stream started on Path %d", best_path);
                } else {
                    snprintf(msg, sizeof(msg), "HANDOVER: Path %d ➔ Path %d", current_active_path, best_path);
                }
                add_event_log(now, msg);
                current_active_path = best_path;
            }
        }

        fprintf(f, "      ]\n");
        fprintf(f, "    }\n");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    rename(tmp_path, path);
}

int server_loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx, void* callback_return) {
    static uint64_t last_paths_dump_us = 0;
    static picoquic_state_enum last_state = (picoquic_state_enum)-1;
    app_ctx_t* app = (app_ctx_t*)cb_ctx;
    picoquic_cnx_t* c;

    (void)callback_return;

    if (cb_mode == picoquic_packet_loop_ready) {
        LOG_INF("[LOOP] QUIC ready, waiting for connections...");
    }

    for (c = picoquic_get_first_cnx(quic); c != NULL; c = picoquic_get_next_cnx(c)) {
        if (picoquic_get_callback_context(c) == NULL) {
            picoquic_set_callback(c, server_stream_cb, app);
        }

        {
            picoquic_state_enum cs = picoquic_get_cnx_state(c);
            if (cs != last_state) {
                struct sockaddr* sa = NULL;
                char hp[128] = {0};
                picoquic_get_peer_addr(c, &sa);
                addr_to_str(sa, hp, sizeof(hp));
                LOG_INF("[CNX] state=%s nb_paths=%d peer=%s", cnx_state_str(cs), (int)c->nb_paths, hp);
                last_state = cs;
            }

            if (!cnx_marked_printed(c) && cs == picoquic_state_ready) {
                struct sockaddr* sa = NULL;
                char hp[128] = {0};
                picoquic_get_peer_addr(c, &sa);
                addr_to_str(sa, hp, sizeof(hp));
                LOG_INF("[CNX] READY peer=%s (paths=%d)", hp, (int)c->nb_paths);
                cnx_mark_set(c);
            }
        }

        if (picoquic_current_time() - last_paths_dump_us > 2 * 1000000ULL) {
            for (int i = 0; i < (int)c->nb_paths; i++) {
                picoquic_path_t* p = c->path[i];
                if (!p) continue;
                LOG_DBG("[PATH] i=%d present=1", i);
            }
            last_paths_dump_us = picoquic_current_time();
        }
    }

    if (cb_mode == picoquic_packet_loop_after_receive || cb_mode == picoquic_packet_loop_after_send) {
        write_stats_json(quic, app, picoquic_current_time());
        for (c = picoquic_get_first_cnx(quic); c != NULL; c = picoquic_get_next_cnx(c)) {
            picoquic_set_app_wake_time(c, picoquic_current_time() + 2000);
        }
    }

    return 0;
}
