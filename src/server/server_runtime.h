#ifndef SERVER_RUNTIME_H
#define SERVER_RUNTIME_H

#include "init.h"
#include "server_utils.h"

typedef struct {
    int port;
    const char* cert;
    const char* key;
    int enable_qlog;
    int enable_binlog;
} server_options_t;

void server_options_init(server_options_t* opts);
int server_parse_args(int argc, char** argv, server_options_t* opts, app_ctx_t* app);
void server_app_init(app_ctx_t* app);
void server_configure_tp(picoquic_quic_t* quic);

int server_stream_cb(picoquic_cnx_t* cnx, uint64_t sid, uint8_t* bytes, size_t len,
                     picoquic_call_back_event_t ev, void* cb_ctx, void* v_stream_ctx);
int server_loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum cb_mode,
                   void* cb_ctx, void* callback_return);

#endif
