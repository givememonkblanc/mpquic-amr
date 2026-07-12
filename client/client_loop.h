#ifndef CLIENT_LOOP_H
#define CLIENT_LOOP_H

#include "client_runtime.h"

int client_loop_cb(picoquic_quic_t* quic,
                   picoquic_packet_loop_cb_enum mode,
                   void* ctx,
                   void* unused);

#endif
