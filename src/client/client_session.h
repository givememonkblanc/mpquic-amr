#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "client_runtime.h"

int client_init_tx_state(tx_t* st,
                         picoquic_cnx_t* cnx,
                         const struct sockaddr_storage* peerA,
                         const client_options_t* opts);
void client_cleanup_tx_state(tx_t* st);

#endif
