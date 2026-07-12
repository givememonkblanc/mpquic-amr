#ifndef CLIENT_CAPTURE_H
#define CLIENT_CAPTURE_H

#include "client_runtime.h"

/* ── Depth (default) camera ── */
int client_start_camera(tx_t* st);
void client_stop_camera(tx_t* st);

/* ── RGB (second) camera for dual-stream ── */
int client_start_camera_rgb(tx_t* st);
void client_stop_camera_rgb(tx_t* st);

#endif
