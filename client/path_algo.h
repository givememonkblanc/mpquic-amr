#pragma once
#include "picoquic.h"
#include <stdbool.h>

typedef struct app_ctx_s app_ctx_t;

/* ---- 초기화 및 콜백 ---- */
void path_algo_init(app_ctx_t* app);
void path_algo_on_wt_ready(picoquic_cnx_t* cnx, app_ctx_t* app);
void path_algo_on_first_data_stream(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t stream_id);
void path_algo_on_path_created(picoquic_cnx_t* cnx, app_ctx_t* app,
                               picoquic_path_t* p, const char* ifname,
                               bool is_wifi, uint8_t cid_seq);
void path_algo_on_metrics(app_ctx_t* app, picoquic_path_t* p,
                          double rtt_ms, double loss, double delivery_bps,
                          uint64_t inflight_bytes, uint64_t now_us);
void path_algo_on_wifi_moved(app_ctx_t* app);
void path_algo_probe_once(picoquic_cnx_t* cnx, app_ctx_t* app);
void path_algo_tick(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t now_usec);

/* ---- Path 선택 ---- */
picoquic_path_t* path_algo_choose_path(app_ctx_t* app);
picoquic_path_t* path_algo_get_primary(app_ctx_t* app);
picoquic_path_t* path_algo_get_wifi_probe_target(app_ctx_t* app);

/* ---- 듀얼 전송 지원 ---- */
int path_algo_wants_dup_now(app_ctx_t* app);
picoquic_path_t* path_algo_get_dup_target(app_ctx_t* app);

/* ---- 기타 ---- */
int path_is_wifi(app_ctx_t* app, picoquic_path_t* p);
const char* path_label(app_ctx_t* app, picoquic_path_t* p);
