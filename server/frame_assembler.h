// frame_assembler.h
#ifndef FRAME_ASSEMBLER_H
#define FRAME_ASSEMBLER_H

#include <stddef.h>
#include <stdint.h>
#include "app_ctx.h"
#include "picoquic_internal.h"

int fa_on_bytes(picoquic_cnx_t* cnx, app_ctx_t* app, uint64_t sid,
                const uint8_t* bytes, size_t length);

/* 저장 성공(0), 실패(<0) */
int save_frame(app_ctx_t* app, const uint8_t* data, size_t len);

/* 조립 상태 해제 */
void rx_clear(rx_stream_t* rx);
void fa_stream_close(app_ctx_t* app, uint64_t sid);

#endif
