#ifndef FRAME_WRITER_H
#define FRAME_WRITER_H

#include <stdint.h>
#include <stddef.h>
#include "app_ctx.h"

/* Enqueue a completed frame for async disk write (+ preview). save_frame copies
 * the buffer; save_frame_take takes ownership of a malloc'd buffer (freed by the
 * worker). 'd'=depth PNG, 'r'=RGB JPEG. Both start the worker on first call. */
int save_frame(app_ctx_t* app, const uint8_t* data, size_t len, char frame_type);
int save_frame_take(app_ctx_t* app, uint8_t* take, size_t len, char frame_type);

#endif /* FRAME_WRITER_H */
