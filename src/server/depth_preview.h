#ifndef DEPTH_PREVIEW_H
#define DEPTH_PREVIEW_H

#include <stdint.h>
#include <stddef.h>

/* True if buf starts with the 8-byte PNG signature. */
int is_png_data(const uint8_t* buf, size_t len);

/* Convert a 16-bit-depth PNG to a jet-colormap preview JPEG. Returns a malloc'd
 * buffer (set *out_len) the caller must free(), or NULL on failure. */
uint8_t* depth_png_to_preview_jpeg(const uint8_t* png_data, size_t png_len, size_t* out_len);

#endif /* DEPTH_PREVIEW_H */
