#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <png.h>
#include <jpeglib.h>
#include "depth_preview.h"

/*
 * Depth-frame preview: 16-bit PNG depth → jet-colormap JPEG, plus the PNG
 * signature check. Pure pixel conversion (libpng/libjpeg) with no server/RX
 * state — moved verbatim out of frame_assembler.c (behaviour preserving).
 */

int is_png_data(const uint8_t* buf, size_t len){
    static const unsigned char png_sig[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (len < 8) return 0;
    return memcmp(buf, png_sig, 8) == 0;
}

/* ── PNG read callback (libpng memory I/O) ──────────────────── */
struct png_mem_io { const uint8_t* d; size_t s; size_t p; };
static void png_mem_read_fn(png_structp p, png_bytep o, png_size_t n){
    struct png_mem_io* m = (struct png_mem_io*)png_get_io_ptr(p);
    size_t avail = m->s - m->p;
    if (n > avail) n = avail;
    memcpy(o, m->d + m->p, n);
    m->p += n;
}

/* ── qsort comparator for uint16_t ──────────────────────────── */
static int cmp_u16(const void* a, const void* b){
    uint16_t va = *(const uint16_t*)a;
    uint16_t vb = *(const uint16_t*)b;
    return (va > vb) - (va < vb);
}

/**
 * Parse a 16-bit grayscale PNG from memory, apply a jet colormap,
 * and JPEG-encode the result into a heap buffer.
 *
 * Returns a malloc'd buffer holding the JPEG data (set *out_len),
 * or NULL on failure. Caller must free().
 */
uint8_t* depth_png_to_preview_jpeg(const uint8_t* png_data, size_t png_len,
                                           size_t* out_len) {
    *out_len = 0;

    /* ── libpng: read from memory ──────────────────────── */
    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING,
                                              NULL, NULL, NULL);
    if (!png) return NULL;
    png_infop info = png_create_info_struct(png);
    if (!info) { png_destroy_read_struct(&png, NULL, NULL); return NULL; }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        return NULL;
    }

    struct png_mem_io io = {png_data, png_len, 0};
    png_set_read_fn(png, &io, png_mem_read_fn);

    png_read_info(png, info);
    int w = (int)png_get_image_width(png, info);
    int h = (int)png_get_image_height(png, info);
    int bit_depth = png_get_bit_depth(png, info);
    int color_type = png_get_color_type(png, info);

    /* Convert to 16-bit grayscale if needed */
    if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
        color_type == PNG_COLOR_TYPE_RGB_ALPHA)
        png_set_strip_alpha(png);
    if (bit_depth < 8) png_set_packing(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 16) png_set_expand_gray_1_2_4_to_8(png);
    /* If it's already 16-bit gray, keep it — we want the full precision */
    png_read_update_info(png, info);

    int row_bytes = (int)png_get_rowbytes(png, info);
    int channels = (int)png_get_channels(png, info);

    /* Allocate rows and read */
    uint8_t** rows = (uint8_t**)malloc(sizeof(uint8_t*) * (size_t)h);
    for (int y = 0; y < h; y++) rows[y] = (uint8_t*)malloc((size_t)row_bytes);
    png_read_image(png, rows);
    png_read_end(png, NULL);
    png_destroy_read_struct(&png, &info, NULL);

    /* ── Normalize 16-bit → 8-bit (robust percentile) ──── */
    int is_16bit = (bit_depth == 16 && channels == 1);
    uint8_t* gray8 = (uint8_t*)malloc((size_t)(w * h));
    uint16_t vmin = 0, vmax = 65535;

    if (is_16bit) {
        /* Gather all valid (>0) samples */
        uint16_t* samples = (uint16_t*)malloc(sizeof(uint16_t) * (size_t)(w * h));
        int n_valid = 0;
        for (int y = 0; y < h; y++) {
            uint16_t* row = (uint16_t*)rows[y];
            for (int x = 0; x < w; x++) {
                uint16_t v = row[x];
                if (v > 0) samples[n_valid++] = v;
            }
        }
        if (n_valid > 0) {
            qsort(samples, (size_t)n_valid, sizeof(uint16_t), cmp_u16);
            vmin = samples[n_valid / 50];       /*  2nd percentile */
            vmax = samples[(n_valid * 49) / 50]; /* 98th percentile */
            if (vmax <= vmin) vmax = vmin + 1;
            /* Normalize per PIXEL from the original depth rows. `samples` is
             * sorted (used only for the percentiles) — indexing it by raster
             * position would scramble the image and read past n_valid. */
            float scale = 255.0f / (float)(vmax - vmin);
            for (int y = 0; y < h; y++) {
                uint16_t* row = (uint16_t*)rows[y];
                for (int x = 0; x < w; x++) {
                    uint16_t v = row[x];
                    int u8 = (v <= vmin) ? 0 : (int)((v - vmin) * scale);
                    if (u8 > 255) u8 = 255;
                    gray8[y * w + x] = (uint8_t)u8;
                }
            }
        } else {
            memset(gray8, 0, (size_t)(w * h)); /* no valid depth → all-black preview */
        }
        free(samples);
    } else {
        /* 8-bit gray — direct copy */
        for (int y = 0; y < h; y++)
            memcpy(gray8 + y * w, rows[y], (size_t)w);
    }

    /* Free PNG rows */
    for (int y = 0; y < h; y++) free(rows[y]);
    free(rows);

    /* ── Apply jet colormap ────────────────────────────── */
    static uint8_t jet_r[256], jet_g[256], jet_b[256];
    static int jet_init = 0;
    if (!jet_init) {
        for (int i = 0; i < 256; i++) {
            float x = i / 255.0f;
            if (x < 0.125f) {
                jet_r[i] = 0;
                jet_g[i] = 0;
                jet_b[i] = (uint8_t)((x / 0.125f) * 255.0f);
            } else if (x < 0.375f) {
                float t = (x - 0.125f) / 0.25f;
                jet_r[i] = (uint8_t)(t * 255.0f);
                jet_g[i] = (uint8_t)(t * 255.0f);
                jet_b[i] = 255;
            } else if (x < 0.625f) {
                float t = (0.625f - x) / 0.25f;
                jet_r[i] = 255;
                jet_g[i] = 255;
                jet_b[i] = (uint8_t)(t * 255.0f);
            } else if (x < 0.875f) {
                float t = (0.875f - x) / 0.25f;
                jet_r[i] = (uint8_t)(t * 255.0f);
                jet_g[i] = (uint8_t)(t * 255.0f);
                jet_b[i] = 0;
            } else {
                jet_r[i] = 0;
                jet_g[i] = 0;
                jet_b[i] = 0;
            }
        }
        jet_init = 1;
    }

    uint8_t* rgb = (uint8_t*)malloc(sizeof(uint8_t) * (size_t)(w * h * 3));
    for (int i = 0; i < w * h; i++) {
        int idx = gray8[i];
        rgb[i * 3 + 0] = jet_r[idx];
        rgb[i * 3 + 1] = jet_g[idx];
        rgb[i * 3 + 2] = jet_b[idx];
    }
    free(gray8);

    /* ── libjpeg: encode RGB → JPEG in memory ─────────── */
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);

    unsigned long jpg_size = 0;
    uint8_t* jpg_data = NULL;
    jpeg_mem_dest(&cinfo, &jpg_data, &jpg_size);

    cinfo.image_width = w;
    cinfo.image_height = h;
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 85, TRUE);
    jpeg_start_compress(&cinfo, TRUE);

    uint8_t* row_ptrs[1];
    for (int y = 0; y < h; y++) {
        row_ptrs[0] = rgb + y * w * 3;
        jpeg_write_scanlines(&cinfo, row_ptrs, 1);
    }
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    free(rgb);

    *out_len = (size_t)jpg_size;
    return jpg_data;  /* caller must free */
}
