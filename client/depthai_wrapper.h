
#ifndef DEPTHAI_WRAPPER_H
#define DEPTHAI_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void *depthai_handle_t;

// Opens the OAK camera and starts a depthai pipeline:
//   - CAM_A (color) -> RGB output at rgb_w x rgb_h
//   - StereoDepth (CAM_B + CAM_C) -> depth output, resized to depth_w x depth_h
// Background threads keep the latest RGB (JPEG-encoded) and depth (16-bit) frames.
// Returns a handle, or NULL if no OAK device is present / init fails (safe fallback).
depthai_handle_t depthai_open(int rgb_w, int rgb_h, int depth_w, int depth_h, int fps);

// Copies the latest RGB frame as a JPEG into buf (capacity cap bytes).
// Returns the number of bytes written, 0 if no frame yet, or -1 on error.
int depthai_read_rgb(depthai_handle_t h, unsigned char *buf, int cap);

// Copies the latest depth frame as raw little-endian 16-bit (Z16) into buf.
// On success sets *w and *h to the depth dimensions. Returns bytes written,
// 0 if no frame yet, or -1 on error.
int depthai_read_depth(depthai_handle_t h, unsigned char *buf, int cap, int *w, int *h_out);

// Stops the pipeline and frees the handle.
void depthai_close(depthai_handle_t h);

#ifdef __cplusplus
}
#endif

#endif // DEPTHAI_WRAPPER_H
