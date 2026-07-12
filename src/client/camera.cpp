#include "camera.h"
#include "depthai_wrapper.h"
#include <opencv2/opencv.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

extern "C" {

namespace {

struct CameraContext {
    cv::VideoCapture* cap;
    int frame_count;
    int is_depth;            // 1 = depth (16-bit, PNG), 0 = RGB (8-bit, JPEG)
    depthai_handle_t oak;    // shared OAK-D device (non-null → OAK-backed handle)
    int is_oak;

    CameraContext() : cap(nullptr), frame_count(0), is_depth(0), oak(nullptr), is_oak(0) {}
};

// ── Shared OAK-D device ───────────────────────────────────
// One physical OAK-D feeds BOTH the depth and the RGB handle, so the device is
// opened once and reference-counted across camera_create()/camera_create_rgb().
std::mutex g_oak_mtx;
depthai_handle_t g_oak = nullptr;
int  g_oak_refs = 0;
bool g_oak_tried = false;   // only probe the OAK once per process

depthai_handle_t oak_acquire() {
    std::lock_guard<std::mutex> lk(g_oak_mtx);
    if (!g_oak && !g_oak_tried) {
        g_oak_tried = true;
        /* Low-bitrate profile so depth+RGB fit a constrained cellular uplink
         * (~1.5 Mbps). Tunable via env for the link at hand:
         *   MPQUIC_OAK_FPS   (default 5)
         *   MPQUIC_OAK_RGB_W / _H  (default 480x360)
         *   MPQUIC_OAK_DEPTH_W / _H (default 256x192)
         * RGB JPEG quality is MPQUIC_OAK_RGB_QUALITY (default 45) in the wrapper. */
        int fps = 5, rgbw = 480, rgbh = 360, dw = 256, dh = 192;
        const char* e;
        if ((e = getenv("MPQUIC_OAK_FPS"))     && *e) { int v = atoi(e); if (v > 0) fps  = v; }
        if ((e = getenv("MPQUIC_OAK_RGB_W"))   && *e) { int v = atoi(e); if (v > 0) rgbw = v; }
        if ((e = getenv("MPQUIC_OAK_RGB_H"))   && *e) { int v = atoi(e); if (v > 0) rgbh = v; }
        if ((e = getenv("MPQUIC_OAK_DEPTH_W")) && *e) { int v = atoi(e); if (v > 0) dw   = v; }
        if ((e = getenv("MPQUIC_OAK_DEPTH_H")) && *e) { int v = atoi(e); if (v > 0) dh   = v; }
        g_oak = depthai_open(rgbw, rgbh, dw, dh, fps);
        if (g_oak) std::fprintf(stderr, "[CAM] OAK-D opened (RGB %dx%d + depth %dx%d @%dfps, low-bitrate)\n",
                                rgbw, rgbh, dw, dh, fps);
    }
    if (g_oak) g_oak_refs++;
    return g_oak;
}

void oak_release() {
    std::lock_guard<std::mutex> lk(g_oak_mtx);
    if (g_oak && --g_oak_refs <= 0) {
        depthai_close(g_oak);
        g_oak = nullptr;
        g_oak_refs = 0;
        g_oak_tried = false;
    }
}

std::vector<int> list_video_indices() {
    std::vector<int> indices;
    DIR* dir = opendir("/dev");
    if (!dir) {
        return indices;
    }

    while (dirent* entry = readdir(dir)) {
        const char* name = entry->d_name;
        constexpr const char* prefix = "video";
        if (std::strncmp(name, prefix, std::strlen(prefix)) != 0) {
            continue;
        }

        const char* suffix = name + std::strlen(prefix);
        if (*suffix == '\0') {
            continue;
        }
        bool all_digits = true;
        for (const char* p = suffix; *p != '\0'; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) {
                all_digits = false;
                break;
            }
        }
        if (!all_digits) {
            continue;
        }
        indices.push_back(std::atoi(suffix));
    }

    closedir(dir);
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    return indices;
}

/**
 * @brief Try to open a DEPTH camera (16-bit Y16 format) at the given index.
 *
 * Opens with CAP_PROP_CONVERT_RGB=0 to get raw 16-bit data,
 * reads a probe frame and checks for CV_16U depth.
 */
cv::VideoCapture* try_open_depth_camera(int index) {
    cv::VideoCapture* cap = new cv::VideoCapture(index, cv::CAP_V4L2);
    if (!cap->isOpened()) {
        delete cap;
        return nullptr;
    }

    // Raw 16-bit mode — do NOT let OpenCV squash to 8-bit BGR
    cap->set(cv::CAP_PROP_CONVERT_RGB, 0);

    cv::Mat probe;
    if (!cap->read(probe) || probe.empty()) {
        cap->release();
        delete cap;
        return nullptr;
    }

    // Confirm it is a real 16-bit depth stream
    if (probe.depth() != CV_16U || probe.channels() != 1) {
        cap->release();
        delete cap;
        return nullptr;
    }

    std::fprintf(stderr, "[CAM] depth camera /dev/video%d  %dx%d  16-bit\n",
                 index, probe.cols, probe.rows);

    // Re-open cleanly for capture with raw mode locked in
    cap->release();
    delete cap;

    cv::VideoCapture* depth_cap = new cv::VideoCapture(index, cv::CAP_V4L2);
    depth_cap->set(cv::CAP_PROP_CONVERT_RGB, 0);
    return depth_cap;
}

/**
 * @brief Fallback: try to open an RGB camera (MJPEG → BGR).
 */
cv::VideoCapture* try_open_rgb_camera(int index) {
    cv::VideoCapture* cap = new cv::VideoCapture(index, cv::CAP_V4L2);
    if (!cap->isOpened()) {
        delete cap;
        return nullptr;
    }

    cap->set(cv::CAP_PROP_FOURCC, cv::VideoWriter::fourcc('M', 'J', 'P', 'G'));
    cap->set(cv::CAP_PROP_FRAME_WIDTH, 640);
    cap->set(cv::CAP_PROP_FRAME_HEIGHT, 480);
    cap->set(cv::CAP_PROP_FPS, 30);

    cv::Mat probe;
    if (!cap->read(probe) || probe.empty()) {
        cap->release();
        delete cap;
        return nullptr;
    }

    return cap;
}

// ── Camera open strategy ──────────────────────────────────
// 1) Scan all /dev/videoN for a depth (16-bit Y16) camera.
// 2) If none found, scan for an RGB camera.
// 3) If still nothing, return nullptr.
//
// Returns the CAMERA — caller must check is_depth field.
static int open_camera(cv::VideoCapture** out_cap, int* out_is_depth) {
    *out_cap = nullptr;
    *out_is_depth = 0;

    // Phase 1 — depth camera
    for (int idx : list_video_indices()) {
        cv::VideoCapture* cap = try_open_depth_camera(idx);
        if (cap) {
            std::fprintf(stderr, "[CAM] opened depth camera /dev/video%d\n", idx);
            *out_cap = cap;
            *out_is_depth = 1;
            return 0;
        }
    }

    // Phase 2 — RGB camera fallback
    for (int idx : list_video_indices()) {
        cv::VideoCapture* cap = try_open_rgb_camera(idx);
        if (cap) {
            std::fprintf(stderr, "[CAM] opened RGB camera /dev/video%d (depth unavailable)\n", idx);
            *out_cap = cap;
            *out_is_depth = 0;
            return 0;
        }
    }

    return -1;   // no camera at all
}

bool allow_test_pattern_fallback() {
    const char* value = std::getenv("MPQUIC_ALLOW_TEST_PATTERN");
    if (!value || *value == '\0') {
        return false;
    }

    std::string s(value);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

}  // namespace

// ────────────────────────────────────────────────────────────
//  Public API — Single-camera (auto-detect)
// ────────────────────────────────────────────────────────────

camera_handle_t camera_create() {
    CameraContext* ctx = new CameraContext();

    // OAK-D first: a single device serves both depth and RGB. This handle
    // carries the DEPTH stream.
    depthai_handle_t oak = oak_acquire();
    if (oak) {
        ctx->oak = oak;
        ctx->is_oak = 1;
        ctx->is_depth = 1;
        std::fprintf(stderr, "[CAM] using OAK-D depth stream\n");
        return static_cast<camera_handle_t>(ctx);
    }

    cv::VideoCapture* cap = nullptr;
    int is_depth = 0;

    if (open_camera(&cap, &is_depth) != 0) {
        if (!allow_test_pattern_fallback()) {
            std::fprintf(stderr,
                         "[CAM][ERR] no camera available and test-pattern fallback is disabled\n");
            delete ctx;
            return nullptr;
        }
        std::fprintf(stderr,
                     "[CAM][WARN] no camera → using test pattern\n");
        ctx->is_depth = 0;   // test pattern produces 8-bit RGB
        return static_cast<camera_handle_t>(ctx);
    }

    ctx->cap = cap;
    ctx->is_depth = is_depth;
    std::fprintf(stderr, "[CAM] ready  is_depth=%d  %dx%d  %d-bit\n",
                 is_depth,
                 (int)cap->get(cv::CAP_PROP_FRAME_WIDTH),
                 (int)cap->get(cv::CAP_PROP_FRAME_HEIGHT),
                 is_depth ? 16 : 8);
    return static_cast<camera_handle_t>(ctx);
}

// ────────────────────────────────────────────────────────────
//  Public API — Dedicated RGB camera
// ────────────────────────────────────────────────────────────

camera_handle_t camera_create_rgb() {
    CameraContext* ctx = new CameraContext();

    // OAK-D first: this handle carries the RGB stream of the shared device.
    depthai_handle_t oak = oak_acquire();
    if (oak) {
        ctx->oak = oak;
        ctx->is_oak = 1;
        ctx->is_depth = 0;
        std::fprintf(stderr, "[CAM] using OAK-D RGB stream\n");
        return static_cast<camera_handle_t>(ctx);
    }

    for (int idx : list_video_indices()) {
        cv::VideoCapture* cap = try_open_rgb_camera(idx);
        if (cap) {
            ctx->cap = cap;
            ctx->is_depth = 0;
            std::fprintf(stderr, "[CAM] opened RGB camera /dev/video%d  %dx%d\n",
                         idx,
                         (int)cap->get(cv::CAP_PROP_FRAME_WIDTH),
                         (int)cap->get(cv::CAP_PROP_FRAME_HEIGHT));
            return static_cast<camera_handle_t>(ctx);
        }
    }

    std::fprintf(stderr, "[CAM][ERR] no RGB camera found\n");
    delete ctx;
    return nullptr;
}

// ────────────────────────────────────────────────────────────
//  Public API — Dedicated Depth camera by index
// ────────────────────────────────────────────────────────────

camera_handle_t camera_create_depth_by_index(int index) {
    CameraContext* ctx = new CameraContext();

    cv::VideoCapture* cap = try_open_depth_camera(index);
    if (cap) {
        ctx->cap = cap;
        ctx->is_depth = 1;
        std::fprintf(stderr, "[CAM] opened depth camera /dev/video%d  %dx%d  16-bit\n",
                     index,
                     (int)cap->get(cv::CAP_PROP_FRAME_WIDTH),
                     (int)cap->get(cv::CAP_PROP_FRAME_HEIGHT));
        return static_cast<camera_handle_t>(ctx);
    }

    std::fprintf(stderr, "[CAM][ERR] no depth camera at /dev/video%d\n", index);
    delete ctx;
    return nullptr;
}

// ────────────────────────────────────────────────────────────
//  Public API — query is_depth flag
// ────────────────────────────────────────────────────────────

int camera_is_depth(camera_handle_t handle) {
    if (!handle) return 0;
    CameraContext* ctx = static_cast<CameraContext*>(handle);
    return ctx->is_depth;
}

void camera_destroy(camera_handle_t handle) {
    if (!handle) return;
    CameraContext* ctx = static_cast<CameraContext*>(handle);
    if (ctx->is_oak) {
        oak_release();
    } else if (ctx->cap) {
        ctx->cap->release();
        delete ctx->cap;
    }
    delete ctx;
}

/**
 * @brief Capture a frame and encode it.
 *
 * - Depth camera: raw 16-bit → **PNG** (lossless, preserves mm precision)
 * - RGB  camera:  BGR          → **JPEG** (quality 70)
 * - Test pattern: synthetic    → **JPEG** (quality 70)
 *
 * Returns the number of encoded bytes written to @p buffer,
 * or a negative value on error.
 */
int camera_capture_jpeg(camera_handle_t handle, unsigned char* buffer, int buf_size) {
    if (!handle) return -1;
    CameraContext* ctx = static_cast<CameraContext*>(handle);

    // ── OAK-D backend ─────────────────────────────────────
    if (ctx->is_oak && ctx->oak) {
        if (!ctx->is_depth) {
            // RGB: depthai already hands us a JPEG. Poll until the first frame.
            int n = 0, tries = 0;
            while ((n = depthai_read_rgb(ctx->oak, buffer, buf_size)) == 0 && tries++ < 400)
                usleep(5000);
            return n;   // >0 bytes; 0 if never ready; <0 on error / too small
        }
        // Depth: raw 16-bit (mm) → cv::Mat → lossless PNG (matches server 'd' contract).
        static thread_local std::vector<unsigned char> raw16;
        if (raw16.size() < 1024 * 1024) raw16.resize(1024 * 1024);
        int w = 0, h = 0, n = 0, tries = 0;
        while ((n = depthai_read_depth(ctx->oak, raw16.data(), (int)raw16.size(), &w, &h)) == 0 && tries++ < 400)
            usleep(5000);
        if (n <= 0 || w <= 0 || h <= 0) return (n < 0) ? -2 : 0;
        cv::Mat depth(h, w, CV_16UC1, raw16.data());
        std::vector<uchar> png_buf;
        std::vector<int> png_params = {cv::IMWRITE_PNG_COMPRESSION, 3};
        if (!cv::imencode(".png", depth, png_buf, png_params)) {
            std::fprintf(stderr, "[CAM] OAK depth PNG encode failed\n");
            return -3;
        }
        if ((int)png_buf.size() > buf_size) {
            std::fprintf(stderr, "[CAM] OAK depth PNG too big: %zu > %d\n", png_buf.size(), buf_size);
            return -4;
        }
        std::memcpy(buffer, png_buf.data(), png_buf.size());
        return static_cast<int>(png_buf.size());
    }

    // ── Real camera ───────────────────────────────────────
    if (ctx->cap) {
        cv::Mat frame;
        if (!ctx->cap->read(frame)) {
            std::fprintf(stderr, "[CAM] frame capture failed\n");
            return -2;
        }

        if (ctx->is_depth) {
            // ── Depth path: 16-bit → PNG (lossless) ─────
            static std::vector<uchar> png_buf;
            png_buf.clear();
            static std::vector<int> png_params;
            if (png_params.empty()) {
                png_params.push_back(cv::IMWRITE_PNG_COMPRESSION);
                png_params.push_back(3);
            }
            if (cv::imencode(".png", frame, png_buf, png_params)) {
                if ((int)png_buf.size() <= buf_size) {
                    std::memcpy(buffer, png_buf.data(), png_buf.size());
                    return static_cast<int>(png_buf.size());
                }
                std::fprintf(stderr, "[CAM] PNG buffer too small: need %zu, have %d\n",
                            png_buf.size(), buf_size);
                // fall through to colormap JPEG
            } else {
                std::fprintf(stderr, "[CAM] PNG encode failed (depth=%d ch=%d); fallback to colormap JPEG\n",
                            frame.depth(), frame.channels());
            }

            // ── Fallback: 16-bit depth → normalize → colormap JPEG ──
            cv::Mat gray8;
            if (frame.depth() == CV_16U && frame.channels() == 1) {
                // Robust percentile normalization
                cv::Mat flat = frame.reshape(1, 640 * 480);
                cv::Mat sorted;
                cv::sort(flat, sorted, cv::SORT_EVERY_COLUMN + cv::SORT_ASCENDING);
                int n = 640 * 480;
                uint16_t* sp = sorted.ptr<uint16_t>(0);
                uint16_t vmin = sp[n / 50];      //  2nd percentile
                uint16_t vmax = sp[(n * 49) / 50]; // 98th percentile
                if (vmax <= vmin) vmax = vmin + 1;
                frame.convertTo(gray8, CV_8U, 255.0 / (vmax - vmin), -vmin * 255.0 / (vmax - vmin));
            } else {
                // Not 16-bit depth — maybe 8-bit? just copy
                frame.convertTo(gray8, CV_8U);
            }

            // Apply jet colormap
            cv::Mat color;
            cv::applyColorMap(gray8, color, cv::COLORMAP_JET);

            static std::vector<uchar> jpg_buf;
            jpg_buf.clear();
            static std::vector<int> jpg_params;
            if (jpg_params.empty()) {
                jpg_params.push_back(cv::IMWRITE_JPEG_QUALITY);
                jpg_params.push_back(85);
            }
            if (!cv::imencode(".jpg", color, jpg_buf, jpg_params)) {
                std::fprintf(stderr, "[CAM] colormap JPEG encode failed\n");
                return -3;
            }
            if ((int)jpg_buf.size() > buf_size) {
                std::fprintf(stderr, "[CAM] colormap JPEG buffer too small: need %zu, have %d\n",
                            jpg_buf.size(), buf_size);
                return -4;
            }
            std::memcpy(buffer, jpg_buf.data(), jpg_buf.size());
            return static_cast<int>(jpg_buf.size());
        } else {
            // ── RGB path: BGR → JPEG ────────────────────
            static std::vector<uchar> jpg_buf;
            jpg_buf.clear();
            static std::vector<int> jpg_params;
            if (jpg_params.empty()) {
                jpg_params.push_back(cv::IMWRITE_JPEG_QUALITY);
                jpg_params.push_back(70);
            }
            if (!cv::imencode(".jpg", frame, jpg_buf, jpg_params)) {
                std::fprintf(stderr, "[CAM] JPEG encode failed\n");
                return -3;
            }
            if ((int)jpg_buf.size() > buf_size) {
                std::fprintf(stderr, "[CAM] buffer too small: need %zu, have %d\n",
                            jpg_buf.size(), buf_size);
                return -4;
            }
            std::memcpy(buffer, jpg_buf.data(), jpg_buf.size());
            static_cast<void>(ctx->frame_count); // unused for RGB
            return static_cast<int>(jpg_buf.size());
        }
    }

    // ── Test-pattern fallback (8-bit RGB → JPEG) ────────
    int w = 640, h = 480;
    cv::Mat test_img(h, w, CV_8UC3);

    int phase = (ctx->frame_count * 10) % 360;
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            int bar = (x * 8 / w + phase / 45) % 8;
            uchar r, g, b;
            switch (bar) {
                case 0: r = 255; g =   0; b =   0; break;
                case 1: r =   0; g = 255; b =   0; break;
                case 2: r =   0; g =   0; b = 255; break;
                case 3: r = 255; g = 255; b =   0; break;
                case 4: r = 255; g =   0; b = 255; break;
                case 5: r =   0; g = 255; b = 255; break;
                case 6: r = 128; g = 128; b = 128; break;
                case 7: r = 255; g = 255; b = 255; break;
                default: r = 0; g = 0; b = 0;
            }
            test_img.at<cv::Vec3b>(y, x) = cv::Vec3b(b, g, r);
        }
    }

    char ts[64];
    std::snprintf(ts, sizeof(ts), "frame %d", ctx->frame_count);
    cv::putText(test_img, ts, cv::Point(20, 40),
                cv::FONT_HERSHEY_SIMPLEX, 1.0, cv::Scalar(255, 255, 255), 2);

    static std::vector<uchar> jpg_buf;
    jpg_buf.clear();
    static std::vector<int> test_compress_params;
    if (test_compress_params.empty()) {
        test_compress_params.push_back(cv::IMWRITE_JPEG_QUALITY);
        test_compress_params.push_back(70);
    }
    if (!cv::imencode(".jpg", test_img, jpg_buf, test_compress_params)) {
        std::fprintf(stderr, "[CAM] test image JPEG encode failed\n");
        return -3;
    }
    if ((int)jpg_buf.size() > buf_size) {
        std::fprintf(stderr, "[CAM] buffer too small for test image\n");
        return -4;
    }
    std::memcpy(buffer, jpg_buf.data(), jpg_buf.size());
    ctx->frame_count++;
    return static_cast<int>(jpg_buf.size());
}

}  // extern "C"
