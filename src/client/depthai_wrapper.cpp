
// depthai_wrapper.cpp — depthai v3 C++ bridge for the OAK-D (OAK-D-PRO-W).
//
// Exposes a small C API (see depthai_wrapper.h) that the client capture layer
// (client_capture.c / camera.cpp) calls directly. A background thread per stream
// continuously pulls the newest frame from the device into a cached buffer, so
// the caller never blocks and always gets the latest frame.
//
// RGB is JPEG-encoded here (so the caller forwards it as-is); depth is kept
// as raw 16-bit (millimetres) and resized to the requested depth resolution.

#include "depthai_wrapper.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <depthai/depthai.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>

namespace {

struct DepthAICam {
    dai::Pipeline pipeline;
    std::shared_ptr<dai::MessageQueue> rgbQ;
    std::shared_ptr<dai::MessageQueue> depthQ;

    int depthW = 320;
    int depthH = 240;

    std::atomic<bool> running{false};
    std::thread rgbThread;
    std::thread depthThread;

    std::mutex rgbMtx;
    std::vector<unsigned char> rgbJpeg;
    bool rgbFresh = false;   // set by rgbLoop, cleared by depthai_read_rgb

    std::mutex depthMtx;
    std::vector<unsigned char> depthRaw; // 16-bit LE, depthW*depthH*2
    bool depthFresh = false; // set by depthLoop, cleared by depthai_read_depth
    // StereoDepth runs at the mono-sensor rate (~27 fps) regardless of the
    // color fps request; without this cap depth alone pushed ~1.35 MB/s of
    // PNG over the uplink (5x the intended rate). 0 = no throttle.
    int64_t depthMinIntervalUs = 0;

    DepthAICam() : pipeline(true /*createImplicitDevice*/) {}
};

// The prebuilt libdepthai-core was compiled without OpenCV support, so
// getCvFrame()/getFrame() are unavailable. We build the cv::Mat ourselves from
// the raw ImgFrame buffer (getData) instead.
void rgbLoop(DepthAICam *c) {
    int q = 45;  /* lower default for constrained uplink; env-tunable */
    const char* qe = getenv("MPQUIC_OAK_RGB_QUALITY");
    if (qe && *qe) { int v = atoi(qe); if (v > 0 && v <= 100) q = v; }
    std::vector<int> jpegParams = {cv::IMWRITE_JPEG_QUALITY, q};
    while (c->running.load()) {
        try {
            bool timedOut = false;
            auto frame = c->rgbQ->get<dai::ImgFrame>(std::chrono::milliseconds(500), timedOut);
            if (timedOut || !frame) continue;
            auto data = frame->getData();
            const int w = static_cast<int>(frame->getWidth());
            const int h = static_cast<int>(frame->getHeight());
            if (w <= 0 || h <= 0 || data.size() < static_cast<size_t>(w) * h * 3) continue;
            int stride = static_cast<int>(frame->getStride());
            if (stride < w * 3) stride = w * 3;
            // BGR888i: interleaved 8-bit BGR.
            cv::Mat bgr(h, w, CV_8UC3, const_cast<uint8_t *>(data.data()), static_cast<size_t>(stride));
            std::vector<unsigned char> enc;
            if (!cv::imencode(".jpg", bgr, enc, jpegParams)) continue;
            std::lock_guard<std::mutex> lk(c->rgbMtx);
            c->rgbJpeg.swap(enc);
            c->rgbFresh = true;
        } catch (const std::exception &) {
            // transient device hiccup; keep last frame and retry
        }
    }
}

void depthLoop(DepthAICam *c) {
    std::chrono::steady_clock::time_point lastAccept{};
    while (c->running.load()) {
        try {
            bool timedOut = false;
            auto frame = c->depthQ->get<dai::ImgFrame>(std::chrono::milliseconds(500), timedOut);
            if (timedOut || !frame) continue;
            if (c->depthMinIntervalUs > 0) {
                auto tnow = std::chrono::steady_clock::now();
                if (lastAccept.time_since_epoch().count() != 0
                    && std::chrono::duration_cast<std::chrono::microseconds>(tnow - lastAccept).count()
                           < c->depthMinIntervalUs) {
                    continue;  /* decimate to the requested fps */
                }
                lastAccept = tnow;
            }
            auto data = frame->getData();
            const int w = static_cast<int>(frame->getWidth());
            const int h = static_cast<int>(frame->getHeight());
            if (w <= 0 || h <= 0 || data.size() < static_cast<size_t>(w) * h * 2) continue;
            int stride = static_cast<int>(frame->getStride());
            if (stride < w * 2) stride = w * 2;
            // RAW16: 16-bit depth in millimetres.
            cv::Mat depth(h, w, CV_16UC1, const_cast<uint8_t *>(data.data()), static_cast<size_t>(stride));
            if (depth.empty()) continue;
            cv::Mat resized;
            if (depth.cols != c->depthW || depth.rows != c->depthH) {
                cv::resize(depth, resized, cv::Size(c->depthW, c->depthH), 0, 0, cv::INTER_NEAREST);
            } else {
                resized = depth;
            }
            if (resized.type() != CV_16UC1) continue;
            if (!resized.isContinuous()) resized = resized.clone();
            const size_t nbytes = static_cast<size_t>(c->depthW) * c->depthH * 2;
            std::vector<unsigned char> buf(nbytes);
            std::memcpy(buf.data(), resized.data, nbytes);
            std::lock_guard<std::mutex> lk(c->depthMtx);
            c->depthRaw.swap(buf);
            c->depthFresh = true;
        } catch (const std::exception &) {
        }
    }
}

} // namespace

extern "C" {

depthai_handle_t depthai_open(int rgb_w, int rgb_h, int depth_w, int depth_h, int fps) {
    try {
        auto *c = new DepthAICam();
        c->depthW = depth_w > 0 ? depth_w : 320;
        c->depthH = depth_h > 0 ? depth_h : 240;
        float fpsF = fps > 0 ? static_cast<float>(fps) : 15.0f;
        c->depthMinIntervalUs = static_cast<int64_t>(1000000.0f / fpsF);

        // Color: CAM_A -> interleaved BGR at requested size.
        auto cam = c->pipeline.create<dai::node::Camera>()->build(dai::CameraBoardSocket::CAM_A);
        auto *rgbOut = cam->requestOutput(
            std::pair<uint32_t, uint32_t>(static_cast<uint32_t>(rgb_w), static_cast<uint32_t>(rgb_h)),
            dai::ImgFrame::Type::BGR888i, dai::ImgResizeMode::CROP, fpsF);

        // Stereo depth: auto-create left/right mono (CAM_B, CAM_C).
        auto stereo = c->pipeline.create<dai::node::StereoDepth>()->build(
            true /*autoCreateCameras*/, dai::node::StereoDepth::PresetMode::DEFAULT);
        stereo->setDepthAlign(dai::CameraBoardSocket::CAM_A);

        c->rgbQ = rgbOut->createOutputQueue(4, false /*non-blocking*/);
        c->depthQ = stereo->depth.createOutputQueue(4, false);

        c->pipeline.start();

        c->running.store(true);
        c->rgbThread = std::thread(rgbLoop, c);
        c->depthThread = std::thread(depthLoop, c);
        return reinterpret_cast<depthai_handle_t>(c);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "[depthai_wrapper] open failed: %s\n", e.what());
        return nullptr;
    } catch (...) {
        std::fprintf(stderr, "[depthai_wrapper] open failed: unknown error\n");
        return nullptr;
    }
}

int depthai_read_rgb(depthai_handle_t h, unsigned char *buf, int cap) {
    if (!h || !buf || cap <= 0) return -1;
    auto *c = reinterpret_cast<DepthAICam *>(h);
    std::lock_guard<std::mutex> lk(c->rgbMtx);
    /* Only hand out a frame ONCE: returning the cached frame on every call
     * makes the capture thread treat it as new, flooding the QUIC send queue
     * with duplicates at spin rate (which starves the RGB stream, sid 66+). */
    if (!c->rgbFresh || c->rgbJpeg.empty()) return 0;
    int n = static_cast<int>(c->rgbJpeg.size());
    if (n > cap) return -1;
    std::memcpy(buf, c->rgbJpeg.data(), n);
    c->rgbFresh = false;
    return n;
}

int depthai_read_depth(depthai_handle_t h, unsigned char *buf, int cap, int *w, int *h_out) {
    if (!h || !buf || cap <= 0) return -1;
    auto *c = reinterpret_cast<DepthAICam *>(h);
    std::lock_guard<std::mutex> lk(c->depthMtx);
    /* One-shot per frame — see depthai_read_rgb. */
    if (!c->depthFresh || c->depthRaw.empty()) return 0;
    int n = static_cast<int>(c->depthRaw.size());
    if (n > cap) return -1;
    std::memcpy(buf, c->depthRaw.data(), n);
    if (w) *w = c->depthW;
    if (h_out) *h_out = c->depthH;
    c->depthFresh = false;
    return n;
}

void depthai_close(depthai_handle_t h) {
    if (!h) return;
    auto *c = reinterpret_cast<DepthAICam *>(h);
    c->running.store(false);
    if (c->rgbThread.joinable()) c->rgbThread.join();
    if (c->depthThread.joinable()) c->depthThread.join();
    try {
        c->pipeline.stop();
    } catch (...) {
    }
    delete c;
}

} // extern "C"
