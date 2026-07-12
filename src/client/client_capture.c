#include "client_capture.h"

/* ── Shared warmup counter ── */
#define CAM_WARMUP_FRAMES 3

static void* camera_thread_main(void* arg) {
    tx_t* st = (tx_t*)arg;
    int cam_warmup = CAM_WARMUP_FRAMES;
    /* Private scratch: encode here WITHOUT the lock, then publish under it.
     * Encoding straight into the shared st->cam_buf raced the consumer's
     * copy_latest_frame() (which reads cam_buf under cam_mtx) → torn frames. */
    uint8_t* scratch = NULL;
    size_t scratch_cap = 0;

    LOGF("[CAM] thread started");
    while (!st->cam_stop) {
        if (!st->cam) {
            usleep(10000);
            continue;
        }

        if (scratch_cap < (1u << 20)) {
            uint8_t* tmp = (uint8_t*)realloc(scratch, 1u << 20);
            if (!tmp) {
                LOGF("[CAM] realloc failed");
                usleep(10000);
                continue;
            }
            scratch = tmp;
            scratch_cap = 1u << 20;
        }

        int n = camera_capture_jpeg(st->cam, scratch, (int)scratch_cap);
        if (n <= 0 || (size_t)n > scratch_cap) {
            continue;
        }

        if (cam_warmup > 0) {
            cam_warmup--;
            if (cam_warmup == 0) {
                LOGF("[CAM] warmup done (3 frames skipped), streaming");
            }
            continue;
        }

        /* Publish atomically w.r.t. the consumer. */
        pthread_mutex_lock(&st->cam_mtx);
        if (st->cam_cap < (1u << 20)) {
            uint8_t* tmp = (uint8_t*)realloc(st->cam_buf, 1u << 20);
            if (tmp) {
                st->cam_buf = tmp;
                st->cam_cap = 1u << 20;
            }
        }
        if (st->cam_cap >= (size_t)n) {
            memcpy(st->cam_buf, scratch, (size_t)n);
            st->cam_len = n;
            st->cam_seq++;
        }
        pthread_mutex_unlock(&st->cam_mtx);
    }

    free(scratch);
    LOGF("[CAM] thread exit");
    return NULL;
}

static void* camera_thread_rgb_main(void* arg) {
    tx_t* st = (tx_t*)arg;
    int cam_warmup = CAM_WARMUP_FRAMES;
    /* See camera_thread_main: encode into private scratch, publish under lock. */
    uint8_t* scratch = NULL;
    size_t scratch_cap = 0;

    LOGF("[CAM-RGB] thread started");
    while (!st->cam_stop) {
        if (!st->cam_rgb) {
            usleep(10000);
            continue;
        }

        if (scratch_cap < (1u << 20)) {
            uint8_t* tmp = (uint8_t*)realloc(scratch, 1u << 20);
            if (!tmp) {
                LOGF("[CAM-RGB] realloc failed");
                usleep(10000);
                continue;
            }
            scratch = tmp;
            scratch_cap = 1u << 20;
        }

        int n = camera_capture_jpeg(st->cam_rgb, scratch, (int)scratch_cap);
        if (n <= 0 || (size_t)n > scratch_cap) {
            continue;
        }

        if (cam_warmup > 0) {
            cam_warmup--;
            if (cam_warmup == 0) {
                LOGF("[CAM-RGB] warmup done (3 frames skipped), streaming");
            }
            continue;
        }

        pthread_mutex_lock(&st->cam_mtx_rgb);
        if (st->cam_cap_rgb < (1u << 20)) {
            uint8_t* tmp = (uint8_t*)realloc(st->cam_buf_rgb, 1u << 20);
            if (tmp) {
                st->cam_buf_rgb = tmp;
                st->cam_cap_rgb = 1u << 20;
            }
        }
        if (st->cam_cap_rgb >= (size_t)n) {
            memcpy(st->cam_buf_rgb, scratch, (size_t)n);
            st->cam_len_rgb = n;
            st->cam_seq_rgb++;
        }
        pthread_mutex_unlock(&st->cam_mtx_rgb);
    }

    free(scratch);
    LOGF("[CAM-RGB] thread exit");
    return NULL;
}

int client_start_camera(tx_t* st) {
    if (!st) return -1;

    LOGF("[MAIN] creating camera...");
    st->cam = camera_create();
    if (!st->cam) {
        LOGF("[ERR] camera_create failed");
        return -1;
    }

    if (pthread_create(&st->cam_thread, NULL, camera_thread_main, st) == 0) {
        st->cam_thread_started = 1;
        LOGF("[MAIN] camera thread started");
        return 0;
    }

    LOGF("[ERR] camera thread create failed");
    camera_destroy(st->cam);
    st->cam = NULL;
    return -1;
}

void client_stop_camera(tx_t* st) {
    if (!st) return;

    if (st->cam_thread_started) {
        st->cam_stop = 1;
        pthread_join(st->cam_thread, NULL);
        st->cam_thread_started = 0;
        LOGF("[MAIN] camera thread joined");
    }

    if (st->cam) {
        camera_destroy(st->cam);
        st->cam = NULL;
        LOGF("[MAIN] camera destroyed");
    }
}

/* ── RGB camera start/stop ── */

int client_start_camera_rgb(tx_t* st) {
    if (!st) return -1;

    LOGF("[MAIN] creating RGB camera...");
    st->cam_rgb = camera_create_rgb();
    if (!st->cam_rgb) {
        LOGF("[ERR] camera_create_rgb failed — RGB stream will be disabled");
        return -1;
    }

    if (pthread_create(&st->cam_thread_rgb, NULL, camera_thread_rgb_main, st) == 0) {
        st->cam_thread_rgb_started = 1;
        LOGF("[MAIN] RGB camera thread started");
        return 0;
    }

    LOGF("[ERR] RGB camera thread create failed");
    camera_destroy(st->cam_rgb);
    st->cam_rgb = NULL;
    return -1;
}

void client_stop_camera_rgb(tx_t* st) {
    if (!st) return;

    if (st->cam_thread_rgb_started) {
        st->cam_stop = 1;
        pthread_join(st->cam_thread_rgb, NULL);
        st->cam_thread_rgb_started = 0;
        LOGF("[MAIN] RGB camera thread joined");
    }

    if (st->cam_rgb) {
        camera_destroy(st->cam_rgb);
        st->cam_rgb = NULL;
        LOGF("[MAIN] RGB camera destroyed");
    }
}
