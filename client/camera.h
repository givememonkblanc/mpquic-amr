#ifndef CAMERA_H
#define CAMERA_H

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Frame type markers used in dual-stream frame header ─── */
#define FRAME_TYPE_DEPTH 'd'   /* Depth frame (16-bit, PNG encoded) */
#define FRAME_TYPE_RGB   'r'   /* RGB frame (8-bit, JPEG encoded)   */
#define FRAME_HDR_SIZE   9     /* 4B magic "MPQ1" + 1B type + 4B BE length */

/**
 * @brief 카메라 객체를 가리키는 포인터 (핸들).
 */
typedef void* camera_handle_t;

/**
 * @brief 새로운 카메라 객체를 생성하고 그 핸들을 반환합니다.
 *
 * 우선적으로 /dev/videoN 에서 16-bit depth 카메라를 찾고,
 * 없으면 RGB 카메라를 찾습니다. 그래도 없으면 테스트 패턴을 사용합니다.
 *
 * @return 성공 시 카메라 핸들, 실패 시 NULL을 반환합니다.
 */
camera_handle_t camera_create();

/**
 * @brief RGB 카메라를 전용으로 엽니다.
 *
 * /dev/videoN 에서 MJPEG/RGB 카메라를 찾아 엽니다.
 * Depth 카메라와 동시에 사용하기 위한 별도 핸들입니다.
 *
 * @return 성공 시 RGB 카메라 핸들, 실패 시 NULL
 */
camera_handle_t camera_create_rgb();

/**
 * @brief 지정된 /dev/video 인덱스로 Depth 카메라를 엽니다.
 *
 * 일반적으로 /dev/video0 이 RealSense depth 스트림입니다.
 * @param index 열 video 장치 인덱스 (0 = /dev/video0)
 * @return 성공 시 depth 카메라 핸들, 실패 시 NULL
 */
camera_handle_t camera_create_depth_by_index(int index);

/**
 * @brief camera_create로 생성된 카메라 객체를 소멸시키고 리소스를 해제합니다.
 * @param handle 소멸시킬 카메라의 핸들
 */
void camera_destroy(camera_handle_t handle);

/**
 * @brief 특정 카메라에서 프레임을 캡처하여 JPEG 형식으로 인코딩합니다.
 * @param handle 작업을 수행할 카메라의 핸들
 * @param buffer JPEG 데이터를 저장할 버퍼
 * @param buf_size 버퍼의 크기
 * @return 성공 시 저장된 JPEG 데이터의 크기(바이트), 실패 시 음수 값을 반환합니다.
 */
int camera_capture_jpeg(camera_handle_t handle, unsigned char* buffer, int buf_size);

/**
 * @brief 카메라 핸들이 depth(16-bit) 카메라인지 확인합니다.
 * @param handle 카메라 핸들
 * @return 1 if depth, 0 if RGB/test-pattern
 */
int camera_is_depth(camera_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif // CAMERA_H