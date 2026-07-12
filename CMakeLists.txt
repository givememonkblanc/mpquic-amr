cmake_minimum_required(VERSION 3.20)

project(mpquic_raw LANGUAGES C CXX)

# ---- 기본 컴파일 설정 ----
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 최적화 기본
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 실행파일 출력 디렉토리
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ---- include 경로 ----
include_directories(${CMAKE_SOURCE_DIR}/third_party/picoquic/loglib)

# ---- picoquic + picotls 자동 Fetch ----
# 최신 picoquic는 자체 CMake에서 picotls를 FetchContent로 끌어옵니다.
# 라이선스 미동의로 실패했다면, xcodebuild -license 부터 동의 필요.
set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "Fetch/build picotls automatically")
add_subdirectory(third_party/picoquic)

# ---- Threads (플랫폼별 올바르게) ----
find_package(Threads REQUIRED)

# ---- OpenCV (client_uploader용) ----
find_package(OpenCV QUIET)

# ---- PNG / JPEG (server depth preview용) ----
find_package(PNG REQUIRED)
find_package(JPEG REQUIRED)

# ---- 서버 ----
add_executable(server_recv
  src/server/server_recv.c
  src/server/server_runtime.c
  src/server/frame_assembler.c
)
target_compile_options(server_recv PRIVATE -Wall -Wextra)
target_link_libraries(server_recv
  PRIVATE
    # draft-20: picoquic-core (sockloop.c) references picoquic_set_qlog defined in
    # picoquic-log, while picoquic-log depends on core → circular static-lib deps.
    # --start-group lets the linker rescan both to resolve the cycle.
    -Wl,--start-group
    picoquic-core           # picoquic 메인 라이브러리
    picoquic-log            # qlog/loglib
    -Wl,--end-group
    Threads::Threads        # 플랫폼별 올바른 pthread 처리
    PNG::PNG                # depth PNG → colormap JPEG 변환
    JPEG::JPEG
)

# ---- 클라이언트 (C++ 링커 사용, OpenCV 사용) ----
if(OpenCV_FOUND)
  add_executable(client_uploader
    src/client/client_uploader.c
    src/client/client_capture.c
    src/client/client_loop.c
    src/client/client_options.c
    src/client/client_paths.c
    src/client/client_session.c
    src/client/client_qlogger.c
    src/client/camera.cpp
    src/client/depthai_wrapper.cpp
  )
  # C 파일이 포함되어도 최종 링크는 C++로
  set_target_properties(client_uploader PROPERTIES LINKER_LANGUAGE CXX)
  target_compile_options(client_uploader PRIVATE -Wall -Wextra)
  # DepthAI (OAK-D) SDK — provides libdepthai-core + headers under /usr/local.
  find_library(DEPTHAI_CORE_LIB NAMES depthai-core PATHS /usr/local/lib /usr/lib REQUIRED)
  target_include_directories(client_uploader PRIVATE ${OpenCV_INCLUDE_DIRS} /usr/local/include)
  target_link_libraries(client_uploader
    PRIVATE
      -Wl,--start-group
      picoquic-core
      picoquic-log
      -Wl,--end-group
      ${DEPTHAI_CORE_LIB}
      Threads::Threads
      ${OpenCV_LIBS}
  )
else()
  message(WARNING "OpenCV not found; skipping client_uploader build. server_recv remains available.")
endif()

# ---- UNIX의 -lm 등 수동 링크 제거 ----
# macOS는 libSystem에 포함되어 있어 -lm 불필요, pthread도 Threads::Threads로 대체

# ---- 진단 옵션 (원하면 켜기) ----
# set(CMAKE_MESSAGE_LOG_LEVEL VERBOSE)
# set(CMAKE_VERBOSE_MAKEFILE ON)
