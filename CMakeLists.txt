cmake_minimum_required(VERSION 3.20)

project(mpquic_raw LANGUAGES C CXX)

# ---- 기본 컴파일 설정 ----
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# macOS Apple Silicon을 기본으로 (혼합 아키텍처 방지)
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
  set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
endif()

# 최적화 기본
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 실행파일 출력 디렉토리
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ---- 종속성 힌트 (Homebrew OpenSSL) ----
# 터미널에서: brew install openssl@3
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  # 사용자가 환경변수로 넘겨줄 수도 있음: export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
  find_program(BREW_EXEC brew)
  if(BREW_EXEC)
    execute_process(COMMAND "${BREW_EXEC}" --prefix openssl@3
                    OUTPUT_VARIABLE BREW_OPENSSL_PREFIX
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(EXISTS "${BREW_OPENSSL_PREFIX}")
      set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_PREFIX}" CACHE PATH "OpenSSL root from Homebrew")
      # pkg-config 힌트 (일부 하위 프로젝트가 사용)
      set(ENV{PKG_CONFIG_PATH} "${OPENSSL_ROOT_DIR}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endif()
  endif()
endif()

# ---- include 경로 ----
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/picoquic/loglib)

# ---- picoquic + picotls 자동 Fetch ----
# 최신 picoquic는 자체 CMake에서 picotls를 FetchContent로 끌어옵니다.
# 라이선스 미동의로 실패했다면, xcodebuild -license 부터 동의 필요.
set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "Fetch/build picotls automatically")
add_subdirectory(third_party/picoquic)

# ---- Threads (플랫폼별 올바르게) ----
find_package(Threads REQUIRED)

# ---- OpenCV (client_uploader용) ----
find_package(OpenCV REQUIRED)

# ---- 공통 loglib 소스 (필요 시 직접 포함) ----
# 참고: picoquic 쪽에 'picoquic-loglib' 타깃이 있다면 그걸 링크하는 방식으로 바꿔도 됩니다.
set(LOG_LIB_SRCS
    third_party/picoquic/loglib/qlog.c
    third_party/picoquic/loglib/logconvert.c
    third_party/picoquic/loglib/logreader.c
    third_party/picoquic/loglib/memory_log.c
    third_party/picoquic/loglib/cidset.c
    third_party/picoquic/loglib/csv.c
    third_party/picoquic/loglib/svg.c
    third_party/picoquic/loglib/autoqlog.c
)

# ---- 서버 ----
add_executable(server_recv
  server/server_recv.c
  server/frame_assembler.c
  ${LOG_LIB_SRCS}
)
target_compile_options(server_recv PRIVATE -Wall -Wextra)
target_link_libraries(server_recv
  PRIVATE
    picoquic-core           # picoquic 메인 라이브러리
    Threads::Threads        # 플랫폼별 올바른 pthread 처리
)

# ---- 클라이언트 (C++ 링커 사용, OpenCV 사용) ----
add_executable(client_uploader
  client/client_uploader.c
  client/camera.cpp
  ${LOG_LIB_SRCS}
)
# C 파일이 포함되어도 최종 링크는 C++로
set_target_properties(client_uploader PROPERTIES LINKER_LANGUAGE CXX)
target_compile_options(client_uploader PRIVATE -Wall -Wextra)
target_include_directories(client_uploader PRIVATE ${OpenCV_INCLUDE_DIRS})
target_link_libraries(client_uploader
  PRIVATE
    picoquic-core
    Threads::Threads
    ${OpenCV_LIBS}
)

# ---- UNIX의 -lm 등 수동 링크 제거 ----
# macOS는 libSystem에 포함되어 있어 -lm 불필요, pthread도 Threads::Threads로 대체

# ---- 진단 옵션 (원하면 켜기) ----
# set(CMAKE_MESSAGE_LOG_LEVEL VERBOSE)
# set(CMAKE_VERBOSE_MAKEFILE ON)
