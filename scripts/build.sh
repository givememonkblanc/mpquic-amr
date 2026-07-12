#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p build_d20 && cd build_d20
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
