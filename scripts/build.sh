#!/usr/bin/env bash
set -e
mkdir -p build_d20 && cd build_d20
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
