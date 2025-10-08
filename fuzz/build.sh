#!/bin/bash -eu
# Copyright 2024 EMQ Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build script for OSS-Fuzz
# This script builds the fuzz targets for quicer

set -x

# Get msquic dependency
./get-msquic.sh v2.3.8

# Build msquic library
cmake -B c_build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DQUIC_BUILD_TEST=OFF \
    -DQUIC_BUILD_TOOLS=OFF \
    -DQUIC_BUILD_PERF=OFF \
    -DQUIC_TLS_SECRETS_SUPPORT=ON

make -C c_build -j$(nproc) inc platform core warnings logging

# Build fuzz targets
for fuzz_target in fuzz/*.c; do
    target_name=$(basename "$fuzz_target" .c)
    
    $CC $CFLAGS -c "$fuzz_target" -o "/tmp/${target_name}.o" \
        -I${SRC}/quicer/msquic/src/inc \
        -I${SRC}/quicer/c_build
    
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "/tmp/${target_name}.o" \
        -o "$OUT/${target_name}" \
        ${SRC}/quicer/c_build/bin/RelWithDebInfo/libmsquic.a \
        -lpthread -ldl -lm
done

# Copy corpus if it exists
if [ -d "fuzz/corpus" ]; then
    for fuzz_target in fuzz/*.c; do
        target_name=$(basename "$fuzz_target" .c)
        if [ -d "fuzz/corpus/${target_name}" ]; then
            cp -r "fuzz/corpus/${target_name}" "$OUT/"
        fi
    done
fi
