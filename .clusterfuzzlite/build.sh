#!/bin/bash -eu
# ClusterFuzzLite / OSS-Fuzz build script for quicer.
#
# The infra exports: $SRC $OUT $WORK $CC $CXX $CFLAGS $CXXFLAGS $SANITIZER
# and $LIB_FUZZING_ENGINE. We pass these through to CMake. The quicer parser
# code and msquic are instrumented (CFLAGS already contains
# -fsanitize=fuzzer-no-link plus the active sanitizer); the harnesses link
# $LIB_FUZZING_ENGINE.

cd "$SRC/quicer"

# erl_nif.h header location (erlang-dev). Avoids invoking `erl`.
export Erlang_OTP_ROOT_DIR=/usr/lib/erlang

BUILD_DIR="$WORK/build_fuzz"
mkdir -p "$BUILD_DIR"

cmake -S . -B "$BUILD_DIR" \
    -DBUILD_FUZZERS=ON \
    -DFUZZ_CFLITE=ON \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS -DQUICER_FUZZ" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS -DQUICER_FUZZ" \
    -DErlang_OTP_ROOT_DIR="$Erlang_OTP_ROOT_DIR"

# Build dependencies then each harness.
FUZZERS="fuzz_cred_config"
cmake --build "$BUILD_DIR" --target $FUZZERS -j"$(nproc)"

for f in $FUZZERS; do
    cp "$BUILD_DIR/test/fuzz/$f" "$OUT/"
    # Per-target libFuzzer options (optional).
    if [ -f "test/fuzz/$f.options" ]; then
        cp "test/fuzz/$f.options" "$OUT/"
    fi
    # Seed corpus, if present.
    if [ -d "test/fuzz/corpus/$f" ]; then
        zip -j "$OUT/${f}_seed_corpus.zip" "test/fuzz/corpus/$f/"* || true
    fi
done
