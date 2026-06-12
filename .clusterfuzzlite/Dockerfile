# ClusterFuzzLite / OSS-Fuzz build image for quicer.
# https://google.github.io/clusterfuzzlite/build-integration/
FROM gcr.io/oss-fuzz-base/base-builder

# Build deps:
#  - erlang-dev: provides erl_nif.h (we only need the HEADER; the harnesses
#    link an in-tree erl_nif shim, not the BEAM -- see test/fuzz/FUZZING.md).
#  - cmake, perl: msquic + bundled quictls build.
#  - libnuma-dev: msquic platform on Linux.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake \
        perl \
        libnuma-dev \
        erlang-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . $SRC/quicer
WORKDIR $SRC/quicer
COPY .clusterfuzzlite/build.sh $SRC/build.sh
