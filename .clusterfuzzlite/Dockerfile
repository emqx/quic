# ClusterFuzzLite / OSS-Fuzz build image for quicer.
# https://google.github.io/clusterfuzzlite/build-integration/
FROM gcr.io/oss-fuzz-base/base-builder

# Dependency bots can use this metadata-only ARG to track msquic releases; keep
# it in sync with /MSQUIC_VERSION, which remains the build-time source of truth.
# renovate: datasource=github-tags depName=microsoft/msquic versioning=semver
ARG MSQUIC_VERSION=v2.5.7

# Build deps:
#  - erlang-dev: provides erl_nif.h (we only need the HEADER; the harnesses
#    link an in-tree erl_nif shim, not the BEAM -- see test/fuzz/FUZZING.md).
#  - cmake, perl: msquic + bundled quictls build.
#  - libnuma-dev: msquic platform on Linux.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake \
        perl \
        erlang-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . $SRC/quicer
WORKDIR $SRC/quicer
COPY .clusterfuzzlite/build.sh $SRC/build.sh
