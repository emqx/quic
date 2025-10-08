# Fuzzing for Quicer

This directory contains fuzz targets and infrastructure for continuous fuzzing of the Quicer library using [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/).

## Overview

Quicer uses ClusterFuzzLite to run fuzz tests automatically via GitHub Actions. The fuzzing workflow runs:
- On pull requests that modify C source code or fuzz targets
- On pushes to the main branch
- Daily via scheduled runs
- On manual workflow dispatch

## Fuzz Targets

### fuzz_config.c
Tests QUIC configuration handling and parameter setting through the msquic library.

## Running Locally

### Prerequisites
- Docker
- ClusterFuzzLite (via Docker)

### Build and Run

To build fuzz targets locally:

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake git curl wget clang

# Build the project normally first
./build.sh v2.3.8

# Build fuzz targets with sanitizers (requires special flags)
export CC=clang
export CXX=clang++
export CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link"
export CXXFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
export OUT=/tmp/fuzz_out
export SRC=/home/runner/work/quic

mkdir -p $OUT
./fuzz/build.sh

# Run a fuzz target
/tmp/fuzz_out/fuzz_config
```

### Using Docker

```bash
# Use ClusterFuzzLite's Docker container
docker run --rm -ti -v $(pwd):/src gcr.io/oss-fuzz-base/base-builder \
  bash -c "cd /src && ./fuzz/build.sh"
```

## Seed Corpus

Seed corpus files are stored in `fuzz/corpus/<target_name>/` directories. These provide initial inputs for the fuzzer to start from.

## GitHub Actions Integration

The fuzzing workflow is defined in `.github/workflows/clusterfuzzlite.yml` and includes:

1. **Fuzzing Job**: Runs on code changes with multiple sanitizers (address, undefined, memory)
2. **Batch Job**: Runs longer fuzzing sessions (1 hour) on a schedule
3. **Prune Job**: Minimizes the corpus to remove redundant test cases

## Sanitizers

The fuzz tests run with multiple sanitizers:
- **AddressSanitizer (ASan)**: Detects memory errors like buffer overflows and use-after-free
- **UndefinedBehaviorSanitizer (UBSan)**: Detects undefined behavior like integer overflow
- **MemorySanitizer (MSan)**: Detects uninitialized memory reads

## Crash Artifacts

When fuzzing finds a crash, the artifacts are uploaded as GitHub Actions artifacts for investigation.

## Contributing

To add new fuzz targets:

1. Create a new `.c` file in the `fuzz/` directory
2. Implement the `LLVMFuzzerTestOneInput` function
3. Add seed corpus files to `fuzz/corpus/<target_name>/`
4. The build script will automatically pick up the new target

## References

- [ClusterFuzzLite Documentation](https://google.github.io/clusterfuzzlite/)
- [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
