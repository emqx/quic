# Fuzzing quicer

This directory contains [libFuzzer] harnesses for quicer's NIF layer and the
[ClusterFuzzLite] wiring that runs them on every pull request.

## Why this is structured the way it is

quicer is a NIF: msquic runs QUIC on its own **worker threads** and calls into
quicer's callbacks, while Erlang code drives the NIF from **BEAM scheduler
threads** (which also run GC). Bugs in quicer often live in the *interleaving*
of those two thread pools around shared context structs, refcounts and the
signal queues. That interleaving is genuinely hard to reproduce: a coverage
guided fuzzer that spins up the BEAM + msquic in-process is non-deterministic,
so a crash rarely replays from the same input.

We therefore split the problem in two:

| Concern | Tool | Where |
|---|---|---|
| **Stateless parsing of untrusted/option input** (ALPN, cert blobs, cacert paths, transport settings, recv-mode) | **libFuzzer** here, single threaded, no BEAM, no msquic workers — fully deterministic & reproducible | `test/fuzz/` |
| **Concurrent NIF/worker interleaving** (refcounts, queues, callback vs. NIF races) | **ThreadSanitizer + AddressSanitizer** driving the existing PropEr *stateful* models and CT suites | `tools/run/`, `.github/workflows/` |

The libFuzzer side is deliberately decoupled from the runtime: the harnesses
link a tiny in-tree `erl_nif` implementation (`nif_shim.c`) instead of the
BEAM, so the parser functions run exactly as they do in production but with
deterministic, single-threaded inputs. See "The shim" below.

This is the part the interleaving problem makes *un*-trackable end-to-end, so
we make it trackable by isolating it. The concurrency side is addressed with
sanitizers + stress, not with a fuzzer (see "Concurrency" below).

## What is fuzzed (client AND server)

`fuzz_cred_config` drives quicer's option-map parsers from a fuzzed byte
string. These take attacker-influenced data on both peers:

- **Server**: `eoptions_to_cred_config()` → `parse_cert_options()` /
  `parse_verify_options(is_server=TRUE)` (certfile/keyfile/PKCS12 blob,
  client-auth flags).
- **Client**: `parse_verify_options(is_server=FALSE)` +
  `parse_cacertfile_option()` (peer verification, CA file).
- **Both**: `load_alpn()` (ALPN protocol list — negotiated with the peer),
  `create_settings()` (transport settings map).

## The shim (`nif_shim.c` / `nif_shim.h`)

`ERL_NIF_TERM` is just an integer in `erl_nif.h`, so the shim models terms as
indices into a small arena and implements only the ~15 `enif_*` functions the
parser paths actually call (maps, binaries, strings, lists, ints). Every other
`enif_*` symbol the linked quicer objects reference is stubbed to `abort()` so
that if a harness ever reaches an unmodelled path it fails loudly instead of
silently misbehaving.

Atoms are interned via `quicer_fuzz_init_atoms()` (exported from
`c_src/quicer_nif.c` only under `-DQUICER_FUZZ`), which reuses quicer's real
`init_atoms()` so `ATOM_CERTFILE`, `ATOM_TRUE`, … match what the parsers
compare against.

## Run locally

```sh
# clang is required for -fsanitize=fuzzer
export CC=clang CXX=clang++
cmake -S . -B build_fuzz -DBUILD_FUZZERS=ON
cmake --build build_fuzz --target fuzz_cred_config -j

# run it (ASan + UBSan + libFuzzer are linked in)
./build_fuzz/test/fuzz/fuzz_cred_config -max_len=2048 test/fuzz/corpus/fuzz_cred_config
```

Reproduce a crash found by CI:

```sh
./build_fuzz/test/fuzz/fuzz_cred_config ./crash-<hash>
```

## ClusterFuzzLite

- `.clusterfuzzlite/Dockerfile` + `build.sh` build the harnesses in the
  OSS-Fuzz base image.
- `.github/workflows/cflite-pr.yml` runs them on PRs touching `c_src/`,
  `test/fuzz/`, etc. (ASan and UBSan).
- `.github/workflows/cflite-batch.yml` runs longer nightly batch + coverage.

Corpus persistence and crash-as-SARIF are opt-in — see the comments in the
workflow files (a `storage-repo` and `output-sarif: true`).

## Adding a harness

1. Write `fuzz_<name>.c` with `LLVMFuzzerTestOneInput` (and optional
   `LLVMFuzzerInitialize`). Build input terms with the `nifshim_*` builders.
2. Add `fuzz_<name>` to `QUICER_FUZZ_TARGETS` in `CMakeLists.txt` and to
   `FUZZERS` in `.clusterfuzzlite/build.sh`.
3. Drop seeds in `test/fuzz/corpus/fuzz_<name>/`.
4. If you reach an `abort()` in the shim, implement that `enif_*` for real.

Good next targets: `send3`/`send_dgram` payload+flags parsing,
`set_owner_recv_mode` (active-N accounting), `getopt3`/`setopt4` option
decoding.

## Concurrency (the interleaving problem)

libFuzzer is the wrong tool for the BEAM-scheduler vs. msquic-worker races.
Cover those with sanitizers over the existing stateful tests instead:

```sh
# AddressSanitizer (already wired)
tools/run/bin/sanitizer-check all

# ThreadSanitizer — recommended addition: build quicer + msquic with
# -fsanitize=thread and run the PropEr stateful models:
#   prop_stateful_client_conn, prop_stateful_server_conn, prop_stateful_stream
```

A dedicated TSan CI job (mirroring `asan.yml`) is the recommended follow-up.

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[ClusterFuzzLite]: https://google.github.io/clusterfuzzlite/
