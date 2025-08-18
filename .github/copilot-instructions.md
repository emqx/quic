# QUIC Erlang Library (Quicer)

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Project Overview
Quicer is an Erlang library providing QUIC (next-generation transport protocol) support through NIF (Native Implemented Function) bindings to Microsoft's msquic library. Written in Erlang with C native code.

**CRITICAL BUILD TIMING**: Build and test processes require significant time - NEVER CANCEL builds or tests prematurely.

## Working Effectively

### Bootstrap and Build
- Install dependencies (Ubuntu/Debian):
  ```bash
  sudo apt-get update
  sudo apt-get install -y erlang build-essential cmake git curl wget clang-format-14
  ```
- Get rebar3:
  ```bash
  wget https://s3.amazonaws.com/rebar3/rebar3 && chmod +x rebar3
  sudo mv rebar3 /usr/local/bin/
  ```
- **Build the native library**: `make build-nif` -- takes 6-11 minutes. NEVER CANCEL. Set timeout to 20+ minutes.
- **Compile Erlang code**: `rebar3 compile` -- takes 30-60 seconds. Set timeout to 2+ minutes.
- **Run full CI**: `make ci` -- takes 10-20 minutes. NEVER CANCEL. Set timeout to 30+ minutes.

### Testing
- **Unit tests**: `make eunit` -- takes 2-5 minutes. NEVER CANCEL. Set timeout to 10+ minutes.
- **Integration tests**: `make ct` -- takes 5-15 minutes. NEVER CANCEL. Set timeout to 25+ minutes.
- **Property-based tests**: `make proper` -- takes 3-8 minutes. NEVER CANCEL. Set timeout to 15+ minutes.
- **All tests**: `make test` -- takes 8-20 minutes. NEVER CANCEL. Set timeout to 30+ minutes.

### Static Analysis and Quality
- **Type analysis**: `make dialyzer` -- takes 2-5 minutes. NEVER CANCEL. Set timeout to 10+ minutes.
- **Dead code detection**: `make hank` -- takes 30-60 seconds. Set timeout to 2+ minutes.
- **Code formatting**: `make fmt` -- takes 5-15 seconds. Set timeout to 1+ minute.
- **Format checking**: `make clang-format` -- takes 5-15 seconds. Set timeout to 1+ minute.

## Validation Requirements
ALWAYS manually validate any new code by running through complete user scenarios after making changes:

### Basic Functionality Test
After any code changes, ALWAYS run this validation scenario:
```erlang
% Start the application
application:ensure_all_started(quicer).

% Test basic connection to Google (external validation)
{ok, Conn} = quicer:connect("google.com", 443, [{alpn, ["h3"]}, {verify, verify_peer}], 5000).
quicer:shutdown_connection(Conn).

% Test local ping-pong scenario (requires build completion for certificates)
% After running 'make build-nif', certificates are available at:
% - ./msquic/submodules/openssl/test/certs/rootCA.pem
% - ./msquic/submodules/openssl/test/certs/servercert.pem  
% - ./msquic/submodules/openssl/test/certs/serverkey.pem
% Example server: 
% Port = 4567,
% {ok, L} = quicer:listen(Port, [{certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"}, 
%                                {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}, 
%                                {alpn, ["sample"]}]).
% Example client: 
% {ok, Conn} = quicer:connect("localhost", Port, [{alpn, ["sample"]}, {verify, none}], 5000).
```

### Build Validation Checklist
Before completing any work, ALWAYS run:
1. `make build-nif` - Ensure native library builds successfully
2. `make test` - Ensure all tests pass
3. `make dialyzer` - Ensure no type errors
4. `make hank` - Ensure no dead code
5. `make fmt` - Format all code properly

## Dependencies Requirements
- **OTP 25+** (Erlang/OTP runtime)
- **rebar3** (Erlang build tool)
- **cmake 3.16+** (C build system)
- **build-essential** (C compiler toolchain)
- **clang-format-14** (C code formatting, exact version required)
- **git, curl, wget** (build dependencies)

## Build Process Details
The build happens in these phases:
1. **msquic download**: `./get-msquic.sh v2.3.8` (~3 seconds)
2. **cmake configuration**: `cmake -B c_build` (~6 seconds)  
3. **native compilation**: `make -C c_build -j$(nproc)` (~5-10 minutes)
4. **erlang compilation**: `rebar3 compile` (~30-60 seconds)

## Troubleshooting

### Debug Logging
Enable debug logging with environment variable:
```bash
QUIC_LOGGING_TYPE=stdout make
QUIC_LOGGING_TYPE=stdout rebar3 ct --suite test/quicer_connection_SUITE.erl --case tc_conn_basic_verify_peer
```

### Advanced Build Configurations
Available environment variables:
- `QUICER_TLS_VER=sys` - Use system OpenSSL instead of bundled
- `CMAKE_BUILD_TYPE=Debug` - Debug build with symbols
- `QUIC_ENABLE_LOGGING=ON` - Enable msquic logging
- `QUIC_LOGGING_TYPE=stdout` - Log to stdout instead of lttng

### Sanitizer and Debugging Tools
For advanced debugging (requires special OTP builds):
```bash
tools/run/bin/sanitizer-check all  # Memory sanitizer tests
tools/run/bin/debug-check all      # Debug build tests  
tools/run/bin/valgrind-check all   # Valgrind analysis
```

### Wireshark Traffic Decryption
Use `sslkeylogfile` parameter in client connections:
```erlang
{ok, Conn} = quicer:connect("google.com", 443, [
    {verify, verify_peer},
    {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
    {alpn, ["h3"]}
], 5000)
```

### Common Build Issues
- **Missing clang-format-14**: Install with `sudo apt-get install clang-format-14`
- **Missing cmake**: Install with `sudo apt-get install cmake`
- **Network timeouts**: Ensure internet access for msquic download
- **Build hangs**: Wait full timeout period, builds can take 10+ minutes

## Repository Navigation

### Key Source Files
- `src/quicer.erl` - Main API module (50KB+ file)
- `src/quicer_nif.erl` - NIF interface (16KB+ file) 
- `src/quicer_connection.erl` - Connection management (22KB+ file)
- `src/quicer_stream.erl` - Stream handling (22KB+ file)
- `c_src/` - C source files for NIF implementation

### Test Organization
- `test/quicer_*_SUITE.erl` - Common Test suites
- `test/prop_*.erl` - Property-based tests with PropEr
- `test/example/` - Example client/server implementations
- `test/example_*_connection.erl` - Reference implementations for testing

### Build Configuration
- `Makefile` - Main build targets and CI commands
- `rebar.config` - Erlang build configuration and dependencies
- `CMakeLists.txt` - C build configuration and linking
- `build.sh` - Native library build script
- `get-msquic.sh` - msquic dependency management

### Documentation
- `README.md` - Project overview and examples
- `docs/Terminology.md` - QUIC terminology and concepts
- `docs/messages_to_owner.md` - Message passing documentation
- `BUILD.ubuntu20.04.md` - Ubuntu-specific build instructions

## Common Development Tasks

### Adding New Features
1. Modify relevant source files in `src/`
2. Add tests in `test/` following existing patterns
3. Update documentation if API changes
4. Run full validation: `make ci && make test`

### Debugging Connection Issues
1. Enable debug logging: `QUIC_LOGGING_TYPE=stdout`
2. Check test examples in `test/example/`
3. Verify certificates and network connectivity
4. Use Wireshark with sslkeylogfile for traffic analysis

### Performance Testing
- Use property-based tests: `make proper`
- Run specific test suites: `rebar3 ct --suite test/quicer_connection_SUITE.erl`
- Enable coverage analysis: `make cover`

### Expected Test Output Patterns
- **Successful test**: Look for "All X tests passed" or "Test passed."
- **Build completion**: Look for "Built target quicer_nif" and symlink creation
- **Format check**: No output means formatting is correct
- **Dialyzer success**: Look for "Checking X modules" followed by "Dialyzer completed successfully"

## CI/CD Integration
The CI workflow (`.github/workflows/main.yml`) runs:
1. Code formatting checks
2. Multi-platform builds (Ubuntu, macOS)
3. Multiple OTP/OpenSSL version combinations
4. Full test suite execution
5. Static analysis and linting

Always ensure your changes pass the complete CI pipeline before submission.

## Quick Reference Commands
Essential commands with timeouts for agents:
```bash
# Bootstrap (20+ minutes total)
make build-nif  # NEVER CANCEL - takes 6-11 minutes
rebar3 compile  # 30-60 seconds

# Testing (30+ minutes total) 
make ci         # NEVER CANCEL - takes 15-25 minutes  
make test       # NEVER CANCEL - takes 8-20 minutes

# Quality checks (10+ minutes total)
make dialyzer   # NEVER CANCEL - takes 2-5 minutes
make hank       # 30-60 seconds
make fmt        # 5-15 seconds

# Debug single test case
QUIC_LOGGING_TYPE=stdout rebar3 ct --suite test/quicer_connection_SUITE.erl --case tc_conn_basic
```