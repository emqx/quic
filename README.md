# quicer

QUIC protocol erlang library.

[msquic](https://github.com/microsoft/msquic) NIF binding.

Project Status: WIP (actively), POC quality

API: is not stable, might be changed in the future.

![Erlang](https://img.shields.io/badge/Erlang-white.svg?style=plastic&logo=erlang&logoColor=a90533)
![CI](https://github.com/emqx/quic/workflows/ci/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage Status](https://coveralls.io/repos/emqx/quic/badge.png?branch=main)](https://coveralls.io/r/emqx/quic?branch=main)

# OS Support
| OS      | Status    |
|---------|-----------|
| Linux   | Supported |
| macOS   | Supported |
| Windows | TBD       |

# BUILD

## Dependencies

1. OTP22+
1. rebar3
1. cmake3.16+
1. [CLOG](https://github.com/microsoft/CLOG) (required for debug logging only)
1. LTTNG2.12 (required for debug build only)

## With DEBUG

Debug build dependency: [CLOG](https://github.com/microsoft/CLOG) 

``` sh
$ rebar3 compile 
# OR
$ make
```

note, 

To enable logging and release build:

``` sh
export CMAKE_BUILD_TYPE=Debug
export QUIC_ENABLE_LOGGING=ON
export QUICER_USE_LTTNG=1
make
```

## BUILD with logging to stdout

``` sh
QUIC_LOGGING_TYPE=stdout make
```

## Without DEBUG

``` sh
export CMAKE_BUILD_TYPE=Release
make
```

# Examples

## Ping Pong server and client

### Server

``` erlang
application:ensure_all_started(quicer),
Port = 4567,
LOptions = [ {certfile, "cert.pem"}
           , {keyfile,  "key.pem"}
           , {alpn, ["sample"]}
           , {peer_bidi_stream_count, 1}
             ],
{ok, L} = quicer:listen(Port, LOptions),
{ok, Conn} = quicer:accept(L, [], 120000),
{ok, Conn} = quicer:handshake(Conn),
{ok, Stm} = quicer:accept_stream(Conn, []),
receive {quic, <<"ping">>, Stm, _Props} -> ok end,
{ok, 4} = quicer:send(Stm, <<"pong">>),
quicer:close_listener(L).
```

### Client

``` erlang
application:ensure_all_started(quicer),
Port = 4567,
{ok, Conn} = quicer:connect("localhost", Port, [{alpn, ["sample"]}, {verify, none}], 5000),
{ok, Stm} = quicer:start_stream(Conn, []),
{ok, 4} = quicer:send(Stm, <<"ping">>),
receive {quic, <<"pong">>, Stm, _Props} -> ok end,
ok = quicer:close_connection(Conn).
```


# TEST

``` sh
$ make test
```

# Documentation

``` sh
$ make doc
```

Then check the doc in browser: 

``` sh
$ firefox doc/index.html
```

# License
Apache License Version 2.0

