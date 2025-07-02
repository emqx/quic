# Quicer

QUIC (Next-generation transport protocol) erlang library.

[msquic](https://github.com/microsoft/msquic) NIF binding.

Project Status: Preview

![Erlang](https://img.shields.io/badge/Erlang-white.svg?style=plastic&logo=erlang&logoColor=a90533)
![CI](https://github.com/emqx/quic/workflows/ci/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage Status](https://coveralls.io/repos/emqx/quic/badge.png?branch=main)](https://coveralls.io/r/emqx/quic?branch=main)

## OS Support

| OS      | Status      |
|---------|-------------|
| Linux   | Supported   |
| macOS   | Supported   |
| Windows | Help Needed |

# Add to your project 

## rebar.config

``` erlang
{deps, [
    {quicer, {git, "https://github.com/emqx/quic.git", {tag, "0.2.4"}}},
    ...
```

## mix.exs

``` elixir
defp deps do
  [
    {:quicer, git: "https://github.com/emqx/quic.git", tag: "0.2.4"},
    ...
  ]
end

```

## Mix Release Compatibility

This library has been optimized for `mix release` compatibility. The build process ensures that no symlinks are created in the `priv/` directory, preventing file duplication during release packaging. This keeps the library size minimal (~14MB) instead of growing to ~23MB due to symlink dereferencing.

The build automatically:
- Creates single library files without versioned symlinks
- Removes any symlinks that might be created during the build process
- Maintains compatibility with hot upgrades through proper ABI versioning

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

## Try connect to Google with QUIC transport

``` erlang
%% Connect to google and disconnect, 
%% You could also tweak the parameters to see how it goes
{ok, Conn} = quicer:connect("google.com", 443, [{alpn, ["h3"]}, 
                            {verify, verify_peer}, 
                            {peer_unidi_stream_count, 3}], 5000),
quicer:shutdown_connection(Conn).
```

## More examples in test dir

refer to [test](./test) dir.

# Documentation

## Get Started

1. Understand the `handles` and the `ownership` in [Terminology](docs/Terminology.md)

1. Then check how to receives the data and signals:  [Messages](docs/messages_to_owner.md)

1. Read more in [msquic doc](https://github.com/microsoft/msquic/tree/main/docs)

## Offline hex doc

``` sh
make doc
firefox doc/index.html
```

# Dependencies

1. OTP25+
1. rebar3
1. cmake3.16+

# Build and test

## Dev mode
``` sh
make ci
```

# Troubleshooting 

### Log to `stdout`

Debug log could be enabled to print to `stdout` with the envvar `QUIC_LOGGING_TYPE=stdout` 

``` sh
QUIC_LOGGING_TYPE=stdout make
```

``` sh
%% Debug one testcase
QUIC_LOGGING_TYPE=stdout rebar3 ct --suite test/quicer_connection_SUITE.erl --case tc_conn_basic_verify_peer
```

### Decrypt traffic with Wireshark

Client could specify the connect param `sslkeylogfile` to record tls secrets for wireshark to decrypt.

``` erlang
    {ok, Conn} = quicer:connect(
        "google.com",
        443,
        [
            {verify, verify_peer},
            {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
            {peer_unidi_stream_count, 3},
            {alpn, ["h3"]}
        ],
        5000
    )
```

# License
Apache License Version 2.0

