# Examples

This directory contains 2 examples, as well as lux test code.

## Example 1, qt.erl

The first example contains a server and a client, the client has a rudimentary
CLI which makes it possible to play around with various combinations of
connect, start_stream, close_stream etc.
Start the server as

```
$ make server``
```

and in another terminal, the client as
```
$ make client
```

In the client terminal, start the CLI by `qt:c()` and then experiment
with issuing various commands:


```
$ make all
......
$ make client
Eshell V13.0.4  (abort with ^G)
1> qt:c().
--> connect.
Connection # 1
--> {stream, 1}.
Sent negotiate data
Stream # 1
--> {ping, 1}.
Got pong 1
ok
--> {close_stream, 1}.
ok
-->

```

Also, it's interesting is to experiment with various variants of CTL-Z and
CTL-C on both the server and the client.

Furthermore, there is an almost identical variant called qt_ssl.erl that can
be used to perform comaparisions between quic and SSL. Both speed and memory
consumption tests can be performed. Spoiler, quic is both smaller and faster
than OTP SSL.

## Example 2, rev.erl

This is an example trying to emulate the case with a server and a client where
the client resides behind a NAT device, thus forcing all connections to go from
"down" to "up"
Once a quicer connections has been established going "up", all subsequent
streams in both directions are shared on top of the same connection.
See the code for run instructions


## lux

Lux is an amazing `expect` like test tool (written in Erlang). It's available at
https://github.com/hawk/lux
To run the lux tests in this example, download, build and install `lux` and
execute

```
$ make lux
```

