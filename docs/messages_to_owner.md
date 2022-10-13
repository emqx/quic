# Messages to the owner process

This doc describes the messages that the owner of QUIC resources (listener, connection, stream) will receive.

The message is a fixed *4* elements tuple formatted as 

``` erlang
{quic, EventName, ResourceHandle, EventProps}.

where

quic :: 
    The mark of quic messages, distinguishing TCP or SSL transport messages

EventName :: atom() | binary()
    The name of event from the stack.
    Event could be the event of the transport layer in atom() or the actual data in binary().
            
ResourceHandle :: handle()
    The handle of the resource that generates the event.
    
EventProps :: undefined | map() | integer() | any()
    The properties of the event.
    The properties provide extra info for the event that usually cannot be ignored.

```

For the types() used in this doc pls refer to 
- ['quicer_types' (Github)](https://github.com/emqx/quic/blob/main/include/quicer_types.hrl)
- ['quicer_types' (Local)](../include/quicer_types.hrl)

Some events could be enabled/disabled by either:

1. Set/unset the options while opening/starting the resources

```erlang
%% Use 'start_flag' option indicating owner wants to receive `peer_accepted` event
{quicer:start_stream(Conn, [ {active, 3}, 
                             {start_flag, ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT}
                           ]),

```

1. Use the **quic_event_mask**, set in mask to enable receiving.

```erlang
{quicer:start_stream(Conn, [{active, 3}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}]),

```

@TODO TBD: if we should have a strict rule that event is enabled in resource options but masked out in **quic_event_mask**

## Messages to Stream Owner

### start_complete

The stream initiated locally is started regardless of success/fail or sync/async.

The only event that will be delivered to the owner if start fails with atom status.

When 'QUIC_STREAM_START_FLAG_FAIL_BLOCKED' is set in stream 'start_flag', stream start will fail and the owner will
get this event with status 'stream_limit_reached' if peer has flow control preventing initiating new stream. 
Otherwise, start stream will be queued. Also see [peer_accepted](#peer_accepted) 

```erlang
{quic, start_complete, stream_handler(), #{ status := atom_status()
                                          , stream_id := integer(), 
                                          , is_peer_accepted := boolean() }
```

### active received data

Data received in binary format.


```erlang
{quic, binary(), stream_handler(), #{ absolute_offset := integer() 
                                    , len := integer()  
                                    , flags := integer()} }
```

#### properties:

- absolute_offset: absolute offset in this stream
- len: byte size of the binary
- flags: recv flags:
  1. 'QUIC_RECEIVE_FLAG_NONE' 
     Default, none 
  1. 'QUIC_RECEIVE_FLAG_0_RTT'
  1. 'QUIC_RECEIVE_FLAG_FIN'
     Last piece of data from stream, implies a remote closing stream (send) 

### send_complete

Send call is handled by stack, caller is ok to release the send buffer

This message is for sync send only. 

IsSendCanceled: Peer abort receive

```erlang
{quic, send_complete, stream_handler(), IsSendCanceled :: boolean()}
```


### peer_send_shutdown

Peer has sent all the data and wants to shutdown gracefully.

```erlang
{quic, peer_send_shutdown, stream_handler(), undefined}
```

@TODO mask

### peer_send_aborted

Received a RESET_STREAM Frame.

Peer terminated the sending part of the stream abruptly.
The receiver can discard any data that it already received on the stream.

```erlang
{quic, peer_send_aborted, stream_handler(), ErrorCode::integer()}
```

where 'ErrorCode' is application layer error code

### peer_receive_aborted

Received a RESET_STREAM Frame.
The peer (receiver) abortively shut down the stream.
The sender may assume the data sent is either handled or not handled.

```erlang
{quic, peer_receive_aborted, stream_handler(), ErrorCode::integer()}
```

where 'ErrorCode' is application layer error code

### send_shutdown_complete

The send has been completely shut down.
This will happen immediately on an abortive send or after a graceful stream 
send shutdown has been acknowledged by the peer.

```erlang
{quic, send_shutdown_complete, stream_handler(), IsGraceful::boolean()}
```

### shutdown_completed, stream is closed

Both endpoints of sending and receiving of the stream have been shut down.

```erlang
{quic, stream_closed, stream_handler(), #{ is_conn_shutdown := boolean()
                                         , is_app_closing := boolean()
                                         , is_shutdown_by_app := boolean()
                                         , is_closed_remotely := boolean()
                                         , status := atom_reason()
                                         , error := error_code()
                                         }
```

### idea_send_buffer_size

@TODO

### peer_accepted

The stream which **was not accepted** due to peer flow control is now accepted by the peer.

To receive this event, the 'QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT' must be set 
in `start_flag` while starting the stream.

```erlang
{quic, peer_accepted, stream_handler(), undefined}
```

Also see [start_complete](#start_complete)

### continue for passive receive

This is for passive recv only, this is used to notify
caller that new data is ready in recv buffer. The data in the recv buffer
will be pulled by NIF function instead of by sending the erlang messages

see usage in: quicer:recv/2

``` erlang
{quic, continue, stream_handler(), undefined}
```

### passive mode

Running out of *active_n*, stream now is in passive mode.

Should call setopt active_n to make it back to active mode again

Or use quicer:recv/2 to receive in passive mode

``` erlang
{quic, passive, stream_handler(), undefined}
```

## Messages to Connection Owner

### Connection connected

``` erlang
{quic, connected, connection_handler(), #{ is_resumed := boolean()
                                         , alpns := string() | undefined
                                         }}
```

This message notifies the connection owner that quic connection is established ( the TLS handshake is done ).


### Transport Shutdown

Connection has been shutdown by the transport locally, such as idle timeout.

``` erlang
{quic, transport_shutdown, connection_handler(), #{ status := atom_reason()
                                                  , error := error_code()
                                                  }
```

### Shutdown initiated by PEER

Peer side initiated connection shutdown.

``` erlang
{quic, shutdown, connection_handler(), ErrorCode :: integer()}
```

### Shutdown Complete

The connection has completed the shutdown process and is ready to be
safely cleaned up.

``` erlang
{quic, closed, connection_handler(), #{ is_handshake_completed := boolean()}
                                      , is_peer_acked := boolean()
                                      , is_app_closing := boolean()
                                      }} 
```

### Local Address Changed

Connection local addr is changed.

```erlang
{quic, local_address_changed, connection_handler(), NewAddr :: string()}.

```

### Peer Address Changed

Connection peer addr is changed.

```erlang
{quic, peer_address_changed, connection_handler(), NewAddr :: string()}.

```

### New stream started from peer

``` erlang
{quic, new_stream, stream_handler(), stream_open_flags()}
```

This message is sent to notify the process which is accepting new incoming streams.

The process becomes the owner of the stream.

### Streams available

More streams are available due to flow control from the peer.

`Available = Max - Used`

```erlang
{quic, streams_available, connection_handler(), #{ bidi_streams := integer()
                                                 , unidi_streams := integer()
                                                 }}
```

### Peer Needs Streams

Peer wants to open more streams but cannot due to flow control
```erlang
{quic, peer_needs_streams, connection_handler(), undefined}
```

### Ideal processor changed

@TODO, move owner close to the same core. 


### DATAGRAM state changed
@TODO convert it to the new format and use some atom state

```erlang
{quic, dgram, connection_handler(), MaxLen::integer()} 
```

### DATAGRAM received

@TODO convert it to the new format

```erlang
{quic, binary(), {dgram, connection_handler()}, flag :: integer()}
```

### DATAGRAM send state changed

@TODO use some atom state

```erlang
{quic, send_dgram_completed, connection_handler(), State::integer()} 
```

### Connection resumed

**Server only**, connection is resumed with session ticket

``` erlang
{quic, connection_resumed, connection_handler(), SessionData :: false | binary() }
```

Connection is resumed with binary session data or with 'false' means empty session data.

### New Session Ticket

**Client Only** The client received the `NST`` (new session ticket) from the server if `QUICER_CONNECTION_EVENT_MASK_NST` had been 
set in connection opt `quic_event_mask` when client starts the connection.

``` erlang
{quic, nst_received, connection_handler(), Ticket::binary()}
```

The `NST` could be used by Client for 0-RTT handshake with a connection opt 
```erlang
{ok, ConnResumed} = quicer:connect("localhost", Port, [{nst, NST}], 5000),
```

## Messages to Listener Owner

### New incoming connection

``` erlang
{quic, new_conn, connection_handler(), ConnecionInfo :: #{ version      := integer()
                                                         , local_addr   := string()
                                                         , remote_addr  := string()
                                                         , server_name  := binary()
                                                         , alpns        := binary()
                                                         , client_alpns := binary()
                                                         , crypto_buffer:= binary()
                                                         }}
```

This message is sent to the process who is accepting new connections.

The process becomes the connection owner.

To complete the TLS handshake, quicer:handshake/1,2 should be called.

#### Properties
1. version: QUIC version
1. local_addr: local addr in IP:Port
1. remote_addr: remote addr in IP:Port
1. server_name: Server name
1. alpns: List of alpn, negotiated
1. client_alpns: Client provided alpns
1. `crypto_buffer`: TLS crypto_buffer in initial packet

### Listener Stopped

```erlang
{quic, listener_stopped, listener_handler(), is_app_closing::boolean()}
```

This message is sent to the listener owner process, indicating the listener
is stopped and closed. 

`is_app_closing`: handle is closed in the stack and in quicer we should never get _true_
because quicer close handle in resource dtor.
