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
{quicer:start_stream(Conn, [{active, 3}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}]),

```

@TODO TBD: if we should have a strict rule that event is enabled in resource options but masked out in **quic_event_mask**

## Messages to Stream Owner

### start_completed

The stream initiated locally is started regardless of success/fail or sync/async.

The only event that will be delivered to the owner if start fails with atom status.

When 'QUIC_STREAM_START_FLAG_FAIL_BLOCKED' is set in stream 'start_flag', stream start will fail and the owner will
get this event with status 'stream_limit_reached' if peer has flow control preventing initiating new stream. 
Otherwise, start stream will be queued. Also see [peer_accepted](#peer_accepted) 

```erlang
{quic, start_completed, stream_handle(), #{ status := atom_status()
                                           , stream_id := integer()
                                           , is_peer_accepted := boolean() }
```

### active received data

Stream data received in binary format with stream handle

also see [DATAGRAM received data].

```erlang
{quic, binary(), stream_handle(), #{ absolute_offset := integer() 
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
{quic, send_complete, stream_handle(), IsSendCanceled :: boolean()}
```


### peer_send_shutdown

Peer has sent all the data and wants to shutdown gracefully.

```erlang
{quic, peer_send_shutdown, stream_handle(), undefined}
```

@TODO mask

### peer_send_aborted

Received a RESET_STREAM Frame.

Peer terminated the sending part of the stream abruptly.
The receiver can discard any data that it already received on the stream.

```erlang
{quic, peer_send_aborted, stream_handle(), ErrorCode::integer()}
```

where 'ErrorCode' is application layer error code

### peer_receive_aborted

Received a RESET_STREAM Frame.
The peer (receiver) abortively shut down the stream.
The sender may assume the data sent is either handled or not handled.

```erlang
{quic, peer_receive_aborted, stream_handle(), ErrorCode::integer()}
```

where 'ErrorCode' is application layer error code

### send_shutdown_complete

The send has been completely shut down.
This will happen immediately on an abortive send or after a graceful stream 
send shutdown has been acknowledged by the peer.

```erlang
{quic, send_shutdown_complete, stream_handle(), IsGraceful::boolean()}
```

### shutdown_completed, stream is closed

Both endpoints of sending and receiving of the stream have been shut down.

```erlang
{quic, stream_closed, stream_handle(), #{ is_conn_shutdown := boolean()
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
{quic, peer_accepted, stream_handle(), undefined}
```

Also see [start_complete](#start_complete)

### continue for passive receive

This is for passive recv only, this is used to notify
caller that new data is ready in recv buffer. The data in the recv buffer
will be pulled by NIF function instead of by sending the erlang messages

see usage in: quicer:recv/2

``` erlang
{quic, continue, stream_handle(), undefined}
```

### passive mode

Running out of *active_n*, stream now is in passive mode.

Should call setopt active_n to make it back to active mode again

Or use quicer:recv/2 to receive in passive mode

``` erlang
{quic, passive, stream_handle(), undefined}
```

## Messages to Connection Owner

### Connection connected

``` erlang
{quic, connected, connection_handle(), #{ is_resumed := boolean()
                                         , alpns := string() | undefined
                                         }}
```

This message notifies the connection owner that quic connection is established ( the TLS handshake is done ).


### Transport Shutdown

Connection has been shutdown by the transport locally, such as idle timeout.

``` erlang
{quic, transport_shutdown, connection_handle(), #{ status := atom_reason()
                                                  , error := error_code()
                                                  }
```

### Shutdown initiated by PEER

Peer side initiated connection shutdown.

``` erlang
{quic, shutdown, connection_handle(), ErrorCode :: error_code()}
```

### Shutdown Complete

The connection has completed the shutdown process and is ready to be
safely cleaned up.

``` erlang
{quic, closed, connection_handle(), #{ is_handshake_completed := boolean()
                                      , is_peer_acked := boolean()
                                      , is_app_closing := boolean()
                                      }} 
```

### Local Address Changed

Connection local addr is changed.

```erlang
{quic, local_address_changed, connection_handle(), NewAddr :: string()}.

```

### Peer Address Changed

Connection peer addr is changed.

```erlang
{quic, peer_address_changed, connection_handle(), NewAddr :: string()}.

```

### New stream started from peer

``` erlang
{quic, new_stream, stream_handle(), #{ flags := stream_open_flags()
                                      , is_orphan := boolean()
                                      }}
```

This message is sent to notify the process that the process becomes the owner of the stream.

When `is_orphan` is false, the process is selected as the owner because it is in the new stream acceptor list.

When `is_orphan` is true, the connection owner process is selected because there is no available stream acceptor
and the stream active mode is set to false (passive mode). 

### Streams available

More streams are available due to flow control from the peer.

If you don't want this event, set 'QUICER_CONNECTION_EVENT_MASK_NO_STREAMS_AVAILABLE'

`Available = Max - Used`

```erlang
{quic, streams_available, connection_handle(), #{ bidi_streams := integer()
                                                 , unidi_streams := integer()
                                                 }}
```

### Peer Needs Streams

Peer wants to open more streams but cannot due to flow control
```erlang
{quic, peer_needs_streams, connection_handle(), unidi_streams | bidi_streams}
```

### Ideal processor changed

@TODO, move owner close to the same core. 


### DATAGRAM state changed

```erlang
{quic, dgram_state_changed, connection_handle(), #{ dgram_send_enabled := boolean(), dgram_max_len := uint64()}}
```

### DATAGRAM received data

with connection handle and integer flag

```erlang
{quic, binary(), connection_handle(), Flags :: non_neg_integer()}
```

### DATAGRAM send completed, success or fail.

```erlang
{quic, dgram_send_state, connection_handle(), #{state := datagram_send_state()}} 
```

### Connection resumed

**Server only**, connection is resumed with session ticket

``` erlang
{quic, connection_resumed, connection_handle(), SessionData :: false | binary() }
```

Connection is resumed with binary session data or with 'false' means empty session data.

### New Session Ticket

**Client Only** The client received the `NST` (new session ticket) from the server if `QUICER_CONNECTION_EVENT_MASK_NST` had been 
set in connection opt `quic_event_mask` when client starts the connection.

``` erlang
{quic, nst_received, connection_handle(), Ticket::binary()}
```

The `NST` could be used by Client for 0-RTT handshake with a connection opt 
```erlang
{ok, ConnResumed} = quicer:connect("localhost", Port, [{nst, NST}], 5000),
```

### Stream's connection is closed

**Acceptor Only** 
Indicating the connection that the stream acceptor is accepting is closed.
The stream acceptor will no longer get new incoming stream.

```erlang
{quic, closed, undefined, undefined}
```

## Messages to Listener Owner

### New incoming connection

``` erlang
{quic, new_conn, connection_handle(), ConnectionInfo :: #{ version      := integer()
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
{quic, listener_stopped, listener_handle(), is_app_closing::boolean()}
```

This message is sent to the listener owner process, indicating the listener
is stopped and closed. 

`is_app_closing`: handle is closed in the stack and in quicer we should never get _true_
because quicer close handle in resource dtor.
