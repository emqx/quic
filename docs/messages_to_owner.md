# Messages to the owner process

This doc describes the the messages that the owner of QUIC resources (listener, connection, stream) will receive.

The message is a fixed *4* elements tuple formatted as 

``` erlang
{quic, EventName, ResourceHandle, EventProps}.

where

quic :: 
    The mark of quic messages, distinguishing tcp or ssl transport messages

EventName :: atom() | binary()
    The name of event from the stack.
    Event could be the event of the transport layer in atom() or the actual data in binary().
            
ResourceHandle :: opaque()
    The handle of the resource that generates the event.
    
EventProps :: any()
    The properties of the event.
    The properties provides extra info for the event that usually cannot be ignored.

```

Some events could be disabled by either 
1. Set/unset some options while open/start the resources
1. Unset the **event_mask**

@TODO TBD: if we should have a strict rule that event is enabled in resource options but masked out in **event_mask**

## Messages to Stream Owner

### 'start_complete'

The stream initiated locally is started regardless of success/fail or sync/async.

```erlang
{quic, start_complete, stream_handler(), #{ status := atom_status()
                                          , stream_id := integer(), 
                                          , is_peer_accepted := boolean() }
```
### 'active received data'

Data received in binary format

```erlang
{quic, binary(), stream_handler(), #{absolute_offset := integer(), 
                                     len := integer(), 
                                     flags := integer()} }
```

### 'send_complete'

Send call is handled by stack, caller is ok to release the sndbuffer

This message is for sync send only.

```erlang
{quic, send_complete, stream_handler(), IsSendCanceled :: boolean()}
```


### 'peer_send_shutdown'

Peer has sent all the data and wants to shutdown gracefully.

```erlang
{quic, peer_send_shutdown, stream_handler(), undefined}
```

### 'peer_send_aborted'
Received a RESET_STREAM Frame.

Peer terminated the sending part of the stream abruptly.
The receiver can discard any data that it already received on the stream.

```erlang
{quic, peer_send_aborted, stream_handler(), ErrorCode}
```

### 'peer_receive_aborted'
Received a RESET_STREAM Frame.
The peer (receiver) abortively shut down the stream.
The sender may assume the data sent is either handled or not handled.

```erlang
{quic, peer_receive_aborted, stream_handler(), ErrorCode}
```

### 'send_shutdown_complete'

@TODO

### shutdown_completed, stream is closed

Both endpoints of sending and receiving of the stream have been shut down.

```erlang
{quic, stream_closed, stream_handler(), #{ is_conn_shutdown := boolean()
                                         , is_app_closing := boolean()
                                         }
```

### 'idea_send_buffer_size'

@TODO

### peer_accepted
The stream which was not accepted due to peer flow control is now accepted by the peer.
```erlang
{quic, peer_accepted, stream_handler(), undefined}
```


### continue recv

This is for passive recv only, this is used to notify
caller that new data is ready in recv buffer. The data in the recv buffer
will be pulled by NIF function instead of by sending the erlang messages

see usage in: quicer:recv/2

``` erlang
{quic, continue, stream_handler(), undefined}
```

### passive mode

Running out of *active_n*, stream now is in passive mode.

Need to call setopt active_n to make it back to passive mode again

Or use quicer:recv/2 to receive in passive mode

``` erlang
{quic, passive, stream_handler(), undefined}
```

## Messages to Connection Owner

### Connection connected

``` erlang
{quic, connected, connection_handler(), #{ is_resumed := boolean()
                                         , alpns = string() | undefined
                                         }}
```

This message notifies the connection owner that quic connection is established(TLS handshake is done).

also see [[Accept New Connection (Server)]]

### Transport Shutdown

Connection has been shutdown by the transport locally, such as idle timeout.

``` erlang
{quic, transport_shutdown, connection_handler(), Status :: atom_status()}
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

Connecion local addr is changed.

```erlang
{quic, local_address_changed, connection_handler(), NewAddr :: string()}.

```

### Peer Address Changed

Connecion peer addr is changed.

```erlang
{quic, peer_address_changed, connection_handler(), NewAddr :: string()}.

```

### New stream started from peer

``` erlang
{quic, new_stream, stream_handler(), stream_open_flags()}
```

This message is sent to notify the process which is accpeting new stream.

The process become the owner of the stream.

also see [[Accept Stream (Server)]]

### Streams available

More streams are available due to flow control from peer.

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

@TODO


### DATAGRAM state changed
@TODO convert it to new format and use some atom state

```erlang
{quic, dgram, connection_handler(), MaxLen::integer()} 
```

### DATAGRAM received

@TODO convert it to new format

```erlang
{quic, binary(), {dgram, connection_handler()}, flag :: integer()}
```

### DATAGRAM send state changed

@TODO use some atom state

```erlang
{quic, send_dgram_completed, connection_handler(), State::integer()} 
```

### Connection resumed

**Server only**, connecion is resumed with session ticket

``` erlang
{quic, connection_resumed, connection_handler(), SessionData :: false | binary() }
```

Connection is resumed with binary session data or with 'false' means empty session data.

### New Session Ticket

**Client Only** The client received the NST (new session ticket) from the server if `QUICER_CONNECTION_EVENT_MASK_NST` had been 
set in connection opt `quic_event_mask` when client starts the connection.

The NST could be used by Client for 0-RTT handshake with connection opt '{nst, Ticket :: binary()}'.

``` erlang
{quic, nst_received, connection_handler(), Ticket::binary()}
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


### Listener Stopped

```erlang
{quic, listener_stopped, listener_handler(), is_app_closing}
```

This message is sent to the listener owner process, indicating the listener
is stopped and closed. 
