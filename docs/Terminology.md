# Terminology
| Term       | Definition                                                       |
|------------|------------------------------------------------------------------|
| server     | listen and accept quic connections from clients                  |
| client     | initiates quic connection                                        |
| listener   | Erlang Process owns listening port                               |
| connection | Quic Connection                                                  |
| stream     | Exchanging app data over a connection                            |
| owner      | 'owner' is a process that receives quic events.                  |
|            | 'connection owner' receive events of a connection                |
|            | 'stream owner' receive application data and events from a stream |
|            | 'listener owner' receive events from listener                    |
|            | When owner is dead, related resources would be released          |
| l_ctx      | listener nif context                                             |
| c_ctx      | connection nif context                                           |
| s_ctx      | stream nif context                                               |


