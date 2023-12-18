%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-ifndef(QUICER_TYPES_HRL).
-define(QUICER_TYPES_HRL, true).

-include("quicer.hrl").

-define(BIT(Bits), (1 bsl (Bits))).
-define(MASK(Bits), (?BIT(Bits) - 1)).

-export_type([handle/0]).

%% @doc Other user defined opts may be used in callbacks
-type user_opts() :: #{ _ => _}.

%% Msquic Status Code Translation
-type atom_reason() ::
        success             |
        pending             |
        continue            |
        out_of_memory       |
        invalid_parameter   |
        invalid_state       |
        not_supported       |
        not_found           |
        buffer_too_small    |
        handshake_failure   |
        aborted             |
        address_in_use      |
        connection_timeout  |
        connection_idle     |
        internal_error      |
        connection_refused  |
        protocol_error      |
        ver_neg_error       |
        unreachable         |
        tls_error           |
        user_canceled       |
        alpn_neg_failure    |
        stream_limit_reached.

-type app_errno() :: non_neg_integer().
-type hostname() :: string().

-type listener_handle()   :: reference().
-type connection_handle() :: reference().
-type stream_handle()     :: reference().
-type conf_handle()       :: reference().
-type reg_handle()        :: reference().
-type global_handle()     :: quic_global.

-type handle() ::
        global_handle()     |
        listener_handle()   |
        connection_handle() |
        stream_handle()     |
        conf_handle()       |
        reg_handle().

-type registration_profile() :: execution_profile().
-type quic_handle_level() :: quic_tls | quic_configuration | false.

-type listen_on() :: inet:port_number() | string().
-type listen_opts() :: listen_security_opts() | quic_settings().
-type listen_security_opts() :: #{ alpn := [alpn()]
                                 , cert := file:filename()
                                 , certfile := file:filename()
                                 , key := file:filename()
                                 , keyfile := file:filename()
                                 , verify => none | peer | verify_peer | verify_none
                                 , cacertfile => file:filename()
                                 , password => string()
                                 , sslkeylogfile => file:filename()
                                 , allow_insecure => boolean()
                                 , quic_registration => reg_handle()
                                 , conn_acceptors => non_neg_integer()
                                 }.


-type uint64() :: 0..?MASK(64).
-type uint32() :: 0..?MASK(32).
-type uint16() :: 0..?MASK(16).
-type uint8() :: 0..?MASK(8).

-type quic_settings() :: #{ max_bytes_per_key => uint64()
                          , handshake_idle_timeout_ms => uint64()
                          , idle_timeout_ms => uint64()
                            %% for client only
                          , tls_client_max_send_buffer => uint32()
                            %% for server only
                          , tls_server_max_send_buffer => uint32()
                          , stream_recv_window_default => uint32()
                          , stream_recv_buffer_default => uint32()
                          , conn_flow_control_window => uint32()
                          %, max_worker_queue_delay_us => uint32()
                          , max_stateless_operations => uint32()
                          , initial_window_packets => uint32()
                          , send_idle_timeout_ms => uint32()
                          , initial_rtt_ms => uint32()
                          , max_ack_delay_ms => uint32()
                          , disconnect_timeout_ms => uint32()
                          , keep_alive_interval_ms => uint32()
                          , peer_bidi_stream_count => uint16()
                          , peer_unidi_stream_count => uint16()
                          , retry_memory_limit => uint16()
                          , load_balancing_mode => uint16()
                          , max_operations_per_drain => uint8()
                          , send_buffering_enabled => uint8()
                          , pacing_enabled => uint8()
                          , migration_enabled => uint8()
                          , datagram_receive_enabled => uint8()
                          , server_resumption_level => uint8()
                          %  internal, not exposed
                          %, version_negotiation_ext_enabled => uint8()
                          , minimum_mtu => uint16()
                          , maximum_mtu => uint16()
                          , mtu_discovery_search_complete_timeout_us => uint64()
                          , mtu_discovery_missing_probe_count => uint8()
                          , max_binding_stateless_operations => uint16()
                          , stateless_operation_expiration_ms => uint16()
                          }.
-type alpn() :: string().

-type conn_opts() :: quic_settings() |  #{ alpn := [string()]
                                         , conn_callback => module()
                                         , cert => file:filename()
                                         , certfile => file:filename()
                                         , key => file:filename()
                                         , keyfile => file:filename()
                                         , password => string()
                                         , verify => none | peer
                                         , handle => connection_handle() %% get NST from last connection, for reconnect.
                                         , nst => binary()
                                         , cacertfile => file:filename()
                                         , sslkeylogfile => file:filename()
                                         , peer_bidi_stream_count => uint16()
                                         , peer_unidi_stream_count => uint16()
                                         , handshake_idle_timeout_ms => non_neg_integer()
                                         , quic_event_mask => uint32()
                                         , param_conn_disable_1rtt_encryption => boolean()
                                           %% Not working well
                                         , param_conn_local_address => string()
                                         , _ => _ %% for Application defined options
                                         }.
-type conn_shutdown_flag() :: ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE |
                              ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT.
-type acceptor_opts() :: map(). %% @TODO expand

-type stream_opts() :: #{ active := boolean() | once | integer()
                        , open_flag => stream_open_flags()
                        , start_flag => stream_start_flags()
                        , event_mask => uint32()
                        , disable_fpbuffer => boolean()
                        , _ => _ %% for Application defined options
                        }. %% @TODO expand

-type stream_open_flags() ::  ?QUIC_STREAM_OPEN_FLAG_NONE |
                              ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL | %% Open unidirectional stream
                              ?QUIC_STREAM_OPEN_FLAG_0_RTT.           %% The stream is opened via a 0-RTT packet
-type stream_start_flags() :: ?QUIC_STREAM_START_FLAG_NONE |
                              ?QUIC_STREAM_START_FLAG_IMMEDIATE |           %% Immediately informs peer that stream is open
                              ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED |        %% If number of streams is rate limited, notify with event start_completed with status 'stream_limit_reached'
                              ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL |    %% Shutdown the stream immediately after start failure
                              ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT. %% Indicate PEER_ACCEPTED event if not accepted at start

-type stream_shutdown_flags() :: ?QUIC_STREAM_SHUTDOWN_FLAG_NONE |          %% **Invalid** option for `StreamShutdown`
                                 ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL |      %% Gracefully shutdown the stream
                                 ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |    %% Abortively shutdown the sending side of the stream
                                 ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE | %% Abortively shutdown the sending side of the stream
                                 ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT |         %% Abortively shutdown both sending and receiveing side of the stream
                                 ?QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE.      %% Don't wait for ack from peer, must be used with abortive shutdown

-type send_flags() :: non_neg_integer(). %% is sync send or not

-type new_stream_props() :: #{ is_orphan := boolean()
                             , flags := stream_open_flags()
                             }.

-type streams_available_props() :: #{ unidi_streams := non_neg_integer()
                                    , bidi_streams := non_neg_integer()
                                    }.

-type send_complete_flag() :: ?QUIC_SEND_COMPLETE_SUCCESS |
                              ?QUIC_SEND_COMPLETE_CANCELLED.

-type optlevel() :: false | %% unspecified
                    quic_global |
                    quic_registration |
                    quic_configuration |
                    quic_tls.

-type optname() ::
        optname_global()        |
        optname_listener()      |
        optname_conn()          |
        optname_stream()        |
        optname_reg()           |
        optname_configuration() |
        optname_tls().
                                                              %% | GET | SET|
-type optname_conn() ::   %% with connection_handle()
        %% /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */|
        param_conn_quic_version                   |           %% |  X  |    |
        param_conn_local_address                  |           %% |  X  |    |
        param_conn_remote_address                 |           %% |  X  |  X | @TODO SET
        param_conn_ideal_processor                |           %% |  X  |    |
        param_conn_settings                       |           %% |  X  |  X |
        param_conn_statistics                     |           %% |  X  |    |
        param_conn_statistics_plat                |           %% |  X  |    | @TODO
        param_conn_share_udp_binding              |           %% |  X  |  X |
        param_conn_local_bidi_stream_count        |           %% |  X  |    |
        param_conn_local_unidi_stream_count       |           %% |  X  |    |
        param_conn_max_stream_ids                 |           %% |  X  |    |
        param_conn_close_reason_phrase            |           %% |  X  |  X |
        param_conn_stream_scheduling_scheme       |           %% |  X  |  X |
        param_conn_datagram_receive_enabled       |           %% |  X  |  X |
        param_conn_datagram_send_enabled          |           %% |  X  |    |
        param_conn_disable_1rtt_encryption        |           %% |  X  |  X |
        param_conn_resumption_ticket              |           %% |     |  X |
        param_conn_peer_certificate_valid         |           %% |     |  X |
        param_conn_local_interface.                           %% |     |  X |

-type optname_tls()   ::  %% with connection_handle()
        param_tls_schannel_context_attribute_w    |           %% |  X  |    |
        param_tls_handshake_info                  |           %% |  X  |    |
        param_tls_negotiated_alpn.                            %% |  X  |    |

-type optname_stream() ::
        active                                    |           %% |  X  |  X |
        controlling_process                       |           %% |     |  X |
        param_stream_id                           |           %% |     |  X |
        param_stream_0rtt_length                  |           %% |  X  |    |
        param_stream_ideal_send_buffer_size       |           %% |  X  |    |
        param_stream_priority.                                %% |     |    |

-type optname_global() ::                                     %% with `undefined' handle
        param_global_retry_memory_percent |                   %% |  X  | X  |
        param_global_supported_versions   |                   %% |  X  |    | @TODO
        param_global_load_balacing_mode   |                   %% |  X  | X  |
        param_global_perf_counters        |                   %% |  X  |    |
        param_global_settings             |                   %% |  X  | X  |
        param_global_version.                                 %% |  X  |    | @TODO

-type optname_reg() :: param_registration_cid_prefix.         %% |  X  | X  | @TODO

-type optname_configuration() ::                              %% with config_handle()
        param_configuration_settings        |                 %% |  X  | X  |
        param_configuration_ticket_keys.                      %% |     | X  | @TODO

-type optname_listener() ::                                   %% with listener_handle
        param_listener_local_address        |                 %% |  X  |    |
        param_listener_stats                |                 %% |  X  |    |
        param_listener_cibir_id.                              %% |     | X  |

-type conn_settings() :: [{conn_settings_key(), non_neg_integer()}].
-type conn_settings_key() ::
        max_bytes_per_key                  |
        handshake_idle_timeout_ms          |
        idle_timeout_ms                    |
        tls_client_max_send_buffer         |
        tls_server_max_send_buffer         |
        stream_recv_window_default         |
        stream_recv_buffer_default         |
        conn_flow_control_window           |
        max_worker_queue_delay_us          |
        max_stateless_operations           |
        initial_window_packets             |
        send_idle_timeout_ms               |
        initial_rtt_ms                     |
        max_ack_delay_ms                   |
        disconnect_timeout_ms              |
        keep_alive_interval_ms             |
        peer_bidi_stream_count             |
        peer_unidi_stream_count            |
        retry_memory_limit                 |
        load_balancing_mode                |
        max_operations_per_drain           |
        send_buffering_enabled             |
        pacing_enabled                     |
        migration_enabled                  |
        datagram_receive_enabled           |
        server_resumption_level            |
        version_negotiation_ext_enabled    |
        desired_versions_list              |
        desired_versions_list_length.

-type execution_profile() ::
        quic_execution_profile_low_latency |
        quic_execution_profile_max_throughput |
        quic_execution_profile_scavenger |
        quic_execution_profile_real_time.

%% Connection Event Props
-type new_conn_props() :: #{ version      := integer()
                           , local_addr   := string()
                           , remote_addr  := string()
                           , server_name  := binary()
                           , alpns        := binary()
                           , client_alpns := binary()
                           , crypto_buffer:= binary()
                           }.

-type connected_props() :: #{ is_resumed := boolean()
                            , alpns := string() | undefined
                            }.

-type conn_closed_props() :: #{ is_handshake_completed := boolean()
                              , is_peer_acked := boolean()
                              , is_app_closing := boolean()
                              }.

-type transport_shutdown_props() :: #{ is_conn_shutdown := boolean()
                                     , is_app_closing := boolean()
                                     , is_shutdown_by_app := boolean()
                                     , is_closed_remotely := boolean()
                                     , status := atom_reason()
                                     , error := error_code()
                                     }.

%% Stream Event Props
-type stream_start_completed_props() :: #{ status := atom()
                                         , stream_id := integer()
                                         , is_peer_accepted := boolean()
                                         }.
-type stream_closed_props() :: map().

-type peer_accepted_props() :: #{ is_conn_shutdown := boolean()
                                , is_app_closing := boolean()
                                , is_shutdown_by_app := boolean()
                                , is_closed_remotely := boolean()
                                , status := atom_reason()
                                , error := error_code()
                                }.

-type recv_data_props() :: #{ absolute_offset := integer()
                            , len := integer()
                            , flags := integer()
                            }.

%% @doc QUIC Application error code, not protocol error code.
%% The app error code will be passed to the peer while shutdown the connection.
%% 0 means no error
-type app_error() :: non_neg_integer().


-type error_code() :: non_neg_integer().

%% @doc addr in quicer, IP and Port
-type quicer_addr() :: string().

%% @doc quic_data fragment with offset index
-type ifrag() :: {Index::non_neg_integer(), quic_data()}.


-type quic_data_buffer() :: ordsets:ordset(ifrag()).

%% @doc future packet buffer
-type fpbuffer() :: #{ next_offset := non_neg_integer()
                     , buffer := quic_data_buffer()
                     }.

%% @doc binary data with offset and size info
-type quic_data() :: #quic_data{}.

-type datagram_send_state() :: ?QUIC_DATAGRAM_SEND_UNKNOWN %% Not sent yet
                             | ?QUIC_DATAGRAM_SEND_SENT    %% Sent but not acked yet
                             | ?QUIC_DATAGRAM_SEND_LOST_SUSPECT %% Suspected lost but still tracked
                             | ?QUIC_DATAGRAM_SEND_LOST_DISCARDED %% Lost and no longer tracked
                             | ?QUIC_DATAGRAM_SEND_ACKNOWLEDGED   %% Acknowledged
                             | ?QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS %% Acknowledged after being suspected lost
                             | ?QUIC_DATAGRAM_SEND_CANCELED.             %% Send cancelled

-type dgram_state() :: #{ dgram_send_enabled := boolean()
                        , dgram_max_len := uint64()
                        }.

-endif. %% QUICER_TYPES_HRL
