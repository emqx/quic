%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-type user_opts() :: #{_ => _}.

%% Msquic Status Code Translation
-type atom_reason() ::
    success
    | pending
    | continue
    | out_of_memory
    | invalid_parameter
    | invalid_state
    | not_supported
    | not_found
    | buffer_too_small
    | handshake_failure
    | aborted
    | address_in_use
    | connection_timeout
    | connection_idle
    | internal_error
    | connection_refused
    | protocol_error
    | ver_neg_error
    | unreachable
    | tls_error
    | user_canceled
    | alpn_neg_failure
    | stream_limit_reached.

-type app_errno() :: non_neg_integer().
-type hostname() :: string().

-type listener_handle() :: reference().
-type connection_handle() :: reference().
-type stream_handle() :: reference().
-type conf_handle() :: reference().
-type reg_handle() :: reference().
-type global_handle() :: quic_global.

-type handle() ::
    global_handle()
    | listener_handle()
    | connection_handle()
    | stream_handle()
    | conf_handle()
    | reg_handle().

-type registration_profile() :: execution_profile().
-type quic_handle_level() :: quic_tls | quic_configuration | false.

-type listen_on() :: inet:port_number() | string().
-type listen_opts() :: listen_security_opts() | quic_settings().
-type listen_security_opts() :: #{
    alpn := [alpn()],
    cert := file:filename(),
    certfile := file:filename(),
    key := file:filename(),
    keyfile := file:filename(),
    verify => none | peer | verify_peer | verify_none,
    cacertfile => file:filename(),
    password => string(),
    sslkeylogfile => file:filename(),
    allow_insecure => boolean(),
    quic_registration => reg_handle(),
    conn_acceptors => non_neg_integer()
}.

-type uint64() :: 0..?MASK(64).
-type uint62() :: 0..?MASK(62).
-type uint32() :: 0..?MASK(32).
-type uint16() :: 0..?MASK(16).
-type uint8() :: 0..?MASK(8).

-type quic_settings() :: #{
    max_bytes_per_key => uint64(),
    handshake_idle_timeout_ms => uint64(),
    idle_timeout_ms => uint64(),
    %% for client only
    tls_client_max_send_buffer => uint32(),
    %% for server only
    tls_server_max_send_buffer => uint32(),
    stream_recv_window_default => uint32(),
    stream_recv_buffer_default => uint32(),
    conn_flow_control_window => uint32(),
    %, max_worker_queue_delay_us => uint32()
    max_stateless_operations => uint32(),
    initial_window_packets => uint32(),
    send_idle_timeout_ms => uint32(),
    initial_rtt_ms => uint32(),
    max_ack_delay_ms => uint32(),
    disconnect_timeout_ms => uint32(),
    keep_alive_interval_ms => uint32(),
    congestion_control_algorithm => uint16(),
    peer_bidi_stream_count => uint16(),
    peer_unidi_stream_count => uint16(),
    retry_memory_limit => uint16(),
    load_balancing_mode => uint16(),
    max_operations_per_drain => uint8(),
    send_buffering_enabled => uint8(),
    pacing_enabled => uint8(),
    migration_enabled => uint8(),
    datagram_receive_enabled => uint8(),
    server_resumption_level => uint8(),
    %  internal, not exposed
    %, version_negotiation_ext_enabled => uint8()
    minimum_mtu => uint16(),
    maximum_mtu => uint16(),
    mtu_discovery_search_complete_timeout_us => uint64(),
    mtu_discovery_missing_probe_count => uint8(),
    max_binding_stateless_operations => uint16(),
    stateless_operation_expiration_ms => uint16()
}.
-type alpn() :: string().

-type conn_opts() ::
    quic_settings()
    | #{
        alpn := [string()],
        conn_callback => module(),
        cert => file:filename(),
        certfile => file:filename(),
        key => file:filename(),
        keyfile => file:filename(),
        password => string(),
        verify => none | peer,
        %% get NST from last connection, for reconnect.
        handle => connection_handle(),
        nst => binary(),
        cacertfile => file:filename(),
        sslkeylogfile => file:filename(),
        handshake_idle_timeout_ms => non_neg_integer(),
        quic_event_mask => uint32(),
        disable_1rtt_encryption => boolean(),
        %% Not working well
        local_address => string(),
        local_bidi_stream_count => uint16(),
        local_peer_unidi_stream_count => uint16(),
        %% for Application defined options
        _ => _
    }.
-type conn_shutdown_flag() ::
    ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE
    | ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT.

-type acceptor_opts() :: quic_settings() | #{active => boolean()}.

-type active_n() :: boolean() | once | integer().

-type stream_opts() :: #{
    active := active_n(),
    open_flag => stream_open_flags(),
    start_flag => stream_start_flags(),
    event_mask => uint32(),
    disable_fpbuffer => boolean(),
    stream_id => uint62(),
    priority => uint16(),
    ideal_send_buffer_size => uint64(),
    '0rtt_length' => uint64(),
    %% for Application defined options
    _ => _
    %% @TODO expand
}.

-type stream_open_flags() ::
    ?QUIC_STREAM_OPEN_FLAG_NONE
    %% Open unidirectional stream
    | ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL
    %% The stream is opened via a 0-RTT packet
    | ?QUIC_STREAM_OPEN_FLAG_0_RTT.
-type stream_start_flags() ::
    ?QUIC_STREAM_START_FLAG_NONE
    %% Immediately informs peer that stream is open
    | ?QUIC_STREAM_START_FLAG_IMMEDIATE
    %% If number of streams is rate limited, notify with event start_completed with status 'stream_limit_reached'
    | ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED
    %% Shutdown the stream immediately after start failure
    | ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL
    %% Indicate PEER_ACCEPTED event if not accepted at start
    | ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT.

-type stream_shutdown_flags() ::
    %% **Invalid** option for `StreamShutdown`
    ?QUIC_STREAM_SHUTDOWN_FLAG_NONE
    %% Gracefully shutdown the stream
    | ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL
    %% Abortively shutdown the sending side of the stream
    | ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND
    %% Abortively shutdown the sending side of the stream
    | ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE
    %% Abortively shutdown both sending and receiveing side of the stream
    | ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT
    %% Don't wait for ack from peer, must be used with abortive shutdown
    | ?QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE.

%% is sync send or not
-type send_flags() ::
    csend_flags() | ?QUICER_SEND_FLAG_SYNC.

-type csend_flags() ::
    ?QUIC_SEND_FLAG_NONE
    | ?QUIC_SEND_FLAG_ALLOW_0_RTT
    | ?QUIC_SEND_FLAG_START
    | ?QUIC_SEND_FLAG_FIN
    | ?QUIC_SEND_FLAG_DGRAM_PRIORITY
    | ?QUIC_SEND_FLAG_DELAY_SEND.

-type stream_start_flag() ::
    ?QUIC_STREAM_START_FLAG_NONE
    | ?QUIC_STREAM_START_FLAG_IMMEDIATE
    | ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED
    | ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL
    | ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT.

-type new_stream_props() :: #{
    is_orphan := boolean(),
    flags := stream_open_flags()
}.

-type streams_available_props() :: #{
    unidi_streams := non_neg_integer(),
    bidi_streams := non_neg_integer()
}.

-type send_complete_flag() ::
    ?QUIC_SEND_COMPLETE_SUCCESS
    | ?QUIC_SEND_COMPLETE_CANCELLED.

%% unspecified
-type optlevel() ::
    false
    | quic_global
    | quic_registration
    | quic_configuration
    | quic_tls.

-type optname() ::
    optname_global()
    | optname_listener()
    | optname_conn()
    | optname_stream()
    | optname_reg()
    | optname_configuration()
    | optname_tls().

%% === | GET | SET| === %%

%% with connection_handle()
-type optname_conn() ::
    %% /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */|
    %% |  X  |    |
    quic_version
    %% |  X  |    |
    | local_address
    %% |  X  |  X | @TODO SET
    | remote_address
    %% |  X  |    |
    | ideal_processor
    %% |  X  |  X |
    | settings
    %% |  X  |    |
    | statistics
    %% |  X  |    | @TODO
    | statistics_plat
    %% |  X  |  X |
    | share_udp_binding
    %% |  X  |    |
    | local_bidi_stream_count
    %% |  X  |    |
    | local_unidi_stream_count
    %% |  X  |    |
    | max_stream_ids
    %% |  X  |  X |
    | close_reason_phrase
    %% |  X  |  X |
    | stream_scheduling_scheme
    %% |  X  |  X |
    | datagram_receive_enabled
    %% |  X  |    |
    | datagram_send_enabled
    %% |  X  |  X |
    | disable_1rtt_encryption
    %% |     |  X |
    | resumption_ticket
    %% |     |  X |
    | peer_certificate_valid
    %% |     |  X |
    | local_interface.

%% with connection_handle()
-type optname_tls() ::
    %% |  X  |    |
    schannel_context_attribute_w
    %% |  X  |    |
    | handshake_info
    %% |  X  |    |
    | negotiated_alpn.

-type optname_stream() ::
    %% |  X  |  X |
    active
    %% |     |  X |
    | controlling_process
    %% |     |  X |
    | stream_id
    %% |  X  |    |
    | '0rtt_length'
    %% |  X  |    |
    | ideal_send_buffer_size
    %% |     |    |
    | priority.

%% with `undefined' handle
-type optname_global() ::
    %% |  X  | X  |
    retry_memory_percent
    %% |  X  |    | @TODO
    | supported_versions
    %% |  X  | X  |
    | load_balacing_mode
    %% |  X  |    |
    | perf_counters
    %% |  X  | X  |
    | global_settings
    %% |  X  |    | @TODO
    | global_version.

%% |  X  | X  | @TODO
-type optname_reg() :: cid_prefix.

%% with config_handle()
-type optname_configuration() ::
    %% |  X  | X  |
    settings
    %% |     | X  | @TODO
    | ticket_keys.

%% with listener_handle
-type optname_listener() ::
    %% |  X  |    |
    local_address
    %% |  X  |    |
    | stats
    %% |     | X  |
    | cibir_id.

-type conn_settings() :: [{conn_settings_key(), non_neg_integer()}].
-type conn_settings_key() ::
    max_bytes_per_key
    | handshake_idle_timeout_ms
    | idle_timeout_ms
    | tls_client_max_send_buffer
    | tls_server_max_send_buffer
    | stream_recv_window_default
    | stream_recv_buffer_default
    | conn_flow_control_window
    | max_worker_queue_delay_us
    | max_stateless_operations
    | initial_window_packets
    | send_idle_timeout_ms
    | initial_rtt_ms
    | max_ack_delay_ms
    | disconnect_timeout_ms
    | keep_alive_interval_ms
    | peer_bidi_stream_count
    | peer_unidi_stream_count
    | retry_memory_limit
    | load_balancing_mode
    | max_operations_per_drain
    | send_buffering_enabled
    | pacing_enabled
    | migration_enabled
    | datagram_receive_enabled
    | server_resumption_level
    | version_negotiation_ext_enabled
    | desired_versions_list
    | desired_versions_list_length.

-type execution_profile() ::
    quic_execution_profile_low_latency
    | quic_execution_profile_max_throughput
    | quic_execution_profile_scavenger
    | quic_execution_profile_real_time.

%% Connection Event Props
-type new_conn_props() :: #{
    version := integer(),
    local_addr := string(),
    remote_addr := string(),
    server_name := binary(),
    alpns := binary(),
    client_alpns := binary(),
    crypto_buffer := binary()
}.

-type connected_props() :: #{
    is_resumed := boolean(),
    alpns := string() | undefined
}.

-type conn_closed_props() :: #{
    is_handshake_completed := boolean(),
    is_peer_acked := boolean(),
    is_app_closing := boolean()
}.

-type transport_shutdown_props() :: #{
    is_conn_shutdown := boolean(),
    is_app_closing := boolean(),
    is_shutdown_by_app := boolean(),
    is_closed_remotely := boolean(),
    status := atom_reason(),
    error := error_code()
}.

%% Stream Event Props
-type stream_start_completed_props() :: #{
    status := atom(),
    stream_id := integer(),
    is_peer_accepted := boolean()
}.
-type stream_closed_props() :: map().

-type peer_accepted_props() :: #{
    is_conn_shutdown := boolean(),
    is_app_closing := boolean(),
    is_shutdown_by_app := boolean(),
    is_closed_remotely := boolean(),
    status := atom_reason(),
    error := error_code()
}.

-type recv_data_props() :: #{
    absolute_offset := integer(),
    len := integer(),
    flags := integer()
}.

%% @doc QUIC Application error code, not protocol error code.
%% The app error code will be passed to the peer while shutdown the connection.
%% 0 means no error
-type app_error() :: non_neg_integer().

-type error_code() :: non_neg_integer().

%% @doc addr in quicer, IP and Port
-type quicer_addr() :: string().

%% @doc quic_data fragment with offset index
-type ifrag() :: {Index :: non_neg_integer(), quic_data()}.

-type quic_data_buffer() :: ordsets:ordset(ifrag()).

%% @doc future packet buffer
-type fpbuffer() :: #{
    next_offset := non_neg_integer(),
    buffer := quic_data_buffer()
}.

%% @doc binary data with offset and size info
-type quic_data() :: #quic_data{}.

%% Not sent yet
-type datagram_send_state() ::
    ?QUIC_DATAGRAM_SEND_UNKNOWN
    %% Sent but not acked yet
    | ?QUIC_DATAGRAM_SEND_SENT
    %% Suspected lost but still tracked
    | ?QUIC_DATAGRAM_SEND_LOST_SUSPECT
    %% Lost and no longer tracked
    | ?QUIC_DATAGRAM_SEND_LOST_DISCARDED
    %% Acknowledged
    | ?QUIC_DATAGRAM_SEND_ACKNOWLEDGED
    %% Acknowledged after being suspected lost
    | ?QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS
    %% Send cancelled
    | ?QUIC_DATAGRAM_SEND_CANCELED.

-type dgram_state() :: #{
    dgram_send_enabled := boolean(),
    dgram_max_len := uint64()
}.

%% QUICER_TYPES_HRL
-endif.
