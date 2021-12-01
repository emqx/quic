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

-type listener_handler()   :: reference().
-type connection_handler() :: reference().
-type stream_handler()     :: reference().
-type conf_handler()       :: reference().
-type reg_handler()        :: reference().
-type global_handler()     :: quic_global.

-type handler() ::
        global_handler()     |
        listener_handler()   |
        connection_handler() |
        stream_handler()     |
        conf_handler()       |
        reg_handler().

-type listen_on() :: inet:port_number() | string().
-type listen_opts() :: map(). %% @TODO expand

-type conn_opts() :: map(). %% @TODO expand
-type conn_close_flag() :: ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE |
                           ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT.
-type acceptor_opts() :: map(). %% @TODO expand

-type stream_opts() :: map(). %% @TODO expand
-type stream_close_flags() :: ?QUIC_STREAM_SHUTDOWN_FLAG_NONE |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE. %% @TODO add xor

-type send_flags() :: non_neg_integer(). %% is sync send or not

-type optlevel() :: false | %% unspecified
                    quic_global |
                    quic_registration |
                    quic_configuration |
                    quic_tls.

-type optname() ::
        optname_global()        |
        optname_conn()          |
        optname_stream()        |
        optname_reg()           |
        optname_configuration() |
        optname_tls().
                                                              %% | GET | SET|
-type optname_conn() ::   %% with connection_handler()
        %% /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */|
        param_conn_quic_version                   |           %% |  X  |    |
        param_conn_local_address                  |           %% |  X  |    | @TODO
        param_conn_remote_address                 |           %% |  X  |  X | @TODO SET
        param_conn_ideal_processor                |           %% |  X  |    | @TODO
        param_conn_settings                       |           %% |  X  |  X |
        param_conn_statistics                     |           %% |  X  |    |
        param_conn_statistics_plat                |           %% |  X  |    | @TODO
        param_conn_share_udp_binding              |           %% |  X  |  X | @TODO
        param_conn_local_bidi_stream_count        |           %% |  X  |    | @TODO
        param_conn_local_unidi_stream_count       |           %% |  X  |    | @TODO
        param_conn_max_stream_ids                 |           %% |  X  |    | @TODO
        param_conn_close_reason_phrase            |           %% |  X  |  X | @TODO
        param_conn_stream_scheduling_scheme       |           %% |  X  |  X | @TODO
        param_conn_datagram_receive_enabled       |           %% |  X  |  X | @TODO
        param_conn_datagram_send_enabled          |           %% |  X  |    | @TODO
        param_conn_disable_1rtt_encryption        |           %% |  X  |  X | @TODO
        param_conn_resumption_ticket              |           %% |     |  X | @TODO
        param_conn_peer_certificate_valid         |           %% |     |  X | @TODO
        param_conn_local_interface.                           %% |     |  X | @TODO

-type optname_tls()   ::  %% with connection_handler()
        param_tls_schannel_context_attribute_w    |           %% |  X  |    | @TODO
        param_tls_handshake_info                  |           %% |  X  |  X | @TODO
        param_tls_negotiated_alpn.                            %% |  X  |    | @TODO

-type optname_stream() ::
        active                                    |           %% |  X  |  X | @TODO GET
        controlling_process                       |           %% |     |    | @TODO GET SET
        param_stream_id                           |           %% |     |  X |
        param_stream_0rtt_length                  |           %% |  X  |    | @TODO
        param_stream_ideal_send_buffer_size       |           %% |  X  |    | @TODO
        param_stream_priority.                                %% |     |    |

-type optname_global() ::                                     %% with `undefined' handler
        param_global_retry_memory_percent |                   %% |  X  | X  | @TODO
        param_global_supported_versions   |                   %% |  X  |    | @TODO
        param_global_load_balacing_mode   |                   %% |  X  | X  | @TODO
        param_global_perf_counters        |                   %% |  X  |    | @TODO
        param_global_settings             |                   %% |  X  | X  | @TODO
        param_global_version.                                 %% |  X  |    | @TODO

-type optname_reg() :: param_registration_cid_prefix.         %% |  X  | X  | @TODO

-type optname_configuration() ::                              %% with config_handler()
        param_configuration_settings        |                 %% |  X  | X  | @TODO
        param_configuration_ticket_keys.                      %% |     | X  | @TODO

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

-endif. %% QUICER_TYPES_HRL
