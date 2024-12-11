%%--------------------------------------------------------------------
%% Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-record(prop_handle, {
    type :: reg | listen | conn | stream,
    name :: string(),
    handle :: reference(),
    destructor :: fun()
}).

-define(dummy_listener, dummy_listener).
-define(DUMMY_PORT, 14567).

-define(valid_flags(FlagType),
    (?SUCHTHAT(
        Flag,
        ?LET(
            Flags,
            [FlagType],
            begin
                lists:foldl(
                    fun(F, Acc) ->
                        Acc bor F
                    end,
                    0,
                    Flags
                )
            end
        ),
        Flag =/= 0
    ))
).

-type quicer_listen_opts() :: [listen_opt()].

-type listen_opt() ::
    {alpn, [alpn()]}
    | {cert, file:filename()}
    | {certfile, file:filename()}
    %-| {key, file:filename()}. %% @FIXME reflect in types
    | {keyfile, file:filename()}
    | {verify, none | peer | verify_peer | verify_none}
    | {cacertfile, file:filename()}
    | {password, string()}
    | {sslkeylogfile, file:filename()}
    | {allow_insecure, boolean()}
    %-| {quic_registration, reg_handle()}
    | {conn_acceptors, non_neg_integer()}
    | {settings, [quicer_setting()]}.

-define(UINT32_MAX, 4294967295).
-type quicer_setting() ::
    {max_bytes_per_key, uint64()}
    | {handshake_idle_timeout_ms, uint64()}
    | {idle_timeout_ms, uint64()}
    | {tls_client_max_send_buffer, uint32()}
    | {tls_server_max_send_buffer, uint32()}
    | {stream_recv_window_default, uint32()}
    | {stream_recv_buffer_default, uint32()}
    | {conn_flow_control_window, uint32()}
    | {max_stateless_operations, uint32()}
    | {initial_window_packets, uint32()}
    | {send_idle_timeout_ms, uint32()}
    | {initial_rtt_ms, uint32()}
    | {max_ack_delay_ms, uint32()}
    | {disconnect_timeout_ms, uint32()}
    | {keep_alive_interval_ms, uint32()}
    | {congestion_control_algorithm, uint16()}
    | {peer_bidi_stream_count, uint16()}
    | {peer_unidi_stream_count, uint16()}
    | {retry_memory_limit, uint16()}
    | {load_balancing_mode, uint16()}
    | {max_operations_per_drain, uint8()}
    | {send_buffering_enabled, uint8()}
    | {pacing_enabled, uint8()}
    | {migration_enabled, uint8()}
    | {datagram_receive_enabled, uint8()}
    | {server_resumption_level, 0 | 1 | 2}
    | {minimum_mtu, uint16()}
    | {maximum_mtu, uint16()}
    | {mtu_discovery_search_complete_timeout_us, uint64()}
    | {mtu_discovery_missing_probe_count, uint8()}
    | {max_binding_stateless_operations, uint16()}
    | {stateless_operation_expiration_ms, uint16()}.

%% happy quicer_settings that msquic won't return invalid_param
-type quicer_setting_with_range() ::
    {max_bytes_per_key, 0..(4 bsl 34 - 1)}
    | {handshake_idle_timeout_ms, 0..(1 bsl 62 - 1)}
    | {idle_timeout_ms, 0..(1 bsl 62 - 1)}
    | {tls_client_max_send_buffer, uint32()}
    | {tls_server_max_send_buffer, uint32()}
    | {stream_recv_window_default, 1..?UINT32_MAX}
    | {stream_recv_buffer_default, 4096..?UINT32_MAX}
    | {conn_flow_control_window, uint32()}
    | {max_stateless_operations, 1..16}
    | {initial_window_packets, uint32()}
    | {send_idle_timeout_ms, uint32()}
    | {initial_rtt_ms, 1..?UINT32_MAX}
    | {max_ack_delay_ms, 1..(1 bsl 14 - 1)}
    | {disconnect_timeout_ms, 1..600000}
    | {keep_alive_interval_ms, uint32()}
    | {congestion_control_algorithm, 0 | 1}
    | {peer_bidi_stream_count, uint16()}
    | {peer_unidi_stream_count, uint16()}
    | {retry_memory_limit, uint16()}
    | {load_balancing_mode, 0..2}
    | {max_operations_per_drain, uint8()}
    | {send_buffering_enabled, 0 | 1}
    | {pacing_enabled, 0 | 1}
    | {migration_enabled, 0 | 1}
    | {datagram_receive_enabled, 0 | 1}
    | {server_resumption_level, 0 | 1 | 2}
    | {minimum_mtu, uint16()}
    | {maximum_mtu, uint16()}
    | {mtu_discovery_search_complete_timeout_us, uint64()}
    | {mtu_discovery_missing_probe_count, uint8()}
    | {max_binding_stateless_operations, uint16()}
    | {stateless_operation_expiration_ms, 10..(1 bsl 16 - 1)}.

-type quicer_conn_opts() :: [conn_opt()].
-type conn_opt() ::
    {alpn, [string()]}
    | {certfile, file:filename()}
    | {keyfile, file:filename()}
    | {password, string()}
    | {verify, none | peer}
    | {nst, binary()}
    | {cacertfile, file:filename()}
    | {sslkeylogfile, file:filename()}
    | {local_bidi_stream_count, uint16()}
    | {local_unidi_stream_count, uint16()}
    | {handshake_idle_timeout_ms, non_neg_integer()}
    | {quic_event_mask, uint32()}
    | {disable_1rtt_encryption, boolean()}
    | {quic_version, uint32()}
    | {local_address, string()}
    | {remote_address, string()}
    | {ideal_processor, uint16()}
    | {settings, [quicer_setting()]}
    % @TODO
    | {statistics, any()}
    % @TODO
    | {statistics_plat, any()}
    | {share_udp_binding, boolean()}
    | {max_stream_ids, uint64()}
    | {close_reason_phrase, string()}
    | {stream_scheduling_scheme, uint16()}
    | {datagram_receive_enabled, boolean()}
    | {datagram_send_enabled, boolean()}
    | {resumption_ticket, [uint8()]}
    | {peer_certificate_valid, boolean()}
    | {local_interface, uint32()}
    % @TODO
    | {tls_secrets, binary()}
    % @TODO
    | {version_settings, any()}
    | {cibir_id, [uint8()]}
    % @TODO
    | {statistics_v2, any()}
    % @TODO
    | {statistics_v2_plat, any()}.

-type quicer_acceptor_opts() :: [acceptor_opt()].
-type acceptor_opt() ::
    {active, active_n()}
    | quicer_setting().

-type quicer_stream_opts() :: [stream_opt()].
-type stream_opt() ::
    {active, active_n()}
    | {stream_id, uint62()}
    | {priority, uint16()}
    | {ideal_send_buffer_size, uint64()}
    | {'0rtt_length', uint64()}
    | {open_flag, stream_open_flags()}
    | {start_flag, stream_start_flags()}
    | {event_mask, uint32()}
    | {disable_fpbuffer, boolean()}.

-type stream_accept_opts() :: [{active, boolean()}].
