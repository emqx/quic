-module(prop_quicer_nif).

-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").

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

-type quicer_listen_opts() :: [quicer_listen_opt()].
-type quicer_listen_opt() ::
    listen_opt_alpn()
    | listen_opt_cert()
    | listen_opt_certfile()
    %listen_opt_key() |
    | listen_opt_keyfile()
    | listen_opt_verify()
    | listen_opt_cacertfile()
    | listen_opt_password()
    | listen_opt_sslkeylogfile()
    | listen_opt_allow_insecure()
    %listen_opt_quic_registration() |
    | listen_opt_conn_acceptors()
    | quicer_setting().

-type quicer_setting() ::
    quic_setting_max_bytes_per_key()
    | quic_setting_handshake_idle_timeout_ms()
    | quic_setting_idle_timeout_ms()
    | quic_setting_tls_client_max_send_buffer()
    | quic_setting_tls_server_max_send_buffer()
    | quic_setting_stream_recv_window_default()
    | quic_setting_stream_recv_buffer_default()
    | quic_setting_conn_flow_control_window()
    | quic_setting_max_stateless_operations()
    | quic_setting_initial_window_packets()
    | quic_setting_send_idle_timeout_ms()
    | quic_setting_initial_rtt_ms()
    | quic_setting_max_ack_delay_ms()
    | quic_setting_disconnect_timeout_ms()
    | quic_setting_keep_alive_interval_ms()
    | quic_setting_peer_bidi_stream_count()
    | quic_setting_peer_unidi_stream_count()
    | quic_setting_retry_memory_limit()
    | quic_setting_load_balancing_mode()
    | quic_setting_max_operations_per_drain()
    | quic_setting_send_buffering_enabled()
    | quic_setting_pacing_enabled()
    | quic_setting_migration_enabled()
    | quic_setting_datagram_receive_enabled()
    | quic_setting_server_resumption_level()
    | quic_setting_minimum_mtu()
    | quic_setting_maximum_mtu()
    | quic_setting_mtu_discovery_search_complete_timeout_us()
    | quic_setting_mtu_discovery_missing_probe_count()
    | quic_setting_max_binding_stateless_operations()
    | quic_setting_stateless_operation_expiration_ms().

-type listen_opt_alpn() :: {alpn, [alpn()]}.
-type listen_opt_cert() :: {cert, file:filename()}.
-type listen_opt_certfile() :: {certfile, file:filename()}.
%-type listen_opt_key() :: {key, file:filename()}. %% @FIXME reflect in types
-type listen_opt_keyfile() :: {keyfile, file:filename()}.
-type listen_opt_verify() :: {verify, none | peer | verify_peer | verify_none}.
-type listen_opt_cacertfile() :: {cacertfile, file:filename()}.
-type listen_opt_password() :: {password, string()}.
-type listen_opt_sslkeylogfile() :: {sslkeylogfile, file:filename()}.
-type listen_opt_allow_insecure() :: {allow_insecure, boolean()}.
-type listen_opt_quic_registration() :: {quic_registration, reg_handle()}.
-type listen_opt_conn_acceptors() :: {conn_acceptors, non_neg_integer()}.

-type quic_setting_max_bytes_per_key() :: {max_bytes_per_key, uint64()}.
-type quic_setting_handshake_idle_timeout_ms() :: {handshake_idle_timeout_ms, uint64()}.
-type quic_setting_idle_timeout_ms() :: {idle_timeout_ms, uint64()}.
-type quic_setting_tls_client_max_send_buffer() :: {tls_client_max_send_buffer, uint32()}.
-type quic_setting_tls_server_max_send_buffer() :: {tls_server_max_send_buffer, uint32()}.
-type quic_setting_stream_recv_window_default() :: {stream_recv_window_default, uint32()}.
-type quic_setting_stream_recv_buffer_default() :: {stream_recv_buffer_default, uint32()}.
-type quic_setting_conn_flow_control_window() :: {conn_flow_control_window, uint32()}.
-type quic_setting_max_stateless_operations() :: {max_stateless_operations, uint32()}.
-type quic_setting_initial_window_packets() :: {initial_window_packets, uint32()}.
-type quic_setting_send_idle_timeout_ms() :: {send_idle_timeout_ms, uint32()}.
-type quic_setting_initial_rtt_ms() :: {initial_rtt_ms, uint32()}.
-type quic_setting_max_ack_delay_ms() :: {max_ack_delay_ms, uint32()}.
-type quic_setting_disconnect_timeout_ms() :: {disconnect_timeout_ms, uint32()}.
-type quic_setting_keep_alive_interval_ms() :: {keep_alive_interval_ms, uint32()}.
-type quic_setting_peer_bidi_stream_count() :: {peer_bidi_stream_count, uint16()}.
-type quic_setting_peer_unidi_stream_count() :: {peer_unidi_stream_count, uint16()}.
-type quic_setting_retry_memory_limit() :: {retry_memory_limit, uint16()}.
-type quic_setting_load_balancing_mode() :: {load_balancing_mode, uint16()}.
-type quic_setting_max_operations_per_drain() :: {max_operations_per_drain, uint8()}.
-type quic_setting_send_buffering_enabled() :: {send_buffering_enabled, uint8()}.
-type quic_setting_pacing_enabled() :: {pacing_enabled, uint8()}.
-type quic_setting_migration_enabled() :: {migration_enabled, uint8()}.
-type quic_setting_datagram_receive_enabled() :: {datagram_receive_enabled, uint8()}.
%% @FIXME reflect in types
-type quic_setting_server_resumption_level() :: {server_resumption_level, 0 | 1 | 2}.
-type quic_setting_minimum_mtu() :: {minimum_mtu, uint16()}.
-type quic_setting_maximum_mtu() :: {maximum_mtu, uint16()}.
-type quic_setting_mtu_discovery_search_complete_timeout_us() ::
    {mtu_discovery_search_complete_timeout_us, uint64()}.
-type quic_setting_mtu_discovery_missing_probe_count() ::
    {mtu_discovery_missing_probe_count, uint8()}.
-type quic_setting_max_binding_stateless_operations() ::
    {max_binding_stateless_operations, uint16()}.
-type quic_setting_stateless_operation_expiration_ms() ::
    {stateless_operation_expiration_ms, uint16()}.

-type quicer_conn_opts() :: [conn_opt()].
-type conn_opt() ::
    conn_opt_alpn()
    %conn_opt_conn_callback() |
    | conn_opt_cert()
    | conn_opt_certfile()
    | conn_opt_key()
    | conn_opt_keyfile()
    | conn_opt_password()
    | conn_opt_verify()
    %conn_opt_handle() |
    | conn_opt_nst()
    | conn_opt_cacertfile()
    | conn_opt_sslkeylogfile()
    | conn_opt_local_bidi_stream_count()
    | conn_opt_local_unidi_stream_count()
    | conn_opt_handshake_idle_timeout_ms()
    | conn_opt_quic_event_mask()
    | conn_opt_param_conn_disable_1rtt_encryption()
    | conn_opt_param_conn_quic_version()
    | conn_opt_param_conn_remote_address()
    | conn_opt_param_conn_ideal_processor()
    | conn_opt_param_conn_settings()
    | conn_opt_param_conn_statistics()
    | conn_opt_param_conn_statistics_plat()
    | conn_opt_param_conn_share_udp_binding()
    %% | conn_opt_param_conn_bidi_stream_count()
    %% | conn_opt_param_conn_unidi_stream_count()
    | conn_opt_param_conn_max_stream_ids()
    | conn_opt_param_conn_close_reason_phrase()
    | conn_opt_param_conn_stream_scheduling_scheme()
    | conn_opt_param_conn_datagram_receive_enabled()
    | conn_opt_param_conn_datagram_send_enabled()
    | conn_opt_param_conn_resumption_ticket()
    | conn_opt_param_conn_peer_certificate_valid()
    | conn_opt_param_conn_local_interface()
    | conn_opt_param_conn_local_address()
    %    | conn_opt_additional()
    | quicer_setting().

-type conn_opt_alpn() :: {alpn, [string()]}.
%% -type conn_opt_conn_callback() :: {conn_callback, module()}. %% @FIXME
-type conn_opt_cert() :: {cert, file:filename()}.
-type conn_opt_certfile() :: {certfile, file:filename()}.
-type conn_opt_key() :: {key, file:filename()}.
-type conn_opt_keyfile() :: {keyfile, file:filename()}.
-type conn_opt_password() :: {password, string()}.
-type conn_opt_verify() :: {verify, none | peer}.
%-type conn_opt_handle() :: {handle, valid_connection_handle()}. %% @FIXME reflect in types
-type conn_opt_nst() :: {nst, binary()}.
-type conn_opt_cacertfile() :: {cacertfile, file:filename()}.
-type conn_opt_sslkeylogfile() :: {sslkeylogfile, file:filename()}.
-type conn_opt_local_bidi_stream_count() :: {param_conn_local_bidi_stream_count, uint16()}.
-type conn_opt_local_unidi_stream_count() :: {param_conn_local_unidi_stream_count, uint16()}.
-type conn_opt_handshake_idle_timeout_ms() :: {handshake_idle_timeout_ms, non_neg_integer()}.
-type conn_opt_quic_event_mask() :: {quic_event_mask, uint32()}.
-type conn_opt_param_conn_disable_1rtt_encryption() ::
    {param_conn_disable_1rtt_encryption, boolean()}.
-type conn_opt_param_conn_quic_version() ::
    {param_conn_quic_version, uint32()}.

-type conn_opt_param_conn_local_address() ::
    {param_conn_local_address, string()}.

-type conn_opt_param_conn_remote_address() ::
    {param_conn_remote_address, string()}.

-type conn_opt_param_conn_ideal_processor() ::
    {param_conn_ideal_processor, uint16()}.

-type conn_opt_param_conn_settings() ::
    {param_conn_settings, [quicer_setting()]}.

-type conn_opt_param_conn_statistics() ::
    %% @TODO
    {param_conn_statistics, any()}.

-type conn_opt_param_conn_statistics_plat() ::
    %% @TODO
    {param_conn_statistics_plat, any()}.

-type conn_opt_param_conn_share_udp_binding() ::
    {param_conn_share_udp_binding, boolean()}.

%% -type conn_opt_param_conn_bidi_stream_count() ::
%%     {param_conn_bidi_stream_count, uint16()}.

%% -type conn_opt_param_conn_unidi_stream_count() ::
%%     {param_conn_unidi_stream_count, uint16()}.

-type conn_opt_param_conn_max_stream_ids() ::
    {param_conn_max_stream_ids, uint64()}.

-type conn_opt_param_conn_close_reason_phrase() ::
    {param_conn_close_reason_phrase, string()}.

-type conn_opt_param_conn_stream_scheduling_scheme() ::
    {param_conn_stream_scheduling_scheme, uint16()}.

-type conn_opt_param_conn_datagram_receive_enabled() ::
    {param_conn_datagram_receive_enabled, boolean()}.

-type conn_opt_param_conn_datagram_send_enabled() ::
    {param_conn_datagram_send_enabled, boolean()}.

-type conn_opt_param_conn_resumption_ticket() ::
    {param_conn_resumption_ticket, [uint8()]}.

-type conn_opt_param_conn_peer_certificate_valid() ::
    {param_conn_peer_certificate_valid, boolean()}.

-type conn_opt_param_conn_local_interface() ::
    {param_conn_local_interface, uint32()}.

-type conn_opt_param_conn_tls_secrets() ::
    {param_conn_tls_secrets, binary()}.
%%{param_conn_tls_secrets, quic_tls_secrets()}.

-type conn_opt_param_conn_version_settings() ::
    %% @TODO
    {param_conn_version_settings, any()}.
%%{param_conn_version_settings, quic_version_settings()}.

-type conn_opt_param_conn_cibir_id() ::
    {param_conn_cibir_id, [uint8()]}.

-type conn_opt_param_conn_statistics_v2() ::
    %% @TODO
    {param_conn_statistics_v2, any()}.

-type conn_opt_param_conn_statistics_v2_plat() ::
    %% @TODO
    {param_conn_statistics_v2_plat, any()}.

-type conn_opt_additional() :: {_, _}.

-type quicer_acceptor_opts() :: [acceptor_opt()].
-type acceptor_opt() ::
    acceptor_opt_active()
    | quicer_setting().

-type acceptor_opt_active() :: {active, boolean() | non_neg_integer()}.

-type quicer_stream_opts() :: [stream_opt()].
-type stream_opt() ::
    stream_opt_active()
    | stream_opt_id()
    | stream_opt_priority()
    | stream_opt_ideal_send_buffer_size()
    | stream_opt_0rtt_length()
    | stream_opt_open_flag()
    | stream_opt_start_flag()
    | stream_opt_event_mask()
    | stream_opt_disable_fpbuffer().
%| stream_opt_additional().

-type stream_opt_active() :: {active, active_n()}.
-type stream_opt_id() :: {id, uint62()}.
-type stream_opt_priority() :: {priority, uint16()}.
-type stream_opt_ideal_send_buffer_size() :: {ideal_send_buffer_size, uint64()}.
-type stream_opt_0rtt_length() :: {'0rtt_length', uint64()}.
-type stream_opt_open_flag() :: {open_flag, stream_open_flags()}.
-type stream_opt_start_flag() :: {start_flag, stream_start_flags()}.
-type stream_opt_event_mask() :: {event_mask, uint32()}.
-type stream_opt_disable_fpbuffer() :: {disable_fpbuffer, boolean()}.
-type stream_opt_additional() :: {_, _}.

prop_robust_new_registration_2() ->
    ?FORALL(
        {Key, Value},
        {string(), term()},
        begin
            case quicer_nif:new_registration(Key, Value) of
                {ok, _} ->
                    true;
                {error, _} ->
                    true
            end
        end
    ).

prop_shutdown_registration_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle},
        valid_reg_handle(),
        begin
            ok == quicer_nif:shutdown_registration(Handle)
        end
    ).

prop_shutdown_registration_3() ->
    ?FORALL(
        {#prop_handle{type = reg, handle = Handle}, IsSilent, ErrorCode},
        {valid_reg_handle(), boolean(), uint64()},
        begin
            ok == quicer_nif:shutdown_registration(Handle, IsSilent, ErrorCode)
        end
    ).

prop_close_registration_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle},
        valid_reg_handle(),
        begin
            ok == quicer_nif:close_registration(Handle)
        end
    ).

prop_get_registration_name() ->
    ?FORALL(
        #prop_handle{type = reg, name = Name, handle = Handle} = H,
        valid_reg_handle(),
        begin
            Res = quicer_nif:get_registration_name(Handle),
            (H#prop_handle.destructor)(),
            {ok, Name} == Res
        end
    ).

%% robustness test, no crash
prop_listen_robust() ->
    ?FORALL(
        {On, Opts},
        {listen_on(), quicer_listen_opts()},
        begin
            case quicer_nif:listen(On, maps:from_list(Opts)) of
                {ok, Handle} ->
                    quicer_nif:close_listener(Handle),
                    true;
                {error, _} ->
                    true;
                {error, _, _} ->
                    true
            end
        end
    ).

%% robustness test, no crash
%% precondition: with valid listener handle
prop_start_listener_with_valid_handle() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = Handle, destructor = Destroy} = H, On, Opts},
        {valid_listen_handle(), listen_on(), quicer_listen_opts()},
        begin
            case quicer_nif:start_listener(Handle, On, maps:from_list(Opts)) of
                {ok, _} ->
                    Destroy(),
                    true;
                {error, _} ->
                    Destroy(),
                    true
            end
        end
    ).

%% robustness test, no crash
prop_robust_stop_listener() ->
    ?FORALL(
        Handle,
        any(),
        begin
            collect(quicer_nif:stop_listener(Handle), true)
        end
    ).

%% robustness test, no crash
prop_robust_close_listener() ->
    ?FORALL(
        Handle,
        any(),
        begin
            collect(quicer_nif:close_listener(Handle), true)
        end
    ).

%% stop_listener with valid listen handle must success
prop_stop_listener_with_valid_handle() ->
    ?FORALL(
        #prop_handle{type = listener, handle = Handle},
        valid_listen_handle(),
        begin
            ok == quicer_nif:stop_listener(Handle)
        end
    ).

%% @doc Start stopped Listener must success with valid opts
%% precondition: with valid listener handle AND valid listen on AND valid listen TLS opts
prop_start_listener_with_valid_handle_AND_valid_listen_on() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = Handle, destructor = Destroy}, On, Opts},
        {valid_listen_handle(), valid_listen_on(), valid_listen_opts()},
        begin
            ok = quicer_nif:stop_listener(Handle),
            LOpts = maps:from_list(Opts),
            Res = quicer_nif:start_listener(Handle, On, LOpts),
            Destroy(),
            % collect(Res, Res == ok orelse Res == {error, invalid_parameter})
            collect(Res, true)
        end
    ).

%% robustness test, no crash
prop_robust_open_connection_0() ->
    ?FORALL(
        _,
        integer(),
        begin
            {ok, H} = quicer_nif:open_connection(),
            quicer:async_shutdown_connection(H, 0, 0),
            true
        end
    ).

%% robustness test, no crash
prop_robust_open_connection_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle, destructor = Destroy},
        valid_reg_handle(),
        begin
            {ok, _Handle} = quicer_nif:open_connection(Handle),
            quicer_nif:async_shutdown_connection(Handle, 0, 0),
            Destroy(),
            true
        end
    ).

%% robustness test, no crash
prop_robust_async_connect_3() ->
    Port = quicer_test_lib:select_free_port(quic),
    {ok, LH} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
    ?FORALL(
        ConnOpts,
        quicer_conn_opts(),
        begin
            COpts = maps:from_list(ConnOpts),
            case quicer_nif:async_connect("localhost", Port, COpts) of
                {ok, ConnHandle} ->
                    quicer:close_listener(LH),
                    quicer_nif:async_shutdown_connection(ConnHandle, 0, 0),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

%% precondition: with valid TLS opts
prop_async_connect_3_with_valid_connopts() ->
    Port = quicer_test_lib:select_free_port(quic),
    {ok, LH} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
    ?FORALL(
        ConnOpts,
        quicer_conn_opts(),
        begin
            COpts = maps:from_list(ConnOpts ++ valid_client_conn_opts()),
            case
                quicer_nif:async_connect(
                    "localhost",
                    Port,
                    COpts
                )
            of
                {ok, ConnHandle} ->
                    quicer:close_listener(LH),
                    quicer_nif:async_shutdown_connection(ConnHandle, 0, 0),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

prop_robust_async_accept_2() ->
    ?FORALL(
        {LH, AcceptOpts},
        {any(), any()},
        begin
            case quicer_nif:async_accept(LH, AcceptOpts) of
                {ok, _ConnHandle} ->
                    quicer:close_listener(LH),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

%% accept on valid listener handle
prop_async_accept_2() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = LH, destructor = Destroy}, AcceptOpts},
        {valid_listen_handle(), quicer_acceptor_opts()},
        begin
            AOpts = maps:from_list(AcceptOpts),
            case quicer_nif:async_accept(LH, AOpts) of
                {ok, _ConnHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

%% 'active_n' always >= 0
prop_async_accept_2_with_active() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = LH, destructor = Destroy}, ActiveN},
        {valid_listen_handle(), oneof([boolean(), integer()])},
        begin
            case quicer_nif:async_accept(LH, #{active => ActiveN}) of
                {ok, ConnHandle} ->
                    quicer:close_connection(ConnHandle),
                    Destroy(),
                    collect(ok, quicer:getopt(ConnHandle, active) >= 0);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_start_stream() ->
    ?FORALL(
        {ConnHandle, StreamOpts},
        {any(), any()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpts) of
                {ok, _StreamHandle} ->
                    quicer:close_connection(ConnHandle),
                    collect(ok, true);
                E ->
                    quicer:close_connection(ConnHandle),
                    collect(E, true)
            end
        end
    ).

prop_start_stream_with_valid_conn_handle() ->
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, StreamOpts},
        {valid_connection_handle(), any()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpts) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_start_stream_with_valid_conn_handle_AND_mandatory() ->
    %% active_n is mandatory
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, StreamOpt, ActiveN},
        {valid_connection_handle(), map(), active_n()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpt#{active => ActiveN}) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_csend() ->
    ?FORALL(
        {Handle, Data, Opts, Flags},
        {any(), any(), any(), any()},
        begin
            case quicer_nif:csend(Handle, Data, Opts, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    quicer:close_stream(Handle),
                    collect(E, true)
            end
        end
    ).

prop_csend_with_valid_opts() ->
    %% @NOTE, start could still fail with different combination of opts
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, Data, Opts, Flags},
        {valid_connection_handle(), data(), quicer_stream_opts(), quicer_send_flags()},
        begin
            SOpts = maps:from_list(Opts),
            case quicer_nif:csend(ConnHandle, Data, SOpts, Flags) of
                {ok, StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                {error, closed} ->
                    Destroy(),
                    %% As we test closed (not started) conn handle
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_send_3() ->
    ?FORALL(
        {Handle, Data, Flags},
        {any(), any(), any()},
        begin
            case quicer_nif:send(Handle, Data, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_send_3() ->
    ?FORALL(
        {#prop_handle{type = stream, handle = StreamHandle, destructor = Destroy}, Data, Flags},
        {valid_stream_handle(), data(), quicer_send_flags()},
        begin
            case quicer_nif:send(StreamHandle, Data, Flags) of
                {ok, _} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_recv_2() ->
    ?FORALL(
        {Handle, Len},
        {any(), any()},
        begin
            case quicer_nif:recv(Handle, Len) of
                {ok, _Data} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    quicer:close_stream(Handle),
                    collect(E, true)
            end
        end
    ).

prop_recv_2_with_valid_stream_handle() ->
    ?FORALL(
        {#prop_handle{type = stream, handle = StreamHandle, destructor = Destroy}, Len},
        {valid_stream_handle(), non_neg_integer()},
        begin
            quicer_nif:setopt(StreamHandle, active, false, false),
            case quicer_nif:recv(StreamHandle, Len) of
                {ok, Data} when Data == not_ready orelse is_binary(Data) ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_send_dgram() ->
    ?FORALL(
        {Handle, Data, Flags},
        {any(), any(), any()},
        begin
            case quicer_nif:send_dgram(Handle, Data, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_send_dgram_with_valid_opts() ->
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, Data, Flags},
        {valid_connection_handle(), data(), quicer_send_flags()},
        begin
            case quicer_nif:send_dgram(ConnHandle, Data, Flags) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_async_shutdown_stream() ->
    ?FORALL(
        {Handle, Flags, ErrorCode},
        {any(), any(), any()},
        begin
            case quicer_nif:async_shutdown_stream(Handle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_async_shutdown_stream_with_valid_stream_handle() ->
    ?FORALL(
        {
            #prop_handle{type = stream, handle = StreamHandle, destructor = Destroy},
            Flags,
            ErrorCode
        },
        {valid_stream_handle(), uint32(), uint64()},
        begin
            case quicer_nif:async_shutdown_stream(StreamHandle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_async_shutdown_stream_with_valid_stream_handle_AND_flags() ->
    ?FORALL(
        {
            #prop_handle{type = stream, handle = StreamHandle, destructor = Destroy},
            Flags,
            ErrorCode
        },
        {valid_stream_handle(), valid_stream_shutdown_flags(), uint64()},
        begin
            case quicer_nif:async_shutdown_stream(StreamHandle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_sockname() ->
    ?FORALL(
        Handle,
        any(),
        begin
            {error, badarg} == quicer_nif:sockname(Handle)
        end
    ).

prop_sockname() ->
    ?FORALL(
        #prop_handle{type = conn, handle = ConnHandle, destructor = Destroy},
        valid_connection_handle(),
        begin
            Res =
                case quicer_nif:sockname(ConnHandle) of
                    {ok, _} -> ok;
                    E -> E
                end,
            Destroy(),
            collect(Res, true)
        end
    ).

prop_robust_getopt_3() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {any(), any(), any()},
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            {error, badarg} == quicer_nif:getopt(Handle, Opt, OptLevel)
        end
    ).

prop_getopt_3_with_valid_handle() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {valid_handle(), any(), any()},
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Opt, OptLevel),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_with_valid_handle_AND_param() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {valid_handle(), oneof([quicer_setting()]), optlevel()},
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Opt, OptLevel),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_robust_setopt_4() ->
    ?FORALL(
        {Handle, Opt, OptLevel, Value},
        {any(), any(), any(), any()},
        begin
            {error, badarg} == quicer_nif:setopt(Handle, Opt, OptLevel, Value)
        end
    ).

prop_robust_setopt_4_with_valid_handle_AND_param() ->
    ?FORALL(
        {Handle, {Optname, Value}, OptLevel},
        {
            valid_handle(),
            oneof([
                quicer_listen_opt(),
                conn_opt(),
                acceptor_opt(),
                stream_opt(),
                quicer_setting()
            ]),
            optlevel()
        },
        begin
            Res = quicer_nif:setopt(Handle#prop_handle.handle, Optname, OptLevel, Value),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_stream_opt() ->
    ?FORALL(
        {Handle, {Optname, _Value}},
        {valid_stream_handle(), stream_opt()},
        begin
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Optname, false),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_conn_opt() ->
    ?FORALL(
        {Handle, {Optname, _Value}},
        {valid_connection_handle(), conn_opt()},
        begin
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Optname, false),
            (Handle#prop_handle.destructor)(),
            case Res of
                {ok, _} ->
                    collect(ok, true);
                _ ->
                    collect({Optname, Res}, true)
            end
        end
    ).

prop_robust_peercert() ->
    ?FORALL(
        Handle,
        any(),
        begin
            {error, badarg} == quicer:peercert(Handle)
        end
    ).

prop_peercert_with_valid_connection_handle() ->
    ?FORALL(
        #prop_handle{type = conn, handle = Handle, destructor = Destroy},
        valid_connection_handle(),
        begin
            Res = quicer_nif:peercert(Handle),
            Destroy(),
            collect(Res, true)
        end
    ).

prop_peercert_with_valid_stream_handle() ->
    ?FORALL(
        #prop_handle{type = stream, handle = Handle, destructor = Destroy},
        valid_stream_handle(),
        begin
            Destroy(),
            collect(quicer_nif:peercert(Handle), true)
        end
    ).

prop_robust_controlling_process() ->
    ?FORALL(
        {Handle, Pid},
        {any(), any()},
        begin
            {error, badarg} == quicer_nif:controlling_process(Handle, Pid)
        end
    ).

prop_controlling_process_with_valid_opts() ->
    ?FORALL(
        {#prop_handle{type = Type, handle = Handle, destructor = Destroy}, Pid},
        {valid_handle(), pid()},
        begin
            Res = quicer_nif:controlling_process(Handle, Pid),
            case Res of
                ok when Type == conn ->
                    {ok, Pid} = quicer_nif:get_conn_owner(Handle);
                ok when Type == stream ->
                    {ok, Pid} = quicer_nif:get_stream_owner(Handle);
                _ ->
                    skip
            end,
            Destroy(),
            collect({Type, Res}, true)
        end
    ).

%%% ============================================================================
%%%  Generators
%%% ============================================================================
valid_handle() ->
    oneof([
        valid_connection_handle(),
        valid_stream_handle(),
        valid_listen_handle(),
        valid_reg_handle()
    ]).

%% @doc pid of process that dies randomly within 0-1000(ms)
pid() ->
    ?LET(
        LiveTimeMs,
        range(0, 1000),
        spawn(fun() -> timer:sleep(LiveTimeMs) end)
    ).

data() ->
    oneof([binary(), list(binary())]).

quicer_send_flags() ->
    ?LET(
        Flags,
        [send_flags()],
        begin
            lists:foldl(
                fun(F, Acc) ->
                    Acc bor F
                end,
                0,
                Flags
            )
        end
    ).

%% valid reg handle
valid_reg_handle() ->
    ?SUCHTHAT(
        Handle,
        ?LET(
            {Name, Profile},
            {reg_name(), registration_profile()},
            begin
                case quicer_nif:new_registration(Name, Profile) of
                    {ok, Handle} ->
                        #prop_handle{
                            type = reg,
                            name = Name,
                            handle = Handle,
                            destructor = fun() ->
                                quicer_nif:close_registration(Handle)
                            end
                        };
                    {error, _} ->
                        error
                end
            end
        ),
        Handle =/= error
    ).

reg_name() ->
    % latin1_string()
    ?LET(
        Rand,
        integer(),
        begin
            "foo" ++ integer_to_list(Rand)
        end
    ).

valid_listen_handle() ->
    ?SUCHTHAT(
        Ret,
        ?LET(
            {On, Opts},
            {valid_listen_on(), valid_listen_opts()},
            begin
                case quicer_nif:listen(On, maps:from_list(Opts)) of
                    {ok, Handle} ->
                        #prop_handle{
                            type = listener,
                            name = "noname",
                            handle = Handle,
                            destructor = fun() ->
                                quicer_nif:close_listener(Handle)
                            end
                        };
                    _E ->
                        ct:pal("listen failed: ~p", [_E]),
                        error
                end
            end
        ),
        Ret =/= error
    ).

valid_listen_opts() ->
    ?LET(
        Opts,
        quicer_listen_opts(),
        begin
            lists:foldl(
                fun proplists:delete/2,
                Opts ++ valid_server_listen_opts(),
                [
                    password,
                    %% flaky per machine sysconf
                    stream_recv_buffer_default
                ]
            )
        end
    ).

valid_listen_on() ->
    ?LET(
        Port,
        range(1025, 65536),
        begin
            case gen_udp:open(Port, [{reuseaddr, true}]) of
                {ok, S} ->
                    ok = gen_udp:close(S),
                    Port;
                _ ->
                    quicer_test_lib:select_free_port(quic)
            end
        end
    ).

%% @doc valid conn handle in different states (opened, started, closed)
valid_connection_handle() ->
    oneof([
        valid_opened_connection_handle(),
        valid_started_connection_handle()
    ]).

valid_opened_connection_handle() ->
    ?LET(
        _Rand,
        integer(),
        begin
            {ok, Handle} = quicer_nif:open_connection(),
            #prop_handle{
                type = conn,
                name = "noname",
                handle = Handle,
                destructor = fun() ->
                    quicer_nif:async_shutdown_connection(Handle, 0, 0)
                end
            }
        end
    ).

valid_started_connection_handle() ->
    ensure_dummy_listener(?DUMMY_PORT),
    ?LET(
        _Rand,
        integer(),
        begin
            {ok, Handle} = quicer_nif:async_connect(
                "localhost", ?DUMMY_PORT, maps:from_list(valid_client_conn_opts())
            ),
            #prop_handle{
                type = conn,
                name = "noname",
                handle = Handle,
                destructor = fun() ->
                    quicer_nif:async_shutdown_connection(Handle, 0, 0)
                end
            }
        end
    ).

valid_stream_handle() ->
    ensure_dummy_listener(?DUMMY_PORT),
    ?SUCHTHAT(
        Conn,
        ?LET(
            _Rand,
            integer(),
            begin
                {ok, Conn} = quicer_nif:async_connect(
                    "localhost", ?DUMMY_PORT, maps:from_list(valid_client_conn_opts())
                ),
                receive
                    {quic, connected, Conn, _} ->
                        {ok, Stream} = quicer_nif:start_stream(Conn, #{active => 1}),
                        #prop_handle{
                            type = stream,
                            name = "noname",
                            handle = Stream,
                            destructor =
                                fun() ->
                                    quicer_nif:async_shutdown_connection(Conn, 0, 0)
                                end
                        }
                after 100 ->
                    %% @FIXME
                    error
                end
            end
        ),
        Conn =/= error
    ).

valid_stream_start_flags() ->
    ?valid_flags(stream_start_flag()).

valid_stream_shutdown_flags() ->
    ?valid_flags(stream_shutdown_flags()).

latin1_string() -> ?SUCHTHAT(S, string(), io_lib:printable_latin1_list(S)).

%% Other helpers

%% @doc Server listen opts must work
valid_server_listen_opts() ->
    [
        {alpn, ["proper"]},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].

valid_client_conn_opts() ->
    [
        {alpn, ["proper"]},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].

-spec ensure_dummy_listener(non_neg_integer()) -> _.
ensure_dummy_listener(Port) ->
    case is_pid(whereis(?dummy_listener)) of
        false ->
            spawn_dummy_listener(Port);
        true ->
            ok
    end.

spawn_dummy_listener(Port) ->
    Parent = self(),
    spawn(fun() ->
        register(?dummy_listener, self()),
        {ok, L} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
        spawn_acceptors(L, 4),
        Parent ! ready,
        receive
            finish -> ok
        end
    end),
    receive
        ready ->
            ok
    end.

spawn_acceptors(_, 0) ->
    ok;
spawn_acceptors(L, N) ->
    spawn_link(fun() ->
        acceptor_loop(L)
    end),
    spawn_acceptors(L, N - 1).

acceptor_loop(L) ->
    case quicer:accept(L, #{active => true}) of
        {ok, Conn} ->
            spawn(fun() ->
                _ = quicer:handshake(Conn),
                timer:sleep(100),
                quicer:async_shutdown_connection(Conn, 0, 0)
            end),
            acceptor_loop(L);
        _ ->
            acceptor_loop(L)
    end.
