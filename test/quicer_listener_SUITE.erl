%%--------------------------------------------------------------------
%% Copyright (c) 2023-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(quicer_listener_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").

-include_lib("quicer/include/quicer.hrl").

-compile(export_all).
-compile(nowarn_export_all).

-import(quicer_test_lib, [
    default_listen_opts/1,
    default_conn_opts/0,
    default_stream_opts/0,
    select_free_port/1
]).

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
    [{timetrap, {seconds, 30}}].

%%--------------------------------------------------------------------
%% @spec init_per_suite(Config0) ->
%%     Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    application:ensure_all_started(quicer),
    quicer_test_lib:generate_tls_certs(Config),
    Config.

%%--------------------------------------------------------------------
%% @spec end_per_suite(Config0) -> term() | {save_config,Config1}
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
    ok.

%%--------------------------------------------------------------------
%% @spec init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_group(global_reg, Config) ->
    Config;
init_per_group(suite_reg, Config) ->
    {ok, SReg} = quicer:new_registration(
        atom_to_list(?MODULE),
        quic_execution_profile_max_throughput
    ),
    [{quic_registration, SReg} | Config].

%%--------------------------------------------------------------------
%% @spec end_per_group(GroupName, Config0) ->
%%               term() | {save_config,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
end_per_group(suite_reg, Config) ->
    Reg = proplists:get_value(quic_registration, Config),
    quicer:shutdown_registration(Reg),
    ok = quicer:close_registration(Reg);
end_per_group(_GroupName, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% @spec init_per_testcase(TestCase, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% TestCase = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_testcase(tc_listener_conf_reload_listen_on_neg, Config) ->
    case os:type() of
        {unix, darwin} -> {skip, "Not runnable on MacOS"};
        _ -> Config
    end;
init_per_testcase(_TestCase, Config) ->
    application:ensure_all_started(quicer),
    quicer_test_lib:cleanup_msquic(),
    Config.

%%--------------------------------------------------------------------
%% @spec end_per_testcase(TestCase, Config0) ->
%%               term() | {save_config,Config1} | {fail,Reason}
%% TestCase = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, Config) ->
    RegH = proplists:get_value(quic_registration, Config, global),
    [quicer:close_listener(L, 1000) || L <- quicer:get_listeners(RegH)],
    quicer_test_lib:report_active_connections(),
    ok.

%%--------------------------------------------------------------------
%% @spec groups() -> [Group]
%% Group = {GroupName,Properties,GroupsAndTestCases}
%% GroupName = atom()
%% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
%% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
%% TestCase = atom()
%% Shuffle = shuffle | {shuffle,{integer(),integer(),integer()}}
%% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
%%              repeat_until_any_ok | repeat_until_any_fail
%% N = integer() | forever
%% @end
%%--------------------------------------------------------------------
groups() ->
    TCs = quicer_test_lib:all_tcs(?MODULE),
    [
        {global_reg, [], TCs},
        {suite_reg, [], TCs}
    ].

%%--------------------------------------------------------------------
%% @spec all() -> GroupsAndTestCases | {skip,Reason}
%% GroupsAndTestCases = [{group,GroupName} | TestCase]
%% GroupName = atom()
%% TestCase = atom()
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        {group, global_reg},
        {group, suite_reg}
    ].

%%--------------------------------------------------------------------
%% @spec TestCase() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
%% my_test_case() ->
%%     [].

%%--------------------------------------------------------------------
%% @spec TestCase(Config0) ->
%%               ok | exit() | {skip,Reason} | {comment,Comment} |
%%               {save_config,Config1} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% Comment = term()
%% @end
%%--------------------------------------------------------------------
tc_open_listener_neg_1(Config) ->
    {error, badarg} = quicer:listen(undefined, default_listen_opts(Config)),
    ok.

tc_open_listener_neg_2(Config) ->
    {error, badarg} = quicer:listen("localhost:4567", default_listen_opts(Config)),
    %% following test should fail, but msquic has some hack to let it pass, ref: MsQuicListenerStart in msquic listener.c
    %% {error, badarg} = quicer:listen("8.8.8.8:4567", default_listen_opts(Config)),
    ok.

tc_open_listener_inval_parm(Config) ->
    Port = select_port(),
    ?assertEqual(
        {error, config_error, invalid_parameter},
        % too small
        quicer:listen(Port, [
            {stream_recv_buffer_default, 1024}
            | default_listen_opts(Config)
        ])
    ),
    ok.

tc_open_listener_inval_cacertfile_1(Config) ->
    Port = select_port(),
    ?assertEqual(
        {error, cacertfile},
        quicer:listen(Port, [
            {cacertfile, atom}
            | default_listen_opts(Config)
        ])
    ),
    ok.

tc_open_listener_inval_cacertfile_2(Config) ->
    Port = select_port(),
    ?assertEqual(
        {error, cacertfile},
        quicer:listen(Port, [
            {cacertfile, <<"1,2,3,4">>}
            | default_listen_opts(Config)
        ])
    ),
    ok.

tc_open_listener_inval_cacertfile_3(Config) ->
    Port = select_port(),
    ?assertEqual(
        {error, cacertfile},
        quicer:listen(Port, [
            {cacertfile, [-1]}
            | default_listen_opts(Config)
        ])
    ),
    ok.

tc_open_listener(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    {ok, {_, Port}} = quicer:sockname(L),
    {error, eaddrinuse} = gen_udp:open(Port),
    ok = quicer:close_listener(L),
    {ok, P} = snabbkaffe:retry(100, 10, fun() -> {ok, _} = gen_udp:open(Port) end),
    ok = gen_udp:close(P),
    ok.

tc_open_listener_with_inval_reg(Config) ->
    Port = select_port(),
    Config1 = proplists:delete(quic_registration, Config),
    %% Given invalid  registration
    Reg = erlang:make_ref(),
    %% When try to listen with the invalid registration
    Res = quicer:listen(Port, default_listen_opts([{quic_registration, Reg} | Config1])),
    %% Then it shall fail to listen and proper error is returned
    ?assertEqual({error, quic_registration}, Res),
    ok.

tc_open_listener_with_new_reg(Config) ->
    Port = select_port(),
    %% Given New registration is created
    {ok, Reg} = quicer:new_registration(
        atom_to_list(?MODULE), quic_execution_profile_max_throughput
    ),
    %% When Listener is created with the New Registration
    {ok, L} = quicer:listen(Port, default_listen_opts([{quic_registration, Reg} | Config])),
    {ok, {_, Port}} = quicer:sockname(L),
    %% Then Listener is created successfully and port is occupied
    {error, eaddrinuse} = gen_udp:open(Port),
    ok = quicer:close_listener(L),
    {ok, P} = snabbkaffe:retry(100, 10, fun() -> {ok, _} = gen_udp:open(Port) end),
    ok = gen_udp:close(P),
    ok = quicer:shutdown_registration(Reg),
    ok.

tc_open_listener_with_cert_password(Config) ->
    Port = select_port(),
    DataDir = ?config(data_dir, Config),
    PasswordCerts = [
        {certfile, filename:join(DataDir, "server-password.pem")},
        {keyfile, filename:join(DataDir, "server-password.key")},
        {password, quicer_test_lib:tls_server_key_password()}
    ],
    {ok, L} = quicer:listen(Port, default_listen_opts(PasswordCerts ++ Config)),
    quicer:close_listener(L),
    ok.

tc_open_listener_with_wrong_cert_password(Config) ->
    Port = select_port(),
    DataDir = ?config(data_dir, Config),
    PasswordCerts = [
        {certfile, filename:join(DataDir, "server-password.pem")},
        {keyfile, filename:join(DataDir, "server-password.key")},
        {password, "123"}
    ],
    ?assertMatch(
        {error, config_error, tls_error},
        quicer:listen(Port, default_listen_opts(PasswordCerts ++ Config))
    ).

tc_open_listener_bind(Config) ->
    Port = select_port(),
    ListenOn = "127.0.0.1" ++ ":" ++ integer_to_list(Port),
    {ok, L} = quicer:listen(ListenOn, default_listen_opts(Config)),
    {ok, {_, _}} = quicer:sockname(L),
    {error, eaddrinuse} = gen_udp:open(Port),
    ok = quicer:close_listener(L),
    {ok, P} = snabbkaffe:retry(100, 10, fun() -> {ok, _} = gen_udp:open(Port) end),
    ok = gen_udp:close(P),
    ok.

tc_open_listener_bind_v6(Config) ->
    Port = select_port(),
    ListenOn = "[::1]" ++ ":" ++ integer_to_list(Port),
    {ok, L} = quicer:listen(ListenOn, default_listen_opts(Config)),
    {ok, {_, _}} = quicer:sockname(L),
    {error, eaddrinuse} = gen_udp:open(Port, [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]),
    ok = quicer:close_listener(L),
    {ok, P} = snabbkaffe:retry(100, 10, fun() ->
        {ok, _} = gen_udp:open(Port, [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}])
    end),
    ok = gen_udp:close(P),
    ok.

tc_set_listener_opt(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    %% must start with 0
    Val = <<0, 1, 2, 3, 4, 5>>,
    ok = quicer:setopt(L, cibir_id, Val),
    {error, not_supported} = quicer:getopt(L, cibir_id),
    quicer:close_listener(L).

tc_set_listener_opt_fail(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    {error, _} = quicer:setopt(L, cibir_id, <<1, 2, 3, 4, 5, 6>>),
    {error, not_supported} = quicer:getopt(L, cibir_id),
    quicer:close_listener(L).

tc_get_listener_opt_addr(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    {ok, {{0, 0, 0, 0}, Port}} = quicer:getopt(L, local_address),
    quicer:close_listener(L).

tc_get_listener_opt_stats(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    {ok, [
        {"total_accepted_connection", _},
        {"total_rejected_connection", _},
        {"binding_recv_dropped_packets", _}
    ]} = quicer:getopt(L, stats),
    quicer:close_listener(L).

tc_close_listener(_Config) ->
    {error, badarg} = quicer:close_listener(make_ref()).

tc_close_listener_twice(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    ok = quicer:close_listener(L),
    %% follow OTP behavior, already closed
    ok = quicer:close_listener(L).

tc_close_listener_dealloc(Config) ->
    Port = select_port(),
    {Pid, Ref} = spawn_monitor(fun() ->
        {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
        exit(L)
    end),
    receive
        {'DOWN', Ref, process, Pid, L} ->
            quicer:close_listener(L)
    end.

tc_stop_start_listener(Config) ->
    Port = select_port(),
    LConf = default_listen_opts(Config),
    {ok, L} = quicer:listen(Port, LConf),
    ok = quicer:stop_listener(L),
    ?assertEqual({error, listener_stopped}, quicer:stop_listener(L)),
    ok = snabbkaffe:retry(100, 10, fun() -> ok = quicer:start_listener(L, Port, LConf) end),
    ok = quicer:close_listener(L).

tc_stop_start_listener_with_new_port(Config) ->
    Port = select_port(),
    LConf = default_listen_opts(Config),
    {ok, L} = quicer:listen(Port, LConf),
    ok = quicer:stop_listener(L),
    Port2 = select_port(),
    ok = snabbkaffe:retry(100, 10, fun() -> ok = quicer:start_listener(L, Port2, LConf) end),
    {ok, Sock1} = gen_udp:open(Port),
    ?assertMatch({error, eaddrinuse}, gen_udp:open(Port2)),
    gen_udp:close(Sock1),
    ok = quicer:close_listener(L).

tc_listener_lock(Config) ->
    process_flag(trap_exit, true),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 2}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 2}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},

    %% GIVEN: A QUIC connection between example client and example server
    {ok, QuicApp} = quicer:spawn_listener(sample, Port, Options),
    ClientConnOpts = default_conn_opts_verify(Config, ca),
    {ok, ClientConnPid} = example_client_connection:start_link(
        "localhost",
        Port,
        {ClientConnOpts, default_stream_opts()}
    ),

    %% ensure conn successfully established before lock
    #{is_resumed := false} = snabbkaffe:retry(
        50,
        20,
        fun() ->
            #{is_resumed := false} = quicer_connection:get_cb_state(ClientConnPid)
        end
    ),

    %% WHEN: the listener is locked
    ok = quicer_listener:lock(QuicApp, infinity),

    %% THEN: 1) new connection should be rejected
    ?assertMatch(
        {error, transport_down, #{error := 1, status := Status}} when
            connection_idle == Status orelse unreachable == Status,
        quicer:connect(
            "localhost",
            Port,
            default_conn_opts_verify(Config, 'ca'),
            2000
        )
    ),

    %% THEN: 2) existing client connection should be kept, and traffic still works
    Handle = quicer_connection:get_handle(ClientConnPid),
    ?assertMatch({ok, {_, Port}}, quicer:peername(Handle)),

    {ok, LocalStream} = quicer:async_csend(
        Handle,
        <<"hello_after_lock_listener">>,
        [{active, true}],
        %?QUIC_SEND_FLAG_NONE
        ?QUIC_SEND_FLAG_FIN
    ),
    receive
        {quic, <<"hello_after_lock_listener">>, LocalStream, _} ->
            ct:pal("Client received hello_after_lock_listener from ~p", [LocalStream]),
            ok
    end,

    gen_server:stop(ClientConnPid),
    quicer_listener:stop_listener(QuicApp),
    ok.

tc_listener_conf_reload(Config) ->
    process_flag(trap_exit, true),
    DataDir = ?config(data_dir, Config),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 1}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 2}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},

    %% Given a QUIC connection between example client and example server
    {ok, QuicApp} = quicer:spawn_listener(sample, Port, Options),
    ClientConnOpts = default_conn_opts_verify(Config, ca),
    {ok, ClientConnPid} = example_client_connection:start_link(
        "localhost",
        Port,
        {ClientConnOpts, default_stream_opts()}
    ),

    ct:pal("C1 status : ~p", [sys:get_status(ClientConnPid)]),
    {ok, LHandle} = quicer_listener:get_handle(QuicApp, 5000),

    %% WHEN: the listener is reloaded with new listener opts (New cert, key and cacert).
    ok = quicer_listener:lock(QuicApp, infinity),
    ok = quicer_listener:unlock(QuicApp, infinity),
    NewListenerOpts =
        ListenerOpts ++
            [
                {certfile, filename:join(DataDir, "other-server.pem")},
                {keyfile, filename:join(DataDir, "other-server.key")},
                {cacertfile, filename:join(DataDir, "other-ca.pem")}
            ],
    ok = quicer_listener:reload(QuicApp, NewListenerOpts),
    %% THEN: the listener handle is unchanged
    ?assertEqual({ok, LHandle}, quicer_listener:get_handle(QuicApp, 5000)),

    %% THEN: start new connection with old cacert must fail
    ?assertMatch(
        {error, transport_down, #{error := _, status := Status}} when
            Status =:= bad_certificate;
            Status =:= cert_untrusted_root;
            Status =:= handshake_failure,
        quicer:connect(
            "localhost",
            Port,
            default_conn_opts_verify(Config, 'ca'),
            5000
        )
    ),
    %% WHEN: start new connection with new cacert
    {ok, Conn2} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts_verify(Config, 'other-ca'),
        5000
    ),

    %% THEN: the new connection shall be established and traffic can be sent and received
    {ok, Stream2} = quicer:start_stream(
        Conn2,
        #{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ),
    {ok, _} = quicer:send(Stream2, <<"ping_from_conn_2">>),

    Stream2Remote =
        receive
            {quic, new_stream, Stream2R, #{is_orphan := true}} ->
                quicer:setopt(Stream2R, active, true),
                Stream2R
        end,

    receive
        {quic, <<"ping_from_conn_2">>, Stream2Remote, _} -> ok
    after 2000 ->
        quicer_test_lib:report_unhandled_messages(),
        ct:fail("nothing from conn 2")
    end,
    catch gen_server:stop(ClientConnPid),
    quicer_listener:stop_listener(QuicApp).

tc_listener_conf_reload_listen_on(Config) ->
    process_flag(trap_exit, true),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 1}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 2}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},

    %% Given a QUIC connection between example client and example server
    {ok, QuicApp} = quicer:spawn_listener(sample, Port, Options),
    ClientConnOpts = default_conn_opts_verify(Config, ca),
    {ok, ClientConnPid} = example_client_connection:start_link(
        "localhost",
        Port,
        {ClientConnOpts, default_stream_opts()}
    ),

    ct:pal("C1 status : ~p", [sys:get_status(ClientConnPid)]),
    {ok, LHandle} = quicer_listener:get_handle(QuicApp, 5000),

    %% WHEN: the listener is reloaded with ListenOn (new bind address)
    NewPort = select_port(),
    ok = quicer_listener:reload(QuicApp, NewPort, ListenerOpts),
    %% THEN: the listener handle is unchanged
    ?assertEqual({ok, LHandle}, quicer_listener:get_handle(QuicApp, 5000)),

    %% THEN: start new connection to old port
    ?assertMatch(
        {error, transport_down, #{error := _, status := _}},
        quicer:connect(
            "localhost",
            Port,
            default_conn_opts_verify(Config, 'ca'),
            1000
        )
    ),
    %% WHEN: start new connection to new port
    {ok, Conn2} = quicer:connect(
        "localhost",
        NewPort,
        default_conn_opts_verify(Config, 'ca'),
        5000
    ),

    %% THEN: the new connection shall be established and traffic can be sent and received
    {ok, Stream2} = quicer:start_stream(
        Conn2,
        #{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ),
    {ok, _} = quicer:send(Stream2, <<"ping_from_conn_2">>),

    Stream2Remote =
        receive
            {quic, new_stream, Stream2R, #{is_orphan := true}} ->
                quicer:setopt(Stream2R, active, true),
                Stream2R
        end,
    receive
        {quic, <<"ping_from_conn_2">>, Stream2Remote, _} -> ok
    after 2000 ->
        quicer_test_lib:report_unhandled_messages(),
        ct:fail("nothing from conn 2")
    end,
    gen_server:stop(ClientConnPid),
    quicer_listener:stop_listener(QuicApp).

tc_listener_conf_reload_listen_on_neg(Config) ->
    process_flag(trap_exit, true),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 1}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 2}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},

    %% Given a QUIC connection between example client and example server
    {ok, QuicApp} = quicer:spawn_listener(?FUNCTION_NAME, Port, Options),
    ClientConnOpts = default_conn_opts_verify(Config, ca),
    {ok, ClientConnPid} = example_client_connection:start_link(
        "localhost",
        Port,
        {ClientConnOpts, default_stream_opts()}
    ),

    ct:pal("C1 status : ~p", [sys:get_status(ClientConnPid)]),
    {ok, LHandle} = quicer_listener:get_handle(QuicApp, 5000),

    %% WHEN: the listener is reloaded with ListenOn (new invalid bind address)
    NewPort = 1,
    %% THEN: We get error
    {error, _, _} = quicer_listener:reload(QuicApp, NewPort, ListenerOpts),
    %% THEN: the listener handle is unchanged
    ?assertEqual({ok, LHandle}, quicer_listener:get_handle(QuicApp, 5000)),

    %% WHEN: we unlock it and start new connection
    ok = quicer_listener:unlock(QuicApp, 3000),

    %% THEN: the new connection shall be established with some reties
    %%       and traffic can be sent and received
    {ok, Conn2} =
        snabbkaffe:retry(
            300,
            10,
            fun() ->
                {ok, _} = quicer:connect(
                    "localhost",
                    Port,
                    default_conn_opts_verify(Config, 'ca'),
                    5000
                )
            end
        ),

    {ok, Stream2} = quicer:start_stream(
        Conn2,
        #{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ),
    {ok, _} = quicer:send(Stream2, <<"ping_from_conn_2">>),

    Stream2Remote =
        receive
            {quic, new_stream, Stream2R, #{is_orphan := true}} ->
                quicer:setopt(Stream2R, active, true),
                Stream2R
        end,

    receive
        {quic, <<"ping_from_conn_2">>, Stream2Remote, _} -> ok
    after 2000 ->
        quicer_test_lib:report_unhandled_messages(),
        ct:fail("nothing from conn 2")
    end,

    quicer_listener:stop_listener(QuicApp).

tc_stop_close_listener(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    ok = quicer:stop_listener(L),
    ok = quicer:close_listener(L, 0).

tc_start_listener_alpn_too_long(Config) ->
    Port = select_port(),
    {Pid, Ref} =
        spawn_monitor(fun() ->
            {error, config_error, invalid_parameter} =
                quicer:listen(
                    Port,
                    default_listen_opts(Config) ++
                        [{alpn, [lists:duplicate(256, $p)]}]
                )
        end),
    receive
        {'DOWN', Ref, process, Pid, normal} ->
            ok
    end.

tc_start_acceptor_without_callback(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    ?assertEqual(
        {error, missing_conn_callback},
        quicer_connection:start_link(undefined, L, {[], [], []}, self())
    ),
    quicer:close_listener(L).

tc_get_listeners(Config) ->
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Listeners = [
        {alpn1, "127.0.0.1:24567"},
        {alpn2, "0.0.0.1:24568"},
        {alpn3, 24569},
        {alpn4, "[::1]:24570"}
    ],
    Res = lists:map(
        fun({Alpn, ListenOn}) ->
            {ok, L} = quicer:spawn_listener(
                Alpn,
                ListenOn,
                {ListenerOpts, ConnectionOpts, StreamOpts}
            ),
            L
        end,
        Listeners
    ),
    ?assertEqual(
        lists:reverse(lists:zip(Listeners, Res)),
        quicer:listeners()
    ),
    lists:foreach(fun({L, _}) -> ok = quicer:terminate_listener(L) end, Listeners).

tc_get_listener(Config) ->
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Listeners = [
        {alpn1, "127.0.0.1:24567"},
        {alpn2, "0.0.0.1:24568"},
        {alpn3, 24569},
        {alpn4, "[::1]:24570"}
    ],
    lists:map(
        fun({Alpn, ListenOn}) ->
            {ok, L} = quicer:spawn_listener(
                Alpn,
                ListenOn,
                {ListenerOpts, ConnectionOpts, StreamOpts}
            ),
            L
        end,
        Listeners
    ),

    lists:foreach(
        fun({Name, _} = NameListenON) ->
            {ok, LPid} = quicer:listener(Name),
            {ok, LPid} = quicer:listener(NameListenON),
            true = is_process_alive(LPid)
        end,
        Listeners
    ),

    lists:foreach(fun({L, _}) -> ok = quicer:terminate_listener(L) end, Listeners),

    lists:foreach(
        fun({Name, _} = NameListenON) ->
            ?assertEqual({error, not_found}, quicer:listener(Name)),
            ?assertEqual({error, not_found}, quicer:listener(NameListenON))
        end,
        Listeners
    ),
    ?assertEqual({error, not_found}, quicer:listener(bad_listen_name)).

tc_listener_closed_when_owner_die_and_gc(Config) ->
    Port = select_port(),
    Me = self(),
    %% Given when port is occupied by another process
    {Pid, MRef} = spawn_monitor(fun() ->
        {ok, _L} = quicer:listen(Port, default_listen_opts(Config)),
        Me ! {started, self()},
        receive
            done -> ok
        end
    end),
    receive
        {started, Pid} -> ok
    end,
    {error, listener_start_error, {unknown_quic_status, Reason}} =
        quicer:listen(Port, default_listen_opts(Config)),
    ?assert(Reason == 91 orelse Reason == 41),

    Pid ! done,
    %% When the owner process dies
    receive
        {'DOWN', MRef, process, Pid, normal} ->
            ok
    end,
    %% Then port is released and new listener can be started
    {ok, L} = snabbkaffe:retry(
        10000,
        10,
        fun() ->
            {ok, _L0} = quicer:listen(Port, default_listen_opts(Config))
        end
    ),
    ok = quicer:close_listener(L).

tc_listener_stopped_when_owner_die(Config) ->
    Port = select_port(),
    Me = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
        Me ! {started, self(), L},
        receive
            done -> ok
        end
    end),
    %% Given a Listener Handle owned by another process
    receive
        {started, Pid, L0} -> ok
    end,
    {error, listener_start_error, {unknown_quic_status, Reason}} =
        quicer:listen(Port, default_listen_opts(Config)),
    ?assert(Reason == 91 orelse Reason == 41),

    Pid ! done,
    %% When the owner process dies
    receive
        {'DOWN', MRef, process, Pid, normal} ->
            ok
    end,
    %% Then port is released and new listener can be started
    {ok, L1} = snabbkaffe:retry(
        10000,
        10,
        fun() ->
            {ok, _L0} = quicer:listen(Port, default_listen_opts(Config))
        end
    ),
    %% Then the old listener can be closed but timeout since it is already stopped
    %% and no stop event is triggered
    {error, timeout} = quicer:close_listener(L0, _timeout = 10),
    %% Then the new listener can be closed
    ok = quicer:close_listener(L1).

tc_verify_none_butwith_cacert(Config) ->
    Port = select_port(),
    %% When Listener is configured with CA certfile but verify_none
    LConfig = default_listener_opts(Config, verify_none),
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {LConfig, ConnectionOpts, StreamOpts},
    {ok, _QuicApp} = quicer:spawn_listener(?FUNCTION_NAME, Port, Options),

    %% Then the connection should succeed
    {ok, Conn} =
        quicer:connect(
            "localhost",
            Port,
            [
                {verify, verify_none},
                {peer_unidi_stream_count, 3},
                {alpn, ["sample"]}
                | Config
            ],
            5000
        ),
    quicer:close_connection(Conn),
    quicer:terminate_listener(?FUNCTION_NAME),
    ok.

tc_get_listeners_from_reg(Config) ->
    Port = select_port(),
    RegH = proplists:get_value(quic_registration, Config, global),
    {ok, L1} = quicer:listen(Port, default_listen_opts(Config)),
    Port2 = select_port(),
    {ok, L2} = quicer:listen(Port2, default_listen_opts(Config)),
    ?assertEqual([L2, L1], quicer:get_listeners(RegH)).

tc_get_listener_owner(Config) ->
    Port = select_port(),
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    ?assertEqual({ok, self()}, quicer:get_listener_owner(L)),
    quicer:close_listener(L).

tc_count_conns(Config) ->
    Port0 = select_port(),
    Port1 = select_port(),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 2}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 2}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},

    %% GIVEN: Two QUIC listeners
    {ok, QuicApp} = quicer:spawn_listener(sample, Port0, Options),

    {ok, QuicApp2} = quicer:spawn_listener(sample2, Port1, Options),

    ClientConnOpts = default_conn_opts_verify(Config, ca),

    %% WHEN: a client is connected to the first listener
    {ok, ClientConnPid} = example_client_connection:start_link(
        "localhost",
        Port0,
        {ClientConnOpts, default_stream_opts()}
    ),
    #{is_resumed := false} = snabbkaffe:retry(
        50,
        20,
        fun() ->
            #{is_resumed := false} = quicer_connection:get_cb_state(ClientConnPid)
        end
    ),

    %% Then the first listener has one connection and other has none
    ?assertEqual({1, 0}, {
        quicer_listener:count_conns(QuicApp), quicer_listener:count_conns(QuicApp2)
    }),

    %% WHEN: client is stopped
    gen_server:stop(ClientConnPid),

    %% THEN: both listeners have no connections
    {0, 0} = snabbkaffe:retry(
        10,
        100,
        fun() ->
            {0, 0} =
                {quicer_listener:count_conns(QuicApp), quicer_listener:count_conns(QuicApp2)}
        end
    ),

    quicer:terminate_listener(sample),
    quicer:terminate_listener(sample2).

%%% Helpers

select_port() ->
    Port = select_free_port(quic),
    timer:sleep(100),
    Port.

default_listener_opts(Config, Verify) ->
    DataDir = ?config(data_dir, Config),
    [
        {cacertfile, filename:join(DataDir, "ca.pem")},
        {conn_acceptors, 4},
        {verify, Verify}
        | tl(default_listen_opts(Config))
    ].

default_conn_opts_verify(Config, Ca) ->
    DataDir = ?config(data_dir, Config),
    CACertFile = filename:join(DataDir, Ca) ++ ".pem",
    [
        {verify, verify_peer},
        {cacertfile, CACertFile},
        {alpn, ["sample"]},
        %% {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
        {idle_timeout_ms, 5000}
    ].
