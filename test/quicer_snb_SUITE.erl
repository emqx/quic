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
-module(quicer_snb_SUITE).

%% API
-export([
    all/0,
    suite/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% test cases
-export([
    tc_app_echo_server/1,
    tc_slow_conn/1,
    tc_stream_owner_down/1,
    tc_stream_acceptor_down/1,
    tc_conn_owner_down/1,
    tc_conn_close_flag_1/1,
    tc_conn_close_flag_2/1,
    tc_stream_close_errno/1,
    tc_stream_shutdown_abort/1,
    tc_conn_idle_close/1,
    tc_conn_gc/1,
    tc_conn_no_gc/1,
    tc_conn_no_gc_2/1,
    tc_conn_resume_nst/1,
    tc_conn_resume_nst_with_stream/1,
    tc_conn_resume_nst_async/1,
    tc_conn_resume_nst_async_2/1,
    tc_conn_resume_nst_with_data/1,
    tc_listener_no_acceptor/1,
    tc_listener_inval_local_addr/1,
    tc_conn_start_inval_port/1,
    tc_conn_stop_notify_acceptor/1,
    tc_accept_stream_active_once/1,
    tc_accept_stream_active_N/1,
    tc_multi_streams/1,
    tc_multi_streams_example_server_1/1,
    tc_multi_streams_example_server_2/1,
    tc_multi_streams_example_server_3/1,
    tc_passive_recv_1/1
]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer.hrl").

-define(my_check_trace(BUCKET, RUN, CHECK),
    ?check_trace(
        BUCKET,
        begin
            quicer_nif:set_snab_kc_pid(whereis(snabbkaffe_collector)),
            ?assert(whereis(snabbkaffe_collector) == quicer_nif:get_snab_kc_pid()),
            RUN
        end,
        CHECK
    )
).

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
    %% dbg:tracer(),
    %% dbg:p(all,c),
    %% dbg:tpl(snabbkaffe, do_find_pairs, cx),
    DataDir = ?config(data_dir, Config),
    _ = quicer_test_lib:gen_ca(DataDir, ?MODULE),
    _ = quicer_test_lib:gen_host_cert("server", ?MODULE, DataDir),
    _ = quicer_test_lib:gen_host_cert("client", ?MODULE, DataDir),
    application:ensure_all_started(quicer),
    application:ensure_all_started(snabbkaffe),
    Config.

%%--------------------------------------------------------------------
%% @spec end_per_suite(Config0) -> term() | {save_config,Config1}
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
    quicer_test_lib:report_active_connections(),
    ok.

%%--------------------------------------------------------------------
%% @spec init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% @end
%%--------------------------------------------------------------------
init_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @spec end_per_group(GroupName, Config0) ->
%%               term() | {save_config,Config1}
%% GroupName = atom()
%% Config0 = Config1 = [tuple()]
%% @end
%%--------------------------------------------------------------------
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
init_per_testcase(tc_listener_inval_local_addr, Config) ->
    case os:type() of
        {unix, darwin} -> {skip, "Not runnable on MacOS"};
        _ -> Config
    end;
init_per_testcase(_TestCase, Config) ->
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
end_per_testcase(_TestCase, _Config) ->
    quicer:terminate_listener(mqtt),
    snabbkaffe:cleanup(),
    quicer_test_lib:report_unhandled_messages(),
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
    [].

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
        tc_app_echo_server,
        tc_slow_conn,
        tc_stream_owner_down,
        tc_stream_acceptor_down,
        tc_conn_owner_down,
        tc_conn_close_flag_1,
        tc_conn_close_flag_2,
        tc_conn_idle_close,
        tc_stream_close_errno,
        tc_stream_shutdown_abort,
        tc_conn_no_gc,
        tc_conn_no_gc_2,
        tc_conn_gc,
        tc_conn_resume_nst,
        tc_conn_resume_nst_with_stream,
        tc_conn_resume_nst_with_data,
        tc_conn_resume_nst_async,
        tc_conn_resume_nst_async_2,
        tc_listener_no_acceptor,
        tc_listener_inval_local_addr,
        tc_conn_start_inval_port,
        tc_conn_stop_notify_acceptor,
        tc_accept_stream_active_once,
        tc_accept_stream_active_N,
        %% multistreams
        tc_multi_streams,
        tc_multi_streams_example_server_1,
        tc_multi_streams_example_server_2,
        tc_multi_streams_example_server_3,
        tc_passive_recv_1
    ].

%%--------------------------------------------------------------------
%% @spec TestCase() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
%% my_test_case() ->
%%   [].

%%--------------------------------------------------------------------
%% @spec TestCase(Config0) ->
%%               ok | exit() | {skip,Reason} | {comment,Comment} |
%%               {save_config,Config1} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% Comment = term()
%% @end
%%--------------------------------------------------------------------
tc_app_echo_server(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
    ?my_check_trace(
        #{timetrap => 5000},
        begin
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            Resp = quicer:recv(Stm, 4),
            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            context := "callback",
                            function := "ServerStreamCallback",
                            mark := ?QUIC_STREAM_EVENT_SEND_COMPLETE,
                            tag := "event"
                        },
                        3000,
                        3000
                    )
            ),
            Resp
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual({ok, <<"ping">>}, Result),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "ClientStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_SEND_COMPLETE,
                        resource_id := _RidC
                    },
                    #{
                        ?snk_kind := debug,
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_RECEIVE,
                        resource_id := _RidS
                    },
                    _RidC =/= _RidS,
                    Trace
                )
            )
        end
    ),

    quicer:close_stream(Stm),
    quicer:close_connection(Conn),
    ok = quicer:terminate_listener(mqtt).

tc_slow_conn(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 1000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            quicer:recv(Stm, 4),
            ct:pal("closing stream"),
            ok = quicer:close_stream(Stm),
            ct:pal("closing conn"),
            quicer:close_connection(Conn),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "ServerListenerCallback",
                        tag := "acceptor_hit",
                        mark := 0,
                        resource_id := _Rid
                    },
                    #{
                        ?snk_kind := debug,
                        function := "async_handshake_1",
                        tag := "start",
                        mark := 0,
                        resource_id := _Rid
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_stream_owner_down(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            quicer:recv(Stm, 4),
            Pid = spawn(fun() ->
                receive
                    down -> ok
                end
            end),
            quicer:controlling_process(Stm, Pid),
            Pid ! down,
            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            context := "callback",
                            function := "ServerStreamCallback",
                            mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                            tag := "event"
                        },
                        1000,
                        1000
                    )
            ),
            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            context := "callback",
                            function := "ClientStreamCallback",
                            mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                            tag := "event"
                        },
                        1000,
                        1000
                    )
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% check that stream down callback is triggered when stream owner process is dead
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "stream_controlling_process",
                        tag := "exit",
                        resource_id := _Rid
                    },
                    #{
                        ?snk_kind := debug,
                        function := "resource_stream_down_callback",
                        tag := "start",
                        mark := 0,
                        resource_id := _Rid
                    },
                    Trace
                )
            ),
            %% check that it triggers an immediate stream shutdown
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "resource_stream_down_callback",
                        tag := "start",
                        mark := 0,
                        resource_id := _Rid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE,
                        resource_id := _Rid
                    },
                    Trace
                )
            ),

            %% check that client side immediate shutdown triggers a peer_send_abort event at server side
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                    },
                    #{
                        ?snk_kind := debug,
                        event := peer_send_aborted,
                        error_code := 0
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_stream_acceptor_down(Config) ->
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 10},
        {peer_unidi_stream_count, 0}
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
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10}, {peer_unidi_stream_count, 1} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            {ok, Stm2} = quicer:start_stream(Conn, [{active, true}]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,
            receive
                {quic, <<"ping2">>, Stm2, _} -> ok
            after 100 -> ct:fail("no ping2")
            end,
            {DeadPid, DMRef} = spawn_monitor(fun() ->
                quicer:async_accept_stream(Conn, [])
            end),
            %% GIVEN: one remote stream acceptor is DOWN
            receive
                {'DOWN', DMRef, process, DeadPid, normal} -> ok
            after 500 -> ct:fail("no DOWN message for dead pid")
            end,
            %% WHEN: We trigger peer (server) to initiate remote stream to us
            {ok, Stm3Out} = quicer:start_stream(Conn, [
                {active, true}, {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
            ]),
            quicer:async_send(Stm3Out, <<"ping3">>),
            Stm3In =
                receive
                    %% THEN: This process is selected as stream owner fallback (is_orphan = true)
                    {quic, new_stream, Incoming, #{flags := Flag, is_orphan := true}} ->
                        ct:pal("incoming stream from server: ~p", [Incoming]),
                        true = quicer:is_unidirectional(Flag),
                        quicer:setopt(Incoming, active, true),
                        Incoming
                after 1000 ->
                    ct:fail("no incoming stream")
                end,
            receive
                {quic, Data, Stm3In, DFlag} ->
                    ct:pal("~p is received from ~p with flag: ~p", [Data, Stm3In, DFlag]),
                    ?assertEqual(Data, <<"ping3">>)
            after 1000 ->
                ct:fail("no incoming data")
            end,
            quicer:async_shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0),
            receive
                {quic, closed, Conn, _} ->
                    ct:pal("Connection is closed")
            end,
            quicer:shutdown_connection(Conn)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            %% check that acceptor is first picked but it is down and fallback is triggered
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        function := "handle_connection_event_peer_stream_started",
                        tag := "acceptor_available",
                        resource_id := _Rid
                    },
                    #{
                        ?snk_kind := debug,
                        function := "handle_connection_event_peer_stream_started",
                        tag := "acceptor_down_fallback",
                        resource_id := _Rid
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_conn_owner_down(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, CRid} = quicer:get_conn_rid(Conn),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            {ok, SRid} = quicer:get_stream_rid(Stm),
            Pid = spawn(fun() ->
                receive
                    down -> ok
                end
            end),
            quicer:controlling_process(Conn, Pid),

            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            function := "connection_controlling_process",
                            tag := "exit",
                            resource_id := CRid
                        },
                        1000,
                        1000
                    )
            ),
            Pid ! down,
            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            context := "callback",
                            function := "ClientConnectionCallback",
                            mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                            tag := "event"
                        },
                        1000,
                        1000
                    )
            ),
            ?assert(
                timeout =/=
                    ?block_until(
                        #{
                            ?snk_kind := debug,
                            context := "callback",
                            function := "ServerConnectionCallback",
                            mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                            tag := "event"
                        },
                        1000,
                        1000
                    )
            ),
            ?assert(
                timeout =/=
                    ?block_until(
                        #{?snk_kind := debug, event := closed, module := quicer_connection},
                        1000,
                        1000
                    )
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt),

            {CRid, SRid}
        end,
        fun(Result, Trace) ->
            {CRid, SRid} = Result,
            ct:pal("Rid is ~p~n Sid is ~p~nTrace is ~p, ", [CRid, SRid, Trace]),
            %% check that conn down callback is triggered when conn owner process is dead
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "connection_controlling_process",
                        tag := "exit",
                        resource_id := CRid
                    },
                    #{
                        ?snk_kind := debug,
                        function := "resource_conn_down_callback",
                        tag := "start",
                        resource_id := CRid
                    },
                    Trace
                )
            ),
            %% Check that it triggers an immediate connection shutdown
            %% and ensure Client Connection Shutdown complete must happen *after*
            %% resource_conn_down_callback is triggered
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        function := "resource_conn_down_callback",
                        tag := "start",
                        resource_id := CRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid
                    },
                    Trace
                )
            ),
            %% check that client side immediate shutdown triggers a stream shutdown
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        function := "resource_conn_down_callback",
                        %% as long as it is started. (ConnectionClose is sync call in non-callback)
                        tag := "start",
                        resource_id := CRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE,
                        tag := "event",
                        resource_id := SRid
                    },
                    Trace
                )
            ),
            %% check that client side conn shutdown happens after stream shutdown
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE,
                        tag := "event",
                        resource_id := SRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid
                    },
                    Trace
                )
            ),
            %% check that client side immediate shutdown triggers a close at server side
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        event := shutdown,
                        module := quicer_connection,
                        '~meta' := #{pid := _PID}
                    },
                    #{
                        ?snk_kind := debug,
                        event := closed,
                        module := quicer_connection,
                        '~meta' := #{pid := _PID}
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_conn_close_flag_1(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 1000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, CRid} = quicer:get_conn_rid(Conn),
            ct:pal("Client connection Rid: ~p", [CRid]),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 9} = quicer:async_send(Stm, <<"__STATE__">>),
            #{conn := SConn} = quicer_test_lib:recv_term_from_stream(Stm),
            {ok, SRid} = quicer:get_conn_rid(SConn),
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerConnectionCallback",
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000,
                3000
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ClientConnectionCallback",
                    resource_id := CRid,
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000,
                3000
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt),
            {CRid, SRid}
        end,
        fun({_CRid, SRid}, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            %% verify that client close_connection with default flag
            %% triggers a close at server side
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER,
                        tag := "event",
                        resource_id := SRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := SRid
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_conn_close_flag_2(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            quicer:recv(Stm, 4),
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 111),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ClientConnectionCallback",
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                    %% assume idle_timeout_is 5s
                    tag := "event"
                },
                3000,
                3000
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% check that client conn silent shutdown does not trigger
            %% active connection shutdown at server side
            ?assertEqual([], ?of_kind(quic_closed, Trace))
        end
    ),
    ok.

tc_stream_close_errno(Config) ->
    Errno = 1234,
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            quicer:recv(Stm, 4),
            quicer:close_stream(Stm, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, Errno, 5000),
            quicer:close_connection(Conn),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerStreamCallback",
                    mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerConnectionCallback",
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000,
                1000
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    event := peer_send_aborted,
                    error_code := 1234
                },
                1000,
                1000
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% check that server side
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "handle_stream_event_peer_send_aborted",
                        tag := "peer_send_aborted",
                        mark := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        event := peer_send_aborted,
                        error_code := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        event := peer_send_aborted,
                        module := quicer_stream,
                        error_code := Errno
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_closed,
                        module := quicer_stream,
                        flags := #{error := 0}
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_stream_shutdown_abort(Config) ->
    Errno = 1234,
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            quicer:recv(Stm, 4),
            quicer:shutdown_stream(Stm, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT, Errno, 5000),
            quicer:close_connection(Conn),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerStreamCallback",
                    mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerConnectionCallback",
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                1000,
                1000
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    event := peer_send_aborted,
                    error_code := 1234
                },
                1000,
                1000
            ),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% check that server side
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "handle_stream_event_peer_send_aborted",
                        tag := "peer_send_aborted",
                        mark := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        event := peer_send_aborted,
                        module := quicer_stream,
                        error_code := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "handle_stream_event_peer_receive_aborted",
                        tag := "peer_receive_aborted",
                        mark := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
                    },
                    #{
                        ?snk_kind := debug,
                        event := peer_receive_aborted,
                        module := quicer_stream,
                        error_code := Errno
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        event := peer_send_aborted,
                        module := quicer_stream,
                        error_code := Errno
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_closed,
                        module := quicer_stream,
                        flags := #{error := 0}
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_conn_idle_close(Config) ->
    Port = select_port(),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32},
        {idle_timeout_ms, 3000}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [
                    {idle_timeout_ms, 1000},
                    {verify, none},
                    {alpn, ["sample"]}
                ],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ClientConnectionCallback",
                    mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
                    %% server timeout is set to 1000
                },
                3000
            ),
            receive
                {quic, transport_shutdown, _Conn, Status} ->
                    ct:pal("conn trans_shutdown status ~p~n", [Status])
            end,
            case quicer:send(Stm, <<"ping2">>) of
                {error, stm_send_error, invalid_state} -> ok;
                {error, cancelled} -> ok;
                {error, closed} -> ok
            end,

            ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "ServerStreamCallback",
                    mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                    tag := "event"
                },
                2000,
                1000
            ),
            ok
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% check that transport shutdown due to idle timeout is triggered at client side
            %% check that shutdown_complete is triggered after idle timeout
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                    },
                    Trace
                )
            ),

            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientStreamCallback",
                        tag := "event",
                        mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
                    },
                    Trace
                )
            )
        end
    ),
    ct:pal("stop listener"),
    ok = quicer:terminate_listener(mqtt),
    ok.

tc_conn_gc(Config) ->
    Port = select_port(),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32},
        {idle_timeout_ms, 5000}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 100000},
        begin
            %% Spawn a process that will die without handle cleanups
            %% The dead process should trigger a connection close
            %% The dead process should trigger a GC
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            Parent = self(),
            {Child, MRef} = spawn_monitor(
                fun() ->
                    %% Note, the client process holds the ref to the `Conn', So `Conn' should get GC-ed when it dies.
                    {ok, Conn} = quicer:connect(
                        "localhost",
                        Port,
                        [
                            {idle_timeout_ms, 1000},
                            {verify, none},
                            {alpn, ["sample"]}
                        ],
                        5000
                    ),
                    {ok, Rid} = quicer:get_conn_rid(Conn),
                    Parent ! {crid, Rid},
                    {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                    {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                    {ok, <<"ping">>} = quicer:recv(Stm, 4)
                end
            ),
            CRid =
                receive
                    {crid, Rid} ->
                        Rid
                end,
            receive
                {'DOWN', MRef, process, Child, normal} ->
                    erlang:garbage_collect()
            end,
            %% Server Process
            {ok, #{resource_id := SRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    5000
                ),
            %% Client Process
            {ok, #{resource_id := CRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid,
                        tag := "event"
                    },
                    5000,
                    1000
                ),
            %% OTP GC callback
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "resource_conn_dealloc_callback",
                    resource_id := 0,
                    tag := "end"
                },
                5000,
                1000
            ),
            timer:sleep(1000),
            {SRid, CRid}
        end,
        fun({_SRid, CRid}, Trace0) ->
            Trace = flush_previous_run(Trace0, fun
                (
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        resource_id := Rid,
                        tag := "event"
                    }
                ) when Rid == CRid ->
                    true;
                (_) ->
                    false
            end),
            ct:pal("Trace is ~p", [Trace]),
            ct:pal("Target SRid: ~p, CRid: ~p", [_SRid, CRid]),
            %% check that at client side, GC is triggered after connection close.
            %% check that at server side, connection was shutdown by client.
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "resource_conn_dealloc_callback",
                        resource_id := 0,
                        tag := "end"
                    },
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER,
                        resource_id := _SRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        resource_id := _SRid,
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    Trace
                )
            ),
            ?assertEqual(
                1,
                length([
                    E
                 || #{
                        function := "resource_conn_dealloc_callback",
                        resource_id := Rid,
                        tag := "end"
                    } = E <- Trace,
                    Rid == 0
                ])
            )
        end
    ),
    ct:pal("stop listener"),
    ok = quicer:terminate_listener(mqtt),
    ok.

tc_conn_no_gc(Config) ->
    Port = select_port(),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32},
        {idle_timeout_ms, 1000}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            %% Spawn a client process that will close the connection explicitly before die.
            %% The dead client process should trigger a connection close at server end.
            %% The dead client process should not trigger a GC of 'Conn' because the parent process
            %% still holds the 'Conn' var ref.
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            %% We hold a ref the Conn in this process, so Conn won't be gc-ed.
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [
                    {idle_timeout_ms, 1000},
                    {verify, none},
                    {alpn, ["sample"]}
                ],
                5000
            ),
            {ok, CRid} = quicer:get_conn_rid(Conn),
            _Child = spawn_link(fun() ->
                {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                {ok, <<"ping">>} = quicer:recv(Stm, 4),
                quicer:shutdown_connection(Conn, 0, 0)
            end),
            %% Server Process
            {ok, #{resource_id := SRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    5000,
                    1000
                ),
            %% Client Process
            {ok, #{resource_id := CRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid,
                        tag := "event"
                    },
                    5000,
                    1000
                ),
            %% Give it time for gc that should not happen on var 'Conn', could be the source of flakiness.
            %% We are rather testing the OTP behavior here but proves our understandings are correct.
            timer:sleep(5000),
            {ok, CRid, SRid, Conn}
        end,
        fun({ok, CRid, _RidS, Conn}, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            %% check that at server side, connection was shutdown by client.
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER,
                        resource_id := _RidS
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        resource_id := _RidS,
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    Trace
                )
            ),
            TraceEvents = flush_previous_run(Trace, fun
                (
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        resource_id := Rid,
                        tag := "event"
                    }
                ) when Rid == CRid ->
                    true;
                (_) ->
                    false
            end),
            %% Check that there is no GC
            ?assertEqual(
                0,
                length([
                    E
                 || #{
                        function := "resource_conn_dealloc_callback",
                        resource_id := Rid
                    } = E <- TraceEvents,
                    Rid == CRid
                ])
            ),
            %% Just keep the ref till end
            ?assert(Conn =/= undefined)
        end
    ),
    ct:pal("stop listener"),
    ok = quicer:terminate_listener(mqtt),
    ok.

tc_conn_no_gc_2(Config) ->
    Port = select_port(),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32},
        {idle_timeout_ms, 1000}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 20000},
        begin
            %% Spawn a client process that will close the connection explicitly before die.
            %% The dead client process should trigger a connection close at server end.
            %% The dead client process should not trigger a GC of 'ClientConn' because the parent process
            %% still holds the 'ClientConn' var ref.
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            Parent = self(),
            PRef = erlang:make_ref(),
            _Child = spawn_link(fun() ->
                {ok, Conn} = quicer:connect(
                    "localhost",
                    Port,
                    [
                        {idle_timeout_ms, 1000},
                        {verify, none},
                        {alpn, ["sample"]}
                    ],
                    5000
                ),
                {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                {ok, ConnRid} = quicer:get_conn_rid(Conn),
                Parent ! {PRef, Conn, ConnRid, Stm},
                {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                {ok, <<"ping">>} = quicer:recv(Stm, 4),
                quicer:shutdown_connection(Conn, 0, 0)
            end),
            {ClientConn, CRid, _ClientStream} =
                receive
                    %% Get ConnRid from client for Matches exact shutdown complete event
                    {PRef, C, ConnRid, S} -> {C, ConnRid, S}
                end,
            %% Server Process
            {ok, #{resource_id := SRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    5000,
                    1000
                ),
            %% Client Process
            {ok, #{resource_id := CRid}} =
                ?block_until(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        resource_id := CRid,
                        tag := "event"
                    },
                    5000,
                    1000
                ),
            %% Give it time for GC of `Conn' that caused by dead client process.
            %% But the resource dealloc callback should not be called since
            %% we still have a ref in current process with Var: `ClientConn'
            %% We are rather testing the OTP behavior here but proves our understandings are correct.
            timer:sleep(5000),
            %% We can get segfault here if it is use-after-free
            quicer:getstat(ClientConn, [send_cnt, recv_oct, send_pend]),
            %% Ensure we hold the ref here
            {ok, CRid, SRid, ClientConn}
        end,
        fun({ok, CRid, _SRid, _}, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            %% check that at server side, connection was shutdown by client.
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER,
                        resource_id := _SRid
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        resource_id := _SRid,
                        mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                        tag := "event"
                    },
                    Trace
                )
            ),
            %% Check that there is no GC
            TraceEvents = flush_previous_run(Trace, fun
                (
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        resource_id := Rid,
                        tag := "event"
                    }
                ) when Rid == CRid ->
                    true;
                (_) ->
                    false
            end),
            ?assertEqual(
                0,
                length([
                    E
                 || #{
                        function := "resource_conn_dealloc_callback",
                        resource_id := Rid
                    } = E <- TraceEvents,
                    Rid == CRid
                ])
            )
        end
    ),
    ct:pal("stop listener"),
    ok = quicer:terminate_listener(mqtt),
    ok.

%%% Resume connection with connection opt: `nst'
tc_conn_resume_nst(Config) ->
    Port = select_port(),
    %% @TODO test Non empty 'Resume Data'
    ExpectedSessionData = false,
    ServerResumeCBFun = fun(_Conn, Data, S) ->
        ct:pal("recv resume data: ~p", [Data]),
        Data =/= ExpectedSessionData andalso
            ct:fail("Unexpected session data: ~p", [Data]),
        {ok, S}
    end,
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {resumed_callback, ServerResumeCBFun},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()],
                5000
            ),
            {ok, HandshakeInfo} = quicer:getopt(Conn, handshake_info, quic_tls),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            NST =
                receive
                    {quic, nst_received, Conn, Ticket} ->
                        Ticket
                after 1000 ->
                    ct:fail("No ticket received")
                end,
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

            {ok, ConnResumed} = quicer:connect(
                "localhost", Port, [{nst, NST} | default_conn_opts()], 5000
            ),
            {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
            {ok, HandshakeInfo0RTT} = quicer:getopt(
                ConnResumed, handshake_info, quic_tls
            ),
            ct:pal("handshake info:~n1RTT: ~p~n0RTT: ~p~n", [HandshakeInfo, HandshakeInfo0RTT]),
            ?assertEqual(HandshakeInfo, HandshakeInfo0RTT),
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
            quicer:shutdown_connection(Conn),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% 1. verify that for each success connect we send a resumption ticket
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        resource_id := _CRid1
                    },
                    Trace
                )
            ),
            %% 2. verify that resumption ticket is received on client side
            %%    and client use it to resume success
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMED,
                        resource_id := _SRid1
                    },
                    Trace
                )
            )
        end
    ),
    ok.

%%% Resume connection with connection opt: `nst' and open stream with 0RTT
tc_conn_resume_nst_with_stream(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [
                {active, false}, {open_flag, ?QUIC_STREAM_OPEN_FLAG_0_RTT}
            ]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            NST =
                receive
                    {quic, nst_received, Conn, Ticket} ->
                        Ticket
                after 1000 ->
                    ct:fail("No ticket received")
                end,
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

            {ok, ConnResumed} = quicer:connect(
                "localhost", Port, [{nst, NST} | default_conn_opts()], 5000
            ),
            {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
            quicer:shutdown_connection(ConnResumed),
            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% 1. verify that for each success connect we send a resumption ticket
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        resource_id := _CRid1
                    },
                    Trace
                )
            ),
            %% 2. verify that resumption ticket is received on client side
            %%    and client use it to resume success
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMED,
                        resource_id := _SRid1
                    },
                    Trace
                )
            )
        end
    ),
    ok.

%%% Non-blocking connection resume, client could send app data without waiting for handshake done.
tc_conn_resume_nst_async(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            NST =
                receive
                    {quic, nst_received, Conn, Ticket} ->
                        Ticket
                after 1000 ->
                    ct:fail("No ticket received")
                end,
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

            {ok, ConnResumed} = quicer:async_connect("localhost", Port, [
                {nst, NST} | default_conn_opts()
            ]),
            {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
            ct:pal("stop listener"),
            quicer:shutdown_connection(ConnResumed),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% 1. verify that for each success connect we send a resumption ticket
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        resource_id := _CRid1
                    },
                    Trace
                )
            ),
            %% 2. verify that resumption ticket is received on client side
            %%    and client use it to resume success
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMED,
                        resource_id := _SRid1
                    },
                    Trace
                )
            )
        end
    ),
    ok.

%%% Non-blocking connection resume, client could send app data without waiting for handshake done using existing handle
tc_conn_resume_nst_async_2(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            NST =
                receive
                    {quic, nst_received, Conn, Ticket} ->
                        Ticket
                after 1000 ->
                    ct:fail("No ticket received")
                end,
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),
            {ok, NewConn} = quicer:open_connection(),
            ok = quicer:setopt(NewConn, resumption_ticket, NST),
            {ok, ConnResumed} = quicer:async_connect("localhost", Port, [
                {handle, NewConn} | default_conn_opts()
            ]),
            {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
            ct:pal("stop listener"),
            quicer:shutdown_connection(ConnResumed),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% 1. verify that for each success connect we send a resumption ticket
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        resource_id := _CRid1
                    },
                    Trace
                )
            ),
            %% 2. verify that resumption ticket is received on client side
            %%    and client use it to resume success
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMED,
                        resource_id := _SRid1
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_conn_resume_nst_with_data(Config) ->
    Port = select_port(),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:async_connect("localhost", Port, [
                {quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()
            ]),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:async_send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 4),
            NST =
                receive
                    {quic, nst_received, Conn, Ticket} ->
                        Ticket
                after 1000 ->
                    ct:fail("No ticket received")
                end,
            quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),
            {ok, NewConn} = quicer_nif:open_connection(),
            ok = quicer:setopt(NewConn, share_udp_binding, false),
            ?assertEqual({ok, false}, quicer:getopt(NewConn, share_udp_binding)),

            %% Send data over new stream in the resumed connection
            {ok, Stm2} = quicer:async_csend(
                NewConn,
                <<"ping_from_resumed">>,
                [{active, false}],
                ?QUIC_SEND_FLAG_ALLOW_0_RTT bor ?QUICER_SEND_FLAG_SYNC
            ),
            %% Now we could start the connection to ensure 0-RTT data in use
            {ok, ConnResumed} = quicer:async_connect("localhost", Port, [
                {nst, NST},
                {handle, NewConn},
                {quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST}
                | default_conn_opts()
            ]),
            {ok, <<"ping_from_resumed">>} = quicer:recv(Stm2, length("ping_from_resumed")),
            ?assertEqual(NewConn, ConnResumed),
            NST2 =
                receive
                    {quic, nst_received, NewConn, Ticket2} ->
                        Ticket2
                after 3000 ->
                    ct:fail("No ticket received for 2nd conn")
                end,
            ?assertNotEqual(NST2, NST),

            ct:pal("stop listener"),
            ok = quicer:terminate_listener(mqtt)
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertEqual(ok, Result),
            %% 1. verify that for each success connect we send a resumption ticket
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_CONNECTED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        resource_id := _CRid1
                    },
                    Trace
                )
            ),
            %% 2. Verify that data is received in 0-RTT with QUIC_RECEIVE_FLAG_0_RTT set
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerStreamCallback",
                        mark := ?QUIC_STREAM_EVENT_RECEIVE,
                        tag := "event",
                        resource_id := _SRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "handle_stream_event_recv",
                        tag := "event_recv_flag",
                        mark := ?QUIC_RECEIVE_FLAG_0_RTT,
                        resource_id := _SRid1
                    },
                    Trace
                )
            ),

            %% 3. verify that resumption ticket is received on client side
            %%    and client use it to resume success
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ClientConnectionCallback",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED,
                        tag := "event",
                        resource_id := _CRid1
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerConnectionCallback",
                        tag := "event",
                        mark := ?QUIC_CONNECTION_EVENT_RESUMED,
                        resource_id := _SRid1
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_listener_no_acceptor(Config) ->
    Port = select_port(),
    ListenerOpts = [{conn_acceptors, 0} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
            {error, transport_down, #{status := connection_refused}} =
                quicer:connect("localhost", Port, default_conn_opts(), 5000)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assert(
                ?causality(
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "ServerListenerCallback",
                        tag := "no_acceptor"
                    },
                    #{
                        ?snk_kind := debug,
                        context := "callback",
                        function := "handle_connection_event_shutdown_complete",
                        tag := "shutdown_complete"
                    },
                    Trace
                )
            )
        end
    ),
    ct:pal("stop listener"),
    ok = quicer:terminate_listener(mqtt),
    ok.

%% @doc this triggers listener start fail
tc_listener_inval_local_addr(Config) ->
    BadListenOn = "8.8.8.8:443",
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            Res = quicer:listen(BadListenOn, default_listen_opts(Config)),
            ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "resource_config_dealloc_callback",
                    tag := "end"
                },
                1000,
                1000
            ),
            Res
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch({error, listener_start_error, {unknown_quic_status, _}}, Result),
            ?assertMatch(
                [
                    #{
                        context := "nif",
                        function := "listen2",
                        tag := "start_fail"
                    }
                ],
                lists:filter(
                    fun(Event) ->
                        "nif" == maps:get(context, Event, undefined)
                    end,
                    Trace
                )
            )
        end
    ).

tc_conn_start_inval_port(_Config) ->
    application:ensure_all_started(quicer),
    BadPort = 65536,
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            Res = quicer:connect("localhost", BadPort, default_conn_opts(), infinity),
            receive
                {quic, closed, _, _} = Msg ->
                    ct:fail("shall not recv msg for failed connection  ~p", [Msg])
            after 100 ->
                ok
            end,
            ?block_until(
                #{
                    ?snk_kind := debug,
                    context := "callback",
                    function := "resource_config_dealloc_callback",
                    tag := "end"
                },
                1000,
                1000
            ),
            Res
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch({error, conn_start_error}, Result),
            ?assertMatch(
                [
                    #{
                        context := "nif",
                        function := "async_connect3",
                        tag := "start_fail"
                    }
                ],
                lists:filter(
                    fun(Event) ->
                        "nif" == maps:get(context, Event, undefined)
                    end,
                    Trace
                )
            )
        end
    ).

tc_conn_stop_notify_acceptor(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            Parent = self(),
            {SPid, Ref} = spawn_monitor(fun() ->
                {ok, Listener} = quicer:listen(Port, ListenerOpts),
                Parent ! {self(), ready},
                {ok, Conn} = quicer:accept(Listener, []),
                Acceptors = lists:map(
                    fun(_) ->
                        spawn(quicer, accept_stream, [Conn, []])
                    end,
                    lists:seq(1, 100)
                ),
                {ok, Conn} = quicer:handshake(Conn),
                case quicer:accept_stream(Conn, []) of
                    {error, closed} -> ok;
                    {ok, _Stream} -> ok
                end,
                quicer:close_listener(Listener),
                exit({normal, Acceptors})
            end),
            receive
                {SPid, ready} -> ok
            end,
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), infinity),
            quicer:shutdown_connection(Conn),

            receive
                {'DOWN', Ref, process, SPid, {normal, AccPids}} ->
                    ct:pal("Server process exit normaly"),
                    ok = wait_for_die(AccPids);
                {'DOWN', Ref, process, SPid, Other} ->
                    ct:fail("Server process exit abnormaly: ~p", [Other])
            after 1000 ->
                ct:fail("Server process blocking: ~p", [process_info(SPid, messages)])
            end
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            Byes = lists:filter(
                fun
                    (#{tag := "acceptor_bye"}) -> true;
                    (_) -> false
                end,
                Trace
            ),
            ?assertEqual(101, length(Byes)),
            ?assertEqual(101, length(?of_kind(stream_acceptor_conn_closed, Trace)))
        end
    ).

tc_accept_stream_active_once(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    ListenerOpts = [
        {conn_acceptors, 32}, {peer_unidi_stream_count, 1} | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback},
        {disable_fpbuffer, true}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10}, {peer_unidi_stream_count, 1} | default_conn_opts()],
                5000
            ),

            %% Accept remote unidir stream from server
            {ok, Conn} = quicer:async_accept_stream(Conn, [{active, once}]),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            {ok, Stm2} = quicer:start_stream(Conn, [
                {active, true}, {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
            ]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,

            Stm3 =
                receive
                    {quic, new_stream, StmFromServer, _StreamFlags} ->
                        case quicer:getopt(StmFromServer, active) of
                            {ok, once} -> ok;
                            %% it recv incoming data already
                            {ok, false} -> ok
                        end,
                        StmFromServer
                after 100 ->
                    ct:fail("No unidi stream from server")
                end,
            receive
                {quic, <<"ping2">>, Stm3, _} ->
                    {ok, false} = quicer:getopt(Stm3, active)
            after 100 ->
                ct:fail("no ping2"),
                quicer:shutdown_connection(Conn)
            end
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch(
                [{pair, _, _}],
                ?find_pairs(
                    #{
                        ?snk_kind := debug,
                        event := handoff_stream,
                        module := quicer,
                        stream := _STREAM0
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_owner_handoff_done,
                        module := quicer_stream,
                        stream := _STREAM0
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_accept_stream_active_N(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    ListenerOpts = [
        {conn_acceptors, 32}, {peer_unidi_stream_count, 1} | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, ServerConnCallback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, ServerStreamCallback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10}, {peer_unidi_stream_count, 1} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            {ok, Stm2} = quicer:start_stream(Conn, [
                {active, true}, {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
            ]),
            %% Set active to 2
            {ok, Conn} = quicer:async_accept_stream(Conn, [{active, 2}]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,

            Stm3 =
                receive
                    {quic, new_stream, StreamFromServer, #{is_orphan := false}} ->
                        StreamFromServer
                after 100 ->
                    ct:fail("accept Stm3 from server fail")
                end,
            receive
                {quic, <<"ping2">>, Stm3, _} -> ok
            after 100 -> ct:fail("no ping2")
            end,
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            receive
                {quic, <<"ping3">>, Stm3, _} -> ok
            after 100 -> ct:fail("no ping3")
            end,
            %% We should get a passive
            receive
                {quic, passive, Stm3, _} -> ok
            after 100 -> ct:fail("No passive received")
            end,

            {ok, false} = quicer:getopt(Stm3, active),

            %% set active after passive
            ok = quicer:setopt(Stm3, active, 20),
            {ok, _} = quicer:async_send(Stm2, <<"ping4">>),
            receive
                {quic, <<"ping4">>, Stm3, _} -> ok
            after 100 -> ct:fail("no ping4")
            end,

            %% Test set active false
            ok = quicer:setopt(Stm3, active, false),
            {ok, false} = quicer:getopt(Stm3, active),

            %% Test set active -100
            ok = quicer:setopt(Stm3, active, -100),
            {ok, false} = quicer:getopt(Stm3, active),

            %% Test set active 1-100
            ok = quicer:setopt(Stm3, active, 2),
            {ok, 2} = quicer:getopt(Stm3, active),
            ok = quicer:setopt(Stm3, active, -100),
            {ok, false} = quicer:getopt(Stm3, active),
            quicer:shutdown_connection(Conn)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch(
                [{pair, _, _}],
                ?find_pairs(
                    #{
                        ?snk_kind := debug,
                        event := handoff_stream,
                        module := quicer,
                        stream := _STREAM0
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_owner_handoff_done,
                        module := quicer_stream,
                        stream := _STREAM0
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_multi_streams(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
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
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            {ok, Stm2} = quicer:start_stream(Conn, [{active, true}]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,
            receive
                {quic, <<"ping2">>, Stm2, _} -> ok
            after 100 -> ct:fail("no ping2")
            end,
            quicer:shutdown_connection(Conn)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch(
                [{pair, _, _}],
                ?find_pairs(
                    #{
                        ?snk_kind := debug,
                        event := handoff_stream,
                        module := quicer,
                        stream := _STREAM0
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_owner_handoff_done,
                        module := quicer_stream,
                        stream := _STREAM0
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_multi_streams_example_server_1(Config) ->
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 10},
        {peer_unidi_stream_count, 0}
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
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10}, {peer_unidi_stream_count, 1} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            {ok, Stm2} = quicer:start_stream(Conn, [{active, true}]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,
            receive
                {quic, <<"ping2">>, Stm2, _} -> ok
            after 100 -> ct:fail("no ping2")
            end,

            quicer:async_accept_stream(Conn, []),
            %% Now we open unidirectional stream
            {ok, Stm3Out} = quicer:start_stream(Conn, [
                {active, true}, {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
            ]),
            quicer:async_send(Stm3Out, <<"ping3">>),
            Stm3In =
                receive
                    {quic, new_stream, Incoming, #{flags := Flag}} ->
                        ct:pal("incoming stream from server: ~p", [Incoming]),
                        true = quicer:is_unidirectional(Flag),
                        Incoming
                after 1000 ->
                    ct:fail("no incoming stream")
                end,
            receive
                {quic, Data, Stm3In, DFlag} ->
                    ct:pal("~p is received from ~p with flag: ~p", [Data, Stm3In, DFlag]),
                    ?assertEqual(Data, <<"ping3">>),
                    %% Assert that send over a remote unidirectional stream get `invalid_state`
                    ?assertEqual(
                        {error, stm_send_error, invalid_state}, quicer:send(Stm3In, <<"foo">>)
                    )
            after 1000 ->
                ct:fail("no incoming data")
            end,
            quicer:async_shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0),
            receive
                {quic, closed, Conn, _} ->
                    ct:pal("Connection is closed")
            end,
            quicer:shutdown_connection(Conn)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assertMatch(
                [{pair, _, _}, {pair, _, _}],
                ?find_pairs(
                    #{
                        ?snk_kind := debug,
                        event := handoff_stream,
                        module := quicer,
                        stream := _STREAM0
                    },
                    #{
                        ?snk_kind := debug,
                        event := stream_owner_handoff_done,
                        module := quicer_stream,
                        stream := _STREAM0
                    },
                    Trace
                )
            ),
            ?assertMatch(
                [{pair, _, _}, {pair, _, _}],
                ?find_pairs(
                    #{
                        ?snk_kind := debug,
                        event := handoff_stream,
                        module := quicer
                    },
                    #{
                        ?snk_kind := debug,
                        context := "nif",
                        function := "stream_controlling_process",
                        tag := "enter"
                    },
                    Trace
                )
            )
        end
    ),
    ok.

tc_multi_streams_example_server_2(Config) ->
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
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            ClientConnOpts = [
                {quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()
            ],
            {ok, ClientConnPid} = example_client_connection:start_link(
                "localhost",
                Port,
                {ClientConnOpts, default_stream_opts()}
            ),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    data := <<"ping_from_example">>,
                    dir := remote_unidir,
                    module := example_client_stream
                },
                5000,
                1000
            ),
            ok,
            ct:pal("status : ~p", [sys:get_status(ClientConnPid)]),
            gen_server:stop(ClientConnPid)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example">>,
                        dir := unidir,
                        module := example_server_stream,
                        stream := _Stream1
                    },

                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example">>,
                        dir := remote_unidir,
                        module := example_client_stream,
                        stream := _Stream2
                    },
                    _Stream1 =/= _Stream2,
                    Trace
                )
            )
        end
    ),
    ok.

tc_multi_streams_example_server_3(Config) ->
    %% Client send data over unidir stream and get message echo back. (ping_from_example)
    %% Client try to start bidir stream but get blocked (ping_from_example_2)
    %% Client send "flow_control.enable_bidi" over unidir stream to ask server
    %% Server unblock bidi stream
    %% Client start yet another stream bidir streams (ping_from_example_3)
    %% All bidir streams get echo messages (ping_from_example, ping_from_example2, ping_from_example3) back.
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 0},
        {peer_unidi_stream_count, 4}
        | proplists:delete(peer_bidi_stream_count, default_listen_opts(Config))
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
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            ClientConnOpts = [
                {quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()
            ],
            {ok, ClientConnPid} = example_client_connection:start_link(
                "localhost",
                Port,
                {ClientConnOpts, default_stream_opts()}
            ),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    data := <<"ping_from_example">>,
                    dir := remote_unidir,
                    module := example_client_stream
                },
                5000,
                1000
            ),
            %% First Attempt blocking,
            {ok, _} = quicer_connection:stream_send(
                ClientConnPid,
                example_client_stream,
                <<"ping_from_example_2">>,
                ?QUIC_SEND_FLAG_NONE,
                #{
                    is_local => true,
                    open_flag => ?QUIC_STREAM_OPEN_FLAG_NONE,
                    start_flag =>
                        ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT,
                    quic_event_mask => ?QUICER_STREAM_EVENT_MASK_START_COMPLETE
                },
                infinity
            ),
            %% 2nd Attempt success over unidir stream and ask server to unblock the bidir stream
            %% This must success
            {ok, _} = quicer_connection:stream_send(
                ClientConnPid,
                example_client_stream,
                <<"flow_control.enable_bidi">>,
                ?QUIC_SEND_FLAG_NONE,
                #{
                    is_local => true,
                    open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                    start_flag => ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL bor
                        ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED bor
                        ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT,
                    quic_event_mask => ?QUICER_STREAM_EVENT_MASK_START_COMPLETE
                },
                infinity
            ),
            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    data := <<"flow_control.enable_bidi">>,
                    dir := unidir,
                    module := example_server_stream
                },
                5000,
                1000
            ),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    %% 2-1
                    bidir_cnt := 1,
                    conn := _Conn,
                    event := streams_available,
                    module := quicer_connection
                },
                5000,
                1000
            ),

            {ok, _} = quicer_connection:stream_send(
                ClientConnPid,
                example_client_stream,
                <<"ping_from_example_3">>,
                ?QUIC_SEND_FLAG_NONE,
                #{
                    is_local => true,
                    open_flag => ?QUIC_STREAM_OPEN_FLAG_NONE,
                    start_flag => ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT,
                    quic_event_mask => ?QUICER_STREAM_EVENT_MASK_START_COMPLETE
                },
                infinity
            ),

            {SenderStm, ReceiverStm} = maps:get(
                master_stream_pair, quicer_connection:get_cb_state(ClientConnPid)
            ),
            ?assert(is_process_alive(ReceiverStm)),
            % with FIN flag
            ?assert(not is_process_alive(SenderStm)),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    event := peer_accepted,
                    module := quicer_stream
                },
                5000,
                1000
            ),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    data := <<"ping_from_example_2">>,
                    module := example_client_stream
                },
                5000,
                1000
            ),

            {ok, _} = ?block_until(
                #{
                    ?snk_kind := debug,
                    data := <<"ping_from_example_3">>,
                    module := example_client_stream
                },
                5000,
                1000
            ),

            H = quicer_connection:get_handle(ClientConnPid),
            gen_server:stop(ClientConnPid),
            H
        end,
        fun(Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            ?assert(undefined =/= Result),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example">>,
                        dir := unidir,
                        module := example_server_stream,
                        stream := _Stream1
                    },
                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example">>,
                        dir := remote_unidir,
                        module := example_client_stream,
                        stream := _Stream2
                    },
                    _Stream1 =/= _Stream2,
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        data := <<"flow_control.enable_bidi">>,
                        dir := unidir,
                        module := example_server_stream
                    },
                    #{
                        ?snk_kind := debug,
                        %% 2-1
                        bidir_cnt := 1,
                        conn := _Conn,
                        event := streams_available,
                        module := quicer_connection
                    },
                    Trace
                )
            ),

            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example_2">>,
                        dir := bidir,
                        module := example_server_stream,
                        stream := _Stream1
                    },

                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example_2">>,
                        dir := local_bidir,
                        module := example_client_stream,
                        stream := _Stream2
                    },
                    _Stream1 =/= _Stream2,
                    Trace
                )
            ),
            ?assert(
                ?strict_causality(
                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example_3">>,
                        dir := bidir,
                        module := example_server_stream,
                        stream := _Stream1
                    },

                    #{
                        ?snk_kind := debug,
                        data := <<"ping_from_example_3">>,
                        dir := local_bidir,
                        module := example_client_stream,
                        stream := _Stream2
                    },
                    _Stream1 =/= _Stream2,
                    Trace
                )
            )
        end
    ),
    ok.

tc_passive_recv_1(Config) ->
    ServerConnCallback = example_server_connection,
    ServerStreamCallback = example_server_stream,
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {peer_bidi_stream_count, 10},
        {peer_unidi_stream_count, 0}
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
    ct:pal("Listener Options: ~p", [Options]),
    ?my_check_trace(
        #{timetrap => 10000},
        begin
            {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{peer_bidi_stream_count, 10}, {peer_unidi_stream_count, 1} | default_conn_opts()],
                5000
            ),
            {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
            %% passive
            {ok, Stm2} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
            ct:pal("ping1 sent"),
            {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
            ct:pal("ping2 sent"),
            receive
                {quic, <<"ping1">>, Stm, _} -> ok
            after 100 -> ct:fail("no ping1")
            end,
            {ok, <<"p">>} = quicer:recv(Stm2, 1),
            {ok, <<"in">>} = quicer:recv(Stm2, 2),
            {ok, <<"g">>} = quicer:recv(Stm2, 1),
            {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
            %% left <<"3">> in buffer
            {ok, <<"2ping">>} = quicer:recv(Stm2, 5),
            {error, _} = quicer:recv(Stm2, 888),
            quicer:shutdown_connection(Conn)
        end,
        fun(_Result, Trace) ->
            ct:pal("Trace is ~p", [Trace]),
            Res = lists:filter(
                fun
                    (#{context := "nif", function := "recv2", tag := "consume"}) -> true;
                    (_) -> false
                end,
                Trace
            ),
            ct:pal("Res is ~p", [Res]),
            %% Check we consume in this order
            ConsumeOrder = ?projection(mark, Res),
            ?assert(
                ConsumeOrder == [1, 2, 1, 1, 4, 1] orelse
                    ConsumeOrder == [1, 2, 1, 5, 1]
            ),

            %% Check we only do one call
            ?assertEqual(
                1,
                length([
                    X
                 || #{
                        context := "nif",
                        function := "recv2",
                        tag := "more",
                        mark := 887
                    } = X <- Trace
                ])
            )
        end
    ),
    ok.

%%% Internal Helpers
default_stream_opts() ->
    [].

default_conn_opts() ->
    [
        {alpn, ["sample"]},
        %% {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
        {verify, none},
        {idle_timeout_ms, 5000}
    ].

default_listen_opts(Config) ->
    DataDir = ?config(data_dir, Config),
    [
        {certfile, filename:join(DataDir, "server.pem")},
        {keyfile, filename:join(DataDir, "server.key")},
        {alpn, ["sample"]},
        {verify, none},
        {idle_timeout_ms, 10000},
        %% some CI runner is slow on this
        {handshake_idle_timeout_ms, 10000},
        % QUIC_SERVER_RESUME_AND_ZERORTT
        {server_resumption_level, 2},
        {peer_bidi_stream_count, 10}
    ].

%% OS picks the available port
select_port() ->
    {ok, S} = gen_udp:open(0, [{reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(S),
    gen_udp:close(S),
    Port.

%% start quicer listener with retries
%% Mostly for MacOS where address reuse has different impl. than Linux
quicer_start_listener(Name, Port, Options) ->
    quicer_start_listener(Name, Port, Options, 10).
quicer_start_listener(Name, Port, Options, N) ->
    case quicer:spawn_listener(mqtt, Port, Options) of
        {ok, QuicApp} ->
            {ok, QuicApp};
        {error, listener_start_error, address_in_use} when N > 0 ->
            %% addr in use, retry....
            timer:sleep(200),
            quicer_start_listener(Name, Port, Options, N - 1);
        Error ->
            Error
    end.

wait_for_die([]) ->
    ok;
wait_for_die([Pid | T]) ->
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, Info} when
            Info =:= normal orelse Info =:= noproc
        ->
            wait_for_die(T)
    end.

%% @doc find the starting point of the test run
%%  some GC test may hit the Rid from previous run
flush_previous_run([], _StartingPointFun) ->
    %%% Oops, maybe wrong starting point
    [];
flush_previous_run([StartingPoint | T], StartingPoint) ->
    T;
flush_previous_run([Event | T], StartingPointFun) when is_function(StartingPointFun) ->
    case StartingPointFun(Event) of
        true ->
            T;
        false ->
            flush_previous_run(T, StartingPointFun)
    end;
flush_previous_run([_H | T], StartingPoint) ->
    flush_previous_run(T, StartingPoint).
%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
