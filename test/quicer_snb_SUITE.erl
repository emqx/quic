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
-module(quicer_snb_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer.hrl").

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
  [{timetrap,{seconds,30}}].

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
  application:ensure_all_started(quicer),
  application:ensure_all_started(snabbkaffe),
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
init_per_testcase(_TestCase, Config) ->
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
  snabbkaffe:cleanup(),
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
  [ tc_app_echo_server
  , tc_slow_conn
  , tc_stream_owner_down
  , tc_conn_owner_down
  , tc_conn_close_flag_1
  , tc_conn_close_flag_2
  , tc_conn_idle_close
  , tc_stream_close_errno
  , tc_conn_no_gc
  , tc_conn_no_gc_2
  , tc_conn_gc
  , tc_conn_resume_old
  , tc_conn_resume_nst
  , tc_conn_resume_nst_async
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
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
  ?check_trace(#{timetrap => 5000},
               begin
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 Resp = quicer:recv(Stm, 4),
                 ?assert(timeout =/=
                           ?block_until(
                              #{ ?snk_kind := debug
                               , context := "callback"
                               , function := "ServerStreamCallback"
                               , mark := ?QUIC_STREAM_EVENT_SEND_COMPLETE
                               , tag := "event"}, 3000, 3000)),
                 Resp
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual({ok, <<"ping">>}, Result),
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "ClientStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_COMPLETE
                                              , resource_id := _RidC
                                              },
                                             #{ ?snk_kind := debug
                                              , function := "ServerStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_RECEIVE
                                              , resource_id := _RidS
                                              },
                                             _RidC =/= _RidS,
                                             Trace))
               end),

  quicer:close_stream(Stm),
  quicer:close_connection(Conn),
  ok = quicer:stop_listener(mqtt).

tc_slow_conn(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
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
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "ServerListenerCallback"
                                              , tag := "acceptor_hit"
                                              , mark := 0
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , function := "async_handshake_1"
                                              , tag := "start"
                                              , mark := 0
                                              , resource_id := _Rid
                                              },
                                             Trace))
               end),
  ok.

tc_stream_owner_down(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 Pid = spawn(fun() ->
                                 receive down -> ok end
                             end),
                 quicer:controlling_process(Stm, Pid),
                 Pid ! down,
                 ?assert(timeout =/=
                           ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ServerStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000, 1000)),
                 ?assert(timeout =/=
                           ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ClientStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000, 1000)),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that stream down callback is triggered when stream owner process is dead
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "stream_controlling_process"
                                              , tag := "exit"
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , function := "resource_stream_down_callback"
                                              , tag := "start"
                                              , mark := 0
                                              , resource_id := _Rid
                                              },
                                             Trace)),
                   %% check that it triggers an immediate stream shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "resource_stream_down_callback"
                                              , tag := "start"
                                              , mark := 0
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              , resource_id := _Rid
                                              },
                                             Trace)),

                   %% check that client side immediate shutdown triggers a peer_send_abort event at server side
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              },
                                             #{ ?snk_kind := peer_send_aborted
                                              , module := quicer_stream
                                              , reason := 0
                                              },
                                             Trace))
                     end),
  ok.


tc_conn_owner_down(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:send(Stm, <<"ping">>),
                 {ok, <<"ping">>} = quicer:recv(Stm, 4),
                 {ok, SRid} = quicer:get_stream_rid(Stm),
                 Pid = spawn(fun() ->
                                 receive down -> ok end
                             end),
                 quicer:controlling_process(Conn, Pid),
                 Pid ! down,
                 ?assert(timeout =/=
                           ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ClientConnectionCallback", mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000, 1000)),
                 ?assert(timeout =/=
                           ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ServerConnectionCallback", mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000, 1000)),
                 ?assert(timeout =/=
                           ?block_until(
                              #{?snk_kind := quic_closed, module := quicer_conn_acceptor}, 1000, 1000)),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt),
                 {ok, CRid} = quicer:get_conn_rid(Conn),
                 {CRid, SRid}
               end,
               fun(Result, Trace) ->
                   {CRid, SRid} = Result,
                   ct:pal("Rid is ~p~n Sid is ~p~nTrace is ~p, ", [CRid, SRid,Trace]),
                   %% check that conn down callback is triggered when conn owner process is dead
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "connection_controlling_process"
                                              , tag := "exit"
                                              , resource_id := CRid
                                              },
                                             #{ ?snk_kind := debug
                                              , function := "resource_conn_down_callback"
                                              , tag := "start"
                                              , resource_id := CRid
                                              },
                                             Trace)),
                   %% check that it triggers an immediate connection shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "resource_conn_down_callback"
                                              , tag := "end"
                                              , resource_id := CRid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , resource_id := CRid
                                              },
                                             Trace)),
                   %% check that client side immediate shutdown triggers a stream shutdown
                   ?assert(?causality(#{ ?snk_kind := debug
                                       , function := "resource_conn_down_callback"
                                       , tag := "end"
                                       , resource_id := CRid
                                       },
                                      #{ ?snk_kind := debug
                                       , context := "callback"
                                       , function := "ClientStreamCallback"
                                       , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                       , tag := "event"
                                       , resource_id := SRid
                                       },
                                      Trace)),
                   %% check that client side conn shutdown happens after stream shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              , tag := "event"
                                              , resource_id := SRid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , resource_id := CRid
                                              },
                                             Trace)),
                   %% check that client side immediate shutdown triggers a close at server side
                   ?assert(?strict_causality( #{ ?snk_kind := quic_shutdown
                                               , module := quicer_conn_acceptor
                                               , '~meta' := #{pid := _PID}},
                                              #{ ?snk_kind := quic_closed
                                               , module := quicer_conn_acceptor
                                               ,'~meta' := #{pid := _PID}},
                                              Trace))
               end),
  ok.


tc_conn_close_flag_1(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),
                 {ok, _} = ?block_until(
                              #{ ?snk_kind := debug
                               , context := "callback"
                               , function := "ServerConnectionCallback"
                               , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                               , tag := "event"}, 1000, 3000),
                 {ok, _} = ?block_until(
                              #{ ?snk_kind := debug
                               , context := "callback"
                               , function := "ClientConnectionCallback"
                               , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                               , tag := "event"}, 1000, 3000),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% verify that client close_connection with default flag
                   %% triggers a close at server side
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
                                              , tag := "event"
                                              , resource_id := _CRid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , resource_id := _CRid
                                              },
                                             Trace))
               end),
  ok.

tc_conn_close_flag_2(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}

                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 111),
                 {ok, _} = ?block_until(
                              #{?snk_kind := debug
                               , context := "callback"
                               , function := "ClientConnectionCallback"
                               , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                               , tag := "event"}, 3000, 3000), %% assume idle_timeout_is 5s
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that client conn silent shutdown does not trigger
                   %% active connection shutdown at server side
                   ?assertEqual([], ?of_kind(quic_closed, Trace))
               end),
  ok.

tc_stream_close_errno(Config) ->
  Errno = 1234,
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 quicer:close_stream(Stm, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, Errno, 5000),
                 quicer:close_connection(Conn),
                 {ok, _} = ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ServerStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000),
                 {ok, _} = ?block_until(
                              #{?snk_kind := debug, context := "callback",
                                function := "ServerConnectionCallback", mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE,
                                tag := "event"}, 1000, 1000),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that server side
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerStreamCallback"
                                              , tag := "peer_send_aborted"
                                              , mark := Errno
                                              },
                                             Trace)),
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_PEER_SEND_ABORTED
                                              },
                                             #{ ?snk_kind := peer_send_aborted
                                              , module := quicer_stream
                                              , reason := Errno
                                              },
                                             Trace))
                     end),
  ok.


tc_conn_idle_close(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   , {idle_timeout_ms, 1000}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, [{idle_timeout_ms, 1000}, {alpn, ["sample"]}], 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 {ok, <<"ping">>} = quicer:recv(Stm, 4),
                 ?block_until(
                    #{?snk_kind := debug, context := "callback",
                      function := "ClientConnectionCallback", mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
                      }, 3000), %% server timeout is set to 1000
                 receive
                   {quic, transport_shutdown, _Conn, Status} ->
                     ct:pal("conn trans_shutdown status ~p~n", [Status])
                 end,
                 case quicer:async_send(Stm, <<"ping2">>) of
                   {error, stm_send_error, invalid_state} -> ok;
                   {error, cancelled} -> ok
                 end,

                 ?block_until(
                    #{?snk_kind := debug, context := "callback",
                      function := "ServerStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                      tag := "event"}, 2000, 1000),
                 ok
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that transport shutdown due to idle timeout is triggered at client side
                   %% check that shutdown_complete is triggered after idle timeout
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              },
                                             Trace)),

                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
                                              },
                                             Trace))
                     end),
  ct:pal("stop listener"),
  ok = quicer:stop_listener(mqtt),
  ok.

tc_conn_gc(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   , {idle_timeout_ms, 5000}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 %% Spawn a process that will die without handler cleanups
                 %% The dead process should trigger a connection close
                 %% The dead process should trigger a GC
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 _Child = spawn_link(fun() ->
                                         %% Note, the client process holds the ref to the `Conn', So `Conn' should get GC-ed when it dies.
                                         {ok, Conn} = quicer:connect("localhost", Port, [{idle_timeout_ms, 1000}, {alpn, ["sample"]}], 5000),
                                         {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                                         {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                                         {ok, <<"ping">>} = quicer:recv(Stm, 4)
                                     end),

                 %% Server Process
                 {ok, #{resource_id := _SRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ServerConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000),
                 %% Client Process
                 {ok, #{resource_id := CRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ClientConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000, 1000),
                 %% OTP GC callback
                 {ok, _} = ?block_until(#{ ?snk_kind := debug
                                         , context := "callback"
                                         , function := "resource_conn_dealloc_callback"
                                         , resource_id := CRid
                                         , tag := "end"},
                                        5000, 1000),
                 ok
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that at client side, GC is triggered after connection close.
                   %% check that at server side, connection was shutdown by client.
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , resource_id := _RidC
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "resource_conn_dealloc_callback"
                                              , resource_id := _RidC
                                              , tag := "end"},
                                             Trace)),
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
                                              , resource_id := _RidS
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , resource_id := _RidS
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , tag := "event"},
                                             Trace)),
                   ?assertEqual(1, length([ E || #{function := "resource_conn_dealloc_callback"
                                                  , tag := "end"} = E <- Trace]))
               end),
  ct:pal("stop listener"),
  ok = quicer:stop_listener(mqtt),
  ok.


tc_conn_no_gc(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   , {idle_timeout_ms, 1000}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 %% Spawn a client process that will close the connection explicitly before die.
                 %% The dead client process should trigger a connection close at server end.
                 %% The dead client process should not trigger a GC of 'Conn' because the parent process
                 %% still holds the 'Conn' var ref.
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 %% We hold a ref the Conn in this process, so Conn won't be gc-ed.
                 {ok, Conn} = quicer:connect("localhost", Port, [{idle_timeout_ms, 1000}, {alpn, ["sample"]}], 5000),
                 _Child = spawn_link(fun() ->
                                         {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                                         {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                                         {ok, <<"ping">>} = quicer:recv(Stm, 4),
                                         quicer:shutdown_connection(Conn, 0, 0)
                                     end),
                 %% Server Process
                 {ok, #{resource_id := _SRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ServerConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000, 1000),
                 %% Client Process
                 {ok, #{resource_id := CRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ClientConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000, 1000),
                 %% Give it time for gc that should not happen on var 'Conn', could be the source of flakiness.
                 %% We are rather testing the OTP behavior here but proves our understandings are correct.
                 %% OTP GC callback, should not happen
                 timeout = ?block_until(#{ ?snk_kind := debug
                                         , context := "callback"
                                         , function := "resource_conn_dealloc_callback"
                                         , resource_id := CRid
                                         , tag := "end"},
                                        5000, 1000),
                 {ok, CRid}

               end,
               fun({ok, CRid}, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   %% check that at server side, connection was shutdown by client.
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
                                              , resource_id := _RidS
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , resource_id := _RidS
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , tag := "event"},
                                             Trace)),
                   %% Check that there is no GC
                   ?assertEqual(0, length([ E || #{ function := "resource_conn_dealloc_callback"
                                                  , resource_id := Rid
                                                  } = E <- Trace, Rid == CRid]))
               end),
  ct:pal("stop listener"),
  ok = quicer:stop_listener(mqtt),
  ok.

tc_conn_no_gc_2(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   , {idle_timeout_ms, 1000}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 20000},
               begin
                 %% Spawn a client process that will close the connection explicitly before die.
                 %% The dead client process should trigger a connection close at server end.
                 %% The dead client process should not trigger a GC of 'ClientConn' because the parent process
                 %% still holds the 'ClientConn' var ref.
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 Parent = self(),
                 PRef = erlang:make_ref(),
                 _Child = spawn_link(fun() ->
                                         {ok, Conn} = quicer:connect("localhost", Port, [{idle_timeout_ms, 1000}, {alpn, ["sample"]}], 5000),
                                         {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                                         Parent ! {PRef, Conn, Stm},
                                         {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                                         {ok, <<"ping">>} = quicer:recv(Stm, 4),
                                         quicer:shutdown_connection(Conn, 0, 0)
                                     end),
                 {ClientConn, ClientStream} = receive
                                {PRef, C, S} -> {C, S}
                              end,
                 %% Server Process
                 {ok, #{resource_id := _SRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ServerConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000, 1000),
                 %% Client Process
                 {ok, #{resource_id := CRid}}
                   = ?block_until(#{ ?snk_kind := debug
                                   , context := "callback"
                                   , function := "ClientConnectionCallback"
                                   , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                   , tag := "event" },
                                  5000, 1000),
                 %% Give it time for GC of `Conn' that caused by dead client process.
                 %% But the resource dealloc callback should not be called since
                 %% we still have a ref in current process with Var: `ClientConn'
                 %% We are rather testing the OTP behavior here but proves our understandings are correct.
                 timeout = ?block_until(#{ ?snk_kind := debug
                                         , context := "callback"
                                         , function := "resource_conn_dealloc_callback"
                                         , resource_id := CRid
                                         , tag := "end"},
                                        5000, 1000),
                 timer:sleep(10000),
                 %% We can get segfault here if it is use-after-free
                 quicer:getstat(ClientConn, [send_cnt, recv_oct, send_pend]),
                 {ok, CRid}

               end,
               fun({ok, CRid}, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   %% check that at server side, connection was shutdown by client.
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER
                                              , resource_id := _RidS
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , resource_id := _RidS
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , tag := "event"},
                                             Trace)),
                   %% Check that there is no GC
                   ?assertEqual(0, length([ E || #{ function := "resource_conn_dealloc_callback"
                                                  , resource_id := Rid
                                                  } = E <- Trace, Rid == CRid]))
               end),
  ct:pal("stop listener"),
  ok = quicer:stop_listener(mqtt),
  ok.

%%% Resume connection with old connection handler
tc_conn_resume_old(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 {ok, <<"ping">>} = quicer:recv(Stm, 4),
                 quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

                 {ok, ConnResumed} = quicer:connect("localhost", Port, [{handler, Conn} | default_conn_opts()], 5000),
                 {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
                 {ok, 5} = quicer:async_send(Stm2, <<"ping2">>),
                 {ok, <<"ping2">>} = quicer:recv(Stm2, 5),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% 1. verify that for each success connect we send a resumption ticket
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_CONNECTED
                                              , tag := "event"
                                              , resource_id := _CRid1
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                              , resource_id := _CRid1
                                              },
                                             Trace)),
                   %% 2. verify that resumption ticket is recevied on client side
                   %%    and client use it to resume success
                     ?assert(?causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                              , tag := "event"
                                              , resource_id := _CRid1
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMED
                                              , resource_id := _SRid1
                                              },
                                             Trace))
               end),
  ok.

%%% Resume connection with connection opt: `nst'
tc_conn_resume_nst(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()], 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 {ok, <<"ping">>} = quicer:recv(Stm, 4),
                 NST = receive
                         {quic, nst_received, Conn, Ticket} ->
                           Ticket
                       after 1000 ->
                           ct:fail("No ticket received")
                       end,
                 quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

                 {ok, ConnResumed} = quicer:connect("localhost", Port, [{nst, NST} | default_conn_opts()], 5000),
                 {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
                 {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
                 {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% 1. verify that for each success connect we send a resumption ticket
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_CONNECTED
                                              , tag := "event"
                                              , resource_id := _CRid1
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                              , resource_id := _CRid1
                                              },
                                             Trace)),
                   %% 2. verify that resumption ticket is received on client side
                   %%    and client use it to resume success
                     ?assert(?causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                              , tag := "event"
                                              , resource_id := _CRid1
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ServerConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMED
                                              , resource_id := _SRid1
                                              },
                                             Trace))
               end),
  ok.


%%% Non-blocking connection resume, client could send app data without waiting for handshake done.
tc_conn_resume_nst_async(Config) ->
  Port = select_port(),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 10000},
               begin
                 {ok, _QuicApp} = quicer_start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, [{quic_event_mask, ?QUICER_CONNECTION_EVENT_MASK_NST} | default_conn_opts()], 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 {ok, <<"ping">>} = quicer:recv(Stm, 4),
                 NST = receive
                         {quic, nst_received, Conn, Ticket} ->
                           Ticket
                       after 1000 ->
                           ct:fail("No ticket received")
                       end,
                 quicer:close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 111),

                 {ok, ConnResumed} = quicer:async_connect("localhost", Port, [{nst, NST} | default_conn_opts()]),
                 {ok, Stm2} = quicer:start_stream(ConnResumed, [{active, false}]),
                 {ok, 5} = quicer:async_send(Stm2, <<"ping3">>),
                 {ok, <<"ping3">>} = quicer:recv(Stm2, 5),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% 1. verify that for each success connect we send a resumption ticket
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , mark := ?QUIC_CONNECTION_EVENT_CONNECTED
                                              , tag := "event"
                                              , resource_id := _CRid1
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                              , resource_id := _CRid1
                                              },
                                             Trace)),
                   %% 2. verify that resumption ticket is received on client side
                   %%    and client use it to resume success
                   ?assert(?causality(#{ ?snk_kind := debug
                                       , context := "callback"
                                       , function := "ClientConnectionCallback"
                                       , mark := ?QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
                                       , tag := "event"
                                       , resource_id := _CRid1
                                       },
                                      #{ ?snk_kind := debug
                                       , context := "callback"
                                       , function := "ServerConnectionCallback"
                                       , tag := "event"
                                       , mark := ?QUIC_CONNECTION_EVENT_RESUMED
                                       , resource_id := _SRid1
                                       },
                                      Trace))
               end),
  ok.

%%% Internal Helpers
default_stream_opts() ->
  [].

default_conn_opts() ->
  [ {alpn, ["sample"]}
  %% , {sslkeylogfile, "/tmp/SSLKEYLOGFILE"}
  , {idle_timeout_ms, 5000}
  ].

default_listen_opts(Config) ->
  DataDir = ?config(data_dir, Config),
  [ {cert, filename:join(DataDir, "cert.pem")}
  , {key,  filename:join(DataDir, "key.pem")}
  , {alpn, ["sample"]}
  , {idle_timeout_ms, 10000}
  , {server_resumption_level, 2} % QUIC_SERVER_RESUME_AND_ZERORTT
  , {peer_bidi_stream_count, 10}
  ].

%% OS picks the available port
select_port()->
  {ok, S} = gen_udp:open(0, [{reuseaddr, true}]),
  {ok, {_, Port}} = inet:sockname(S),
  gen_udp:close(S),
  Port.

%% start quicer listener with retries
%% Mostly for MacOS where address reuse has different impl. than Linux
quicer_start_listener(Name, Port, Options)->
  quicer_start_listener(Name, Port, Options, 10).
quicer_start_listener(Name, Port, Options, N) ->
  case quicer:start_listener(mqtt, Port, Options) of
    {ok, QuicApp} -> {ok, QuicApp};
    {error, listener_start_error, address_in_use} when N > 0 ->
      %% addr in use, retry....
      timer:sleep(200),
      quicer_start_listener(Name, Port, Options, N-1);
    Error ->
      Error
  end.


%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
