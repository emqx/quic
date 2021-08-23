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
%-include_lib("quicer/include/quicer.hrl").
-include("quicer_nif_macro.hrl").

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
  Port = 8888,
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   , {fast_conn, false}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4)
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
  Port = 8888,
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {fast_conn, false}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
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
                                              , tag := "fast_conn"
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
  Port = 8888,
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {fast_conn, false}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 Pid = spawn(fun() ->
                                 receive down -> ok end
                             end),
                 quicer:controlling_process(Stm, Pid),
                 Pid ! down,
                 ?block_until(
                    #{'$kind' := debug, context := "callback",
                      function := "ServerStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                      tag := "event"}, 1000),
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
                   %% check that it triggered a immediate stream shutdown
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
  Port = 8888,
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {fast_conn, false}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  ?check_trace(#{timetrap => 1000},
               begin
                 {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                 {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                 {ok, 4} = quicer:async_send(Stm, <<"ping">>),
                 quicer:recv(Stm, 4),
                 Pid = spawn(fun() ->
                                 receive down -> ok end
                             end),
                 quicer:controlling_process(Conn, Pid),
                 Pid ! down,
                 ?block_until(
                    #{'$kind' := debug, context := "callback",
                      function := "ServerStreamCallback", mark := ?QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE,
                      tag := "event"}, 1000),
                 ct:pal("stop listener"),
                 ok = quicer:stop_listener(mqtt)
               end,
               fun(Result, Trace) ->
                   ct:pal("Trace is ~p", [Trace]),
                   ?assertEqual(ok, Result),
                   %% check that conn down callback is triggered when conn owner process is dead
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "connection_controlling_process"
                                              , tag := "exit"
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , function := "resource_conn_down_callback"
                                              , tag := "start"
                                              , resource_id := _Rid
                                              },
                                             Trace)),
                   %% check that it triggered a immediate connection shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "resource_conn_down_callback"
                                              , tag := "end"
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              , resource_id := _Rid
                                              },
                                             Trace)),
                   %% check that client side immediate shutdown triggers a stream shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , function := "resource_conn_down_callback"
                                              , tag := "end"
                                              , resource_id := _Rid
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              , tag := "event"
                                              },
                                             Trace)),
                   %% check that client side conn shutdown happens after stream shutdown
                   ?assert(?strict_causality(#{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientStreamCallback"
                                              , mark := ?QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
                                              , tag := "event"
                                              },
                                             #{ ?snk_kind := debug
                                              , context := "callback"
                                              , function := "ClientConnectionCallback"
                                              , tag := "event"
                                              , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                              },
                                             Trace)),
                   %% check that client side immediate shutdown triggers a close at server side
                   ?assertMatch([{pair, _, _}],
                                ?find_pairs(true,
                                            #{ ?snk_kind := debug
                                             , context := "callback"
                                             , function := "ClientConnectionCallback"
                                             , tag := "event"
                                             , mark := ?QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
                                             },
                                            #{ ?snk_kind := quic_closed
                                             , module := quicer_conn_acceptor
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



%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
