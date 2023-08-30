%%--------------------------------------------------------------------
%% Copyright (c) 2023 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-compile(export_all).
-compile(nowarn_export_all).

-import(quicer_test_lib, [ default_listen_opts/1
                         , default_conn_opts/0
                         , default_stream_opts/0
                         , select_free_port/1
                         ]).

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
  application:ensure_all_started(quicer),
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
  quicer_test_lib:all_tcs(?MODULE).

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
  ?assertEqual({error, config_error, invalid_parameter},
               quicer:listen(Port, [ {stream_recv_buffer_default, 1024} % too small
                                   | default_listen_opts(Config)])),
  ok.

tc_open_listener_inval_cacertfile_1(Config) ->
  Port = select_port(),
  ?assertEqual({error, badarg},
               quicer:listen(Port, [ {cacertfile, atom}
                                   | default_listen_opts(Config)])),
  ok.

tc_open_listener_inval_cacertfile_2(Config) ->
  Port = select_port(),
  {error, badarg} = quicer:listen(Port, [ {cacertfile, [1,2,3,4]}
                                        | default_listen_opts(Config)]),
  ok.

tc_open_listener_inval_cacertfile_3(Config) ->
  Port = select_port(),
  ?assertEqual({error, badarg},
               quicer:listen(Port, [ {cacertfile, [-1]}
                                   | default_listen_opts(Config)])),
  ok.

tc_open_listener(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, {_, Port}} = quicer:sockname(L),
  {error, eaddrinuse} = gen_udp:open(Port),
  ok = quicer:close_listener(L),
  {ok, P} = gen_udp:open(Port),
  ok = gen_udp:close(P),
  ok.

tc_open_listener_with_cert_password(Config) ->
  Port = select_port(),
  DataDir = ?config(data_dir, Config),
  PasswordCerts = [ {certfile, filename:join(DataDir, "server-password.pem")}
                  , {keyfile,  filename:join(DataDir, "server-password.key")}
                  , {password, quicer_test_lib:tls_server_key_password()}
                  ],
  {ok, L} = quicer:listen(Port, default_listen_opts(PasswordCerts ++ Config)),
  quicer:close_listener(L),
  ok.

tc_open_listener_with_wrong_cert_password(Config) ->
  Port = select_port(),
  DataDir = ?config(data_dir, Config),
  PasswordCerts = [ {certfile, filename:join(DataDir, "server-password.pem")}
                  , {keyfile,  filename:join(DataDir, "server-password.key")}
                  , {password, "123"}
                  ],
  ?assertMatch( {error, config_error, tls_error}
              , quicer:listen(Port, default_listen_opts(PasswordCerts ++ Config))).

tc_open_listener_bind(Config) ->
  ListenOn = "127.0.0.1:4567",
  {ok, L} = quicer:listen(ListenOn, default_listen_opts(Config)),
  {ok, {_, _}} = quicer:sockname(L),
  {error,eaddrinuse} = gen_udp:open(4567),
  ok = quicer:close_listener(L),
  {ok, P} = gen_udp:open(4567),
  ok = gen_udp:close(P),
  ok.

tc_open_listener_bind_v6(Config) ->
  ListenOn = "[::1]:4567",
  {ok, L} = quicer:listen(ListenOn, default_listen_opts(Config)),
  {ok, {_, _}} = quicer:sockname(L),
  {error,eaddrinuse} = gen_udp:open(4567, [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]),
  ok = quicer:close_listener(L),
  {ok, P} = gen_udp:open(4567, [{ip, {0, 0, 0, 0, 0, 0, 0, 1}}]),
  ok = gen_udp:close(P),
  ok.

tc_set_listener_opt(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Val = <<0, 1, 2, 3, 4, 5>>, %% must start with 0
  ok = quicer:setopt(L, param_listener_cibir_id, Val),
  {error, not_supported} = quicer:getopt(L, param_listener_cibir_id),
  quicer:close_listener(L).

tc_set_listener_opt_fail(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {error, _} = quicer:setopt(L, param_listener_cibir_id, <<1, 2, 3, 4, 5, 6>>),
  {error, not_supported} = quicer:getopt(L, param_listener_cibir_id),
  quicer:close_listener(L).

tc_get_listener_opt_addr(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, {{0, 0, 0, 0}, Port}} = quicer:getopt(L, param_listener_local_address),
  quicer:close_listener(L).

tc_get_listener_opt_stats(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, [{"total_accepted_connection", _},
        {"total_rejected_connection", _},
        {"binding_recv_dropped_packets", _}
       ]} = quicer:getopt(L, param_listener_stats),
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
  receive {'DOWN', Ref, process, Pid, L} ->
      quicer:close_listener(L)
  end.

tc_stop_start_listener(Config) ->
  Port = select_port(),
  LConf = default_listen_opts(Config),
  {ok, L} = quicer:listen(Port, LConf),
  ok = quicer:stop_listener(L),
  ok = quicer:start_listener(L, Port, LConf),
  ok = quicer:close_listener(L).

tc_stop_close_listener(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  ok = quicer:stop_listener(L),
  ok = quicer:close_listener(L, 0).

tc_start_listener_alpn_too_long(Config) ->
  Port = select_port(),
  {Pid, Ref} =
    spawn_monitor(fun() ->
                      {error, config_error, invalid_parameter}
                        = quicer:listen(Port, default_listen_opts(Config) ++
                                          [{alpn, [lists:duplicate(256, $p)]}])
                  end),
  receive {'DOWN', Ref, process, Pid, normal} ->
      ok
  end.

tc_start_acceptor_without_callback(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  ?assertEqual({error, missing_conn_callback},
               quicer_connection:start_link(undefined, L, {[],[],[]}, self())),
  quicer:close_listener(L).

tc_get_listeners(Config) ->
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Listeners = [ {alpn1, "127.0.0.1:24567"}
              , {alpn2, "0.0.0.1:24568"}
              , {alpn3, 24569}
              , {alpn4, "[::1]:24570"}
              ],
  Res = lists:map(
          fun({Alpn, ListenOn}) ->
              {ok, L} = quicer:spawn_listener(
                          Alpn, ListenOn,
                          {ListenerOpts, ConnectionOpts, StreamOpts}),
              L
          end, Listeners),
  ?assertEqual(lists:reverse(lists:zip(Listeners, Res)),
               quicer:listeners()),
  lists:foreach(fun({L, _}) -> ok = quicer:terminate_listener(L) end, Listeners).

tc_get_listener(Config) ->
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Listeners = [ {alpn1, "127.0.0.1:24567"}
              , {alpn2, "0.0.0.1:24568"}
              , {alpn3, 24569}
              , {alpn4, "[::1]:24570"}
              ],
  lists:map(fun({Alpn, ListenOn}) ->
                {ok, L} = quicer:spawn_listener(Alpn, ListenOn,
                                                {ListenerOpts, ConnectionOpts, StreamOpts}),
                L
            end, Listeners),

  lists:foreach(fun({Name, _} = NameListenON) ->
                    {ok, LPid} = quicer:listener(Name),
                    {ok, LPid} = quicer:listener(NameListenON),
                    true = is_process_alive(LPid)
                end, Listeners),

  lists:foreach(fun({L, _}) -> ok = quicer:terminate_listener(L) end, Listeners),

  lists:foreach(fun({Name, _} = NameListenON) ->
                    ?assertEqual({error, not_found}, quicer:listener(Name)),
                    ?assertEqual({error, not_found}, quicer:listener(NameListenON))
                end, Listeners),
  ?assertEqual({error, not_found}, quicer:listener(bad_listen_name)).

select_port() ->
  select_free_port(quic).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
