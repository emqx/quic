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

-module(quicer_SUITE).
-include_lib("kernel/include/file.hrl").
-include("quicer.hrl").

%% API
-export([all/0,
         suite/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         group/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% test cases
-export([ tc_nif_module_load/1
        , tc_nif_module_unload/1
        , tc_nif_module_reload/1
        , tc_open_lib_test/1
        , tc_close_lib_test/1
        , tc_lib_registration/1
        , tc_lib_registration_1/1
        , tc_lib_re_registration/1
        , tc_lib_registration_neg/1
        , tc_open_listener/1
        , tc_open_listener_bind/1
        , tc_open_listener_bind_v6/1
        , tc_open_listener_neg_1/1
        , tc_open_listener_neg_2/1
        , tc_close_listener/1
        , tc_get_listeners/1
        , tc_get_listener/1

        , tc_conn_basic/1
        , tc_conn_basic_slow_start/1
        , tc_conn_timeout/1
        , tc_async_conn_timeout/1
        , tc_conn_double_close/1
        , tc_conn_other_port/1
        , tc_conn_with_localaddr/1
        , tc_conn_controlling_process/1

        , tc_stream_client_init/1
        , tc_stream_client_send_binary/1
        , tc_stream_client_send_iolist/1
        , tc_stream_client_async_send/1

        , tc_stream_passive_receive/1
        , tc_stream_passive_receive_buffer/1
        , tc_stream_passive_receive_large_buffer_1/1
        , tc_stream_passive_receive_large_buffer_2/1
        , tc_stream_send_after_conn_close/1
        , tc_stream_send_after_async_conn_close/1
        , tc_stream_sendrecv_large_data_passive/1
        %% @deprecated
        %%, tc_stream_sendrecv_large_data_passive_2/1
        , tc_stream_sendrecv_large_data_active/1
        , tc_stream_passive_switch_to_active/1
        , tc_stream_active_switch_to_passive/1
        , tc_stream_controlling_process/1

        , tc_dgram_client_send/1

        % , tc_getopt_raw/1
        , tc_getopt/1
        , tc_setopt_bad_opt/1
        , tc_getopt_stream_active/1
        , tc_setopt/1

        %% @TODO following two tcs are failing due to:
        %  https://github.com/microsoft/msquic/issues/2033
        % , tc_setopt_conn_local_addr/1
        % , tc_setopt_conn_local_addr_in_use/1
        , tc_setopt_stream_priority/1
        , tc_strm_opt_active_n/1
        , tc_strm_opt_active_once/1
        , tc_strm_opt_active_1/1
        , tc_strm_opt_active_badarg/1
        , tc_conn_opt_sslkeylogfile/1
        , tc_get_stream_id/1
        , tc_getstat/1
        , tc_getstat_closed/1
        , tc_peername_v4/1
        , tc_peername_v6/1

        , tc_alpn/1
        , tc_alpn_mismatch/1
        , tc_idle_timeout/1


        , tc_get_conn_rid/1
        , tc_get_stream_rid/1

        , tc_stream_open_flag_unidirectional/1
        , tc_stream_start_flag_fail_blocked/1
        , tc_stream_start_flag_immediate/1
        , tc_stream_start_flag_shutdown_on_fail/1
        , tc_stream_start_flag_indicate_peer_accept_1/1
        %% insecure, msquic only
        , tc_insecure_traffic/1

        %% counters,
        , tc_perf_counters/1

        %% stream event masks
        , tc_event_start_compl/1
        %% testcase to verify env works
        %% , tc_network/1
        ]).

-export([tc_app_echo_server/1]).

%% -include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(PROPTEST(M,F), true = proper:quickcheck(M:F())).

all() ->
  lists:filtermap(
    fun({Fun, _A}) ->
        lists:prefix("tc_", atom_to_list(Fun))
          andalso {true, Fun}
    end, ?MODULE:module_info(exports)).

suite() ->
  [{ct_hooks,[cth_surefire]}, {timetrap, {seconds, 30}}].

groups() ->
  [
   %% TODO: group definitions here e.g.
   %% {crud, [], [
   %%          t_create_resource,
   %%          t_read_resource,
   %%          t_update_resource,
   %%          t_delete_resource
   %%         ]}

  ].

%%%===================================================================
%%% Overall setup/teardown
%%%===================================================================
init_per_suite(Config) ->
  application:ensure_all_started(quicer),
  Config.

end_per_suite(_Config) ->
  ok.


%%%===================================================================
%%% Group specific setup/teardown
%%%===================================================================
group(_Groupname) ->
  [].

init_per_group(_Groupname, Config) ->
  Config.

end_per_group(_Groupname, _Config) ->

  ok.


%%%===================================================================
%%% Testcase specific setup/teardown
%%%===================================================================
init_per_testcase(_TestCase, Config) ->
  [{timetrap, 5000} | Config].

end_per_testcase(tc_close_lib_test, _Config) ->
  quicer:open_lib();
end_per_testcase(tc_lib_registration, _Config) ->
  quicer:reg_open();
end_per_testcase(tc_lib_re_registration, _Config) ->
  quicer:reg_open();
end_per_testcase(tc_open_listener_neg_1, _Config) ->
  quicer:open_lib(),
  quicer:reg_open();
end_per_testcase(_TestCase, _Config) ->
  quicer:stop_listener(mqtt),
  ok.

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================
%% tc_network(_Config) ->
%%   {ok, _} = gen_tcp:listen(12456, []),
%%   {ok, _} = gen_udp:open(12456, []).

tc_nif_module_load(_Config) ->
  {module, quicer_nif} = c:l(quicer_nif).

tc_nif_module_unload(_Config) ->
  M = quicer_nif,
  case code:delete(M) of
    false -> code:purge(M);
    true -> ok
  end,
  true = code:delete(M).

tc_nif_module_reload(_Config) ->
  M = quicer_nif,
  c:l(M),
  {module, M} = c:l(M),
  ok.

tc_open_lib_test(_Config) ->
  {ok, false} = quicer:open_lib(),
  %% verify that reopen lib success.
  {ok, false} = quicer:open_lib().

tc_close_lib_test(_Config) ->
  {ok, false} = quicer:open_lib(),
  %% @todo  close reg before close lib
  ok = quicer:reg_close(),
  ok = quicer:close_lib(),
  ok = quicer:close_lib(),
  {ok, Res0} = quicer:open_lib(),
  ?assert(Res0 == true orelse Res0 == debug).

tc_lib_registration_neg(_Config) ->
  ok = quicer:close_lib(),
  {error, badarg} = quicer:reg_open(),
  ok = quicer:reg_close().

tc_lib_registration(_Config) ->
  quicer:open_lib(),
  ok = quicer:reg_open(),
  ok = quicer:reg_close().

tc_lib_registration_1(_Config) ->
  ok =quicer:reg_close(),
  {error, badarg} = quicer:reg_open(foo),
  ok = quicer:reg_open(quic_execution_profile_low_latency),
  ok =quicer:reg_close(),
  ok = quicer:reg_open(quic_execution_profile_type_real_time),
  ok = quicer:reg_close(),
  ok = quicer:reg_open(quic_execution_profile_type_max_throughput),
  ok = quicer:reg_close(),
  ok = quicer:reg_open(quic_execution_profile_type_scavenger),
  ok = quicer:reg_close().

tc_open_listener_neg_1(Config) ->
  Port = select_port(),
  ok = quicer:reg_close(),
  ok = quicer:close_lib(),
  {error, config_error, reg_failed} = quicer:listen(Port, default_listen_opts(Config)),
  ok.

tc_open_listener_neg_2(Config) ->
  {error, badarg} = quicer:listen("localhost:4567", default_listen_opts(Config)),
  %% following test should fail, but msquic has some hack to let it pass, ref: MsQuicListenerStart in msquic listener.c
  %% {error, badarg} = quicer:listen("8.8.8.8:4567", default_listen_opts(Config)),
  ok.

tc_lib_re_registration(_Config) ->
  case quicer:reg_open() of
    ok ->
      ok;
    {error, _} ->
      ok = quicer:reg_close(),
      ok = quicer:reg_open()
  end,
  {error, badarg} = quicer:reg_open(),
  ok = quicer:reg_close(),
  ok = quicer:reg_close().

tc_open_listener(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, {_, Port}} = quicer:sockname(L),
  {error, eaddrinuse} = gen_udp:open(Port),
  ok = quicer:close_listener(L),
  {ok, P} = gen_udp:open(Port),
  ok = gen_udp:close(P),
  ok.

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

tc_close_listener(_Config) ->
  {error,badarg} = quicer:close_listener(make_ref()).

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
  Res = lists:map(fun({Alpn, ListenOn}) ->
                      {ok, L} = quicer:start_listener(Alpn, ListenOn,
                                                     {ListenerOpts, ConnectionOpts, StreamOpts}),
                      L
                  end, Listeners),
  ?assertEqual(lists:reverse(lists:zip(Listeners, Res)),
               quicer:listeners()),
  lists:foreach(fun({L, _}) -> ok = quicer:stop_listener(L) end, Listeners).

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
                {ok, L} = quicer:start_listener(Alpn, ListenOn,
                                                {ListenerOpts, ConnectionOpts, StreamOpts}),
                L
            end, Listeners),

  lists:foreach(fun({Name, _} = NameListenON) ->
                    {ok, LPid} = quicer:listener(Name),
                    {ok, LPid} = quicer:listener(NameListenON),
                    true = is_process_alive(LPid)
                end, Listeners),

  lists:foreach(fun({L, _}) -> ok = quicer:stop_listener(L) end, Listeners),
  
  lists:foreach(fun({Name, _} = NameListenON) ->
                    ?assertEqual({error, not_found}, quicer:listener(Name)),
                    ?assertEqual({error, not_found}, quicer:listener(NameListenON))
                end, Listeners),
  ?assertEqual({error, not_found}, quicer:listener(bad_listen_name)).

tc_conn_basic(Config) ->
  {Pid, Ref} = spawn_monitor(fun() -> run_tc_conn_basic(Config) end),
  receive
    {'DOWN', Ref, process, Pid, normal} ->
      ok;
    {'DOWN', Ref, process, Pid, Error} ->
      ct:fail({run_error, Error})
  end.

run_tc_conn_basic(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ct:pal("closing connection : ~p", [Conn]),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_basic_slow_start(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_slow_conn_server(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_timeout(Config)->
  Port = select_port(),
  Owner = self(),
  TOut = 10,
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_slow_conn_server(Owner, Config, Port, TOut*2)
                   end),
  receive
    listener_ready ->
      {error, timeout} = quicer:connect("localhost", Port, default_conn_opts(), TOut),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_async_conn_timeout(Config)->
  Port = select_port(),
  Owner = self(),
  Tout = 100,
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_slow_conn_server(Owner, Config, Port, Tout*2)
                   end),
  receive
    listener_ready ->
      {ok, H} = quicer:async_connect("localhost", Port, [{handshake_idle_timeout_ms, Tout} |
                                                         default_conn_opts()]),
      receive
        {quic, transport_shutdown, H, Reason} ->
          %% silent local close
          ?assertEqual(connection_idle, Reason)
       after Tout * 5 ->
           ct:fail("conn didn't timeout")
      end,
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_double_close(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      quicer:async_close_connection(Conn),
      %% Wait for it crash if it will
      timer:sleep(1000),
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_other_port(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> simple_conn_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_with_localaddr(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> simple_conn_server(Owner, Config, Port) end),

  {ok, CPort0} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
  {ok, {{127, 0, 0, 1}, PortX}} = inet:sockname(CPort0),
  ok = gen_udp:close(CPort0),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, [{param_conn_local_address, "127.0.0.1:" ++ integer_to_list(PortX)}
                                                     | default_conn_opts()], 5000),
      ?assertEqual({ok, {{127,0,0,1}, PortX}}, quicer:sockname(Conn)),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_client_init(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> simple_stream_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_stream(Stm),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.


tc_stream_client_send_binary(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      receive
        {quic, streams_available, Conn, _, _} -> ok
      end,
      receive
        {quic, <<"pong">>, _, _, _, _} ->
          ok = quicer:close_stream(Stm),
          ok = quicer:close_connection(Conn);
        Other ->
          ct:fail("Unexpected Msg ~p", [Other])
      end,
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_client_send_iolist(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, ["p", ["i", ["n"]], <<"g">>]),
      receive
        {quic, streams_available, Conn, _, _} -> ok
      end,
      receive
        {quic, <<"pong">>, _, _, _, _} ->
          ok = quicer:close_stream(Stm),
          ok = quicer:close_connection(Conn);
        Other ->
          ct:fail("Unexpected Msg ~p", [Other])
      end,
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_client_async_send(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:async_send(Stm, <<"ping">>),
      receive
        {quic, streams_available, Conn, _, _} -> ok
      end,
      receive
        {quic, <<"pong">>, _, _, _, _} ->
          ok = quicer:close_stream(Stm),
          ok = quicer:close_connection(Conn);
        Other ->
          ct:fail("Unexpected Msg ~p", [Other])
      end,
      SPid ! done,
      receive
        {quic, send_completed, _Stm, _} -> ct:fail("shouldn't recv send_completed")
      after 0 ->
            ok
      end,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_sendrecv_large_data_passive(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                  fun() ->
                      echo_server(Owner, [{stream_recv_window_default, 1048576} | Config], Port)
                  end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port,
                                  [{stream_recv_window_default, 1048576} | default_conn_opts()], 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      TestData = crypto:strong_rand_bytes(1000000),
      {ok, _} = quicer:async_send(Stm, TestData),
      {ok, TestData} = quicer:recv(Stm, byte_size(TestData)),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

%% We decide not to check the default recv window since it is too expensive.
%% tc_stream_sendrecv_large_data_passive_2(Config) ->
%%   %% test when stream_recv_window_default isn't large enough
%%   Port = select_port(),
%%   Owner = self(),
%%   {SPid, Ref} = spawn_monitor(
%%                   fun() ->
%%                       echo_server(Owner, Config, Port)
%%                   end),
%%   receive
%%     listener_ready ->
%%       {ok, Conn} = quicer:connect("localhost", Port,
%%                                   default_conn_opts(), 5000),
%%       {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
%%       TestData = crypto:strong_rand_bytes(1000000),
%%       {ok, _} = quicer:async_send(Stm, TestData),
%%       {error, stream_recv_window_too_small} = quicer:recv(Stm, byte_size(TestData)),
%%       SPid ! done,
%%       ensure_server_exit_normal(Ref)
%%   after 6000 ->
%%       ct:fail("timeout")
%%   end.

tc_stream_sendrecv_large_data_active(Config) ->
  %% test when stream_recv_window_default isn't large enough
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                  fun() ->
                      echo_server(Owner, Config, Port)
                  end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port,
                                  default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
      TestData = crypto:strong_rand_bytes(1000000),
      {ok, _} = quicer:async_send(Stm, TestData),
      TestData = active_recv(Stm, byte_size(TestData)),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_switch_to_active(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 12} = quicer:send(Stm, <<"ping_passive">>),
      {ok, <<"ping_passive">>} = quicer:recv(Stm, 0),
      quicer:setopt(Stm, active, true),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      {error, einval} = quicer:recv(Stm, 0),
      receive
        {quic, <<"ping_active">>, Stm, _, _, _} -> ok
      end,
      quicer:setopt(Stm, active, 100),
      {ok, 13} = quicer:send(Stm, <<"ping_active_2">>),
      receive
        {quic, <<"ping_active_2">>, Stm, _, _, _} -> ok
      end,
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_active_switch_to_passive(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      receive
        {quic, streams_available, Conn, _, _} -> ok
      end,
      {error, einval} = quicer:recv(Stm, 0),
      receive
        {quic, <<"ping_active">>, Stm, _, _, _} -> ok
      end,
      quicer:setopt(Stm, active, false),
      {ok, 12} = quicer:send(Stm, <<"ping_passive">>),
      {ok, <<"ping_passive">>} = quicer:recv(Stm, 0),
      receive
        Other -> ct:fail("Unexpected recv : ~p", [Other])
      after 0 ->
          ok
      end,
      {ok, 14} = quicer:send(Stm, <<"ping_passive_2">>),
      {ok, <<"ping_passive_2">>} = quicer:recv(Stm, 0),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      quicer:close_stream(Stm),
      quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive_buffer(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"p">>} = quicer:recv(Stm, 1),
      {ok, <<"on">>} = quicer:recv(Stm, 2),
      {ok, <<"g">>} = quicer:recv(Stm, 0),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.


tc_stream_passive_receive_large_buffer_1(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      %% put some sleep to ensure server side won't send the data in batch
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      %% put some sleep to ensure server side won't send the data in batch
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pingpingping">>} = quicer:recv(Stm, 12),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive_large_buffer_2(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, <<"pongpongpong">>} = quicer:recv(Stm, 12),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_send_after_conn_close(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> simple_stream_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, {_, _}} = quicer:sockname(Conn),
      %% Next close_connection call has two scenarios:
      %% a) Just close connection, stream is not created in QUIC
      %% b) Close the connection after the stream is created in QUIC
      ok = quicer:close_connection(Conn),
      {error, stm_send_error, aborted} = quicer:send(Stm, <<"ping2">>),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_send_after_async_conn_close(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> simple_stream_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, {_, _}} = quicer:sockname(Conn),
      %% Send some data otherwise stream will never get started.
      quicer:send(Stm, <<"ping1">>),
      ok = quicer:async_close_connection(Conn),
      %% we created a race here, the send can success or fail
      %% but it should not crash
      quicer:send(Stm, <<"ping2">>),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_controlling_process(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      ok = quicer:controlling_process(Stm, self()),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      {ok, _} = quicer:recv(Stm, 11),
      {NewOwner, MonRef} = spawn_monitor(
                             fun() ->
                                 receive
                                   {quic, <<"owner_changed">>, Stm, _, _, _} ->
                                     ok = quicer:async_close_stream(Stm)
                                 end
                             end),
      ok = quicer:controlling_process(Stm, NewOwner),
      ok = quicer:setopt(Stm, active, true),
      {ok, _Len} = quicer:send(Stm, <<"owner_changed">>),
      receive
        {'DOWN', MonRef, process, NewOwner, normal} ->
          SPid ! done
      end,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_dgram_client_send(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server_dgram(Owner, Config, Port) end),
  receive
    listener_ready ->
      Opts = default_conn_opts() ++ [{datagram_receive_enabled, 1}],
      {ok, Conn} = quicer:connect("localhost", Port, Opts, 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, 4} = quicer:send_dgram(Conn, <<"ping">>),
      receive
        {quic, streams_available, Conn, _, _} -> ok
      end,
      dgram_client_recv_loop(Conn, false, false),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
    ct:fail("timeout here")
  end.

dgram_client_recv_loop(Conn, true, true) ->
  ok = quicer:close_connection(Conn);

dgram_client_recv_loop(Conn, ReceivedOnStream, ReceivedViaDgram) ->
  receive
    {quic, dgram, <<"pong">>} ->
      dgram_client_recv_loop(Conn, ReceivedOnStream, true);
    {quic, <<"pong">>, _, _, _, _} ->
      dgram_client_recv_loop(Conn, true, ReceivedViaDgram);
    {quic, dgram_max_len, _} ->
      dgram_client_recv_loop(Conn, ReceivedOnStream, ReceivedViaDgram);
    Other ->
      ct:fail("Unexpected Msg ~p", [Other])
  end.

tc_conn_controlling_process(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      ok = quicer:controlling_process(Conn, self()),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      {ok, _} = quicer:recv(Stm, 11),
      {NewOwner, MonRef} = spawn_monitor(
                             fun() ->
                                 receive
                                   {quic, closed, Conn} ->
                                     ok
                                 end
                             end),
      ok = quicer:controlling_process(Conn, NewOwner),
      %% Trigger *async* connection shutdown since I am not the conn owner
      quicer:async_shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0),
      receive
        {'DOWN', MonRef, process, NewOwner, normal} ->
          SPid ! done
      end,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

%% tc_getopt_raw(Config) ->
%%   Parm = param_conn_quic_version,
%%   Port = select_port(),
%%   Owner = self(),
%%   {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
%%   receive
%%     listener_ready ->
%%       {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 1000),
%%       {ok, <<1,0,0,0>>} = quicer:getopt(Conn, Parm),
%%       {ok, Stm} = quicer:start_stream(Conn, []),
%%       timer:sleep(10),
%%       {ok, 4} = quicer:send(Stm, <<"ping">>),
%%       receive {quic, <<"ping">>, Stm, _, _, _} -> ok end,
%%       {ok, <<1,0,0,0>>} = quicer:getopt(Stm, Parm),
%%       ok = quicer:close_connection(Conn),
%%       SPid ! done,
%%       ensure_server_exit_normal(Ref)
%%   after 3000 ->
%%       ct:fail("listener_timeout")
%%   end.

tc_getopt(Config) ->
  Parm = param_conn_statistics,
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stats} = quicer:getopt(Conn, Parm, false),
      {ok, false} = quicer:getopt(Conn, param_conn_disable_1rtt_encryption, false),
      0 = proplists:get_value("Recv.DroppedPackets", Stats),
      [true = proplists:is_defined(SKey, Stats)
       || SKey <- ["Send.TotalPackets", "Recv.TotalPackets"]],
      {ok, Settings} = quicer:getopt(Conn, param_conn_settings, false),
      5000 = proplists:get_value(idle_timeout_ms, Settings),
      true = proplists:get_value(send_buffering_enabled, Settings),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      receive {quic, <<"ping">>, Stm, _, _, _} -> ok end,
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_getopt_stream_active(Config) ->
  Parm = active,
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {error,param_error} = quicer:getopt(Conn, Parm, false),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      receive {quic, <<"ping">>, Stm, _, _, _} -> ok end,
      {ok, true} = quicer:getopt(Stm, Parm, false),
      ok = quicer:setopt(Stm, active, false),
      {ok, false} = quicer:getopt(Stm, Parm, false),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_get_stream_id(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, 0} = quicer:get_stream_id(Stm),
      {ok, Stm2} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm2, <<"ping">>),
      {ok, 4} = quicer:get_stream_id(Stm2),
      {ok, Stm3} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm3, <<"ping">>),
      {ok, 8} = quicer:get_stream_id(Stm3),
      {error, param_error} = quicer:get_stream_id(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 5000 ->
      ct:fail("listener_timeout")
  end.


tc_getstat(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, [{send_cnt, _}, {recv_oct, _}, {send_pend, _}]} =
        quicer:getstat(Conn, [send_cnt, recv_oct, send_pend]),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_getstat_closed(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      receive {quic, _, _, _,_,_} -> ok end,
      ok = quicer:close_stream(Stm),
      ok = quicer:close_connection(Conn),
      case quicer:getstat(Conn, [send_cnt, recv_oct, send_pend]) of
        {error,invalid_parameter} -> ok;
        {error,invalid_state} -> ok;
        {error, closed} -> ok;
        {ok, [_|_]} ->
          %% We still hold a ref in Var Conn, and the Conn is not closed in MsQuic
          ok
      end,
      %ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_peername_v6(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("::1", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, badarg} = quicer:peername(0),
      {ok, {Addr, RPort}} = quicer:peername(Conn),
      %% checks
      true = is_integer(RPort),
      ct:pal("addr is ~p", [Addr]),
      "::1" = inet:ntoa(Addr),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_peername_v4(Config) ->
  Port = select_port(),
  Owner = self(),
  {_SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, badarg} = quicer:peername(0),
      {ok, {Addr, RPort}} = quicer:peername(Conn),
      %% checks
      true = is_integer(RPort),
      ct:pal("addr is ~p", [Addr]),
      "127.0.0.1" =  inet:ntoa(Addr),
      ok = quicer:close_connection(Conn)
      %{error, _} = quicer:peername(Conn)
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_alpn(Config) ->
  Port = select_port(),
  Owner = self(),
  Opts = lists:keyreplace(alpn, 1, default_listen_opts(Config), {alpn, ["sample2", "sample"]}),
  {SPid, _Ref} = spawn_monitor(fun() -> conn_server_with(Owner, Port, Opts) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 1000 ->
    ct:fail("timeout")
  end.

tc_alpn_mismatch(Config) ->
  Port = select_port(),
  Owner = self(),
  Opts = lists:keyreplace(alpn, 1, default_listen_opts(Config), {alpn, ["no"]}),
  {SPid, _Ref} = spawn_monitor(fun() -> conn_server_with(Owner, Port, Opts) end),
  receive
    listener_ready ->
      spawn_monitor(fun() ->
                        Res = quicer:connect("localhost", Port, default_conn_opts(), 5000),
                        Owner ! Res end),
      receive
        ok ->
          ct:fail("illegal connection");
        {error, transport_down} ->
          ok
      after 1000 ->
        SPid ! done
      end
  after 1000 ->
    ct:fail("timeout")
  end.

tc_idle_timeout(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      Opts = lists:keyreplace(idle_timeout_ms, 1, default_conn_opts(), {idle_timeout_ms, 100}),
      {ok, Conn} = quicer:connect("localhost", Port, Opts, 5000),
      {ok, Stm0} = quicer:start_stream(Conn, []),
      {ok, 5} = quicer:send(Stm0, <<"ping0">>),
      timer:sleep(5000),
      case quicer:start_stream(Conn, []) of
        {error, ctx_init_failed} ->
          %% connection is closing
          ok;
        {error, stm_open_error, invalid_parameter} ->
          %% connection is closed
          ok;
        {error, stm_open_error, invalid_state} ->
          %% Invalid state
          ok
      end,
      SPid ! done,
      ensure_server_exit_normal(Ref)
  end.


tc_setopt(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm0} = quicer:start_stream(Conn, [{active, false}]),
      %% Stream 0
      {ok, 5} = quicer:send(Stm0, <<"ping0">>),
      {ok, <<"ping0">>} = quicer:recv(Stm0, 0),
      %% Stream 1 but get blocked due to stream count
      {ok, Stm1} = quicer:start_stream(Conn, [{active, true}]),
      {ok, 5} = quicer:send(Stm1, <<"ping1">>),
      receive
        {quic, _Data, Stm1, _, _, _} = Msg ->
          ct:fail("unexpected_recv ~p ", [Msg])
      after 1000 ->
                ok
      end,

      %% unblock Stream 1
      SPid ! {set_stm_cnt, 3},

      receive
        {quic, <<"ping1">>, Stm1, _, _, _} ->
          ok
      after 1000 ->
          ct:fail("sending is still blocked", [])
      end,
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 5000 ->
    ct:fail("listener_timeout")
  end.

tc_setopt_bad_opt(_Config)->
  Port = select_port(),
  {error, param_error} = quicer:connect("localhost", Port,
                                        [{nst, foobar} %% BAD opt
                                        | default_conn_opts()], 5000).


tc_setopt_conn_local_addr(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),

  receive
    listener_ready ->
      ok
  after 5000 ->
    ct:fail("listener_timeout")
  end,

  {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 5000),
  {ok, Stm0} = quicer:start_stream(Conn, [{active, true}]),
  {ok, 5} = quicer:send(Stm0, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm0, _, _, _} ->
      ok
  after 1000 ->
      ct:fail("recv ping1 timeout")
  end,
  {ok, OldAddr} = quicer:sockname(Conn),
  %% change local addr with a new random port (0)
  ?assertEqual(ok, quicer:setopt(Conn, param_conn_local_address, "127.0.0.1:0")),
  %% sleep is needed to finish migration at protocol level
  timer:sleep(100),
  {ok, NewAddr} = quicer:sockname(Conn),
  ?assertNotEqual(OldAddr, NewAddr),
  ?assertNotEqual({ok, {{127,0,0,1}, 50600}}, NewAddr),
  ?assertNotEqual({ok, {{127,0,0,1}, 50600}}, OldAddr),
  %% change local addr with a new port 5060
  ?assertEqual(ok, quicer:setopt(Conn, param_conn_local_address, "127.0.0.1:50600")),
  %% sleep is needed to finish migration at protocol level
  retry_with(fun() ->
                 timer:sleep(100),
                 case quicer:sockname(Conn) of
                   {ok, {{127,0,0,1}, 50600}} -> true;
                   {ok, Other} -> {false, Other}
                 end
             end, 20, "addr migration failed"),
  {ok, 5} = quicer:send(Stm0, <<"ping2">>),
  receive
    {quic, <<"ping2">>, Stm0, _, _, _} ->
      ok
  after 1000 ->
      ct:fail("recv ping2 timeout")
  end,
  %% check with server if peer addr is correct.
  SPid ! {peer_addr, self()},
  receive {peer_addr, Peer} -> ok end,
    ?assertEqual({ok, {{127,0,0,1}, 50600}}, Peer),
  SPid ! done,
  ensure_server_exit_normal(Ref).

tc_setopt_conn_local_addr_in_use(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      ok
  after 5000 ->
    ct:fail("listener_timeout")
  end,
  {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 5000),
  {ok, Stm0} = quicer:start_stream(Conn, [{active, true}]),
  {ok, 5} = quicer:send(Stm0, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm0, _, _, _} ->
      ok
  after 1000 ->
      ct:fail("recv ping1 timeout")
  end,
  {ok, OldAddr} = quicer:sockname(Conn),
  %% change local addr with a new random port (0)
  ?assertEqual(ok, quicer:setopt(Conn, param_conn_local_address, "127.0.0.1:0")),
  %% sleep is needed to finish migration at protocol level
  timer:sleep(50),
  {ok, NewAddr} = quicer:sockname(Conn),
  ?assertNotEqual(OldAddr, NewAddr),
  ?assertNotEqual({ok, {{127,0,0,1}, 50600}}, NewAddr),
  ?assertNotEqual({ok, {{127,0,0,1}, 50600}}, OldAddr),

  %% Occupy 50600
  {ok, ESocket} = gen_udp:open(50600, [{ip, element(1, NewAddr)}]),
  %% change local addr with a new port 5060
  ?assertEqual({error,address_in_use}, quicer:setopt(Conn, param_conn_local_address, "127.0.0.1:50600")),

  %gen_udp:close(ESocket),

  %% sleep is needed to finish migration at protocol level
  ct:pal("send after migration failed"),
  {ok, 5} = quicer:send(Stm0, <<"ping2">>),
  receive
    {quic, <<"ping2">>, Stm0, _, _, _} ->
      ok
  after 1000 ->
      ct:fail("recv ping2 timeout")
  end,
  %% check with server if peer addr is correct.
  SPid ! {peer_addr, self()},
  receive {peer_addr, Peer} -> ok end,
  ?assertEqual({ok, NewAddr}, Peer),
  SPid ! done,
  ensure_server_exit_normal(Ref).

tc_setopt_stream_priority(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      ok = quicer:setopt(Stm, param_stream_priority, 10),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"ping">>} = quicer:recv(Stm, 0),
      % try to set priority out of range
      {error, param_error} = quicer:setopt(Stm, param_stream_priority, 65536),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 5000 ->
    ct:fail("listener_timeout")
  end.

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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
  {ok, 4} = quicer:async_send(Stm, <<"ping">>),
  {ok, 4} = quicer:async_send(Stm, <<"ping">>),
  {ok, 4} = quicer:async_send(Stm, <<"ping">>),
  {ok, <<"pingpingping">>} = quicer:recv(Stm, 12),
  ok = quicer:close_stream(Stm),
  ok = quicer:close_connection(Conn),
  ok = quicer:stop_listener(mqtt),
  %% test that listener could be reopened
  {ok, _} = quicer:start_listener(mqtt, Port, Options),
  ok = quicer:stop_listener(mqtt),
  ok.

tc_strm_opt_active_1(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, 1}]),
  {ok, 5} = quicer:send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} -> ok
  end,

  receive {quic_passive, Stm} -> ok end,

  {ok, 5} = quicer:async_send(Stm, <<"ping4">>),
  {ok, <<"ping4">>} = quicer:recv(Stm, 5),
  quicer:close_stream(Stm),
  quicer:close_connection(Conn).

tc_strm_opt_active_n(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, 3}]),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} -> ok
  end,
  {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
  receive
    {quic, <<"ping2">>, Stm,  _, _, _} -> ok
  end,
  {ok, 5} = quicer:async_send(Stm, <<"ping3">>),
  receive
    {quic, <<"ping3">>, Stm,  _, _, _} ->
      receive {quic_passive, Stm} -> ok end
  end,

  {ok, 5} = quicer:async_send(Stm, <<"ping4">>),
  {ok, <<"ping4">>} = quicer:recv(Stm, 5),
  quicer:close_stream(Stm),
  quicer:close_connection(Conn).

tc_strm_opt_active_once(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, once}]),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} ->
      receive {quic_passive, Stm} = Event ->
          ct:fail("unexpected recv ~p ", Event)
      after 500 ->
          ok
      end
  end,
  {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
  {ok, <<"ping2">>} = quicer:recv(Stm, 5),
  quicer:close_stream(Stm),
  quicer:close_connection(Conn).

tc_strm_opt_active_badarg(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {error, badarg} = quicer:start_stream(Conn, [{active, twice}]).

tc_get_conn_rid(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Rid} = quicer:get_conn_rid(Conn),
  ?assert(is_integer(Rid) andalso Rid =/=0).

tc_get_stream_rid(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, 3}]),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} -> ok
  end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).

tc_stream_open_flag_unidirectional(Config) ->
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
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [ {active, 3}
                                        , {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
                                        ]),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} -> ct:fail("unidirectional stream should not receive any");
    {quic, closed, Stm, 1} -> ct:pal("stream is closed due to connecion idle")
  end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).

tc_stream_start_flag_fail_blocked(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                 | lists:keyreplace(peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count,0})],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [ {active, 3}, {start_flag, ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED}
                                        , {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                                        ]),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} ->
      ct:fail("Should not get ping1 due to rate limiter");
    {quic, start_completed, Stm, stream_limit_reached, StreamID, _} ->
      ct:pal("Stream ~p limit reached", [StreamID]);
    {quic, start_completed, Stm, Reason, StreamID, _} ->
      ct:fail("Stream ~pstart complete with unexpect reason: ~p", [StreamID, Reason])
  end,

  receive
    {quic, closed, Stm, _} ->
      ct:failed("Stream ~p is closed but shouldn't since QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL is unset", [Stm]);
    {quic, transport_shutdown, Conn, connection_idle} ->
      ct:pal("Connection ~p transport shutdown due to idle, stream isn't closed ahead", [Conn])
    end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).


tc_stream_start_flag_immediate(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                 | lists:keyreplace(peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count,0})],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [ {active, 3}, {start_flag, ?QUIC_STREAM_START_FLAG_IMMEDIATE}
                                        , {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                                        ]),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  %% We don't need to send anything, we should get start_completed even it is rate limited
  receive
    {quic, start_completed, Stm, stream_limit_reached, StreamID, _} ->
      ct:fail("Stream ~p limit reached", [StreamID]);
    {quic, start_completed, Stm, Reason, StreamID, _} ->
      ct:pal("Stream ~pstart complete with reason: ~p", [StreamID, Reason])
  end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).

tc_stream_start_flag_shutdown_on_fail(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                 | lists:keyreplace(peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count,0})],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [ {active, 3}, {start_flag, ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL
                                                        bor ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED
                                                       }
                                          , {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                                        ]),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  case quicer:async_send(Stm, <<"ping1">>) of
    {ok, 5} -> ok;
    {error, stm_send_error, invalid_state} -> ok %% already closed
  end,
  receive
    {quic, start_completed, Stm, stream_limit_reached, StreamID, _} ->
      ct:pal("Stream ~p limit reached", [StreamID]);
    {quic, start_completed, Stm, Reason, StreamID, _} ->
      ct:fail("Stream ~pstart complete with other reason: ~p", [StreamID, Reason])
  end,
  %% We should get a stream closed event since it is rate limited
  receive
    {quic, closed, Stm, 0} -> % not a conn close
      ct:pal("Stream ~p is closed", [Stm]);
    {quic, transport_shutdown, Conn, connection_idle} ->
      ct:fail("Unexpected connection ~p transport shutdown", [Conn]);
    Other ->
      ct:fail("Unexpected event ~p after stream start complete", [Other])
  end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).

tc_stream_start_flag_indicate_peer_accept_1(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  %% We don't enable flow control
  ListenerOpts = [{conn_acceptors, 32}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                 | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, [ {active, 3}, {start_flag, ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT}
                                        , {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}
                                        ]),
  quicer:async_send(Stm, <<"ping1">>),
  {ok, Rid} = quicer:get_stream_rid(Stm),
  %% We don't need to send anything
  receive
    {quic, start_completed, Stm, stream_limit_reached, StreamID, _} ->
      ct:fail("Stream ~p limit reached", [StreamID]);
    {quic, start_completed, Stm, Reason, StreamID, _} ->
      ct:pal("Stream ~p start complete with reason: ~p", [StreamID, Reason])
  end,
  ?assert(is_integer(Rid)),
  ?assert(Rid =/= 0).

tc_conn_opt_sslkeylogfile(Config) ->
  Port = select_port(),
  TargetFName = "SSLKEYLOGFILE",
  file:delete(TargetFName),
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port,
                              [ {sslkeylogfile, TargetFName} |
                                default_conn_opts() ],
                              5000),
  quicer:close_connection(Conn),
  timer:sleep(100),
  {ok, #file_info{type=regular}} = file:read_file_info("SSLKEYLOGFILE").

tc_insecure_traffic(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  ListenerOpts = [{allow_insecure, true}, {conn_acceptors, 32}
                 | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port,
                              [{param_conn_disable_1rtt_encryption, true} |
                               default_conn_opts()], 5000),
  {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  receive
    {quic, <<"ping1">>, Stm,  _, _, _} ->
      {ok, true} = quicer:getopt(Conn, param_conn_disable_1rtt_encryption, false),
      ok
  end,
  quicer:close_connection(Conn),
  ok.

tc_perf_counters(_Config) ->
  {ok, _} = quicer:perf_counters().

tc_event_start_compl(Config) ->
  Port = select_port(),
  application:ensure_all_started(quicer),
  ListenerOpts = [{allow_insecure, true}, {conn_acceptors, 32}
                 | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                   | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  ct:pal("Listener Options: ~p", [Options]),
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port,
                              [{param_conn_disable_1rtt_encryption, true} |
                               default_conn_opts()], 5000),
  %% Stream 1 enabled
  {ok, Stm} = quicer:start_stream(Conn, [{active, true}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_SEND_COMPLETE}]),
  %% Stream 1 disabled
  {ok, Stm2} = quicer:start_stream(Conn, [{active, true}, {quic_event_mask, 0}]),
  {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
  {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
  receive
    {quic, start_completed, Stm, success, StreamId, 1} ->
      ct:pal("Stream ~p started", [StreamId]);
    {quic, start_completed, Stm, Err, StreamId, _} ->
      ct:fail("Stream ~p failed to start: ~p", [StreamId, Err])
  end,
  receive
    {quic, start_completed, Stm2, Status, _StreamId, _} ->
      ct:fail("Stream ~p should NOT recv event : ~p", [Stm, Status])
  after 0 ->
      ok
  end,
  quicer:close_connection(Conn),
  ok.

%%% ====================
%%% Internal helpers
%%% ====================
echo_server(Owner, Config, Port)->
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Conn} = quicer:async_accept_stream(Conn, []),
      {ok, Conn} = quicer:handshake(Conn),
      ct:pal("echo server conn accepted", []),
      receive
        {quic, new_stream, Stm} ->
          {ok, Conn} = quicer:async_accept_stream(Conn, [])
      end,
      ct:pal("echo server stream accepted", []),
      echo_server_stm_loop(L, Conn, Stm);
    {error, listener_start_error, 200000002} ->
      ct:pal("echo_server: listener_start_error", []),
      timer:sleep(100),
      echo_server(Owner, Config, Port)
  end.

echo_server_stm_loop(L, Conn, Stm) ->
  receive
    {quic, Bin, Stm, _, _, _} ->
      quicer:async_send(Stm, Bin),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, peer_send_aborted, Stm, _Error} ->
      ct:pal("echo server peer_send_aborted", []),
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, peer_send_shutdown, Stm} ->
      ct:pal("echo server peer_send_shutdown", []),
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, shutdown, Conn} ->
      ct:pal("echo server conn shutdown ~p", [Conn]),
      quicer:close_connection(Conn),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, closed, Conn} ->
      ct:pal("echo server Conn closed", []),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, closed, Stm, Flag} ->
      ct:pal("echo server stream closed ~p", [Flag]),
      echo_server_stm_loop(L, Conn, Stm);
    {set_stm_cnt, N } ->
      ct:pal("echo_server: set max stream count: ~p", [N]),
      ok = quicer:setopt(Conn, param_conn_settings, #{peer_bidi_stream_count => N}),
      {ok, NewStm} = quicer:accept_stream(Conn, []),
      echo_server_stm_loop(L, Conn, NewStm);
    {peer_addr, From} ->
      From ! {peer_addr, quicer:peername(Conn)},
      echo_server_stm_loop(L, Conn, Stm);
    done ->
      ct:pal("echo server shutting down", []),
      quicer:async_close_connection(Conn),
      quicer:close_listener(L)
  end.

ping_pong_server(Owner, Config, Port) ->
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Conn} = quicer:async_accept_stream(Conn, []),
      {ok, Conn} = quicer:handshake(Conn),
      receive
        {quic, new_stream, Stm} ->
          {ok, Conn} = quicer:async_accept_stream(Conn, [])
      end,
      ping_pong_server_stm_loop(L, Conn, Stm);
    {error, listener_start_error, R} ->
      ct:pal("Failed to start listener:~p , retry ...", [R]),
      timer:sleep(100),
      ping_pong_server(Owner, Config, Port)
  end.

ping_pong_server_stm_loop(L, Conn, Stm) ->
  true = is_reference(Stm),
  receive
    {quic, <<"ping">>, _, _, _, _} ->
      ct:pal("send pong"),
      {ok, 4} = quicer:send(Stm, <<"pong">>),
      ping_pong_server_stm_loop(L, Conn, Stm);
    {quic, peer_send_shutdown, Stm} ->
      ct:pal("closing stream"),
      quicer:close_stream(Stm),
      ping_pong_server_stm_loop(L, Conn, Stm);
    {quic, shutdown, Conn} ->
      ct:pal("closing conn"),
      quicer:close_connection(Conn),
      ping_pong_server_stm_loop(L, Conn, Stm);
    done ->
      quicer:close_listener(L)
  end.

ping_pong_server_dgram(Owner, Config, Port) ->
  Opts = default_listen_opts(Config) ++ [{datagram_receive_enabled, 1}],
  case quicer:listen(Port, Opts) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Conn} = quicer:handshake(Conn),
      {ok, Stm} = quicer:accept_stream(Conn, []),
      ping_pong_server_dgram_loop(L, Conn, Stm);
    {error, listener_start_error, R} ->
      ct:pal("Failed to start listener:~p , retry ...", [R]),
      timer:sleep(100),
      ping_pong_server_dgram(Owner, Config, Port)
  end.

ping_pong_server_dgram_loop(L, Conn, Stm) ->
  receive
    {quic, <<"ping">>, _, _, _, _} ->
      ct:pal("send stream pong"),
      {ok, 4} = quicer:send(Stm, <<"pong">>),
      ping_pong_server_dgram_loop(L, Conn, Stm);
    {quic, dgram, <<"ping">>} ->
      ct:pal("send dgram pong"),
      {ok, 4} = quicer:send_dgram(Conn, <<"pong">>),
      ping_pong_server_dgram_loop(L, Conn, Stm);
    {quic, peer_send_shutdown, Stm} ->
      ct:pal("closing stream"),
      quicer:close_stream(Stm),
      ping_pong_server_dgram_loop(L, Conn, Stm);
    {quic, shutdown, Conn} ->
      ct:pal("closing conn"),
      quicer:close_connection(Conn),
      ping_pong_server_dgram_loop(L, Conn, Stm);
    done ->
      quicer:close_listener(L)
  end.

simple_conn_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 1000),
  {ok, Conn} = quicer:handshake(Conn),
  receive 
    done ->
      quicer:close_listener(L),
      ok;
    {quic, shutdown, Conn} ->
      quicer:close_connection(Conn),
      quicer:close_listener(L)
  end.

simple_slow_conn_server(Owner, Config, Port) ->
  simple_slow_conn_server(Owner, Config, Port, 0).
simple_slow_conn_server(Owner, Config, Port, HandshakeDelay) ->
  {ok, L} = quicer:listen(Port, [ {handshake_idle_timeout_ms, HandshakeDelay*2+10}
                                | default_listen_opts(Config)]),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 5000),
  ct:pal("~p  new conn ~p", [?FUNCTION_NAME, Conn]),
  timer:sleep(HandshakeDelay),
  ok = quicer:async_handshake(Conn),
  ct:pal("~p  handshake ~p", [?FUNCTION_NAME, Conn]),
  receive
    {quic, connected, Conn} ->
      ct:pal("~p  Connected ~p", [?FUNCTION_NAME, Conn]),
      ok;
    {quic, closed, Conn} ->
      %% for timeout test
      ct:pal("~p conn ~p closed", [?FUNCTION_NAME, Conn]),
      ok
  end,
  %% test what happens if handshake twice
  {error, invalid_state} = quicer:handshake(Conn),
  receive done ->
      quicer:close_listener(L),
      ok
  end.

conn_server_with(Owner, Port, Opts) ->
  {ok, L} = quicer:listen(Port, Opts),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 10000),
  {ok, Conn} = quicer:handshake(Conn),
  receive done ->
    quicer:close_listener(L),
    ok
  end.

simple_stream_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 5000),
  {ok, Conn} = quicer:async_accept_stream(Conn, []),
  {ok, Conn} = quicer:handshake(Conn),
  receive
    {quic, new_stream, Stream} ->
      {ok, StreamId} = quicer:get_stream_id(Stream),
      ct:pal("New StreamID: ~p", [StreamId]),
      receive
        {quic, shutdown, Conn} ->
          ct:pal("closing ~p", [Conn]),
          quicer:close_connection(Conn);
        {quic, peer_send_shutdown, Stream} ->
          quicer:close_stream(Stream);
        done ->
          exit(normal)
      end;
   {quic, shutdown, Conn} ->
      ct:pal("Received Conn close for ~p", [Conn]),
      quicer:close_connection(Conn)
  end,
  receive
    {quic, shutdown, Conn} ->
      ct:pal("Received Conn close for ~p", [Conn]),
      quicer:close_connection(Conn);
    done ->
      ok
  end,
  quicer:close_listener(L).


ensure_server_exit_normal(MonRef) ->
  ensure_server_exit_normal(MonRef, 5000).
ensure_server_exit_normal(MonRef, Timeout) ->
  receive
    {'DOWN', MonRef, process, _, normal} ->
      ok;
    {'DOWN', MonRef, process, _, Other} ->
      ct:fail("server exits abnormally ~p ", [Other])
  after Timeout ->
      ct:fail("server still running", [])
  end.

default_stream_opts() ->
  [].

default_conn_opts() ->
  [{alpn, ["sample"]},
   %{sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
   {idle_timeout_ms, 5000}
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

active_recv(Stream, Len) ->
  active_recv(Stream, Len, []).
active_recv(Stream, Len, BinList) ->
  case iolist_size(BinList) >= Len of
    true ->
      binary:list_to_bin(lists:reverse(BinList));
    false ->
      receive {quic, Bin, Stream, _, _, _} ->
          active_recv(Stream, Len, [Bin |BinList])
      end
end.

retry_with(_Fun, 0, ErrorInfo) ->
  ct:fail(ErrorInfo);
retry_with(Fun, Retry, ErrorInfo) ->
  case Fun() of
    true ->
      ok;
    false ->
      retry_with(Fun, Retry - 1, ErrorInfo);
    {false, NewErrorInfo} ->
      retry_with(Fun, Retry - 1, NewErrorInfo)
  end.

%% select a random port picked by OS
select_port()->
  {ok, S} = gen_udp:open(0, [{reuseaddr, true}]),
  {ok, {_, Port}} = inet:sockname(S),
  gen_udp:close(S),
  case os:type() of
    {unix,darwin} ->
      %% in MacOS, still get address_in_use after close port
      timer:sleep(500);
    _ ->
      skip
  end,
  ct:pal("select port: ~p", [Port]),
  Port.
%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
