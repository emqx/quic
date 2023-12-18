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
-module(quicer_connection_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include("quicer.hrl").

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").

-import(quicer_test_lib, [ default_listen_opts/1
                         , default_conn_opts/0
                         , default_stream_opts/0
                         , select_free_port/1
                         , flush/1
                         , ensure_server_exit_normal/1
                         , ensure_server_exit_normal/2
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
    code:purge(quicer_nif),
    code:delete(quicer_nif),
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
  {ok, SReg} = quicer:new_registration(atom_to_list(?MODULE),
                                       quic_execution_profile_max_throughput),
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
end_per_testcase(_TestCase, _Config) ->
    quicer_test_lib:report_active_connections(),
    ct:pal("Counters ~p", [quicer:perf_counters()]),
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
  [ {global_reg, [], TCs}
  , {suite_reg, [], TCs}
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
  [ {group, global_reg}
  , {group, suite_reg}
  ].

%%--------------------------------------------------------------------
%% @spec TestCase(Config0) ->
%%               ok | exit() | {skip,Reason} | {comment,Comment} |
%%               {save_config,Config1} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% Comment = term()
%% @end
%%--------------------------------------------------------------------
tc_open0(_) ->
    {ok, H} = quicer_nif:open_connection(),
    quicer:close_connection(H).

tc_open1(_) ->
    {ok, H} = quicer_nif:open_connection(#{}),
    quicer:close_connection(H).

tc_open2(Config0) ->
    Config = maps:from_list(Config0),
    {ok, H} = quicer_nif:open_connection(Config),
    quicer:close_connection(H).

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
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_basic_verify_peer(Config)->
  {ok, Conn} = quicer:connect("google.com", 443,
                              [ {verify, verify_peer}
                              %, {sslkeylogfile, "/tmp/SSLKEYLOGFILE"}
                              , {peer_unidi_stream_count, 3}
                              , {alpn, ["h3"]} | Config], 5000),
  {ok, {_, _}} = quicer:sockname(Conn),
  {ok, Info} = quicer:getopt(Conn, param_tls_handshake_info, quic_tls),
  ct:pal("Handshake Info with Google: ~p", [Info]),
  ok = quicer:close_connection(Conn),
  ok.

tc_conn_basic_verify_peer_no_cacert(Config)->
  %% Verify that the connection handshake should fail if
  %% `verif_peer` is set but CA is unknown
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                  fun() ->
                      simple_slow_conn_server(Owner, Config, Port)
                  end),
  receive listener_ready -> ok end,

  %% ErrorCode is different per platform
  {error,transport_down,
   #{error := _ErrorCode,
     status := ErrorStatus}} =
    quicer:connect("localhost", Port,
                   [ {verify, verify_peer}
                   , {peer_unidi_stream_count, 3}
                   , {alpn, ["sample"]} | Config], 5000),

  ?assert(ErrorStatus =:= cert_untrusted_root orelse ErrorStatus =:= bad_certificate),

  receive
    {quic, closed, _, _} ->
      ct:fail("closed should be flushed")
  after 500 ->
      ok
  end,

  SPid ! done,
  ensure_server_exit_normal(Ref),
  ok.

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
      {error, transport_down, #{error := 1, status := connection_idle}}
        = quicer:connect("localhost", Port, default_conn_opts(Config), TOut),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_async_conn_timeout(Config)->
  Port = select_port(),
  Owner = self(),
  %% The value set here might not be the one actual in use
  %% because loss detection takes many facts into account
  %% A minimal value will be selected rather than this one
  %% for more, look for QuicLossDetectionComputeProbeTimeout
  Tout = 1000,
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_slow_conn_server(Owner, Config, Port, Tout*2)
                   end),
  receive
    listener_ready ->
      {ok, H} = quicer:async_connect("localhost", Port, [{handshake_idle_timeout_ms, Tout} |
                                                         default_conn_opts(Config)]),
      receive
        {quic, transport_shutdown, H, Reason} ->
          %% silent local close
          ?assertEqual(#{ error => 1
                        , status => connection_idle}, Reason)
       after Tout * 10 ->
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
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
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
                                                     | default_conn_opts(Config)], 5000),
      ?assertEqual({ok, {{127,0,0,1}, PortX}}, quicer:sockname(Conn)),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ok = ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_custom_ca(Config) ->
  {Pid, Ref} = spawn_monitor(fun() -> run_tc_conn_custom_ca(Config) end),
  receive
    {'DOWN', Ref, process, Pid, normal} ->
      ok;
    {'DOWN', Ref, process, Pid, Error} ->
      ct:fail({run_error, Error})
  end.

run_tc_conn_custom_ca(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts_verify(Config, "ca"), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ct:pal("closing connection : ~p", [Conn]),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_custom_ca_other(Config) ->
  {Pid, Ref} = spawn_monitor(fun() -> run_tc_conn_custom_ca_other(Config) end),
  receive
    {'DOWN', Ref, process, Pid, normal} ->
      ok;
    {'DOWN', Ref, process, Pid, Error} ->
      ct:fail({run_error, Error})
  end.

run_tc_conn_custom_ca_other(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server_close(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {error,transport_down,
       #{error := _ErrorCode,
         status := bad_certificate}} =
        quicer:connect("localhost", Port,
                       default_conn_opts_verify(Config, "other-ca"),
                       5000),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_client_cert(Config) ->
  {Pid, Ref} = spawn_monitor(fun() -> run_tc_conn_client_cert(Config) end),
  receive
    {'DOWN', Ref, process, Pid, normal} ->
      ok;
    {'DOWN', Ref, process, Pid, Error} ->
      ct:fail({run_error, Error})
  end.

run_tc_conn_client_cert(Config)->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server_client_cert(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port,
                                  default_conn_opts_client_cert(Config, "ca"),
                                  5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ct:pal("closing connection : ~p", [Conn]),
      ok = quicer:close_connection(Conn),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_client_bad_cert(Config) ->
  {Pid, Ref} = spawn_monitor(fun() -> run_tc_conn_client_bad_cert(Config) end),
  receive
    {'DOWN', Ref, process, Pid, normal} ->
      ok;
    {'DOWN', Ref, process, Pid, Error} ->
      ct:fail({run_error, Error})
  end.

tc_datagram_disallowed(Config) ->
  Port = select_port(),
  ServerConnCallback = example_server_connection,
  ServerStreamCallback = example_server_stream,
  ListenerOpts = [{conn_acceptors, 4} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, ServerConnCallback}
                   , {stream_acceptors, 2}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, ServerStreamCallback}
               , {disable_fpbuffer, true}
               | default_stream_opts() ],
  %% GIVEN: A listener with datagram_receive_enabled = false
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},

  {ok, _} = quicer:spawn_listener(mqtt, Port, Options),
  %% WHEN: Client send dgram data
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  %% THEN: It get an error
  ?assertEqual({error, dgram_send_error, invalid_state}, quicer:send_dgram(Conn, <<"dg_ping">>)),
  quicer:shutdown_connection(Conn),
  ok.

tc_datagram_peer_allowed(Config) ->
  Port = select_port(),
  ServerConnCallback = example_server_connection,
  ServerStreamCallback = example_server_stream,
  %% GIVEN: A listener with datagram_receive_enabled = 1 (true)
  ListenerOpts = [{conn_acceptors, 4}, {datagram_receive_enabled, 1} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, ServerConnCallback}
                   , {stream_acceptors, 2}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, ServerStreamCallback}
               , {disable_fpbuffer, true}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},

  {ok, _} = quicer:spawn_listener(mqtt, Port, Options),
  %% WHEN: A client send_dgram
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  %% THEN: It should success
  ?assertEqual({ok, 7}, quicer:send_dgram(Conn, <<"dg_ping">>)),

  receive
    %% THEN: the client should not recv dgram from peer as the receiving is disabled
    {quic, Data, _Conn, _Flag} when is_binary(Data) ->
      ct:fail("client side dgram recv timeout")
  after 500 ->
      ok
  end,
  quicer:shutdown_connection(Conn),
  ok.

tc_datagram_local_peer_allowed(Config) ->
  Port = select_port(),
  ServerConnCallback = example_server_connection,
  ServerStreamCallback = example_server_stream,
  %% GIVEN: A listener with datagram_receive_enabled = 1 (true)
  ListenerOpts = [{conn_acceptors, 4}, {datagram_receive_enabled, 1} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, ServerConnCallback}
                   , {stream_acceptors, 2}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, ServerStreamCallback}
               , {disable_fpbuffer, true}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},

  {ok, _} = quicer:spawn_listener(mqtt, Port, Options),
  %% WHEN: Client connect with datagram_receive_enabled = 1 (true)
  {ok, Conn} = quicer:connect("localhost", Port, [{datagram_receive_enabled, 1} | default_conn_opts()], 5000),
  ?assertEqual({ok, 7}, quicer:send_dgram(Conn, <<"dg_ping">>)),
  receive
    %% THEN: the client is able to receive the dgram from server
    {quic, <<"dg_ping">>, Conn, Flag} ->
      ?assertEqual(0, Flag)
  after 1000 ->
     ct:fail("client side dgram recv timeout")
  end,
  quicer:shutdown_connection(Conn),
  ok.

run_tc_conn_client_bad_cert(Config)->
  Port = select_port(),
  Owner = self(),
  {_SPid, Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server_client_bad_cert(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect(
                     "localhost", Port,
                     default_conn_opts_bad_client_cert(Config, "ca"),
                     5000),
      case quicer:start_stream(Conn, []) of
        {error, stm_open_error, aborted} ->
          %% Depending on the timing, connection open could fail already.
          ok;
        {error, stm_start_error, aborted} ->
          %% Depending on the timing, connection open could fail already.
          ok;
        {ok, Stm} ->
          case quicer:send(Stm, <<"ping">>) of
            {ok, 4} -> ok;
            {error, cancelled} -> ok;
            {error, stm_send_error, aborted} -> ok;
            {error, closed} -> ok
          end,
          receive
            {quic, transport_shutdown, _Ref,
             #{error := _ErrorCode, status := bad_certificate}} ->
              _ = flush([])
          after
            2000 ->
              Other = flush([]),
              ct:fail("Unexpected Msg ~p", [Other])
          end,
          ensure_server_exit_normal(Ref)
      end
  after 1000 ->
      ct:fail("timeout")
  end.

%% @doc check old owner is demonitored.
tc_conn_controlling_process_demon(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      Parent = self(),
      {OldOwner, MonRef} = spawn_monitor(
                             fun() ->
                                 {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
                                 Res = quicer:controlling_process(Conn, Parent),
                                 exit({Res, Conn})
                             end),
      Conn = receive
               {'DOWN', MonRef, process, OldOwner, {Res, TheConn}} ->
                 ct:pal("Old Owner is down, mon res: ~p", [Res]),
                 TheConn
             end,
      %% Try set owner back to dead previous owner, should fail
      ?assertEqual({error, owner_dead}, quicer:controlling_process(Conn, OldOwner)),
      %% rollback to this owner.

      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      {ok, _} = quicer:recv(Stm, 11),
      SPid ! done,

      {NewOwner2, MonRef2} = spawn_monitor(fun() ->
                                               receive stop -> ok end
                                           end),
      ok = quicer:controlling_process(Conn, NewOwner2),
      NewOwner2 ! stop,
      receive
        {'DOWN', MonRef2, process, NewOwner2, normal} -> ok
      end,
      ?assertNotMatch({ok, _},  quicer:send(Stm, <<"ping_active">>)),
      quicer:async_shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0),
      SPid ! done,
      ensure_server_exit_normal(Ref)
  after 6000 ->
      ct:fail("timeout")
  end.

tc_conn_controlling_process(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(Config), 5000),
      {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
      ok = quicer:controlling_process(Conn, self()),
      {ok, 11} = quicer:send(Stm, <<"ping_active">>),
      {ok, _} = quicer:recv(Stm, 11),
      {NewOwner, MonRef} = spawn_monitor(
                             fun() ->
                                 receive
                                   {quic, closed, Conn, _Flags} ->
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

tc_conn_opt_ideal_processor(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(Config), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, Processor} = quicer:getopt(Conn, param_conn_ideal_processor),
      ?assert(is_integer(Processor)),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_conn_opt_share_udp_binding(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(Config), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, IsShared} = quicer:getopt(Conn, param_conn_share_udp_binding),
      ?assert(is_boolean(IsShared)),
      {error, invalid_state} = quicer:setopt(Conn, param_conn_share_udp_binding, not IsShared),
      {ok, IsShared} = quicer:getopt(Conn, param_conn_share_udp_binding),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_conn_opt_local_bidi_stream_count(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(Config), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, Cnt} = quicer:getopt(Conn, param_conn_local_bidi_stream_count),
      ?assert(is_integer(Cnt)),
      {error, invalid_parameter} = quicer:setopt(Conn, param_conn_local_bidi_stream_count, Cnt + 2),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_conn_opt_local_uni_stream_count(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(Config), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, Cnt} = quicer:getopt(Conn, param_conn_local_unidi_stream_count),
      ?assert(is_integer(Cnt)),
      {error, invalid_parameter} = quicer:setopt(Conn, param_conn_local_unidi_stream_count, Cnt + 2),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_conn_list(Config) ->
  Port = select_port(),
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  Reg = proplists:get_value(quic_registration, Config, undefined),
  receive
    listener_ready ->
      case Reg of
        undefined ->
          ?assertEqual(0, length(quicer:get_connections()));
        Reg ->
          ?assertEqual(0, length(quicer:get_connections(Reg)))
      end
  after 5000 ->
      ct:fail("listener_timeout")
  end,
  {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(Config), 5000),
  {ok, Stm} = quicer:start_stream(Conn, []),
  {ok, 4} = quicer:send(Stm, <<"ping">>),
  {ok, Cnt} = quicer:getopt(Conn, param_conn_local_unidi_stream_count),
  ?assert(is_integer(Cnt)),
  Conns = case Reg of
            undefined ->
              quicer:get_connections();
            Reg ->
              quicer:get_connections(Reg)
          end,
  ?assertEqual(2, length(Conns)),

  {ok, ClientName} = quicer:sockname(Conn),
  ?assertMatch([{ok, ClientName}, {ok, {_, Port}}],
               lists:map(fun quicer:peername/1, Conns)),
  SPid ! done.

tc_get_conn_owner_client(_Config) ->
  {ok, Conn} = quicer:open_connection(),
  {ok, Pid} = quicer:get_conn_owner(Conn),
  quicer:close_connection(Conn),
  ?assertEqual(self(), Pid).

tc_get_conn_owner_server(Config) ->
  Port = select_port(),
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, L} = quicer:async_accept(L, #{}),
  {ClientPid, CMref} = erlang:spawn_monitor(fun()->
                                                {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 1000),
                                                {ok, _Stm} = quicer:async_csend(Conn, <<"hello">>, [{active, true}], ?QUIC_SEND_FLAG_START),
                                                receive
                                                  done ->
                                                    quicer:connection_close(Conn),
                                                    ok
                                                end
                                            end),
  receive
    {quic, new_conn, SConn, _} ->
      {ok, Pid} = quicer:get_conn_owner(SConn),
      ?assertEqual(self(), Pid),
      quicer:close_connection(SConn),
      quicer:close_listener(L),
      ClientPid ! done;
    {'DOWN', CMref, process, ClientPid, Reason} -> ct:fail({client_fail, Reason})
  end.

%%%
%%% Helpers
%%%
select_port() ->
  select_free_port(quic).

simple_conn_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 1000),
  {ok, Conn} = quicer:handshake(Conn),
  simple_conn_server_loop(L, Conn, Owner).

simple_conn_server_loop(L, Conn, Owner) ->
  receive
    done ->
      quicer:close_connection(Conn),
      quicer:close_listener(L),
      ok;
    peercert ->
      CertResp = quicer:peercert(Conn),
      Owner ! {self(), peercert, CertResp},
      simple_conn_server_loop(L, Conn, Owner);
    {quic, shutdown, Conn} ->
      quicer:close_connection(Conn),
      quicer:close_listener(L)
  end.

simple_conn_server_close(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 1000),
  {error, closed} = quicer:handshake(Conn),
  receive
    done ->
      quicer:close_listener(L),
      ok;
    {quic, shutdown, Conn} ->
      quicer:close_listener(L)
  end.

simple_conn_server_client_cert(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts_client_cert(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 1000),
  case quicer:handshake(Conn) of
    {ok, Conn} ->
      simple_conn_server_client_cert_loop(L, Conn, Owner);
    {error, closed} ->
      receive done ->
          quicer:close_listener(L)
      end
  end.

simple_conn_server_client_cert_loop(L, Conn, Owner) ->
  receive
    done ->
      quicer:close_listener(L),
      ok;
    peercert ->
      {ok, PeerCert} = quicer:peercert(Conn),
      Owner ! {self(), peercert, PeerCert},
      simple_conn_server_client_cert_loop(L, Conn, Owner);
    {quic, shutdown, Conn, _ErrorCode} ->
      quicer:close_connection(Conn),
      quicer:close_listener(L)
  end.

simple_conn_server_client_bad_cert(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts_client_cert(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 1000),
  {error, closed} = quicer:handshake(Conn),
  quicer:close_listener(L).

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
    {quic, connected, Conn, _} ->
      ct:pal("~p  Connected ~p", [?FUNCTION_NAME, Conn]),
      ok;
    {quic, closed, Conn, _Flags} ->
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


default_conn_opts_verify(Config, Ca) ->
  DataDir = ?config(data_dir, Config),
  CACertFile = filename:join(DataDir, Ca) ++ ".pem",
  [{verify, peer},
   {cacertfile, CACertFile} |
   tl(default_conn_opts())].

default_conn_opts_client_cert(Config, Ca) ->
  DataDir = ?config(data_dir, Config),
  [{keyfile, filename:join(DataDir, "client.key")},
   {certfile, filename:join(DataDir, "client.pem")}|
   default_conn_opts_verify(Config, Ca)].

default_conn_opts_bad_client_cert(Config, Ca) ->
  DataDir = ?config(data_dir, Config),
  [{keyfile, filename:join(DataDir, "other-client.key")},
   {certfile, filename:join(DataDir, "other-client.pem")}|
   default_conn_opts_verify(Config, Ca)].

default_listen_opts_client_cert(Config) ->
  DataDir = ?config(data_dir, Config),
  [ {cacertfile, filename:join(DataDir, "ca.pem")}
  , {verify, peer} |
    tl(default_listen_opts(Config)) ].


echo_server(Owner, Config, Port)->
  put(echo_server_test_coordinator, Owner),
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Conn} = quicer:async_accept_stream(Conn, []),
      {ok, Conn} = quicer:handshake(Conn),
      ct:pal("echo server conn accepted", []),
      receive
        {quic, new_stream, Stm, _Props} ->
          {ok, Conn} = quicer:async_accept_stream(Conn, []);
        {flow_ctl, BidirCount, UniDirCount} ->
          ct:pal("echo server stream flow control to bidirectional: ~p : ~p", [BidirCount, UniDirCount]),
          quicer:setopt(Conn, param_conn_settings, #{peer_bidi_stream_count => BidirCount,
                                                     peer_unidi_stream_count => UniDirCount}),
          receive {quic, new_stream, Stm, _Props} ->
              {ok, Conn} = quicer:async_accept_stream(Conn, [])
          end
      end,
      ct:pal("echo server stream accepted", []),
      catch echo_server_stm_loop(L, Conn, [Stm]),
      quicer:close_listener(L);
    {error, listener_start_error, 200000002} ->
      ct:pal("echo_server: listener_start_error", []),
      timer:sleep(100),
      echo_server(Owner, Config, Port)
  end.

echo_server_stm_loop(L, Conn, Stms) ->
  receive
    {quic, <<"Abort">>, Stm, #{flags := _Flag}} ->
      quicer:async_shutdown_stream(Stm, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 1),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, Bin, Stm, #{flags := Flag}} when is_binary(Bin) ->
      SendFlag = case (Flag band ?QUIC_RECEIVE_FLAG_FIN) > 0 of
                   true -> ?QUICER_SEND_FLAG_SYNC bor ?QUIC_SEND_FLAG_FIN;
                   false -> ?QUICER_SEND_FLAG_SYNC
                 end,
      case quicer:send(Stm, Bin, SendFlag) of
        {error, stm_send_error, aborted} ->
          ct:pal("echo server: send aborted: ~p ", [Bin]);
        {error, stm_send_error, invalid_state} ->
          {ok, RetStream} =
            quicer:start_stream(Conn, [{open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}]),
          quicer:send(RetStream, Bin);
        {error, cancelled} ->
          ct:pal("echo server: send cancelled: ~p ", [Bin]),
          cancelled;
        {error, closed} ->
          closed;
        {ok, _} ->
          ok
      end,
      echo_server_stm_loop(L, Conn, Stms);
    {quic, peer_send_aborted, Stm, _Error} ->
      ct:pal("echo server peer_send_aborted", []),
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, peer_send_shutdown, Stm, undefined} ->
      ct:pal("echo server peer_send_shutdown", []),
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, transport_shutdown, Conn, #{status := ErrorAtom}} ->
      ct:pal("echo server transport_shutdown due to ~p", [ErrorAtom]),
      get(echo_server_test_coordinator) ! {echo_server_transport_shutdown, ErrorAtom},
      echo_server_stm_loop(L, Conn, Stms);
    {quic, shutdown, Conn, ErrorCode} ->
      ct:pal("echo server conn shutdown ~p due to ~p", [Conn, ErrorCode]),
      quicer:close_connection(Conn),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, closed, Conn, _Flags} ->
      ct:pal("echo server Conn closed", []),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, stream_closed, Stm, Flag} ->
      ct:pal("echo server stream closed ~p", [Flag]),
      echo_server_stm_loop(L, Conn, Stms -- [Stm]);
    {set_stm_cnt, N } ->
      ct:pal("echo_server: set max stream count: ~p", [N]),
      ok = quicer:setopt(Conn, param_conn_settings, #{peer_bidi_stream_count => N}),
      {ok, NewStm} = quicer:accept_stream(Conn, []),
      echo_server_stm_loop(L, Conn, [NewStm | Stms]);
    {peer_addr, From} ->
      From ! {peer_addr, quicer:peername(Conn)},
      echo_server_stm_loop(L, Conn, Stms);
    {flow_ctl, BidirCount, UniDirCount} ->
      ct:pal("echo server stream flow control to bidirectional: ~p : ~p", [BidirCount, UniDirCount]),
      quicer:setopt(Conn, param_conn_settings, #{peer_bidi_stream_count => BidirCount,
                                                 peer_unidi_stream_count => UniDirCount}),
      {ok, Conn} = quicer:async_accept_stream(Conn, []),
      echo_server_stm_loop(L, Conn, Stms);
    {quic, new_stream, NewStm, #{flags := Flags}} ->
      NewStmList = case quicer:is_unidirectional(Flags) of
                     true ->
                       ct:pal("echo server: new incoming unidirectional stream"),
                       {ok, ReturnStm} = quicer:start_stream(Conn, [{open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}]),
                       [{NewStm, ReturnStm} | Stms];
                     false ->
                       ct:pal("echo server: new incoming binary stream"),
                       [NewStm | Stms]
                   end,
      echo_server_stm_loop(L, Conn, NewStmList);
    done ->
      ct:pal("echo server shutting down", []),
      quicer:async_close_connection(Conn)
  end.

default_conn_opts(Config) ->
  default_conn_opts() ++ Config.
