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
        , tc_open_lib_test/1
        , tc_close_lib_test/1
        , tc_lib_registration/1
        , tc_lib_re_registration/1
        , tc_open_listener/1
        , tc_close_listener/1

        , tc_conn_basic/1
        , tc_conn_other_port/1

        , tc_stream_client_init/1
        , tc_stream_client_send/1

        , tc_stream_passive_receive/1
        , tc_stream_passive_receive_buffer/1
        , tc_stream_passive_receive_large_buffer_1/1
        , tc_stream_passive_receive_large_buffer_2/1

        , tc_getopt_raw/1
        , tc_getopt/1
        , tc_get_stream_id/1
        , tc_getstat/1
        , tc_peername_v4/1
        , tc_peername_v6/1

        , tc_alpn/1
        , tc_alpn_mismatch/1
        , tc_idle_timeout/1
        ]).

-export([tc_app_echo_server/1]).

%% -include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").

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
  Config.

end_per_testcase(tc_close_lib_test, _Config) ->
  quicer_nif:open_lib();
end_per_testcase(tc_lib_registration, _Config) ->
  quicer_nif:reg_open();
end_per_testcase(tc_lib_re_registration, _Config) ->
  quicer_nif:reg_open();
end_per_testcase(_TestCase, _Config) ->
  ok.

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================
tc_nif_module_load(_Config) ->
  {module, quicer_nif} = c:l(quicer_nif).

tc_open_lib_test(_Config) ->
  ok = quicer_nif:open_lib(),
  %% verify that reopen lib success.
  ok = quicer_nif:open_lib().

tc_close_lib_test(_Config) ->
  ok = quicer_nif:open_lib(),
  ok = quicer_nif:close_lib(),
  ok = quicer_nif:close_lib().

tc_lib_registration(_Config) ->
  ok = quicer_nif:reg_open(),
  ok = quicer_nif:reg_close().

tc_lib_re_registration(_Config) ->
  ok = quicer_nif:reg_open(),
  ok = quicer_nif:reg_open(),
  ok = quicer_nif:reg_close(),
  ok = quicer_nif:reg_close().

tc_open_listener(Config) ->
  Port = 4567,
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  {ok, {_, _}} = quicer:sockname(L),
  {error,eaddrinuse} = gen_udp:open(Port),
  ok = quicer:close_listener(L),
  {ok, P} = gen_udp:open(Port),
  ok = gen_udp:close(P),
  ok.

tc_close_listener(_Config) ->
  {error,badarg} = quicer:close_listener(make_ref()).

tc_conn_basic(Config)->
  Port = 4567,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(
                   fun() ->
                       simple_conn_server(Owner, Config, Port)
                   end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, {_, _}} = quicer:sockname(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 1000 ->
      ct:fail("timeout")
  end.

tc_conn_other_port(Config)->
  Port = 4568,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> simple_conn_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_client_init(Config) ->
  Port = 4568,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> simple_stream_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, {_, _}} = quicer:sockname(Stm),
      ok = quicer:close_stream(Stm),
      SPid ! done
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_client_send(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      receive
        {quic, <<"pong">>, _, _, _, _} ->
          ok = quicer:close_stream(Stm),
          ok = quicer:close_connection(Conn);
        Other ->
          ct:fail("Unexpected Msg ~p", [Other])
      end,
      SPid ! done
  after 1000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      SPid ! done
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive_buffer(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pong">>} = quicer:recv(Stm, 0),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"p">>} = quicer:recv(Stm, 1),
      {ok, <<"on">>} = quicer:recv(Stm, 2),
      {ok, <<"g">>} = quicer:recv(Stm, 0),
      SPid ! done
  after 6000 ->
      ct:fail("timeout")
  end.


tc_stream_passive_receive_large_buffer_1(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {ok, <<"pingpingping">>} = quicer:recv(Stm, 12),
      SPid ! done
  after 6000 ->
      ct:fail("timeout")
  end.

tc_stream_passive_receive_large_buffer_2(Config) ->
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      timer:sleep(100),
      {ok, <<"pongpongpong">>} = quicer:recv(Stm, 12),
      SPid ! done
  after 6000 ->
      ct:fail("timeout")
  end.

tc_getopt_raw(Config) ->
  Parm = param_conn_quic_version,
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, <<1,0,0,0>>} = quicer:getopt(Conn, Parm),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, badarg} = quicer:getopt(Stm, Parm),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 1000 ->
      ct:fail("listener_timeout")
  end.

tc_getopt(Config) ->
  Parm = param_conn_statistics,
  Port = 4570,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stats} = quicer:getopt(Conn, Parm, false),
      1 = proplists:get_value("Recv.ValidAckFrames", Stats),
      [true = proplists:is_defined(SKey, Stats)
       || SKey <- ["Send.TotalPackets", "Recv.TotalPackets"]],
      {ok, Settings} = quicer:getopt(Conn, param_conn_settings, false),
      5000 = proplists:get_value("IdleTimeoutMs", Settings),
      true = proplists:get_value("SendBufferingEnabled", Settings),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      %% test that op is fallbakced to connection
      {ok, _} = quicer:getopt(Stm, Parm, false),
      {ok, Settings0} = quicer:getopt(Stm, param_conn_settings, false),
      5000 = proplists:get_value("IdleTimeoutMs", Settings0),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_get_stream_id(Config) ->
  Port = 4571,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
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
      {error, badarg} = quicer:get_stream_id(Conn),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.


tc_getstat(Config) ->
  Port = 4572,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      [{send_cnt, _}, {recv_oct, _}] = quicer:getstats(Conn, [send_cnt, recv_oct]),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.


tc_peername_v6(Config) ->
  Port = 4573,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("::1", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, badarg} = quicer:peername(0),
      {ok, {Addr, RPort}} = quicer:peername(Conn),
      {ok, {Addr, RPort}} = quicer:peername(Stm),
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
  Port = 4574,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 5000),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, badarg} = quicer:peername(0),
      {ok, {Addr, RPort}} = quicer:peername(Conn),
      {ok, {Addr, RPort}} = quicer:peername(Stm),
      %% checks
      true = is_integer(RPort),
      ct:pal("addr is ~p", [Addr]),
      "127.0.0.1" =  inet:ntoa(Addr),
      ok = quicer:close_connection(Conn),
      %% @todo coredump, msquic isn't robust enough to handle the following call after
      %% connection get closed. We need a follow-up later.
      %{ok, {Addr, RPort}} = quicer:peername(Conn),
      SPid ! done
  after 5000 ->
      ct:fail("listener_timeout")
  end.

tc_alpn(Config) ->
  Port = 4575,
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
  Port = 4576,
  Owner = self(),
  Opts = lists:keyreplace(alpn, 1, default_listen_opts(Config), {alpn, ["no"]}),
  {SPid, _Ref} = spawn_monitor(fun() -> conn_server_with(Owner, Port, Opts) end),
  receive
    listener_ready ->
      spawn_monitor(fun() -> quicer:connect("localhost", Port, default_conn_opts(), 5000),
                             Owner ! connected end),
      receive
        connected ->
          ct:fail("illegal connection")
      after 1000 ->
        SPid ! done
      end
  after 1000 ->
    ct:fail("timeout")
  end.

tc_idle_timeout(Config) ->
  Port = 4577,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      Opts = lists:keyreplace(idle_timeout_ms, 1, default_conn_opts(), {idle_timeout_ms, 1}),
      {ok, Conn} = quicer:connect("localhost", Port, Opts, 5000),
      timer:sleep(500),
      {error, stm_open_error} = quicer:start_stream(Conn, []),
      SPid ! done
  end.

tc_app_echo_server(Config) ->
  Port = 8888,
  application:ensure_all_started(quicer),
  ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
  ConnectionOpts = [ {conn_callback, quicer_server_conn_callback}
                   , {stream_acceptors, 32}
                     | default_conn_opts()],
  StreamOpts = [ {stream_callback, quicer_echo_server_stream_callback}
               | default_stream_opts() ],
  Options = {ListenerOpts, ConnectionOpts, StreamOpts},
  {ok, _QuicApp} = quicer:start_listener(mqtt, Port, Options),
  {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
  {ok, Stm} = quicer:start_stream(Conn, []),
  {ok, 4} = quicer:send(Stm, <<"ping">>),
  {ok, 4} = quicer:send(Stm, <<"ping">>),
  {ok, 4} = quicer:send(Stm, <<"ping">>),
  {ok, <<"pingpingping">>} = quicer:recv(Stm, 12),
  ok.

%%% ====================
%%% Internal helpers
%%% ====================
echo_server(Owner, Config, Port)->
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Stm} = quicer:accept_stream(Conn, []),
      echo_server_stm_loop(L, Conn, Stm);
    {error, listener_start_error, 200000002} ->
      timer:sleep(100),
      echo_server(Owner, Config, Port)
  end.

echo_server_stm_loop(L, Conn, Stm) ->
  receive
    {quic, Bin, Stm, _, _, _} ->
      quicer:send(Stm, Bin),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, peer_send_aborted, Stm, _Error} ->
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, peer_send_shutdown, Stm, _Error} ->
      quicer:close_stream(Stm),
      echo_server_stm_loop(L, Conn, Stm);
    {quic, closed, Stm, _Flag} ->
      echo_server_stm_loop(L, Conn, Stm);
    done ->
      quicer:close_connection(Conn),
      quicer:close_listener(L)
  end.

ping_pong_server(Owner, Config, Port) ->
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Stm} = quicer:accept_stream(Conn, []),
      ping_pong_server_stm_loop(L, Conn, Stm);
    {error, listener_start_error, 200000002} ->
      timer:sleep(100),
      ping_pong_server(Owner, Config, Port)
  end.

ping_pong_server_stm_loop(L, Conn, Stm) ->
  true = is_reference(Stm),
  receive
    {quic, <<"ping">>, _, _, _, _} ->
      {ok, 4} = quicer:send(Stm, <<"pong">>),
      ping_pong_server_stm_loop(L, Conn, Stm);
    done ->
      quicer:close_connection(Conn),
      quicer:close_listener(L)
  end.

simple_conn_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, _Conn} = quicer:accept(L, [], 5000),
  receive done ->
      quicer:close_listener(L),
      ok
  end.

conn_server_with(Owner, Port, Opts) ->
  {ok, L} = quicer:listen(Port, Opts),
  Owner ! listener_ready,
  {ok, _Conn} = quicer:accept(L, [], 5000),
  receive done ->
    quicer:close_listener(L),
    ok
  end.

simple_stream_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 5000),
  {ok, _Stream }= quicer:accept_stream(Conn, []),
  receive done ->
      quicer:close_listener(L),
      ok
  end.

default_stream_opts() ->
  [].

default_conn_opts() ->
  [{alpn, ["sample"]},
   {idle_timeout_ms, 5000},
   {peer_unidi_stream_count, 1},
   {peer_bidi_stream_count, 10}].

default_listen_opts(Config) ->
  DataDir = ?config(data_dir, Config),
  [ {cert, filename:join(DataDir, "cert.pem")}
  , {key,  filename:join(DataDir, "key.pem")}
  , {alpn, ["sample"]}].


%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
