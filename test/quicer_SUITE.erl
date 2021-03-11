%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
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

        , tc_getopt/1
        ]).

%% -include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").

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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
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

tc_getopt(Config) ->
  Parm = param_conn_quic_version,
  Port = 4569,
  Owner = self(),
  {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
  receive
    listener_ready ->
      {ok, Conn} = quicer:connect("localhost", Port, [], 5000),
      {ok, <<1,0,0,0>>} = quicer:getopt(Conn, Parm),
      {ok, Stm} = quicer:start_stream(Conn, []),
      {ok, 4} = quicer:send(Stm, <<"ping">>),
      {error, buffer_too_small} = quicer:getopt(Stm, Parm),
      ok = quicer:close_connection(Conn),
      SPid ! done
  after 1000 ->
      ct:fail("listener_timoeut")
  end.

%% internal helpers
echo_server(Owner, Config, Port)->
  case quicer:listen(Port, default_listen_opts(Config)) of
    {ok, L} ->
      Owner ! listener_ready,
      {ok, Conn} = quicer:accept(L, [], 5000),
      {ok, Stm} = quicer:accept_stream(Conn, []),
      echo_server_stm_loop(L, Conn, Stm);
    {error, listener_start_error, 200000002} ->
      timer:sleep(100),
      ping_pong_server(Owner, Config, Port)
  end.

echo_server_stm_loop(L, Conn, Stm) ->
  receive
    {quic, Bin, Stm, _, _, _} ->
      quicer:send(Stm, Bin),
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

simple_stream_server(Owner, Config, Port) ->
  {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
  Owner ! listener_ready,
  {ok, Conn} = quicer:accept(L, [], 5000),
  {ok, _Stream }= quicer:accept_stream(Conn, []),
  receive done ->
      quicer:close_listener(L),
      ok
  end.

default_listen_opts(Config) ->
  DataDir = ?config(data_dir, Config),
  [ {cert, filename:join(DataDir, "cert.pem")}
  , {key,  filename:join(DataDir, "key.pem")}].


%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
