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
  {error,eaddrinuse} = gen_udp:open(Port),
  ok = quicer:close_listener(L),
  ok.

tc_close_listener(_Config) ->
  {error,badarg} = quicer:close_listener(make_ref()).

%% internal helpers
default_listen_opts(Config) ->
  DataDir = ?config(data_dir, Config),
  [ {cert, filename:join(DataDir, "cert.pem")}
  , {key,  filename:join(DataDir, "key.pem")}].


%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
