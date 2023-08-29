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

-module(quicer_reg_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).
-compile(nowarn_export_all).

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
    [ F
      || {F, 1} <- ?MODULE:module_info(exports),
         nomatch =/= string:prefix(atom_to_list(F), "tc_")
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
tc_new_reg(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, _Reg} = quicer:new_registration(Name, Profile),
    ok.

tc_shutdown_reg_1(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg),
    ok.

tc_shutdown_1_abnormal(_Config) ->
    ?assertEqual({error, badarg}, quicer:shutdown_registration(erlang:make_ref())),
    ?assertEqual({error, badarg}, quicer:shutdown_registration(1)).

tc_shutdown_3_abnormal(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ?assertEqual({error, badarg}, quicer:shutdown_registration(Reg, 1, 2)),
    ?assertEqual({error, badarg}, quicer:shutdown_registration(Reg, 1, foo)),
    ?assertEqual({error, badarg}, quicer:shutdown_registration(Reg, true, -1)).

tc_shutdown_ok(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg).

tc_shutdown_twice(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:shutdown_registration(Reg).

tc_shutdown_with_reason(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg, false, 123).
