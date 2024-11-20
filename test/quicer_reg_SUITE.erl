%%--------------------------------------------------------------------
%% Copyright (c) 2023-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
    [{timetrap, {seconds, 30}}].

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
    erlang:garbage_collect(self(), [{type, major}]),
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
tc_new_reg(Config) ->
    {Pid, Ref} = erlang:spawn_monitor(fun() -> do_tc_new_reg(Config) end),
    receive
        {'DOWN', Ref, process, Pid, Reason} ->
            ?assertEqual(normal, Reason)
    end.

do_tc_new_reg(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    quicer:shutdown_registration(Reg),
    quicer:close_registration(Reg),
    ok.

tc_shutdown_reg_1(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:close_registration(Reg),
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
    ?assertEqual({error, badarg}, quicer:shutdown_registration(Reg, true, -1)),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:close_registration(Reg).

tc_shutdown_ok(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:close_registration(Reg).

tc_shutdown_twice(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:shutdown_registration(Reg),
    ok = quicer:close_registration(Reg).

tc_shutdown_with_reason(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ok = quicer:shutdown_registration(Reg, false, 123),
    ok = quicer:close_registration(Reg).

tc_get_reg_name(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    ?assertEqual({ok, Name}, quicer:get_registration_name(Reg)),
    ok = quicer:shutdown_registration(Reg),
    ?assertEqual({ok, Name}, quicer:get_registration_name(Reg)),
    ok = quicer:close_registration(Reg).

tc_close_with_opened_conn(_Config) ->
    Name = atom_to_list(?FUNCTION_NAME),
    Profile = quic_execution_profile_low_latency,
    {ok, Reg} = quicer:new_registration(Name, Profile),
    %% @NOTE This is a hack to make sure the connection is abled to be closed
    %%       which is triggered by the registration close
    spawn(fun() ->
        {ok, Conn} = quicer:open_connection(#{quic_registration => Reg}),
        quicer:connect("localhost", 5060, [{alpn, ["sample"]}, {handle, Conn}], 1000)
    end),
    _ = quicer:shutdown_registration(Reg),
    ?assertEqual(ok, quicer:close_registration(Reg)).

tc_close_global_reg(_Config) ->
    ?assertEqual(ok, quicer:reg_close()),
    %% close more
    ?assertEqual(ok, quicer:reg_close()),
    %% close one more
    ?assertEqual(ok, quicer:reg_close()),
    quicer:reg_open().

tc_open_global_reg(_Config) ->
    ?assertEqual(ok, quicer:reg_close()),
    ?assertEqual(ok, quicer:reg_open()).

tc_shutdown_global_reg(_Config) ->
    ?assertEqual(ok, quicer:shutdown_registration(global)),
    ?assertEqual(ok, quicer:reg_close()).

tc_get_links_link_closed(_Config) ->
    ok = quicer:reg_close(),
    ?assertEqual({error, quic_registration}, quicer:get_connections()).
