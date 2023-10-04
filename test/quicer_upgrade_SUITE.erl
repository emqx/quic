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
-module(quicer_upgrade_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
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
    %% close all listeners under global registration
    [quicer:close_listener(L, 1000) || L <- quicer:get_listeners()],
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
init_per_testcase(TestCase, Config) ->
    case erlang:function_exported(?MODULE, TestCase, 2) of
        false ->
            Config;
        true ->
            ?MODULE:TestCase(init, Config)
    end.

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
%% @spec TestCase(Config0) ->
%%               ok | exit() | {skip,Reason} | {comment,Comment} |
%%               {save_config,Config1} | {skip_and_save,Reason,Config1}
%% Config0 = Config1 = [tuple()]
%% Reason = term()
%% Comment = term()
%% @end
%%--------------------------------------------------------------------
tc_nif_module_is_loaded(_Config) ->
    ?assertMatch({file, _}, code:is_loaded(quicer_nif)).

tc_nif_module_purge(init, Config) ->
    %% When we have both old code and new code
    case code:load_file(quicer_nif) of
        {module, quicer_nif} ->
            ok;
        {error, not_purged} ->
            ok
    end,
    Config.
tc_nif_module_purge(_Config) ->
    %% Then purge old code should success (test nif lib no crash)
    ?assertEqual(false, code:purge(quicer_nif)).

tc_nif_no_old_module_purge(init, Config) ->
    %% Give there is no old code of quicer_nif present
    code:purge(quicer_nif),
    Config.
tc_nif_no_old_module_purge(_Config) ->
    %% Then purge non existing old code should success (test nif lib no crash)
    ?assertEqual(false, code:purge(quicer_nif)).

tc_nif_module_reload(init, Config) ->
    %% Given no old code of quicer_nif present
    code:purge(quicer_nif),
    Config.
tc_nif_module_reload(_Config) ->
    %% When reload quicer_nif with same module file
    %% Then load success
    ?assertEqual({module, quicer_nif}, code:load_file(quicer_nif)).

tc_nif_module_load_current(init, Config) ->
    %% Given no new/old code of quicer_nif present
    ensure_module_no_code(quicer_nif),
    Config.
tc_nif_module_load_current(_Config) ->
    %% When load quicer_nif, it should success
    ?assertEqual({module, quicer_nif}, code:load_file(quicer_nif)).

tc_nif_module_softpurge(init, Config) ->
    %% When we have both old code and new code
    case code:load_file(quicer_nif) of
        {module, quicer_nif} ->
            ok;
        {error, not_purged} ->
            ok
    end,
    Config.
tc_nif_module_softpurge(_Config) ->
    ?assertEqual(true, code:soft_purge(quicer_nif)).

tc_nif_module_no_reinit(_Config) ->
    %% Given quicer_nif is not loaded
    ensure_module_no_code(quicer_nif),
    Res = {error, {reload, "NIF library already loaded (reload disallowed since OTP 20)."}},
    %% When calling quicer_nif:init/1 with ABI version 1
    %% Then it should still fail
    ?assertEqual(Res, quicer_nif:init(1)).

tc_nif_module_load_fail_dueto_mismatch_abiversion(init, Config) ->
    %% Given quicer_nif is not loaded
    ensure_module_no_code(quicer_nif),
    %% When _quicer_overrides_ provides ABI version 0 which is reserved
    persistent_term:put({'_quicer_overrides_', abi_version}, 0),
    Config.
tc_nif_module_load_fail_dueto_mismatch_abiversion(_Config) ->
    %% Then load quicer_nif should fail due to abi version mismatch
    ?assertEqual({error, on_load_failure}, code:load_file(quicer_nif)),
    persistent_term:erase({'_quicer_overrides_', abi_version}).

tc_nif_module_upgrade_fail_dueto_mismatch_abiversion(init, Config) ->
    %% Given quicer_nif has current code
    ensure_module_current_vsn(quicer_nif),
    %% When _quicer_overrides_ provides ABI version 0 which is reserved
    persistent_term:put({'_quicer_overrides_', abi_version}, 0),
    Config.
tc_nif_module_upgrade_fail_dueto_mismatch_abiversion(_Config) ->
    %% Then upgrade quicer_nif should fail due to abi version mismatch
    ?assertEqual({error, on_load_failure}, code:load_file(quicer_nif)),
    persistent_term:erase({'_quicer_overrides_', abi_version}),
    %% Then quicer_nif should still be loaded
    ?assertMatch({file, _}, code:is_loaded(quicer_nif)).

%% Helpers

%% @doc ensure neither old nor new code is present
ensure_module_no_code(Module) ->
    %% purge old if any
    code:purge(Module),
    %% current become old
    code:delete(Module),
    %% assert no current.
    not_loaded = code:module_status(Module),
    %% force purge this old
    _ = code:purge(Module).

%% @doc ensure only current code is present
ensure_module_current_vsn(Module) ->
    ensure_module_no_code(Module),
    _ = code:load_file(Module),
    ok.
