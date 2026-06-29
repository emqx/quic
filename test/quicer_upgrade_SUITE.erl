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
-module(quicer_upgrade_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").
-include_lib("quicer/include/quicer.hrl").

-import(quicer_test_lib, [
    default_conn_opts/0,
    default_listen_opts/1,
    select_free_port/1
]).

-define(DEFAULT_OLD_VERSION, "0.2.5").
-define(HTTP_TIMEOUT, 120000).
-define(SLAVE_TIMEOUT, 40000).
%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
    [{timetrap, {minutes, 1}}].

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
    quicer_test_lib:generate_tls_certs(Config),
    try prepare_upgrade_dirs(Config) of
        Config1 -> Config1
    catch
        throw:{skip, Reason} -> {skip, Reason}
    end.

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
    [
        {old_to_current, [sequence], [
            tc_upgrade_basic_nif_reload,
            tc_upgrade_soft_and_hard_purge,
            tc_application_upgrade,
            tc_upgrade_with_traffic,
            tc_unload_module_with_bg_traffic
        ]},
        {release, [sequence], [
            tc_release_package_contract,
            tc_same_version_load_delete_purge_no_thread_growth
        ]}
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
    LocalTcs =
        quicer_test_lib:all_tcs(?MODULE) --
            [
                tc_upgrade_basic_nif_reload,
                tc_upgrade_soft_and_hard_purge,
                tc_application_upgrade,
                tc_upgrade_with_traffic,
                tc_unload_module_with_bg_traffic,
                tc_release_package_contract,
                tc_same_version_load_delete_purge_no_thread_growth
            ],
    LocalTcs ++ [{group, old_to_current}, {group, release}].

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

tc_upgrade_basic_nif_reload(Config) ->
    with_slave(Config, fun(Node) ->
        %% GIVEN: slave runs old vsn quicer
        OldPriv = rpc_call(Node, ?MODULE, slave_load_old_quicer, []),
        assert_remote_alive(Node),
        ?assertEqual(old_priv_dir(Config), OldPriv),
        %% WHEN: slave is called to upgrade the NIF.
        {ok, Info} = rpc_call(
            Node,
            ?MODULE,
            slave_upgrade_nif,
            [current_app_dir(Config), old_app_dir(Config)]
        ),
        assert_remote_alive(Node),
        ?assertEqual(current_priv_dir(Config), maps:get(priv_dir, Info)),
        ?assertEqual(1, maps:get(abi_version, Info)),
        %% THEN: 'old' code exists
        true = rpc_call(Node, erlang, check_old_code, [quicer_nif]),
        ok
    end).

tc_upgrade_soft_and_hard_purge(Config) ->
    with_slave(Config, fun(Node) ->
        _ = rpc_call(Node, ?MODULE, slave_load_old_quicer, []),
        {ok, _Info} = rpc_call(
            Node,
            ?MODULE,
            slave_upgrade_nif,
            [current_app_dir(Config), old_app_dir(Config)]
        ),
        %% GIVEN: slave runs new code but also has old code
        true = rpc_call(Node, erlang, check_old_code, [quicer_nif]),
        %% WHEN: *soft* purge old code success
        true = rpc_call(Node, code, soft_purge, [quicer_nif]),
        %% THEN: NO old code.
        false = rpc_call(Node, erlang, check_old_code, [quicer_nif]),
        assert_remote_alive(Node),
        %% WHEN: slave load New code (same vsn) and then *hard* purge
        {module, quicer_nif} = rpc_call(Node, code, load_file, [quicer_nif]),
        _ = rpc_call(Node, code, purge, [quicer_nif]),
        %% THEN: old code is purged.
        false = rpc_call(Node, erlang, check_old_code, [quicer_nif]),
        assert_remote_alive(Node),
        ok
    end).

tc_application_upgrade(Config) ->
    with_slave(Config, fun(Node) ->
        %% GIVEN: when slave rus old vsn app
        {ok, OldVsn} = rpc_call(Node, ?MODULE, slave_start_old_application, []),
        ?assertEqual(old_version(Config), OldVsn),
        %% WHEN: upgrade app with release handler
        {ok, UpgradeInfo} = rpc_call(
            Node,
            ?MODULE,
            slave_upgrade_application,
            [current_app_dir(Config), old_app_dir(Config)]
        ),
        assert_remote_alive(Node),
        %% THEN: app vsn is switched to new
        ?assertEqual(current_version(Config), maps:get(vsn, UpgradeInfo)),
        ?assertEqual(current_priv_dir(Config), maps:get(priv_dir, UpgradeInfo)),
        ok
    end).

tc_upgrade_with_traffic(Config) ->
    with_slave(Config, fun(Node) ->
        Port = select_free_port(quic),
        {ok, OldVsn} = rpc_call(Node, ?MODULE, slave_start_old_application, []),
        CheckThreads = rpc_call(Node, ?MODULE, thread_count_check_supported, []),
        OldNoThreads = maybe_no_threads(Node, CheckThreads),
        %% GIVEN: slave node is running traffic
        ?assertEqual(OldVsn, old_version()),
        {ok, Pair} = rpc_call(Node, ?MODULE, slave_start_ping_pair, [Config, Port]),
        %% WHEN: we load new vsn of code
        UpgradeResult = rpc_call(
            Node,
            ?MODULE,
            slave_upgrade_nif_with_timeout,
            [current_app_dir(Config), old_app_dir(Config), 5000]
        ),
        ct:pal("upgrade-with-traffic NIF reload result: ~p", [UpgradeResult]),
        timer:sleep(1000),
        NewNoThreads = maybe_no_threads(Node, CheckThreads),

        assert_remote_alive(Node),
        %% THEN: old code is still in use and new code spawn more worker treads
        ?assertEqual(true, rpc_call(Node, erlang, check_old_code, [quicer_nif])),
        maybe_assert_thread_growth(OldNoThreads, NewNoThreads),
        %% WHEN: we purge the code after stopped the traffic and the listener.
        ok = rpc_call(Node, ?MODULE, slave_stop_ping_pair, [Pair]),
        ct:pal("rpc slave_stop_ping_pair ok"),
        %% THEN: purge success and no killed process.
        ?assertEqual(false, rpc_call(Node, code, purge, [quicer_nif])),
        %% THEN: no old code for quicer_nif
        ?assertEqual(false, rpc_call(Node, erlang, check_old_code, [quicer_nif])),
        maybe_assert_thread_count_at_most(Node, CheckThreads, NewNoThreads),
        case UpgradeResult of
            {ok, _UpgradeInfo} ->
                assert_remote_alive(Node);
            {timeout, _Pid} ->
                assert_remote_alive(Node)
        end,
        ok
    end).

tc_unload_module_with_bg_traffic(Config) ->
    with_slave(Config, fun(Node) ->
        Port = select_free_port(quic),
        {ok, OldVsn} = rpc_call(Node, ?MODULE, slave_start_old_application, []),
        ?assertEqual(OldVsn, old_version()),
        %% GIVE: quicer is running traffic with old version
        {ok, Pair} = rpc_call(Node, ?MODULE, slave_start_ping_pair, [Config, Port]),
        ?assertEqual(false, rpc_call(Node, erlang, check_old_code, [quicer_nif])),
        {ok, BgTraffic} = rpc_call(Node, ?MODULE, slave_start_bg_ping_traffic, [Pair]),
        timer:sleep(1000),
        %% WHEN: unload the quicer nif.
        UnloadResult = rpc_call(Node, code, delete, [quicer_nif]),
        ct:pal("module delete while traffic running result: ~p", [UnloadResult]),
        assert_remote_alive(Node),
        %% THEN: quicer nif is unloaded but old process is lingering with old code.
        ?assertEqual(true, rpc_call(Node, erlang, check_old_code, [quicer_nif])),
        %% WHEN: we start new pair of the traffic
        ok = rpc_call(Node, ?MODULE, slave_ping_pair, [Pair, <<"after-unload">>]),
        %% THEN: we have co-exists new & old code but same copy
        ?assertEqual(true, rpc_call(Node, erlang, check_old_code, [quicer_nif])),
        ?assertNotEqual(false, rpc_call(Node, code, is_loaded, [quicer_nif])),
        ok = rpc_call(Node, ?MODULE, slave_stop_bg_ping_traffic, [BgTraffic]),
        ok = rpc_call(Node, ?MODULE, slave_stop_ping_pair, [Pair]),
        ok
    end).

%% verifies that a release-style prebuilt NIF package can be created,
%%        checksummed, extracted, and loaded from a separate quicer app directory
%%        on a peer node
tc_release_package_contract(Config) ->
    PackageDir = filename:join(?config(priv_dir, Config), "release_package"),
    PackageSrc = filename:join(PackageDir, "src"),
    ReleaseAppDir = filename:join([PackageDir, "release_app", "quicer"]),
    ReleaseEbin = filename:join(ReleaseAppDir, "ebin"),
    ReleasePriv = filename:join(ReleaseAppDir, "priv"),
    PackageName = release_nif_asset_name(env_or_default("QUICER_VERSION", current_version(Config))),
    Package = filename:join(PackageDir, PackageName),
    Sha256File = Package ++ ".sha256",
    ok = ensure_clean_dir(PackageDir),
    ok = filelib:ensure_dir(filename:join(PackageSrc, "dummy")),
    ok = filelib:ensure_dir(filename:join(ReleaseEbin, "dummy")),
    ok = filelib:ensure_dir(filename:join(ReleasePriv, "dummy")),
    ok = copy_dir_files(filename:join(current_app_dir(Config), "ebin"), ReleaseEbin),
    StagedNif = filename:join(PackageSrc, "libquicer_nif.so"),
    ok = copy_file(current_nif_file(), StagedNif),
    ok = create_nif_release_package(Package, StagedNif),
    Sha256 = sha256_hex(Package),
    ok = file:write_file(Sha256File, [Sha256, $\n]),
    {ok, WrittenSha256} = file:read_file(Sha256File),
    ?assertEqual(Sha256, string:trim(binary_to_list(WrittenSha256))),
    ok = erl_tar:extract(Package, [compressed, {cwd, ReleasePriv}]),
    ok = assert_old_nif_present(ReleasePriv),
    with_slave(Config, fun(Node) ->
        ok = rpc_call(Node, ?MODULE, slave_load_release_nif, [ReleaseAppDir]),
        assert_remote_alive(Node),
        ok
    end).

tc_same_version_load_delete_purge_no_thread_growth(Config) ->
    with_slave(Config, fun(Node) ->
        ok = rpc_call(Node, ?MODULE, slave_same_version_load_delete_purge, [
            current_app_dir(Config), 10
        ]),
        assert_remote_alive(Node),
        ok
    end).

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

%% Upgrade fixture setup

prepare_upgrade_dirs(Config) ->
    OldVersion = old_version(),
    PrivDir = ?config(priv_dir, Config),
    WorkDir = filename:join(PrivDir, "upgrade"),
    OldAppDir = filename:join([WorkDir, "old", "quicer"]),
    CurrentAppDir = filename:join([WorkDir, "current", "quicer"]),
    ok = ensure_clean_dir(WorkDir),
    ok = prepare_current_app_dir(CurrentAppDir),
    ok = prepare_old_app_dir(OldVersion, WorkDir, OldAppDir),
    OldApp = read_app_file(filename:join([OldAppDir, "ebin", "quicer.app"])),
    CurrentApp = read_app_file(filename:join([CurrentAppDir, "ebin", "quicer.app"])),
    OldVsn = app_vsn(OldApp),
    CurrentVsn = app_vsn(CurrentApp),
    ok = write_appup(OldAppDir, OldVsn, CurrentVsn, []),
    ok = write_appup(CurrentAppDir, CurrentVsn, OldVsn, current_modules(CurrentApp)),
    ct:pal("quicer upgrade fixture old_version=~s current_version=~s old_dir=~s current_dir=~s", [
        OldVsn, CurrentVsn, OldAppDir, CurrentAppDir
    ]),
    [
        {upgrade_work_dir, WorkDir},
        {old_quicer_version, OldVsn},
        {old_quicer_app_dir, OldAppDir},
        {current_quicer_version, CurrentVsn},
        {current_quicer_app_dir, CurrentAppDir}
        | Config
    ].

prepare_current_app_dir(CurrentAppDir) ->
    Ebin = filename:join(CurrentAppDir, "ebin"),
    Priv = filename:join(CurrentAppDir, "priv"),
    ok = ensure_clean_dir(CurrentAppDir),
    ok = filelib:ensure_dir(filename:join(Ebin, "dummy")),
    ok = filelib:ensure_dir(filename:join(Priv, "dummy")),
    CurrentEbin = code:lib_dir(quicer, ebin),
    ok = copy_dir_files(CurrentEbin, Ebin),
    Nif = current_nif_file(),
    ok = copy_file(Nif, filename:join(Priv, filename:basename(Nif))),
    case filename:basename(Nif) of
        "libquicer_nif.so" ->
            ok;
        _ ->
            ok = copy_file(Nif, filename:join(Priv, "libquicer_nif.so"))
    end,
    ok.

prepare_old_app_dir(OldVersion, WorkDir, OldAppDir) ->
    Downloads = filename:join(WorkDir, "downloads"),
    SourceRoot = filename:join(WorkDir, "old_source"),
    OldEbin = filename:join(OldAppDir, "ebin"),
    OldPriv = filename:join(OldAppDir, "priv"),
    ok = filelib:ensure_dir(filename:join(Downloads, "dummy")),
    ok = ensure_clean_dir(OldAppDir),
    ok = filelib:ensure_dir(filename:join(OldEbin, "dummy")),
    ok = filelib:ensure_dir(filename:join(OldPriv, "dummy")),
    SourceDir = fetch_old_source(OldVersion, Downloads, SourceRoot),
    ok = compile_old_beams(SourceDir, OldEbin),
    ok = write_old_app(SourceDir, OldEbin, OldVersion),
    ok = fetch_old_nif(OldVersion, Downloads, OldPriv),
    ok.

old_version() ->
    env_or_default("QUICER_UPGRADE_FROM_VERSION", ?DEFAULT_OLD_VERSION).

old_version(Config) ->
    ?config(old_quicer_version, Config).

current_version(Config) ->
    ?config(current_quicer_version, Config).

old_app_dir(Config) ->
    ?config(old_quicer_app_dir, Config).

current_app_dir(Config) ->
    ?config(current_quicer_app_dir, Config).

old_priv_dir(Config) ->
    filename:join(old_app_dir(Config), "priv").

current_priv_dir(Config) ->
    filename:join(current_app_dir(Config), "priv").

env_or_default(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        "" -> Default;
        Value -> Value
    end.

fetch_old_source(OldVersion, Downloads, SourceRoot) ->
    SourceTar = filename:join(Downloads, "quicer-" ++ OldVersion ++ ".tar.gz"),
    SourceUrls = source_urls(OldVersion),
    ok = download_first(SourceUrls, SourceTar),
    ok = ensure_clean_dir(SourceRoot),
    ok = erl_tar:extract(SourceTar, [compressed, {cwd, SourceRoot}]),
    [Dir] = filelib:wildcard(filename:join(SourceRoot, "*")),
    Dir.

source_urls(OldVersion) ->
    Tags =
        case string:prefix(OldVersion, "v") of
            nomatch -> [OldVersion, "v" ++ OldVersion];
            _ -> [OldVersion]
        end,
    ["https://github.com/emqx/quic/archive/refs/tags/" ++ Tag ++ ".tar.gz" || Tag <- Tags].

fetch_old_nif(OldVersion, Downloads, OldPriv) ->
    GzFile = filename:join(Downloads, old_nif_asset_name(OldVersion)),
    {IsExactUrl, Urls} =
        case os:getenv("QUICER_UPGRADE_FROM_URL") of
            false -> {false, old_nif_urls(OldVersion)};
            "" -> {false, old_nif_urls(OldVersion)};
            Url -> {true, [Url]}
        end,
    case download_first_result(Urls, GzFile) of
        ok ->
            ok;
        {error, Reasons} when IsExactUrl ->
            ct:fail({download_failed, GzFile, lists:reverse(Reasons)});
        {error, Reasons} ->
            throw(
                {skip,
                    {old_prebuilt_nif_not_available, old_nif_asset_name(OldVersion),
                        lists:reverse(Reasons)}}
            )
    end,
    ok = unpack_old_nif(GzFile, OldPriv),
    ok = assert_old_nif_present(OldPriv).

unpack_old_nif(GzFile, OldPriv) ->
    case erl_tar:extract(GzFile, [compressed, {cwd, OldPriv}]) of
        ok ->
            ok;
        {error, _Reason} ->
            {ok, GzBin} = file:read_file(GzFile),
            NifBin = zlib:gunzip(GzBin),
            ok = file:write_file(filename:join(OldPriv, "libquicer_nif.so"), NifBin)
    end.

assert_old_nif_present(OldPriv) ->
    case filelib:is_file(filename:join(OldPriv, "libquicer_nif.so")) of
        true -> ok;
        false -> ct:fail({old_nif_not_found_after_unpack, OldPriv})
    end.

old_nif_urls(OldVersion) ->
    Asset = old_nif_asset_name(OldVersion),
    Tags =
        case string:prefix(OldVersion, "v") of
            nomatch -> [OldVersion, "v" ++ OldVersion];
            _ -> [OldVersion]
        end,
    ["https://github.com/emqx/quic/releases/download/" ++ Tag ++ "/" ++ Asset || Tag <- Tags].

old_nif_asset_name(OldVersion) ->
    lists:flatten(
        io_lib:format(
            "libquicer-~s-otp~s-~s-~s-~s.gz",
            [
                OldVersion,
                erlang:system_info(otp_release),
                quicer_upgrade_openssl(),
                package_system(),
                package_arch()
            ]
        )
    ).

release_nif_asset_name(Version) ->
    lists:flatten(
        io_lib:format(
            "libquicer-~s-otp~s-~s-~s-~s.gz",
            [
                Version,
                erlang:system_info(otp_release),
                env_or_default("QUICER_TLS_VER", "openssl"),
                package_system(),
                package_arch()
            ]
        )
    ).

quicer_upgrade_openssl() ->
    case os:getenv("QUICER_UPGRADE_OPENSSL") of
        false -> package_openssl_name(env_or_default("QUICER_TLS_VER", "openssl"));
        "" -> package_openssl_name(env_or_default("QUICER_TLS_VER", "openssl"));
        Value -> Value
    end.

package_openssl_name("sys") -> "sys";
package_openssl_name("openssl3") -> "openssl3";
package_openssl_name(_BundledOpenSSL) -> "openssl".

package_arch() ->
    string:trim(os:cmd("uname -m")).

package_system() ->
    case os:type() of
        {unix, darwin} ->
            Major = string:trim(os:cmd("sw_vers -productVersion | cut -d. -f1")),
            "macos" ++ Major;
        {unix, linux} ->
            linux_package_system();
        Other ->
            ct:fail({unsupported_upgrade_os, Other})
    end.

linux_package_system() ->
    {ok, Bin} = file:read_file("/etc/os-release"),
    Lines = string:split(binary_to_list(Bin), "\n", all),
    Id = os_release_value("ID", Lines),
    VersionId = os_release_value("VERSION_ID", Lines),
    strip_linux_suffix(Id ++ VersionId).

os_release_value(Key, Lines) ->
    Prefix = Key ++ "=",
    case
        [
            strip_quotes(string:trim(string:substr(Line, length(Prefix) + 1)))
         || Line <- Lines,
            lists:prefix(Prefix, Line)
        ]
    of
        [Value | _] -> Value;
        [] -> ""
    end.

strip_quotes([$" | Rest]) ->
    lists:reverse(strip_leading_quote(lists:reverse(Rest)));
strip_quotes(Value) ->
    Value.

strip_leading_quote([$" | Rest]) -> Rest;
strip_leading_quote(Value) -> Value.

strip_linux_suffix(System) ->
    case string:chr(System, $-) of
        0 ->
            System;
        Pos ->
            {Letters, _} = lists:splitwith(
                fun(C) ->
                    (C >= $a andalso C =< $z) orelse
                        (C >= $A andalso C =< $Z)
                end,
                string:slice(System, 0, Pos - 1)
            ),
            Letters
    end.

download_first(Urls, Target) ->
    case download_first_result(Urls, Target) of
        ok ->
            ok;
        {error, Reasons} ->
            ct:fail({download_failed, Target, lists:reverse(Reasons)})
    end.

download_first_result(Urls, Target) ->
    download_first(Urls, Target, []).

download_first([], _Target, Reasons) ->
    {error, Reasons};
download_first([Url | Rest], Target, Reasons) ->
    ct:pal("download ~s to ~s", [Url, Target]),
    case download(Url, Target) of
        ok -> ok;
        {error, Reason} -> download_first(Rest, Target, [{Url, Reason} | Reasons])
    end.

download(Url, Target) ->
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(inets),
    Headers = [{"user-agent", "quicer-upgrade-suite"}],
    HttpOptions = [{autoredirect, true}, {timeout, ?HTTP_TIMEOUT}],
    Options = [{body_format, binary}],
    case httpc:request(get, {Url, Headers}, HttpOptions, Options) of
        {ok, {{_, 200, _}, _RespHeaders, Body}} ->
            file:write_file(Target, Body);
        {ok, {{_, Status, ReasonPhrase}, _RespHeaders, Body}} ->
            {error, {http_status, Status, ReasonPhrase, byte_size(Body)}};
        {error, Reason} ->
            {error, Reason}
    end.

compile_old_beams(SourceDir, OldEbin) ->
    Include = filename:join(SourceDir, "include"),
    SrcFiles = filelib:wildcard(filename:join([SourceDir, "src", "*.erl"])),
    Results = [
        compile:file(Src, [
            report,
            {i, Include},
            {outdir, OldEbin}
        ])
     || Src <- SrcFiles
    ],
    case [Error || Error <- Results, not is_compile_ok(Error)] of
        [] -> ok;
        Errors -> ct:fail({old_source_compile_failed, Errors})
    end.

is_compile_ok({ok, _Module}) -> true;
is_compile_ok({ok, _Module, _Warnings}) -> true;
is_compile_ok(_) -> false.

write_old_app(SourceDir, OldEbin, OldVersion) ->
    AppSrc = filename:join([SourceDir, "src", "quicer.app.src"]),
    App = read_app_file(AppSrc),
    Modules = compiled_modules(OldEbin),
    App1 = set_app_props(App, [
        {vsn, OldVersion},
        {modules, Modules}
    ]),
    write_term_file(filename:join(OldEbin, "quicer.app"), App1).

write_appup(AppDir, ToVsn, FromVsn, Modules) ->
    Instructions = appup_instructions(Modules),
    Appup = {ToVsn, [{FromVsn, Instructions}], [{FromVsn, Instructions}]},
    write_term_file(filename:join([AppDir, "ebin", "quicer.appup"]), Appup).

appup_instructions([]) ->
    [];
appup_instructions(Modules) ->
    [{load_module, Module} || Module <- Modules].

read_app_file(File) ->
    {ok, [App]} = file:consult(File),
    App.

app_vsn({application, quicer, Props}) ->
    proplists:get_value(vsn, Props).

current_modules({application, quicer, Props}) ->
    [
        Module
     || Module <- proplists:get_value(modules, Props, []), lists:member(Module, quicer_modules())
    ].

compiled_modules(Ebin) ->
    lists:sort([
        list_to_atom(filename:basename(Beam, ".beam"))
     || Beam <- filelib:wildcard(filename:join(Ebin, "*.beam"))
    ]).

set_app_props({application, quicer, Props}, Updates) ->
    {application, quicer, lists:foldl(fun set_app_prop/2, Props, Updates)}.

set_app_prop({Key, Value}, Props) ->
    lists:keystore(Key, 1, Props, {Key, Value}).

write_term_file(File, Term) ->
    file:write_file(File, io_lib:format("~p.~n", [Term])).

create_nif_release_package(Package, NifFile) ->
    {ok, Tar} = erl_tar:open(Package, [write, compressed]),
    ok = erl_tar:add(Tar, NifFile, "libquicer_nif.so", []),
    ok = erl_tar:close(Tar).

sha256_hex(File) ->
    {ok, Bin} = file:read_file(File),
    lists:flatten([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= crypto:hash(sha256, Bin)]).

current_nif_file() ->
    Candidates = [
        filename:join(code:priv_dir(quicer), "libquicer_nif.so"),
        filename:join(["c_build", "priv", "libquicer_nif.so"])
    ],
    case [Path || Path <- Candidates, filelib:is_file(Path)] of
        [Path | _] -> Path;
        [] -> ct:fail({current_nif_not_found, Candidates})
    end.

copy_dir_files(From, To) ->
    {ok, Files} = file:list_dir(From),
    lists:foreach(
        fun(File) ->
            Src = filename:join(From, File),
            Dst = filename:join(To, File),
            case file:read_file_info(Src) of
                {ok, #file_info{type = regular}} ->
                    ok = copy_file(Src, Dst);
                {ok, #file_info{type = directory}} ->
                    ok = ensure_clean_dir(Dst),
                    ok = copy_dir_files(Src, Dst);
                {ok, _} ->
                    ok;
                {error, Reason} ->
                    ct:fail({copy_failed, Src, Reason})
            end
        end,
        Files
    ),
    ok.

copy_file(Src, Dst) ->
    case file:copy(Src, Dst) of
        {ok, _Bytes} -> ok;
        {error, Reason} -> ct:fail({copy_failed, Src, Dst, Reason})
    end.

ensure_clean_dir(Dir) ->
    _ = file:del_dir_r(Dir),
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")).

%% Slave control

with_slave(Config, Fun) ->
    {ok, Peer, Node} = start_upgrade_peer(Config),
    try
        Fun(Node)
    after
        ct:pal("stopping peer ~p on node ~p state=~p", [Peer, Node, catch peer:get_state(Peer)]),
        catch peer:stop(Peer)
    end.

start_upgrade_peer(Config) ->
    ok = ensure_distributed_master(),
    Name = upgrade_slave_name(),
    {ok, Peer, Node} = peer:start_link(#{
        name => Name,
        wait_boot => 30000,
        shutdown => {halt, 5000}
    }),
    OldEbin = filename:join(old_app_dir(Config), "ebin"),
    TestEbin = filename:dirname(code:which(?MODULE)),
    TestLibEbin = filename:dirname(code:which(quicer_test_lib)),
    ok = rpc_add_path(Node, add_patha, OldEbin),
    ok = rpc_add_path(Node, add_pathz, TestEbin),
    ok = rpc_add_path(Node, add_pathz, TestLibEbin),
    {module, ?MODULE} = rpc_call(Node, code, load_file, [?MODULE]),
    {module, quicer_test_lib} = rpc_call(Node, code, load_file, [quicer_test_lib]),
    {ok, Peer, Node}.

upgrade_slave_name() ->
    Suffix = lists:flatten(
        io_lib:format("~B_~B", [
            erlang:system_time(millisecond),
            erlang:unique_integer([positive])
        ])
    ),
    list_to_atom("quicer_upgrade_" ++ Suffix).

rpc_add_path(Node, Fun, Path) ->
    case rpc_call(Node, code, Fun, [Path]) of
        true -> ok;
        ok -> ok;
        {error, Reason} -> ct:fail({add_code_path_failed, Node, Path, Reason})
    end.

ensure_distributed_master() ->
    case node() of
        nonode@nohost ->
            Name = list_to_atom(
                "quicer_ct_master_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            case net_kernel:start([Name, shortnames]) of
                {ok, _Pid} -> ok;
                {error, {{already_started, _Pid}, _}} -> ok;
                {error, Reason} -> ct:fail({failed_to_start_distribution, Reason})
            end;
        _Node ->
            ok
    end.

rpc_call(Node, M, F, A) ->
    rpc_call(Node, M, F, A, ?SLAVE_TIMEOUT).
rpc_call(Node, M, F, A, Timeout) ->
    case rpc:call(Node, M, F, A, Timeout) of
        {badrpc, Reason} ->
            ct:fail({rpc_failed, Node, M, F, A, Reason});
        Result ->
            Result
    end.

assert_remote_alive(Node) ->
    pong = net_adm:ping(Node),
    true = rpc_call(Node, erlang, is_alive, []),
    ok.

maybe_no_threads(Node, true) ->
    rpc_call(Node, ?MODULE, no_threads, []);
maybe_no_threads(_Node, false) ->
    unsupported.

maybe_assert_thread_growth(unsupported, unsupported) ->
    ok;
maybe_assert_thread_growth(OldNoThreads, NewNoThreads) ->
    ?assertEqual(NewNoThreads, OldNoThreads + erlang:system_info(schedulers)).

maybe_assert_thread_count_at_most(_Node, false, _MaxThreads) ->
    ok;
maybe_assert_thread_count_at_most(Node, true, MaxThreads) ->
    ?assert(rpc_call(Node, ?MODULE, no_threads, []) =< MaxThreads).

%% Functions executed on the slave node.

slave_load_old_quicer() ->
    slave_purge_quicer_modules(),
    ok = ensure_quicer_loaded(),
    {ok, _} = application:ensure_all_started(quicer),
    OldEbin = code:lib_dir(quicer, ebin),
    ok = assert_module_loaded_from(quicer_nif, OldEbin),
    code:priv_dir(quicer).

slave_load_release_nif(ReleaseAppDir) ->
    slave_purge_quicer_modules(),
    ReleaseEbin = filename:join(ReleaseAppDir, "ebin"),
    ReleasePriv = filename:join(ReleaseAppDir, "priv"),
    ok = add_patha(ReleaseEbin),
    ok = ensure_quicer_loaded(),
    {ok, _} = application:ensure_all_started(quicer),
    ok = assert_module_loaded_from(quicer_nif, ReleaseEbin),
    ReleasePriv = code:priv_dir(quicer),
    ok.

slave_same_version_load_delete_purge(AppDir, Times) ->
    Ebin = filename:join(AppDir, "ebin"),
    ok = add_patha(Ebin),
    CheckThreads = thread_count_check_supported(),
    BaselineThreads =
        case CheckThreads of
            true -> no_threads();
            false -> unsupported
        end,
    io:format("same-version reload baseline threads: ~p~n", [BaselineThreads]),
    lists:foreach(
        fun(I) ->
            ok = slave_load_delete_purge_once(Ebin),
            ok = maybe_assert_same_version_thread_count(I, BaselineThreads)
        end,
        lists:seq(1, Times)
    ),
    ?assertEqual(false, erlang:check_old_code(quicer_nif)),
    ok = maybe_assert_final_thread_count(BaselineThreads),
    ok.

maybe_assert_same_version_thread_count(_I, unsupported) ->
    ok;
maybe_assert_same_version_thread_count(I, BaselineThreads) ->
    Threads = wait_thread_count_at_most(BaselineThreads, 2000),
    io:format("same-version reload iteration ~p threads: ~p~n", [I, Threads]),
    case Threads =< BaselineThreads of
        true -> ok;
        false -> exit({thread_count_increased, I, BaselineThreads, Threads})
    end.

maybe_assert_final_thread_count(unsupported) ->
    ok;
maybe_assert_final_thread_count(BaselineThreads) ->
    ?assertEqual(BaselineThreads, no_threads()),
    ok.

wait_thread_count_at_most(MaxThreads, Timeout) ->
    Sleep = 100,
    Attempts = max(1, Timeout div Sleep),
    wait_thread_count_at_most(MaxThreads, Attempts, Sleep, no_threads()).

wait_thread_count_at_most(MaxThreads, _Attempts, _Sleep, Threads) when Threads =< MaxThreads ->
    Threads;
wait_thread_count_at_most(_MaxThreads, 0, _Sleep, Threads) ->
    Threads;
wait_thread_count_at_most(MaxThreads, Attempts, Sleep, _Threads) ->
    timer:sleep(Sleep),
    wait_thread_count_at_most(MaxThreads, Attempts - 1, Sleep, no_threads()).

slave_load_delete_purge_once(Ebin) ->
    slave_purge_quicer_modules(),
    ok = add_patha(Ebin),
    ok = ensure_quicer_loaded(),
    {ok, _} = application:ensure_all_started(quicer),
    ok = assert_module_loaded_from(quicer_nif, Ebin),
    _ = application:stop(quicer),
    _ = application:unload(quicer),
    _ = code:delete(quicer_nif),
    _ = code:purge(quicer_nif),
    false = erlang:check_old_code(quicer_nif),
    ok.

slave_upgrade_nif(CurrentAppDir, _OldAppDir) ->
    CurrentEbin = filename:join(CurrentAppDir, "ebin"),
    ok = add_patha(CurrentEbin),
    case code:load_file(quicer_nif) of
        {module, quicer_nif} -> ok;
        {error, not_purged} -> ok
    end,
    ok = assert_module_loaded_from(quicer_nif, CurrentEbin),
    {ok, #{
        priv_dir => code:priv_dir(quicer),
        abi_version => quicer:abi_version(),
        loaded => code:is_loaded(quicer_nif)
    }}.

slave_upgrade_nif_with_timeout(CurrentAppDir, OldAppDir, Timeout) ->
    Parent = self(),
    Pid = spawn(fun() ->
        Parent ! {self(), catch slave_upgrade_nif(CurrentAppDir, OldAppDir)}
    end),
    receive
        {Pid, {'EXIT', Reason}} ->
            {error, Reason};
        {Pid, Result} ->
            Result
    after Timeout ->
        exit(Pid, kill),
        {timeout, Pid}
    end.

slave_start_old_application() ->
    slave_purge_quicer_modules(),
    ok = ensure_quicer_loaded(),
    {ok, _} = application:ensure_all_started(quicer),
    {ok, Vsn} = application:get_key(quicer, vsn),
    {ok, Vsn}.

slave_upgrade_application(CurrentAppDir, OldAppDir) ->
    CurrentEbin = filename:join(CurrentAppDir, "ebin"),
    OldEbin = filename:join(OldAppDir, "ebin"),
    case release_handler:upgrade_app(quicer, CurrentAppDir) of
        {ok, _Unpurged} ->
            ok;
        {error, {old_processes, _} = Reason} ->
            exit(Reason);
        {error, Reason} ->
            exit({upgrade_app_failed, Reason})
    end,
    ok = add_patha(CurrentEbin),
    ok = assert_module_loaded_from(quicer_nif, CurrentEbin),
    ok = assert_no_modules_loaded_from(OldEbin),
    ok = assert_no_old_code(quicer_modules()),
    {ok, Vsn} = application:get_key(quicer, vsn),
    {ok, #{
        vsn => Vsn,
        priv_dir => code:priv_dir(quicer),
        loaded => code:is_loaded(quicer_nif)
    }}.

slave_restart_quicer() ->
    _ = application:stop(quicer),
    _ = application:unload(quicer),
    application:ensure_all_started(quicer),
    ok.

assert_module_loaded_from(Module, Ebin) ->
    Expected = filename:absname(filename:join(Ebin, atom_to_list(Module) ++ ".beam")),
    case code:is_loaded(Module) of
        {file, Path} ->
            ?assertEqual(Expected, filename:absname(Path)),
            ok;
        Other ->
            exit({module_not_loaded_from_expected_path, Module, Expected, Other})
    end.

assert_no_modules_loaded_from(Ebin) ->
    OldEbin = filename:absname(Ebin),
    Lingering = [
        {Module, filename:absname(Path)}
     || Module <- quicer_modules(),
        {file, Path} <- [code:is_loaded(Module)],
        path_in_dir(Path, OldEbin)
    ],
    case Lingering of
        [] -> ok;
        _ -> exit({old_modules_lingering, OldEbin, Lingering})
    end.

assert_no_old_code(Modules) when is_list(Modules) ->
    Lingering = [Module || Module <- Modules, erlang:check_old_code(Module)],
    case Lingering of
        [] -> ok;
        _ -> exit({old_code_lingering, Lingering})
    end;
assert_no_old_code(Module) ->
    assert_no_old_code([Module]).

path_in_dir(Path, Dir) ->
    AbsPath = filename:absname(Path),
    AbsDir = filename:absname(Dir),
    lists:prefix(filename:join(AbsDir, ""), AbsPath).

add_patha(Path) ->
    case code:add_patha(Path) of
        true -> ok;
        ok -> ok;
        {error, Reason} -> exit({add_code_path_failed, Path, Reason})
    end.

ensure_quicer_loaded() ->
    case application:load(quicer) of
        ok -> ok;
        {error, {already_loaded, quicer}} -> ok;
        {error, Reason} -> exit({load_quicer_failed, Reason})
    end.

slave_purge_quicer_modules() ->
    _ = application:stop(quicer),
    _ = maybe_apply(quicer, reg_close, []),
    _ = maybe_apply(quicer, shutdown_registration, [global]),
    _ = maybe_apply(quicer, lib_close, []),
    _ = application:unload(quicer),
    lists:foreach(
        fun(Module) ->
            _ = code:purge(Module),
            _ = code:delete(Module),
            _ = code:purge(Module),
            false = code:is_loaded(Module),
            false = erlang:check_old_code(Module)
        end,
        quicer_modules()
    ),
    ok.

maybe_apply(Module, Function, Args) ->
    case erlang:function_exported(Module, Function, length(Args)) of
        true -> catch apply(Module, Function, Args);
        false -> ok
    end.

quicer_modules() ->
    [
        quicer,
        quicer_app,
        quicer_conn_acceptor_sup,
        quicer_connection,
        quicer_lib,
        quicer_listener,
        quicer_listener_sup,
        quicer_local_stream,
        quicer_nif,
        quicer_remote_stream,
        quicer_server_conn_callback,
        quicer_stream,
        quicer_sup
    ].

slave_hold_connection_resource() ->
    Parent = self(),
    Pid = spawn(fun() ->
        Conn = quicer_nif:open_connection(),
        Parent ! {self(), holding, Conn},
        receive
            release -> ok
        after 10000 ->
            ok
        end
    end),
    receive
        {Pid, holding, _Conn} -> Pid
    after 5000 ->
        exit(holder_timeout)
    end.

slave_wait_holder(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _Reason} -> ok
    after 5000 ->
        exit(holder_not_released)
    end.

slave_start_ping_pair(Config, Port) ->
    Parent = self(),
    Pid = spawn_link(fun() -> slave_ping_pair_controller(Parent, Config, Port) end),
    receive
        {Pid, ready} -> {ok, Pid};
        {Pid, failed, Reason} -> exit(Reason)
    after 5000 ->
        exit(ping_pair_timeout)
    end.

slave_start_bg_ping_traffic(Pair) ->
    Parent = self(),
    Pid = spawn(fun() -> slave_bg_ping_traffic_loop(Parent, Pair) end),
    receive
        {Pid, ready} -> {ok, Pid};
        {Pid, failed, Reason} -> exit(Reason)
    after 5000 ->
        exit(bg_ping_traffic_timeout)
    end.

slave_stop_bg_ping_traffic(Pid) ->
    Ref = erlang:monitor(process, Pid),
    Pid ! stop,
    receive
        {Pid, stopped} ->
            erlang:demonitor(Ref, [flush]),
            ok;
        {'DOWN', Ref, process, Pid, normal} ->
            ok;
        {'DOWN', Ref, process, Pid, Reason} ->
            exit({bg_ping_traffic_down, Reason})
    after 5000 ->
        erlang:demonitor(Ref, [flush]),
        exit(bg_ping_traffic_stop_timeout)
    end.

slave_bg_ping_traffic_loop(Parent, Pair) ->
    Parent ! {self(), ready},
    slave_bg_ping_traffic_run(Parent, Pair).

slave_bg_ping_traffic_run(Parent, Pair) ->
    receive
        stop ->
            Parent ! {self(), stopped},
            ok
    after 0 ->
        case catch slave_ping_pair(Pair, <<"bg-traffic">>) of
            ok ->
                timer:sleep(50),
                slave_bg_ping_traffic_run(Parent, Pair);
            {'EXIT', Reason} ->
                exit({bg_ping_traffic_failed, Reason});
            Other ->
                exit({bg_ping_traffic_failed, Other})
        end
    end.

slave_ping_pair(Pid, Payload) ->
    Ref = erlang:monitor(process, Pid),
    Pid ! {ping, self(), Ref, Payload},
    receive
        {Ref, Result} ->
            erlang:demonitor(Ref, [flush]),
            Result;
        {'DOWN', Ref, process, Pid, Reason} ->
            exit({ping_pair_down, Reason})
    after 5000 ->
        erlang:demonitor(Ref, [flush]),
        exit({ping_pair_timeout, Payload})
    end.

slave_stop_ping_pair(Pid) ->
    Ref = erlang:monitor(process, Pid),
    io:format("stopping traffic pair ~p ref=~p~n", [Pid, Ref]),
    Pid ! {stop, self(), Ref},
    receive
        {Ref, Result} ->
            io:format("traffic pair stop reply ~p from ~p~n", [Result, Pid]),
            erlang:demonitor(Ref, [flush]),
            Result;
        {'DOWN', Ref, process, Pid, _Reason} ->
            io:format("traffic pair went down before stop reply ~p~n", [Pid]),
            ok
    after 30000 ->
        io:format("traffic pair stop timeout ~p~n", [Pid]),
        erlang:demonitor(Ref, [flush]),
        exit(Pid, kill),
        ok
    end.

slave_ping_pair_controller(Parent, Config, Port) ->
    process_flag(trap_exit, true),
    ListenOn = "127.0.0.1:" ++ integer_to_list(Port),
    try
        {ok, Listener} = quicer:listen(ListenOn, default_listen_opts(Config)),
        Server = spawn_link(fun() -> slave_ping_server_acceptor(Listener) end),
        {ok, Conn} = quicer:connect("127.0.0.1", Port, default_conn_opts(), 5000),
        {ok, Stream} = quicer:start_stream(Conn, [{active, true}]),
        ok = slave_assert_ping(Stream, <<"before-upgrade">>),
        Parent ! {self(), ready},
        slave_ping_pair_loop(Server, Conn, Stream)
    catch
        Class:Reason:Stacktrace ->
            Parent ! {self(), failed, {Class, Reason, Stacktrace}}
    end.

slave_ping_pair_loop(Server, Conn, Stream) ->
    receive
        {ping, From, Ref, Payload} ->
            From ! {Ref, slave_assert_ping(Stream, Payload)},
            slave_ping_pair_loop(Server, Conn, Stream);
        {stop, From, Ref} ->
            From ! {Ref, ok},
            slave_ping_pair_stopped();
        {'EXIT', Server, Reason} ->
            slave_ping_pair_loop({exited, Server, Reason}, Conn, Stream);
        {'EXIT', _Pid, _Reason} ->
            slave_ping_pair_loop(Server, Conn, Stream)
    end.

slave_ping_pair_stopped() ->
    receive
        _Any ->
            slave_ping_pair_stopped()
    end.

slave_start_ping_server(Config, Port) ->
    Parent = self(),
    Pid = spawn_link(fun() -> slave_ping_server(Parent, Config, Port) end),
    receive
        {Pid, ready} -> {ok, Pid};
        {Pid, failed, Reason} -> exit(Reason)
    after 5000 ->
        exit(listener_timeout)
    end.

slave_wait_server(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, normal} -> ok;
        {'DOWN', Ref, process, Pid, Reason} -> exit({server_exit, Reason})
    after 5000 ->
        exit(server_stop_timeout)
    end.

slave_ping_server_acceptor(Listener) ->
    {ok, Conn} = quicer:accept(Listener, [], 5000),
    {ok, Conn} = quicer:async_accept_stream(Conn, []),
    {ok, Conn} = quicer:handshake(Conn),
    receive
        {quic, new_stream, Stream, _Props} ->
            slave_ping_server_loop(Listener, Conn, Stream)
    after 5000 ->
        exit(stream_accept_timeout)
    end.

slave_ping_server(Parent, Config, Port) ->
    ListenOn = "127.0.0.1:" ++ integer_to_list(Port),
    case quicer:listen(ListenOn, default_listen_opts(Config)) of
        {ok, Listener} ->
            Parent ! {self(), ready},
            {ok, Conn} = quicer:accept(Listener, [], 5000),
            {ok, Conn} = quicer:async_accept_stream(Conn, []),
            {ok, Conn} = quicer:handshake(Conn),
            receive
                {quic, new_stream, Stream, _Props} ->
                    slave_ping_server_loop(Listener, Conn, Stream)
            after 5000 ->
                exit(stream_accept_timeout)
            end;
        {error, Reason} ->
            Parent ! {self(), failed, Reason}
    end.

slave_stop_ping_pair_resources(Server, Conn, Stream) ->
    _ = catch quicer:close_stream(Stream),
    _ = catch quicer:close_connection(Conn),
    catch exit(Server, shutdown),
    timer:sleep(3000),
    ok.

slave_ping_server_loop(Listener, Conn, Stream) ->
    receive
        {quic, Bin, Stream, #{flags := Flags}} when is_binary(Bin) ->
            SendFlags =
                case (Flags band ?QUIC_RECEIVE_FLAG_FIN) > 0 of
                    true -> ?QUICER_SEND_FLAG_SYNC bor ?QUIC_SEND_FLAG_FIN;
                    false -> ?QUICER_SEND_FLAG_SYNC
                end,
            {ok, _} = quicer:send(Stream, Bin, SendFlags),
            slave_ping_server_loop(Listener, Conn, Stream);
        {quic, peer_send_shutdown, Stream, undefined} ->
            ok = quicer:close_stream(Stream),
            slave_ping_server_loop(Listener, Conn, Stream);
        {quic, shutdown, Conn, _ErrorCode} ->
            ok = quicer:close_connection(Conn),
            slave_ping_server_loop(Listener, Conn, Stream);
        stop ->
            io:format("server loop stop"),
            _ = quicer:close_connection(Conn),
            _ = quicer:close_listener(Listener),
            ok
    end.

slave_assert_ping(Stream, Payload) ->
    case quicer:send(Stream, Payload) of
        {ok, _} ->
            receive
                {quic, Payload, Stream, _Flags} -> ok
            after 5000 ->
                {error, {ping_timeout, Payload}}
            end;
        Error ->
            {error, {send_failed, Error}}
    end.

-spec no_threads() -> integer().
no_threads() ->
    true = thread_count_check_supported(),
    StatusFile = filename:join(["/proc", os:getpid(), "status"]),
    {ok, Status} = file:read_file(StatusFile),
    [ThreadsLine] = [
        Line
     || Line <- string:split(binary_to_list(Status), "\n", all),
        lists:prefix("Threads:", Line)
    ],
    ["Threads:", Count] = string:tokens(ThreadsLine, "\t "),
    list_to_integer(Count).

thread_count_check_supported() ->
    os:type() =:= {unix, linux}.
