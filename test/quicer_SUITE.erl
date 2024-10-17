%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-include_lib("public_key/include/public_key.hrl").
-include("quicer.hrl").

%% API
-export([
    all/0,
    suite/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    group/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% test cases
-export([
    tc_nif_module_load/1,
    tc_nif_module_unload/1,
    tc_nif_module_reload/1,
    tc_open_lib_test/1,
    tc_close_lib_test/1,
    tc_lib_registration/1,
    tc_lib_registration_1/1,
    tc_lib_re_registration/1,
    tc_lib_registration_neg/1,
    tc_setopt_global_lb_mode_ifip/1,
    tc_open_listener_inval_reg/1,

    tc_stream_client_init/1,
    tc_stream_client_send_binary/1,
    tc_stream_client_send_iolist/1,
    tc_stream_client_async_send/1,

    tc_stream_passive_receive/1,
    tc_stream_passive_receive_shutdown/1,
    tc_stream_passive_receive_closed/1,
    tc_stream_passive_receive_aborted/1,
    tc_stream_passive_receive_buffer/1,
    tc_stream_passive_receive_large_buffer_1/1,
    tc_stream_passive_receive_large_buffer_2/1,
    tc_stream_send_after_conn_close/1,
    tc_stream_send_after_stream_shutdown/1,
    tc_stream_send_after_async_conn_close/1,
    tc_stream_sendrecv_large_data_passive/1,
    %% @deprecated
    %% , tc_stream_sendrecv_large_data_passive_2/1
    tc_stream_sendrecv_large_data_active/1,
    tc_stream_passive_switch_to_active/1,
    tc_stream_active_switch_to_passive/1,
    tc_stream_controlling_process/1,
    tc_stream_controlling_process_demon/1,
    tc_stream_get_owner_local/1,
    tc_stream_get_owner_remote/1,

    tc_dgram_client_send/1,
    tc_dgram_client_send_fail/1,

    % , tc_getopt_raw/1
    tc_getopt/1,
    tc_getopt_statistics_v2/1,
    tc_setopt_conn_settings/1,
    tc_setopt_bad_opt/1,
    tc_setopt_bad_nst/1,
    tc_setopt_config_settings/1,
    tc_setopt_global_retry_mem_percent/1,
    tc_getopt_global_retry_mem_percent/1,
    tc_setopt_global_lb_mode/1,
    tc_getopt_global_lb_mode/1,
    tc_getopt_global_lib_git_hash/1,
    tc_getopt_stream_active/1,
    tc_setopt/1,
    tc_setopt_remote_addr/1,
    tc_getopt_settings/1,
    tc_setopt_congestion_control_algorithm/1,

    %% @TODO following two tcs are failing due to:
    %  https://github.com/microsoft/msquic/issues/2033
    % , tc_setopt_conn_local_addr/1
    % , tc_setopt_conn_local_addr_in_use/1
    tc_setopt_conn_remote_addr/1,
    tc_setopt_stream_priority/1,
    tc_setopt_stream_unsupp_opts/1,
    tc_strm_opt_active_n/1,
    tc_strm_opt_active_once/1,
    tc_strm_opt_active_1/1,
    tc_strm_opt_active_badarg/1,
    tc_conn_opt_sslkeylogfile/1,
    tc_get_stream_id/1,
    tc_get_stream_id_after_close/1,
    tc_getstat/1,
    tc_getstat_closed/1,
    tc_peername_v4/1,
    tc_peername_v6/1,

    tc_alpn/1,
    tc_alpn_mismatch/1,
    tc_idle_timeout/1,

    tc_getopt_tls_handshake_info/1,
    tc_get_conn_rid/1,
    tc_get_stream_rid/1,

    tc_stream_open_flag_unidirectional/1,
    tc_stream_start_flag_fail_blocked/1,
    tc_stream_start_flag_immediate/1,
    tc_stream_start_flag_shutdown_on_fail/1,
    tc_stream_start_flag_indicate_peer_accept_1/1,
    tc_stream_start_flag_indicate_peer_accept_2/1,

    tc_stream_send_with_fin/1,
    tc_stream_send_with_fin_passive/1,
    tc_stream_send_shutdown_complete/1,
    tc_conn_and_stream_shared_owner/1,

    tc_get_stream_0rtt_length/1,
    tc_get_stream_ideal_sndbuff_size/1,
    %% insecure, msquic only
    tc_insecure_traffic/1,

    %% counters,
    tc_perf_counters/1,

    %% stream event masks
    tc_event_start_compl_client/1,
    tc_event_start_compl_server/1,

    %% API: csend
    tc_direct_send_over_conn/1,
    tc_direct_send_over_conn_block/1,
    tc_direct_send_over_conn_fail/1,

    %% TLS certs
    tc_peercert_client/1,
    tc_peercert_client_nocert/1,
    tc_peercert_server/1,
    tc_peercert_server_nocert/1,

    %% Versions test
    tc_abi_version/1
    %% testcase to verify env works
    %% , tc_network/1
]).

-export([tc_app_echo_server/1]).

-import(quicer_test_lib, [
    default_listen_opts/1,
    default_conn_opts/0,
    default_stream_opts/0,
    select_free_port/1
]).

%% -include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/inet.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(PROPTEST(M, F), true = proper:quickcheck(M:F())).

-define(SERVER_KEY_PASSWORD, "sErve7r8Key$!").

all() ->
    quicer_test_lib:all_tcs(?MODULE).

suite() ->
    [{ct_hooks, [cth_surefire]}, {timetrap, {seconds, 30}}].

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
    quicer_test_lib:generate_tls_certs(Config),
    application:ensure_all_started(quicer),
    Config.

end_per_suite(_Config) ->
    quicer_test_lib:report_active_connections(),
    application:stop(quicer),
    code:purge(quicer_nif),
    code:delete(quicer_nif),
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
    quicer_test_lib:cleanup_msquic(),
    [{timetrap, 5000} | Config].

end_per_testcase(tc_close_lib_test, _Config) ->
    quicer:open_lib();
end_per_testcase(tc_lib_registration, _Config) ->
    quicer:reg_open();
end_per_testcase(tc_lib_registration_1, _Config) ->
    quicer:reg_open();
end_per_testcase(tc_lib_re_registration, _Config) ->
    quicer:reg_open();
end_per_testcase(tc_lib_re_registration_neg, _Config) ->
    quicer:reg_open();
end_per_testcase(tc_open_listener_neg_1, _Config) ->
    quicer:open_lib(),
    quicer:reg_open();
end_per_testcase(tc_lib_registration_neg, _Config) ->
    quicer:reg_open();
end_per_testcase(_TestCase, _Config) ->
    quicer:terminate_listener(mqtt),
    quicer_test_lib:report_unhandled_messages(),
    quicer_test_lib:report_active_connections(fun ct:comment/2),
    ct:pal("Counters ~p", [quicer:perf_counters()]),
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
    code:purge(M),
    true = code:delete(M),
    ok.

tc_open_lib_test(_Config) ->
    {ok, false} = quicer:open_lib(),
    %% verify that reopen lib success.
    {ok, false} = quicer:open_lib().

tc_close_lib_test(_Config) ->
    ok = quicer:reg_close(),
    {ok, false} = quicer:open_lib(),
    ok = quicer:reg_close(),
    ok = quicer:close_lib(),
    ok = quicer:close_lib(),
    {ok, Res0} = quicer:open_lib(),
    ?assert(Res0 == true orelse Res0 == debug).

tc_lib_registration_neg(_Config) ->
    ok = quicer:close_lib(),
    {error, badarg} = quicer:reg_open(),
    {error, badarg} = quicer:reg_close().

tc_lib_registration(_Config) ->
    quicer:open_lib(),
    case quicer:reg_open() of
        {error, badarg} ->
            quicer:reg_close();
        ok ->
            ok
    end,
    ok = quicer:reg_close().

tc_lib_registration_1(_Config) ->
    ok = quicer:reg_close(),
    {error, badarg} = quicer:reg_open(foo),
    ok = quicer:reg_open(quic_execution_profile_low_latency),
    ok = quicer:reg_close(),
    ok = quicer:reg_open(quic_execution_profile_real_time),
    ok = quicer:reg_close(),
    ok = quicer:reg_open(quic_execution_profile_max_throughput),
    ok = quicer:reg_close(),
    ok = quicer:reg_open(quic_execution_profile_scavenger),
    ok = quicer:reg_close().

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

tc_open_listener_inval_reg(Config) ->
    Port = select_port(),
    ok = quicer:reg_close(),
    {error, quic_registration} = quicer:listen(Port, default_listen_opts(Config)),
    quicer:open_lib(),
    quicer:reg_open(),
    ok.

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
            flush_streams_available(Conn),
            flush_datagram_state_changed(Conn),
            receive
                {quic, <<"pong">>, _, _} ->
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
            flush_streams_available(Conn),
            flush_datagram_state_changed(Conn),
            receive
                {quic, <<"pong">>, _, _} ->
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
            flush_streams_available(Conn),
            flush_datagram_state_changed(Conn),
            receive
                {quic, <<"pong">>, _, _} ->
                    ok = quicer:close_stream(Stm),
                    ok = quicer:close_connection(Conn);
                Other ->
                    ct:fail("Unexpected Msg ~p", [Other])
            end,
            SPid ! done,
            receive
                {quic, send_complete, _Stm, _} -> ct:fail("shouldn't recv send_complete")
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
        end
    ),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                [{stream_recv_window_default, 1048576} | default_conn_opts()],
                5000
            ),
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
        end
    ),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect(
                "localhost",
                Port,
                default_conn_opts(),
                5000
            ),
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
                {quic, <<"ping_active">>, Stm, _} -> ok
            end,
            quicer:setopt(Stm, active, 100),
            {ok, 13} = quicer:send(Stm, <<"ping_active_2">>),
            receive
                {quic, <<"ping_active_2">>, Stm, _} -> ok
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
            flush_streams_available(Conn),
            flush_datagram_state_changed(Conn),
            {error, einval} = quicer:recv(Stm, 0),
            receive
                {quic, <<"ping_active">>, Stm, _} -> ok
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

tc_stream_passive_receive_shutdown(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"pong">>} = quicer:recv(Stm, 0),
            {ok, 4} = quicer:send(Stm, <<"ping">>, ?QUIC_SEND_FLAG_FIN),
            {ok, <<"pong">>} = quicer:recv(Stm, 0),
            case quicer:recv(Stm, 0) of
                {error, peer_send_shutdown} -> ok;
                {error, closed} -> ok
            end,
            quicer:close_connection(Conn),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 6000 ->
        ct:fail("timeout")
    end.

tc_stream_passive_receive_closed(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> ping_pong_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"pong">>} = quicer:recv(Stm, 0),
            quicer:async_shutdown_stream(Stm, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, 1),
            {error, closed} = quicer:recv(Stm, 0),
            quicer:close_connection(Conn),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 6000 ->
        ct:fail("timeout")
    end.

tc_stream_passive_receive_aborted(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 0),
            {ok, 5} = quicer:send(Stm, <<"Abort">>),
            case quicer:recv(Stm, 0) of
                {error, peer_send_aborted} -> ok;
                {error, closed} -> ok
            end,
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
            case quicer:send(Stm, <<"ping2">>) of
                {error, closed} ->
                    ok;
                {error, stm_send_error, aborted} ->
                    ok
            end,
            SPid ! done,
            ok = ensure_server_exit_normal(Ref)
    after 1000 ->
        ct:fail("timeout")
    end.

tc_stream_send_after_stream_shutdown(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> simple_stream_server(Owner, Config, Port) end),
    receive
        listener_ready -> ok
    end,

    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, []),
    {ok, 4} = quicer:send(Stm, <<"ping">>),
    {ok, {_, _}} = quicer:sockname(Conn),

    ok = quicer:async_shutdown_stream(Stm),
    case quicer:send(Stm, <<"ping2">>) of
        {error, closed} ->
            ok;
        {error, stm_send_error, aborted} ->
            ok;
        {error, stm_send_error, invalid_state} ->
            ok;
        {error, cancelled} ->
            ok
    end,
    ok = quicer:close_connection(Conn),
    SPid ! done,
    ok = ensure_server_exit_normal(Ref).

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
                        {quic, <<"owner_changed">>, Stm, _} ->
                            ok = quicer:async_close_stream(Stm)
                    end
                end
            ),
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

%% @doc Check that old owner down will not shutdown the stream
tc_stream_controlling_process_demon(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            Parent = self(),
            {_Old, MonRef} = spawn_monitor(
                fun() ->
                    {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
                    Res = quicer:controlling_process(Stm, Parent),
                    exit({Res, Stm})
                end
            ),
            receive
                {'DOWN', MonRef, process, NewOwner, {Res, Stm}} ->
                    ct:pal("Set controlling_process res: ~p", [Res])
            end,
            ?assertEqual({error, owner_dead}, quicer:controlling_process(Stm, NewOwner)),
            ok = quicer:setopt(Stm, active, true),
            {ok, _Len} = quicer:send(Stm, <<"owner_changed">>),
            receive
                {quic, <<"owner_changed">>, _Stm, _} ->
                    ok
            end,
            %% Set controlling_process again
            {NewOwner2, MonRef2} = spawn_monitor(fun() ->
                receive
                    stop -> ok
                end
            end),
            ok = quicer:controlling_process(Stm, NewOwner2),
            NewOwner2 ! stop,
            receive
                {'DOWN', MonRef2, process, NewOwner2, normal} ->
                    ok
            end,
            ?assertNotMatch({ok, _}, quicer:send(Stm, <<"owner_changed">>)),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 6000 ->
        ct:fail("timeout")
    end.

tc_dgram_client_send_fail(_) ->
    Opts = default_conn_opts() ++ [{datagram_receive_enabled, 1}],
    {ok, Conn} = quicer:async_connect("localhost", 65535, Opts),
    ?assertEqual(
        %% fire and forget
        {ok, 4},
        quicer:send_dgram(Conn, <<"ping">>)
    ),
    ok.

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
            flush_streams_available(Conn),
            flush_datagram_state_changed(Conn),
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
        {quic, <<"pong">>, Conn, Flag} when is_integer(Flag) ->
            dgram_client_recv_loop(Conn, ReceivedOnStream, true);
        {quic, <<"pong">>, _Stream, _Flag} ->
            dgram_client_recv_loop(Conn, true, ReceivedViaDgram);
        {quic, dgram_state_changed, Conn, #{dgram_send_enabled := true, dgram_max_len := _Size}} ->
            dgram_client_recv_loop(Conn, ReceivedOnStream, ReceivedViaDgram);
        Other ->
            ct:fail("Unexpected Msg ~p", [Other])
    end.

%% @doc test conn and stream share the same owner.
tc_conn_and_stream_shared_owner(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready -> ok
    end,
    TestFun = fun() ->
        {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
        {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
        {ok, 11} = quicer:send(Stm, <<"ping_active">>),
        {ok, _} = quicer:recv(Stm, 11),
        receive
            stop -> ok
        end,
        exit({Conn, Stm})
    end,
    {ChildPid, ChildMRef} = spawn_monitor(TestFun),
    ChildPid ! stop,
    receive
        {'DOWN', ChildMRef, process, ChildPid, {Conn, Stm}} ->
            timer:sleep(100),
            %% Send over old stream
            ?assertNotMatch({ok, _}, quicer:send(Stm, <<"some data">>)),
            %% Try start new stream
            ?assertNotMatch({ok, _}, quicer:start_stream(Conn, [{active, false}]))
    end,
    SPid ! done,
    ensure_server_exit_normal(Ref).

%% tc_getopt_raw(Config) ->
%%   Parm = quic_version,
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
%%       receive {quic, <<"ping">>, Stm, _} -> ok end,
%%       {ok, <<1,0,0,0>>} = quicer:getopt(Stm, Parm),
%%       ok = quicer:close_connection(Conn),
%%       SPid ! done,
%%       ensure_server_exit_normal(Ref)
%%   after 3000 ->
%%       ct:fail("listener_timeout")
%%   end.

tc_getopt(Config) ->
    Parm = statistics,
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stats} = quicer:getopt(Conn, Parm, false),
            ?assertEqual({ok, false}, quicer:getopt(Conn, datagram_receive_enabled)),
            ?assertEqual({ok, false}, quicer:getopt(Conn, datagram_send_enabled)),
            ?assertEqual({ok, false}, quicer:getopt(Conn, disable_1rtt_encryption)),
            ?assertEqual({ok, 1}, quicer:getopt(Conn, quic_version)),
            %% 0: fifo
            %% 1: round-robin
            ?assertEqual({ok, 0}, quicer:getopt(Conn, stream_scheduling_scheme)),
            ?assertMatch({ok, {_, _}}, quicer:getopt(Conn, local_address)),
            {ok, MaxIds} = quicer:getopt(Conn, max_stream_ids),
            ct:pal(
                "MaxStreamIds: client bidi: ~p, server bidi: ~p "
                "client unidi ~p, server unidi ~p",
                MaxIds
            ),
            ?assertEqual(
                {error, invalid_parameter}, quicer:getopt(Conn, local_interface)
            ),
            ?assertEqual(
                {error, invalid_parameter}, quicer:getopt(Conn, peer_certificate_valid)
            ),
            {error, not_supported} = quicer:getopt(Conn, resumption_ticket),
            0 = proplists:get_value("Recv.DroppedPackets", Stats),
            [
                true = proplists:is_defined(SKey, Stats)
             || SKey <- ["Send.TotalPackets", "Recv.TotalPackets"]
            ],
            {ok, Settings} = quicer:getopt(Conn, settings, false),
            5000 = proplists:get_value(idle_timeout_ms, Settings),
            true = proplists:get_value(send_buffering_enabled, Settings),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} -> ok
            end,
            ok = quicer:close_connection(Conn),
            %% @NOTE: msquic returns not_found when it is unset.
            {error, Reason} = quicer:getopt(Conn, close_reason_phrase),
            ?assert(Reason == not_found orelse Reason == closed),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_getopt_statistics_v2(Config) ->
    Parm = statistics_v2,
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stats} = quicer:getopt(Conn, Parm, false),
    {ok, Stm} = quicer:start_stream(Conn, []),
    {ok, 4} = quicer:send(Stm, <<"ping">>),
    ?assertMatch(
        [
            {correlation_id, _},
            {version_negotiation, _},
            {stateless_retry, _},
            {resumption_attempted, _},
            {resumption_succeeded, _},
            {grease_bit_negotiated, _},
            {ecn_capable, _},
            {encryption_offloaded, _},
            {reserved, _},
            {rtt, _},
            {min_rtt, _},
            {max_rtt, _},
            {timing_start, _},
            {timing_initial_flight_end, _},
            {timing_handshake_flight_end, _},
            {handshake_client_flight_1_bytes, _},
            {handshake_server_flight_1_bytes, _},
            {handshake_client_flight_2_bytes, _},
            {send_path_mtu, _},
            {send_total_packets, _},
            {send_retransmittable_packets, _},
            {send_suspected_lost_packets, _},
            {send_spurious_lost_packets, _},
            {send_total_bytes, _},
            {send_total_stream_bytes, _},
            {send_congestion_count, _},
            {send_persistent_congestion_count, _},
            {recv_total_packets, _},
            {recv_reordered_packets, _},
            {recv_dropped_packets, _},
            {recv_duplicate_packets, _},
            {recv_total_bytes, _},
            {recv_total_stream_bytes, _},
            {recv_decryption_failures, _},
            {recv_valid_ack_frames, _},
            {key_update_count, _}
        ],
        Stats
    ),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_getopt_settings(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Settings} = quicer:getopt(Conn, settings, false),
            ?assertEqual(
                {ok, Settings},
                quicer:getopt(Conn, settings, quic_configuration)
            ),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} -> ok
            end,
            ?assertEqual(
                {ok, Settings}, quicer:getopt(Stm, settings, quic_configuration)
            ),
            ?assertEqual(
                ok, quicer:setopt(quic_global, settings, #{idle_timeout_ms => 12000})
            ),
            {ok, NewGSettings} = quicer:getopt(quic_global, settings),
            ?assertEqual(12000, proplists:get_value(idle_timeout_ms, NewGSettings)),
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
            {error, param_error} = quicer:getopt(Conn, Parm, false),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} -> ok
            end,
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

tc_get_stream_id_after_close(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, Stm2} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, 4} = quicer:send(Stm2, <<"ping">>),
            ok = quicer:close_stream(Stm),
            {ok, 0} = quicer:get_stream_id(Stm),
            {ok, 4} = quicer:get_stream_id(Stm2),
            ok = quicer:close_connection(Conn),
            SPid ! done,
            {ok, 0} = quicer:get_stream_id(Stm),
            {ok, 4} = quicer:get_stream_id(Stm2),
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_get_stream_0rtt_length(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} ->
                    ok
            end,
            %% before stream shutdown,
            {error, invalid_state} = quicer:getopt(Stm, '0rtt_length'),
            quicer:async_shutdown_stream(Stm),
            case quicer:getopt(Stm, '0rtt_length') of
                {ok, Val} -> ?assert(is_integer(Val));
                {error, invalid_state} -> ok;
                {error, closed} -> ok
            end,
            quicer:close_connection(Conn),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_get_stream_ideal_sndbuff_size(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} ->
                    ok
            end,
            %% before stream shutdown,
            {ok, Val} = quicer:getopt(Stm, ideal_send_buffer_size),
            ?assert(is_integer(Val)),
            ok = quicer:shutdown_stream(Stm),
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
            receive
                {quic, Bin, _, _} when is_binary(Bin) -> ok
            end,
            ok = quicer:close_stream(Stm),
            ok = quicer:close_connection(Conn),
            case quicer:getstat(Conn, [send_cnt, recv_oct, send_pend]) of
                {error, invalid_parameter} ->
                    ok;
                {error, invalid_state} ->
                    ok;
                {error, closed} ->
                    ok;
                {ok, [_ | _]} ->
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
    {SPid, _Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
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
            "127.0.0.1" = inet:ntoa(Addr),
            ok = quicer:close_connection(Conn),
            SPid ! done
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
            {ok, <<"sample">>} = quicer:getopt(Conn, negotiated_alpn, quic_tls),
            {ok, <<"sample">>} = quicer:negotiated_protocol(Conn),
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
                Owner ! Res
            end),
            receive
                ok ->
                    ct:fail("illegal connection");
                {error, transport_down, #{error := 376, status := alpn_neg_failure}} ->
                    ok
            end,
            SPid ! done
    after 1000 ->
        ct:fail("timeout")
    end.

tc_idle_timeout(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            Opts = lists:keyreplace(
                idle_timeout_ms, 1, default_conn_opts(), {idle_timeout_ms, 100}
            ),
            {ok, Conn} = quicer:connect("localhost", Port, Opts, 5000),
            {ok, Stm0} = quicer:start_stream(Conn, []),
            {ok, 5} = quicer:send(Stm0, <<"ping0">>),
            receive
                {echo_server_transport_shutdown, connection_idle} ->
                    ok
            end,
            case quicer:start_stream(Conn, []) of
                {error, ctx_init_failed} ->
                    %% connection is closing
                    ok;
                {error, stm_open_error, invalid_parameter} ->
                    %% connection is closed
                    ok;
                {error, stm_open_error, invalid_state} ->
                    %% Invalid state
                    ok;
                {error, closed} ->
                    %% Conn is closed
                    ok;
                {ok, _Stream} ->
                    ok
            end,
            SPid ! done,
            ensure_server_exit_normal(Ref)
    end.

tc_setopt_conn_settings(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() ->
        echo_server(
            Owner,
            Config ++ [{peer_bidi_stream_count, 1}],
            Port
        )
    end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Settings} = quicer:getopt(Conn, settings),
            ok = quicer:setopt(Conn, settings, Settings),
            {ok, Stm0} = quicer:start_stream(Conn, [{active, false}]),
            %% Stream 0
            {ok, 5} = quicer:send(Stm0, <<"ping0">>),
            {ok, <<"ping0">>} = quicer:recv(Stm0, 0),
            %% Stream 1 but get blocked due to stream count
            {ok, Stm1} = quicer:start_stream(Conn, [{active, true}]),
            {ok, 5} = quicer:send(Stm1, <<"ping1">>),
            receive
                {quic, Data, Stm1, _} = Msg when is_binary(Data) ->
                    ct:fail("unexpected_recv ~p ", [Msg])
            after 1000 ->
                ok
            end,

            %% unblock Stream 1
            SPid ! {set_stm_cnt, 3},

            receive
                {quic, <<"ping1">>, Stm1, _} ->
                    ok
            after 1000 ->
                ct:fail("sending is still blocked", [])
            end,
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_setopt(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() ->
        echo_server(
            Owner,
            Config ++ [{peer_bidi_stream_count, 1}],
            Port
        )
    end),
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
                {quic, Data, Stm1, _} = Msg when is_binary(Data) ->
                    ct:fail("unexpected_recv ~p ", [Msg])
            after 1000 ->
                ok
            end,

            {error, not_supported} = quicer:setopt(Conn, quic_version, 1),
            %% must be set before start
            {error, invalid_state} = quicer:setopt(Conn, remote_address, "8.8.8.8:443"),

            {error, not_supported} = quicer:setopt(Conn, ideal_processor, 1),
            {error, not_supported} = quicer:setopt(Conn, max_stream_ids, [1, 2, 3, 4]),
            ok = quicer:setopt(Conn, close_reason_phrase, "You are not welcomed!"),
            {ok, <<"You are not welcomed!">>} = quicer:getopt(Conn, close_reason_phrase),
            ok = quicer:setopt(Conn, stream_scheduling_scheme, 1),
            {ok, 1} = quicer:getopt(Conn, stream_scheduling_scheme),
            %% get-only
            {error, invalid_parameter} = quicer:setopt(
                Conn, datagram_send_enabled, false
            ),
            %% Must set before start
            {error, invalid_state} = quicer:setopt(
                Conn, datagram_receive_enabled, false
            ),
            {error, invalid_state} = quicer:setopt(Conn, datagram_receive_enabled, true),
            {error, invalid_state} = quicer:setopt(
                Conn, datagram_receive_enabled, false
            ),
            ok = quicer:setopt(Conn, peer_certificate_valid, true),
            ok = quicer:setopt(Conn, peer_certificate_valid, false),
            {error, invalid_state} = quicer:setopt(Conn, local_interface, 1),
            %% test invalid
            {error, invalid_parameter} = quicer:setopt(Conn, resumption_ticket, <<>>),
            %% unblock Stream 1
            SPid ! {set_stm_cnt, 3},

            receive
                {quic, <<"ping1">>, Stm1, _} ->
                    ok
            after 1000 ->
                ct:fail("sending is still blocked", [])
            end,
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_setopt_remote_addr(_Config) ->
    {ok, Conn} = quicer:open_connection(),
    ok = quicer:setopt(Conn, remote_address, "8.8.8.8:443"),
    ?assertEqual({ok, {{8, 8, 8, 8}, 443}}, quicer:getopt(Conn, remote_address)),
    quicer:shutdown_connection(Conn).

tc_setopt_bad_opt(_Config) ->
    Port = select_port(),
    {error, badarg} = quicer:connect(
        "localhost",
        Port,
        %% BAD opt
        [
            {nst, foobar}
            | default_conn_opts()
        ],
        5000
    ).

tc_setopt_bad_nst(_Config) ->
    Port = select_port(),
    {error, invalid_parameter} = quicer:connect(
        "localhost",
        Port,
        [
            {nst, <<"">>}
            | default_conn_opts()
        ],
        5000
    ).

tc_setopt_config_settings(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Settings} = quicer:getopt(Conn, settings, false),
            ?assertEqual(
                ok,
                quicer:setopt(
                    Conn,
                    settings,
                    #{idle_timeout_ms => 60000},
                    quic_configuration
                )
            ),
            {ok, Settings} = quicer:getopt(Conn, settings, false),
            {ok, Stm} = quicer:start_stream(Conn, []),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            receive
                {quic, <<"ping">>, Stm, _} -> ok
            end,
            Settings1 = lists:keyreplace(idle_timeout_ms, 1, Settings, {idle_timeout_ms, 60000}),
            %% This is meaning less test, just for coverage
            %% config resources are not really exposed
            ?assertEqual(
                {ok, Settings1},
                quicer:getopt(Conn, settings, quic_configuration)
            ),
            ?assertEqual(
                {ok, Settings1},
                quicer:getopt(Stm, settings, quic_configuration)
            ),
            ok = quicer:close_connection(Conn),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_setopt_conn_remote_addr(_Config) ->
    {ok, Conn} = quicer:open_connection(),
    ok = quicer:setopt(Conn, remote_address, "8.8.8.8:443"),
    ok = quicer:setopt(Conn, datagram_receive_enabled, false),
    Res = quicer:connect(
        "google.com",
        443,
        [
            {verify, verify_peer},
            {handle, Conn},
            {peer_unidi_stream_count, 3},
            {idle_timeout_ms, 5000},
            {handshake_idle_timeout_ms, 5000},
            {alpn, ["h3"]}
        ],
        1000
    ),
    case Res of
        %% Linux
        {ok, _} ->
            ok;
        {error, transport_down, #{error := 298, status := bad_certificate}} ->
            %% Mac @TODO don't know why it failed
            ok
    end.

tc_setopt_global_retry_mem_percent(_Config) ->
    ?assertEqual(ok, quicer:setopt(quic_global, retry_memory_percent, 30, false)).

tc_getopt_global_retry_mem_percent(_Config) ->
    {ok, Val} = quicer:getopt(quic_global, retry_memory_percent),
    ?assert(is_integer(Val)).

tc_getopt_global_lb_mode(_Config) ->
    ?assertEqual(
        {ok, 0},
        quicer:getopt(quic_global, load_balacing_mode)
    ).

tc_getopt_global_lib_git_hash(_Config) ->
    {ok, HashBin} = quicer:getopt(quic_global, library_git_hash),
    ct:pal("msquic git hash ~s", [HashBin]),
    ?assert(is_binary(HashBin)).

tc_setopt_global_lb_mode(_Config) ->
    ?assertEqual(
        {error, badarg},
        quicer:setopt(quic_global, load_balacing_mode, 4)
    ),
    %% v1 api
    ?assertEqual(
        {error, invalid_parameter},
        quicer:setopt(quic_global, load_balacing_mode, 1)
    ).

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
        {quic, <<"ping1">>, Stm0, _} ->
            ok
    after 1000 ->
        ct:fail("recv ping1 timeout")
    end,
    {ok, OldAddr} = quicer:sockname(Conn),
    %% change local addr with a new random port (0)
    ?assertEqual(ok, quicer:setopt(Conn, local_address, "127.0.0.1:0")),
    {ok, NewAddr} = quicer:sockname(Conn),
    ?assertNotEqual(OldAddr, NewAddr),
    ?assertNotEqual({ok, {{127, 0, 0, 1}, 50600}}, NewAddr),
    ?assertNotEqual({ok, {{127, 0, 0, 1}, 50600}}, OldAddr),
    %% change local addr with a new port 5060
    ?assertEqual(ok, quicer:setopt(Conn, local_address, "127.0.0.1:50600")),
    receive
        {quic, peer_address_changed, Conn, NewPeerAddr} ->
            ct:pal("new peer addr: ~p", [NewPeerAddr])
    after 1000 ->
        ct:fail("timeout wait for peer_address_changed")
    end,
    %% sleep is needed to finish migration at protocol level
    retry_with(
        fun() ->
            timer:sleep(100),
            case quicer:sockname(Conn) of
                {ok, {{127, 0, 0, 1}, 50600}} -> true;
                {ok, Other} -> {false, Other}
            end
        end,
        20,
        "addr migration failed"
    ),
    {ok, 5} = quicer:send(Stm0, <<"ping2">>),
    receive
        {quic, <<"ping2">>, Stm0, _} ->
            ok
    after 1000 ->
        ct:fail("recv ping2 timeout")
    end,
    %% check with server if peer addr is correct.
    SPid ! {peer_addr, self()},
    receive
        {peer_addr, Peer} -> ok
    end,
    ?assertEqual({ok, {{127, 0, 0, 1}, 50600}}, Peer),
    SPid ! done,
    ensure_server_exit_normal(Ref).

%% Disabled, not always working with MsQuic
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
        {quic, <<"ping1">>, Stm0, _} ->
            ok
    after 1000 ->
        ct:fail("recv ping1 timeout")
    end,
    {ok, OldAddr} = quicer:sockname(Conn),
    %% change local addr with a new random port (0)
    ?assertEqual(ok, quicer:setopt(Conn, local_address, "127.0.0.1:0")),
    %% sleep is needed to finish migration at protocol level
    timer:sleep(50),
    {ok, NewAddr} = quicer:sockname(Conn),
    ?assertNotEqual(OldAddr, NewAddr),
    ?assertNotEqual({ok, {{127, 0, 0, 1}, 50600}}, NewAddr),
    ?assertNotEqual({ok, {{127, 0, 0, 1}, 50600}}, OldAddr),

    %% Occupy 50600
    {ok, ESocket} = gen_udp:open(50600, [{ip, element(1, NewAddr)}]),
    %% change local addr with a new port 5060
    ?assertEqual(
        {error, address_in_use}, quicer:setopt(Conn, local_address, "127.0.0.1:50600")
    ),

    gen_udp:close(ESocket),

    %% sleep is needed to finish migration at protocol level
    ct:pal("send after migration failed"),
    {ok, 5} = quicer:send(Stm0, <<"ping2">>),
    receive
        {quic, <<"ping2">>, Stm0, _} ->
            ok
    after 1000 ->
        ct:fail("recv ping2 timeout")
    end,
    %% check with server if peer addr is correct.
    SPid ! {peer_addr, self()},
    receive
        {peer_addr, Peer} -> ok
    end,
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
            ok = quicer:setopt(Stm, priority, 10),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 0),
            % try to set priority out of range
            {error, param_error} = quicer:setopt(Stm, priority, 65536),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_setopt_stream_unsupp_opts(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(fun() -> echo_server(Owner, Config, Port) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
            ?assertEqual({error, not_supported}, quicer:setopt(Stm, stream_id, 8)),
            ?assertEqual(
                {error, not_supported}, quicer:setopt(Stm, '0rtt_length', 4096)
            ),
            ?assertEqual(
                {error, not_supported},
                quicer:setopt(Stm, ideal_send_buffer_size, 4096)
            ),
            {ok, 4} = quicer:send(Stm, <<"ping">>),
            {ok, <<"ping">>} = quicer:recv(Stm, 0),
            % try to set priority out of range
            {error, param_error} = quicer:setopt(Stm, priority, 65536),
            quicer:shutdown_stream(Stm),
            SPid ! done,
            ensure_server_exit_normal(Ref)
    after 5000 ->
        ct:fail("listener_timeout")
    end.

tc_app_echo_server(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, false}]),
    {ok, 4} = quicer:async_send(Stm, <<"ping">>),
    {ok, 4} = quicer:async_send(Stm, <<"ping">>),
    {ok, 4} = quicer:async_send(Stm, <<"ping">>),
    {ok, <<"pingpingping">>} = quicer:recv(Stm, 12),
    ok = quicer:close_stream(Stm),
    ok = quicer:close_connection(Conn),
    ok = quicer:terminate_listener(mqtt),
    %% test that listener could be reopened
    {ok, _} = quicer:spawn_listener(mqtt, Port, Options),
    ok = quicer:terminate_listener(mqtt),
    ok.

tc_strm_opt_active_1(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, 1}]),
    {ok, 5} = quicer:send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} -> ok
    end,

    receive
        {quic, passive, Stm, undefined} -> ok
    end,

    {ok, 5} = quicer:async_send(Stm, <<"ping4">>),
    {ok, <<"ping4">>} = quicer:recv(Stm, 5),
    quicer:close_stream(Stm),
    quicer:close_connection(Conn).

tc_strm_opt_active_n(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, 3}]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} -> ok
    end,
    {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
    receive
        {quic, <<"ping2">>, Stm, _} -> ok
    end,
    {ok, 5} = quicer:async_send(Stm, <<"ping3">>),
    receive
        {quic, <<"ping3">>, Stm, _} ->
            receive
                {quic, passive, Stm, undefined} -> ok
            end
    end,

    {ok, 5} = quicer:async_send(Stm, <<"ping4">>),
    {ok, <<"ping4">>} = quicer:recv(Stm, 5),
    quicer:close_stream(Stm),
    quicer:close_connection(Conn).

tc_strm_opt_active_once(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, once}]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} ->
            receive
                {quic, passive, Stm, undefined} = Event ->
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
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {error, badarg} = quicer:start_stream(Conn, [{active, twice}]),
    ok.

tc_get_conn_rid(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Rid} = quicer:get_conn_rid(Conn),
    ?assert(is_integer(Rid) andalso Rid =/= 0).

tc_get_stream_rid(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [{active, 3}]),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} -> ok
    end,
    ?assert(is_integer(Rid)),
    ?assert(Rid =/= 0).

tc_stream_open_flag_unidirectional(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, 3},
        {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ]),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} ->
            ct:fail("unidirectional stream should not receive any");
        {quic, stream_closed, Stm, #{is_conn_shutdown := _, is_app_closing := false}} ->
            ct:pal("stream is closed due to connecion idle")
    end,
    ?assert(is_integer(Rid)),
    ?assert(Rid =/= 0),
    quicer:close_connection(Conn).

tc_stream_start_flag_fail_blocked(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    %% Given a server with 0 allowed remote bidi stream.
    ListenerOpts = [
        {conn_acceptors, 32},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
        | lists:keyreplace(
            peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count, 0}
        )
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    %% When a client tries to start a bidi stream with flag "QUIC_STREAM_START_FLAG_FAIL_BLOCKED"
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, 3},
        {start_flag, ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    case quicer:async_send(Stm, <<"ping1">>) of
        {ok, 5} ->
            ok;
        {error, closed} ->
            ok;
        {error, stm_send_error, invalid_state} ->
            %% Deps on the timing
            ok
    end,
    receive
        {quic, <<"ping1">>, Stm, _} ->
            ct:fail("Should not get ping1 due to rate limiter");
        {quic, start_completed, Stm, #{status := stream_limit_reached, stream_id := StreamID}} ->
            %% Then stream start should fail with reason stream_limit_reached
            quicer:close_stream(
                Stm,
                ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT bor ?QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
                0,
                1000
            ),
            ct:pal("Stream ~p limit reached", [StreamID]);
        {quic, start_completed, Stm, #{
            status := AtomStatus, stream_id := StreamID, is_peer_accepted := _PeerAccepted
        }} ->
            ct:fail("Stream ~pstart complete with unexpect reason: ~p", [StreamID, AtomStatus])
    end,

    %% Then stream is closed automatically
    receive
        {quic, stream_closed, Stm, _} ->
            ct:failed(
                "Stream ~p is closed but shouldn't since QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL is unset",
                [Stm]
            );
        {quic, transport_shutdown, Conn, #{status := connection_idle}} ->
            ct:pal("Connection ~p transport shutdown due to idle, stream isn't closed ahead", [Conn])
    end,
    receive
        {quic, closed, Conn, _Flags} ->
            ct:pal("Connecion is closed ~p", [Conn])
    end,
    quicer:terminate_listener(mqtt),
    ?assert(is_integer(Rid)).

tc_stream_start_flag_immediate(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {conn_acceptors, 32},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
        | lists:keyreplace(
            peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count, 0}
        )
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, 3},
        {start_flag, ?QUIC_STREAM_START_FLAG_IMMEDIATE},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    %% We don't need to send anything, we should get start_completed even it is flow controlled
    receive
        {quic, start_completed, Stm, #{status := stream_limit_reached, stream_id := StreamID}} ->
            ct:fail("Stream ~p limit reached", [StreamID]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamID}} ->
            ct:pal("Stream ~pstart complete with reason: ~p", [StreamID, Reason])
    end,
    ?assert(is_integer(Rid)),
    ?assert(Rid =/= 0).

tc_stream_start_flag_shutdown_on_fail(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    %% Given a server with 0 allowed remote bidi stream.
    ListenerOpts = [
        {conn_acceptors, 32},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
        | lists:keyreplace(
            peer_bidi_stream_count, 1, default_listen_opts(Config), {peer_bidi_stream_count, 0}
        )
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    %% When a client tries to start a bidi stream with flag "QUIC_STREAM_START_FLAG_FAIL_BLOCKED" unset
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, 3},
        {start_flag,
            ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL bor
                ?QUIC_STREAM_START_FLAG_FAIL_BLOCKED},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    case quicer:async_send(Stm, <<"ping1">>) of
        {ok, 5} -> ok;
        {error, closed} -> ok;
        %% already closed
        {error, stm_send_error, invalid_state} -> ok
    end,
    receive
        %% THEN we should recv event `start_completed' with status: `stream_limit_reached'
        {quic, start_completed, Stm, #{status := stream_limit_reached, stream_id := StreamID}} ->
            ct:pal("Stream ~p limit reached", [StreamID]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamID}} ->
            ct:fail("Stream ~pstart complete with other reason: ~p", [StreamID, Reason])
    end,
    flush_datagram_state_changed(Conn),
    %% Expect a send_shutdown_complete
    receive
        {quic, send_shutdown_complete, Stm, false} -> ok
    end,

    %% We should get a stream closed event since it is rate limited
    receive
        % not a conn close
        {quic, stream_closed, Stm, #{is_conn_shutdown := false}} ->
            ct:pal("Stream ~p is closed", [Stm]);
        {quic, transport_shutdown, Conn, connection_idle} ->
            ct:fail("Unexpected connection ~p transport shutdown", [Conn]);
        Other ->
            ct:fail("Unexpected event ~p after stream start complete", [Other])
    end,
    {error, closed} = snabbkaffe:retry(
        100,
        10,
        fun() ->
            {error, closed} = quicer:getopt(Stm, settings, quic_configuration)
        end
    ),
    ?assert(is_integer(Rid)).

tc_stream_start_flag_indicate_peer_accept_1(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    %% We don't enable flow control
    ListenerOpts = [
        {conn_acceptors, 32},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, 3},
        {start_flag, ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    quicer:async_send(Stm, <<"ping1">>),
    {ok, Rid} = quicer:get_stream_rid(Stm),
    %% We don't need to send anything
    receive
        {quic, start_completed, Stm, #{status := stream_limit_reached, stream_id := StreamID}} ->
            ct:fail("Stream ~p limit reached", [StreamID]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamID}} ->
            ct:pal("Stream ~p start complete with reason: ~p", [StreamID, Reason])
    end,
    ?assert(is_integer(Rid)),
    ?assert(Rid =/= 0).

tc_stream_start_flag_indicate_peer_accept_2(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "127.0.0.1",
        Port,
        default_conn_opts() ++ [{peer_unidi_stream_count, 1}],
        5000
    ),
    {ok, Stm0} = quicer:start_stream(Conn, [
        {active, true},
        {start_flag, ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT},
        {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ]),
    {ok, 5} = quicer:send(Stm0, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm0, _} ->
            ct:fail("We should not recv ping1 due to flow control: bidir stream 0")
    after 1000 ->
        ct:pal("recv ping1 timeout"),
        SPid ! {flow_ctl, 10, 1}
    end,
    quicer:async_accept_stream(Conn, []),
    %% check with server if peer addr is correct.
    receive
        {quic, peer_accepted, Stm0, undefined} ->
            ct:pal("peer_accepted received")
    after 1000 ->
        ct:fail("peer_accepted timeout")
    end,

    %% Now we expect server initiat an Server -> Stream unidirectional stream
    receive
        {quic, new_stream, Stm1, #{flags := Flags}} ->
            ?assert(quicer:is_unidirectional(Flags)),
            %% We also expect server send reply over new stream
            receive
                {quic, <<"ping1">>, Stm0, _} ->
                    ct:fail("Data recvd from client -> server unidirectional stream");
                {quic, <<"ping1">>, Stm1, _} ->
                    ct:pal("Data recvd from server -> client unidirectional stream")
            end
    after 2000 ->
        ct:fail("No new_stream for stream initiated from Server")
    end,

    SPid ! done,
    ensure_server_exit_normal(Ref).

tc_stream_send_with_fin(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "127.0.0.1",
        Port,
        default_conn_opts() ++ [{peer_unidi_stream_count, 1}],
        5000
    ),
    {ok, Stm0} = quicer:start_stream(Conn, [{active, true}]),
    {ok, 5} = quicer:send(Stm0, <<"ping1">>, ?QUIC_SEND_FLAG_FIN),
    receive
        {quic, <<"ping1">>, Stm0, #{flags := Flag}} ->
            ct:pal("ping1 recvd with flag ~p ", [Flag]),
            ?assert(Flag band ?QUIC_RECEIVE_FLAG_FIN > 0)
    after 1000 ->
        ct:fail("recv ping1 timeout")
    end,

    %% Check that stream close isn't caused by conn close.
    receive
        {quic, stream_closed, Stm0, #{is_conn_shutdown := IsConn}} ->
            ?assert(not IsConn)
    after 1000 ->
        ct:fail("stream didn't close")
    end,

    SPid ! done,
    ensure_server_exit_normal(Ref).

tc_stream_send_with_fin_passive(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "127.0.0.1",
        Port,
        default_conn_opts() ++ [{peer_unidi_stream_count, 1}],
        5000
    ),
    {ok, Stm0} = quicer:start_stream(Conn, [{active, false}]),
    {ok, 5} = quicer:send(Stm0, <<"ping1">>, ?QUIC_SEND_FLAG_FIN),
    receive
        {quic, send_shutdown_complete, Stm0, true} -> ok
    end,
    %% Since socket is passive we shall not get the stream data and stream close
    receive
        {quic, <<"ping1">>, Stm0, #{flags := Flag0}} ->
            ct:fail("ping1 recvd with flag ~p ", [Flag0]);
        {quic, _, Stm0, _} = Msg ->
            ct:fail("recv unexpected msg: ~p", [Msg])
    after 1000 ->
        ct:pal("ping1 not received")
    end,

    quicer:setopt(Stm0, active, true),
    receive
        {quic, <<"ping1">>, Stm0, #{flags := Flag}} ->
            ct:pal("ping1 recvd with flag ~p ", [Flag]),
            ?assert(Flag band ?QUIC_RECEIVE_FLAG_FIN > 0);
        {quic, _, Stm0, _} = Msg2 ->
            ct:fail("recv unexpected msg: ~p", [Msg2])
    after 1000 ->
        ct:pal("ping1 not received")
    end,

    %% Check that stream close isn't caused by conn close.
    receive
        {quic, stream_closed, Stm0, #{is_conn_shutdown := IsConn}} ->
            ?assert(not IsConn)
    after 1000 ->
        ct:fail("stream didn't close")
    end,

    SPid ! done,
    ensure_server_exit_normal(Ref).

tc_stream_send_shutdown_complete(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "127.0.0.1",
        Port,
        default_conn_opts() ++ [{peer_unidi_stream_count, 1}],
        5000
    ),
    {ok, Stm0} = quicer:start_stream(Conn, [{active, true}]),
    {ok, 5} = quicer:send(Stm0, <<"ping1">>, ?QUIC_SEND_FLAG_FIN),
    receive
        {quic, <<"ping1">>, Stm0, #{flags := Flag}} ->
            ct:pal("ping1 recvd with flag ~p ", [Flag]),
            ?assert(Flag band ?QUIC_RECEIVE_FLAG_FIN > 0)
    after 1000 ->
        ct:fail("recv ping1 timeout")
    end,

    quicer:async_shutdown_stream(Stm0, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0),

    %% Check we shutdown the stream gracefully.
    receive
        {quic, send_shutdown_complete, Stm0, IsGraceful} ->
            ?assert(IsGraceful)
    end,

    %% Check that stream close isn't caused by conn close.
    receive
        {quic, stream_closed, Stm0, #{is_conn_shutdown := IsConn}} ->
            ?assert(not IsConn)
    after 1000 ->
        ct:fail("stream didn't close")
    end,

    SPid ! done,
    ensure_server_exit_normal(Ref).

tc_conn_opt_sslkeylogfile(Config) ->
    Port = select_port(),
    TargetFName = "SSLKEYLOGFILE",
    file:delete(TargetFName),
    application:ensure_all_started(quicer),
    ListenerOpts = [{conn_acceptors, 32} | default_listen_opts(Config)],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        [
            {sslkeylogfile, TargetFName}
            | default_conn_opts()
        ],
        5000
    ),
    quicer:close_connection(Conn),
    timer:sleep(100),
    {ok, #file_info{type = regular}} = file:read_file_info(TargetFName).

tc_insecure_traffic(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        [
            {disable_1rtt_encryption, true}
            | default_conn_opts()
        ],
        5000
    ),
    {ok, Stm} = quicer:start_stream(Conn, [{active, true}]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm, _} ->
            {ok, true} = quicer:getopt(Conn, disable_1rtt_encryption, false),
            ok
    end,
    quicer:close_connection(Conn),
    ok.

tc_perf_counters(_Config) ->
    {ok, _} = quicer:perf_counters().

tc_event_start_compl_client(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts(),
        5000
    ),
    %% Stream 1 enabled
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, true},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE},
        {start_flag, ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL}
    ]),
    %% Stream 2 disabled
    {ok, Stm2} = quicer:start_stream(Conn, [
        {active, true},
        {quic_event_mask, 0},
        {start_flag, ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL}
    ]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
    receive
        {quic, start_completed, Stm, #{
            status := success, stream_id := StreamId, is_peer_accepted := true
        }} ->
            ct:pal("Stream ~p started", [StreamId]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamId}} ->
            ct:fail("Stream ~p failed to start: ~p", [StreamId, Reason])
    end,
    receive
        {quic, start_completed, Stm2, #{status := Status}} ->
            ct:fail("Stream ~p should NOT recv event : ~p", [Stm, Status])
    after 500 ->
        ok
    end,
    quicer:close_connection(Conn),
    ok.

tc_event_start_compl_server(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback},
        %% server reply us on a server to client stream
        {is_echo_new_stream, true},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts(),
        5000
    ),
    %% Stream 1 enabled
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, true},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    %% Stream 2 disabled
    {ok, Stm2} = quicer:start_stream(Conn, [{active, true}, {quic_event_mask, 0}]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),
    {ok, 5} = quicer:async_send(Stm, <<"ping2">>),
    {ok, Conn} = quicer:async_accept_stream(Conn, [{active, true}]),
    receive
        {quic, start_completed, Stm, #{
            status := success, stream_id := StreamId, is_peer_accepted := true
        }} ->
            ct:pal("Stream ~p started", [StreamId]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamId}} ->
            ct:fail("Stream ~p failed to start: ~p", [StreamId, Reason])
    end,
    receive
        {quic, start_completed, Stm2, #{status := Status}} ->
            ct:fail("Stream ~p should NOT recv event : ~p", [Stm, Status])
    after 0 ->
        ok
    end,
    receive
        {quic, Data, NewStream, _} = Evt when
            is_binary(Data) andalso
                NewStream =/= Stm andalso
                NewStream =/= Stm2
        ->
            ct:pal("recv ~p", [Evt])
    end,
    quicer:close_connection(Conn),
    ok.

tc_direct_send_over_conn(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:async_connect(
        "localhost",
        Port,
        [
            {disable_1rtt_encryption, true}
            | default_conn_opts()
        ]
    ),
    %% Stream 1 enabled
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, true}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),

    {ok, Stm2} = quicer:async_csend(
        Conn,
        <<"ping2">>,
        [{active, true}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}],
        ?QUIC_SEND_FLAG_NONE
    ),
    %% Stream 3 is one shot, shutdown after send
    {ok, Stm3} = quicer:async_csend(
        Conn,
        <<"ping3">>,
        [{active, true}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}],
        ?QUIC_SEND_FLAG_START bor ?QUIC_SEND_FLAG_FIN
    ),
    receive
        {quic, start_completed, Stm, #{
            status := success, stream_id := StreamId, is_peer_accepted := _
        }} ->
            ct:pal("Stream1 ~p started", [StreamId]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamId}} ->
            ct:fail("Stream ~p failed to start: ~p", [StreamId, Reason])
    end,
    receive
        {quic, start_completed, Stm2, #{status := success, stream_id := StreamId2}} ->
            ct:pal("Stream ~p started", [StreamId2])
    end,
    receive
        {quic, start_completed, Stm3, #{status := success, stream_id := StreamId3}} ->
            ct:pal("Stream ~p started", [StreamId3])
    end,
    receive
        {quic, <<"ping1">>, Stm, _} ->
            ct:pal("Get ping from stream1")
    end,
    receive
        {quic, <<"ping2">>, Stm2, _} ->
            ct:pal("Get ping from stream2")
    end,

    receive
        {quic, <<"ping3">>, Stm3, _} ->
            ct:pal("Get ping from stream3")
    end,
    receive
        {quic, send_shutdown_complete, Stm3, IsGraceful} ->
            ct:pal("Stm3 shutdown gracefully: ~p", [IsGraceful])
    end,
    ?assert(IsGraceful),

    quicer:close_connection(Conn),
    ok.

tc_direct_send_over_conn_block(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:async_connect(
        "localhost",
        Port,
        [
            {disable_1rtt_encryption, true}
            | default_conn_opts()
        ]
    ),
    %% Stream 1 enabled
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, true}, {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE}
    ]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),

    {ok, Stm2} = quicer:async_csend(
        Conn,
        <<"ping2">>,
        [
            {active, true},
            {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE},
            {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
        ],
        ?QUIC_SEND_FLAG_NONE
    ),
    receive
        {quic, start_completed, Stm, #{
            status := success, stream_id := StreamId, is_peer_accepted := _
        }} ->
            ct:pal("Stream1 ~p started", [StreamId]);
        {quic, start_completed, Stm, #{status := Reason, stream_id := StreamId}} ->
            ct:fail("Stream ~p failed to start: ~p", [StreamId, Reason])
    end,
    receive
        {quic, start_completed, Stm2, #{status := success, stream_id := StreamId2}} ->
            ct:pal("Stream ~p started", [StreamId2])
    end,

    receive
        {quic, streams_available, Conn, #{bidi_streams := _, unidi_streams := NoUni}} ->
            ct:pal("Server allows ~p unidi_streams!", [NoUni]),
            %% Assert server allows 0 unidi_streams
            ?assertEqual(0, NoUni)
    end,

    receive
        {quic, <<"ping1">>, Stm, _} ->
            ct:pal("Get ping from stream1")
    end,

    receive
        {quic, <<"ping2">>, Stm2, _} ->
            ct:fail("Get ping from stream2")
    after 100 ->
        ct:pal("No resp from unidi Stm2")
    end,
    quicer:close_connection(Conn),
    ok.

tc_direct_send_over_conn_fail(Config) ->
    Port = select_port(),
    application:ensure_all_started(quicer),
    ListenerOpts = [
        {allow_insecure, true},
        {conn_acceptors, 32}
        | default_listen_opts(Config)
    ],
    ConnectionOpts = [
        {conn_callback, quicer_server_conn_callback},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, quicer_echo_server_stream_callback}
        | default_stream_opts()
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    ct:pal("Listener Options: ~p", [Options]),
    {ok, _QuicApp} = quicer:spawn_listener(mqtt, Port, Options),
    {ok, Conn} = quicer:async_connect(
        "localhost",
        Port,
        [
            {disable_1rtt_encryption, true}
            | default_conn_opts()
        ]
    ),
    %% Stream 1 enabled
    {ok, Stm} = quicer:start_stream(Conn, [
        {active, true},
        {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE},
        {start_flag, ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL}
    ]),
    {ok, 5} = quicer:async_send(Stm, <<"ping1">>),

    quicer:shutdown_connection(Conn),

    %% csend over a closed conn

    case
        quicer:async_csend(
            Conn,
            <<"ping22">>,
            [
                {active, true},
                {quic_event_mask, ?QUICER_STREAM_EVENT_MASK_START_COMPLETE},
                {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
            ],
            ?QUIC_SEND_FLAG_ALLOW_0_RTT
        )
    of
        {error, closed} -> ok;
        {error, stm_open_error, invalid_parameter} -> ok;
        {error, stm_open_error, invalid_state} -> ok
    end,
    receive
        {quic, start_completed, Stm0, #{status := StartStatus, stream_id := StreamId2}} ->
            ct:pal("Stream id: ~p started: ~p", [StreamId2, StartStatus]),
            %% Depends on the timing of closing connection, for stream 1, it can be either success or fail
            ?assert(invalid_state =:= StartStatus orelse success =:= StartStatus),
            ?assertEqual(Stm, Stm0)
    end,

    receive
        {quic, start_completed, StmX, #{status := StartStatusX, stream_id := StreamIdX}} when
            StmX =/= Stm0
        ->
            ct:fail("Stream id: ~p started: ~p", [StreamIdX, StartStatusX])
    after 100 ->
        quicer:close_connection(Conn),
        ok
    end.

tc_getopt_tls_handshake_info(Config) ->
    Port = select_port(),
    Owner = self(),
    Opts = lists:keyreplace(alpn, 1, default_listen_opts(Config), {alpn, ["sample2", "sample"]}),
    {SPid, _Ref} = spawn_monitor(fun() -> conn_server_with(Owner, Port, Opts) end),
    receive
        listener_ready ->
            {ok, Conn} = quicer:connect("localhost", Port, default_conn_opts(), 5000),
            {ok, {_, _}} = quicer:sockname(Conn),
            {ok,
                #{
                    cipher_algorithm := aes_256,
                    cipher_strength := 256,
                    cipher_suite := aes_256_gcm_sha384,
                    hash_algorithm := sha_384,
                    hash_strength := 0,
                    key_exchange_algorithm := none,
                    key_exchange_strength := 0,
                    tls_protocol_version := tlsv1_3
                } = HSInfo} =
                quicer:getopt(Conn, handshake_info, quic_tls),
            ?assertEqual(
                {error, not_supported},
                quicer:setopt(Conn, handshake_info, HSInfo, quic_tls)
            ),
            ok = quicer:close_connection(Conn),
            SPid ! done
    after 1000 ->
        ct:fail("timeout")
    end.

tc_peercert_client(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            simple_conn_server_client_cert(Owner, Config, Port)
        end
    ),
    receive
        listener_ready -> ok
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts_client_cert(Config, "ca"),
        5000
    ),
    {ok, {_, _}} = quicer:sockname(Conn),
    {ok, PeerCert} = quicer:peercert(Conn),
    OTPCert = public_key:pkix_decode_cert(PeerCert, otp),
    Subject =
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-countryName', "SE"}],
            [{'AttributeTypeAndValue', ?'id-at-organizationName', {utf8String, <<"TEST">>}}],
            [{'AttributeTypeAndValue', ?'id-at-commonName', {utf8String, <<"server">>}}]
        ]},
    ?assertMatch(
        {_, Subject},
        pubkey_cert:subject_id(OTPCert)
    ),
    ok = quicer:close_connection(Conn),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_peercert_client_nocert(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            simple_conn_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready -> ok
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts(),
        5000
    ),
    {ok, {_, _}} = quicer:sockname(Conn),
    ?assertEqual({error, no_peercert}, quicer:peercert(Conn)),
    ok = quicer:close_connection(Conn),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_peercert_server(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            simple_conn_server_client_cert(Owner, Config, Port)
        end
    ),
    receive
        listener_ready -> ok
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts_client_cert(Config, "ca"),
        5000
    ),
    SPid ! peercert,
    PeerCert =
        receive
            {SPid, peercert, Cert} ->
                Cert;
            {quic, transport_shutdown, Conn, _} = M ->
                ct:fail("conn fail : ~p", [M])
        end,
    OTPCert = public_key:pkix_decode_cert(PeerCert, otp),
    ct:pal("client cert is ~p", [OTPCert]),
    Subject =
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-countryName', "SE"}],
            [{'AttributeTypeAndValue', ?'id-at-organizationName', {utf8String, <<"TEST">>}}],
            [{'AttributeTypeAndValue', ?'id-at-commonName', {utf8String, <<"client">>}}]
        ]},
    ?assertMatch(
        {_, Subject},
        pubkey_cert:subject_id(OTPCert)
    ),
    ok = quicer:close_connection(Conn),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_peercert_server_nocert(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            simple_conn_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready -> ok
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts(),
        5000
    ),
    {ok, {_, _}} = quicer:sockname(Conn),
    SPid ! peercert,
    receive
        {SPid, peercert, CertResp} ->
            ?assertEqual({error, no_peercert}, CertResp)
    end,
    ok = quicer:close_connection(Conn),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_abi_version(_Config) ->
    ?assertEqual(1, quicer:abi_version()).

tc_stream_get_owner_local(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            simple_conn_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready -> ok
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        default_conn_opts(),
        5000
    ),
    {ok, {_, _}} = quicer:sockname(Conn),
    {ok, Conn} = quicer:async_accept_stream(Conn, []),
    {ok, Stm} = quicer:async_csend(Conn, <<"hello">>, [{active, true}], ?QUIC_SEND_FLAG_START),
    ?assertEqual({ok, self()}, quicer:get_stream_owner(Stm)),
    ok = quicer:close_stream(Stm),
    _ = quicer:close_connection(Conn),
    SPid ! done,
    ensure_server_exit_normal(Ref),
    ok.

tc_stream_get_owner_remote(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "127.0.0.1",
        Port,
        default_conn_opts() ++ [{peer_unidi_stream_count, 1}],
        5000
    ),
    {ok, Stm0} = quicer:start_stream(Conn, [
        {active, true},
        {start_flag, ?QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT},
        {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
    ]),
    {ok, 5} = quicer:send(Stm0, <<"ping1">>),
    receive
        {quic, <<"ping1">>, Stm0, _} ->
            ct:fail("We should not recv ping1 due to flow control: bidir stream 0")
    after 1000 ->
        ct:pal("recv ping1 timeout"),
        SPid ! {flow_ctl, 10, 1}
    end,
    quicer:async_accept_stream(Conn, []),
    %% check with server if peer addr is correct.
    receive
        {quic, peer_accepted, Stm0, undefined} ->
            ct:pal("peer_accepted received")
    after 1000 ->
        ct:fail("peer_accepted timeout")
    end,

    %% Now we expect server initiat an Server -> Stream unidirectional stream
    receive
        {quic, new_stream, Stm1, #{flags := Flags}} ->
            ?assert(quicer:is_unidirectional(Flags)),
            ?assertEqual({ok, self()}, quicer:get_stream_owner(Stm1)),
            %% We also expect server send reply over new stream
            receive
                {quic, <<"ping1">>, Stm0, _} ->
                    ct:fail("Data recvd from client -> server unidirectional stream");
                {quic, <<"ping1">>, Stm1, _} ->
                    ct:pal("Data recvd from server -> client unidirectional stream")
            end
    after 2000 ->
        ct:fail("No new_stream for stream initiated from Server")
    end,
    SPid ! done,
    ensure_server_exit_normal(Ref).

tc_setopt_global_lb_mode_ifip(_Config) ->
    {ok, _} = application:ensure_all_started(quicer),
    true = code:soft_purge(quicer_nif),
    true = code:delete(quicer_nif),
    %% If test fail ensure we have this netdev
    NetDevName =
        case os:type() of
            {unix, darwin} -> "lo0";
            _ -> "lo"
        end,
    application:set_env(quicer, lb_mode, NetDevName),
    quicer:reg_close(),
    quicer:close_lib(),
    {ok, _} = quicer:open_lib(),
    ?assertEqual(
        {ok, ?QUIC_LOAD_BALANCING_SERVER_ID_FIXED},
        quicer:getopt(quic_global, load_balacing_mode)
    ).

tc_setopt_congestion_control_algorithm(Config) ->
    Port = select_port(),
    Owner = self(),
    {SPid, _Ref} = spawn_monitor(
        fun() ->
            echo_server(Owner, Config, Port)
        end
    ),
    receive
        listener_ready ->
            ok
    after 5000 ->
        ct:fail("listener_timeout")
    end,
    {ok, Conn} = quicer:connect(
        "localhost",
        Port,
        [
            {congestion_control_algorithm, ?QUIC_CONGESTION_CONTROL_ALGORITHM_BBR}
            | default_conn_opts()
        ],
        5000
    ),
    {ok, Stm} = quicer:start_stream(Conn, []),
    {ok, 4} = quicer:send(Stm, <<"ping">>),

    {ok, Settings} = quicer:getopt(Conn, settings),
    ?assertMatch(
        ?QUIC_CONGESTION_CONTROL_ALGORITHM_BBR,
        proplists:get_value(congestion_control_algorithm, Settings)
    ),

    quicer:shutdown_connection(Conn),
    SPid ! done,
    ok.

%%% ====================
%%% Internal helpers
%%% ====================
echo_server(Owner, Config, Port) ->
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
                    ct:pal("echo server stream flow control to bidirectional: ~p : ~p", [
                        BidirCount, UniDirCount
                    ]),
                    quicer:setopt(Conn, settings, #{
                        peer_bidi_stream_count => BidirCount,
                        peer_unidi_stream_count => UniDirCount
                    }),
                    receive
                        {quic, new_stream, Stm, _Props} ->
                            {ok, Conn} = quicer:async_accept_stream(Conn, [])
                    end
            end,
            ct:pal("echo server stream accepted", []),
            echo_server_stm_loop(L, Conn, [Stm]);
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
            SendFlag =
                case (Flag band ?QUIC_RECEIVE_FLAG_FIN) > 0 of
                    true -> ?QUICER_SEND_FLAG_SYNC bor ?QUIC_SEND_FLAG_FIN;
                    false -> ?QUICER_SEND_FLAG_SYNC
                end,
            case quicer:send(Stm, Bin, SendFlag) of
                {error, stm_send_error, aborted} ->
                    ct:pal("echo server: send aborted: ~p ", [Bin]);
                {error, stm_send_error, invalid_state} ->
                    {ok, RetStream} =
                        quicer:start_stream(Conn, [
                            {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
                        ]),
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
        {set_stm_cnt, N} ->
            ct:pal("echo_server: set max stream count: ~p", [N]),
            ok = quicer:setopt(Conn, settings, #{peer_bidi_stream_count => N}),
            {ok, NewStm} = quicer:accept_stream(Conn, []),
            echo_server_stm_loop(L, Conn, [NewStm | Stms]);
        {peer_addr, From} ->
            From ! {peer_addr, quicer:peername(Conn)},
            echo_server_stm_loop(L, Conn, Stms);
        {flow_ctl, BidirCount, UniDirCount} ->
            ct:pal("echo server stream flow control to bidirectional: ~p : ~p", [
                BidirCount, UniDirCount
            ]),
            quicer:setopt(Conn, settings, #{
                peer_bidi_stream_count => BidirCount,
                peer_unidi_stream_count => UniDirCount
            }),
            {ok, Conn} = quicer:async_accept_stream(Conn, []),
            echo_server_stm_loop(L, Conn, Stms);
        {quic, new_stream, NewStm, #{flags := Flags}} ->
            NewStmList =
                case quicer:is_unidirectional(Flags) of
                    true ->
                        ct:pal("echo server: new incoming unidirectional stream"),
                        {ok, ReturnStm} = quicer:start_stream(Conn, [
                            {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
                        ]),
                        [{NewStm, ReturnStm} | Stms];
                    false ->
                        ct:pal("echo server: new incoming binary stream"),
                        [NewStm | Stms]
                end,
            echo_server_stm_loop(L, Conn, NewStmList);
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
                {quic, new_stream, Stm, _Props} ->
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
        {quic, <<"ping">>, _, _} ->
            ct:pal("send pong"),
            {ok, 4} = quicer:send(Stm, <<"pong">>),
            ping_pong_server_stm_loop(L, Conn, Stm);
        {quic, peer_send_shutdown, Stm, undefined} ->
            ct:pal("closing stream"),
            quicer:close_stream(Stm),
            ?assertNotEqual(
                {error, closed},
                quicer:get_stream_id(Stm)
            ),
            ping_pong_server_stm_loop(L, Conn, Stm);
        {quic, shutdown, Conn, ErrorCode} ->
            ct:pal("closing conn: ~p", [ErrorCode]),
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
            {ok, Conn} = quicer:async_accept_stream(Conn, []),
            {ok, Conn} = quicer:handshake(Conn),
            ping_pong_server_dgram_loop(L, Conn);
        {error, listener_start_error, R} ->
            ct:pal("Failed to start listener:~p , retry ...", [R]),
            timer:sleep(100),
            ping_pong_server_dgram(Owner, Config, Port)
    end.

ping_pong_server_dgram_loop(L, Conn) ->
    receive
        {quic, new_stream, Stm, _} ->
            ping_pong_server_dgram_loop(L, Conn, Stm)
    end.

ping_pong_server_dgram_loop(L, Conn, Stm) ->
    receive
        {quic, <<"ping">>, Stm, _} ->
            ct:pal("send stream pong"),
            {ok, 4} = quicer:send(Stm, <<"pong">>),
            ping_pong_server_dgram_loop(L, Conn, Stm);
        {quic, <<"ping">>, Conn, Flag} when is_integer(Flag) ->
            ct:pal("send dgram pong"),
            {ok, 4} = quicer:send_dgram(Conn, <<"pong">>),
            ping_pong_server_dgram_loop(L, Conn, Stm);
        {quic, peer_send_shutdown, Stm, undefined} ->
            ct:pal("closing stream"),
            quicer:close_stream(Stm),
            ping_pong_server_dgram_loop(L, Conn, Stm);
        {quic, shutdown, Conn, ErrorCode} ->
            ct:pal("closing conn: ~p", [ErrorCode]),
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

simple_conn_server_client_cert(Owner, Config, Port) ->
    {ok, L} = quicer:listen(Port, default_listen_opts_client_cert(Config)),
    Owner ! listener_ready,
    {ok, Conn} = quicer:accept(L, [], 1000),
    case quicer:handshake(Conn) of
        {ok, Conn} ->
            simple_conn_server_client_cert_loop(L, Conn, Owner);
        {error, closed} ->
            receive
                done ->
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

conn_server_with(Owner, Port, Opts) ->
    {ok, L} = quicer:listen(Port, Opts),
    Owner ! listener_ready,
    case quicer:accept(L, [], 10000) of
        {error, _} ->
            quicer:close_listener(L);
        {ok, Conn} ->
            {ok, Conn} = quicer:handshake(Conn)
    end,
    receive
        done ->
            quicer:close_listener(L)
    end.

simple_stream_server(Owner, Config, Port) ->
    {ok, L} = quicer:listen(Port, default_listen_opts(Config)),
    Owner ! listener_ready,
    {ok, Conn} = quicer:accept(L, [], 5000),
    {ok, Conn} = quicer:async_accept_stream(Conn, []),
    {ok, Conn} = quicer:handshake(Conn),
    receive
        {quic, new_stream, Stream, _Props} ->
            StreamId =
                case quicer:get_stream_id(Stream) of
                    {ok, Stm} ->
                        Stm;
                    {error, _} ->
                        simple_stream_server_exit(L)
                end,
            ct:pal("New StreamID: ~p", [StreamId]),
            receive
                {quic, shutdown, Conn, _ErrorCode} ->
                    ct:pal("closing ~p", [Conn]),
                    quicer:close_connection(Conn);
                {quic, peer_send_shutdown, Stream, undefined} ->
                    quicer:close_stream(Stream);
                done ->
                    simple_stream_server_exit(L)
            end;
        {quic, shutdown, Conn, _ErrorCode} ->
            ct:pal("Received Conn close for ~p", [Conn]),
            quicer:close_connection(Conn)
    end,
    receive
        {quic, shutdown, Conn, ErrorCode} ->
            ct:pal("Received Conn shutdown for ~p: ~p", [Conn, ErrorCode]),
            quicer:close_connection(Conn);
        done ->
            ok
    end,
    simple_stream_server_exit(L).

simple_stream_server_exit(L) ->
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

default_conn_opts_verify(Config, Ca) ->
    DataDir = ?config(data_dir, Config),
    [
        {verify, peer},
        {cacertfile, filename(DataDir, "~s.pem", [Ca])}
        | tl(default_conn_opts())
    ].

default_conn_opts_client_cert(Config, Ca) ->
    DataDir = ?config(data_dir, Config),
    [
        {keyfile, filename:join(DataDir, "client.key")},
        {certfile, filename:join(DataDir, "client.pem")}
        | default_conn_opts_verify(Config, Ca)
    ].

default_conn_opts_bad_client_cert(Config, Ca) ->
    DataDir = ?config(data_dir, Config),
    [
        {keyfile, filename:join(DataDir, "other-client.key")},
        {certfile, filename:join(DataDir, "other-client.pem")}
        | default_conn_opts_verify(Config, Ca)
    ].

default_listen_opts_client_cert(Config) ->
    DataDir = ?config(data_dir, Config),
    [
        {cacertfile, filename:join(DataDir, "ca.pem")},
        {verify, peer}
        | tl(default_listen_opts(Config))
    ].

active_recv(Stream, Len) ->
    active_recv(Stream, Len, []).
active_recv(Stream, Len, BinList) ->
    case iolist_size(BinList) >= Len of
        true ->
            binary:list_to_bin(lists:reverse(BinList));
        false ->
            receive
                {quic, Bin, Stream, _} when is_binary(Bin) ->
                    active_recv(Stream, Len, [Bin | BinList])
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

flush_streams_available(Conn) ->
    receive
        {quic, streams_available, Conn, #{bidi_streams := _, unidi_streams := _}} -> ok
    end.

flush_datagram_state_changed(Conn) ->
    receive
        {quic, dgram_state_changed, Conn, _} -> ok
    end.

filename(Path, F, A) ->
    filename:join(Path, str(io_lib:format(F, A))).
str(Arg) ->
    binary_to_list(iolist_to_binary(Arg)).

select_port() ->
    select_free_port(quic).
