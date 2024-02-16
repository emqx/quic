%%--------------------------------------------------------------------
%% Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(prop_quicer_nif).
-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").
-include("prop_quic_types.hrl").

-import(
    quicer_prop_gen,
    [
        valid_client_conn_opts/0,
        valid_server_listen_opts/0,
        valid_stream_shutdown_flags/0,
        valid_stream_start_flags/0,
        valid_stream_handle/0,
        valid_started_connection_handle/0,
        valid_opened_connection_handle/0,
        valid_connection_handle/0,
        valid_listen_on/0,
        valid_listen_opts/0,
        valid_listen_handle/0,
        valid_global_handle/0,
        valid_reg_handle/0,
        valid_handle/0,
        pid/0,
        data/0,
        quicer_send_flags/0
    ]
).

prop_robust_new_registration_2() ->
    ?FORALL(
        {Key, Value},
        {string(), term()},
        begin
            case quicer_nif:new_registration(Key, Value) of
                {ok, _} ->
                    true;
                {error, _} ->
                    true
            end
        end
    ).

prop_shutdown_registration_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle},
        valid_reg_handle(),
        begin
            ok == quicer_nif:shutdown_registration(Handle)
        end
    ).

prop_shutdown_registration_3() ->
    ?FORALL(
        {#prop_handle{type = reg, handle = Handle}, IsSilent, ErrorCode},
        {valid_reg_handle(), boolean(), uint64()},
        begin
            ok == quicer_nif:shutdown_registration(Handle, IsSilent, ErrorCode)
        end
    ).

prop_close_registration_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle},
        valid_reg_handle(),
        begin
            ok == quicer_nif:close_registration(Handle)
        end
    ).

prop_get_registration_name() ->
    ?FORALL(
        #prop_handle{type = reg, name = Name, handle = Handle} = H,
        valid_reg_handle(),
        begin
            Res = quicer_nif:get_registration_name(Handle),
            (H#prop_handle.destructor)(),
            {ok, Name} == Res
        end
    ).

%% robustness test, no crash
prop_listen_robust() ->
    ?FORALL(
        {On, Opts},
        {listen_on(), quicer_listen_opts()},
        begin
            case quicer_nif:listen(On, maps:from_list(Opts)) of
                {ok, Handle} ->
                    quicer_nif:close_listener(Handle),
                    true;
                {error, _} ->
                    true;
                {error, _, _} ->
                    true
            end
        end
    ).

%% robustness test, no crash
%% precondition: with valid listener handle
prop_start_listener_with_valid_handle() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = Handle, destructor = Destroy} = H, On, Opts},
        {valid_listen_handle(), listen_on(), quicer_listen_opts()},
        begin
            case quicer_nif:start_listener(Handle, On, maps:from_list(Opts)) of
                {ok, _} ->
                    Destroy(),
                    true;
                {error, _} ->
                    Destroy(),
                    true
            end
        end
    ).

%% robustness test, no crash
prop_robust_stop_listener() ->
    ?FORALL(
        Handle,
        any(),
        begin
            collect(quicer_nif:stop_listener(Handle), true)
        end
    ).

%% robustness test, no crash
prop_robust_close_listener() ->
    ?FORALL(
        Handle,
        any(),
        begin
            collect(quicer_nif:close_listener(Handle), true)
        end
    ).

%% stop_listener with valid listen handle must success
prop_stop_listener_with_valid_handle() ->
    ?FORALL(
        #prop_handle{type = listener, handle = Handle},
        valid_listen_handle(),
        begin
            ok == quicer_nif:stop_listener(Handle)
        end
    ).

%% @doc Start stopped Listener must success with valid opts
%% precondition: with valid listener handle AND valid listen on AND valid listen TLS opts
prop_start_listener_with_valid_handle_AND_valid_listen_on() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = Handle, destructor = Destroy}, On, Opts},
        {valid_listen_handle(), valid_listen_on(), valid_listen_opts()},
        begin
            ok = quicer_nif:stop_listener(Handle),
            LOpts = maps:from_list(Opts),
            Res = quicer_nif:start_listener(Handle, On, LOpts),
            Destroy(),
            % collect(Res, Res == ok orelse Res == {error, invalid_parameter})
            collect(Res, true)
        end
    ).

%% robustness test, no crash
prop_robust_open_connection_0() ->
    ?FORALL(
        _,
        integer(),
        begin
            {ok, H} = quicer_nif:open_connection(),
            quicer:async_shutdown_connection(H, 0, 0),
            true
        end
    ).

%% robustness test, no crash
prop_robust_open_connection_1() ->
    ?FORALL(
        #prop_handle{type = reg, handle = Handle, destructor = Destroy},
        valid_reg_handle(),
        begin
            {ok, _Handle} = quicer_nif:open_connection(Handle),
            quicer_nif:async_shutdown_connection(Handle, 0, 0),
            Destroy(),
            true
        end
    ).

%% robustness test, no crash
prop_robust_async_connect_3() ->
    Port = quicer_test_lib:select_free_port(quic),
    {ok, LH} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
    ?FORALL(
        ConnOpts,
        quicer_conn_opts(),
        begin
            COpts = maps:from_list(ConnOpts),
            case quicer_nif:async_connect("localhost", Port, COpts) of
                {ok, ConnHandle} ->
                    quicer:close_listener(LH),
                    quicer_nif:async_shutdown_connection(ConnHandle, 0, 0),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

%% precondition: with valid TLS opts
prop_async_connect_3_with_valid_connopts() ->
    Port = quicer_test_lib:select_free_port(quic),
    {ok, LH} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
    ?FORALL(
        ConnOpts,
        quicer_conn_opts(),
        begin
            COpts = maps:from_list(ConnOpts ++ valid_client_conn_opts()),
            case
                quicer_nif:async_connect(
                    "localhost",
                    Port,
                    COpts
                )
            of
                {ok, ConnHandle} ->
                    quicer:close_listener(LH),
                    quicer_nif:async_shutdown_connection(ConnHandle, 0, 0),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

prop_robust_async_accept_2() ->
    ?FORALL(
        {LH, AcceptOpts},
        {any(), any()},
        begin
            case quicer_nif:async_accept(LH, AcceptOpts) of
                {ok, _ConnHandle} ->
                    quicer:close_listener(LH),
                    collect(ok, true);
                E ->
                    quicer:close_listener(LH),
                    collect(E, true)
            end
        end
    ).

%% accept on valid listener handle
prop_async_accept_2() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = LH, destructor = Destroy}, AcceptOpts},
        {valid_listen_handle(), quicer_acceptor_opts()},
        begin
            AOpts = maps:from_list(AcceptOpts),
            case quicer_nif:async_accept(LH, AOpts) of
                {ok, _ConnHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

%% 'active_n' always >= 0
prop_async_accept_2_with_active() ->
    ?FORALL(
        {#prop_handle{type = listener, handle = LH, destructor = Destroy}, ActiveN},
        {valid_listen_handle(), oneof([boolean(), integer()])},
        begin
            case quicer_nif:async_accept(LH, #{active => ActiveN}) of
                {ok, ConnHandle} ->
                    quicer:close_connection(ConnHandle),
                    Destroy(),
                    collect(ok, quicer:getopt(ConnHandle, active) >= 0);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_start_stream() ->
    ?FORALL(
        {ConnHandle, StreamOpts},
        {any(), any()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpts) of
                {ok, _StreamHandle} ->
                    quicer:close_connection(ConnHandle),
                    collect(ok, true);
                E ->
                    quicer:close_connection(ConnHandle),
                    collect(E, true)
            end
        end
    ).

prop_start_stream_with_valid_conn_handle() ->
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, StreamOpts},
        {valid_connection_handle(), any()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpts) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_start_stream_with_valid_conn_handle_AND_mandatory() ->
    %% active_n is mandatory
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, StreamOpt, ActiveN},
        {valid_connection_handle(), map(), active_n()},
        begin
            case quicer_nif:start_stream(ConnHandle, StreamOpt#{active => ActiveN}) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_csend() ->
    ?FORALL(
        {Handle, Data, Opts, Flags},
        {any(), any(), any(), any()},
        begin
            case quicer_nif:csend(Handle, Data, Opts, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    quicer:close_stream(Handle),
                    collect(E, true)
            end
        end
    ).

prop_csend_with_valid_opts() ->
    %% @NOTE, start could still fail with different combination of opts
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, Data, Opts, Flags},
        {valid_connection_handle(), data(), quicer_stream_opts(), quicer_send_flags()},
        begin
            SOpts = maps:from_list(Opts),
            case quicer_nif:csend(ConnHandle, Data, SOpts, Flags) of
                {ok, StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                {error, closed} ->
                    Destroy(),
                    %% As we test closed (not started) conn handle
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_send_3() ->
    ?FORALL(
        {Handle, Data, Flags},
        {any(), any(), any()},
        begin
            case quicer_nif:send(Handle, Data, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_send_3() ->
    ?FORALL(
        {#prop_handle{type = stream, handle = StreamHandle, destructor = Destroy}, Data, Flags},
        {valid_stream_handle(), data(), quicer_send_flags()},
        begin
            case quicer_nif:send(StreamHandle, Data, Flags) of
                {ok, _} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_recv_2() ->
    ?FORALL(
        {Handle, Len},
        {any(), any()},
        begin
            case quicer_nif:recv(Handle, Len) of
                {ok, _Data} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    quicer:close_stream(Handle),
                    collect(E, true)
            end
        end
    ).

prop_recv_2_with_valid_stream_handle() ->
    ?FORALL(
        {#prop_handle{type = stream, handle = StreamHandle, destructor = Destroy}, Len},
        {valid_stream_handle(), non_neg_integer()},
        begin
            quicer_nif:setopt(StreamHandle, active, false, false),
            case quicer_nif:recv(StreamHandle, Len) of
                {ok, Data} when Data == not_ready orelse is_binary(Data) ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_send_dgram() ->
    ?FORALL(
        {Handle, Data, Flags},
        {any(), any(), any()},
        begin
            case quicer_nif:send_dgram(Handle, Data, Flags) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_send_dgram_with_valid_opts() ->
    ?FORALL(
        {#prop_handle{type = conn, handle = ConnHandle, destructor = Destroy}, Data, Flags},
        {valid_connection_handle(), data(), quicer_send_flags()},
        begin
            case quicer_nif:send_dgram(ConnHandle, Data, Flags) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_async_shutdown_stream() ->
    ?FORALL(
        {Handle, Flags, ErrorCode},
        {any(), any(), any()},
        begin
            case quicer_nif:async_shutdown_stream(Handle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    quicer:close_stream(Handle),
                    collect(ok, true);
                E ->
                    collect(E, true)
            end
        end
    ).

prop_async_shutdown_stream_with_valid_stream_handle() ->
    ?FORALL(
        {
            #prop_handle{type = stream, handle = StreamHandle, destructor = Destroy},
            Flags,
            ErrorCode
        },
        {valid_stream_handle(), uint32(), uint64()},
        begin
            case quicer_nif:async_shutdown_stream(StreamHandle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_async_shutdown_stream_with_valid_stream_handle_AND_flags() ->
    ?FORALL(
        {
            #prop_handle{type = stream, handle = StreamHandle, destructor = Destroy},
            Flags,
            ErrorCode
        },
        {valid_stream_handle(), valid_stream_shutdown_flags(), uint64()},
        begin
            case quicer_nif:async_shutdown_stream(StreamHandle, Flags, ErrorCode) of
                {ok, _StreamHandle} ->
                    Destroy(),
                    collect(ok, true);
                E ->
                    Destroy(),
                    collect(E, true)
            end
        end
    ).

prop_robust_sockname() ->
    ?FORALL(
        Handle,
        any(),
        begin
            {error, badarg} == quicer_nif:sockname(Handle)
        end
    ).

prop_sockname() ->
    ?FORALL(
        #prop_handle{type = conn, handle = ConnHandle, destructor = Destroy},
        valid_connection_handle(),
        begin
            Res =
                case quicer_nif:sockname(ConnHandle) of
                    {ok, _} -> ok;
                    E -> E
                end,
            Destroy(),
            collect(Res, true)
        end
    ).

prop_robust_getopt_3() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {any(), any(), any()},
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            {error, badarg} == quicer_nif:getopt(Handle, Opt, OptLevel)
        end
    ).

prop_getopt_3_with_valid_handle() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {valid_handle(), any(), any()},
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Opt, OptLevel),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_with_valid_handle_AND_param() ->
    ?FORALL(
        {Handle, Opt0, OptLevel},
        {
            valid_handle(),
            oneof([
                listen_opt(),
                conn_opt(),
                acceptor_opt(),
                stream_opt()
            ]),
            optlevel()
        },
        begin
            Opt =
                case Opt0 of
                    {Opt1, _} -> Opt1;
                    Opt1 -> Opt1
                end,
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Opt, OptLevel),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_robust_setopt_4() ->
    ?FORALL(
        {Handle, Opt, OptLevel, Value},
        {any(), any(), any(), any()},
        begin
            {error, badarg} == quicer_nif:setopt(Handle, Opt, OptLevel, Value)
        end
    ).

prop_robust_setopt_4_with_valid_handle_AND_param() ->
    ?FORALL(
        {Handle, {Optname, Value}, OptLevel},
        {
            valid_handle(),
            oneof([
                listen_opt(),
                conn_opt(),
                acceptor_opt(),
                stream_opt(),
                quicer_setting()
            ]),
            optlevel()
        },
        begin
            Res = quicer_nif:setopt(Handle#prop_handle.handle, Optname, OptLevel, Value),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_stream_opt() ->
    ?FORALL(
        {Handle, {Optname, _Value}},
        {valid_stream_handle(), stream_opt()},
        begin
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Optname, false),
            (Handle#prop_handle.destructor)(),
            collect(Res, true)
        end
    ).

prop_getopt_3_conn_opt() ->
    ?FORALL(
        {Handle, {Optname, _Value}},
        {valid_connection_handle(), conn_opt()},
        begin
            Res = quicer_nif:getopt(Handle#prop_handle.handle, Optname, false),
            (Handle#prop_handle.destructor)(),
            case Res of
                {ok, _} ->
                    collect(ok, true);
                _ ->
                    collect({Optname, Res}, true)
            end
        end
    ).

prop_robust_peercert() ->
    ?FORALL(
        Handle,
        any(),
        begin
            {error, badarg} == quicer:peercert(Handle)
        end
    ).

prop_peercert_with_valid_connection_handle() ->
    ?FORALL(
        #prop_handle{type = conn, handle = Handle, destructor = Destroy},
        valid_connection_handle(),
        begin
            Res = quicer_nif:peercert(Handle),
            Destroy(),
            collect(Res, true)
        end
    ).

prop_peercert_with_valid_stream_handle() ->
    ?FORALL(
        #prop_handle{type = stream, handle = Handle, destructor = Destroy},
        valid_stream_handle(),
        begin
            Destroy(),
            collect(quicer_nif:peercert(Handle), true)
        end
    ).

prop_robust_controlling_process() ->
    ?FORALL(
        {Handle, Pid},
        {any(), any()},
        begin
            {error, badarg} == quicer_nif:controlling_process(Handle, Pid)
        end
    ).

prop_controlling_process_with_valid_opts() ->
    ?FORALL(
        {#prop_handle{type = Type, handle = Handle, destructor = Destroy}, Pid},
        {valid_handle(), pid()},
        begin
            Res = quicer_nif:controlling_process(Handle, Pid),
            case Res of
                ok when Type == conn ->
                    {ok, Pid} = quicer_nif:get_conn_owner(Handle);
                ok when Type == stream ->
                    {ok, Pid} = quicer_nif:get_stream_owner(Handle);
                _ ->
                    skip
            end,
            Destroy(),
            collect({Type, Res}, true)
        end
    ).

%%% ============================================================================
%%%  Generators
%%% ============================================================================
