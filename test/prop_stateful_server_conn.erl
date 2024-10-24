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
-module(prop_stateful_server_conn).
-compile([export_all]).
-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").
-include("prop_quic_types.hrl").

-define(PORT, 14569).

%% Model Callbacks
-export([
    command/1,
    initial_state/0,
    next_state/3,
    precondition/2,
    postcondition/3
]).

%%%%%%%%%%%%%%%%%%
%%% PROPERTIES %%%
%%%%%%%%%%%%%%%%%%
prop_server_state_test(opts) ->
    [{numtests, 2000}].
prop_server_state_test() ->
    process_flag(trap_exit, true),
    ?SETUP(
        fun() ->
            {ok, L} = quicer:listen(?PORT, default_listen_opts()),
            put(listener, L),
            fun() -> quicer:close_listener(L) end
        end,
        ?FORALL(
            Cmds,
            commands(?MODULE),
            begin
                {History, State, Result} = run_commands(?MODULE, Cmds),
                ?WHENFAIL(
                    io:format(
                        "History: ~p\nState: ~p\nResult: ~p\n",
                        [History, State, Result]
                    ),
                    aggregate(command_names(Cmds), Result =:= ok)
                )
            end
        )
    ).

%%%%%%%%%%%%%
%%% MODEL %%%
%%%%%%%%%%%%%
%% @doc Initial model value at system start. Should be deterministic.
initial_state() ->
    process_flag(trap_exit, true),
    {ok, _L} = quicer:async_accept(get(listener), #{active => false}),

    %%% We don't care about the client thus no linking.
    spawn(fun() ->
        {ok, _Client} = example_client_connection:start_link(
            "localhost",
            ?PORT,
            {default_conn_opts(), quicer_test_lib:default_stream_opts()}
        )
    end),

    receive
        {quic, new_conn, Conn, _} ->
            #{
                state => accepted,
                handle => Conn,
                owner => self(),
                me => self(),
                % cnt calls
                calls => 0
            }
    after 100 ->
        initial_state()
    end.

%% @doc List of possible commands to run against the system
%%
command(#{handle := Handle}) ->
    frequency([
        {200, {call, quicer, handshake, [Handle, 1000]}},
        {100, {call, quicer, getopt, [Handle, ?LET({Opt, _}, conn_opt(), Opt)]}},
        {100,
            {call, quicer, async_accept_stream, [Handle, ?LET(Opts, quicer_acceptor_opts(), Opts)]}},
        {100, {call, quicer, peername, [Handle]}},
        {50, {call, quicer, peercert, [Handle]}},
        {10, {call, quicer, negotiated_protocol, [Handle]}},
        {10, {call, quicer, get_connections, []}},
        {10, {call, quicer, get_conn_owner, [Handle]}},
        {1, {call, quicer, controlling_process, [Handle, ?LET(Pid, quicer_prop_gen:pid(), Pid)]}},
        {100,
            {call, quicer, async_csend, [
                Handle,
                ?LET(Bin, binary(), Bin),
                quicer_prop_gen:valid_csend_stream_opts(),
                ?valid_flags(send_flags())
            ]}},
        {50,
            {call, quicer, close_connection, [
                Handle, ?valid_flags(conn_shutdown_flag()), non_neg_integer(), 10
            ]}},
        {50,
            {call, quicer, shutdown_connection, [
                Handle, ?valid_flags(conn_shutdown_flag()), ?LET(ErrorCode, uint62(), ErrorCode), 10
            ]}}
    ]).

%% @doc Determines whether a command should be valid under the
%% current state.
precondition(#{state := accepted}, {call, _Mod, _Fun, _Args}) ->
    true;
precondition(#{state := connected}, {call, _Mod, _Fun, _Args}) ->
    true;
precondition(#{state := closed}, {call, _Mod, _Fun, _Args}) ->
    true;
precondition(_State, {call, _Mod, _Fun, _Args}) ->
    false.

%% @doc Given the state `State' *prior* to the call
%% `{call, Mod, Fun, Args}', determine whether the result
%% `Res' (coming from the actual system) makes sense.
postcondition(#{state := accepted}, {call, quicer, handshake, _Args}, {ok, _}) ->
    true;
postcondition(#{state := accepted}, {call, quicer, handshake, _Args}, {error, invalid_state}) ->
    true;
postcondition(#{state := closed}, {call, quicer, handshake, _}, {error, timeout}) ->
    true;
postcondition(#{state := _}, {call, quicer, handshake, _Args}, {error, timeout}) ->
    %% @FIXME
    true;
postcondition(
    #{state := accepted, me := Me, owner := Owner},
    {call, quicer, handshake, _Args},
    {error, timeout}
) when
    Me =/= Owner
->
    %% @FIXME https://github.com/emqx/quic/issues/266
    true;
postcondition(#{state := S}, {call, quicer, handshake, _Args}, {error, invalid_state}) when
    S =/= accepted
->
    true;
postcondition(_State, {call, quicer, getopt, _Args}, {ok, _}) ->
    true;
postcondition(_State, {call, quicer, getopt, [_, password]}, {error, badarg}) ->
    true;
postcondition(_State, {call, quicer, getopt, [_, NotSupp]}, {error, not_supported}) when
    NotSupp == statistics_plat orelse
        NotSupp == resumption_ticket
->
    true;
postcondition(_State, {call, quicer, getopt, [_, SetOnly]}, {error, param_error}) when
    SetOnly =:= nst orelse
        SetOnly =:= cibir_id orelse
        SetOnly =:= cacertfile orelse
        SetOnly =:= keyfile orelse
        SetOnly =:= certfile orelse
        SetOnly =:= password orelse
        SetOnly =:= local_interface orelse
        SetOnly =:= tls_secrets orelse
        SetOnly =:= alpn orelse
        SetOnly =:= sslkeylogfile orelse
        SetOnly =:= verify orelse
        SetOnly =:= handshake_idle_timeout_ms orelse
        %% @TODO. unimpl.
        SetOnly =:= version_settings orelse
        %% @TODO. unimpl.
        SetOnly =:= statistics_v2 orelse
        %% @TODO. unimpl.
        SetOnly =:= statistics_v2_plat orelse
        SetOnly =:= quic_event_mask
->
    true;
postcondition(_State, {call, quicer, getopt, [_, SetOnly]}, {error, invalid_parameter}) when
    SetOnly =:= local_interface orelse
        SetOnly =:= peer_certificate_valid
->
    true;
postcondition(_State, {call, quicer, getopt, [_, close_reason_phrase]}, {error, not_found}) ->
    %% @NOTE, msquic returns not_found whne it is not set.
    true;
postcondition(_State, {call, quicer, async_csend, _}, {ok, _}) ->
    %% relaxed check on csend
    true;
postcondition(_State, {call, quicer, async_csend, _Args}, {error, stm_open_error, _}) ->
    true;
postcondition(_State, {call, quicer, async_accept_stream, _Args}, {ok, _}) ->
    true;
postcondition(
    _State, {call, quicer, async_accept_stream, _Args}, {error, stm_open_error, invalid_state}
) ->
    true;
postcondition(_State, {call, quicer, close_connection, _Args}, ok) ->
    true;
postcondition(_State, {call, quicer, shutdown_connection, _Args}, ok) ->
    true;
postcondition(#{state := accepted}, {call, quicer, close_connection, _Args}, {error, timeout}) ->
    true;
postcondition(#{state := accepted}, {call, quicer, shutdown_connection, _Args}, {error, timeout}) ->
    true;
postcondition(#{state := accepted}, {call, quicer, close_connection, _Args}, {error, closed}) ->
    true;
postcondition(#{state := closed}, {call, quicer, close_connection, _Args}, {error, timeout}) ->
    true;
postcondition(_, {call, quicer, shutdown_connection, [_, _, Tout]}, {error, timeout}) when
    Tout < 200
->
    true;
postcondition(_, {call, quicer, close_connection, [_, Tout]}, {error, timeout}) when
    Tout < 200
->
    true;
postcondition(#{state := accepted}, {call, quicer, shutdown_connection, _Args}, {error, closed}) ->
    true;
postcondition(
    #{me := Me, owner := Owner, state := State},
    {call, quicer, shutdown_connection, _Args},
    {error, timeout}
) when Me =/= Owner orelse State == closed ->
    true;
postcondition(
    #{me := Me, owner := Owner, state := State},
    {call, quicer, close_connection, [_]},
    {error, timeout}
) when Me =/= Owner orelse State == closed ->
    true;
postcondition(
    #{state := S}, {call, quicer, negotiated_protocol, [_]}, {error, invalid_parameter}
) when
    S =:= accepted orelse S =:= closed
->
    true;
postcondition(
    #{state := accepted}, {call, quicer, async_csend, [_]}, {error, stm_send_error, aborted}
) ->
    true;
postcondition(#{state := accepted}, {call, quicer, async_csend, [_]}, {error, timeout}) ->
    %% @FIXME https://github.com/emqx/quic/issues/265
    true;
postcondition(_State, {call, quicer, negotiated_protocol, [_]}, {ok, <<"prop">>}) ->
    true;
postcondition(_State, {call, quicer, peername, [_]}, {ok, {_, _}}) ->
    true;
postcondition(_State, {call, quicer, peercert, [_]}, {error, no_peercert}) ->
    true;
postcondition(_State, {call, quicer, controlling_process, [_, _]}, ok) ->
    true;
postcondition(#{me := Me, owner := Other}, {call, quicer, _, _}, {error, timeout}) when
    Me =/= Other
->
    %% @FIXME if owner is changed, some API get {error, timeout}
    true;
postcondition(_State, {call, quicer, get_conn_owner, _}, {ok, Pid}) when is_pid(Pid) ->
    true;
postcondition(
    #{owner := Owner, state := _S},
    {call, quicer, controlling_process, [_, _]},
    {error, not_owner}
) ->
    Owner =/= self();
postcondition(
    #{owner := _, state := _S},
    {call, quicer, controlling_process, [_, NewOwner]},
    {error, owner_dead}
) ->
    is_pid(NewOwner);
%% postcondition(#{owner := Owner, state := closed} = State, {call, quicer, controlling_process, [_, _]}, {error, not_owner}) ->
%%     true;
postcondition(#{handle := _H, state := _S}, {call, quicer, get_connections, _}, Conns) when
    is_list(Conns)
->
    %% @TODO check why handle is not member
    % lists:member(H, Conns);
    true;
postcondition(#{state := closed}, {call, _Mod, _Fun, _Args}, {error, closed}) ->
    true;
postcondition(#{state := accepted}, {call, _Mod, _Fun, _Args}, {error, closed}) ->
    %% handshake didnt take place on time
    true;
postcondition(_State, {call, _Mod, _Fun, _Args} = _Call, _Res) ->
    false.

%% @doc Assuming the postcondition for a call was true, update the model
%% accordingly for the test to proceed.
next_state(State, Res, Call) ->
    step_calls(do_next_state(State, Res, Call)).

do_next_state(#{state := _} = State, {error, closed}, {call, quicer, _, _Args}) ->
    State#{state := closed};
do_next_state(#{state := accepted} = State, {error, _}, {call, quicer, handshake, _Args}) ->
    State;
do_next_state(#{state := accepted} = State, _Res, {call, quicer, handshake, _Args}) ->
    State#{state := connected};
do_next_state(#{state := accepted} = State, _Res, {call, quicer, close_connection, _Args}) ->
    State#{state := closed};
do_next_state(#{state := accepted} = State, _Res, {call, quicer, shutdown_connection, _Args}) ->
    State#{state := closed};
do_next_state(#{state := connected} = State, _Res, {call, quicer, close_connection, _Args}) ->
    State#{state := closed};
do_next_state(#{state := connected} = State, _Res, {call, quicer, shutdown_connection, _Args}) ->
    State#{state := closed};
do_next_state(
    #{state := _} = State, ok, {call, quicer, controlling_process, [_, Owner]}
) ->
    State#{owner := Owner};
do_next_state(State, _Res, {call, _Mod, _Fun, _Args}) ->
    State.

step_calls(#{calls := Calls} = S) ->
    S#{calls := Calls + 1}.
%%% Generators

%%%%%%%%%%%%%%%%%%%%%%%
%%% Listener helper %%%
%%%%%%%%%%%%%%%%%%%%%%%
listener_start_link(ListenerName) ->
    application:ensure_all_started(quicer),
    LPort = 14568,
    ListenerOpts = default_listen_opts(),
    ConnectionOpts = [
        {conn_callback, example_server_connection},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, example_server_stream}
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    quicer:spawn_listener(ListenerName, LPort, Options).

%% OS picks the available port
select_port() ->
    {ok, S} = gen_udp:open(0, [{reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(S),
    gen_udp:close(S),
    Port.

default_listen_opts() ->
    [
        {conn_acceptors, 32},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"},
        {alpn, ["prop"]},
        {verify, none},
        {idle_timeout_ms, 0},
        %% reduce execution time,
        {handshake_idle_timeout_ms, 100},
        % QUIC_SERVER_RESUME_AND_ZERORTT
        {server_resumption_level, 2},
        {peer_bidi_stream_count, 10}
    ].

default_conn_opts() ->
    [
        {alpn, ["prop"]},
        %% {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
        {verify, none},
        {idle_timeout_ms, 5000},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].
