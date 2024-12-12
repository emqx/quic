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
-module(prop_stateful_client_conn).
-compile([export_all]).
-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").
-include("prop_quic_types.hrl").

%% Model Callbacks
-export([
    command/1,
    initial_state/0,
    next_state/3,
    precondition/2,
    postcondition/3
]).

%% Helpers
-export([
    spawn_stream_acceptor/3
]).
%%%%%%%%%%%%%%%%%%
%%% PROPERTIES %%%
%%%%%%%%%%%%%%%%%%
prop_client_state_test(opts) ->
    [{numtests, 2000}].
prop_client_state_test() ->
    {ok, _} = listener_start_link(?MODULE),
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
    ).

%%%%%%%%%%%%%
%%% MODEL %%%
%%%%%%%%%%%%%
%% @doc Initial model value at system start. Should be deterministic.
initial_state() ->
    net_kernel:start([?MODULE, shortnames]),
    {ok, H} = quicer:connect("localhost", 14568, default_conn_opts(), 10000),
    #{
        state => connected,
        handle => H,
        owner => self(),
        me => self(),
        % cnt calls
        calls => 0
    }.

%% @doc List of possible commands to run against the system
%%
command(#{handle := Handle}) ->
    frequency([
        {100, {call, quicer, getopt, [Handle, ?LET({Opt, _}, conn_opt(), Opt)]}},
        {100,
            {call, quicer, async_accept_stream, [Handle, ?LET(Opts, quicer_acceptor_opts(), Opts)]}},
        {100,
            {call, ?MODULE, spawn_stream_acceptor, [
                Handle, ?LET(Opts, quicer_acceptor_opts(), Opts), range(0, 200)
            ]}},
        {100, {call, quicer, peername, [Handle]}},
        {50, {call, quicer, peercert, [Handle]}},
        {50, {call, quicer, probe, [Handle, 5000]}},
        {50, {call, quicer, send_dgram, [Handle, binary()]}},
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
        {50, {call, quicer, close_connection, [Handle]}},
        {50,
            {call, quicer, shutdown_connection, [
                Handle, ?valid_flags(conn_shutdown_flag()), ?LET(ErrorCode, uint62(), ErrorCode)
            ]}}
    ]).

%% @doc Determines whether a command should be valid under the
%% current state.
precondition(#{state := connected}, {call, _Mod, _Fun, _Args}) ->
    true;
precondition(#{state := closed}, {call, _Mod, _Fun, _Args}) ->
    true;
precondition(_State, {call, _Mod, _Fun, _Args}) ->
    false.

%% @doc Given the state `State' *prior* to the call
%% `{call, Mod, Fun, Args}', determine whether the result
%% `Res' (coming from the actual system) makes sense.
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
postcondition(_State, {call, quicer, async_csend, _Args}, {error, stm_open_error, invalid_state}) ->
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
    #{state := closed}, {call, quicer, negotiated_protocol, [_]}, {error, invalid_parameter}
) ->
    true;
postcondition(_State, {call, quicer, negotiated_protocol, [_]}, {ok, <<"prop">>}) ->
    true;
postcondition(_State, {call, quicer, peername, [_]}, {ok, {_, 14568}}) ->
    true;
postcondition(_State, {call, quicer, peercert, [_]}, {error, no_peercert}) ->
    true;
postcondition(_State, {call, quicer, controlling_process, [_, _]}, ok) ->
    true;
postcondition(_State, {call, quicer, get_conn_owner, _}, {ok, Pid}) when is_pid(Pid) ->
    true;
postcondition(
    #{owner := Owner, state := connected},
    {call, quicer, controlling_process, [_, _]},
    {error, not_owner}
) ->
    Owner =/= self();
postcondition(
    #{state := ConnState},
    {call, quicer, probe, [_, _]},
    {error, dgram_send_error, _}
) ->
    ConnState =/= connected;
postcondition(
    #{state := _ConnState},
    {call, quicer, probe, [_, _]},
    #probe_state{final = FinalState, final_at = FinalTs}
) ->
    FinalState =/= undefined andalso FinalTs =/= undefined;
postcondition(
    #{state := _ConnState},
    {call, quicer, send_dgram, [_, _]},
    {ok, _}
) ->
    true;
postcondition(
    #{state := ConnState},
    {call, quicer, send_dgram, [_, _]},
    {error, _, _}
) ->
    ConnState =/= connected;
postcondition(
    #{state := ConnState},
    {call, quicer, send_dgram, [_, _]},
    {error, _}
) ->
    ConnState =/= connected;
postcondition(
    #{owner := _, state := connected},
    {call, quicer, controlling_process, [_, NewOwner]},
    {error, owner_dead}
) ->
    NewOwner =/= self();
%% postcondition(#{owner := Owner, state := closed} = State, {call, quicer, controlling_process, [_, _]}, {error, not_owner}) ->
%%     true;
postcondition(#{handle := H, state := connected}, {call, quicer, get_connections, _}, Conns) ->
    lists:member(H, Conns);
postcondition(#{handle := _H, state := closed}, {call, quicer, get_connections, _}, _Conns) ->
    %% May or may not in Conns deps on the timing
    true;
postcondition(#{state := closed}, {call, _Mod, _Fun, _Args}, {error, closed}) ->
    true;
postcondition(_State, {call, ?MODULE, spawn_stream_acceptor, _Args}, ok) ->
    true;
postcondition(_State, {call, _Mod, _Fun, _Args} = _Call, _Res) ->
    false.

%% @doc Assuming the postcondition for a call was true, update the model
%% accordingly for the test to proceed.
next_state(State, Res, Call) ->
    step_calls(do_next_state(State, Res, Call)).
do_next_state(#{state := connected} = State, _Res, {call, quicer, close_connection, _Args}) ->
    State#{state := closed};
do_next_state(#{state := connected} = State, _Res, {call, quicer, shutdown_connection, _Args}) ->
    State#{state := closed};
do_next_state(
    #{state := connected} = State, ok, {call, quicer, controlling_process, [_, Owner]}
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
        %% some CI runner is slow on this
        {handshake_idle_timeout_ms, 10000},
        % QUIC_SERVER_RESUME_AND_ZERORTT
        {server_resumption_level, 2},
        {peer_bidi_stream_count, 10},
        {datagram_receive_enabled, 1}
    ].

default_conn_opts() ->
    [
        {alpn, ["prop"]},
        %%{sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
        {verify, none},
        {idle_timeout_ms, 0},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"},
        {datagram_receive_enabled, 1}
    ].

%% Test helpers
spawn_stream_acceptor(ConnHandle, Opts, DieAfter) ->
    spawn(
        fun() ->
            do_accept_stream(ConnHandle, Opts, DieAfter)
        end
    ),
    ok.

do_accept_stream(Conn, Opts, DieAfter) ->
    {ok, Conn} = quicer:async_accept_stream(Conn, Opts),
    receive
        {quicer, new_stream, _Stream, _Flags} ->
            timer:sleep(DieAfter)
    after DieAfter ->
        ok
    end.
