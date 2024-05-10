-module(prop_stateful_stream).
-compile([export_all]).
-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").
-include("prop_quic_types.hrl").

%% Test APIs:
%% - async accept stream
%% - start stream
%% - send
%% - recv
%% - shutdown_stream
%% - close_stream
%% - setopt
%% - getopt

%% Model Callbacks
-export([
    command/1,
    initial_state/0,
    next_state/3,
    precondition/2,
    postcondition/3
]).

-define(MAX_STREAMS, 64 * 1024 - 1).

%%%%%%%%%%%%%%%%%%
%%% PROPERTIES %%%
%%%%%%%%%%%%%%%%%%
prop_stateful_client_stream_test(opts) ->
    [{numtests, 2000}].
prop_stateful_client_stream_test() ->
    process_flag(trap_exit, true),
    ?SETUP(
        fun() ->
            {ok, _} = listener_start_link(?MODULE),
            fun() -> listener_stop(?MODULE) end
        end,
        ?FORALL(
            Cmds,
            commands(?MODULE),
            begin
                flush_quic_msgs(),
                {ok, H} = quicer:connect("localhost", 14569, default_conn_opts(), 10000),
                {History, State, Result} = run_commands(?MODULE, Cmds, [{conn_handle, H}]),
                quicer:async_shutdown_connection(H, ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0),
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

prop_stateful_server_stream_test(opts) ->
    [{numtests, 2000}].
prop_stateful_server_stream_test() ->
    Port = 14570,
    process_flag(trap_exit, true),
    ?SETUP(
        fun() ->
            {ok, L} = quicer:listen(Port, default_listen_opts()),
            put(?FUNCTION_NAME, L),
            fun() -> quicer:stop_listener(L) end
        end,
        ?FORALL(
            Cmds,
            commands(?MODULE),
            begin
                flush_quic_msgs(),
                L = get(?FUNCTION_NAME),
                {ok, L} = quicer:async_accept(L, maps:from_list([{active, false}])),
                {ok, Client} = example_client_connection:start_link(
                    "localhost",
                    Port,
                    {default_conn_opts(), quicer_test_lib:default_stream_opts()}
                ),
                Conn =
                    receive
                        {quic, new_conn, C, _} ->
                            case quicer:handshake(C) of
                                {ok, C} -> C;
                                Err -> error({quicer:get_conn_rid(C), Err})
                            end
                    after 3000 ->
                        %% hard to reproduce here
                        error(new_conn_timeout)
                    end,
                {History, State, Result} = run_commands(?MODULE, Cmds, [
                    {conn_handle, Conn}
                ]),
                quicer:async_shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0),
                catch gen_server:stop(Client),
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
    #{
        conn_state => connected,
        stream_set => [],
        owner => self(),
        me => self(),
        % cnt calls
        calls => 1
    }.

%% @doc List of possible commands to run against the system
command(#{stream_set := SS}) ->
    C = {var, conn_handle},
    oneof([
        {call, quicer, start_stream, [
            C,
            ?LET(
                Opts,
                quicer_stream_opts(),
                Opts ++ [{open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}]
            )
        ]},
        {call, quicer, start_stream, [C, ?LET(Opts, quicer_stream_opts(), Opts)]},
        {call, quicer, async_accept_stream, [C, ?LET(Opt, stream_accept_opts(), Opt)]},
        {call, quicer, async_send, [random_stream(SS), binary()]},
        {call, quicer, async_send, [remote_stream(SS), binary()]},
        {call, ?MODULE, send_recv, [random_stream(SS), binary()]},
        {call, quicer, async_shutdown_stream, [random_stream(SS)]},
        {call, quicer, async_close_stream, [random_stream(SS)]},
        {call, ?MODULE, getopt, [random_stream(SS)]},
        {call, ?MODULE, setopt, [random_stream(SS)]},
        {call, ?MODULE, close_remote_stream, []},
        {call, ?MODULE, stop_client_user, [SS]},
        %% @TODO mix with close_connection
        %{call, quicer, close_connection, [C]},
        {call, quicer, send, [random_stream(SS), binary()]}
    ]).

%% @doc Determines whether a command should be valid under the
%% current state.
precondition(#{conn_state := closed}, {call, _, _, _}) ->
    false;
precondition(#{stream_set := []}, {call, ?MODULE, getopt, _}) ->
    false;
precondition(#{stream_set := []}, {call, ?MODULE, setopt, _}) ->
    false;
precondition(#{stream_set := []}, {call, ?MODULE, send_recv, _}) ->
    false;
precondition(#{stream_set := []}, {call, quicer, Act, _}) when
    Act =/= start_stream andalso
        Act =/= async_accept_stream
->
    false;
precondition(SS, {call, ?MODULE, stop_client_user, _}) ->
    maps:is_key(client_user, SS);
precondition(_State, {call, _Mod, _Fun, _Args}) ->
    true.

%% @doc Given the state `State' *prior* to the call
%% `{call, Mod, Fun, Args}', determine whether the result
%% `Res' (coming from the actual system) makes sense.
postcondition(#{conn_state := closed}, {call, quicer, _, _}, {error, _}) ->
    true;
%% postcondition(_State, {call, quicer, start_stream, _Args}, {error, _} = E) ->
%%     false;
postcondition(_State, {call, quicer, send, [_, <<>>]}, {error, _}) ->
    %% send empty binary results badarg
    true;
postcondition(_State, {call, quicer, send, [_, _]}, {error, E}) when
    E == closed orelse E == cancelled
->
    %% async shutdowned stream
    true;
postcondition(_State, {call, quicer, send, [closed, _]}, {error, badarg}) ->
    true;
postcondition(_State, {call, quicer, send, [stm_open_error, _]}, {error, badarg}) ->
    true;
postcondition(_State, {call, quicer, send, _Args}, {error, _}) ->
    false;
postcondition(_State, {call, _Mod, _Fun, _Args}, _Res) ->
    true.

%% @doc Assuming the postcondition for a call was true, update the model
%% accordingly for the test to proceed.
next_state(#{calls := C} = State, {error, _, _}, {call, quicer, start_stream, _Args}) ->
    State#{calls := C + 1};
next_state(#{stream_set := SS, calls := C} = State, V, {call, quicer, start_stream, _Args}) ->
    State#{stream_set := [{call, erlang, element, [2, V]} | SS], calls := C + 1};
next_state(
    #{stream_set := SS, calls := C} = State, _V, {call, quicer, async_shutdown_stream, [Stream]}
) ->
    State#{stream_set := lists:delete(Stream, SS), calls := C + 1};
next_state(#{calls := C} = State, _V, {call, quicer, close_connection, _Args}) ->
    State#{calls := C + 1, conn_state := closed};
next_state(#{calls := C} = State, _Res, {call, _Mod, _Fun, _Args}) ->
    NewState = State,
    NewState#{calls := C + 1}.

%%% helpers
send_recv(Stream, Binary) ->
    case quicer:send(Stream, Binary) of
        ok ->
            quicer:recv(Stream, byte_size(Binary));
        E ->
            E
    end.

unblock_streams(Conn) ->
    receive
        {quic, peer_needs_streams, Conn, unidi_streams} ->
            {ok, Current} = quicer:getopt(Conn, local_unidi_stream_count),
            ok = quicer:setopt(Conn, settings, #{peer_unidi_stream_count => Current + 10});
        {quic, peer_needs_streams, Conn, bidi_streams} ->
            {ok, Current} = quicer:getopt(Conn, local_bidi_stream_count),
            ok = quicer:setopt(Conn, settings, #{peer_bidi_stream_count => Current + 10})
    after 0 ->
        ok
    end.

setopt(SS) ->
    {K, V} = ?LET(Opt, stream_opt(), Opt),
    quicer:setopt(random_stream(SS), K, V, stream).

getopt(SS) ->
    quicer:setopt(random_stream(SS), ?LET({K, _V}, stream_opt(), K), stream).

close_remote_stream() ->
    receive
        {new_stream, Stream, _, _} ->
            quicer:close_stream(
                Stream,
                ?LET(FLAG, stream_shutdown_flags(), FLAG),
                ?LET(Err, app_errno(), Err)
            )
    after 0 ->
        ok
    end.

remote_stream(_) ->
    receive
        {new_stream, Stream, _, _} ->
            quicer:async_send(Stream, binary())
    after 0 ->
        ok
    end.

stop_client_user(#{client_user := Pid}) ->
    Pid ! stop.

flush_quic_msgs() ->
    receive
        {quic, _, _, _} ->
            flush_quic_msgs()
    after 0 ->
        ok
    end.

%%%%%%%%%%%%%%%%%%%%%%%
%%% Listener helper %%%
%%%%%%%%%%%%%%%%%%%%%%%
listener_start_link(ListenerName) ->
    application:ensure_all_started(quicer),
    LPort = 14569,
    ListenerOpts = default_listen_opts(),
    ConnectionOpts = [
        {conn_callback, example_server_connection},
        {stream_acceptors, 32}
        | default_conn_opts()
    ],
    StreamOpts = [
        {stream_callback, example_server_stream},
        {auto_unblock_stream, true}
    ],
    Options = {ListenerOpts, ConnectionOpts, StreamOpts},
    quicer:spawn_listener(ListenerName, LPort, Options).

listener_stop(ListenerName) ->
    quicer:terminate_listener(ListenerName).

random_stream([H | _]) when is_tuple(H) ->
    %% For Exec
    H;
random_stream(SS) ->
    %% For symbolic
    {call, erlang, hd, [SS]}.

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
        {peer_bidi_stream_count, ?MAX_STREAMS},
        {peer_unidi_stream_count, ?MAX_STREAMS}
    ].

default_conn_opts() ->
    [
        {alpn, ["prop"]},
        %% , {sslkeylogfile, "/tmp/SSLKEYLOGFILE"}
        {verify, none},
        {idle_timeout_ms, 0},
        {handshake_idle_timeout_ms, 10000},
        {local_bidi_stream_count, ?MAX_STREAMS},
        {local_unidi_stream_count, ?MAX_STREAMS},
        {peer_bidi_stream_count, ?MAX_STREAMS},
        {peer_unidi_stream_count, ?MAX_STREAMS},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].
