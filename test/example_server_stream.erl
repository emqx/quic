-module(example_server_stream).

-behavior(quicer_stream).

-export([ init_handoff/4
        , new_stream/3
        , start_completed/3
        , send_complete/3
        , peer_send_shutdown/3
        , peer_send_aborted/3
        , peer_receive_aborted/3
        , send_shutdown_complete/3
        , stream_closed/3
        , peer_accepted/3
        , passive/3
        , handle_call/4
        ]).

-export([handle_stream_data/4]).

-include("quicer.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").

init_handoff(Stream, StreamOpts, Conn, Flags) ->
    InitState = #{ stream => Stream
                 , conn => Conn
                 , is_local => false
                 , is_unidir => quicer:is_unidirectional(Flags)
                 },
    ct:pal("init_handoff ~p", [{InitState, StreamOpts}]),
    {ok, InitState}.

new_stream(Stream, #{open_flags := Flags}, Conn) ->
    InitState = #{ stream => Stream
                  , conn => Conn
                  , is_local => false
                  , is_unidir => quicer:is_unidirectional(Flags)},
    {ok, InitState}.

peer_accepted(_Stream, _Flags, S) ->
    %% we just ignore it
    {ok, S}.

peer_receive_aborted(Stream, ErrorCode, #{is_unidir := false} = S) ->
    %% we abort send with same reason
    quicer:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT, ErrorCode),
    {ok, S};

peer_receive_aborted(Stream, ErrorCode, #{is_unidir := true, is_local := true} = S) ->
    quicer:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT, ErrorCode),
    {ok, S}.

peer_send_aborted(Stream, ErrorCode, #{is_unidir := false} = S) ->
    %% we abort receive with same reason
    quicer:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE, ErrorCode),
    {ok, S};
peer_send_aborted(Stream, ErrorCode, #{is_unidir := true, is_local := false} = S) ->
    quicer:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE, ErrorCode),
    {ok, S}.

peer_send_shutdown(Stream, _Flags, S) ->
    ok = quicer:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0),
    {ok, S}.

send_complete(_Stream, false, S) ->
    {ok, S};
send_complete(_Stream, true = _IsCanceled, S) ->
    ct:pal("~p : send is canceled", [?FUNCTION_NAME]),
    {ok, S}.


send_shutdown_complete(_Stream, _Flags, S) ->
    ct:pal("~p : stream send is happy", [?FUNCTION_NAME]),
    {ok, S}.

start_completed(_Stream, #{status := success, stream_id := StreamId}, S) ->
    {ok, S#{stream_id => StreamId}};
start_completed(_Stream, #{status := Other }, S) ->
    %% or we could retry
    {stop, {start_fail, Other}, S}.

handle_stream_data(Stream, Bin, _Opts, #{is_unidir := false} = State) ->
    %% for bidir stream, we just echo in place.
    ?tp(debug, #{stream => Stream, data => Bin, module => ?MODULE, dir => bidir}),
    {ok, _} = quicer:send(Stream, Bin),
    {ok, State};
handle_stream_data(Stream, Bin, _Opts, #{is_unidir := true, conn := Conn} = State) ->
    ?tp(debug, #{stream => Stream, data => Bin, module => ?MODULE, dir => unidir}),
    {ok, StreamProc} = quicer_stream:start_link(?MODULE, Conn,
                                                [ {open_flag, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}
                                                , {is_local, true}
                                                ]),
    {ok, _} = quicer_stream:send(StreamProc, Bin),
    {ok, State}.

passive(_Stream, undefined, S)->
    ct:fail("Steam go into passive mode"),
    {ok, S}.

handle_call(_Stream, _Request, _Opts, S) ->
    {error, notimpl, S}.

stream_closed(_Stream, _Flags, S) ->
    {stop, normal, S}.
