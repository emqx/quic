%%--------------------------------------------------------------------
%% Copyright (c) 2022 EMQ Technologies Co., Ltd. All Rights Reserved.
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

init_handoff(Stream, StreamOpts, Conn, #{flags := Flags}) ->
    InitState = #{ stream => Stream
                 , conn => Conn
                 , is_local => false
                 , is_unidir => quicer:is_unidirectional(Flags)
                 },
    ct:pal("init_handoff ~p", [{InitState, StreamOpts}]),
    {ok, InitState}.

new_stream(Stream, #{flags := Flags}, Conn) ->
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
    ct:pal("~p : stream send is complete", [?FUNCTION_NAME]),
    {ok, S}.

start_completed(_Stream, #{status := success, stream_id := StreamId}, S) ->
    {ok, S#{stream_id => StreamId}};
start_completed(_Stream, #{status := Other }, S) ->
    %% or we could retry
    {stop, {start_fail, Other}, S}.

handle_stream_data(Stream, <<"flow_control.enable_bidi">> = Bin, _Flags, #{is_unidir := true, conn := Conn} = State) ->
    ?tp(debug, #{stream => Stream, data => Bin, module => ?MODULE, dir => unidir}),
    ok = quicer:setopt(Conn, param_conn_settings, #{peer_bidi_stream_count => 2}),
    {ok, State};
handle_stream_data(Stream, Bin, _Flags, #{is_unidir := false} = State) ->
    %% for bidir stream, we just echo in place.
    ?tp(debug, #{stream => Stream, data => Bin, module => ?MODULE, dir => bidir}),
    ct:pal("Server recv: ~p from ~p", [Bin, Stream] ),
    {ok, _} = quicer:send(Stream, Bin),
    {ok, State};
handle_stream_data(Stream, Bin, _Flags, #{is_unidir := true, conn := Conn} = State) ->
    ?tp(debug, #{stream => Stream, data => Bin, module => ?MODULE, dir => unidir}),
    ct:pal("Server recv: ~p from ~p", [Bin, Stream] ),
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
    {error, not_impl, S}.

stream_closed(_Stream, #{ is_conn_shutdown := IsConnShutdown
                        , is_app_closing := IsAppClosing
                        , is_shutdown_by_app := IsAppShutdown
                        , is_closed_remotely := IsRemote
                        , status := Status
                        , error := Code
                        }, S) when is_boolean(IsConnShutdown) andalso
                                   is_boolean(IsAppClosing) andalso
                                   is_boolean(IsAppShutdown) andalso
                                   is_boolean(IsRemote) andalso
                                   is_atom(Status) andalso
                                   is_integer(Code) ->
    {stop, normal, S}.
