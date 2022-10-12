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

-module(example_client_connection).

-behavior(quicer_connection).

-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer_types.hrl").

%% API
-export([start_link/3]).

%% Callback init
-export([ init/1 ]).

%% Connection Callbacks
-export([ new_conn/3
        , connected/3
        , transport_shutdown/3
        , shutdown/3
        , closed/3
        , local_address_changed/3
        , peer_address_changed/3
        , streams_available/3
        , peer_needs_streams/3
        , resumed/3
        , nst_received/3
        , new_stream/3
        ]).

start_link(Host, Port, {_COpts, _SOpts} = Opts)->
    quicer_connection:start_link(?MODULE, {Host, Port}, Opts).

init(ConnOpts) when is_list(ConnOpts) ->
    init(maps:from_list(ConnOpts));
init(#{stream_opts := SOpts} = S) when is_list(SOpts) ->
    init(S#{stream_opts := maps:from_list(SOpts)});
init(#{conn := Conn, stream_opts := SOpts} = ConnOpts) when is_map(ConnOpts) ->
    %% for accepting
    {ok, Stream2} = quicer_stream:start_link(example_client_stream, Conn, SOpts#{is_local => false}),
    %% for sending unidi_streams
    {ok, Stream1} = quicer_stream:start_link(example_client_stream, Conn,
                                             SOpts#{ is_local => true
                                                   , open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL
                                                   }),
    {ok,_} = quicer_stream:send(Stream1, <<"ping_from_example">>, ?QUICER_SEND_FLAG_SYNC bor ?QUIC_SEND_FLAG_FIN),
    {ok, ConnOpts#{stream_pids => #{send_stream => Stream1, recv_stream => Stream2}}}.

closed(_Conn, #{is_peer_acked := true}, S)->
    {stop, normal, S};
closed(_Conn, #{is_peer_acked := false}, S)->
    {stop, abnorml, S}.

new_conn(_Conn, #{version := _Vsn}, #{stream_opts := _SOpts} = S) ->
    %% I am client not server.
    {stop, internal_error, S}.

connected(Conn, Flags, #{conn := Conn} = S) ->
    ?tp(debug, #{module => ?MODULE, conn => Conn, flags => Flags, event => connected}),
    ct:pal("~p connected and expecting NST within 100ms", [?MODULE]),
    {100, maps:merge(S, Flags)}.

resumed(Conn, Data, #{resumed_callback := ResumeFun} = S)
  when is_function(ResumeFun) ->
    ResumeFun(Conn, Data, S);
resumed(_Conn, _Data, S) ->
    {ok, S}.

nst_received(_Conn, Data, S) ->
    {ok, S#{nst => Data}}.

new_stream(Stream, Flags, #{ conn := Conn, streams := Streams
                           , stream_opts := SOpts} = CBState) ->
    %% Spawn new stream
    case quicer_stream:start_link(example_server_stream, Stream, Conn, SOpts, Flags) of
        {ok, StreamOwner} ->
            quicer_connection:handoff_stream(Stream, StreamOwner),
            {ok, CBState#{ streams := [ {StreamOwner, Stream} | Streams] }};
        Other ->
            Other
    end.

shutdown(_Conn, _ErrorCode, S) ->
    {ok, S}.

transport_shutdown(_C, _Reason, S) ->
    {ok, S}.

peer_address_changed(_C, _NewAddr, S) ->
    {ok, S}.

local_address_changed(_C, _NewAddr, S) ->
    {ok, S}.

streams_available(_C, {_BidirCnt, _UnidirCnt}, S) ->
    {hibernate, S}.

peer_needs_streams(C, #{unidi_streams := Current}, S) ->
    ok = quicer:setopt(C, param_conn_settings, #{peer_unidi_stream_count => Current + 1}),
    {ok, S};
peer_needs_streams(C, #{bidi_streams := Current}, S) ->
    ok = quicer:setopt(C, param_conn_settings, #{peer_bidi_stream_count => Current + 1}),
    {ok, S};
%% for https://github.com/microsoft/msquic/issues/3120
peer_needs_streams(_C, undefined, S) ->
    {ok, S}.
