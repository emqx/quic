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


%% @doc example server connection
%% Function Spec:
%% 1. Spawn a control stream acceptor
%% 2. finish handshake with Peer
%% 3. Close connection when control stream is shutdown/abort/closed.
%% 4. When Peer need more stream, spawn one stream acceptor and then
%%    bump the number of stream with flow control.
%% 5. Terminate only when connection is closed by both endpoints.
%% @end
-module(example_server_connection).

-behavior(quicer_connection).

-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer_types.hrl").

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
        , datagram_state_changed/3
        ]).

init(ConnOpts) when is_list(ConnOpts) ->
    init(maps:from_list(ConnOpts));
init(#{stream_opts := SOpts} = S) when is_list(SOpts) ->
    init(S#{stream_opts := maps:from_list(SOpts)});
init(ConnOpts) when is_map(ConnOpts) ->
    {ok, ConnOpts}.

closed(_Conn, _CloseProp, S) ->
    {stop, normal, S}.

new_conn(Conn, #{version := _Vsn}, #{stream_opts := SOpts} = S) ->
    case quicer_stream:start_link(example_server_stream, Conn, SOpts) of
        {ok, Pid} ->
            ok = quicer:async_handshake(Conn),
            {ok, S#{ conn => Conn
                   , streams => [{Pid, undefined}]}};
        {error, _} = Error ->
            Error
    end.

connected(_Conn, _Flags, S) ->
    {ok, S}.

resumed(Conn, Data, #{resumed_callback := ResumeFun} = S)
  when is_function(ResumeFun) ->
    ResumeFun(Conn, Data, S);
resumed(_Conn, _Data, S) ->
    {ok, S}.

nst_received(_Conn, _Data, S) ->
    {stop, no_nst_for_server, S}.


new_stream(Stream, Flags, #{ conn := Conn, streams := Streams
                           , stream_opts := SOpts} = CBState) ->
    %% Spawn new stream
    case quicer_stream:start_link(example_server_stream, Stream, Conn, SOpts, Flags) of
        {ok, StreamOwner} ->
            case quicer:handoff_stream(Stream, StreamOwner) of
                ok ->
                    {ok, CBState#{ streams := [ {StreamOwner, Stream} | Streams ] }};
                false ->
                    {error, handoff_fail}
            end;
        Other ->
            Other
    end.

shutdown(_Conn, _ErrorCode, S) ->
    {ok, S}.

transport_shutdown(_C, _DownInfo, S) ->
    {ok, S}.

peer_address_changed(_C, _NewAddr, S) ->
    {ok, S}.

local_address_changed(_C, _NewAddr, S) ->
    {ok, S}.

streams_available(_C, {_BidirCnt, _UnidirCnt}, S) ->
    {ok, S}.

peer_needs_streams(C, #{unidi_streams := Current}, S) ->
    ok = quicer:setopt(C, param_conn_settings, #{peer_unidi_stream_count => Current + 1}),
    {ok, S};
peer_needs_streams(C, #{bidi_streams := Current}, S) ->
    ok = quicer:setopt(C, param_conn_settings, #{peer_bidi_stream_count => Current + 1}),
    {ok, S};
%% for https://github.com/microsoft/msquic/issues/3120
peer_needs_streams(_C, undefined, S) ->
    {ok, S}.

datagram_state_changed(_C, _Flags, S) ->
    {ok, S}.
