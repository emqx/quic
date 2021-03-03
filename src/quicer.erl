%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(quicer).

-export([ listen/2
        , close_listener/1
        , connect/4
        , accept/3
        , close_connection/1
        , accept_stream/2
        , start_stream/2
        , send/2
        , close_stream/1
        ]).

-on_load(init/0).

-type listener_handler() :: reference().
-type connection_handler() :: reference().
-type stream_handler() :: reference().

-spec listen(inet:port_number(), proplists:proplists() | map()) ->
        {ok, listener_handler()} | {error, any()}.
listen(Port, Opts) when is_list(Opts)->
  listen(Port, maps:from_list(Opts));
listen(Port, Opts) when is_map(Opts)->
  quicer_nif:listen(Port, Opts).

-spec close_listener(listener_handler()) -> ok.
close_listener(Listener) ->
  quicer_nif:close_listener(Listener).

-spec connect(inet:hostname(), inet:port_number(), proplists:proplists(), timeout()) ->
        {ok, connection_handler()} | {error, any()}.
connect(Host, Port, Opts, _Timeout) ->
  case quicer_nif:async_connect(Host, Port, Opts) of
    {ok, _H} ->
      receive
        {quic, connected, Ctx} ->
          {ok, Ctx}
      end;
    {error, _} = Err ->
      Err
  end.

-spec accept(listener_handler(), proplists:proplists(), timeout()) ->
        {ok, connection_handler()} | {error, any()}.
accept(LSock, Opts, Timeout) ->
  % non-blocking
  {ok, LSock} = quicer_nif:async_accept(LSock, Opts),
  receive
    {new_conn, C} ->
      {ok, C}
  after Timeout ->
    {error, timeout}
  end.

-spec close_connection(connection_handler()) -> ok.
close_connection(Conn) ->
  quicer_nif:close_connection(Conn).

-spec accept_stream(connection_handler(), proplists:proplist()) ->
        {ok, stream_handler()} | {error, any()}.
accept_stream(Conn, Opts) ->
  % @todo msg ref hack
  % @todo error handling
  case quicer_nif:async_accept_stream(Conn, Opts) of
    {ok, Conn} ->
      receive
        {quic, new_stream, Stream} ->
          {ok, Stream}
      end;
    {error, _} = E->
      E
  end.

-spec start_stream(connection_handler(), proplists:proplists()) ->
        {ok, stream_handler()} | {error, any()}.
start_stream(Conn, Opts) ->
  quicer_nif:start_stream(Conn, Opts).

-spec send(stream_handler(), Data :: binary()) ->
        {ok, Len :: integer()} | {error, any()}.
send(Stream, Data) ->
  quicer_nif:send(Stream, Data).

-spec close_stream(stream_handler()) -> ok.
close_stream(Stream) ->
  quicer_nif:close_stream(Stream).

init() ->
  quicer_nif:open_lib(),
  quicer_nif:reg_open().

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
