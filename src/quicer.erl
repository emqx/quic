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

-include("quicer.hrl").
-include("quicer_types.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").


%% Library APIs
-export([ open_lib/0
        , close_lib/0
        , reg_open/0
        , reg_close/0
        ]
       ).

%% Traffic APIs
-export([ listen/2
        , close_listener/1
        , connect/4
        , handshake/1
        , handshake/2
        , async_handshake/1
        , accept/2
        , accept/3
        , async_accept/2
        , close_connection/1
        , close_connection/2
        , close_connection/3
        , close_connection/4
        , async_close_connection/1
        , async_close_connection/3
        , accept_stream/2
        , accept_stream/3
        , async_accept_stream/2
        , start_stream/2
        , send/2
        , async_send/2
        , recv/2
        , send_dgram/2
        , close_stream/1
        , close_stream/2
        , close_stream/4
        , async_close_stream/1
        , async_close_stream/3
        , sockname/1
        , getopt/2
        , getopt/3
        , setopt/3
        , get_stream_id/1
        , getstat/2
        , peername/1
        , listeners/0
        , listener/1
        , controlling_process/2
        ]).

%% Exports for test
-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

-export([ start_listener/3 %% start application over quic
        , stop_listener/1
        ]).

-type connection_opts() :: proplists:proplist() | quicer_conn_acceptor:opts().
-type listener_opts() :: proplists:proplist() | quicer_listener:listener_opts().

-spec open_lib() ->
        {ok, true}  | %% opened
        {ok, false} | %% already opened
        {ok, debug} | %% opened with lttng debug library loaded (if present)
        {error, open_failed, atom_reason()}.
open_lib() ->
  quicer_nif:open_lib().

-spec close_lib() -> ok.
close_lib() ->
  quicer_nif:close_lib().

-spec reg_open() -> ok.
reg_open() ->
  quicer_nif:reg_open().

-spec reg_close() -> ok.
reg_close() ->
  quicer_nif:reg_close().

-spec start_listener(Appname :: atom(), listen_on(),
                     {listener_opts(), connection_opts(), stream_opts()}) ->
        {ok, pid()} | {error, any()}.
start_listener(AppName, Port, Options) ->
  quicer_listener:start_listener(AppName, Port, Options).

-spec stop_listener(atom()) -> ok.
stop_listener(AppName) ->
  quicer_listener:stop_listener(AppName).

-spec listen(listen_on(), listen_opts()) ->
        {ok, listener_handler()} |
        {error, listener_open_error,  atom_reason()} |
        {error, listener_start_error, atom_reason()}.
listen(ListenOn, Opts) when is_list(Opts) ->
  listen(ListenOn, maps:from_list(Opts));
listen(ListenOn, Opts) when is_map(Opts) ->
  quicer_nif:listen(ListenOn, Opts).

-spec close_listener(listener_handler()) -> ok.
close_listener(Listener) ->
  quicer_nif:close_listener(Listener).

-spec connect(inet:hostname() | inet:ip_address(),
              inet:port_number(), conn_opts(), timeout()) ->
          {ok, connection_handler()} |
          {error, conn_open_error | config_error | conn_start_error} |
          {error, timeout}.
connect(Host, Port, Opts, Timeout) when is_list(Opts) ->
  connect(Host, Port, maps:from_list(Opts), Timeout);
connect(Host, Port, Opts, Timeout) when is_tuple(Host) ->
  connect(inet:ntoa(Host), Port, Opts, Timeout);
connect(Host, Port, Opts, Timeout) when is_map(Opts) ->
  NewOpts = maps:merge(default_conn_opts(), Opts),
  case quicer_nif:async_connect(Host, Port, NewOpts) of
    {ok, H} ->
      receive
        {quic, connected, Ctx} ->
          {ok, Ctx};
        {quic, transport_shutdown, _, Reason} ->
          {error, transport_down, Reason}
      after Timeout ->
          %% @TODO caller should provide the method to handle timeout
          async_close_connection(H, ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0),
          {error, timeout}
      end;
    {error, _} = Err ->
      Err
  end.

-spec handshake(connection_handler()) -> ok | {error, any()}.
handshake(Conn) ->
  handshake(Conn, 1000).

-spec handshake(connection_handler(), timer:timeout()) -> ok | {error, any()}.
handshake(Conn, Timeout) ->
  case async_handshake(Conn) of
    {error, _} = E -> E;
    ok ->
      receive
        {quic, connected, C} -> {ok, C}
      after Timeout ->
          {error, timeout}
      end
  end.

-spec async_handshake(connection_handler()) -> ok | {error, any()}.
async_handshake(Conn) ->
  quicer_nif:async_handshake(Conn).

-spec accept(listener_handler(), acceptor_opts()) ->
        {ok, connection_handler()} | {error, any()}.
accept(LSock, Opts) ->
  accept(LSock, Opts, infinity).

-spec accept(listener_handler(), acceptor_opts(), timer:timeout()) ->
        {ok, connection_handler()} |
        {error, badarg | param_error | not_enough_mem | badpid} |
        {error, timeout}.
accept(LSock, Opts, Timeout) when is_list(Opts) ->
  accept(LSock, maps:from_list(Opts), Timeout);
accept(LSock, Opts, Timeout) ->
  % non-blocking
  {ok, LSock} = quicer_nif:async_accept(LSock, Opts),
  receive
    {quic, new_conn, C} ->
      {ok, C};
    {quic, connected, C} ->
      {ok, C}
  after Timeout ->
    {error, timeout}
  end.

-spec async_accept(listener_handler(), acceptor_opts()) ->
        {ok, listener_handler()} |
        {error, badarg | param_error | not_enough_mem | badpid}.
async_accept(Listener, Opts) ->
  NewOpts = maps:merge(default_conn_opts(), Opts),
  quicer_nif:async_accept(Listener, NewOpts).

-spec close_connection(connection_handler()) -> ok.
close_connection(Conn) ->
  close_connection(Conn, 5000).

-spec close_connection(connection_handler(), timer:timeout()) -> ok.
close_connection(Conn, Timeout) ->
  close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, Timeout).

-spec close_connection(connection_handler(),
                       conn_close_flag(),
                       app_errno()
                      ) -> ok.
close_connection(Conn, Flags, ErrorCode) ->
  close_connection(Conn, Flags, ErrorCode, 5000).

-spec close_connection(connection_handler(),
                       conn_close_flag(),
                       app_errno(),
                       timer:timeout()) -> ok.
close_connection(Conn, Flags, ErrorCode, Timeout) ->
  ok = async_close_connection(Conn, Flags, ErrorCode),
  %% @todo make_ref
  receive
    {quic, closed, Conn} ->
      ok
  after Timeout ->
      {error, timeout}
  end.

-spec async_close_connection(connection_handler()) -> ok.
async_close_connection(Conn) ->
  quicer_nif:async_close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0).

-spec async_close_connection(connection_handler(),
                             conn_close_flag(),
                             app_errno()) -> ok.
async_close_connection(Conn, Flags, ErrorCode) ->
  quicer_nif:async_close_connection(Conn, Flags, ErrorCode).

-spec accept_stream(connection_handler(), stream_opts()) ->
        {ok, stream_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {erro, timeout}.
accept_stream(Conn, Opts) ->
  accept_stream(Conn, Opts, infinity).

-spec accept_stream(connection_handler(), stream_opts(), timeout()) ->
        {ok, stream_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {erro, timeout}.
accept_stream(Conn, Opts, Timeout) when is_list(Opts) ->
  accept_stream(Conn, maps:from_list(Opts), Timeout);
accept_stream(Conn, Opts, Timeout) when is_map(Opts) ->
  % @todo make_ref
  % @todo error handling
  NewOpts = maps:merge(default_stream_opts(), Opts),
  case quicer_nif:async_accept_stream(Conn, NewOpts) of
    {ok, Conn} ->
      receive
        {quic, new_stream, Stream} ->
          {ok, Stream}
      after Timeout ->
          {error, timeout}
      end;
    {error, _} = E ->
      E
  end.

-spec async_accept_stream(connection_handler(), proplists:proplist() | map()) ->
        {ok, connection_handler()} | {error, any()}.
async_accept_stream(Conn, Opts) when is_list(Opts) ->
  async_accept_stream(Conn, maps:from_list(Opts));
async_accept_stream(Conn, Opts) when is_map(Opts) ->
  quicer_nif:async_accept_stream(Conn, maps:merge(default_stream_opts(), Opts)).

-spec start_stream(connection_handler(), stream_opts()) ->
        {ok, stream_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {error, stream_open_error, atom_reason()} |
        {error, stream_start_error, atom_reason()}.
start_stream(Conn, Opts) when is_list(Opts) ->
  start_stream(Conn, maps:from_list(Opts));
start_stream(Conn, Opts) when is_map(Opts) ->
  quicer_nif:start_stream(Conn, maps:merge(default_stream_opts(), Opts)).


-spec send(stream_handler(), iodata()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(Stream, Data) ->
  case quicer_nif:send(Stream, Data, _IsSync = 1) of
    %% @todo make ref
    {ok, _Len} = OK ->
      receive
        {quic, send_completed, Stream, _} ->
          OK
      end;
    E ->
      E
  end.

-spec async_send(stream_handler(), iodata()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
async_send(Stream, Data) ->
  quicer_nif:send(Stream, Data, _IsSync = 0).

-spec recv(stream_handler(), Count::non_neg_integer())
          -> {ok, binary()} | {error, any()}.
recv(Stream, Count) ->
  case quicer:getopt(Stream, param_conn_settings, false) of
  {ok, Settings} ->
      case proplists:get_value(stream_recv_window_default, Settings, 0) of
        X when X < Count ->
          {error, stream_recv_window_too_small};
        _ ->
          do_recv(Stream, Count)
      end;
  {error, _} = Error ->
      Error
  end.

do_recv(Stream, Count) ->
  case quicer_nif:recv(Stream, Count) of
    {ok, not_ready} ->
      %% Data is not ready yet but last call has been reg.
      receive
        %% @todo recv_mark
        {quic, Stream, continue} ->
          recv(Stream, Count)
      end;
    {ok, Bin} ->
      {ok, Bin};
    {error, _} = E ->
      E
   end.

-spec send_dgram(connection_handler(), binary()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, dgram_send_error, atom_reason()}.
send_dgram(Conn, Data) ->
  case quicer_nif:send_dgram(Conn, Data, _IsSync = 1) of
    %% @todo make ref
    {ok, _Len} = OK ->
      receive
        {quic, send_dgram_completed, Conn} ->
          OK
      end;
    E ->
      E
  end.

-spec close_stream(stream_handler()) -> ok | {error, any()}.
close_stream(Stream) ->
  close_stream(Stream, infinity).

-spec close_stream(stream_handler(), timer:timeout()) ->
        ok |
        {error, badarg | atom_reason()} |
        {error, timeout}.
close_stream(Stream, Timeout) ->
  close_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0, Timeout).

-spec close_stream(stream_handler(),
                   stream_close_flags(),
                   app_errno(),
                   time:timeout()) ->
        {error, badarg | atom_reason()} |
        {error, timeout}.
close_stream(Stream, Flags, ErrorCode, Timeout) ->
  case async_close_stream(Stream, Flags, ErrorCode) of
    ok ->
      receive
        {quic, closed, Stream, _IsGraceful} ->
          ok
      after Timeout ->
          {error, timeout}
      end;
    Err ->
      Err
  end.

-spec async_close_stream(stream_handler()) ->
        ok |
        {error, badarg | atom_reason()}.
async_close_stream(Stream) ->
  quicer_nif:async_close_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0).

-spec async_close_stream(stream_handler(),
                         stream_close_flags(),
                         app_errno())
                        -> ok | {error, badarg | atom_reason()}.
async_close_stream(Stream, Flags, Reason) ->
  quicer_nif:async_close_stream(Stream, Flags, Reason).

-spec sockname(listener_handler() | connection_handler() | stream_handler()) ->
        {ok, {inet:ip_address(), inet:port_number()}} | {error, any()}.
sockname(Conn) ->
  quicer_nif:sockname(Conn).

-spec getopt(Handle::connection_handler()
                   | stream_handler()
                   | listener_handler(),
             optname()) ->
        {ok, OptVal::any()} | {error, any()}.
getopt(Handle, Opt) ->
  quicer_nif:getopt(Handle, Opt, false).

-spec getopt(handler(), optname(), optlevel()) ->
        not_found | %% `optname' not found, or wrong `optlevel' must be a bug.
        {ok, conn_settings()}   | %% when optname = param_conn_settings
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
getopt(Handle, Opt, Optlevel) ->
  quicer_nif:getopt(Handle, Opt, Optlevel).

-spec setopt(handler(), optname(), any()) ->
        ok |
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
setopt(Handle, param_conn_settings, Value) when is_list(Value) ->
  setopt(Handle, param_conn_settings, maps:from_list(Value));
setopt(Handle, Opt, Value) ->
  quicer_nif:setopt(Handle, Opt, Value, false).

-spec get_stream_id(Stream::stream_handler()) ->
        {ok, integer()} | {error, any()}.
get_stream_id(Stream) ->
  quicer_nif:getopt(Stream, param_stream_id, false).

-spec getstat(connection_handler(), [inet:stat_option()]) ->
        {ok, list()} | {error, any()}.
getstat(Conn, Cnts) ->
  case quicer_nif:getopt(Conn, param_conn_statistics, false) of
    {error, _} = E ->
      E;
    {ok, Res} ->
      CntRes = lists:map(fun(Cnt) ->
                             Key = stats_map(Cnt),
                             V = proplists:get_value(Key, Res, {Key, -1}),
                             {Cnt, V}
                         end, Cnts),
      {ok, CntRes}
  end.

-spec peername(connection_handler()  | stream_handler()) ->
        {ok, {inet:ip_address(), inet:port_number()}} | {error, any()}.
peername(Handle) ->
  quicer_nif:getopt(Handle, param_conn_remote_address, false).

-spec get_conn_rid(connection_handler()) ->
        {ok, non_neg_integer()} | {error, any()}.
get_conn_rid(Conn) ->
  quicer_nif:get_conn_rid(Conn).

-spec get_stream_rid(stream_handler()) ->
        {ok, non_neg_integer()} | {error, any()}.
get_stream_rid(Stream) ->
  quicer_nif:get_stream_rid(Stream).

-spec listeners() -> [{{ quicer_listener:listener_name()
                       , quicer_listener:listen_on()},
                       pid()}].
listeners() ->
  quicer_listener_sup:listeners().

-spec listener(quicer_listener:listener_name()
              | {quicer_listener:listener_name(),
                 quicer_listener:listen_on()}) -> pid().
listener(Name) ->
  quicer_listener_sup:listener(Name).

-spec controlling_process(connection_handler() | stream_handler(), pid()) ->
        ok |
        {error, closed | badarg | owner_dead | not_owner}.
controlling_process(Handler, Pid) ->
  quicer_nif:controlling_process(Handler, Pid).

%%% Internal helpers
stats_map(recv_cnt) ->
  "Recv.TotalPackets";
stats_map(recv_oct) ->
  "Recv.TotalBytes";
stats_map(send_cnt) ->
  "Send.TotalPackets";
stats_map(send_oct) ->
  "Send.TotalBytes";
stats_map(send_pend) ->
  "Send.CongestionCount";
stats_map(_) ->
  undefined.

default_stream_opts() ->
  #{active => true}.

default_conn_opts() ->
  #{ peer_bidi_stream_count => 1
   , peer_unidi_stream_count => 1
   }.
%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
