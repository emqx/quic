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
        , reg_open/1
        , reg_close/0
        ]
       ).

%% Traffic APIs
-export([ listen/2
        , close_listener/1
        , connect/4
        , async_connect/3
        , handshake/1
        , handshake/2
        , async_handshake/1
        , accept/2
        , accept/3
        , async_accept/2
        , shutdown_connection/1
        , shutdown_connection/2
        , shutdown_connection/3
        , shutdown_connection/4
        , async_shutdown_connection/3
        , close_connection/1
        , close_connection/3
        , close_connection/4
        , async_close_connection/1
        , async_close_connection/3
        , accept_stream/2
        , accept_stream/3
        , async_accept_stream/2
        , start_stream/2
        , send/2
        , send/3
        , async_send/2
        , async_send/3
        , recv/2
        , send_dgram/2
        , shutdown_stream/1
        , shutdown_stream/2
        , shutdown_stream/4
        , async_shutdown_stream/3
        , async_shutdown_stream/1
        , close_stream/1
        , close_stream/2
        , close_stream/4
        , async_close_stream/1
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
        , perf_counters/0
        ]).

%% helpers
-export([ %% Stream flags tester
          is_unidirectional/1
        ]).
%% Exports for test
-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

-export([ start_listener/3 %% start application over quic
        , stop_listener/1
        ]).

-type connection_opts() :: proplists:proplist() | quicer_connection:opts().
-type listener_opts() :: proplists:proplist() | quicer_listener:listener_opts().

%% @doc Quicer library must be opened before any use.
%%
%%      This is called automatically while quicer application is started
%% @end
-spec open_lib() ->
        {ok, true}  | %% opened
        {ok, false} | %% already opened
        {ok, debug} | %% opened with lttng debug library loaded (if present)
        {error, open_failed, atom_reason()}.
open_lib() ->
  quicer_nif:open_lib().

%% @doc Close library.
%%
%%      This is reserved for upgrade support
%%
%%      <b>Danger!</b> Do not use it!
%% @end
-spec close_lib() -> ok.
close_lib() ->
  quicer_nif:close_lib().


%% @doc Registraion should be opened before calling traffic APIs.
%%
%% This is called automatically when quicer application starts with
%% app env: `profile'
%% @end
%% @see reg_open/1
%% @see reg_close/0
reg_open() ->
  Profile = application:get_env(quicer, profile, quic_execution_profile_low_latency),
  quicer_nif:reg_open(Profile).

%% @doc Registraion should be opened before calling traffic APIs.
%% Registraion creates application context, worker threads
%% shared for all the connections
%%
%% Currently only support one application.
%% @end
%% @see reg_open/1
%% @see reg_close/0
%% @TODO support more applications with different profiles
-spec reg_open(execution_profile()) -> ok | {error, badarg}.
reg_open(Profile) ->
  quicer_nif:reg_open(Profile).

%% @doc close Registraion.
%% Reserved for future upgrade, don't use it.
%% @see reg_open/1
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

%% @doc Start listen on Port or "HOST:PORT".
%%
%% listener_handle() is used for accepting new connection.
%% notes,
%%
%% 1. Port binding is done in NIF context, thus you cannot see it from inet:i().
%%
%% 2. ListenOn can either be integer() for Port or be String for HOST:PORT
%%
%% 3. There is no address binding even HOST is specified.
%% @end
-spec listen(listen_on(), listen_opts()) ->
        {ok, listener_handle()} |
        {error, listener_open_error,  atom_reason()} |
        {error, listener_start_error, atom_reason()}.
listen(ListenOn, Opts) when is_list(Opts) ->
  listen(ListenOn, maps:from_list(Opts));
listen(ListenOn, Opts) when is_map(Opts) ->
  quicer_nif:listen(ListenOn, Opts).

%% @doc close listener with listener handle
-spec close_listener(listener_handle()) -> ok.
close_listener(Listener) ->
  quicer_nif:close_listener(Listener).

%% @doc
%% Initiate New Connection (Client)
%%
%% Initiate new connection to remote endpoint with connection opts specified.
%% @see async_connect/3
%% @end
-spec connect(inet:hostname() | inet:ip_address(),
              inet:port_number(), conn_opts(), timeout()) ->
          {ok, connection_handle()} |
          {error, conn_open_error | config_error | conn_start_error} |
          {error, timeout}.
connect(Host, Port, Opts, Timeout) when is_list(Opts) ->
  connect(Host, Port, maps:from_list(Opts), Timeout);
connect(Host, Port, Opts, Timeout) when is_tuple(Host) ->
  connect(inet:ntoa(Host), Port, Opts, Timeout);
connect(Host, Port, Opts, Timeout) when is_map(Opts) ->
  NewTimeout = maps:get(handshake_idle_timeout_ms, Opts, Timeout),
  NewOpts = maps:merge(default_conn_opts(), Opts#{handshake_idle_timeout_ms => NewTimeout}),
  case quicer_nif:async_connect(Host, Port, NewOpts) of
    {ok, H} ->
      receive
        {quic, connected, H, _} ->
          {ok, H};
        {quic, transport_shutdown, H, Reason} when Reason == connection_timeout
                                                   orelse Reason == connection_idle ->
          {error, timeout};
        {quic, transport_shutdown, _, Reason} ->
          {error, transport_down, Reason}
      end;
    {error, _} = Err ->
      Err
  end.

%% @doc
%% Initiate New Connection (Client)
%%
%% Async variant of connect/4
%% @see connect/4
%% @end
-spec async_connect(inet:hostname() | inet:ip_address(),
              inet:port_number(), conn_opts()) ->
          {ok, connection_handle()} |
          {error, conn_open_error | config_error | conn_start_error}.
async_connect(Host, Port, Opts) when is_list(Opts) ->
  async_connect(Host, Port, maps:from_list(Opts));
async_connect(Host, Port, Opts) when is_tuple(Host) ->
  async_connect(inet:ntoa(Host), Port, Opts);
async_connect(Host, Port, Opts) when is_map(Opts) ->
  NewOpts = maps:merge(default_conn_opts(), Opts),
  quicer_nif:async_connect(Host, Port, NewOpts).


%% @doc Complete TLS handshake after accepted a Connection
%%      with 5s timeout (Server)
%% @end
%% @see accept/3
%% @see handshake/2
-spec handshake(connection_handle()) -> ok | {error, any()}.
handshake(Conn) ->
  handshake(Conn, 5000).

%% @doc Complete TLS handshake after accepted a Connection
%% @see handshake/2
%% @see async_handshake/1
-spec handshake(connection_handle(), timeout()) -> ok | {error, any()}.
handshake(Conn, Timeout) ->
  case async_handshake(Conn) of
    {error, _} = E -> E;
    ok ->
      receive
        {quic, connected, Conn, _} -> {ok, Conn};
        {quic, closed, Conn, _Flags} -> {error, closed}
      after Timeout ->
          {error, timeout}
      end
  end.

%% @doc Complete TLS handshake after accepted a Connection.
%% Caller should expect to receive ```{quic, connected, connection_handle()}'''
%%
%% @see handshake/2
-spec async_handshake(connection_handle()) -> ok | {error, any()}.
async_handshake(Conn) ->
  quicer_nif:async_handshake(Conn).

%% @doc Accept new Connection (Server)
%%
%% Accept new connection from listener_handle().
%%
%% Calling process becomes the owner of the connection.
%% @end.
-spec accept(listener_handle(), acceptor_opts()) ->
        {ok, connection_handle()} | {error, any()}.
accept(LSock, Opts) ->
  accept(LSock, Opts, infinity).


%% @doc Accept new Connection (Server) with timeout
%% @see accept/2
-spec accept(listener_handle(), acceptor_opts(), timeout()) ->
        {ok, connection_handle()} |
        {error, badarg | param_error | not_enough_mem | badpid} |
        {error, timeout}.
accept(LSock, Opts, Timeout) when is_list(Opts) ->
  accept(LSock, maps:from_list(Opts), Timeout);
accept(LSock, Opts, Timeout) ->
  % non-blocking
  {ok, LSock} = quicer_nif:async_accept(LSock, Opts),
  receive
    {quic, new_conn, C, _} ->
      {ok, C};
    {quic, connected, C, _} ->
      {ok, C}
  after Timeout ->
    {error, timeout}
  end.

-spec async_accept(listener_handle(), acceptor_opts()) ->
        {ok, listener_handle()} |
        {error, badarg | param_error | not_enough_mem | badpid}.
async_accept(Listener, Opts) ->
  NewOpts = maps:merge(default_conn_opts(), Opts),
  quicer_nif:async_accept(Listener, NewOpts).

%% @doc Starts the shutdown process on a connection and block until it is finished.
%% @see shutdown_connection/4
-spec shutdown_connection(connection_handle()) -> ok | {error, timeout | closed}.
shutdown_connection(Conn) ->
  shutdown_connection(Conn, 5000).

%% @doc Starts the shutdown process on a connection and block until it is finished.
%% but with a timeout
%% @end
%% @see shutdown_connection/4
-spec shutdown_connection(connection_handle(), timeout()) ->
        ok | {error, timeout | badarg}.
shutdown_connection(Conn, Timeout) ->
  shutdown_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, Timeout).

%% @doc Starts the shutdown process on a connection with shutdown flag
%% and applications error with 5s timeout
-spec shutdown_connection(connection_handle(),
                       conn_shutdown_flag(),
                       app_errno()
                      ) -> ok | {error, timeout | badarg}.
shutdown_connection(Conn, Flags, ErrorCode) ->
  shutdown_connection(Conn, Flags, ErrorCode, 5000).

%% @doc Starts the shutdown process on a connection with shutdown flag
%% and applications error with timeout
%% @end
%% @see shutdown_connection/1
%% @see shutdown_connection/2
%% @see shutdown_connection/3
-spec shutdown_connection(connection_handle(),
                       conn_shutdown_flag(),
                       app_errno(),
                       timeout()) -> ok | {error, timeout | badarg}.
shutdown_connection(Conn, Flags, ErrorCode, Timeout) ->
  %% @todo make_ref
  case async_shutdown_connection(Conn, Flags, ErrorCode) of
    ok ->
      receive
        {quic, closed, Conn, _Flags} ->
          ok
      after Timeout ->
          {error, timeout}
      end;
    {error, _} = Err ->
      Err
  end.

%% @doc Async starts the shutdown process and caller should expect for
%% connection down message {quic, close, Conn}
%% @end
-spec async_shutdown_connection(connection_handle(),
                                conn_shutdown_flag(),
                                app_errno()) -> ok | {error, badarg | closed}.
async_shutdown_connection(Conn, Flags, ErrorCode) ->
  quicer_nif:async_shutdown_connection(Conn, Flags, ErrorCode).

-spec close_connection(connection_handle()) -> ok | {error, badarg}.
close_connection(Conn) ->
  close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, 5000).

%% @doc Close connection with flag specified and application reason code.
%% @see shutdown_connection/3
-spec close_connection(connection_handle(),
                       conn_shutdown_flag(),
                       app_errno()
                      ) -> ok | {error, badarg | timeout}.
close_connection(Conn, Flags, ErrorCode) ->
  close_connection(Conn, Flags, ErrorCode, 5000).

%% @doc Close connection with flag specified and application reason code with timeout
%% @see shutdown_connection/4
-spec close_connection(connection_handle(),
                       conn_shutdown_flag(),
                       app_errno(),
                       timeout()) -> ok | {error, badarg | timeout}.
close_connection(Conn, Flags, ErrorCode, Timeout) ->
  shutdown_connection(Conn, Flags, ErrorCode, Timeout).

-spec async_close_connection(connection_handle()) -> ok.
async_close_connection(Conn) ->
  async_close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0).

%% @doc Async variant of {@link close_connection/4}
%% @see async_close_connection/3
-spec async_close_connection(connection_handle(),
                             conn_shutdown_flag(),
                             app_errno()) -> ok.
async_close_connection(Conn, Flags, ErrorCode) ->
  async_shutdown_connection(Conn, Flags, ErrorCode).

%% @doc Accept new stream on a existing connection with stream opts
%%
%% Calling process become the owner of the new stream and it get monitored by NIF.
%%
%% Once the Calling process is dead, closing stream will be triggered. (@TODO may not be default)
%%
%% @end
-spec accept_stream(connection_handle(), stream_opts()) ->
        {ok, stream_handle()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {erro, timeout}.
accept_stream(Conn, Opts) ->
  accept_stream(Conn, Opts, infinity).

%% @doc Accept new stream on a existing connection with stream opts with timeout
%%
%% Calling process become the owner of the new stream and it get monitored by NIF.
%%
%% Once the Calling process is dead, closing stream will be triggered.
%%
%% @end
%% @see async_accept_stream/2
-spec accept_stream(connection_handle(), stream_opts(), timeout()) ->
        {ok, stream_handle()} |
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
        {quic, new_stream, Stream, _StreamFlags} ->
          {ok, Stream}
      after Timeout ->
          {error, timeout}
      end;
    {error, _} = E ->
      E
  end.

%% @doc Accept new stream on a existing connection with stream opts
%%
%% Calling process become the owner of the new stream and it get monitored by NIF.
%%
%% Once the Calling process is dead, closing stream will be triggered.
%%
%% Caller process should expect to receive
%% ```
%% {quic, new_stream, stream_handle(), stream_open_flags()}
%% '''
%%
%% note, it returns
%%
%% ```
%% {ok, connection_handle()}.
%% '''
%% NOT
%% ```
%% {ok, stream_handle()}.
%% '''
%% @end
%% @see async_accept_stream/2
-spec async_accept_stream(connection_handle(), proplists:proplist() | map()) ->
        {ok, connection_handle()} | {error, any()}.
async_accept_stream(Conn, Opts) when is_list(Opts) ->
  async_accept_stream(Conn, maps:from_list(Opts));
async_accept_stream(Conn, Opts) when is_map(Opts) ->
  quicer_nif:async_accept_stream(Conn, maps:merge(default_stream_opts(), Opts)).

%% @doc Start new stream in connection, return new stream handle.
%%
%% Calling process becomes the owner of the stream.
%%
%% Both client and server could start the stream
%% @end
-spec start_stream(connection_handle(), stream_opts()) ->
        {ok, stream_handle()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {error, stream_open_error, atom_reason()} |
        {error, stream_start_error, atom_reason()}.
start_stream(Conn, Opts) when is_list(Opts) ->
  start_stream(Conn, maps:from_list(Opts));
start_stream(Conn, Opts) when is_map(Opts) ->
  quicer_nif:start_stream(Conn, maps:merge(default_stream_opts(), Opts)).

%% @doc Send binary data over stream, blocking until send request is handled by the transport worker.
%% either succeeded or cancelled
-spec send(stream_handle(), iodata()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, cancelled}                        |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(Stream, Data) ->
  send(Stream, Data, ?QUICER_SEND_FLAG_SYNC).

%% @doc Send binary data over stream with send flags
%% either succeeded or cancelled
-spec send(stream_handle(), iodata(), non_neg_integer()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, cancelled}                        |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(Stream, Data, Flag) ->
  %% This is an sync send, set flag ?QUICER_SEND_FLAG_SYNC
  case quicer_nif:send(Stream, Data, Flag bor ?QUICER_SEND_FLAG_SYNC) of
    %% @todo make ref
    {ok, _Len} = OK ->
      receive
        {quic, send_complete, Stream, false} ->
          OK;
        {quic, send_complete, Stream, true} ->
          {error, cancelled}
      end;
    E ->
      E
  end.

%% @doc async variant of {@link send/3}
%% If QUICER_SEND_FLAG_SYNC is set , the caller should expect to receive
%% ```{quic, send_complete, Stream, send_complete_flag()}'''
%% note, check send_complete_flag() to ensure it is delivered or not.
-spec async_send(stream_handle(), iodata(), non_neg_integer()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
async_send(Stream, Data, Flag) ->
  quicer_nif:send(Stream, Data, Flag).

%% @doc async variant of {@link send/2}
%% Caller should NOT expect to receive
%% ```{quic, send_complete, Stream, send_complete_flag()}'''
%% note, check send_complete_flag() to ensure it is delivered or not.
-spec async_send(stream_handle(), iodata()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
async_send(Stream, Data) ->
  async_send(Stream, Data, ?QUIC_SEND_FLAG_NONE).

%% @doc Recv Data (Passive mode)
%% Passive recv data from stream.
%%
%% If Len = 0, return all data in recv buffer if it is not empty.
%%             if buffer is empty, blocking for a Quic msg from stack to arrive and return all data in that msg.
%%
%% If Len > 0, desired bytes will be returned, other data would be left in recv buffer.
%%
%% Suggested to use Len=0 if caller want to buffer or reassemble the data on its own.
%%
%% note, the requested Len cannot exceed the 'stream_recv_window_default' specified in connection opts
%% otherwise the function will never return
-spec recv(stream_handle(), Count::non_neg_integer())
          -> {ok, binary()} | {error, any()}.
recv(Stream, Count) ->
  do_recv(Stream, Count).

do_recv(Stream, Count) ->
  case quicer_nif:recv(Stream, Count) of
    {ok, not_ready} ->
      %% Data is not ready yet but last call has been reg.
      receive
        %% @todo recv_mark
        {quic, continue, Stream, undefined} ->
          recv(Stream, Count)
      end;
    {ok, Bin} ->
      {ok, Bin};
    {error, _} = E ->
      E
   end.

%% @doc Sending Unreliable Datagram
%%
%% ref: [https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram]
%% @see send/2
-spec send_dgram(connection_handle(), binary()) ->
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

%% @doc
%%
%% ref: [https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram]
%% @see send/2
-spec shutdown_stream(stream_handle()) -> ok | {error, badarg}.
shutdown_stream(Stream) ->
  shutdown_stream(Stream, infinity).

%% @doc Shutdown stream gracefully, with app_errno 0
%%
%% returns when both endpoints closed the stream
%%
%% @see shutdown_stream/4
-spec shutdown_stream(stream_handle(), timeout()) ->
        ok |
        {error, badarg} |
        {error, timeout}.
shutdown_stream(Stream, Timeout) ->
  shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0, Timeout).

%% @doc Start shutdown Stream process with flags and application specified error code.
%%
%% returns when stream closing is confirmed in the stack (Blocking).
%%
%% Flags could be used to control the behavior like half-close.
%% @end
%% @see async_shutdown_stream/4
-spec shutdown_stream(stream_handle(),
                      stream_shutdown_flags(),
                      app_errno(),
                      timeout()) ->
        ok |
        {error, badarg} |
        {error, timeout}.
shutdown_stream(Stream, Flags, ErrorCode, Timeout) ->
  case async_shutdown_stream(Stream, Flags, ErrorCode) of
    ok ->
      receive
        {quic, stream_closed, Stream, _Flags} ->
          ok
      after Timeout ->
          {error, timeout}
      end;
    Err ->
      Err
  end.


%% @doc async variant of {@link shutdown_stream/2}
%% @see async_shutdown_stream/3
-spec async_shutdown_stream(stream_handle()) ->
        ok |
        {error, badarg | atom_reason()}.
async_shutdown_stream(Stream) ->
  quicer_nif:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0).


%% @doc async variant of {@link shutdown_stream/4}
%% Caller should expect to receive
%% ```{quic, stream_closed, Stream, Flags}'''
%%
-spec async_shutdown_stream(stream_handle(),
                         stream_shutdown_flags(),
                         app_errno())
                        -> ok | {error, badarg}.
async_shutdown_stream(Stream, Flags, Reason) ->
  quicer_nif:async_shutdown_stream(Stream, Flags, Reason).

%% @doc Normal shutdown stream with infinity timeout.
%% @see close_stream/2
-spec close_stream(stream_handle()) -> ok | {error, badarg | timeout}.
close_stream(Stream) ->
  close_stream(Stream, infinity).

%% @doc Normal shutdown (App errno=0) Stream gracefully with timeout.
%% @see close_stream/4
-spec close_stream(stream_handle(), timeout())
                  -> ok | {error, badarg | timeout}.
close_stream(Stream, Timeout) ->
  close_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0, Timeout).

%% @doc Another name of shutdown stream for migration from tcp/ssl.
%% @see close_stream/1
%% @see shutdown_stream/4
-spec close_stream(stream_handle(), stream_shutdown_flags(),
                   app_errno(), timeout())
                  -> ok | {error, badarg | timeout}.
close_stream(Stream, Flags, ErrorCode, Timeout) ->
  shutdown_stream(Stream, Flags, ErrorCode, Timeout).

%% @doc async variant of {@link close_stream/1}, prefer to use async_shutdown_stream/4
%% @see close_stream/4
%% @see async_shutdown_stream/4
-spec async_close_stream(stream_handle()) -> ok | {error, badarg}.
async_close_stream(Stream) ->
  async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0).

%% @doc Get socket name
%% mimic {@link ssl:sockname/1}
-spec sockname(listener_handle() | connection_handle() | stream_handle()) ->
        {ok, {inet:ip_address(), inet:port_number()}} | {error, any()}.
sockname(Conn) ->
  quicer_nif:sockname(Conn).

%% @doc Get connection/stream/listener opts
%% mimic {@link ssl:getopts/2}
-spec getopt(Handle::handle(), optname()) ->
        {ok, OptVal::any()} | {error, any() | not_found}.
getopt(Handle, Opt) ->
  quicer_nif:getopt(Handle, Opt, false).

%% @doc Get connection/stream/listener opts
%% mimic {@link ssl:getopt/2}
-spec getopt(handle(), optname(), optlevel()) ->
        not_found | %% `optname' not found, or wrong `optlevel' must be a bug.
        {ok, [any()]}   | %% when optname = param_conn_settings
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
getopt(Handle, Opt, Optlevel) ->
  quicer_nif:getopt(Handle, Opt, Optlevel).

%% @doc Set connection/stream/listener opts
%% mimic {@link ssl:setopt/2}
-spec setopt(handle(), optname(), any()) ->
        ok |
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
setopt(Handle, param_conn_settings, Value) when is_list(Value) ->
  setopt(Handle, param_conn_settings, maps:from_list(Value));
setopt({_Conn, Stream}, active, Value) ->
  setopt(Stream, active, Value);
setopt(Handle, Opt, Value) ->
  quicer_nif:setopt(Handle, Opt, Value, false).

%% @doc get stream id with stream handle
-spec get_stream_id(Stream::stream_handle()) ->
        {ok, integer()} | {error, any()} | not_found.
get_stream_id(Stream) ->
  quicer_nif:getopt(Stream, param_stream_id, false).

%% @doc get connection state
%% mimic {@link ssl:getstat/2}
-spec getstat(connection_handle(), [inet:stat_option()]) ->
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

%% @doc Peer name
%% mimic {@link ssl:peername/1}
-spec peername(connection_handle()  | stream_handle()) ->
        {ok, {inet:ip_address(), inet:port_number()}} | {error, any()}.
peername(Handle) ->
  quicer_nif:getopt(Handle, param_conn_remote_address, false).

%% @doc Return true if stream open flags has unidirectional flag set
-spec is_unidirectional(stream_open_flags()) -> boolean().
is_unidirectional(Flags) ->
  Flags band ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL > 0.

-spec get_conn_rid(connection_handle()) ->
        {ok, non_neg_integer()} | {error, any()}.
get_conn_rid(Conn) ->
  quicer_nif:get_conn_rid(Conn).

-spec get_stream_rid(stream_handle()) ->
        {ok, non_neg_integer()} | {error, any()}.
get_stream_rid(Stream) ->
  quicer_nif:get_stream_rid(Stream).

%% @doc list all listeners
-spec listeners() -> [{{ quicer_listener:listener_name()
                       , quicer_listener:listen_on()},
                       pid()}].
listeners() ->
  quicer_listener_sup:listeners().

%% @doc List listener with app name
-spec listener(quicer_listener:listener_name()
              | {quicer_listener:listener_name(),
                 quicer_listener:listen_on()}) -> {ok, pid()} | {error, not_found}.
listener(Name) ->
  quicer_listener_sup:listener(Name).

%% @doc set controlling process for Connection/Stream.
%% mimic {@link ssl:controlling_process/2}
%% @end
-spec controlling_process(connection_handle() | stream_handle(), pid()) ->
        ok |
        {error, closed | badarg | owner_dead | not_owner}.
controlling_process(Handle, Pid) ->
  quicer_nif:controlling_process(Handle, Pid).


%%% @doc get QUIC stack performance counters
-spec perf_counters() -> {ok, list({atom(), integer()})} | {error, any()}.
perf_counters() ->
  CntNames = [ conn_created,
               conn_handshake_fail,
               conn_app_reject,
               conn_active,
               conn_connected,
               conn_protocol_errors,
               conn_no_alpn,
               strm_active,
               pkts_suspected_lost,
               pkts_dropped,
               pkts_decryption_fail,
               udp_recv,
               udp_send,
               udp_recv_bytes,
               udp_send_bytes,
               udp_recv_events,
               udp_send_calls,
               app_send_bytes,
               app_recv_bytes,
               conn_queue_depth,
               conn_oper_queue_depth,
               conn_oper_queued,
               conn_oper_completed,
               work_oper_queue_depth,
               work_oper_queued,
               work_oper_completed,
               path_validated,
               path_failure,
               send_stateless_reset,
               send_stateless_retry
             ],
  case quicer_nif:getopt(quic_global,
                         param_global_perf_counters, false) of
    {ok, Res} ->
       {ok, lists:zip(CntNames, Res)};
    Error ->
      Error
  end.

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
