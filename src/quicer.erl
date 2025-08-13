%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-export([
    open_lib/0,
    close_lib/0,
    new_registration/2,
    shutdown_registration/1,
    shutdown_registration/3,
    get_registration_name/1,
    get_registration_refcnt/1,
    reg_open/0,
    reg_open/1,
    reg_close/0
]).

%% Traffic APIs
-export([
    listen/2,
    stop_listener/1,
    start_listener/3,
    close_listener/1,
    close_listener/2,
    connect/4,
    async_connect/3,
    handshake/1,
    handshake/2,
    handshake/3,
    async_handshake/1,
    async_handshake/2,
    accept/2,
    accept/3,
    async_accept/2,
    shutdown_connection/1,
    shutdown_connection/2,
    shutdown_connection/3,
    shutdown_connection/4,
    async_shutdown_connection/3,
    close_connection/1,
    close_connection/3,
    close_connection/4,
    async_close_connection/1,
    async_close_connection/3,
    probe/2,
    accept_stream/2,
    accept_stream/3,
    async_accept_stream/2,
    start_stream/2,
    send/2,
    send/3,
    async_csend/4,
    async_send/2,
    async_send/3,
    recv/2,
    async_send_dgram/2,
    send_dgram/2,
    shutdown_stream/1,
    shutdown_stream/2,
    shutdown_stream/4,
    async_shutdown_stream/3,
    async_shutdown_stream/1,
    close_stream/1,
    close_stream/2,
    close_stream/4,
    async_close_stream/1,
    sockname/1,
    getopt/2,
    getopt/3,
    setopt/3,
    setopt/4,
    get_stream_id/1,
    getstat/2,
    negotiated_protocol/1,
    peername/1,
    peercert/1,
    complete_cert_validation/3,
    listeners/0,
    listener/1,
    controlling_process/2,
    wait_for_handoff/2,
    handoff_stream/2,
    handoff_stream/3,
    perf_counters/0,
    count_reg_conns/1
]).

%% helpers

%% Stream flags tester
-export([
    is_unidirectional/1,
    %% Future Packets Buffering
    quic_data/1,
    merge_quic_datalist/1,
    new_fpbuffer/0,
    new_fpbuffer/1,
    update_fpbuffer/2,
    defrag_fpbuffer/2,
    is_set/2
]).
%% Exports for test
-export([
    get_conn_rid/1,
    get_stream_rid/1,
    open_connection/0,
    get_listeners/0,
    get_listeners/1,
    get_connections/0,
    get_connections/1,
    close_registration/1,
    get_conn_owner/1,
    get_stream_owner/1,
    get_listener_owner/1
]).

%% start application over quic
-export([
    spawn_listener/3,
    terminate_listener/1
]).

%% versions
-export([abi_version/0]).

%% export types

%% handles
-export_type([
    listener_handle/0,
    listen_on/0,
    connection_handle/0,
    stream_handle/0,

    %% Options
    conn_opts/0,
    stream_opts/0,
    listener_opts/0,

    %% Flags
    stream_open_flags/0,
    stream_start_flags/0,
    stream_shutdown_flags/0,

    %% Events Props
    recv_data_props/0,
    peer_accepted_props/0,
    stream_closed_props/0,
    stream_start_completed_props/0,
    transport_shutdown_props/0,
    conn_closed_props/0,
    connected_props/0,
    new_conn_props/0,
    streams_available_props/0,
    new_stream_props/0,
    dgram_state/0,

    %% Suporting types
    error_code/0,
    quicer_addr/0,

    %% Registraion Profiles
    registration_profile/0,

    %% probes
    probe_res/0
]).

-type listener_opts() :: quicer_listener:listener_opts().

%% @doc Return ABI version of the library.
-spec abi_version() -> quicer_nif:abi_version().
abi_version() ->
    quicer_nif:abi_version().

%% @doc Quicer library must be opened before any use.
%%
%%      This is called automatically while quicer application is started
%% @end
-spec open_lib() ->
    %% opened
    {ok, true}
    %% already opened
    | {ok, false}
    %% opened with lttng debug library loaded (if present)
    | {ok, debug}
    | {ok, fake}
    | {error, open_failed, atom_reason()}.
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

%% @doc Create a new registration.
-spec new_registration(string(), registration_profile()) ->
    quicer_nif:new_registration().
new_registration(Name, Profile) ->
    quicer_nif:new_registration(Name, Profile).

%% @doc Shutdown a registration.
-spec shutdown_registration(reg_handle()) ->
    quicer_nif:shutdown_registration().
shutdown_registration(Handle) ->
    quicer_nif:shutdown_registration(Handle).

%% @doc Shutdown a registration with error code and silent flag.
-spec shutdown_registration(reg_handle(), boolean(), uint64()) ->
    quicer_nif:shutdown_registration().
shutdown_registration(Handle, IsSilent, ErrCode) ->
    quicer_nif:shutdown_registration(Handle, IsSilent, ErrCode).

%% @doc close a registration.
-spec close_registration(reg_handle()) -> ok.
close_registration(Handle) ->
    case quicer_nif:close_registration(Handle) of
        ok ->
            ok;
        N ->
            logger:info("pending close_registration refcnt: ~p~n", [N]),
            timer:sleep(100),
            close_registration(Handle)
    end.

%% @doc get registration name
-spec get_registration_name(reg_handle()) ->
    quicer_nif:get_registration_name().
get_registration_name(Handle) ->
    quicer_nif:get_registration_name(Handle).

%% @doc get registration reference count
-spec get_registration_refcnt(global | reg_handle()) ->
    quicer_nif:get_registration_refcnt().
get_registration_refcnt(Handle) ->
    quicer_nif:get_registration_refcnt(Handle).

%% @doc GRegistraion should be opened before calling traffic APIs.
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

%% @doc Start a stopped listener with listener handle with new Options.
-spec start_listener(listener_handle(), listen_on(), listen_opts()) ->
    ok | {error, any()}.
start_listener(Listener, Port, Options) when is_list(Options) ->
    start_listener(Listener, Port, maps:from_list(Options));
start_listener(Listener, Port, Options) ->
    quicer_nif:start_listener(Listener, Port, Options).

%% @doc Stop a started listener which could be closed or restarted later.
-spec stop_listener(listener_handle()) -> ok | {error, any()}.
stop_listener(Handle) ->
    case quicer_nif:stop_listener(Handle) of
        ok ->
            receive
                {quic, listener_stopped, Handle} ->
                    ok
            end;
        %% @TODO handle already stopped
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc start a listener process under supervisor tree
-spec spawn_listener(
    Appname :: atom() | listener_handle(),
    listen_on(),
    listener_opts()
) ->
    {ok, pid()} | {error, any()}.
spawn_listener(AppName, Port, Options) when is_atom(AppName) ->
    quicer_listener:start_listener(AppName, Port, Options).

%% @doc terminate a listener process under supervisor tree
-spec terminate_listener(atom() | listener_handle()) -> ok.
terminate_listener(AppName) when is_atom(AppName) ->
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
    {ok, listener_handle()}
    %% bad tls related opts, cacertfile, certfile, keyfile, password...
    | {error, quic_tls}
    %% bad cacert file
    | {error, cacertfile}
    %% wrong registration opt
    | {error, quic_registration}
    | {error, badarg}
    | {error, listener_open_error, atom_reason()}
    | {error, listener_start_error, atom_reason()}.
listen(ListenOn, Opts) when is_list(Opts) ->
    listen(ListenOn, maps:from_list(Opts));
listen(ListenOn, Opts) when is_map(Opts) ->
    quicer_nif:listen(ListenOn, Opts).

%% @doc close listener with listener handle
-spec close_listener(listener_handle()) -> ok | {error, badarg | closed | timeout}.
close_listener(Listener) ->
    close_listener(Listener, 5000).

-spec close_listener(listener_handle(), timeout()) ->
    ok | {error, badarg | closed | timeout}.
close_listener(Listener, Timeout) ->
    case quicer_nif:close_listener(Listener) of
        closed ->
            ok;
        ok when Timeout == 0 ->
            ok;
        ok ->
            receive
                {quic, listener_stopped, Listener} ->
                    ok
            after Timeout ->
                {error, timeout}
            end;
        {error, closed} ->
            %% already closed
            %% follow OTP behavior
            ok;
        {error, _} = E ->
            E
    end.

%% @doc
%% Initiate New Connection (Client)
%%
%% Initiate new connection to remote endpoint with connection opts specified.
%% @see async_connect/3
%% @end
-spec connect(
    inet:hostname() | inet:ip_address(),
    inet:port_number(),
    conn_opts(),
    timeout()
) ->
    {ok, connection_handle()}
    | {error, conn_open_error | config_error | conn_start_error | timeout | nst_not_found}
    | {error, transport_down, transport_shutdown_props()}.
connect(Host, Port, Opts, Timeout) when is_list(Opts) ->
    connect(Host, Port, maps:from_list(Opts), Timeout);
connect(Host, Port, Opts, Timeout) when is_tuple(Host) ->
    case inet:ntoa(Host) of
        NewHost when is_list(NewHost) ->
            connect(NewHost, Port, Opts, Timeout);
        E ->
            E
    end;
connect(Host, Port, Opts, Timeout) when is_map(Opts) ->
    NewTimeout = maps:get(handshake_idle_timeout_ms, Opts, Timeout),
    NewOpts = maps:merge(default_conn_opts(), Opts#{handshake_idle_timeout_ms => NewTimeout}),
    case quicer_nif:async_connect(Host, Port, NewOpts) of
        {ok, H} ->
            receive
                {quic, connected, H, _} ->
                    {ok, H};
                {quic, transport_shutdown, H, Reason} ->
                    flush(closed, H),
                    {error, transport_down, Reason};
                {quic, peer_cert_received, H, Cert} ->
                    {ok, H, Cert}
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
-spec async_connect(
    inet:hostname() | inet:ip_address(),
    inet:port_number(),
    conn_opts()
) ->
    {ok, connection_handle()}
    | {error, conn_open_error | config_error | conn_start_error}.
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
-spec handshake(connection_handle()) ->
    {ok, connection_handle()}
    | {error, any()}.
handshake(Conn) ->
    handshake(Conn, 5000).

-spec handshake(connection_handle(), timeout()) ->
    {ok, connection_handle()} | {error, any()}.
handshake(Conn, Timeout) ->
    case async_handshake(Conn) of
        {error, _} = E ->
            E;
        ok ->
            receive
                {quic, connected, Conn, _} -> {ok, Conn};
                {quic, closed, Conn, _Flags} -> {error, closed};
                {quic, peer_cert_received, Conn, Cert} -> {ok, Conn, Cert}
            after Timeout ->
                {error, timeout}
            end
    end.

%% @doc Complete TLS handshake after accepted a Connection
%% @see handshake/2
%% @see async_handshake/1
-spec handshake(connection_handle(), conn_opts(), timeout()) ->
    {ok, connection_handle()}
    | {error, any()}.
handshake(Conn, ConnOpts, Timeout) ->
    case async_handshake(Conn, ConnOpts) of
        {error, _} = E ->
            E;
        ok ->
            receive
                {quic, connected, Conn, _} -> {ok, Conn};
                {quic, closed, Conn, _Flags} -> {error, closed}
            after Timeout ->
                {error, timeout}
            end
    end.

%% @doc Complete TLS handshake after accepted a Connection.
%%
%% @see handshake/2
%% @see async_handshake/2
-spec async_handshake(connection_handle()) -> ok | {error, any()}.
async_handshake(Conn) ->
    quicer_nif:async_handshake(Conn).

%% @doc Complete TLS handshake after accepted a Connection.
%%      also set connection options which override the default listener options.
%%
%% @see handshake/2
%% @see async_handshake/1
-spec async_handshake(connection_handle(), conn_opts()) -> ok | {error, any()}.
async_handshake(Conn, ConnOpts) when is_list(ConnOpts) ->
    async_handshake(Conn, maps:from_list(ConnOpts));
async_handshake(Conn, ConnOpts) ->
    quicer_nif:async_handshake(Conn, ConnOpts).

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
    {ok, connection_handle()}
    | {error, badarg | param_error | not_enough_mem | badpid}
    | {error, timeout}.
accept(LSock, Opts, Timeout) when is_list(Opts) ->
    accept(LSock, maps:from_list(Opts), Timeout);
accept(LSock, Opts, Timeout) ->
    % non-blocking
    case quicer_nif:async_accept(LSock, Opts) of
        {ok, LSock} ->
            receive
                {quic, new_conn, C, _} ->
                    {ok, C};
                {quic, connected, C, _} ->
                    {ok, C}
            after Timeout ->
                {error, timeout}
            end;
        E ->
            E
    end.

-spec async_accept(listener_handle(), acceptor_opts()) ->
    {ok, listener_handle()}
    | {error, badarg | param_error | not_enough_mem | badpid}.
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
-spec shutdown_connection(
    connection_handle(),
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
-spec shutdown_connection(
    connection_handle(),
    conn_shutdown_flag(),
    app_errno(),
    timeout()
) -> ok | {error, timeout | badarg}.
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
-spec async_shutdown_connection(
    connection_handle(),
    conn_shutdown_flag(),
    app_errno()
) -> ok | {error, badarg | closed}.
async_shutdown_connection(Conn, Flags, ErrorCode) ->
    quicer_nif:async_shutdown_connection(Conn, Flags, ErrorCode).

-spec close_connection(connection_handle()) -> ok | {error, badarg}.
close_connection(Conn) ->
    close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0, 5000).

%% @doc Close connection with flag specified and application reason code.
%% @see shutdown_connection/3
-spec close_connection(
    connection_handle(),
    conn_shutdown_flag(),
    app_errno()
) -> ok | {error, badarg | timeout}.
close_connection(Conn, Flags, ErrorCode) ->
    close_connection(Conn, Flags, ErrorCode, 5000).

%% @doc Close connection with flag specified and application reason code with timeout
%% @see shutdown_connection/4
-spec close_connection(
    connection_handle(),
    conn_shutdown_flag(),
    app_errno(),
    timeout()
) -> ok | {error, badarg | timeout}.
close_connection(Conn, Flags, ErrorCode, Timeout) ->
    shutdown_connection(Conn, Flags, ErrorCode, Timeout).

-spec async_close_connection(connection_handle()) -> ok.
async_close_connection(Conn) ->
    async_close_connection(Conn, ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0).

%% @doc Async variant of {@link close_connection/4}
%% @see async_close_connection/3
-spec async_close_connection(
    connection_handle(),
    conn_shutdown_flag(),
    app_errno()
) -> ok.
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
    {ok, stream_handle()}
    | {error, badarg | internal_error | bad_pid | owner_dead}
    | {erro, timeout}.
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
    {ok, stream_handle()}
    | {error, badarg | internal_error | bad_pid | owner_dead}
    | {erro, timeout}.
accept_stream(Conn, Opts, Timeout) when is_list(Opts) ->
    accept_stream(Conn, maps:from_list(Opts), Timeout);
accept_stream(Conn, Opts, Timeout) when is_map(Opts) ->
    NewOpts = maps:merge(default_stream_opts(), Opts),
    case quicer_nif:async_accept_stream(Conn, NewOpts) of
        {ok, Conn} ->
            receive
                {quic, new_stream, Stream, _StreamProps} ->
                    {ok, Stream};
                {quic, closed, undefined, undefined} ->
                    ?tp_ignore_side_effects_in_prod(stream_acceptor_conn_closed, #{conn => Conn}),
                    {error, closed}
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
%% {quic, new_stream, stream_handle(), new_stream_props()}
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
%% Both client and server could start the stream.
%% @end
-spec start_stream(connection_handle(), stream_opts()) ->
    {ok, stream_handle()}
    | {error, badarg | internal_error | bad_pid | owner_dead}
    | {error, stream_open_error, atom_reason()}
    | {error, stream_start_error, atom_reason()}.
start_stream(Conn, Opts) when is_list(Opts) ->
    start_stream(Conn, maps:from_list(Opts));
start_stream(Conn, Opts) when is_map(Opts) ->
    quicer_nif:start_stream(Conn, maps:merge(default_stream_opts(), Opts)).

%% @doc Send data over a new local stream in the connection, return new stream handle if success.
-spec async_csend(connection_handle(), iodata(), stream_opts(), send_flags()) ->
    {ok, stream_handle()}
    | {error, any()}
    | {error, stm_open_error, atom_reason()}
    | {error, stream_send_error, atom_reason()}.

async_csend(Conn, IoData, Opts, SendFlags) when is_list(Opts) ->
    async_csend(Conn, IoData, maps:from_list(Opts), SendFlags);
async_csend(Conn, IoData, Opts, SendFlags) ->
    quicer_nif:csend(Conn, IoData, Opts, SendFlags).

%% @doc Send binary data over stream, blocking until send request is handled by the transport worker.
%% either succeeded or cancelled
-spec send(stream_handle(), iodata()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, cancelled}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
send(Stream, Data) ->
    send(Stream, Data, ?QUICER_SEND_FLAG_SYNC).

%% @doc Send binary data over stream with send flags
%% either succeeded or cancelled
-spec send(stream_handle(), iodata(), non_neg_integer()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, cancelled}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
send(Stream, Data, Flag) when is_integer(Flag) ->
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
%% `{quic, send_complete, Stream, send_complete_flag()}'
%% note, check send_complete_flag() to ensure it is delivered or not.
%% @end
-spec async_send(stream_handle(), iodata(), non_neg_integer()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
async_send(Stream, Data, Flag) ->
    quicer_nif:send(Stream, Data, Flag).

%% @doc async variant of {@link send/2}
%% Caller should NOT expect to receive
%% ```{quic, send_complete, Stream, send_complete_flag()}'''
%% note, check send_complete_flag() to ensure it is delivered or not.
-spec async_send(stream_handle(), iodata()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
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
-spec recv(stream_handle(), Count :: non_neg_integer()) ->
    {ok, binary()} | {error, any()}.
recv(Stream, Count) ->
    do_recv(Stream, Count, []).

do_recv(Stream, Count, Buff) ->
    case quicer_nif:recv(Stream, Count) of
        {ok, not_ready} ->
            %% Data is not ready yet but last call has been reg.
            receive
                %% @todo recv_mark
                {quic, continue, Stream, undefined} ->
                    do_recv(Stream, Count, Buff);
                {quic, peer_send_shutdown, Stream, undefined} ->
                    {error, peer_send_shutdown};
                {quic, peer_send_aborted, Stream, _ErrorCode} ->
                    {error, peer_send_aborted};
                {quic, stream_closed, Stream, _Props} ->
                    {error, closed}
            end;
        {ok, Bin} when (Count == 0 orelse byte_size(Bin) == Count) andalso Buff == [] ->
            {ok, Bin};
        {ok, Bin} when byte_size(Bin) == Count ->
            {ok, iolist_to_binary(lists:reverse([Bin | Buff]))};
        {ok, Bin} when byte_size(Bin) < Count ->
            do_recv(Stream, Count - byte_size(Bin), [Bin | Buff]);
        {error, _} = E ->
            E
    end.

%% @doc Sending Unreliable Datagram.
%% Caller should handle the async signals for the send results
%%
%% ref: [https://datatracker.ietf.org/doc/html/rfc9221]
%% @see send/2
%% @see send_dgram/2
-spec async_send_dgram(connection_handle(), binary()) ->
    {ok, non_neg_integer()}
    | {error, badarg | not_enough_mem | invalid_parameter | closed}
    | {error, dgram_send_error, atom_reason()}.
async_send_dgram(Conn, Data) ->
    quicer_nif:send_dgram(Conn, Data, _IsSyncRel = 1).

%% @doc Sending Unreliable Datagram
%%  return error only if sending could not be scheduled such as
%%  not_enough_mem, connection is already closed or wrong args.
%%  otherwise, it is fire and forget.
%%
%% %% ref: [https://datatracker.ietf.org/doc/html/rfc9221]
%% @see send/2
%% @see async_send_dgram/2
-spec send_dgram(connection_handle(), binary()) ->
    {ok, BytesSent :: non_neg_integer()}
    | {error, badarg | not_enough_mem | invalid_parameter | closed}
    | {error, dgram_send_error, atom_reason()}.
send_dgram(Conn, Data) ->
    case quicer_nif:send_dgram(Conn, Data, _IsSync = 1) of
        {ok, _Len} = OK ->
            case quicer_lib:handle_dgram_send_states(Conn) of
                ok ->
                    OK;
                {error, E} ->
                    {error, dgram_send_error, E}
            end;
        {error, E} ->
            {error, E};
        E ->
            E
    end.

%% @doc Probe conn state with 0 len dgram.
-spec probe(connection_handle(), timeout()) -> probe_res().
probe(Conn, Timeout) ->
    quicer_lib:probe(Conn, Timeout).

%% @doc Shutdown stream gracefully, with infinity timeout
%%
%% @see shutdown_stream/1
-spec shutdown_stream(stream_handle()) -> ok | {error, badarg}.
shutdown_stream(Stream) ->
    shutdown_stream(Stream, infinity).

%% @doc Shutdown stream gracefully, with app_errno 0
%%
%% returns when both endpoints closed the stream
%%
%% @see shutdown_stream/4
-spec shutdown_stream(stream_handle(), timeout()) ->
    ok
    | {error, badarg}
    | {error, timeout}.
shutdown_stream(Stream, Timeout) ->
    shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0, Timeout).

%% @doc Start shutdown Stream process with flags and application specified error code.
%%
%% returns when stream closing is confirmed in the stack (Blocking).
%%
%% Flags could be used to control the behavior like half-close.
%% @end
%% @see async_shutdown_stream/3
-spec shutdown_stream(
    stream_handle(),
    stream_shutdown_flags(),
    app_errno(),
    timeout()
) ->
    ok
    | {error, badarg}
    | {error, timeout}.
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
    ok
    | {error, badarg | atom_reason()}.
async_shutdown_stream(Stream) ->
    quicer_nif:async_shutdown_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0).

%% @doc async variant of {@link shutdown_stream/4}
%% Caller should expect to receive
%% ```{quic, stream_closed, Stream, Flags}'''
%%
-spec async_shutdown_stream(
    stream_handle(),
    stream_shutdown_flags(),
    app_errno()
) ->
    ok | {error, badarg}.
async_shutdown_stream(Stream, Flags, Reason) ->
    quicer_nif:async_shutdown_stream(Stream, Flags, Reason).

%% @doc Normal shutdown stream with infinity timeout.
%% @see close_stream/2
-spec close_stream(stream_handle()) -> ok | {error, badarg | timeout}.
close_stream(Stream) ->
    close_stream(Stream, infinity).

%% @doc Normal shutdown (App errno=0) Stream gracefully with timeout.
%% @see close_stream/4
-spec close_stream(stream_handle(), timeout()) ->
    ok | {error, badarg | timeout}.
close_stream(Stream, Timeout) ->
    close_stream(Stream, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0, Timeout).

%% @doc Another name of shutdown stream for migration from tcp/ssl.
%% @see close_stream/1
%% @see shutdown_stream/4
-spec close_stream(
    stream_handle(),
    stream_shutdown_flags(),
    app_errno(),
    timeout()
) ->
    ok | {error, badarg | timeout}.
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
-spec getopt(Handle :: handle(), optname()) ->
    {ok, OptVal :: any()} | {error, any() | not_found}.
getopt(Handle, Opt) ->
    quicer_nif:getopt(Handle, Opt, false).

%% @doc Get connection/stream/listener opts
%% mimic {@link ssl:getopt/2}
-spec getopt(handle(), optname(), optlevel()) ->
    %% `optname' not found, or wrong `optlevel' must be a bug.
    not_found
    %% when optname = settings
    | {ok, [any()]}
    | {error, badarg | param_error | internal_error | not_enough_mem}
    | {error, atom_reason()}.
getopt(Handle, Opt, Optlevel) ->
    quicer_nif:getopt(Handle, Opt, Optlevel).

%% @doc Set connection/stream/listener opts
%% mimic {@link ssl:setopt/2}
-spec setopt(handle(), optname(), any()) ->
    ok
    | {error, badarg | param_error | internal_error | not_enough_mem}
    | {error, atom_reason()}.
setopt(Handle, settings, Value) when is_list(Value) ->
    setopt(Handle, settings, maps:from_list(Value));
setopt({_Conn, Stream}, active, Value) ->
    setopt(Stream, active, Value);
setopt(Handle, Opt, Value) ->
    setopt(Handle, Opt, Value, false).

-spec setopt(handle(), optname(), any(), quic_handle_level()) ->
    ok
    | {error, badarg | param_error | internal_error | not_enough_mem}
    | {error, atom_reason()}.
setopt(Handle, Opt, Value, Level) ->
    quicer_nif:setopt(Handle, Opt, Value, Level).

%% @doc get stream id with stream handle
-spec get_stream_id(Stream :: stream_handle()) ->
    {ok, integer()} | {error, any()} | not_found.
get_stream_id(Stream) ->
    quicer_nif:getopt(Stream, stream_id, false).

%% @doc get connection state
%% mimic {@link ssl:getstat/2}
-spec getstat(connection_handle(), [inet:stat_option()]) ->
    {ok, list()} | {error, any()}.
getstat(Conn, Cnts) ->
    case quicer_nif:getopt(Conn, statistics, false) of
        {error, _} = E ->
            E;
        {ok, Res} ->
            CntRes = lists:map(
                fun(Cnt) ->
                    Key = stats_map(Cnt),
                    V = proplists:get_value(Key, Res, {Key, -1}),
                    {Cnt, V}
                end,
                Cnts
            ),
            {ok, CntRes}
    end.

%% @doc Returns the protocol negotiated through ALPN or NPN extensions.
-spec negotiated_protocol(Conn :: connection_handle()) ->
    {ok, Protocol :: binary()} | {error, Reason :: any()}.
negotiated_protocol(Conn) ->
    quicer:getopt(Conn, negotiated_alpn, quic_tls).

%% @doc Peer name
%% mimic {@link ssl:peername/1}
-spec peername(connection_handle() | stream_handle()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, any()}.
peername(Handle) ->
    quicer_nif:getopt(Handle, remote_address, false).

%% @doc Peer Cert in DER-encoded binary
%% mimic {@link ssl:peername/1}
-spec peercert(connection_handle() | stream_handle()) ->
    {ok, CertDerEncoded :: binary()} | {error, any()}.
peercert(Handle) ->
    quicer_nif:peercert(Handle).

-spec complete_cert_validation(connection_handle(), boolean(), integer()) -> ok | {error, any()}.
complete_cert_validation(Conn, IsAccepted, TlsAlert) ->
    quicer_nif:complete_cert_validation(Conn, IsAccepted, TlsAlert).

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

-spec open_connection() -> {ok, connection_handle()} | {error, atom_reason()}.
open_connection() ->
    quicer_nif:open_connection().

%% @doc list all listeners
-spec listeners() -> [{{quicer_listener:listener_name(), quicer:listen_on()}, pid()}].
listeners() ->
    quicer_listener_sup:listeners().

%% @doc List listener with app name
-spec listener(
    quicer_listener:listener_name()
    | {quicer_listener:listener_name(), quicer:listen_on()}
) -> {ok, pid()} | {error, not_found}.
listener(Name) ->
    quicer_listener_sup:listener(Name).

%% @doc Get a list listeners under global registration
-spec get_listeners() -> quicer_nif:get_listeners().
get_listeners() ->
    quicer_nif:get_listeners().

%% @doc Get a list of listeners under registration handle
-spec get_listeners(reg_handle() | global) -> quicer_nif:get_listeners().
get_listeners(global) ->
    quicer_nif:get_listeners();
get_listeners(Reg) ->
    quicer_nif:get_listeners(Reg).

%% @doc Get a list connections under global registration
-spec get_connections() -> quicer_nif:get_connections().
get_connections() ->
    quicer_nif:get_connections().

%% @doc Get a list of connections under registration handle
-spec get_connections(reg_handle() | global) -> quicer_nif:get_connections().
get_connections(global) ->
    quicer_nif:get_connections();
get_connections(Reg) ->
    quicer_nif:get_connections(Reg).

-spec count_reg_conns(reg_handle() | global) -> non_neg_integer().
count_reg_conns(global) ->
    quicer_nif:count_reg_conns();
count_reg_conns(Reg) ->
    quicer_nif:count_reg_conns(Reg).

-spec get_conn_owner(connection_handle()) -> quicer_nif:get_owner().
get_conn_owner(Conn) ->
    quicer_nif:get_conn_owner(Conn).

-spec get_stream_owner(stream_handle()) -> quicer_nif:get_owner().
get_stream_owner(Stream) ->
    quicer_nif:get_stream_owner(Stream).

-spec get_listener_owner(listener_handle()) -> quicer_nif:get_owner().
get_listener_owner(Listener) ->
    quicer_nif:get_listener_owner(Listener).

%% @doc set controlling process for Connection/Stream.
%% For Stream, also flush the sig buffer to old owner if failed or new owner if succeeded.
%% mimic {@link ssl:controlling_process/2}
%% @see handoff_stream/2
%% @see wait_for_handoff/2
%% @end
-spec controlling_process(connection_handle() | stream_handle(), pid()) ->
    ok
    | {error, closed | badarg | owner_dead | not_owner}.
controlling_process(Handle, Pid) ->
    quicer_nif:controlling_process(Handle, Pid).

%% @doc Used by new stream owner to wait for stream handoff complete.
%% Use this for handoff the orphan stream *only*.
%%
%% @see handoff_stream/3
%% @see controlling_process/2
%% @end
-spec wait_for_handoff(From :: pid(), stream_handle()) ->
    {error, owner_down} | {ok, PostInfo :: term()}.
wait_for_handoff(From, Stream) ->
    quicer_stream:wait_for_handoff(From, Stream).

%% @doc handoff_stream without post handoff data.
%% see handoff_stream/3
%% @end
-spec handoff_stream(stream_handle(), pid()) -> ok | {error, any()}.
handoff_stream(Stream, NewOwner) ->
    handoff_stream(Stream, NewOwner, undefined).

%% @doc Used by Old stream owner to handoff to the new stream owner.
%%
%%      1. The Stream will be put into passive mode so the data is paused.
%%
%%      2. The Stream signal buffer will be enabled, so the signal is paused.
%%
%%      3. Stream messages (for both data and sig )in the current owners process messages queue will
%%         be forwarded to the New Owner's mailbox in the same recv order.
%%
%%      4. Set the control process of the stream to the new owner, signal buffer will be flushed to new owner if succeed, otherwise to the old owner
%%
%%      5. A signal msg `{handoff_done, Stream, PostHandoff}' will be sent to the new owner.
%%         The new owner should block for this message before handle any stream data to
%%         ensure the ordering.
%%
%%      6. Revert stream active mode whatever handoff fail or success.
%% also @see wait_for_handoff/2
%% also @see controlling_process/2
%% @end
-spec handoff_stream(stream_handle(), pid(), term()) -> ok | {error, any()}.
handoff_stream(Stream, NewOwner, HandoffData) when NewOwner == self() ->
    NewOwner ! {handoff_done, Stream, HandoffData},
    ok;
handoff_stream(Stream, NewOwner, HandoffData) ->
    ?tp_ignore_side_effects_in_prod(debug, #{
        event => ?FUNCTION_NAME, module => ?MODULE, stream => Stream, owner => NewOwner
    }),
    case quicer:getopt(Stream, active) of
        {ok, ActiveN} ->
            ActiveN =/= false andalso quicer:setopt(Stream, active, false),
            ok = quicer_nif:enable_sig_buffer(Stream),
            Res =
                case forward_stream_msgs(Stream, NewOwner) of
                    ok ->
                        _ = quicer:controlling_process(Stream, NewOwner),
                        NewOwner ! {handoff_done, Stream, HandoffData},
                        ok;
                    {error, _} = Other ->
                        _ = quicer_nif:flush_stream_buffered_sigs(Stream),
                        Other
                end,
            ActiveN =/= false andalso quicer:setopt(Stream, active, ActiveN),
            Res;
        {error, _} = E ->
            E
    end.

%%% @doc get QUIC stack performance counters
-spec perf_counters() -> {ok, list({atom(), integer()})} | {error, any()}.
perf_counters() ->
    CntNames = [
        conn_created,
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
    case
        quicer_nif:getopt(
            quic_global,
            perf_counters,
            false
        )
    of
        {ok, Res} ->
            {ok, lists:zip(CntNames, Res)};
        Error ->
            Error
    end.

%% @doc Convert quic data event to quic_data for fpbuffer
-spec quic_data({quic, binary(), stream_handle(), recv_data_props()}) -> quic_data().
quic_data(
    {quic, Bin, _Handle, #{
        absolute_offset := Offset,
        len := Len,
        flags := Flags
    }}
) when is_binary(Bin) ->
    #quic_data{offset = Offset, size = Len, bin = Bin, flags = Flags}.

-spec merge_quic_datalist([quic_data()]) ->
    {iolist(), Size :: non_neg_integer(), Flag :: integer()}.
merge_quic_datalist(QuicDataList) ->
    lists:foldr(
        fun(#quic_data{bin = B, size = Size, flags = Flags}, {Acc, TotalSize, AFlags}) ->
            {[B | Acc], Size + TotalSize, AFlags bor Flags}
        end,
        {[], 0, 0},
        QuicDataList
    ).

-spec new_fpbuffer() -> fpbuffer().
new_fpbuffer() ->
    new_fpbuffer(0).
new_fpbuffer(StartOffset) ->
    #{next_offset => StartOffset, buffer => ordsets:new()}.

%% @doc update fpbuffer and return *next* continuous data.
-spec update_fpbuffer(quic_data(), fpbuffer()) -> {list(quic_data()), NewBuff :: fpbuffer()}.
update_fpbuffer(
    #quic_data{offset = Offset, size = Size} = Data, #{next_offset := Offset, buffer := []} = This
) ->
    %% Fast Path:. Offset is expected offset and buffer is empty.
    {[Data], This#{next_offset := Offset + Size}};
update_fpbuffer(#quic_data{} = Data, #{next_offset := NextOffset, buffer := Buffer} = This) ->
    Buffer1 = ordsets:add_element(ifrag(Data), Buffer),
    {NewOffset, NewBuffer, NewData} = defrag_fpbuffer(NextOffset, Buffer1),
    {NewData, This#{next_offset := NewOffset, buffer := NewBuffer}}.

%% @doc Pop out continuous data from the buffer start from the offset.
-spec defrag_fpbuffer(Offset :: non_neg_integer(), quic_data_buffer()) ->
    {NewOffset :: non_neg_integer(), NewBuffer :: quic_data_buffer(), Res :: [quic_data()]}.
defrag_fpbuffer(Offset, Buffer) ->
    defrag_fpbuffer(Offset, Buffer, []).
defrag_fpbuffer(Offset, [{Offset, Data} | T], Res) ->
    defrag_fpbuffer(Offset + Data#quic_data.size, T, [Data | Res]);
defrag_fpbuffer(Offset, [], Res) ->
    {Offset, [], lists:reverse(Res)};
defrag_fpbuffer(Offset, [{HeadOffset, _Data} | _T] = Buffer, Res) when HeadOffset >= Offset ->
    % Nomatch
    {Offset, Buffer, lists:reverse(Res)}.

%%% Internal helpers
-spec ifrag(quic_data()) -> ifrag().
ifrag(#quic_data{offset = Offset} = Data) ->
    {Offset, Data}.

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
    #{active => true, start_flag => ?QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL}.

default_conn_opts() ->
    #{
        peer_bidi_stream_count => 1,
        peer_unidi_stream_count => 1
    }.

%% @doc Forward all erl msgs of the Stream to the New Stream Owner
%% Stream Owner should block for the handoff_done
-spec forward_stream_msgs(stream_handle(), pid()) -> ok | {error, owner_down}.
forward_stream_msgs(Stream, Owner) when is_pid(Owner) ->
    do_forward_stream_msgs(Stream, Owner, erlang:monitor(process, Owner)).
do_forward_stream_msgs(Stream, Owner, MRef) ->
    receive
        {quic, _EventOrData, Stream, _Props} = Msg ->
            Owner ! Msg,
            do_forward_stream_msgs(Stream, Owner, MRef);
        {'DOWN', MRef, process, Owner, _} ->
            ?tp_ignore_side_effects_in_prod(do_forward_stream_msg_fail, #{
                stream => Stream, owner => Owner
            }),
            {error, owner_down}
    after 0 ->
        ?tp_ignore_side_effects_in_prod(do_forward_stream_msg_done, #{
            stream => Stream, owner => Owner
        }),
        erlang:demonitor(MRef),
        ok
    end.

%% @doc garbage collect some quic event that is useless to the caller.
-spec flush(atom(), handle()) -> ok.
flush(QuicEventName, Handle) when is_atom(QuicEventName) ->
    receive
        {quic, QuicEventName, Handle, _} -> ok
        %% Event must come, do not timeout
    end.

%% @doc Check if the bit mask is set in the integer.
-spec is_set(integer(), integer()) -> boolean().
is_set(Num, BitMask) when
    is_integer(Num) andalso
        is_integer(BitMask)
->
    (Num band BitMask) =:= BitMask.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

update_fpbuffer_test_() ->
    Frag0 = #quic_data{offset = 0, size = 1, bin = <<1>>},
    Frag1 = #quic_data{offset = 1, size = 2, bin = <<2, 3>>},
    Frag3 = #quic_data{offset = 3, size = 3, bin = <<4, 5, 6>>},
    Frag6 = #quic_data{offset = 6, size = 6, bin = <<7, 8, 9, 10, 11, 12>>},
    FPBuffer1 = #{next_offset => 0, buffer => []},
    FPBuffer1_3 = #{next_offset => 0, buffer => [ifrag(Frag1)]},
    FPBuffer1_3_6 = #{next_offset => 0, buffer => [ifrag(Frag1), ifrag(Frag3), ifrag(Frag6)]},
    FPBuffer1_6 = #{next_offset => 0, buffer => [ifrag(Frag1), ifrag(Frag6)]},
    FPBuffer2 = #{next_offset => 1, buffer => []},
    FPBuffer3 = #{next_offset => 3, buffer => []},
    FPBuffer6 = #{next_offset => 3, buffer => [ifrag(Frag6)]},
    FPBufferEnd = #{next_offset => 12, buffer => []},
    [
        ?_assertEqual({[Frag0], FPBuffer2}, update_fpbuffer(Frag0, FPBuffer1)),
        ?_assertEqual({[Frag1], FPBuffer3}, update_fpbuffer(Frag1, FPBuffer2)),
        ?_assertEqual({[], FPBuffer1_3}, update_fpbuffer(Frag1, FPBuffer1)),
        ?_assertEqual(
            FPBuffer1_3_6,
            lists:foldl(
                fun(Frag, Acc) ->
                    {[], NewAcc} = update_fpbuffer(Frag, Acc),
                    NewAcc
                end,
                FPBuffer1,
                [Frag1, Frag3, Frag6]
            )
        ),
        ?_assertEqual(
            FPBuffer1_3_6,
            lists:foldl(
                fun(Frag, Acc) ->
                    {[], NewAcc} = update_fpbuffer(Frag, Acc),
                    NewAcc
                end,
                FPBuffer1,
                [Frag6, Frag3, Frag1]
            )
        ),
        ?_assertEqual(
            {[Frag0, Frag1, Frag3, Frag6], FPBufferEnd}, update_fpbuffer(Frag0, FPBuffer1_3_6)
        ),
        ?_assertEqual({[Frag0, Frag1], FPBuffer6}, update_fpbuffer(Frag0, FPBuffer1_6))
    ].

defrag_fpbuffer_test_() ->
    Frag0 = #quic_data{offset = 0, size = 1, bin = <<1>>},
    Frag1 = #quic_data{offset = 1, size = 2, bin = <<2, 3>>},
    Frag3 = #quic_data{offset = 3, size = 3, bin = <<4, 5, 6>>},
    Frag6 = #quic_data{offset = 6, size = 6, bin = <<7, 8, 9, 10, 11, 12>>},

    Buffer1 = orddict:from_list([ifrag(Frag0)]),
    Buffer2 = orddict:from_list([ifrag(Frag0), ifrag(Frag3)]),
    Buffer3 = orddict:from_list([ifrag(Frag0), ifrag(Frag3), ifrag(Frag6)]),
    Buffer4 = orddict:from_list([ifrag(Frag0), ifrag(Frag1), ifrag(Frag6)]),
    Buffer5 = orddict:from_list([ifrag(Frag1), ifrag(Frag0), ifrag(Frag6), ifrag(Frag3)]),
    Buffer6 = orddict:from_list([ifrag(Frag1), ifrag(Frag6), ifrag(Frag3)]),
    Buffer7 = orddict:from_list([ifrag(Frag1), ifrag(Frag6)]),
    [
        ?_assertEqual(
            {1, [], [Frag0]},
            defrag_fpbuffer(0, Buffer1)
        ),
        ?_assertEqual(
            {1, [ifrag(Frag3)], [Frag0]},
            defrag_fpbuffer(0, Buffer2)
        ),
        ?_assertEqual(
            {1, [ifrag(Frag3), ifrag(Frag6)], [Frag0]},
            defrag_fpbuffer(0, Buffer3)
        ),
        ?_assertEqual(
            {3, [ifrag(Frag6)], [Frag0, Frag1]},
            defrag_fpbuffer(0, Buffer4)
        ),
        ?_assertEqual(
            {12, [], [Frag0, Frag1, Frag3, Frag6]},
            defrag_fpbuffer(0, Buffer5)
        ),
        ?_assertEqual(
            {0, Buffer6, []},
            defrag_fpbuffer(0, Buffer6)
        ),
        ?_assertEqual(
            {12, [], [Frag1, Frag3, Frag6]},
            defrag_fpbuffer(1, Buffer6)
        ),
        ?_assertEqual(
            {3, [ifrag(Frag6)], [Frag1]},
            defrag_fpbuffer(1, Buffer7)
        )
    ].

merge_quic_datalist_test_() ->
    Frag0 = #quic_data{offset = 0, size = 1, flags = ?QUIC_RECEIVE_FLAG_0_RTT, bin = <<1>>},
    Frag1 = #quic_data{offset = 1, size = 2, bin = <<2, 3>>},
    Frag3 = #quic_data{offset = 3, size = 3, bin = <<4, 5, 6>>},
    Frag6 = #quic_data{
        offset = 6, size = 6, flags = ?QUIC_RECEIVE_FLAG_FIN, bin = <<7, 8, 9, 10, 11, 12>>
    },
    [
        ?_assertEqual({[], 0, 0}, merge_quic_datalist([])),
        ?_assertEqual({[<<1>>], 1, ?QUIC_RECEIVE_FLAG_0_RTT}, merge_quic_datalist([Frag0])),
        ?_assertEqual(
            {[<<1>>, <<2, 3>>], 3, ?QUIC_RECEIVE_FLAG_0_RTT}, merge_quic_datalist([Frag0, Frag1])
        ),
        ?_assertEqual({[<<2, 3>>, <<4, 5, 6>>], 5, 0}, merge_quic_datalist([Frag1, Frag3])),
        ?_assertEqual(
            {[<<7, 8, 9, 10, 11, 12>>], 6, ?QUIC_RECEIVE_FLAG_FIN}, merge_quic_datalist([Frag6])
        ),
        ?_assertEqual(
            {[<<2, 3>>, <<4, 5, 6>>, <<7, 8, 9, 10, 11, 12>>], 11, ?QUIC_RECEIVE_FLAG_FIN},
            merge_quic_datalist([Frag1, Frag3, Frag6])
        ),
        ?_assertEqual(
            {
                [<<1>>, <<2, 3>>, <<4, 5, 6>>, <<7, 8, 9, 10, 11, 12>>],
                12,
                ?QUIC_RECEIVE_FLAG_FIN bor ?QUIC_RECEIVE_FLAG_0_RTT
            },
            merge_quic_datalist([Frag0, Frag1, Frag3, Frag6])
        )
    ].
% TEST
-endif.
