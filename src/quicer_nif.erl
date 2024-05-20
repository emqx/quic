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
-module(quicer_nif).
-export([
    open_lib/0,
    close_lib/0,
    reg_open/0,
    reg_open/1,
    reg_close/0,
    new_registration/2,
    shutdown_registration/1,
    shutdown_registration/3,
    close_registration/1,
    get_registration_name/1,
    listen/2,
    start_listener/3,
    stop_listener/1,
    close_listener/1,
    async_connect/3,
    async_accept/2,
    async_handshake/1,
    async_shutdown_connection/3,
    async_accept_stream/2,
    start_stream/2,
    csend/4,
    send/3,
    recv/2,
    send_dgram/3,
    async_shutdown_stream/3,
    sockname/1,
    getopt/3,
    setopt/4,
    controlling_process/2,
    controlling_process/3,
    peercert/1,
    lock_stream/1,
    unlock_stream/1
]).

-export([
    get_conn_rid/1,
    get_stream_rid/1
]).

%% For tests only
-export([
    open_connection/0,
    open_connection/1,
    get_listeners/0,
    get_listeners/1,
    get_connections/0,
    get_connections/1,
    get_conn_owner/1,
    get_stream_owner/1,
    get_listener_owner/1
]).

-export([abi_version/0]).

%% for test
-export([init/1]).

-export_type([
    abi_version/0,
    new_registration/0,
    shutdown_registration/0,
    close_registration/0,
    get_registration_name/0,
    get_listeners/0,
    get_connections/0,
    get_owner/0,

    reg_handle/0
]).

%% NIF fuction return types
-type abi_version() :: integer().
-type new_registration() :: {ok, reg_handle()} | {error, atom_reason()}.
-type shutdown_registration() :: ok | {error, badarg}.
-type close_registration() :: ok | {error, badarg}.
-type get_registration_name() :: {ok, string()} | {error, badarg}.
-type get_listeners() :: [listener_handle()].
-type get_connections() :: [connection_handle()].
-type get_owner() :: {ok, pid()} | {error, undefined | badarg}.

%% @NOTE: In embedded mode, first all modules are loaded. Then all on_load functions are called.
-on_load(init/0).

-include_lib("kernel/include/file.hrl").
-include("quicer.hrl").
-include("quicer_types.hrl").
-include("quicer_vsn.hrl").

-spec abi_version() -> abi_version().
abi_version() ->
    ?QUICER_ABI_VERSION.

-spec init() -> ok.
init() ->
    ABIVsn =
        case persistent_term:get({'_quicer_overrides_', abi_version}, undefined) of
            undefined -> abi_version();
            Vsn -> Vsn
        end,
    init(ABIVsn).

init(ABIVsn) ->
    NifName = "libquicer_nif",
    {ok, Niflib} = locate_lib(priv_dir(), NifName),
    case erlang:load_nif(Niflib, ABIVsn) of
        ok ->
            %% It could cause segfault if MsQuic library is not opened nor registered.
            %% here we have added dummy calls, and it should cover most of cases
            %% unless caller wants to call erlang:load_nif/1 and then call quicer_nif
            %% without opened library to suicide.
            %%
            %% Note, we could do same dummy calls in nif instead but it might mess up the reference counts.
            {ok, _} = open_lib(),
            %% dummy reg open
            case reg_open() of
                ok ->
                    ok;
                {error, badarg} ->
                    %% already opened
                    ok
            end;
        {error, _Reason} = Res ->
            Res
    end.
-spec open_lib() ->
    %% opened
    {ok, true}
    %% already opened
    | {ok, false}
    %% opened with lttng debug library loaded (if present)
    | {ok, debug}
    | {error, open_failed, atom_reason()}.
open_lib() ->
    LibFile =
        case locate_lib(priv_dir(), "lib/libmsquic.lttng.so") of
            {ok, File} ->
                File;
            {error, _} ->
                priv_dir()
        end,
    open_lib(LibFile).

open_lib(_LttngLib) ->
    erlang:nif_error(nif_library_not_loaded).

-spec close_lib() -> ok.
close_lib() ->
    erlang:nif_error(nif_library_not_loaded).

-spec reg_open() -> ok | {error, badarg}.
reg_open() ->
    erlang:nif_error(nif_library_not_loaded).

-spec reg_open(execution_profile()) -> ok | {error, badarg}.
reg_open(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec reg_close() -> ok.
reg_close() ->
    erlang:nif_error(nif_library_not_loaded).

-spec new_registration(Name :: string(), Profile :: registration_profile()) -> new_registration().
new_registration(_Name, _Profile) ->
    erlang:nif_error(nif_library_not_loaded).

-spec shutdown_registration(reg_handle()) -> shutdown_registration().
shutdown_registration(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec shutdown_registration(reg_handle(), IsSilent :: boolean(), ErrorCode :: uint64()) ->
    shutdown_registration().
shutdown_registration(_Handle, _IsSilent, _ErrorCode) ->
    erlang:nif_error(nif_library_not_loaded).

-spec close_registration(reg_handle()) -> close_registration().
close_registration(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_registration_name(reg_handle()) -> get_registration_name().
get_registration_name(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec listen(listen_on(), listen_opts()) ->
    {ok, listener_handle()}
    | {error, listener_open_error, atom_reason()}
    | {error, listener_start_error, atom_reason()}.
listen(_ListenOn, _Options) ->
    erlang:nif_error(nif_library_not_loaded).

-spec start_listener(listener_handle(), listen_on(), listen_opts()) ->
    ok | {error, closed | badarg}.
start_listener(_Listener, _ListenOn, _Opts) ->
    erlang:nif_error(nif_library_not_loaded).

-spec close_listener(listener_handle()) -> ok | {error, closed | badarg}.
close_listener(_Listener) ->
    erlang:nif_error(nif_library_not_loaded).

-spec stop_listener(listener_handle()) -> ok | {error, closed | listener_stopped | badarg}.
stop_listener(_Listener) ->
    erlang:nif_error(nif_library_not_loaded).

-spec open_connection() -> {ok, connection_handle()} | {error, atom_reason()}.
open_connection() ->
    erlang:nif_error(nif_library_not_loaded).

-spec open_connection(#{quic_registration => reg_handle()}) ->
    {ok, connection_handle()} | {error, atom_reason()}.
open_connection(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_connect(hostname(), inet:port_number(), conn_opts()) ->
    {ok, connection_handle()}
    | {error, conn_open_error | config_error | conn_start_error}
    | {error, not_found, any()}.
async_connect(_Host, _Port, _Opts) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_accept(listener_handle(), acceptor_opts()) ->
    {ok, listener_handle()}
    | {error, badarg | param_error | not_enough_mem | badpid}.
async_accept(_Listener, _Opts) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_handshake(connection_handle()) ->
    ok | {error, badarg | atom_reason()}.
async_handshake(_Connection) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_shutdown_connection(connection_handle(), conn_shutdown_flag(), app_errno()) ->
    ok | {error, badarg}.
async_shutdown_connection(_Conn, _Flags, _ErrorCode) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_accept_stream(connection_handle(), stream_opts()) ->
    {ok, connection_handle()}
    | {error, badarg | internal_error | bad_pid | owner_dead}.
async_accept_stream(_Conn, _Opts) ->
    erlang:nif_error(nif_library_not_loaded).

-spec start_stream(connection_handle(), stream_opts()) ->
    {ok, stream_handle()}
    | {error, badarg | internal_error | bad_pid | owner_dead | not_enough_mem}
    | {error, stream_open_error, atom_reason()}
    | {error, stream_start_error, atom_reason()}.
start_stream(_Conn, _Opts) ->
    erlang:nif_error(nif_library_not_loaded).

-spec csend(connection_handle(), iodata(), stream_opts(), send_flags()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
csend(_Conn, _Data, _Opts, _Flags) ->
    erlang:nif_error(nif_library_not_loaded).

-spec send(stream_handle(), iodata(), send_flags()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, badarg | not_enough_mem | closed}
    | {error, stream_send_error, atom_reason()}.
send(_Stream, _Data, _Flags) ->
    erlang:nif_error(nif_library_not_loaded).

-spec recv(stream_handle(), non_neg_integer()) ->
    {ok, binary()}
    | {ok, not_ready}
    | {error, badarg | einval | closed}.
recv(_Stream, _Len) ->
    erlang:nif_error(nif_library_not_loaded).

-spec send_dgram(connection_handle(), iodata(), send_flags()) ->
    {ok, BytesSent :: pos_integer()}
    | {error, badarg | not_enough_memory | closed}
    | {error, dgram_send_error, atom_reason()}.
send_dgram(_Conn, _Data, _Flags) ->
    erlang:nif_error(nif_library_not_loaded).

-spec async_shutdown_stream(stream_handle(), stream_shutdown_flags(), app_errno()) ->
    ok
    | {error, badarg | atom_reason()}.
async_shutdown_stream(_Stream, _Flags, _ErrorCode) ->
    erlang:nif_error(nif_library_not_loaded).

-spec sockname(connection_handle() | stream_handle()) ->
    {ok, {inet:ip_address(), inet:port_number()}}
    | {error, badarg | sockname_error}.
sockname(_Conn) ->
    erlang:nif_error(nif_library_not_loaded).

-spec getopt(handle(), optname(), optlevel()) ->
    %% `optname' not found, or wrong `optlevel' must be a bug.
    not_found
    %% when optname = settings
    | {ok, any()}
    | {error, badarg | param_error | internal_error | not_enough_mem}
    | {error, atom_reason()}.

getopt(_Handle, _Optname, _Level) ->
    erlang:nif_error(nif_library_not_loaded).

-spec setopt(handle(), optname(), any(), optlevel()) ->
    ok
    | {error, badarg | param_error | internal_error | not_enough_mem}
    | {error, atom_reason()}.
setopt(_Handle, _Opt, _Value, _Level) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_conn_rid(connection_handle()) ->
    {ok, non_neg_integer()}
    | {error, badarg | internal_error}.
get_conn_rid(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_stream_rid(stream_handle()) ->
    {ok, non_neg_integer()}
    | {error, badarg | internal_error}.
get_stream_rid(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec controlling_process(connection_handle() | stream_handle(), pid()) ->
    ok
    | {error, closed | badarg | owner_dead | not_owner}.
controlling_process(_H, _P) ->
    erlang:nif_error(nif_library_not_loaded).

-spec controlling_process(connection_handle() | stream_handle(), pid(), boolean()) ->
    ok
    | {error, closed | badarg | owner_dead | not_owner}.
controlling_process(_H, _P, IsLocked) ->
    erlang:nif_error(nif_library_not_loaded).

-spec peercert(connection_handle() | stream_handle()) ->
    {ok, CertDerEncoded :: binary()} | {error, any()}.
peercert(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec lock_stream(stream_handle()) -> ok | {error, badarg}.
lock_stream(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec unlock_stream(stream_handle()) -> ok | {error, badarg}.
unlock_stream(_Handle) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_conn_owner(connection_handle()) -> get_owner().
get_conn_owner(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_stream_owner(connection_handle()) -> get_owner().
get_stream_owner(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_listener_owner(listener_handle()) -> get_owner().
get_listener_owner(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_listeners() -> get_listeners().
get_listeners() ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_listeners(reg_handle()) -> get_listeners().
get_listeners(_) ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_connections() -> [connection_handle()].
get_connections() ->
    erlang:nif_error(nif_library_not_loaded).

-spec get_connections(reg_handle()) -> [connection_handle()] | {error, badarg}.
get_connections(_RegHandle) ->
    erlang:nif_error(nif_library_not_loaded).

%% Internals
-spec locate_lib(file:name(), file:name()) ->
    {ok, file:filename()} | {error, not_found}.
locate_lib(PrivDir, LibName) ->
    case prim_file:read_file_info(PrivDir) of
        {ok, #file_info{type = directory}} ->
            {ok, filename:join(PrivDir, LibName)};
        %% maybe escript,
        {error, enotdir} ->
            Escript = filename:dirname(filename:dirname(PrivDir)),
            case file:read_file_info(Escript) of
                {ok, #file_info{type = regular}} ->
                    %% try locate the file in same dir of escript
                    {ok, filename:join(filename:dirname(Escript), LibName)};
                _ ->
                    {error, not_found}
            end
    end.

priv_dir() ->
    case code:priv_dir(quicer) of
        {error, bad_name} ->
            "priv";
        Dir ->
            Dir
    end.
