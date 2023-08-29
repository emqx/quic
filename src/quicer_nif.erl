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
-export([ open_lib/0
        , close_lib/0
        , reg_open/0
        , reg_open/1
        , reg_close/0
        , new_registration/2
        , shutdown_registration/1
        , shutdown_registration/3
        , listen/2
        , start_listener/3
        , stop_listener/1
        , close_listener/1
        , async_connect/3
        , async_accept/2
        , async_handshake/1
        , async_shutdown_connection/3
        , async_accept_stream/2
        , start_stream/2
        , csend/4
        , send/3
        , recv/2
        , send_dgram/3
        , async_shutdown_stream/3
        , sockname/1
        , getopt/3
        , setopt/4
        , controlling_process/2
        , peercert/1
        ]).

-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

%% For tests only
-export([open_connection/0]).

-on_load(init/0).

-include_lib("kernel/include/file.hrl").
-include("quicer.hrl").
-include("quicer_types.hrl").

-spec init() -> ok.
init() ->
  NifName = "libquicer_nif",
  {ok, Niflib} = locate_lib(priv_dir(), NifName),
  ok = erlang:load_nif(Niflib, 0),
  %% It could cause segfault if MsQuic library is not opened nor registered.
  %% here we have added dummy calls, and it should cover most of cases
  %% unless caller wants to call erlang:load_nif/1 and then call quicer_nif
  %% without opened library to suicide.
  %%
  %% Note, we could do same dummy calls in nif instead but it might mess up the reference counts.
  {ok, _} = open_lib(),
  %% dummy reg open
  case reg_open() of
    ok -> ok;
    {error, badarg} ->
      %% already opened
      ok
  end.

-spec open_lib() ->
        {ok, true}  | %% opened
        {ok, false} | %% already opened
        {ok, debug} | %% opened with lttng debug library loaded (if present)
        {error, open_failed, atom_reason()}.
open_lib() ->
  LibFile = case locate_lib(priv_dir(), "libmsquic.lttng.so") of
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


-spec new_registration(Name::string(), registration_profile()) ->
          {ok, reg_handle()} | {error, atom_reason()}.
new_registration(_Name, _Profile) ->
  erlang:nif_error(nif_library_not_loaded).

-spec shutdown_registration(reg_handle()) -> ok | {error | badarg}.
shutdown_registration(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec shutdown_registration(reg_handle(), IsSilent::boolean(), ErrorCode::uint64())
                           -> ok | {error | badarg}.
shutdown_registration(_Handle, _IsSilent, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec listen(listen_on(), listen_opts()) ->
        {ok, listener_handle()} |
        {error, listener_open_error,  atom_reason()} |
        {error, listener_start_error, atom_reason()}.
listen(_ListenOn, _Options) ->
  erlang:nif_error(nif_library_not_loaded).

-spec start_listener(listener_handle(), listen_on(), listen_opts()) -> ok | {error, closed | badarg}.
start_listener(_Listener, _ListenOn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec close_listener(listener_handle()) -> ok | {error, closed | badarg}.
close_listener(_Listener) ->
  erlang:nif_error(nif_library_not_loaded).

-spec stop_listener(listener_handle()) -> ok | {error, closed | badarg}.
stop_listener(_Listener) ->
  erlang:nif_error(nif_library_not_loaded).

-spec open_connection() -> {ok, connection_handle()} | {error, atom_reason()}.
open_connection() ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_connect(hostname(), inet:port_number(), conn_opts()) ->
        {ok, connection_handle()} |
        {error, conn_open_error | config_error | conn_start_error} |
          {error, not_found, any()}.
async_connect(_Host, _Port, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_accept(listener_handle(), acceptor_opts()) ->
        {ok, listener_handle()} |
        {error, badarg | param_error | not_enough_mem | badpid}.
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
        {ok, connection_handle()} |
        {error, badarg | internal_error | bad_pid | owner_dead}.
async_accept_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec start_stream(connection_handle(), stream_opts()) ->
        {ok, stream_handle()} |
        {error, badarg | internal_error | bad_pid | owner_dead | not_enough_mem} |
        {error, stream_open_error, atom_reason()} |
        {error, stream_start_error, atom_reason()}.
start_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).


-spec csend(connection_handle(), iodata(), stream_opts(), send_flags()) ->
          {ok, BytesSent :: pos_integer()}          |
          {error, badarg | not_enough_mem | closed} |
          {error, stream_send_error, atom_reason()}.
csend(_Conn, _Data, _Opts, _Flags) ->
    erlang:nif_error(nif_library_not_loaded).

-spec send(stream_handle(), iodata(), send_flags()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(_Stream, _Data, _Flags) ->
  erlang:nif_error(nif_library_not_loaded).

-spec recv(stream_handle(), non_neg_integer()) ->
        {ok, binary()}     |
        {ok, not_ready}     |
        {error, badarg | einval | closed}.
recv(_Stream, _Len) ->
  erlang:nif_error(nif_library_not_loaded).

-spec send_dgram(connection_handle(), iodata(), send_flags()) ->
  {ok, BytesSent :: pos_integer()} |
  {error, badarg | not_enough_memory | closed} |
  {error, dgram_send_error, atom_reason()}.
send_dgram(_Conn, _Data, _Flags) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_shutdown_stream(stream_handle(), stream_shutdown_flags(), app_errno()) ->
        ok |
        {error, badarg | atom_reason()}.
async_shutdown_stream(_Stream, _Flags, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec sockname(connection_handle() | stream_handle()) ->
        {ok, {inet:ip_address(), inet:port_number()}} |
        {error, badarg | sockname_error}.
sockname(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

-spec getopt(handle(), optname(), optlevel()) ->
        not_found | %% `optname' not found, or wrong `optlevel' must be a bug.
        {ok, any()}   | %% when optname = param_conn_settings
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.

getopt(_Handle, _Optname, _IsRaw) ->
  erlang:nif_error(nif_library_not_loaded).

-spec setopt(handle(), optname(), any(), optlevel()) ->
        ok |
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
setopt(_Handle, _Opt, _Value, _Level) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_conn_rid(connection_handle()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_conn_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_stream_rid(stream_handle()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_stream_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec controlling_process(connection_handle() | stream_handle(), pid()) ->
        ok |
        {error, closed | badarg | owner_dead | not_owner}.
controlling_process(_H, _P) ->
  erlang:nif_error(nif_library_not_loaded).

-spec peercert(connection_handle()  | stream_handle()) ->
        {ok, Cert:: public_key:der_encoded()} | {error, any()}.
peercert(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

%% Internals
-spec locate_lib(file:name(), file:name()) ->
        {ok, file:filename()} | {error, not_found}.
locate_lib(PrivDir, LibName) ->
  case prim_file:read_file_info(PrivDir) of
    {ok, #file_info{type = directory}} ->
      {ok, filename:join(PrivDir, LibName)};
    {error, enotdir} -> %% maybe escript,
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
