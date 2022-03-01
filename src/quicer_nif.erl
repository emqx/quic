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
        , reg_close/0
        , listen/2
        , close_listener/1
        , async_connect/3
        , async_accept/2
        , async_handshake/1
        , async_shutdown_connection/3
        , async_close_connection/1
        , async_accept_stream/2
        , start_stream/2
        , send/3
        , recv/2
        , send_dgram/3
        , async_close_stream/3
        , sockname/1
        , getopt/3
        , setopt/4
        , controlling_process/2
        ]).

-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

-on_load(init/0).

-include_lib("kernel/include/file.hrl").
-include("quicer.hrl").
-include("quicer_types.hrl").

-spec init() -> ok.
init() ->
  NifName = "libquicer_nif",
  {ok, Niflib} = locate_lib(code:priv_dir(quicer), NifName),
  ok = erlang:load_nif(Niflib, 0).


-spec open_lib() ->
        {ok, true}  | %% opened
        {ok, false} | %% already opened
        {ok, debug} | %% opened with lttng debug library loaded (if present)
        {error, open_failed, atom_reason()}.
open_lib() ->
  LibFile = case locate_lib(code:priv_dir(quicer), "libmsquic.lttng.so") of
              {ok, File} ->
                File;
              {error, _} ->
                code:priv_dir(quicer)
            end,
  open_lib(LibFile).

open_lib(_LttngLib) ->
  erlang:nif_error(nif_library_not_loaded).

-spec close_lib() -> ok.
close_lib() ->
  erlang:nif_error(nif_library_not_loaded).


-spec reg_open() -> ok.
reg_open() ->
  erlang:nif_error(nif_library_not_loaded).

-spec reg_close() -> ok.
reg_close() ->
  erlang:nif_error(nif_library_not_loaded).

-spec listen(listen_on(), listen_opts()) ->
        {ok, listener_handler()} |
        {error, listener_open_error,  atom_reason()} |
        {error, listener_start_error, atom_reason()}.
listen(_ListenOn, _Options) ->
  erlang:nif_error(nif_library_not_loaded).

-spec close_listener(listener_handler()) -> ok.
close_listener(_Listener) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_connect(hostname(), inet:port_number(), conn_opts()) ->
        {ok, connection_handler()} |
        {error, conn_open_error | config_error | conn_start_error}.
async_connect(_Host, _Port, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_accept(listener_handler(), acceptor_opts()) ->
        {ok, listener_handler()} |
        {error, badarg | param_error | not_enough_mem | badpid}.
async_accept(_Listener, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_handshake(connection_handler()) ->
        ok | {error, badarg | atom_reason()}.
async_handshake(_Connection) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_shutdown_connection(connection_handler(), conn_close_flag(), app_errno()) ->
        ok | {error, badarg}.
async_shutdown_connection(_Conn, _Flags, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_close_connection(connection_handler()) ->
        ok | {error, badarg}.
async_close_connection(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_accept_stream(connection_handler(), stream_opts()) ->
        {ok, connection_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead}.
async_accept_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec start_stream(connection_handler(), stream_opts()) ->
        {ok, stream_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead | not_enough_mem} |
        {error, stream_open_error, atom_reason()} |
        {error, stream_start_error, atom_reason()}.
start_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec send(stream_handler(), iodata(), send_flags()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(_Stream, _Data, _Flags) ->
  erlang:nif_error(nif_library_not_loaded).

-spec recv(stream_handler(), non_neg_integer()) ->
        {ok, binary()}     |
        {ok, not_ready}     |
        {error, badarg | einval | closed}.
recv(_Stream, _Len) ->
  erlang:nif_error(nif_library_not_loaded).

-spec send_dgram(connection_handler(), iodata(), send_flags()) ->
  {ok, BytesSent :: pos_integer()} |
  {error, badarg | not_enough_memory | closed} |
  {error, dgram_send_error, atom_reason()}.
send_dgram(_Conn, _Data, _Flags) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_close_stream(stream_handler(), stream_close_flags(), app_errno()) ->
        ok |
        {error, badarg | atom_reason()}.
async_close_stream(_Stream, _Flags, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec sockname(connection_handler() | stream_handler()) ->
        {ok, {inet:ip_address(), inet:port_number()}} |
        {error, badarg | sockname_error}.
sockname(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

-spec getopt(handler(), optname(), optlevel()) ->
        not_found | %% `optname' not found, or wrong `optlevel' must be a bug.
        {ok, conn_settings()}   | %% when optname = param_conn_settings
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.

getopt(_Handle, _Optname, _IsRaw) ->
  erlang:nif_error(nif_library_not_loaded).

-spec setopt(handler(), optname(), any(), optlevel()) ->
        ok |
        {error, badarg | param_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
setopt(_Handle, _Opt, _Value, _Level) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_conn_rid(connection_handler()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_conn_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_stream_rid(stream_handler()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_stream_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec controlling_process(connection_handler() | stream_handler(), pid()) ->
        ok |
        {error, closed | badarg | owner_dead | not_owner}.
controlling_process(_H, _P) ->
  erlang:nif_error(nif_library_not_loaded).

%% Internals
-spec locate_lib(file:name(), file:name()) ->
        {ok, file:filename()} | {error, not_found}.
locate_lib(PrivDir, LibName) ->
  case file:read_file_info(PrivDir) of
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
