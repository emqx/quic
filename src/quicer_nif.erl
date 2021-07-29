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
        , async_close_connection/1
        , async_accept_stream/2
        , start_stream/2
        , async_send/2
        , recv/2
        , async_close_stream/1
        , sockname/1
        , getopt/3
        , setopt/3
        ]).

-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

-on_load(init/0).

-include_lib("kernel/include/file.hrl").

init() ->
  NifName = "libquicer_nif",
  {ok, Niflib} = locate_lib(code:priv_dir(quicer), NifName),
  ok = erlang:load_nif(Niflib, 0).

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

close_lib() ->
  erlang:nif_error(nif_library_not_loaded).

reg_open() ->
  erlang:nif_error(nif_library_not_loaded).

reg_close() ->
  erlang:nif_error(nif_library_not_loaded).

listen(_Port, _Options)->
  erlang:nif_error(nif_library_not_loaded).

close_listener(_Listener) ->
  erlang:nif_error(nif_library_not_loaded).

async_connect(_Host, _Port, _Opts)->
  erlang:nif_error(nif_library_not_loaded).

async_accept(_Listener, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

async_handshake(_Connection)->
  erlang:nif_error(nif_library_not_loaded).

async_close_connection(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

async_accept_stream(_Conn, _Opts)->
  erlang:nif_error(nif_library_not_loaded).

start_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

async_send(_Stream, _Data) ->
  erlang:nif_error(nif_library_not_loaded).

recv(_Stream, _Len) ->
  erlang:nif_error(nif_library_not_loaded).

async_close_stream(_Stream) ->
  erlang:nif_error(nif_library_not_loaded).

sockname(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

getopt(_Handle, _Optname, _IsRaw) ->
  erlang:nif_error(nif_library_not_loaded).

setopt(_Handle, _Opt, _Value) ->
  erlang:nif_error(nif_library_not_loaded).

get_conn_rid(_Handle)->
  erlang:nif_error(nif_library_not_loaded).

get_stream_rid(_Handle)->
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
