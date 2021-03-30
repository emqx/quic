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
        , close_connection/1
        , async_accept_stream/2
        , start_stream/2
        , send/2
        , close_stream/1
        , sockname/1
        , getopt/3
        , setopt/3
        ]).

-on_load(init/0).

init() ->
  Niflib = filename:join([code:priv_dir(quicer), "libquicer_nif"]),
  ok = erlang:load_nif(Niflib, 0).

open_lib() ->
  open_lib(code:priv_dir(quicer)).

open_lib(_PrivDir) ->
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

close_connection(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

async_accept_stream(_Conn, _Opts)->
  erlang:nif_error(nif_library_not_loaded).

start_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

send(_Stream, _Data) ->
  erlang:nif_error(nif_library_not_loaded).

close_stream(_Stream) ->
  erlang:nif_error(nif_library_not_loaded).

sockname(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

getopt(_Handle, _Optname, _IsRaw) ->
  erlang:nif_error(nif_library_not_loaded).

setopt(_Handle, _Opt, _Value) ->
  erlang:nif_error(nif_library_not_loaded).