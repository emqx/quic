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
