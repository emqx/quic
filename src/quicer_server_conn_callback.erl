%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(quicer_server_conn_callback).

-export([ init/1
        , new_conn/2
        , resumed/3
        , connected/2
        , shutdown/2
        ]).

init(ConnOpts) when is_list(ConnOpts) ->
    init(maps:from_list(ConnOpts));
init(ConnOpts) when is_map(ConnOpts) ->
    ConnOpts.

new_conn(Conn, #{stream_opts := SOpts} = S) ->
    quicer_stream:start_link(Conn, SOpts),
    ok = quicer:async_handshake(Conn),
    {ok, S}.

resumed(Conn, Data, #{resumed_callback := ResumeFun} = S)
  when is_function(ResumeFun) ->
    ResumeFun(Conn, Data, S);
resumed(_Conn, _Data, S) ->
    {ok, S}.

connected(Conn, #{slow_start := false, stream_opts := SOpts} = S) ->
    quicer_stream:start_link(Conn, SOpts),
    {ok, S};
connected(_Conn, S) ->
    {ok, S}.

shutdown(Conn, S) ->
    quicer:async_close_connection(Conn),
    {ok, S}.
