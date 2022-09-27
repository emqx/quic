%%--------------------------------------------------------------------
%% Copyright (c) 2021 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(quicer_echo_server_stream_callback).
-export([ new_stream/2
        , handle_call/4
        , handle_stream_data/4
        , shutdown/1
        , peer_send_aborted/3
        ]
       ).

new_stream(_,_) ->
    InitState = #{sent_bytes => 0},
    {ok, InitState}.

handle_stream_data(Stream, Bin, _Opts, #{sent_bytes := Cnt} = State) ->
    {ok, Size} = quicer:send(Stream, Bin),
    {ok, State#{ sent_bytes => Cnt + Size }}.

shutdown(Stream) ->
    ok = quicer:close_stream(Stream).

peer_send_aborted(Stream, State, _Reason)->
    quicer:close_stream(Stream),
    State.

handle_call(_Stream, _Request, _Opts, _CBState) ->
    ok.
