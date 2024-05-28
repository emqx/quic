%%--------------------------------------------------------------------
%% Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(prop_stream_sig_queue).
-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").
-include("prop_quic_types.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%
prop_buffer_sig_err_none() ->
    ?FORALL(
        {#prop_handle{handle = S, destructor = Destructor}, Pid, Term},
        {valid_stream(), pid(), term()},
        begin
            Res = quicer_nif:mock_buffer_sig(S, Pid, Term),
            Destructor(),
            Res == {error, none}
        end
    ).

prop_enable_sig_queue() ->
    ?FORALL(
        #prop_handle{type = stream, handle = S, destructor = Destructor},
        valid_stream(),
        begin
            ok = quicer:setopt(S, active, 100),
            ok = quicer_nif:enable_sig_buffer(S),
            Res = quicer:getopt(S, active),
            Destructor(),
            Res == {ok, false}
        end
    ).

prop_buffer_sig_success() ->
    ?FORALL(
        {#prop_handle{handle = S, destructor = Destructor}, Pid, Term},
        {valid_stream(), pid(), term()},
        begin
            ok = quicer_nif:enable_sig_buffer(S),
            Res = quicer_nif:mock_buffer_sig(S, Pid, Term),
            Destructor(),
            Res == ok
        end
    ).

prop_flush_buffered_sig_no_owner_change() ->
    ?FORALL(
        {#prop_handle{handle = S, destructor = Destructor}, Pid, TermList},
        {valid_stream(), pid(), list(term())},
        begin
            ok = quicer_nif:enable_sig_buffer(S),
            Ref = erlang:make_ref(),
            lists:foreach(
                fun(Term) ->
                    quicer_nif:mock_buffer_sig(S, Pid, {Ref, Term})
                end,
                TermList
            ),
            ok = quicer_nif:flush_stream_buffered_sigs(S),
            Destructor(),
            Rcvd = receive_n(length(TermList), Ref),
            Rcvd == TermList
        end
    ).

prop_flush_buffered_sig_success() ->
    ?FORALL(
        {#prop_handle{handle = S, destructor = Destructor}, Pid, TermList},
        {valid_stream(), pid(), list(integer())},
        begin
            ok = quicer_nif:enable_sig_buffer(S),
            Ref = erlang:make_ref(),
            lists:foreach(
                fun(Term) ->
                    ok = quicer_nif:mock_buffer_sig(S, Pid, {Ref, Term})
                end,
                TermList
            ),
            ok = quicer:controlling_process(S, self()),
            {ok, NewOwner} = quicer:get_stream_owner(S),
            NewOwner = self(),
            %% assert already flushed by quicer:controlling_process/2
            {error, none} = quicer_nif:flush_stream_buffered_sigs(S),
            Res = receive_n(length(TermList), Ref),
            Destructor(),
            Res == TermList
        end
    ).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%
receive_n(N, Ref) ->
    receive_n(N, Ref, []).
receive_n(0, _Ref, Acc) ->
    lists:reverse(Acc);
receive_n(N, Ref, Acc) ->
    receive
        {Ref, X} ->
            receive_n(N - 1, Ref, [X | Acc]);
        {quic, _, _, _} = _Drop ->
            receive_n(N, Ref, Acc)
    after 500 ->
        {timeout, N}
    end.

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
valid_stream() -> quicer_prop_gen:valid_stream_handle().

pid() ->
    quicer_prop_gen:pid().
