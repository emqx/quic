%%--------------------------------------------------------------------
%% Copyright (c) 2022-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(quicer_lib).
-include("quicer_types.hrl").

-export_type([
    cb_ret/0,
    cb_state/0
]).

-type cb_ret() :: cb_ret_noreply() | cb_ret_reply().
-type cb_state() :: term().

-type cb_ret_reply() ::
    {reply, Reply :: term(), cb_state()}
    | {reply, Reply :: term(), cb_state(), action()}
    | cb_ret_stop_reply().

%% ok and update cb_state
-type cb_ret_noreply() ::
    {ok, cb_state()}
    %% error handling per callback
    | {error, Reason :: term(), cb_state()}
    | {action(), cb_state()}
    | cb_ret_stop_noreply().

-type cb_ret_stop_noreply() :: {stop, Reason :: term(), cb_state()}.
-type cb_ret_stop_reply() :: {stop, Reason :: term(), Reply :: term(), cb_state()}.

-type action() :: hibernate | timeout() | {continue, Continue :: term()}.

-export([
    default_cb_ret/2,
    handle_dgram_send_states/1,
    handle_dgram_send_states/3,
    probe/2
]).

-spec default_cb_ret(cb_ret(), State :: term()) ->
    {reply, NewState :: term()}
    | {reply, NewState :: term(), action()}
    | {noreply, NewState :: term()}
    | {noreply, NewState :: term(), action()}
    | {stop, Reason :: term(), Reply :: term(), NewState :: term()}
    | {stop, Reason :: term(), NewState :: term()}.
default_cb_ret({ok, NewCBState}, State) ->
    %% ok
    {noreply, State#{callback_state := NewCBState}};
default_cb_ret({hibernate, NewCBState}, State) ->
    %% hibernate
    {noreply, State#{callback_state := NewCBState}, hibernate};
default_cb_ret({Timeout, NewCBState}, State) when is_integer(Timeout) ->
    %% timeout
    {noreply, State#{callback_state := NewCBState}, Timeout};
default_cb_ret({{continue, _} = Continue, NewCBState}, State) ->
    %% continue
    {noreply, State#{callback_state := NewCBState}, Continue};
default_cb_ret({stop, Reason, NewCBState}, State) ->
    %% stop
    {stop, Reason, State#{callback_state := NewCBState}};
default_cb_ret({reply, Reply, NewCBState, Action}, State) ->
    {reply, Reply, State#{callback_state := NewCBState}, Action};
default_cb_ret({reply, Reply, NewCBState}, State) ->
    {reply, Reply, State#{callback_state := NewCBState}}.

-spec probe(connection_handle(), timeout()) -> probe_res().
probe(Conn, Timeout) ->
    case quicer_nif:send_dgram(Conn, <<>>, _IsSync = 1) of
        {ok, _Len} ->
            handle_dgram_send_states(Conn, probe_dgram_send_cb(), Timeout);
        {error, E} ->
            {error, dgram_send_error, E};
        E ->
            E
    end.

-spec handle_dgram_send_states(connection_handle()) ->
    ok
    | {error,
        dgram_send_canceled
        | dgram_send_unknown
        | dgram_send_lost_discarded}.
handle_dgram_send_states(Conn) ->
    handle_dgram_send_states(init, Conn, default_dgram_suspect_lost_cb(), 5000).

-type lost_suspect_callback() ::
    {fun((connection_handle(), term(), term()) -> term()), term()}
    | {atom(), term()}.
-spec handle_dgram_send_states(connection_handle(), lost_suspect_callback(), timeout()) -> any().
handle_dgram_send_states(Conn, {_CBFun, _CBState} = CB, Timeout) ->
    handle_dgram_send_states(init, Conn, CB, Timeout).

handle_dgram_send_states(init, Conn, {Fun, CallbackState}, Timeout) ->
    receive
        {quic, dgram_send_state, Conn, #{state := ?QUIC_DATAGRAM_SEND_SENT}} ->
            NewCBState = Fun(Conn, ?QUIC_DATAGRAM_SEND_SENT, CallbackState),
            handle_dgram_send_states(sent, Conn, {Fun, NewCBState}, Timeout);
        {quic, dgram_send_state, Conn, #{state := Final}} ->
            Fun(Conn, Final, CallbackState)
    after 5000 ->
        %% @TODO proper test caught this, may fire a bug report to msquic
        Fun(Conn, timeout, CallbackState)
    end;
handle_dgram_send_states(sent, Conn, {Fun, CallbackState}, Timeout) ->
    receive
        {quic, dgram_send_state, Conn, #{state := ?QUIC_DATAGRAM_SEND_LOST_SUSPECT}} ->
            %% Lost suspected, call the callback for the return hits.
            %% however, we still need to wait for the final state.
            NewCBState = Fun(Conn, ?QUIC_DATAGRAM_SEND_LOST_SUSPECT, CallbackState),
            receive
                {quic, dgram_send_state, Conn, #{state := EState}} ->
                    Fun(Conn, EState, NewCBState)
            after Timeout ->
                %% @TODO proper test caught this, may fire a bug report to msquic
                Fun(Conn, timeout, CallbackState)
            end;
        {quic, dgram_send_state, Conn, #{state := Final}} ->
            Fun(Conn, Final, CallbackState)
    after Timeout ->
        %% @TODO proper test caught this, may fire a bug report to msquic
        Fun(Conn, timeout, CallbackState)
    end.

%% Default Callback for Datagram Send lost suspected
default_dgram_suspect_lost_cb() ->
    Fun = fun(_Conn, _, _CallbackState) ->
        %% just return ok, even it is lost, we don't care.
        ok
    end,
    {Fun, undefined}.

probe_dgram_send_cb() ->
    Fun = fun
        (_Conn, ?QUIC_DATAGRAM_SEND_SENT, CallbackState) ->
            CallbackState#probe_state{sent_at = ts_ms()};
        (_Conn, ?QUIC_DATAGRAM_SEND_LOST_SUSPECT, CallbackState) ->
            CallbackState#probe_state{suspect_lost_at = ts_ms()};
        (_Conn, State, CallbackState) ->
            CallbackState#probe_state{
                final_at = ts_ms(),
                final = State
            }
    end,
    {Fun, #probe_state{}}.

ts_ms() ->
    erlang:monotonic_time(millisecond).
