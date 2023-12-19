%%--------------------------------------------------------------------
%% Copyright (c) 2022 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-export([default_cb_ret/2]).

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
