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

-export_type([ cb_ret/0
             ]).

-type cb_state() :: term().
-type cb_ret() :: {ok, cb_state()}                    %% ok and update cb_state
                | {error, Reason::term(), cb_state()} %% error handling per callback
                | {hibernate, cb_state()}           %% ok but also hibernate process
                | {{continue, Continue :: term()}, cb_state()}  %% split callback work with Continue
                | {timeout(), cb_state()}           %% ok but also hibernate process
                | {stop, Reason :: term(), cb_state()}.            %% terminate with reason

-export([default_cb_ret/2]).

-spec default_cb_ret(cb_ret(), State::term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), timeout() | hibernate | {continue, term()}} |
          {stop, Reason :: term(), NewState :: term()}.
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
    {stop, Reason, State#{callback_state := NewCBState}}.
