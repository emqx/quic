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
%
-module(quicer_listener_sup).

-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_listener/3,
    stop_listener/1,
    listeners/0,
    listener/1
]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(CHILD_ID(AppName), {quicer_listener, AppName}).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%% @end
%%--------------------------------------------------------------------
-spec start_link() ->
    {ok, Pid :: pid()}
    | {error, {already_started, Pid :: pid()}}
    | {error, {shutdown, term()}}
    | {error, term()}
    | ignore.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_listener(AppName, Port, Options) ->
    supervisor:start_child(?MODULE, chid_spec(AppName, Port, Options)).

stop_listener(AppName) ->
    _ = supervisor:terminate_child(?MODULE, ?CHILD_ID(AppName)),
    supervisor:delete_child(?MODULE, ?CHILD_ID(AppName)).

-spec listeners() -> [{{atom(), integer() | string()}, pid()}].
listeners() ->
    lists:filtermap(
        fun({Id, Child, _Type, _Modules}) ->
            case supervisor:get_childspec(?MODULE, Id) of
                {ok, #{
                    id := {_, Alpn},
                    start := {_M, _F, [Alpn, ListenOn | _]}
                }} ->
                    Res = {{Alpn, ListenOn}, Child},
                    {true, Res};
                _ ->
                    false
            end
        end,
        supervisor:which_children(?MODULE)
    ).

-spec listener(atom() | {atom(), integer() | string()}) -> {ok, pid()} | {error, not_found}.
listener({Name, _ListenOn}) when is_atom(Name) ->
    listener(Name);
listener(Name) when is_atom(Name) ->
    Targets = lists:filtermap(
        fun
            ({?CHILD_ID(Id), Child, _Type, _Modules}) when Id =:= Name ->
                {true, Child};
            (_) ->
                false
        end,
        supervisor:which_children(?MODULE)
    ),
    case Targets of
        [Pid] -> {ok, Pid};
        [] -> {error, not_found}
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart intensity, and child
%% specifications.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) ->
    {ok, {SupFlags :: supervisor:sup_flags(), [ChildSpec :: supervisor:child_spec()]}}
    | ignore.
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10000,
        period => 1
    },
    {ok, {SupFlags, []}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
chid_spec(AppName, ListenOn, Options) ->
    #{
        id => ?CHILD_ID(AppName),
        start => {quicer_listener, start_link, [AppName, ListenOn, Options]},
        restart => transient,
        shutdown => infinity,
        type => supervisor
    }.
