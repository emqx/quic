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
-module(quicer_listener).

-behaviour(gen_server).

%% API
-export([start_link/3,
         start_listener/3,
         stop_listener/1
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-record(state, { name :: atom()
               , listener :: quicer:listener_handle()
               , conn_sup :: pid()
               , alpn :: [string()]
               }).

-type listener_name() :: atom().
-type listen_on() :: inet:port_number() | string(). %% "127.0.0.1:8080"
-type listener_opts() :: map().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Name :: listener_name(),
                 ListenOn :: listen_on(),
                 Options ::
                   { listener_opts()
                   , quicer_connection:opts()
                   , quicer_stream:stream_opts()
                   }
                ) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Name, ListenOn, Opts) ->
    gen_server:start_link({local, Name}, ?MODULE, [Name, ListenOn, Opts], []).

start_listener(Name, ListenOn, Options) ->
    quicer_listener_sup:start_listener(Name, ListenOn, Options).

stop_listener(Name) ->
    quicer_listener_sup:stop_listener(Name).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) -> {ok, State :: term()} |
          {ok, State :: term(), Timeout :: timeout()} |
          {ok, State :: term(), hibernate} |
          {stop, Reason :: term()} |
          ignore.

init([Name, ListenOn, {LOpts, COpts, SOpts}]) when is_list(LOpts) ->
    init([Name, ListenOn, {maps:from_list(LOpts), COpts, SOpts}]);
init([Name, ListenOn, { #{conn_acceptors :=  N, alpn := Alpn} = LOpts,
                        _COpts, _SOpts} = Opts]) ->
    process_flag(trap_exit, true),
    {ok, L} = quicer:listen(ListenOn, maps:without([conn_acceptors], LOpts)),
    {ok, ConnSup} = supervisor:start_link(quicer_conn_acceptor_sup, [L, Opts]),
    [{ok, _} = supervisor:start_child(ConnSup, [ConnSup]) || _ <- lists:seq(1, N)],
    {ok, #state{ name = Name
               , listener = L
               , conn_sup = ConnSup
               , alpn = Alpn
               }}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
          {reply, Reply :: term(), NewState :: term()} |
          {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
          {reply, Reply :: term(), NewState :: term(), hibernate} |
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
          {stop, Reason :: term(), NewState :: term()}.
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_cast(Request :: term(), State :: term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: term(), NewState :: term()}.
handle_cast(_Request, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: normal | term(), NewState :: term()}.
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
                State :: term()) -> any().
terminate(_Reason, #state{listener = L}) ->
    %% nif listener has no owner process so we need to close it explicitly.
    quicer:close_listener(L),
    ok.
