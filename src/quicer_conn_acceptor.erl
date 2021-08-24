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
-module(quicer_conn_acceptor).
-include_lib("snabbkaffe/include/snabbkaffe.hrl").

-behaviour(gen_server).

%% API
-export([start_link/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-record(state, { listener :: quicer:listener_handler()
               , sup :: pid()
               , conn = undefined
               , opts :: {quicer_listener:listener_opts(),
                          conn_opts(),
                          quicer_steam:stream_opts()}
               , callback :: module()
               , callback_state :: map()
               , slow_start :: boolean()
               }).

-type conn_opts() :: map().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Listener::quicer:listener_handler(),
                 ConnOpts :: map(), Sup :: pid()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Listener, ConnOpts, Sup) ->
    gen_server:start_link(?MODULE, [Listener, ConnOpts, Sup], []).

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
init([Listener, {LOpts, COpts, SOpts}, Sup]) when is_list(COpts) ->
    init([Listener, {LOpts, maps:from_list(COpts), SOpts}, Sup]);
init([Listener, {_, #{conn_callback := CallbackModule} = COpts, SOpts} = Opts, Sup]) ->
    process_flag(trap_exit, true),
    %% Async Acceptor
    {ok, Listener} = quicer_nif:async_accept(Listener, COpts),
    {ok, #state{ listener = Listener
               , callback = CallbackModule
               , callback_state = CallbackModule:init(COpts#{stream_opts => SOpts})
               , opts = Opts
               , slow_start = not maps:get(fast_conn, COpts, false)
               , sup = Sup}}.

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
handle_info({quic, new_conn, C},
            #state{callback = M, sup = Sup, callback_state = CBState} = State) ->
    ?tp(quic_new_conn, #{module=>?MODULE, conn=>C}),
    %% I become the connection owner, I should start an new acceptor.
    supervisor:start_child(Sup, [Sup]),
    {ok, NewCBState} = M:new_conn(C, CBState),
    {noreply, State#state{conn = C, slow_start = true, callback_state = NewCBState} };

handle_info({quic, connected, C}, #state{ slow_start = false
                                        , callback = M
                                        , sup = Sup
                                        , callback_state = CbState
                                        } = State) ->
    ?tp(quic_connected, #{module=>?MODULE, conn=>C}),
    %% I become the connection owner, I should start an new acceptor.
    supervisor:start_child(Sup, [Sup]),
    NewCBState = M:connected(C, CbState#{slow_start => false}),
    {noreply, State#state{conn = C, callback_state = NewCBState} };

handle_info({quic, connected, C}, #state{ slow_start = true
                                        , conn = C
                                        , callback = M
                                        , callback_state = CbState} = State) ->
    ?tp(quic_connected_slow, #{module=>?MODULE, conn=>C}),
    {ok, NewCBState} = M:connected(C, CbState#{slow_start => true} ),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({'EXIT', _Pid, {shutdown, normal}}, State) ->
    %% exit signal from stream
    {noreply, State};

handle_info({'EXIT', _Pid, {shutdown, _Other}}, State) ->
    %% @todo
    {noreply, State};

handle_info({'EXIT', _Pid, normal}, State) ->
    %% @todo
    {noreply, State};

handle_info({quic, shutdown, C}, #state{conn = C, callback = M,
                                        callback_state = CBState} = State) ->
    ?tp(quic_shutdown, #{module=>?MODULE}),
    M:shutdown(C, CBState),
    {noreply, State};

handle_info({quic, closed, C}, #state{conn = C} = State) ->
    %% @todo, connection closed
    ?tp(quic_closed, #{module=>?MODULE}),
    {stop, normal, State}.

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
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
                  State :: term(),
                  Extra :: term()) -> {ok, NewState :: term()} |
          {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
                    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
    Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
