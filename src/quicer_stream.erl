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
-module(quicer_stream).
-include_lib("snabbkaffe/include/snabbkaffe.hrl").

-behaviour(gen_server).

%% API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-record(state, { stream :: quicer:stream_handler()
               , opts :: stream_opts()
               , cbstate :: any()
               }).

-type stream_opts() :: map().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Conn :: quicer:connection_handler(),
                 Opts :: map()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Conn, Opts) ->
    gen_server:start_link(?MODULE, [Conn, Opts], []).

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
init([Conn, SOpts]) when is_list(SOpts) ->
    init([Conn, maps:from_list(SOpts)]);
init([Conn, SOpts]) ->
    process_flag(trap_exit, true),
    {ok, Conn} = quicer:async_accept_stream(Conn, SOpts),
    {ok, #state{opts = SOpts}}.

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
handle_call(_Request, _From,
            #state{stream = Stream,
                   opts = Options, cbstate = CBState} = State) ->
    #{stream_callback := CallbackModule} = Options,
    try CallbackModule:handle_call(Stream, Options, CBState) of
        {ok, Reply, NewCBState} ->
            {reply, Reply, #state{ cbstate = NewCBState
                                 , opts = Options
                                 }};
        Other -> % @todo
            Other
    catch _:Reason:ST ->
            maybe_log_stracetrace(ST),
            {reply, {callback_error, Reason}, State}
    end.

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
handle_info({quic, new_stream, Stream}, #state{opts = Options} = State) ->
    ?tp(new_stream, #{module=>?MODULE, stream=>Stream}),
    #{stream_callback := CallbackModule} = Options,
    try CallbackModule:new_stream(Stream, Options) of
        {ok, CBState} ->
            {noreply, State#state{stream = Stream, cbstate = CBState}};
        {error, Reason} ->
            {stop, Reason, State#state{stream = Stream}}
    catch
        _:Reason:ST ->
            maybe_log_stracetrace(ST),
            {stop, {new_stream_crash, Reason}, State#state{stream = Stream}}
    end;
handle_info({quic, Bin, Stream, _, _, Flags},
            #state{stream = Stream, opts = Options, cbstate = CBState}= State) ->
    ?tp(stream_data, #{module=>?MODULE, stream=>Stream}),
    #{stream_callback := CallbackModule} = Options,
    try CallbackModule:handle_stream_data(Stream, Bin, Options, CBState) of
        {ok, NewCBState} ->
            %% @todo this should be a configurable behavior
            is_fin(Flags) andalso CallbackModule:shutdown(Stream),
            {noreply, State#state{cbstate = NewCBState}};
        {error, Reason, NewCBState} ->
            {noreply, Reason, State#state{cbstate = NewCBState}}
    catch
        _:Reason:ST ->
            maybe_log_stracetrace(ST),
            {stop, {handle_stream_data_crash, Reason}, State}
    end;

handle_info({quic, _Bin, StreamA, _, _, _}, #state{stream = StreamB} = State)
  when StreamB =/=StreamA ->
    ?tp(inval_stream_data, #{module=>?MODULE, stream_a=>StreamA, stream_b => StreamB}),
    {stop, wrong_stream, State};

handle_info({quic, peer_send_shutdown, Stream}, #state{stream = Stream, opts = Options} = State) ->
    ?tp(peer_shutdown, #{module=>?MODULE, stream=>Stream}),
    #{stream_callback := CallbackModule} = Options,
    CallbackModule:shutdown(Stream),
    {noreply, State};

handle_info({quic, closed, Stream, _Reason}, #state{stream = Stream} = State) ->
    %% @todo
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
terminate(Reason, _State) ->
    error_code(Reason),
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
error_code(normal)->
    'QUIC_ERROR_NO_ERROR';
error_code(shutdown)->
    'QUIC_ERROR_NO_ERROR';
error_code(_)->
    %% @todo mapping errors to error code
    %% for closing stream
    'QUIC_ERROR_INTERNAL_ERROR'.

maybe_log_stracetrace(ST)->
    logger:error("~p~n", [ST]),
    ok.

-spec is_fin(integer()) ->  boolean().
is_fin(0) ->
    false;
is_fin(Flags) when is_integer(Flags) ->
    (1 bsl 1) band Flags =/= 0.
