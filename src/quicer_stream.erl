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
-export([ %% Start before conn handshake, with only Conn handler
          start_link/2
          %% Start after conn handshake with new Stream Handler
        , start_link/3
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).
-define(post_init, post_init).

-record(state, { stream :: quicer:stream_handler()
               , conn   :: quicer:connection_handler()
               , opts :: stream_opts()
               , cbstate :: any()
               , is_owner :: boolean()
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

-spec start_link(Stream :: quicer:connection_handler(),
                 Conn :: quicer:connection_handler(),
                 Opts :: map()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Stream, Conn, Opts) ->
    gen_server:start_link(?MODULE, [Stream, Conn, Opts], []).

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
%% Before conn handshake, with only Conn handler
init([Conn, SOpts]) when is_list(SOpts) ->
    init([Conn, maps:from_list(SOpts)]);
init([Conn, SOpts]) ->
    process_flag(trap_exit, true),
    {ok, Conn} = quicer:async_accept_stream(Conn, SOpts),
    {ok, #state{opts = SOpts, conn = Conn, is_owner = true }};

%% After conn handshake, with stream handler
init([Stream, Conn, SOpts]) when is_list(SOpts) ->
    ?tp(new_stream_2, #{module=>?MODULE, stream=>Stream}),
    init([Stream, Conn, maps:from_list(SOpts)]);
init([Stream, Conn, #{stream_callback := CallbackModule} = SOpts]) ->
    ?tp(new_stream_3, #{module=>?MODULE, stream=>Stream}),
    process_flag(trap_exit, true),
    case CallbackModule:new_stream(Stream, SOpts) of
        {ok, CBState} ->
            %% handoff must be done for now
            self() ! ?post_init,
            {ok, #state{ is_owner = false
                       , opts = SOpts
                       , conn = Conn
                       , stream = Stream
                       , cbstate = CBState
                       }};
        {error, Reason} ->
            {stop , Reason}
    end.
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
handle_call(Request, _From,
            #state{stream = Stream,
                   opts = Options, cbstate = CBState} = State) ->
    #{stream_callback := CallbackModule} = Options,
    try CallbackModule:handle_call(Stream, Request, Options, CBState) of
        {ok, Reply, NewCBState} ->
            {reply, Reply, State#state{ cbstate = NewCBState
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
handle_info(?post_init, #state{ is_owner = false, stream = Stream} = State) ->
    ?tp(debug, #{event=>?post_init, module=>?MODULE, stream=>Stream}),
    case wait_for_handoff() of
        undefined ->
            ?tp(debug, #{event=>post_init_undef , module=>?MODULE, stream=>Stream}),
            {noreply, State#state{is_owner = true}};
        {BinList, Len, Flag} ->
            ?tp(debug, #{event=>post_init_data, module=>?MODULE, stream=>Stream}),
            %% @TODO first data from the stream, offset 0,
            Msg = {quic, iolist_to_binary(BinList), Stream, 0, Len, Flag},
            handle_info(Msg, State#state{is_owner = true})
    end;
handle_info(?post_init, #state{ is_owner = true} = State) ->
    logger:error("post_init when is owner"),
    {noreply, State};
handle_info({quic, new_stream, Stream, Flags}, #state{opts = Options} = State) ->
    ?tp(new_stream, #{module=>?MODULE, stream=>Stream, stream_flags => Flags}),
    #{stream_callback := CallbackModule} = Options,
    try CallbackModule:new_stream(Stream, Options#{open_flags => Flags}) of
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

handle_info({quic, peer_send_aborted, Stream, Reason},
            #state{stream = Stream, opts = Options} = State) ->
    ?tp(peer_send_aborted, #{module=>?MODULE, stream=>Stream, reason=>Reason}),
    #{stream_callback := CallbackModule} = Options,
    case erlang:function_exported(CallbackModule, peer_send_aborted, 3) of
        true ->
            NewState = CallbackModule:peer_send_aborted(Stream, State, Reason),
            {noreply, NewState};
        false ->
            {noreply, State}
    end;

handle_info({quic, peer_send_shutdown, Stream},
            #state{stream = Stream, opts = Options} = State) ->
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
error_code(normal) ->
    'QUIC_ERROR_NO_ERROR';
error_code(shutdown) ->
    'QUIC_ERROR_NO_ERROR';
error_code(_) ->
    %% @todo mapping errors to error code
    %% for closing stream
    'QUIC_ERROR_INTERNAL_ERROR'.

maybe_log_stracetrace(ST) ->
    logger:error("~p~n", [ST]),
    ok.

-spec is_fin(integer()) ->  boolean().
is_fin(0) ->
    false;
is_fin(Flags) when is_integer(Flags) ->
    (1 bsl 1) band Flags =/= 0.

%% handoff must happen
wait_for_handoff() ->
    receive
        {stream_owner_handoff, _From, Msg} ->
            Msg
    end.
