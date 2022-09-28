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
-include("quicer_types.hrl").

-behaviour(gen_server).

%% ====================================================================================================
%%      init while spawn
%%      a. init callback state
-callback init(_Args) -> _State.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle new incoming connection, from listener
%%      a. Reject (close) the connection
%%      b. Continue handshake,
%%      c. Spawn stream acceptors and continue with handshake. (accept new stream call could be sync/async)
-callback new_conn(connection_handler(), _OldState) -> {ok, _NewState} | {error, term()}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle connection handshake done
%%      a. init new streams from the Server
-callback connected(connection_handler(), _OldState) -> {ok, _NewState} | {error, term()}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle transport_shutdown
%%
-callback transport_shutdown(connection_handler(), Reason::atom(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle connection shutdown initiated by peer
%%
-callback shutdown(connection_handler(), ErrorCode :: integer(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle connection closed (both sides shutdown_complete)
%%
-callback closed(connection_handler(), Flags::map(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%     Handle Local Addr Changed
%%
-callback local_address_changed(connection_handler(), NewAddr::string(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%     Handle Peer Addr Changed
%%
-callback peer_address_changed(connection_handler(), NewAddr::string(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%     Handle Stream Available
%%
-callback streams_available(connection_handler(), BidirStreams::integer(), UnidirStreams::integer(),
                            _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%     Handle Peer needs streams
%%
-callback peer_needs_streams(connection_handler(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%    Handle connection resumed
%%
-callback resumed(connection_handler(), SessionData:: binary() | false, _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle new stream
%%      a. spawn new process to handle this stream
%%      b. just be the owner of stream
%%
%%      Suggest to keep a stream & owner pid mapping in the callback state
-callback new_stream(connection_handler(), stream_handler(), _OldState) -> {ok, pid()} | {error, term()}.
%% ====================================================================================================

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  Stream callbacks
%%
%% ====================================================================================================
%%      Handle stream started
-callback start_completed(stream_handler(), Status :: atom(), StreamID::integer(),
                          IsSuccess:: 0|1, _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle stream send_complete
%%
-callback send_complete(stream_handler(), IsCanceled::boolean(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle stream peer_send_shutdown
%%
-callback peer_send_shutdown(stream_handler(), ErrorCode::integer(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle stream peer_send_aborted
%%
-callback peer_send_aborted(stream_handler(), ErrorCode::integer(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle stream peer_send_aborted
%%
-callback peer_receive_aborted(stream_handler(), ErrorCode::integer(), _OldState) -> {ok, _State}.
%% ====================================================================================================


%% ====================================================================================================
%%      Handle stream send_shutdown_complete @TODO
%%      Happen Immediately on an abortive send or after a graceful send has been acknowledged by the peer.
-callback send_shutdown_complete(stream_handler(), ErrorCode::integer(), _OldState) -> {ok, _State}.
%% ====================================================================================================


%% ====================================================================================================
%%      Handle stream closed, this means peer side shutdown the receiving
%%      but our end could still keep sending
%% a. forward a msg to the (new) owner process
%%
-callback stream_closed(connection_handler(), stream_handler(), CloseFlags :: map(), _OldState) -> {ok, _State}.
%% ====================================================================================================

%% ====================================================================================================
%%      Handle stream 'peer_accepted'
%%      The stream which was not accepted due to peer flow control is now accepted by the peer.
%%
-callback peer_accepted(connection_handler(), stream_handler(), _OldState) -> {ok, _State}.
%% ====================================================================================================


-optional_callbacks([ start_completed/5
                    , send_complete/3
                    , peer_send_shutdown/3
                    , peer_send_aborted/3
                    , peer_receive_aborted/3
                    , send_shutdown_complete/3
                    , stream_closed/4
                    , peer_accepted/3
                    ]).

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
               }).

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
    {noreply, State#state{conn = C, callback_state = NewCBState} };

handle_info({quic, connection_resumed, C, ResumeData},
            #state{callback = M, callback_state = CBState} = State) ->
    case erlang:function_exported(M, resumed, 3) of
        true ->
            {ok, NewCBState} = M:resumed(C, ResumeData, CBState),
            {noreply, State#state{callback_state = NewCBState}};
        false ->
            {noreply, State}
    end;

%% @TODO handle conn info
handle_info({quic, connected, C, #{is_resumed := _IsResumed}}, #state{ conn = C
                                                                     , callback = M
                                                                     , callback_state = CbState} = State) ->
    ?tp(quic_connected_slow, #{module=>?MODULE, conn=>C}),
    {ok, NewCBState} = M:connected(C, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, new_stream, Stream, Flags}, #state{ conn = C
                                                     , callback = M
                                                     , callback_state = CbState} = State) ->
    %% Best practice:
    %%   One connection will have a control stream that have the same life cycle as the connection.
    %%   The connection may spawn one *control stream* acceptor before starting the handshake
    %%   AND the stream acceptor should accept new stream so it will likely pick up the control stream
    %% note, by desgin, control stream doesn't have to be the first stream initiated.
    %% here, it handles new stream when there is no available stream acceptor for the connection.
    ?tp(debug, #{module=>?MODULE, conn=>C, stream=>Stream, event => new_stream}),
    NewCBState = case erlang:function_exported(M, new_stream, 3) of
                     true ->
                         case M:new_stream(C, Stream, CbState#{open_flag => Flags}) of
                             {ok, NewS} -> NewS;
                             {error, Reason} when is_integer(Reason) -> %% @TODO most likely it won't be a integer
                                 %% We ignore the return, stream could be closed already.
                                 _ = quicer:async_shutdown_stream(Stream,
                                                                  ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT, Reason)
                         end;
                     false ->
                         %% Backward compatibility
                         CbState
                 end,
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, transport_shutdown, C, Reason}, #state{ conn = C
                                                                 , callback = M
                                                                 , callback_state = CbState
                                                                 } = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => transport_shutdown}),
    {ok, NewCBState} = M:transport_shutdown(C, Reason, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, shutdown, C}, #state{ conn = C
                                       , callback = M
                                       , callback_state = CbState
                                       } = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => shutdown}),
    NewCBState = M:shutdown(C, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

%% handle stream close, the process is the owner of stream or it is during ownership handoff.
handle_info({quic, stream_closed, Stream, Flags}, #state{callback = M,
                                                                          conn = C,
                                                                          callback_state = CbState} = State)->
    ?tp(debug, #{module=>?MODULE, conn=>C, stream=>Stream, event=>stream_closed}),
    NewCBState = case erlang:function_exported(M, stream_closed, 4) of
                     true ->
                         case M:stream_closed(C, Stream, Flags, CbState) of
                             {ok, NewCBState0} ->
                                 NewCBState0;
                             {error, _Reason} ->
                                 CbState
                         end;
                     false ->
                         CbState
                 end,
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, transport_shutdown, C, Reason}, #state{ conn = C
                                                              , callback = M
                                                              , callback_state = CbState} = State) ->
    ?tp(debug, #{module=>?MODULE, conn=>C, event=>transport_shutdown}),
    case erlang:function_exported(M, transport_shutdown, 3) of
        true ->
            {ok, NewCBState} = M:transport_shutdown(C, Reason, CbState),
            {noreply, State#state{ callback_state = NewCBState }};
        false ->
            {noreply, State}
    end;

handle_info({quic, peer_address_changed, C, NewAddr}, #state{ conn = C
                                                            , callback = M
                                                            , callback_state = CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => peer_address_changed, new_addr => NewAddr}),
    {ok, NewCBState} = M:peer_address_changed(C, NewAddr, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, local_address_changed, C, NewAddr}, #state{ conn = C
                                                                     , callback = M
                                                                     , callback_state = CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => local_address_changed, new_addr => NewAddr}),
    {ok, NewCBState} = M:local_address_changed(C, NewAddr, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, streams_available, BiDirStreams, UniDirStreams}, #state{ conn = C
                                                                                  , callback = M
                                                                                  , callback_state = CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => streams_available,
                 bidir_cnt => BiDirStreams, unidir_cnt => UniDirStreams}),
    {ok, NewCBState} = M:streams_available(C, BiDirStreams, UniDirStreams, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, peer_needs_streams, C, BiDirStreams, UniDirStreams}, #state{ conn = C
                                                                              , callback = M
                                                                              , callback_state = CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => peer_needs_streams}),
    {ok, NewCBState} = M:peer_needs_streams(C, BiDirStreams, UniDirStreams, CbState),
    {noreply, State#state{ callback_state = NewCBState }};

handle_info({quic, shutdown, C, ErrorCode}, #state{conn = C, callback = M,
                                                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => shutdown}),
    {ok, NewCBState} = M:shutdown(C, ErrorCode, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, closed, C, #{is_app_closing := false} = Flags}, #state{conn = C, callback = M,
                                                                         callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => closed}),
    M:closed(C, Flags, CBState),
    {stop, normal, State};

%%% ==============================================================
%%% Handle messages from streams
%%% !!! note, we don't handle recv event
%%% ==============================================================
handle_info({quic, start_completed, Stream,
             #{status := AtomStatus, stream_id := StreamId, is_peer_accepted := PeerAccepted}
            }, #state{callback = M,
                      callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => start_completed}),
    {ok, NewCBState} = M:start_complete(Stream, AtomStatus, StreamId, PeerAccepted, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, send_complete, Stream, IsSendCanceled},
            #state{callback = M,
                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => send_complete}),
    {ok, NewCBState} = M:send_complete(Stream, IsSendCanceled, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, peer_send_shutdown, Stream, undefined},
            #state{callback = M,
                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_send_shutdown}),
    {ok, NewCBState} = M:peer_send_shutdown(Stream, undefined, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, peer_send_aborted, Stream, ErrorCode},
            #state{callback = M,
                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_send_aborted}),
    {ok, NewCBState} = M:peer_send_aborted(Stream, ErrorCode, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, peer_receive_aborted, Stream, ErrorCode},
            #state{callback = M,
                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_receive_aborted}),
    {ok, NewCBState} = M:peer_receive_aborted(Stream, ErrorCode, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

handle_info({quic, peer_accepted, Stream},
            #state{callback = M,
                   callback_state = CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_accepted}),
    {ok, NewCBState} = M:peer_accepted(Stream, CBState),
    {noreply, State#state{ callback_state = NewCBState} };

%%% ==============================================================
%%% Handle messages for link/monitor
%%% ==============================================================
handle_info({'EXIT', _Pid, {shutdown, normal}}, State) ->
    %% exit signal from stream
    {noreply, State};

handle_info({'EXIT', _Pid, {shutdown, _Other}}, State) ->
    %% @todo
    {noreply, State};

handle_info({'EXIT', _Pid, normal}, State) ->
    %% @todo
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
