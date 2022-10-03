%%--------------------------------------------------------------------
%% Copyright (c) 2021-2022 EMQ Technologies Co., Ltd. All Rights Reserved.
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

%% @doc QUIC connection acceptor beahivor.
%% == Generic Quic Connection Acceptor ==
%% Best practice for server side connection owner and stream owner.
%%
%% @end
-module(quicer_conn_acceptor).
-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer_types.hrl").

-behaviour(gen_server).

-export_type([ cb_init_args/0
             , cb_state/0
             , cb_ret/0
             ]).

-type state() :: #{ listener := listener_handler()
                  , conn := connection_handler()
                  , callback := atom()
                  , callback_state := term()
                  , sup := undefined | pid()
                  , conn_opts := map()
                  , stream_opts := map()
                  , is_resumed := boolean()
                  }.

-type cb_init_args() :: [ listener_handler() |
                          [ {listen_opts(), conn_opts(), stream_opts()}
                          | [Supervisor :: undefined | pid() ]]
                        ].

-type cb_state() :: any().

-type cb_ret() :: {ok, cb_state()}                    %% ok and update cb_state
                | {error, Reason::term(), cb_state()} %% error handling per callback
                | {hibernate, cb_state()}           %% ok but also hibernate process
                | {{continue, Continue :: term()}, cb_state()}  %% split callback work with Continue
                | {timeout(), cb_state()}           %% ok but also hibernate process
                | {stop, Reason :: term(), cb_state()}.            %% terminate with reason


-callback init(cb_init_args()) -> {ok, cb_state()} | {error, app_error(), cb_state()}.
%% Init Callback, after return should expect for recv new connection

-callback new_conn(connection_handler(), new_conn_props(), cb_state()) -> cb_ret().
%% Handle new incoming connection request
%%  return {ok, cb_state()} to complete handshake
%%
%%  return {error, Reason, cb_state()} to reject the new connection, this process will be terminated
%%
%% NOTE:
%%   1. If acceptor is supervised,new new acceptor will be spawned.
%%   2. Connection maybe rejected in the stack earlier before this Callback.
%%

-callback connected(connection_handler(), connected_props(), cb_state()) -> cb_ret().
%% Handle connection handshake done
%%      callback is suggested to accept new streams @see quicer:accept_stream/3

-callback transport_shutdown(connection_handler(), Reason::atom(), cb_state()) -> cb_ret().
%% Handle connection shutdown due to transport error with error reason.
%%
%% NOTE: Cleanup is prefered to be handled in @see closed/3
%% @TODO: the Reason is bounded to a few atoms.

-callback shutdown(connection_handler(), error_code(), cb_state()) -> cb_ret().
%% Handle connection shutdown initiated by peer

-callback closed(connection_handler(), conn_closed_props(), cb_state()) -> cb_ret().
%% Handle connection closed.
%% We don't have to terminate this process since connection could be resumed.

-callback local_address_changed(connection_handler(), quicer_addr(), cb_state()) -> cb_ret().
%% Handle Local Addr Changed, currently not in use.

-callback peer_address_changed(connection_handler(), quicer_addr(), cb_state) -> cb_ret().
%% Handle Peer Addr Changed

-callback streams_available(connection_handler(), {BidirStreams::non_neg_integer(), UnidirStreams::non_neg_integer()},
                            cb_state()) -> cb_ret().
%% Handle Stream Available, reflect number of streams flow control at peer.

-callback peer_needs_streams(connection_handle(), undefined, cb_state()) -> cb_ret().
%% Handle Peer needs streams that peer could not start new stream due to local flow control.

-callback resumed(connection_handler(), SessionData:: binary() | false, cb_state()) -> cb_ret().
%% Handle connection is resumed with 0-RTT
%% SessionData contains session data was sent in 0-RTT

-callback new_stream(connection_handler(), stream_handler(), cb_state()) -> cb_ret().
%% Handle new stream from peer
%% NOTE: It could be a race cond. that new stream isn't accepted in new process that is created by connection owner.
%% In this case, handoff should be used to hand over the owership and the message to the new stream owner

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  Stream Callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback start_completed(stream_handler(), stream_start_completed_props(), cb_state()) -> cb_ret().
%% Handle local initiated stream start completed

-callback send_complete(stream_handler(), IsCanceled::boolean(), cb_state()) -> cb_ret().
%% Handle send completed.

-callback peer_send_shutdown(stream_handler(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_send_shutdown.

-callback peer_send_aborted(stream_handler(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_send_aborted.

-callback peer_receive_aborted(stream_handler(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_receive_aborted

-callback send_shutdown_complete(stream_handler(), error_code(), cb_state()) -> cb_ret().
%% Handle stream send_shutdown_complete.
%% Happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

-callback stream_closed(stream_handle(), stream_closed_props(), cb_state()) -> cb_ret().
%% Handle stream closed, Both endpoints of sending and receiving of the stream have been shut down.

-callback peer_accepted(connection_handler(), stream_handler(), cb_state()) -> cb_ret().
%% Handle stream 'peer_accepted'.
%% The stream which **was not accepted** due to peer flow control is now accepted by the peer.

-callback passive(stream_handler(), undefined, cb_state()) -> cb_ret().
%% Stream now in 'passive' mode.

%% API
-export([start_link/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

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
init([Listener, {_, #{conn_callback := CallbackModule} = COpts, SOpts}, Sup]) ->
    process_flag(trap_exit, true),
    %% Async Acceptor
    {ok, Listener} = quicer_nif:async_accept(Listener, COpts),

    State0 = #{ listener => Listener
              , callback => CallbackModule
              , conn_opts => maps:without([conn_callback], COpts)
              , stream_opts => SOpts
              , sup => Sup},
    case CallbackModule:init(COpts#{stream_opts => SOpts}) of
        {ok, CBState} ->
            {ok, State0#{callback_state => CBState}};
        {ok, CBState, Action} ->
            {ok, State0#{callback_state => CBState}, Action};
         Other -> %% ignore, {stop, Reason} ...
            Other
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
-spec handle_info(Info :: timeout() | term(), State :: state()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: normal | term(), NewState :: term()}.
handle_info({quic, new_conn, C, Props},
            #{callback := M, sup := Sup, callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, conn=>C, props=>Props, event=>new_conn}),
    %% I become the connection owner, I should start an new acceptor.
    Sup =/= undefined andalso (catch supervisor:start_child(Sup, [Sup])),
    default_cb_ret(M:new_conn(C, Props, CBState), State#{conn => C});

handle_info({quic, connected, C, #{is_resumed := IsResumed} = Props},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp(debug, #{module=>?MODULE, conn=>C, props=>Props, event => connected}),
    default_cb_ret(M:connected(C, Props, CbState), State#{is_resumed => IsResumed});

handle_info({quic, transport_shutdown, C, Reason},
            #{ conn := C
             , callback := M
             , callback_state := CbState
             } = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => transport_shutdown}),
    default_cb_ret(M:transport_shutdown(C, Reason, CbState), State);

handle_info({quic, shutdown, C, ErrorCode},
            #{ conn := C
             , callback := M
             , callback_state := CbState
             } = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => shutdown}),
    default_cb_ret(M:shutdown(C, ErrorCode, CbState), State);

handle_info({quic, closed, C, #{is_app_closing := false} = Flags},
            #{conn := C, callback := M,
              callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, conn=>C, event => closed}),
    default_cb_ret(M:closed(C, Flags, CBState), State);

handle_info({quic, local_address_changed, C, NewAddr},
            #{ conn := C
             , callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => local_address_changed, new_addr => NewAddr}),
    default_cb_ret(M:local_address_changed(C, NewAddr, CBState), State);

handle_info({quic, peer_address_changed, C, NewAddr},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => peer_address_changed, new_addr => NewAddr}),
    default_cb_ret(M:peer_address_changed(C, NewAddr, CbState), State);

handle_info({quic, new_stream, Stream, Flags},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) when C =/= undefined->
    %% Best practice:
    %%   One connection will have a control stream that have the same life cycle as the connection.
    %%   The connection may spawn one *control stream* acceptor before starting the handshake
    %%   AND the stream acceptor should accept new stream so it will likely pick up the control stream
    %% note, by desgin, control stream doesn't have to be the first stream initiated.
    %% here, it handles new stream when there is no available stream acceptor for the connection.
    ?tp(debug, #{module=>?MODULE, conn=>C, stream=>Stream, event => new_stream}),
    default_cb_ret(M:new_stream(Stream, Flags, CbState), State);

handle_info({quic, streams_available, BiDirStreams, UniDirStreams},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => streams_available,
                 bidir_cnt => BiDirStreams, unidir_cnt => UniDirStreams}),
    default_cb_ret(M:streams_available(C, {BiDirStreams, UniDirStreams}, CbState), State);

handle_info({quic, peer_needs_streams, C},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => peer_needs_streams}),
    default_cb_ret(M:peer_needs_streams(C, undefined, CbState), State);

handle_info({quic, connection_resumed, C, ResumeData},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => connection_resumed, data => ResumeData}),
    default_cb_ret(M:resumed(C, ResumeData, CBState), State);

%%% ==============================================================
%%% Handle messages from streams
%%% !!! note, we don't handle recv event
%%% ==============================================================
handle_info({quic, start_completed, Stream,
             #{ status := _AtomStatus
              , stream_id := _StreamId
              , is_peer_accepted := _PeerAccepted}} = Props
           , #{ callback := M
              , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => start_completed, props => Props}),
    default_cb_ret(M:start_complete(Stream, Props, CBState), State);

handle_info({quic, send_complete, Stream, IsSendCanceled},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event=>send_complete, is_canceled=>IsSendCanceled}),
    default_cb_ret(M:send_complete(Stream, IsSendCanceled, CBState), State);

handle_info({quic, peer_send_shutdown, Stream, undefined},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_send_shutdown}),
    default_cb_ret(M:peer_send_shutdown(Stream, undefined, CBState), State);

handle_info({quic, peer_send_aborted, Stream, ErrorCode},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_send_aborted, error_code => ErrorCode}),
    default_cb_ret(M:peer_send_aborted(Stream, ErrorCode, CBState), State);

handle_info({quic, peer_receive_aborted, Stream, ErrorCode},
            #{ callback := M,
               callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_receive_aborted, error_code => ErrorCode}),
    default_cb_ret(M:peer_receive_aborted(Stream, ErrorCode, CBState), State);

handle_info({quic, send_shutdown_complete, Stream, IsGraceful},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => send_shutdown_complete, is_graceful => IsGraceful}),
    default_cb_ret(M:send_shutdown_complete(Stream, IsGraceful, CBState), State);

handle_info({quic, stream_closed, Stream, Flags},
            #{ callback := M
              , conn := C
              , callback_state := CbState} = State) when C =/= undefined andalso is_map(Flags) ->
    ?tp(debug, #{module=>?MODULE, conn=>C, stream=>Stream, event=>stream_closed, flags=>Flags}),
    default_cb_ret(M:stream_closed(Stream, Flags, CbState), State);

handle_info({quic, peer_accepted, Stream, undefined},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => peer_accepted}),
    default_cb_ret(M:peer_accepted(Stream, CBState), State);

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
-spec default_cb_ret(cb_ret(), state()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), timeout() | hibernate | {continue, term()}} |
          {stop, Reason :: term(), NewState :: term()}.
default_cb_ret({ok, NewCBState}, State) ->
    %% ok
    {noreply, State#{callback_state => NewCBState}};
default_cb_ret({hibernate, NewCBState}, State) ->
    %% hibernate
    {noreply, State#{callback_state => NewCBState}, hibernate};
default_cb_ret({Timeout, NewCBState}, State) when is_integer(Timeout) ->
    %% timeout
    {noreply, State#{callback_state => NewCBState}, Timeout};
default_cb_ret({{continue, _} = Continue, NewCBState}, State) ->
    %% continue
    {noreply, State#{callback_state => NewCBState}, Continue};
default_cb_ret({stop, Reason, NewCBState}, State) ->
    %% stop
    {stop, Reason, State#{callback_state => NewCBState}}.
