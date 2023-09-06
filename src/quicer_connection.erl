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

%% @doc
%% == Quic Connection Behavior  ==
%% Best practice for
%% 1. server side connection acceptor
%%
%% 1. server side connection initiator
%%
%% @end
-module(quicer_connection).
-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include("quicer_types.hrl").

-behaviour(gen_server).

-export_type([ cb_state/0
             , cb_ret/0
             ]).

-type cb_state() :: quicer_lib:cb_state().

-type state() :: #{ listener := listener_handle()
                  , conn := connection_handle()
                  , callback := atom()
                  , callback_state := term()
                  , sup := undefined | pid()
                  , conn_opts := map()
                  , stream_opts := map()
                  , is_resumed := boolean()
                  }.

-type cb_init_args() :: #{ stream_opts => stream_opts() | user_opts()
                         , conn => connection_handle()
                         } | conn_opts().


-type cb_ret() :: quicer_lib:cb_ret().

-callback init(cb_init_args()) -> {ok, cb_state()} | {error, app_error(), cb_state()}.
%% Init Callback, after return should expect for recv new connection

-callback new_conn(connection_handle(), new_conn_props(), cb_state()) -> cb_ret().
%% Handle new incoming connection request
%%  return {ok, cb_state()} to complete handshake
%%
%%  return {error, Reason, cb_state()} to reject the new connection, this process will be terminated
%%
%% NOTE:
%%   1. If acceptor is supervised,new new acceptor will be spawned.
%%   2. Connection maybe rejected in the stack earlier before this Callback.
%%

-callback connected(connection_handle(), connected_props(), cb_state()) -> cb_ret().
%% Handle connection handshake done
%%      callback is suggested to accept new streams @see quicer:accept_stream/3

-callback transport_shutdown(connection_handle(), transport_shutdown_props(), cb_state()) -> cb_ret().
%% Handle connection shutdown due to transport error with error reason.
%%
%% NOTE: Cleanup is prefered to be handled in @see closed/3
%% @TODO: the Reason is bounded to a few atoms.

-callback shutdown(connection_handle(), error_code(), cb_state()) -> cb_ret().
%% Handle connection shutdown initiated by peer

-callback closed(connection_handle(), conn_closed_props(), cb_state()) -> cb_ret().
%% Handle connection closed.
%% We don't have to terminate this process since connection could be resumed.

-callback local_address_changed(connection_handle(), quicer_addr(), cb_state()) -> cb_ret().
%% Handle Local Addr Changed, currently not in use.

-callback peer_address_changed(connection_handle(), quicer_addr(), cb_state) -> cb_ret().
%% Handle Peer Addr Changed

-callback streams_available(connection_handle(), {BidirStreams::non_neg_integer(), UnidirStreams::non_neg_integer()},
                            cb_state()) -> cb_ret().
%% Handle Stream Available, reflect number of streams flow control at peer.

-callback peer_needs_streams(connection_handle(), undefined, cb_state()) -> cb_ret().
%% Handle Peer needs streams that peer could not start new stream due to local flow control.

-callback resumed(connection_handle(), SessionData:: binary() | false, cb_state()) -> cb_ret().
%% Handle connection is resumed with 0-RTT
%% SessionData contains session data was sent in 0-RTT

-callback new_stream(stream_handle(), new_stream_props(), cb_state()) -> cb_ret().
%% Handle new stream from peer which has no owner assigned, or stream acceptor
%% didn't accept the stream on time
%% NOTE: The connection could start stream handoff procedure

-callback nst_received(connection_handle(), TicketBin :: binary(), cb_state()) -> cb_ret().
%% Client only, New session ticket received,

-callback handle_call(Req::term(), From::gen_server:from(), cb_state()) -> cb_ret().

-callback handle_info(Info::term(), cb_state()) -> cb_ret().
%% handle unhandled info with callback state.

-callback handle_continue(Cont::term(), cb_state()) -> cb_ret().
%% Handle continue from other callbacks with callback state.

-optional_callbacks([ handle_call/3
                    , handle_info/2
                    , handle_continue/2
                    , peer_needs_streams/3 %% require newer MsQuic
                    , nst_received/3       %% client only
                    ]).
%% Handle API call with callback state.

%% API
-export([start_link/3, %% for client
         start_link/4, %% for server
         get_cb_state/1,
         stream_send/6,
         get_handle/1
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, handle_continue/2,
         terminate/2]).

-import(quicer_lib, [default_cb_ret/2]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Spawn Client connection or Start connection acceptor at server side
%% @end
%%--------------------------------------------------------------------

%% start_link/3
-spec start_link(atom(), {hostname(), inet:port_number()}, {conn_opts(), stream_opts()}) -> gen_server:start_ret().
start_link(CallbackModule, {_Host, _Port} = Peer, {_COpts, _SOpts} = Opts) when is_atom(CallbackModule) ->
    gen_server:start_link(?MODULE, [CallbackModule, Peer, Opts], []).

%% start_link/4
%% Server starts acceptors for new connection on the Listener
%% Get `CallbackModule` from conn_opts, key:`conn_callback` if `CallbackModule` is undefined,
%% this is the entry for supervised acceptor.
-spec start_link(CallbackModule :: undefined | module(),
                 Listener ::quicer:listener_handle(),
                 ConnOpts :: term(),
                 Sup :: pid()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(undefined, Listener, {LOpts, COpts, SOpts}, Sup) when is_list(COpts)->
    start_link(undefined, Listener, {LOpts, maps:from_list(COpts), SOpts}, Sup);
start_link(undefined, Listener, {_LOpts, COpts, _SOpts} = Opts, Sup) when is_map(COpts)->
    case maps:get(conn_callback, COpts, undefined) of
        undefined ->
            {error, missing_conn_callback};
        Callback ->
            start_link(Callback, Listener, Opts, Sup)
    end;
start_link(CallbackModule, Listener, Opts, Sup) ->
    gen_server:start_link(?MODULE, [CallbackModule, Listener, Opts, Sup], []).

-spec get_cb_state(ConnPid :: pid()) -> {ok, cb_state()} | {error, any()}.
get_cb_state(ConnPid) ->
    gen_server:call(ConnPid, get_cb_state, infinity).

-spec stream_send(ConnPid :: pid(), Callback :: atom(), Data :: iodata(), SendFlag :: send_flags(),
                  StreamOpts :: stream_opts(), timeout())
                 -> ok | {error, any()}.
stream_send(ConnPid, Callback, Data, SendFlag, StreamOpts, Timeout) ->
    gen_server:call(ConnPid, {stream_send, Callback, Data, SendFlag, StreamOpts}, Timeout).

%% @doc get connection handle from quic connection process
-spec get_handle(pid()) -> undefined | connection_handle().
get_handle(ConnPid) ->
    gen_server:call(ConnPid, get_handle, infinity).

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

%% For Client
init([CallbackModule, {Host, Port}, {COpts, SOpts}])
  when is_atom(CallbackModule) andalso
       is_list(COpts) ->
    init([CallbackModule, {Host, Port}, {maps:from_list(COpts), SOpts}]);
init([CallbackModule, {Host, Port}, {COpts, SOpts}])
  when is_atom(CallbackModule) andalso
       is_map(COpts) ->
    process_flag(trap_exit, true),
    State0 = #{ listener => undefined
              , conn => undefined
              , callback => CallbackModule
              , conn_opts => COpts
              , stream_opts => SOpts
              , sup => undefined
              },
    {ok, Conn} = quicer:async_connect(Host, Port, COpts),
    State1 = State0#{conn := Conn},
    case CallbackModule:init(COpts#{stream_opts => SOpts, conn => Conn}) of
        {ok, CBState} ->
            {ok, State1#{callback_state => CBState}};
        {ok, CBState, Action} ->
            {ok, State1#{callback_state => CBState}, Action};
        Other -> %% ignore, {stop, Reason} ...
            Other
    end;

%% For Server
init([CallbackModule, Listener, {LOpts, COpts, SOpts}, Sup]) when is_list(COpts) ->
    init([CallbackModule, Listener, {LOpts, maps:from_list(COpts), SOpts}, Sup]);
init([CallbackModule, Listener, {_LOpts, COpts, SOpts}, Sup]) when CallbackModule =/= undefined ->
    process_flag(trap_exit, true),
    State0 = #{ listener => Listener
              , conn => undefined
              , callback => CallbackModule
              , conn_opts => COpts
              , stream_opts => SOpts
              , sup => Sup},
    %% Async Acceptor
    {ok, Listener} = quicer_nif:async_accept(Listener, COpts),
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
handle_call(get_cb_state, _From, #{ callback_state := CbState } = State) ->
    {reply, CbState, State};
handle_call(get_handle, _From, #{ conn := Connection } = State) ->
    {reply, Connection, State};
handle_call({stream_send, Callback, Data, SendFlags, Opts}, _From,
            #{ callback_state := _CbState, conn := Conn } = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, event => stream_send, conn => Conn}),
    case quicer_stream:start_link(Callback, Conn, Opts) of
        {ok, StreamPid} ->
            try quicer_stream:send(StreamPid, Data, SendFlags) of
                Res ->
                    {reply, Res, State}
            catch exit:Info:_ ->
                    {reply , {error, {stream_down, Info}}, State}
            end;
        {error, Reason} ->
            {reply, {error, {start_stream, Reason}}, State}
    end;
handle_call(Request, From, #{ callback_state := CBState, callback := M} = State) ->
    default_cb_ret(M:handle_call(Request, From, CBState), State).

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
    ?tp_ignore_side_effects_in_prod(debug, #{module=>?MODULE, conn=>C, props=>Props, event=>new_conn}),
    %% I become the connection owner, I should start an new acceptor.
    Sup =/= undefined andalso (catch supervisor:start_child(Sup, [Sup])),
    default_cb_ret(M:new_conn(C, Props, CBState), State#{conn := C});

handle_info({quic, connected, C, #{is_resumed := IsResumed} = Props},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module=>?MODULE, conn=>C, props=>Props, event => connected}),
    %% @TODO add option to unlink from supervisor
    default_cb_ret(M:connected(C, Props, CbState), State#{is_resumed => IsResumed});

handle_info({quic, transport_shutdown, C, DownInfo},
            #{ conn := C
             , callback := M
             , callback_state := CbState
             } = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => transport_shutdown}),
    default_cb_ret(M:transport_shutdown(C, DownInfo, CbState), State);

handle_info({quic, shutdown, C, ErrorCode},
            #{ conn := C
             , callback := M
             , callback_state := CbState
             } = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => shutdown}),
    default_cb_ret(M:shutdown(C, ErrorCode, CbState), State);

handle_info({quic, closed, C, #{is_app_closing := false} = Flags},
            #{conn := C, callback := M,
              callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module=>?MODULE, conn=>C, event => closed}),
    default_cb_ret(M:closed(C, Flags, CBState), State);

handle_info({quic, local_address_changed, C, NewAddr},
            #{ conn := C
             , callback := M
             , callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => local_address_changed, new_addr => NewAddr}),
    default_cb_ret(M:local_address_changed(C, NewAddr, CBState), State);

handle_info({quic, peer_address_changed, C, NewAddr},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => peer_address_changed, new_addr => NewAddr}),
    default_cb_ret(M:peer_address_changed(C, NewAddr, CbState), State);

handle_info({quic, new_stream, Stream, Props},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) when C =/= undefined->
    %% Best practice:
    %%   One connection will have a control stream that has the same life cycle as the connection.
    %%   The connection may spawn one *control stream* acceptor before starting the handshake
    %%   AND the stream acceptor should accept new stream so it will likely pick up the control stream
    %% note, by desgin, control stream doesn't have to be the first stream initiated.
    %% here, it handles new stream when there is no available stream acceptor for the connection.
    ?tp_ignore_side_effects_in_prod(debug, #{module=>?MODULE, conn=>C, stream=>Stream, event => new_stream}),
    default_cb_ret(M:new_stream(Stream, Props, CbState), State);

handle_info({quic, streams_available, C, #{ bidi_streams := BidirStreams
                                          , unidi_streams := UnidirStreams}},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => streams_available,
                 bidir_cnt => BidirStreams, unidir_cnt => UnidirStreams}),
    default_cb_ret(M:streams_available(C, {BidirStreams, UnidirStreams}, CbState), State);

%% for https://github.com/microsoft/msquic/issues/3120
handle_info({quic, peer_needs_streams, C, Needs},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => peer_needs_streams}),
    default_cb_ret(M:peer_needs_streams(C, Needs, CbState), State);

handle_info({quic, connection_resumed, C, ResumeData},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => connection_resumed, data => ResumeData}),
    default_cb_ret(M:resumed(C, ResumeData, CBState), State);

%% Client Only
handle_info({quic, nst_received, C, TicketBin},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => nst_received, ticket => TicketBin}),
    default_cb_ret(M:nst_received(C, TicketBin, CBState), State);

handle_info({quic, dgram_state_changed, C, Flags},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module => ?MODULE, conn => C, event => dgram_state_changed, flags => Flags}),
    default_cb_ret(M:datagram_state_changed(C, Flags, CBState), State);

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
    {noreply, State};
handle_info(OtherInfo, #{callback := M,
                         callback_state := CBState} = State) ->
    default_cb_ret(M:handle_info(OtherInfo, CBState), State).

-spec handle_continue(Cont::term(), State::term()) ->
          {noreply, NewState :: term()} |
          {noreply, NewState :: term(), Timeout :: timeout()} |
          {noreply, NewState :: term(), hibernate} |
          {stop, Reason :: normal | term(), NewState :: term()}.
handle_continue(Cont, #{callback := M,
                        callback_state := CBState} = State) ->
    ?tp_ignore_side_effects_in_prod(debug, #{module=>?MODULE, event=>continue, stream=>maps:get(stream, State)}),
    default_cb_ret(M:handle_continue(Cont, CBState), State).
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
