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

-export_type([cb_state/0]).

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

-type cb_init_args() :: [ listener_handle() |
                          [ {listen_opts(), conn_opts(), stream_opts()}
                          | [Supervisor :: undefined | pid() ]]
                        ].

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

-callback transport_shutdown(connection_handle(), Reason::atom(), cb_state()) -> cb_ret().
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

-callback new_stream(stream_handle(), stream_open_flags(), cb_state()) -> cb_ret().
%% Handle new stream from peer which has no owner assigned, or stream acceptor
%% didn't accept the stream on time
%% NOTE: The connection could start stream handoff procedure

-callback nst_received(connection_handle(), TicketBin :: binary(), cb_state()) -> cb_ret().
%% Client only, New session ticket received,

%% API
-export([start_link/3, handoff_stream/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-import(quicer_lib, [default_cb_ret/2]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(StartFrom::quicer:listener_handle() | { inet:hostname(), inet:ip_address() },
                 ConnOpts :: map(), Sup :: pid()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(StartFrom, ConnOpts, Sup) ->
    gen_server:start_link(?MODULE, [StartFrom, ConnOpts, Sup], []).


%% @doc
%%  handoff stream to another proc
%%  1) change stream owner to new pid
%%  2) forward all data to new pid
%%  3) @TODO also handoff signaling
%% @end
-spec handoff_stream(stream_handle(), pid()) -> ok.
handoff_stream(Stream, Owner) ->
    ?tp(debug, #{event=>?FUNCTION_NAME , module=>?MODULE, stream=>Stream, owner => Owner}),
    case quicer:controlling_process(Stream, Owner) of
        ok ->
            forward_stream_msgs(Stream, Owner, _ACC = []);
        {error, _Reason} = E->
            E
    end.
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
init([StartFrom, {LOpts, COpts, SOpts}, Sup]) when is_list(COpts) ->
    init([StartFrom, {LOpts, maps:from_list(COpts), SOpts}, Sup]);
init([StartFrom, {_, #{conn_callback := CallbackModule} = COpts, SOpts}, Sup]) ->
    process_flag(trap_exit, true),
    State0 = #{ listener => undefined
              , conn => undefined
              , callback => CallbackModule
              , conn_opts => maps:without([conn_callback], COpts)
              , stream_opts => SOpts
              , sup => Sup},
    State1 = case StartFrom of
                 {Host, Port} ->
                     {ok, Conn} = quicer:async_connect(Host, Port, COpts),
                     State0#{conn := Conn};
                 Listener ->
                     %% Async Acceptor
                     {ok, Listener} = quicer_nif:async_accept(Listener, COpts),
                     State0#{listener := Listener}
             end,
    case CallbackModule:init(COpts#{stream_opts => SOpts}) of
        {ok, CBState} ->
            {ok, State1#{callback_state => CBState}};
        {ok, CBState, Action} ->
            {ok, State1#{callback_state => CBState}, Action};
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

%% for https://github.com/microsoft/msquic/issues/3120
handle_info({quic, peer_needs_streams, C, Needs},
            #{ conn := C
             , callback := M
             , callback_state := CbState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => peer_needs_streams}),
    default_cb_ret(M:peer_needs_streams(C, Needs, CbState), State);

handle_info({quic, connection_resumed, C, ResumeData},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => connection_resumed, data => ResumeData}),
    default_cb_ret(M:resumed(C, ResumeData, CBState), State);

%% Client Only
handle_info({quic, nst_received, C, TicketBin},
            #{callback := M, callback_state := CBState} = State) ->
    ?tp(debug, #{module => ?MODULE, conn => C, event => nst_received, ticket => TicketBin}),
    default_cb_ret(M:nst_received(C, TicketBin, CBState), State);

%%% ==============================================================
%%% Handle messages from streams
%%% !!! note, we don't handle recv event
%%% ==============================================================
handle_info({quic, Event, _Stream, _Props} = Msg, State) when
      Event =:= start_completed orelse
      Event =:= send_complete orelse
      Event =:= peer_send_complete orelse
      Event =:= peer_send_aborted orelse
      Event =:= peer_receive_aborted orelse
      Event =:= peer_shutdown_complete orelse
      Event =:= stream_closed orelse
      Event =:= peer_accepted orelse
      Event =:= passive ->
    quicer_stream:handle_info(Msg, State);

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

%% @doc Forward all erl msgs of the Stream to the Stream Owner
%% Stream Owner should block for the {owner_handoff, Msg} and then 'flush_done' msg,
-spec forward_stream_msgs(stream_handle(), pid(), list()) -> ok.
forward_stream_msgs(Stream, Owner, Acc) ->
    receive
        {quic, Data, Stream, _Props} = Msg when is_binary(Data) ->
            forward_stream_msgs(Stream, Owner, [Msg | Acc])
    after 0 ->
            Owner ! {stream_owner_handoff, self(), aggr_stream_data(Acc)},
            ok
    end.

aggr_stream_data([]) ->
    undefined;
aggr_stream_data(Acc) ->
    %% Maybe assert offset is 0
    lists:foldl(fun({quic, Bin, _Stream, #{len := Len, flags := Flag}},
                    {BinAcc, LenAcc, FlagAcc}) ->
                        {[Bin | BinAcc], LenAcc + Len, FlagAcc bor Flag}
                end, {[], _Len = 0, _Flag = 0}, Acc).
