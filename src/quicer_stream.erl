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
-include("quicer_types.hrl").
-behaviour(gen_server).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  Stream Callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback init_handoff(stream_handle(), stream_opts(), connection_handle(), new_stream_props()) -> cb_ret().
%% Prepare callback state before ownership handoff

-callback post_handoff(stream_handle(), PostInfo::term(), cb_state()) -> cb_ret().
%% Post handoff with PostData if any. Most common action is to set the stream mode to active.

-callback new_stream(stream_handle(), new_stream_props(), connection_handle()) -> cb_ret().
%% Stream accepter is assigned to the owner of the new stream

-callback start_completed(stream_handle(), stream_start_completed_props(), cb_state()) -> cb_ret().
%% Handle local initiated stream start completed

-callback send_complete(stream_handle(), IsCanceled::boolean(), cb_state()) -> cb_ret().
%% Handle send completed.

-callback peer_send_shutdown(stream_handle(), undefined, cb_state()) -> cb_ret().
%% Handle stream peer_send_shutdown.

-callback peer_send_aborted(stream_handle(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_send_aborted.

-callback peer_receive_aborted(stream_handle(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_receive_aborted

-callback send_shutdown_complete(stream_handle(), IsGraceful::boolean(), cb_state()) -> cb_ret().
%% Handle stream send_shutdown_complete.
%% Happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

-callback stream_closed(stream_handle(), stream_closed_props(), cb_state()) -> cb_ret().
%% Handle stream closed, Both endpoints of sending and receiving of the stream have been shut down.

-callback peer_accepted(connection_handle(), stream_handle(), cb_state()) -> cb_ret().
%% Handle stream 'peer_accepted'.
%% The stream which **was not accepted** due to peer flow control is now accepted by the peer.

-callback passive(stream_handle(), undefined, cb_state()) -> cb_ret().
%% Stream now in 'passive' mode.


-callback handle_call(Req::term(), gen_server:from(), cb_state()) -> cb_ret().
%% Handle API call with callback state.

-callback handle_continue(Cont::term(), cb_state()) -> cb_ret().
%% Handle continue from other callbacks with callback state.

-callback handle_info(Info::term(), cb_state()) -> cb_ret().
%% Handle unhandled info with callback state.

-optional_callbacks([post_handoff/3, handle_call/3, handle_info/2, handle_continue/2]).

-import(quicer_lib, [default_cb_ret/2]).

-export_type([cb_state/0, cb_ret/0]).

-type cb_state() :: term().
-type cb_ret() :: {ok, cb_state()}                    %% ok and update cb_state
                | {error, Reason::term(), cb_state()} %% error handling per callback
                | {hibernate, cb_state()}           %% ok but also hibernate process
                | {{continue, Continue :: term()}, cb_state()}  %% split callback work with Continue
                | {timeout(), cb_state()}           %% ok but also hibernate process
                | {stop, Reason :: term(), cb_state()}.            %% terminate with reason

%% API
-export([ %% Start before conn handshake, with only Conn handle
          start_link/3
          %% Start after conn handshake with new Stream Handle
        , start_link/5
        , send/2
        , send/3
        ]).

%% Helpers
-export([wait_for_handoff/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         handle_continue/2,
         terminate/2]).

-define(post_init, post_init).

-type state() :: #{ stream := quicer:stream_handle()
                  , conn := quicer:connection_handle()
                  , callback := atom()
                  , callback_state := term()
                  , is_owner := boolean()
                  , stream_opts := map()
                  }.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
%% Start acceptor or Start new local stream
-spec start_link(Callback :: module(),
                 Conn :: quicer:connection_handle(),
                 StreamOpts :: map()) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Callback, Conn, StreamOpts) when is_atom(Callback) ->
    gen_server:start_link(?MODULE, [Callback, Conn, StreamOpts], []).

%%--------------------------------------------------------------------
%% @doc Start a new stream owner process and
%% then handoff ownership to this process
%%--------------------------------------------------------------------
-spec start_link(Callback :: module(),
                 Stream :: quicer:connection_handle(),
                 Conn :: quicer:connection_handle(),
                 StreamOpts :: map(),
                 Props :: new_stream_props()
                ) -> {ok, Pid :: pid()} |
          {error, Error :: {already_started, pid()}} |
          {error, Error :: term()} |
          ignore.
start_link(Callback, Stream, Conn, StreamOpts, Props)
  when Callback =/= undefined
       andalso is_atom(Callback)
       andalso is_map(Props) ->
    gen_server:start_link(?MODULE, [Callback, Stream, Conn, StreamOpts, Props, self()], []).

-spec send(pid(), binary()) -> {ok, Length::non_neg_integer()} | {error, any()}.
send(StreamProc, Data) ->
    send(StreamProc, Data, ?QUICER_SEND_FLAG_SYNC).

send(StreamProc, Data, Flag) ->
    gen_server:call(StreamProc, {send, Data, Flag}, infinity).

wait_for_handoff(FromOwner, Stream) ->
    MRef = erlang:monitor(process, FromOwner),
    receive
        {handoff_done, Stream, PostInfo} ->
            ?tp(debug, #{event=>stream_owner_handoff_done,
                         stream=>Stream,
                         module=>?MODULE,
                         post_info=>PostInfo
                        }),
            {ok, PostInfo};
        {'DOWN', MRef, process, FromOwner, _Info} ->
            ?tp(debug, #{event=>handoff_exit_owner_down,
                         stream=>Stream,
                         module=>?MODULE
                        }),
            {error, owner_down}
    %% For correctness we should never add timeout
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
-spec init(Args :: term()) -> {ok, state()} |
          {ok, state(), Timeout :: timeout()} |
          {ok, state(), hibernate} |
          {stop, Reason :: term()} |
          ignore.
%% With only Conn handle
%% Stream will be started or accepted.
init([Callback, Conn, StreamOpts]) when is_list(StreamOpts) ->
    init([Callback, Conn, maps:from_list(StreamOpts)]);
init([Callback, Conn, StreamOpts]) ->
    process_flag(trap_exit, true),
    IsLocal = maps:get(is_local, StreamOpts, false),
    InitState = #{ stream_opts => StreamOpts
                 , conn => Conn
                 , callback => Callback
                 , callback_state => undefined
                 },
    case IsLocal of
        false ->
            %% Accept remote stream,
            case quicer:async_accept_stream(Conn, StreamOpts) of
                {ok, Conn} ->
                    ?tp(new_stream_accept, #{module=>?MODULE, conn=>Conn}),
                    {ok, InitState#{ stream => undefined
                                   , is_owner => false
                                   , is_local => false
                                   }};
                {error, Reason} ->
                    {stop, Reason}
            end;
        true  ->
            %% Initiate local stream
            case quicer:start_stream(Conn, StreamOpts) of
                {ok, Stream} ->
                    ?tp(new_stream_local_start, #{module=>?MODULE, stream=>Stream}),
                    IsUni = quicer:is_unidirectional(
                              maps:get(open_flag, StreamOpts, ?QUIC_STREAM_START_FLAG_NONE)),
                    {ok, InitState#{ stream => Stream
                                   , is_owner => true
                                   , callback_state :=
                                         #{ conn => Conn
                                          , is_owner => true
                                          , is_local => true
                                          , is_unidir => IsUni
                                          }
                                   }};
                {error, Reason, SecReason} ->
                    {stop, {Reason, SecReason}};
                {error, Reason} ->
                    {stop, Reason}
            end
    end;

%% After conn handshake, with stream handle for remote stream
init([Callback, Stream, Conn, StreamOpts, Props, PrevOwner]) when is_list(StreamOpts) ->
    ?tp(new_stream_2, #{module=>?MODULE, stream=>Stream}),
    init([Callback, Stream, Conn, maps:from_list(StreamOpts), Props, PrevOwner]);
init([Callback, Stream, Conn, StreamOpts, Props, PrevOwner]) ->
    ?tp(new_stream_3, #{module=>?MODULE, stream=>Stream, opts => StreamOpts}),
    process_flag(trap_exit, true),
    case Callback:init_handoff(Stream, StreamOpts, Conn, Props) of
        {ok, CBState} ->
            State = #{ is_owner => false
                     , stream_opts => StreamOpts
                     , conn => Conn
                     , stream => Stream
                     , callback => Callback
                     , callback_state => CBState
                     },
            {ok,  State, {continue , {?post_init, PrevOwner}}};
        {error, _} = E ->
            {stop, E}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, state()) ->
          {reply, Reply :: term(), state()} |
          {reply, Reply :: term(), state(), Timeout :: timeout()} |
          {reply, Reply :: term(), state(), hibernate} |
          {noreply, state()} |
          {noreply, state(), Timeout :: timeout()} |
          {noreply, state(), hibernate} |
          {stop, Reason :: term(), Reply :: term(), state()} |
          {stop, Reason :: term(), state()}.

handle_call({send, Data, Flag}, _From,
            #{stream := Stream,
              stream_opts := _Options, callback_state := _CallbackState} = State) ->
    Res = quicer:async_send(Stream, Data, Flag),
    {reply, Res, State};

handle_call(Request, From,
            #{stream := _Stream,
              callback := CallbackModule,
              callback_state := CallbackState} = State) ->
    default_cb_ret(CallbackModule:handle_call(Request, From, CallbackState), State).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_cast(Request :: term(), state()) ->
          {noreply, state()} |
          {noreply, state(), Timeout :: timeout()} |
          {noreply, state(), hibernate} |
          {stop, Reason :: term(), state()}.
handle_cast(_Request, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), state()) ->
          {noreply, state()} |
          {noreply, state(), Timeout :: timeout()} |
          {noreply, state(), hibernate} |
          {stop, Reason :: normal | term(), state()}.
handle_info({quic, closed, undefined, undefined},
            #{ is_local := false
             , stream := undefined
             , conn := Conn
             } = S) ->
    ?tp(debug, acceptor_recv_conn_stop, #{conn => Conn, module => ?MODULE, pid => self()}),
    {stop, normal, S};

%% For acceptor
handle_info({quic, new_stream, Stream, #{flags := Flags, is_orphan := false} = Props},
            #{ stream_opts := Options
             , stream := undefined
             , conn := Conn
             , callback := CallbackModule
             , callback_state := undefined
             } = State) ->
    ?tp(debug, new_stream, #{module=>?MODULE, stream=>Stream, stream_flags => Flags}),
    try CallbackModule:new_stream(Stream, maps:merge(Options, Props), Conn) of
        {ok, CallbackState} ->
            {noreply, State#{stream := Stream, callback_state := CallbackState}};
        {error, Reason} ->
            {stop, Reason, State#{stream := Stream}}
    catch
        _:Reason:ST ->
            maybe_log_stracetrace(ST),
            {stop, {new_stream_crash, Reason}, State#{stream := Stream}}
    end;
handle_info({quic, Bin, Stream, #{flags := Flags}},
            #{ stream := Stream, callback := M
             , callback_state := CallbackState } = State)
  when is_binary(Bin) ->
    ?tp(debug, stream_data, #{module=>?MODULE, stream=>Stream}),
    default_cb_ret(M:handle_stream_data(Stream, Bin, Flags, CallbackState), State);

handle_info({quic, start_completed, Stream,
             #{ status := _AtomStatus
              , stream_id := _StreamId
              , is_peer_accepted := _PeerAccepted} = Props
             }
           , #{ callback := M
              , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => start_completed, props => Props}),
    default_cb_ret(M:start_completed(Stream, Props, CBState), State);

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
    default_cb_ret(M:peer_accepted(Stream, undefined, CBState), State);

handle_info({quic, passive, Stream, undefined},
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => passive}),
    default_cb_ret(M:passive(Stream, undefined, CBState), State);
handle_info(Info,
            #{ callback := M
             , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event => info}),
    default_cb_ret(M:handle_info(Info, CBState), State).

%% @TODO  handle_info({EXIT....

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This callback is optional, so callback modules need to export it only if they return
%% one of the tuples containing {continue,Continue} from another callback.
%% If such a {continue,_} tuple is used and the callback is not implemented,
%% the process will exit with undef error.
-spec handle_continue(Continue::term(), State::term()) ->
          {noreply, state()} |
          {noreply, state(), Timeout :: timeout()} |
          {noreply, state(), hibernate} |
          {stop, Reason :: normal | term(), state()}.
handle_continue({?post_init, PrevOwner}, #{ is_owner := false, stream := Stream
                                          , callback_state := CBState
                                          , callback := M} = State) ->
    ?tp(debug, #{event=>?post_init, module=>?MODULE, stream=>Stream}),
    case wait_for_handoff(PrevOwner, Stream) of
        {ok, PostInfo}->
            case erlang:function_exported(M, post_handoff, 3) of
                true ->
                    default_cb_ret(M:post_handoff(Stream, PostInfo, CBState), State#{is_owner => true});
                false ->
                    {noreply, State#{is_owner => true}}
            end;
        {error, owner_down} ->
            {stop, owner_down, State}
    end;
handle_continue(Other, #{ callback := M
                        , callback_state := CBState} = State) ->
    ?tp(debug, #{module=>?MODULE, event=>continue, stream=>maps:get(stream, State)}),
    default_cb_ret(M:handle_continue(Other, CBState), State).
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
                state()) -> any().
terminate(Reason, _State) ->
    error_code(Reason),
    ok.

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

