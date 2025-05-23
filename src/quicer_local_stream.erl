%%--------------------------------------------------------------------
%% Copyright (c) 2023-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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

%% @doc Stream initiated from local
-module(quicer_local_stream).

%% this module uses optional callbacks that should be implemented in this generic module
-hank([unused_callbacks]).

-export([
    start/4,
    start_link/3,
    start_link/4
]).

-include("quicer_types.hrl").

-type local_stream_opts() :: stream_opts() | proplists:proplist().
-type cb_ret() :: quicer_stream:cb_ret().
-type cb_state() :: quicer_stream:cb_state().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  Local Stream Callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-callback start_completed(stream_handle(), stream_start_completed_props(), cb_state()) -> cb_ret().
%% Handle local initiated stream start completed

-callback send_complete(stream_handle(), IsCanceled :: boolean(), cb_state()) -> cb_ret().
%% Handle send completed.

-callback peer_send_shutdown(stream_handle(), undefined, cb_state()) -> cb_ret().
%% Handle stream peer_send_shutdown.

-callback peer_send_aborted(stream_handle(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_send_aborted.

-callback peer_receive_aborted(stream_handle(), error_code(), cb_state()) -> cb_ret().
%% Handle stream peer_receive_aborted

-callback send_shutdown_complete(stream_handle(), IsGraceful :: boolean(), cb_state()) -> cb_ret().
%% Handle stream send_shutdown_complete.
%% Happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

-callback stream_closed(stream_handle(), stream_closed_props(), cb_state()) -> cb_ret().
%% Handle stream closed, Both endpoints of sending and receiving of the stream have been shut down.

-callback peer_accepted(connection_handle(), stream_handle(), cb_state()) -> cb_ret().
%% Handle stream 'peer_accepted'.
%% The stream which **was not accepted** due to peer flow control is now accepted by the peer.

-callback passive(stream_handle(), undefined, cb_state()) -> cb_ret().
%% Stream now in 'passive' mode.

-callback handle_stream_data(stream_handle(), binary(), recv_data_props(), cb_state()) -> cb_ret().
%% Stream handle data

-callback handle_call(Req :: term(), gen_server:from(), cb_state()) -> cb_ret().
%% Handle API call with callback state.

-callback handle_continue(Cont :: term(), cb_state()) -> cb_ret().
%% Handle continue from other callbacks with callback state.

-callback handle_info(Info :: term(), cb_state()) -> cb_ret().
%% Handle unhandled info with callback state.

-optional_callbacks([
    start_completed/3,
    send_complete/3,
    peer_accepted/3,
    handle_stream_data/4,
    handle_call/3,
    handle_info/2,
    handle_continue/2
]).

-spec start_link(module(), connection_handle(), local_stream_opts()) -> gen_server:start_ret().
start_link(CallbackModule, Connection, Opts) ->
    start_link(CallbackModule, Connection, Opts, []).
-spec start_link(module(), connection_handle(), local_stream_opts(), [gen_server:start_opt()]) ->
    gen_server:start_ret().
start_link(CallbackModule, Connection, Opts, StartOpts) when is_list(Opts) ->
    start_link(CallbackModule, Connection, maps:from_list(Opts), StartOpts);
start_link(CallbackModule, Connection, Opts, StartOpts) ->
    quicer_stream:start_link(CallbackModule, Connection, Opts#{is_local => true}, StartOpts).

-spec start(module(), connection_handle(), local_stream_opts(), [gen_server:start_opt()]) ->
    gen_server:start_ret().
start(CallbackModule, Connection, Opts, StartOpts) when is_list(Opts) ->
    start(CallbackModule, Connection, maps:from_list(Opts), StartOpts);
start(CallbackModule, Connection, Opts, StartOpts) ->
    quicer_stream:start(CallbackModule, Connection, Opts#{is_local => true}, StartOpts).
