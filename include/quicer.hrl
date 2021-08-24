%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-ifndef(QUICER_HRL).
-define(QUICER_HRL, true).

%%% ========================================
%%% mirror macro from NIF code
%%% ========================================

%% QUIC_STREAM_EVENT_TYPE
-define(QUIC_STREAM_EVENT_START_COMPLETE            , 0).
-define(QUIC_STREAM_EVENT_RECEIVE                   , 1).
-define(QUIC_STREAM_EVENT_SEND_COMPLETE             , 2).
-define(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN        , 3).
-define(QUIC_STREAM_EVENT_PEER_SEND_ABORTED         , 4).
-define(QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED      , 5).
-define(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE    , 6).
-define(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE         , 7).
-define(QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE    , 8).


%% QUIC_LISTENER_EVENT_TYPE
-define(QUIC_LISTENER_EVENT_NEW_CONNECTION          , 0).

%% QUIC_CONNECTION_EVENT_TYPE
-define(QUIC_CONNECTION_EVENT_CONNECTED                         , 0).
-define(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT   , 1).
-define(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER        , 2).
-define(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE                 , 3).
-define(QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED             , 4).
-define(QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED              , 5).
-define(QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED               , 6).
-define(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE                 , 7).
-define(QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS                , 8).
-define(QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED           , 9).
-define(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED            , 10).
-define(QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED                 , 11).
-define(QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED       , 12).
-define(QUIC_CONNECTION_EVENT_RESUMED                           , 13).
-define(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED        , 14).
-define(QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED         , 15).


%% STREAM SHUTDOWN FLAGS
-define(QUIC_STREAM_SHUTDOWN_FLAG_NONE          , 0).
-define(QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL      , 1).   % Cleanly closes the send path.
-define(QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND    , 2).   % Abruptly closes the send path.
-define(QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE , 4).   % Abruptly closes the receive path.
-define(QUIC_STREAM_SHUTDOWN_FLAG_ABORT         , 6).   % Abruptly closes both send and receive paths.
-define(QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE     , 8).


%% CONNECTED SHUTDOWN FLAGS
-define(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE      , 0).
-define(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT    , 1).
-endif. %% QUICER_HRL
