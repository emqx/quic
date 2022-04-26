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


%% CONNECTION SHUTDOWN FLAGS
-define(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE      , 0).
-define(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT    , 1).



%% QUIC_CREDENTIAL_FLAGS
-define(QUIC_CREDENTIAL_FLAG_NONE                                   , 0x00000000).
-define(QUIC_CREDENTIAL_FLAG_CLIENT                                 , 0x00000001). %% Lack of client flag indicates server.
-define(QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS                      , 0x00000002).
-define(QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION              , 0x00000004).
-define(QUIC_CREDENTIAL_FLAG_ENABLE_OCSP                            , 0x00000008). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED          , 0x00000010).
-define(QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION           , 0x00000020). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION          , 0x00000040). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION , 0x00000080). %% OpenSSL only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT              , 0x00000100). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN                 , 0x00000200). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT    , 0x00000400). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK             , 0x00000800). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE              , 0x00001000). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES              , 0x00002000).
-define(QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES              , 0x00004000). %% OpenSSL only currently

-endif. %% QUICER_HRL
