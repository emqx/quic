%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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
%%% % @noformat
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


-define(QUIC_SEND_COMPLETE_SUCCESS                  , 0).
-define(QUIC_SEND_COMPLETE_CANCELLED                , 1).
%% QUIC_LISTENER_EVENT_TYPE
-define(QUIC_LISTENER_EVENT_NEW_CONNECTION          , 0).
-define(QUIC_LISTENER_EVENT_STOP_COMPLETE           , 1).

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


%% STREAM OPEN FLAGS
-define(QUIC_STREAM_OPEN_FLAG_NONE                          , 0).
-define(QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL                , 1).
-define(QUIC_STREAM_OPEN_FLAG_0_RTT                         , 2).

%% STREAM START FLAGS
-define(QUIC_STREAM_START_FLAG_NONE                          , 0).
-define(QUIC_STREAM_START_FLAG_IMMEDIATE                     , 1).
-define(QUIC_STREAM_START_FLAG_FAIL_BLOCKED                  , 2).
-define(QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL              , 4).
-define(QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT          , 8).
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
-define(QUIC_CREDENTIAL_FLAG_NONE                                   , 16#00000000).
-define(QUIC_CREDENTIAL_FLAG_CLIENT                                 , 16#00000001). %% Lack of client flag indicates server.
-define(QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS                      , 16#00000002).
-define(QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION              , 16#00000004).
-define(QUIC_CREDENTIAL_FLAG_ENABLE_OCSP                            , 16#00000008). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED          , 16#00000010).
-define(QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION           , 16#00000020). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION          , 16#00000040). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION , 16#00000080). %% OpenSSL only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT              , 16#00000100). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN                 , 16#00000200). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT    , 16#00000400). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK             , 16#00000800). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE              , 16#00001000). %% Schannel only currently
-define(QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES              , 16#00002000).
-define(QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES              , 16#00004000). %% OpenSSL only currently

%% QUICER_CONNECTION_EVENT_MASKS
-define(QUICER_CONNECTION_EVENT_MASK_NST                            , 16#00000001).
-define(QUICER_CONNECTION_EVENT_MASK_NO_STREAMS_AVAILABLE           , 16#00000002).

%% QUICER_STREAM_EVENT_MASKS
-define(QUICER_STREAM_EVENT_MASK_START_COMPLETE                      , 16#00000001).

%% QUIC SEND FLAGS
-define(QUIC_SEND_FLAG_NONE                     , 16#0000).
-define(QUIC_SEND_FLAG_ALLOW_0_RTT              , 16#0001).   % Allows the use of encrypting with 0-RTT key.
-define(QUIC_SEND_FLAG_START                    , 16#0002).   % Asynchronously starts the stream with the sent data.
-define(QUIC_SEND_FLAG_FIN                      , 16#0004).   % Indicates the request is the one last sent on the stream.
-define(QUIC_SEND_FLAG_DGRAM_PRIORITY           , 16#0008).   % Indicates the datagram is higher priority than others.
-define(QUIC_SEND_FLAG_DELAY_SEND               , 16#0010).
%% QUICER SEND FLAG
-define(QUICER_SEND_FLAG_SYNC                   , 16#1000).

%% QUIC RECV FLAGS
-define(QUIC_RECEIVE_FLAG_NONE                  , 16#0000).
-define(QUIC_RECEIVE_FLAG_0_RTT                 , 16#0001).
-define(QUIC_RECEIVE_FLAG_FIN                   , 16#0002).

%% QUIC DATAGRAM_SEND_STATE
-define(QUIC_DATAGRAM_SEND_UNKNOWN, dgram_send_unknown).                  %% Not yet sent.
-define(QUIC_DATAGRAM_SEND_SENT, dgram_send_sent).                        %% Sent and awaiting acknowledegment
-define(QUIC_DATAGRAM_SEND_LOST_SUSPECT, dgram_send_lost_suspect).        %% Suspected as lost, but still tracked
-define(QUIC_DATAGRAM_SEND_LOST_DISCARDED, dgram_send_lost_discarded).    %% Lost and not longer being tracked
-define(QUIC_DATAGRAM_SEND_ACKNOWLEDGED, dgram_send_acknowledged).        %% Acknowledged
-define(QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS, dgram_send_acknowledged_spurious).   %% Acknowledged after being suspected lost
-define(QUIC_DATAGRAM_SEND_CANCELED, dgram_send_canceled).

-record(quic_data, {
    offset = 0 :: non_neg_integer(),
    size = 0 :: non_neg_integer(),
    flags = 0 :: integer(),
    bin :: binary()
}).

-define(QUIC_LOAD_BALANCING_DISABLED, 0).
-define(QUIC_LOAD_BALANCING_SERVER_ID_IP, 1).
-define(QUIC_LOAD_BALANCING_SERVER_ID_FIXED, 2).
-define(QUIC_LOAD_BALANCING_COUNT, 3).
-define(QUICER_LOAD_BALANCING_IFIP_AS_SERVER_ID, 100). %% User Network Interface IP as Server ID

-define(QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, 0).
-define(QUIC_CONGESTION_CONTROL_ALGORITHM_BBR, 1).


-define(QUIC_TLS_ALERT_CODE_SUCCESS, 16#ffff).       % Not a real TlsAlert
-define(QUIC_TLS_ALERT_CODE_UNEXPECTED_MESSAGE, 10).
-define(QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE, 42).
-define(QUIC_TLS_ALERT_CODE_UNSUPPORTED_CERTIFICATE, 43).
-define(QUIC_TLS_ALERT_CODE_CERTIFICATE_REVOKED, 44).
-define(QUIC_TLS_ALERT_CODE_CERTIFICATE_EXPIRED, 45).
-define(QUIC_TLS_ALERT_CODE_CERTIFICATE_UNKNOWN, 46).
-define(QUIC_TLS_ALERT_CODE_ILLEGAL_PARAMETER, 47).
-define(QUIC_TLS_ALERT_CODE_UNKNOWN_CA, 48).
-define(QUIC_TLS_ALERT_CODE_ACCESS_DENIED, 49).
-define(QUIC_TLS_ALERT_CODE_INSUFFICIENT_SECURITY, 71).
-define(QUIC_TLS_ALERT_CODE_INTERNAL_ERROR, 80).
-define(QUIC_TLS_ALERT_CODE_USER_CANCELED, 90).
-define(QUIC_TLS_ALERT_CODE_CERTIFICATE_REQUIRED, 116).
-define(QUIC_TLS_ALERT_CODE_MAX, 255).

-record(probe_state, {
    final :: term() | undefined,
    sent_at :: integer() | undefined,
    suspect_lost_at :: integer() | undefined,
    final_at :: integer() | undefined
}).

-endif. %% QUICER_HRL
