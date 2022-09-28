/*--------------------------------------------------------------------
Copyright (c) 2021 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------------------------------------------------------------*/

#include "quicer_nif.h"

#include <dlfcn.h>

#include "quicer_listener.h"

static ERL_NIF_TERM connection_controlling_process(ErlNifEnv *env,
                                                   QuicerConnCTX *c_ctx,
                                                   const ErlNifPid *caller,
                                                   const ERL_NIF_TERM *pid);

static ERL_NIF_TERM stream_controlling_process(ErlNifEnv *env,
                                               QuicerStreamCTX *s_ctx,
                                               const ErlNifPid *caller,
                                               const ERL_NIF_TERM *pid);

/*
** atoms in use, initialized while load nif
*/

ERL_NIF_TERM ATOM_TRUE;
ERL_NIF_TERM ATOM_FALSE;

// quicer internal 'errors'
ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;
ERL_NIF_TERM ATOM_REG_FAILED;
ERL_NIF_TERM ATOM_OPEN_FAILED;
ERL_NIF_TERM ATOM_CTX_INIT_FAILED;
ERL_NIF_TERM ATOM_BAD_PID;
ERL_NIF_TERM ATOM_CONFIG_ERROR;
ERL_NIF_TERM ATOM_PARAM_ERROR;
ERL_NIF_TERM ATOM_CERT_ERROR;
ERL_NIF_TERM ATOM_BAD_MON;
ERL_NIF_TERM ATOM_LISTENER_OPEN_ERROR;
ERL_NIF_TERM ATOM_LISTENER_START_ERROR;
ERL_NIF_TERM ATOM_BADARG;
ERL_NIF_TERM ATOM_CONN_OPEN_ERROR;
ERL_NIF_TERM ATOM_CONN_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_OPEN_ERROR;
ERL_NIF_TERM ATOM_STREAM_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_SEND_ERROR;
ERL_NIF_TERM ATOM_DGRAM_SEND_ERROR;
ERL_NIF_TERM ATOM_SOCKNAME_ERROR;
ERL_NIF_TERM ATOM_OWNER_DEAD;
ERL_NIF_TERM ATOM_NOT_OWNER;

// Mirror 'errors' in msquic_linux.h
ERL_NIF_TERM ATOM_ERROR_NO_ERROR;
ERL_NIF_TERM ATOM_ERROR_CONTINUE;
ERL_NIF_TERM ATOM_ERROR_NOT_READY;
ERL_NIF_TERM ATOM_ERROR_NOT_ENOUGH_MEMORY;
ERL_NIF_TERM ATOM_ERROR_INVALID_STATE;
ERL_NIF_TERM ATOM_ERROR_INVALID_PARAMETER;
ERL_NIF_TERM ATOM_ERROR_NOT_SUPPORTED;
ERL_NIF_TERM ATOM_ERROR_NOT_FOUND;
ERL_NIF_TERM ATOM_ERROR_BUFFER_OVERFLOW;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_REFUSED;
ERL_NIF_TERM ATOM_ERROR_OPERATION_ABORTED;
ERL_NIF_TERM ATOM_ERROR_HANDSHAKE_FAILURE;
ERL_NIF_TERM ATOM_ERROR_NETWORK_UNREACHABLE;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_IDLE;
ERL_NIF_TERM ATOM_ERROR_INTERNAL_ERROR;
ERL_NIF_TERM ATOM_ERROR_PROTOCOL_ERROR;
ERL_NIF_TERM ATOM_ERROR_VER_NEG_ERROR;
ERL_NIF_TERM ATOM_ERROR_EPOLL_ERROR;
ERL_NIF_TERM ATOM_ERROR_DNS_RESOLUTION_ERROR;
ERL_NIF_TERM ATOM_ERROR_SOCKET_ERROR;
ERL_NIF_TERM ATOM_ERROR_SSL_ERROR;
ERL_NIF_TERM ATOM_ERROR_USER_CANCELED;
ERL_NIF_TERM ATOM_ERROR_ALPN_NEG_FAILURE;

ERL_NIF_TERM ATOM_UNKNOWN_STATUS_CODE;
ERL_NIF_TERM ATOM_QUIC_STATUS_SUCCESS;
ERL_NIF_TERM ATOM_QUIC_STATUS_PENDING;
ERL_NIF_TERM ATOM_QUIC_STATUS_CONTINUE;
ERL_NIF_TERM ATOM_QUIC_STATUS_OUT_OF_MEMORY;
ERL_NIF_TERM ATOM_QUIC_STATUS_INVALID_PARAMETER;
ERL_NIF_TERM ATOM_QUIC_STATUS_INVALID_STATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_NOT_SUPPORTED;
ERL_NIF_TERM ATOM_QUIC_STATUS_NOT_FOUND;
ERL_NIF_TERM ATOM_QUIC_STATUS_BUFFER_TOO_SMALL;
ERL_NIF_TERM ATOM_QUIC_STATUS_HANDSHAKE_FAILURE;
ERL_NIF_TERM ATOM_QUIC_STATUS_ABORTED;
ERL_NIF_TERM ATOM_QUIC_STATUS_ADDRESS_IN_USE;
ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_TIMEOUT;
ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_IDLE;
ERL_NIF_TERM ATOM_QUIC_STATUS_INTERNAL_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_REFUSED;
ERL_NIF_TERM ATOM_QUIC_STATUS_PROTOCOL_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_VER_NEG_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_UNREACHABLE;
ERL_NIF_TERM ATOM_QUIC_STATUS_TLS_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_USER_CANCELED;
ERL_NIF_TERM ATOM_QUIC_STATUS_ALPN_NEG_FAILURE;
ERL_NIF_TERM ATOM_QUIC_STATUS_STREAM_LIMIT_REACHED;
// TLS ERROR_STATUS
ERL_NIF_TERM ATOM_QUIC_STATUS_CLOSE_NOTIFY;
ERL_NIF_TERM ATOM_QUIC_STATUS_BAD_CERTIFICATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_UNSUPPORTED_CERTIFICATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_REVOKED_CERTIFICATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_EXPIRED_CERTIFICATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_UNKNOWN_CERTIFICATE;
ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_EXPIRED;
ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT;

// option keys
ERL_NIF_TERM ATOM_CERT;
ERL_NIF_TERM ATOM_KEY;
ERL_NIF_TERM ATOM_PASSWORD;
ERL_NIF_TERM ATOM_ALPN;
ERL_NIF_TERM ATOM_HANDLER;

/*-------------------------------------------------------*/
/*         msquic  execution profile for registration    */
/*-------------------------------------------------------*/
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY; // Default
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;

/*-----------------------------------------*/
/*         msquic params starts             */
/*-----------------------------------------*/

// Parameters for QUIC_PARAM_LEVEL_GLOBAL.
//
ERL_NIF_TERM ATOM_QUIC_GLOBAL;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SETTINGS;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_VERSION;

//
// Parameters for QUIC_PARAM_LEVEL_REGISTRATION.
//
ERL_NIF_TERM ATOM_QUIC_REGISTRATION;
ERL_NIF_TERM ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX;

//
// Parameters for QUIC_PARAM_LEVEL_CONFIGURATION.
//
ERL_NIF_TERM ATOM_QUIC_CONFIGURATION;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS;

//
// Parameters for QUIC_PARAM_LEVEL_LISTENER.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
ERL_NIF_TERM ATOM_QUIC_PARAM_LISTENER_STATS;

//
// Parameters for QUIC_PARAM_LEVEL_CONNECTION.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_QUIC_VERSION;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_SETTINGS;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STATISTICS;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;

ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION;

ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE;

//
// Parameters for QUIC_PARAM_LEVEL_TLS.
//
ERL_NIF_TERM ATOM_QUIC_TLS;
ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W;
ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO;
ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN;

//
// Parameters for QUIC_PARAM_LEVEL_STREAM.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_ID;
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH;
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE;
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_PRIORITY;

/*-----------------------*/
/* msquic params ends     */
/*-----------------------*/

/*----------------------------------------------------------*/
/* QUIC_SETTINGS starts      */
/*----------------------------------------------------------*/

ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxBytesPerKey;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_HandshakeIdleTimeoutMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_IdleTimeoutMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_TlsServerMaxSendBuffer;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_StreamRecvWindowDefault;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_StreamRecvBufferDefault;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_ConnFlowControlWindow;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxWorkerQueueDelayUs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxStatelessOperations;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_InitialWindowPackets;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_SendIdleTimeoutMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_InitialRttMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxAckDelayMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_DisconnectTimeoutMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_KeepAliveIntervalMs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_PeerBidiStreamCount;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_PeerUnidiStreamCount;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_RetryMemoryLimit;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_LoadBalancingMode;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxOperationsPerDrain;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_SendBufferingEnabled;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_PacingEnabled;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MigrationEnabled;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_DatagramReceiveEnabled;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_ServerResumptionLevel;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_VersionNegotiationExtEnabled;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_DesiredVersionsList;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_DesiredVersionsListLength;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MinimumMtu;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaximumMtu;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MtuDiscoverySearchCompleteTimeoutUs;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MtuDiscoveryMissingProbeCount;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxBindingStatelessOperations;
ERL_NIF_TERM ATOM_QUIC_SETTINGS_StatelessOperationExpirationMs;

/*----------------------------------------------------------*/
/* QUIC_SETTINGS ends      */
/*----------------------------------------------------------*/

/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS starts */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_ACTIVE;
ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_OPEN_FLAG;
ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_START_FLAG;
/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS ends  */
/*----------------------------------------------------------*/

ERL_NIF_TERM ATOM_CLOSED;
ERL_NIF_TERM ATOM_STREAM_CLOSED;
ERL_NIF_TERM ATOM_LISTENER_STOPPED;
ERL_NIF_TERM ATOM_TRANS_SHUTDOWN;
ERL_NIF_TERM ATOM_SHUTDOWN;
ERL_NIF_TERM ATOM_PEER_SEND_SHUTDOWN;
ERL_NIF_TERM ATOM_PEER_SEND_ABORTED;
ERL_NIF_TERM ATOM_PEER_RECEIVE_ABORTED;
ERL_NIF_TERM ATOM_PEER_ADDRESS_CHANGED;
ERL_NIF_TERM ATOM_PEER_ACCEPTED;
ERL_NIF_TERM ATOM_LOCAL_ADDRESS_CHANGED;
ERL_NIF_TERM ATOM_STREAMS_AVAILABLE;
ERL_NIF_TERM ATOM_PEER_NEEDS_STREAMS;
ERL_NIF_TERM ATOM_START_COMPLETE;
ERL_NIF_TERM ATOM_SEND_COMPLETE;
ERL_NIF_TERM ATOM_SEND_DGRAM_COMPLETE;
ERL_NIF_TERM ATOM_EINVAL;
ERL_NIF_TERM ATOM_QUIC;
ERL_NIF_TERM ATOM_QUIC_PASSIVE;
ERL_NIF_TERM ATOM_QUIC_EVENT_MASK;
ERL_NIF_TERM ATOM_NST_RECEIVED;
ERL_NIF_TERM ATOM_NST;
ERL_NIF_TERM ATOM_DGRAM;
ERL_NIF_TERM ATOM_DGRAM_MAX_LEN;
ERL_NIF_TERM ATOM_DEBUG;
ERL_NIF_TERM ATOM_ONCE;
ERL_NIF_TERM ATOM_NEW_CONN;
ERL_NIF_TERM ATOM_CONNECTED;
ERL_NIF_TERM ATOM_CONN_RESUMED;
ERL_NIF_TERM ATOM_NEW_STREAM;

/*----------------------------------------------------------*/
/* for code insert with SNABBKAFFE   */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_SNABBKAFFE_COLLECTOR;
ERL_NIF_TERM ATOM_TRACE;
// Trace point Context, nif for callback
ERL_NIF_TERM ATOM_CONTEXT;
ERL_NIF_TERM ATOM_NIF;
ERL_NIF_TERM ATOM_CALLBACK;
ERL_NIF_TERM ATOM_TAG;
ERL_NIF_TERM ATOM_RESOURCE_ID;
ERL_NIF_TERM ATOM_MARK;
ERL_NIF_TERM ATOM_KIND;
ERL_NIF_TERM ATOM_SNK_KIND;
ERL_NIF_TERM ATOM_SNK_META;
ERL_NIF_TERM ATOM_GEN_CAST;
ERL_NIF_TERM ATOM_FUNCTION;
ERL_NIF_TERM ATOM_SNABBKAFFE_NEMESIS;

/*----------------------------------------------------------*/
/* Additional Connection Opt                                */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_SSL_KEYLOGFILE_NAME;
ERL_NIF_TERM ATOM_ALLOW_INSECURE;

/*----------------------------------------------------------*/
/* Used in messages to the owners */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_IS_RESUMED;
ERL_NIF_TERM ATOM_ALPNS;
ERL_NIF_TERM ATOM_IS_HANDSHAKE_COMPLETED;
ERL_NIF_TERM ATOM_IS_PEER_ACKED;
ERL_NIF_TERM ATOM_IS_APP_CLOSING;
ERL_NIF_TERM ATOM_BIDI_STREAMS;
ERL_NIF_TERM ATOM_UNIDI_STREAMS;
ERL_NIF_TERM ATOM_UNDEFINED;

// Mirror 'status' in msquic_linux.h

/*
**  Helper macros
*/
#define INIT_ATOMS                                                            \
  ATOM(ATOM_TRUE, true);                                                      \
  ATOM(ATOM_FALSE, false);                                                    \
                                                                              \
  ATOM(ATOM_OK, ok);                                                          \
  ATOM(ATOM_ERROR, error);                                                    \
  ATOM(ATOM_REG_FAILED, reg_failed);                                          \
  ATOM(ATOM_OPEN_FAILED, open_failed);                                        \
  ATOM(ATOM_CTX_INIT_FAILED, ctx_init_failed);                                \
  ATOM(ATOM_BAD_PID, bad_pid);                                                \
  ATOM(ATOM_CONFIG_ERROR, config_error);                                      \
  ATOM(ATOM_PARAM_ERROR, param_error);                                        \
  ATOM(ATOM_CERT_ERROR, cert_error);                                          \
  ATOM(ATOM_BAD_MON, bad_mon);                                                \
  ATOM(ATOM_LISTENER_OPEN_ERROR, listener_open_error);                        \
  ATOM(ATOM_LISTENER_START_ERROR, listener_start_error);                      \
  ATOM(ATOM_BADARG, badarg);                                                  \
  ATOM(ATOM_CONN_OPEN_ERROR, conn_open_error);                                \
  ATOM(ATOM_CONN_START_ERROR, conn_start_error);                              \
  ATOM(ATOM_STREAM_OPEN_ERROR, stm_open_error);                               \
  ATOM(ATOM_STREAM_START_ERROR, stm_start_error);                             \
  ATOM(ATOM_STREAM_SEND_ERROR, stm_send_error);                               \
  ATOM(ATOM_DGRAM_SEND_ERROR, dgram_send_error);                              \
  ATOM(ATOM_OWNER_DEAD, owner_dead);                                          \
  ATOM(ATOM_NOT_OWNER, not_owner);                                            \
                                                                              \
  ATOM(ATOM_ERROR_NO_ERROR, no_error);                                        \
  ATOM(ATOM_ERROR_CONTINUE, contiune);                                        \
  ATOM(ATOM_ERROR_NOT_READY, not_ready);                                      \
  ATOM(ATOM_ERROR_NOT_ENOUGH_MEMORY, not_enough_mem);                         \
  ATOM(ATOM_ERROR_INVALID_STATE, invalid_state);                              \
  ATOM(ATOM_ERROR_INVALID_PARAMETER, invalid_parm);                           \
  ATOM(ATOM_ERROR_NOT_SUPPORTED, not_supported);                              \
  ATOM(ATOM_ERROR_NOT_FOUND, not_found);                                      \
  ATOM(ATOM_ERROR_BUFFER_OVERFLOW, buffer_overflow);                          \
  ATOM(ATOM_ERROR_CONNECTION_REFUSED, connection_refused);                    \
  ATOM(ATOM_ERROR_OPERATION_ABORTED, operation_aborted);                      \
  ATOM(ATOM_ERROR_HANDSHAKE_FAILURE, handshake_failure);                      \
  ATOM(ATOM_ERROR_NETWORK_UNREACHABLE, network_unreachable);                  \
  ATOM(ATOM_ERROR_CONNECTION_IDLE, connection_idle);                          \
  ATOM(ATOM_ERROR_INTERNAL_ERROR, internal_error);                            \
  ATOM(ATOM_ERROR_PROTOCOL_ERROR, protocol_error);                            \
  ATOM(ATOM_ERROR_VER_NEG_ERROR, vsn_neg_error);                              \
  ATOM(ATOM_ERROR_EPOLL_ERROR, epoll_error);                                  \
  ATOM(ATOM_ERROR_DNS_RESOLUTION_ERROR, dns_resolution_error);                \
  ATOM(ATOM_ERROR_SOCKET_ERROR, socket_error);                                \
  ATOM(ATOM_ERROR_SSL_ERROR, ssl_error);                                      \
  ATOM(ATOM_ERROR_USER_CANCELED, user_canceled);                              \
  ATOM(ATOM_ERROR_ALPN_NEG_FAILURE, alpn_neg_failure);                        \
                                                                              \
  ATOM(ATOM_UNKNOWN_STATUS_CODE, unknown_quic_status);                        \
  ATOM(ATOM_QUIC_STATUS_SUCCESS, success);                                    \
  ATOM(ATOM_QUIC_STATUS_PENDING, pending);                                    \
  ATOM(ATOM_QUIC_STATUS_CONTINUE, continue);                                  \
  ATOM(ATOM_QUIC_STATUS_OUT_OF_MEMORY, out_of_memory);                        \
  ATOM(ATOM_QUIC_STATUS_INVALID_PARAMETER, invalid_parameter);                \
  ATOM(ATOM_QUIC_STATUS_INVALID_STATE, invalid_state);                        \
  ATOM(ATOM_QUIC_STATUS_NOT_SUPPORTED, not_supported);                        \
  ATOM(ATOM_QUIC_STATUS_NOT_FOUND, not_found);                                \
  ATOM(ATOM_QUIC_STATUS_BUFFER_TOO_SMALL, buffer_too_small);                  \
  ATOM(ATOM_QUIC_STATUS_HANDSHAKE_FAILURE, handshake_failure);                \
  ATOM(ATOM_QUIC_STATUS_ABORTED, aborted);                                    \
  ATOM(ATOM_QUIC_STATUS_ADDRESS_IN_USE, address_in_use);                      \
  ATOM(ATOM_QUIC_STATUS_CONNECTION_TIMEOUT, connection_timeout);              \
  ATOM(ATOM_QUIC_STATUS_CONNECTION_IDLE, connection_idle);                    \
  ATOM(ATOM_QUIC_STATUS_INTERNAL_ERROR, internal_error);                      \
  ATOM(ATOM_QUIC_STATUS_CONNECTION_REFUSED, connection_refused);              \
  ATOM(ATOM_QUIC_STATUS_PROTOCOL_ERROR, protocol_error);                      \
  ATOM(ATOM_QUIC_STATUS_VER_NEG_ERROR, ver_neg_error);                        \
  ATOM(ATOM_QUIC_STATUS_UNREACHABLE, unreachable);                            \
  ATOM(ATOM_QUIC_STATUS_TLS_ERROR, tls_error);                                \
  ATOM(ATOM_QUIC_STATUS_USER_CANCELED, user_canceled);                        \
  ATOM(ATOM_QUIC_STATUS_ALPN_NEG_FAILURE, alpn_neg_failure);                  \
  ATOM(ATOM_QUIC_STATUS_STREAM_LIMIT_REACHED, stream_limit_reached);          \
  ATOM(ATOM_QUIC_STATUS_CLOSE_NOTIFY, atom_quic_status_close_notify);         \
  /*  TLS Error Status */                                                     \
  ATOM(ATOM_QUIC_STATUS_BAD_CERTIFICATE, atom_quic_status_bad_certificate);   \
  ATOM(ATOM_QUIC_STATUS_UNSUPPORTED_CERTIFICATE,                              \
       atom_quic_status_unsupported_certificate);                             \
  ATOM(ATOM_QUIC_STATUS_REVOKED_CERTIFICATE,                                  \
       atom_quic_status_revoked_certificate);                                 \
  ATOM(ATOM_QUIC_STATUS_EXPIRED_CERTIFICATE,                                  \
       atom_quic_status_expired_certificate);                                 \
  ATOM(ATOM_QUIC_STATUS_UNKNOWN_CERTIFICATE,                                  \
       atom_quic_status_unknown_certificate);                                 \
  ATOM(ATOM_QUIC_STATUS_CERT_EXPIRED, atom_quic_status_cert_expired);         \
  ATOM(ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT,                                  \
       atom_quic_status_cert_untrusted_root);                                 \
  /*-------------------------------------------------------*/                 \
  /*         msquic  execution profile for reg             */                 \
  /*-------------------------------------------------------*/                 \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY,                               \
       quic_execution_profile_low_latency);                                   \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,                       \
       quic_execution_profile_type_max_throughput);                           \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER,                            \
       quic_execution_profile_type_scavenger);                                \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME,                            \
       quic_execution_profile_type_real_time);                                \
  /*-----------------------------------------*/                               \
  /*         msquic params starts            */                               \
  /*-----------------------------------------*/                               \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_GLOBAL. */                              \
  ATOM(ATOM_QUIC_GLOBAL, quic_global);                                        \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,                           \
       param_global_retry_memory_percent);                                    \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS,                             \
       param_global_supported_versions);                                      \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,                             \
       param_global_load_balacing_mode);                                      \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS, param_global_perf_counters);     \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SETTINGS, param_global_settings);               \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_VERSION, param_global_version);                 \
                                                                              \
  /*Parameters for QUIC_PARAM_LEVEL_REGISTRATION.*/                           \
  ATOM(ATOM_QUIC_REGISTRATION, quic_registration);                            \
  ATOM(ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX,                               \
       param_registration_cid_prefix);                                        \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_CONFIGURATION. */                        \
  ATOM(ATOM_QUIC_CONFIGURATION, quic_configuration);                          \
  ATOM(ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS, param_configuration_settings); \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_LISTENER. */                             \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS, param_listener_local_address); \
  ATOM(ATOM_QUIC_PARAM_LISTENER_STATS, param_listener_stats);                 \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */                           \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_QUIC_VERSION, param_conn_quic_version);           \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS, param_conn_local_address);         \
  ATOM(ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS, param_conn_remote_address);       \
  ATOM(ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR, param_conn_ideal_processor);     \
  ATOM(ATOM_QUIC_PARAM_CONN_SETTINGS, param_conn_settings);                   \
  ATOM(ATOM_QUIC_PARAM_CONN_STATISTICS, param_conn_statistics);               \
  ATOM(ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT, param_conn_statistics_plat);     \
  ATOM(ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING, param_conn_share_udp_binding); \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT,                          \
       param_conn_local_bidi_stream_count);                                   \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT,                         \
       param_conn_local_unidi_stream_count);                                  \
  ATOM(ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS, param_conn_max_stream_ids);       \
  ATOM(ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,                              \
       param_conn_close_reason_phrase);                                       \
  ATOM(ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,                         \
       param_conn_stream_scheduling_scheme);                                  \
  ATOM(ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,                         \
       param_conn_datagram_receive_enabled);                                  \
  ATOM(ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED,                            \
       param_conn_datagram_send_enabled);                                     \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,                          \
       param_conn_disable_1rtt_encryption);                                   \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET, param_conn_resumption_ticket); \
  ATOM(ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID,                           \
       param_conn_peer_certificate_valid);                                    \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE, param_conn_local_interface);     \
  /* Parameters for QUIC_PARAM_LEVEL_TLS. */                                  \
  ATOM(ATOM_QUIC_TLS, quic_tls)                                               \
  ATOM(ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,                      \
       param_tls_schannel_context_attribute_w);                               \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO, param_tls_handshake_info);         \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN, param_tls_negotiated_alpn);       \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_STREAM.  */                             \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_STREAM_ID, param_stream_id);                           \
  ATOM(ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH, param_stream_0rtt_length);         \
  ATOM(ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,                         \
       param_stream_ideal_send_buffer_size);                                  \
  ATOM(ATOM_QUIC_PARAM_STREAM_PRIORITY, param_stream_priority);               \
                                                                              \
  /*-----------------------*/                                                 \
  /* msquic params ends     */                                                \
  /*-----------------------*/                                                 \
                                                                              \
  /*                 QUIC_SETTINGS start                      */              \
  ATOM(ATOM_QUIC_SETTINGS_MaxBytesPerKey, max_bytes_per_key);                 \
  ATOM(ATOM_QUIC_SETTINGS_HandshakeIdleTimeoutMs, handshake_idle_timeout_ms); \
  ATOM(ATOM_QUIC_SETTINGS_IdleTimeoutMs, idle_timeout_ms);                    \
  ATOM(ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer,                             \
       tls_client_max_send_buffer);                                           \
  ATOM(ATOM_QUIC_SETTINGS_TlsServerMaxSendBuffer,                             \
       tls_server_max_send_buffer);                                           \
  ATOM(ATOM_QUIC_SETTINGS_StreamRecvWindowDefault,                            \
       stream_recv_window_default);                                           \
  ATOM(ATOM_QUIC_SETTINGS_StreamRecvBufferDefault,                            \
       stream_recv_buffer_default);                                           \
  ATOM(ATOM_QUIC_SETTINGS_ConnFlowControlWindow, conn_flow_control_window);   \
  ATOM(ATOM_QUIC_SETTINGS_MaxWorkerQueueDelayUs, max_worker_queue_delay_us);  \
  ATOM(ATOM_QUIC_SETTINGS_MaxStatelessOperations, max_stateless_operations);  \
  ATOM(ATOM_QUIC_SETTINGS_InitialWindowPackets, initial_window_packets);      \
  ATOM(ATOM_QUIC_SETTINGS_SendIdleTimeoutMs, send_idle_timeout_ms);           \
  ATOM(ATOM_QUIC_SETTINGS_InitialRttMs, initial_rtt_ms);                      \
  ATOM(ATOM_QUIC_SETTINGS_MaxAckDelayMs, max_ack_delay_ms);                   \
  ATOM(ATOM_QUIC_SETTINGS_DisconnectTimeoutMs, disconnect_timeout_ms);        \
  ATOM(ATOM_QUIC_SETTINGS_KeepAliveIntervalMs, keep_alive_interval_ms);       \
  ATOM(ATOM_QUIC_SETTINGS_PeerBidiStreamCount, peer_bidi_stream_count);       \
  ATOM(ATOM_QUIC_SETTINGS_PeerUnidiStreamCount, peer_unidi_stream_count);     \
  ATOM(ATOM_QUIC_SETTINGS_RetryMemoryLimit, retry_memory_limit);              \
  ATOM(ATOM_QUIC_SETTINGS_LoadBalancingMode, load_balancing_mode);            \
  ATOM(ATOM_QUIC_SETTINGS_MaxOperationsPerDrain, max_operations_per_drain);   \
  ATOM(ATOM_QUIC_SETTINGS_SendBufferingEnabled, send_buffering_enabled);      \
  ATOM(ATOM_QUIC_SETTINGS_PacingEnabled, pacing_enabled);                     \
  ATOM(ATOM_QUIC_SETTINGS_MigrationEnabled, migration_enabled);               \
  ATOM(ATOM_QUIC_SETTINGS_DatagramReceiveEnabled, datagram_receive_enabled);  \
  ATOM(ATOM_QUIC_SETTINGS_ServerResumptionLevel, server_resumption_level);    \
  ATOM(ATOM_QUIC_SETTINGS_VersionNegotiationExtEnabled,                       \
       version_negotiation_ext_enabled);                                      \
  ATOM(ATOM_QUIC_SETTINGS_DesiredVersionsList, desired_versions_list);        \
  ATOM(ATOM_QUIC_SETTINGS_DesiredVersionsListLength,                          \
       desired_versions_list_length);                                         \
  ATOM(ATOM_QUIC_SETTINGS_MinimumMtu, minimum_mtu);                           \
  ATOM(ATOM_QUIC_SETTINGS_MaximumMtu, maximum_mtu);                           \
  ATOM(ATOM_QUIC_SETTINGS_MtuDiscoverySearchCompleteTimeoutUs,                \
       mtu_discovery_search_complete_timeout_us);                             \
  ATOM(ATOM_QUIC_SETTINGS_MtuDiscoveryMissingProbeCount,                      \
       mtu_discovery_missing_probe_count);                                    \
  ATOM(ATOM_QUIC_SETTINGS_MaxBindingStatelessOperations,                      \
       max_binding_stateless_operations);                                     \
  ATOM(ATOM_QUIC_SETTINGS_StatelessOperationExpirationMs,                     \
       stateless_operation_expiration_ms);                                    \
  /*                  QUIC_SETTINGS end                        */             \
  /*                  QUIC_STREAM_OPTS start                        */        \
  ATOM(ATOM_QUIC_STREAM_OPTS_ACTIVE, active)                                  \
  ATOM(ATOM_QUIC_STREAM_OPTS_OPEN_FLAG, open_flag)                            \
  ATOM(ATOM_QUIC_STREAM_OPTS_START_FLAG, start_flag)                          \
  /*                  QUIC_STREAM_OPTS end                        */          \
  ATOM(ATOM_CERT, cert);                                                      \
  ATOM(ATOM_KEY, key);                                                        \
  ATOM(ATOM_PASSWORD, password);                                              \
  ATOM(ATOM_ALPN, alpn);                                                      \
  ATOM(ATOM_HANDLER, handler);                                                \
  ATOM(ATOM_CLOSED, closed);                                                  \
  ATOM(ATOM_STREAM_CLOSED, stream_closed);                                    \
  ATOM(ATOM_LISTENER_STOPPED, listener_stopped);                              \
  ATOM(ATOM_TRANS_SHUTDOWN, transport_shutdown);                              \
  ATOM(ATOM_SHUTDOWN, shutdown);                                              \
  ATOM(ATOM_PEER_SEND_SHUTDOWN, peer_send_shutdown);                          \
  ATOM(ATOM_PEER_SEND_ABORTED, peer_send_aborted);                            \
  ATOM(ATOM_PEER_RECEIVE_ABORTED, peer_receive_aborted);                      \
  ATOM(ATOM_PEER_ADDRESS_CHANGED, peer_address_changed);                      \
  ATOM(ATOM_PEER_ACCEPTED, peer_accepted);                                    \
  ATOM(ATOM_LOCAL_ADDRESS_CHANGED, local_address_changed);                    \
  ATOM(ATOM_STREAMS_AVAILABLE, streams_available);                            \
  ATOM(ATOM_PEER_NEEDS_STREAMS, peer_needs_streams);                          \
  ATOM(ATOM_START_COMPLETE, start_completed);                                 \
  ATOM(ATOM_SEND_COMPLETE, send_completed);                                   \
  ATOM(ATOM_SEND_DGRAM_COMPLETE, send_dgram_completed);                       \
  ATOM(ATOM_EINVAL, einval);                                                  \
  ATOM(ATOM_QUIC, quic);                                                      \
  ATOM(ATOM_QUIC_PASSIVE, quic_passive);                                      \
  ATOM(ATOM_QUIC_EVENT_MASK, quic_event_mask);                                \
  ATOM(ATOM_NST_RECEIVED, nst_received);                                      \
  ATOM(ATOM_NST, nst);                                                        \
  ATOM(ATOM_DGRAM, dgram);                                                    \
  ATOM(ATOM_DGRAM_MAX_LEN, dgram_max_len);                                    \
  ATOM(ATOM_DEBUG, debug);                                                    \
  ATOM(ATOM_ONCE, once);                                                      \
  ATOM(ATOM_NEW_CONN, new_conn);                                              \
  ATOM(ATOM_CONNECTED, connected);                                            \
  ATOM(ATOM_CONN_RESUMED, connection_resumed);                                \
  ATOM(ATOM_NEW_STREAM, new_stream);                                          \
  ATOM(ATOM_SNABBKAFFE_COLLECTOR, snabbkaffe_collector);                      \
  ATOM(ATOM_TRACE, trace);                                                    \
  ATOM(ATOM_CONTEXT, context);                                                \
  ATOM(ATOM_NIF, nif);                                                        \
  ATOM(ATOM_CALLBACK, callback);                                              \
  ATOM(ATOM_TAG, tag);                                                        \
  ATOM(ATOM_RESOURCE_ID, resource_id);                                        \
  ATOM(ATOM_MARK, mark);                                                      \
  ATOM(ATOM_KIND, kind);                                                      \
  ATOM(ATOM_SNK_KIND, $kind);                                                 \
  ATOM(ATOM_SNK_META, ~meta);                                                 \
  ATOM(ATOM_GEN_CAST, $gen_cast);                                             \
  ATOM(ATOM_FUNCTION, function);                                              \
  ATOM(ATOM_SNABBKAFFE_NEMESIS, snabbkaffe_nemesis);                          \
  ATOM(ATOM_SSL_KEYLOGFILE_NAME, sslkeylogfile);                              \
  ATOM(ATOM_ALLOW_INSECURE, allow_insecure);                                  \
  ATOM(ATOM_IS_RESUMED, is_resumed);                                          \
  ATOM(ATOM_ALPNS, alpns);                                                    \
  ATOM(ATOM_IS_HANDSHAKE_COMPLETED, is_handshake_completed)                   \
  ATOM(ATOM_IS_PEER_ACKED, is_peer_acked)                                     \
  ATOM(ATOM_IS_APP_CLOSING, is_app_closing)                                   \
  ATOM(ATOM_BIDI_STREAMS, bidi_streams)                                       \
  ATOM(ATOM_UNIDI_STREAMS, unidi_streams)                                     \
  ATOM(ATOM_UNDEFINED, undefined);

HQUIC GRegistration = NULL;
const QUIC_API_TABLE *MsQuic = NULL;

// @todo, these flags are not threads safe, wrap it in a context
BOOLEAN isRegistered = false;
BOOLEAN isLibOpened = false;

ErlNifResourceType *ctx_listener_t = NULL;
ErlNifResourceType *ctx_connection_t = NULL;
ErlNifResourceType *ctx_stream_t = NULL;
ErlNifResourceType *ctx_config_t = NULL;

QUIC_REGISTRATION_CONFIG GRegConfig
    = { "quicer_nif", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

void
resource_listener_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                                __unused_parm__ void *obj,
                                __unused_parm__ ErlNifPid *pid,
                                __unused_parm__ ErlNifMonitor *mon)
{
  // @TODO
}

void
resource_listener_dealloc_callback(__unused_parm__ ErlNifEnv *env, void *obj)
{
  QuicerListenerCTX *l_ctx = (QuicerListenerCTX *)obj;

  TP_CB_3(start, (uintptr_t)l_ctx->Listener, 0);

  // Unlike other resources, it is safe to close listener here
  // because MsQuic will stop the listener if it is not and wait for
  // all ongoing listener callback to finish.
  // We should not assert l_ctx->is_closed to be true because it could happen
  // when the listener process is terminated and there is no any acceptors on
  // it.
  //
  if (!l_ctx->is_closed && l_ctx->Listener)
    {
      // We must close listener since there is no chance that any erlang
      // process is able to access the listener via any l_ctx
      MsQuic->ListenerClose(l_ctx->Listener);
    }

  deinit_l_ctx(l_ctx);
  // @TODO notify acceptors that the listener is closed
  TP_CB_3(end, (uintptr_t)l_ctx->Listener, 0);
}

void
resource_conn_dealloc_callback(__unused_parm__ ErlNifEnv *env, void *obj)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)obj;
  TP_CB_3(start, (uintptr_t)c_ctx->Connection, c_ctx->is_closed);
  // must be closed otherwise will trigger callback and casue race cond.
  assert(c_ctx->is_closed == TRUE); // in dealloc
  if (c_ctx->Connection)
    {
      TP_CB_3(close, (uintptr_t)c_ctx->Connection, c_ctx->is_closed);
      MsQuic->ConnectionClose(c_ctx->Connection);
    }
  CXPLAT_FREE(c_ctx->TlsSecrets, QUICER_TLS_SECRETS);
  CXPLAT_FREE(c_ctx->ResumptionTicket, QUICER_RESUME_TICKET);
  CXPLAT_FREE(c_ctx->ssl_keylogfile, QUICER_TRACE);
  AcceptorDestroy(c_ctx->owner);
  deinit_c_ctx(c_ctx);
  TP_CB_3(end, (uintptr_t)c_ctx->Connection, c_ctx->is_closed);
}

void
resource_conn_down_callback(__unused_parm__ ErlNifEnv *env,
                            void *ctx,
                            __unused_parm__ ErlNifPid *pid,
                            __unused_parm__ ErlNifMonitor *mon)
{
  QuicerConnCTX *c_ctx = ctx;
  if (!ctx)
    {
      return;
    }
  else
    {
      TP_CB_3(start, (uintptr_t)c_ctx->Connection, (uintptr_t)ctx);
      MsQuic->ConnectionShutdown(
          c_ctx->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      TP_CB_3(end, (uintptr_t)c_ctx->Connection, (uintptr_t)ctx);
    }
}

void
resource_stream_dealloc_callback(__unused_parm__ ErlNifEnv *env, void *obj)
{
  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)obj;
  TP_CB_3(start, (uintptr_t)s_ctx->Stream, s_ctx->is_closed);
  assert(s_ctx->is_closed == TRUE);
  if (s_ctx->Stream)
    {
      MsQuic->StreamClose(s_ctx->Stream);
    }

  // ensure it is called *After* StreamClose
  enif_release_resource(s_ctx->c_ctx);
  AcceptorDestroy(s_ctx->owner);
  deinit_s_ctx(s_ctx);
  TP_CB_3(end, (uintptr_t)s_ctx->Stream, s_ctx->is_closed);
}

void
resource_stream_down_callback(__unused_parm__ ErlNifEnv *env,
                              void *ctx,
                              __unused_parm__ ErlNifPid *pid,
                              __unused_parm__ ErlNifMonitor *mon)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  QuicerStreamCTX *s_ctx = ctx;

  if (!ctx)
    {
      return;
    }

  TP_CB_3(start, (uintptr_t)s_ctx->Stream, 0);
  if (QUIC_FAILED(status = MsQuic->StreamShutdown(
                      s_ctx->Stream,
                      QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE
                          | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE
                          | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
                      0)))
    {
      TP_CB_3(shutdown_fail, (uintptr_t)s_ctx->Stream, status);
    }
  else
    {
      TP_CB_3(shutdown_success, (uintptr_t)s_ctx->Stream, status);
    }
}

void
resource_config_dealloc_callback(__unused_parm__ ErlNifEnv *env,
                                 __unused_parm__ void *obj)
{
  TP_CB_3(start, (uintptr_t)obj, 0);
  QuicerConfigCTX *config_ctx = (QuicerConfigCTX *)obj;
  // Check if Registration is closed or not
  if (GRegistration && config_ctx->Configuration)
    {
      MsQuic->ConfigurationClose(config_ctx->Configuration);
    }
  TP_CB_3(end, (uintptr_t)obj, 0);
}

/*
** on_load is called when the NIF library is loaded and no previously loaded
*library exists for this module.
*/
static int
on_load(ErlNifEnv *env,
        __unused_parm__ void **priv_data,
        __unused_parm__ ERL_NIF_TERM loadinfo)
{
  int ret_val = 0;

// init atoms in use.
#define ATOM(name, val)                                                       \
  {                                                                           \
    (name) = enif_make_atom(env, #val);                                       \
  }
  INIT_ATOMS
#undef ATOM

  ErlNifResourceFlags flags
      = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

  ErlNifResourceTypeInit streamInit
      = { .dtor = resource_stream_dealloc_callback,
          .down = resource_stream_down_callback,
          .stop = NULL };
  ErlNifResourceTypeInit connInit = { .dtor = resource_conn_dealloc_callback,
                                      .down = resource_conn_down_callback,
                                      .stop = NULL };
  ErlNifResourceTypeInit listenerInit
      = { .dtor = resource_listener_dealloc_callback,
          .down = resource_listener_down_callback,
          .stop = NULL };

  ErlNifResourceTypeInit configInit = {
    .dtor = resource_config_dealloc_callback, .down = NULL, .stop = NULL
  };

  ctx_config_t = enif_open_resource_type_x(env,
                                           "config_context_resource",
                                           &configInit, // init callbacks
                                           flags,
                                           NULL);

  ctx_listener_t = enif_open_resource_type_x(env,
                                             "listener_context_resource",
                                             &listenerInit, // init callbacks
                                             flags,
                                             NULL);
  ctx_connection_t = enif_open_resource_type_x(env,
                                               "connection_context_resource",
                                               &connInit, // init callbacks
                                               flags,
                                               NULL);
  ctx_stream_t = enif_open_resource_type_x(env,
                                           "stream_context_resource",
                                           &streamInit, // init callbacks
                                           flags,
                                           NULL);

  return ret_val;
}

/*
** on_upgrade is called when the NIF library is loaded and there is old code of
*this module with a loaded NIF library.
*/
static int
on_upgrade(ErlNifEnv *env,
           void **priv_data,
           __unused_parm__ void **old_priv_data,
           ERL_NIF_TERM load_info)
{
  return on_load(env, *priv_data, load_info);
}

/*
** unload is called when the module code that the NIF library belongs to is
*purged as old. New code of the same module may or may not exist.
*/
static void
on_unload(__unused_parm__ ErlNifEnv *env, __unused_parm__ void *priv_data)
{
  // @TODO We want registration context and APIs for it
  if (isRegistered)
    {
      MsQuic->RegistrationClose(GRegistration);
      isRegistered = FALSE;
    }

  if (isLibOpened)
    {
      MsQuicClose(MsQuic);
      isLibOpened = FALSE;
    }
}

static ERL_NIF_TERM
openLib(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  assert(1 == argc);
  TP_NIF_3(enter, 0, 1);
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM res = ATOM_FALSE;
  ERL_NIF_TERM lttngLib = argv[0];
  char lttngPath[PATH_MAX] = { 0 };

  if (isLibOpened)
    {
      TP_NIF_3(skip, 0, 2);
      return SUCCESS(res);
    }

  // @todo external call for static link
  CxPlatSystemLoad();
  MsQuicLibraryLoad();

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(status = MsQuicOpen2(&MsQuic)))
    {
      isLibOpened = false;
      return ERROR_TUPLE_3(ATOM_OPEN_FAILED, ATOM_STATUS(status));
    }

  isLibOpened = true;
  TP_NIF_3(success, 0, 2);

  res = ATOM_TRUE;

  if (enif_get_string(env, lttngLib, lttngPath, PATH_MAX, ERL_NIF_LATIN1))
    {
      // loading lttng lib is optional, ok to fail
      if (dlopen(lttngPath, (unsigned)RTLD_NOW | (unsigned)RTLD_GLOBAL))
        {
          res = ATOM_DEBUG;
        }
    }

  return SUCCESS(res);
}

static ERL_NIF_TERM
closeLib(__unused_parm__ ErlNifEnv *env,
         __unused_parm__ int argc,
         __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isLibOpened && MsQuic)
    {
      // @todo ensure registration is closed first
      //
      TP_NIF_3(do_close, 0, isLibOpened);
      MsQuicClose(MsQuic);
      isLibOpened = false;
    }

  return ATOM_OK;
}

static ERL_NIF_TERM
registration(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM profile = argv[0];

  if (isRegistered || !isLibOpened)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (argc == 1)
    {
      if (IS_SAME_TERM(profile, ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY))
        {
          GRegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
        }
      else if (IS_SAME_TERM(profile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT))
        {
          GRegConfig.ExecutionProfile
              = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
        }
      else if (IS_SAME_TERM(profile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER))
        {
          GRegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
        }
      else if (IS_SAME_TERM(profile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME))
        {
          GRegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  if (QUIC_FAILED(status
                  = MsQuic->RegistrationOpen(&GRegConfig, &GRegistration)))
    {
      isRegistered = false;
      TP_NIF_3(fail, 0, status);
      return ERROR_TUPLE_3(ATOM_REG_FAILED, ETERM_INT(status));
    }
  TP_NIF_3(success, 0, status);
  isRegistered = true;
  return ATOM_OK;
}

static ERL_NIF_TERM
deregistration(__unused_parm__ ErlNifEnv *env,
               __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isRegistered && GRegistration)
    {
      MsQuic->RegistrationClose(GRegistration);
      GRegistration = NULL;
      isRegistered = false;
    }
  return ATOM_OK;
}

ERL_NIF_TERM
atom_status(ErlNifEnv *env, QUIC_STATUS status)
{
  ERL_NIF_TERM eterm = ATOM_UNKNOWN_STATUS_CODE;
  switch (status)
    {
    case QUIC_STATUS_SUCCESS:
      eterm = ATOM_QUIC_STATUS_SUCCESS;
      break;
    case QUIC_STATUS_PENDING:
      eterm = ATOM_QUIC_STATUS_PENDING;
      break;
    case QUIC_STATUS_CONTINUE:
      eterm = ATOM_QUIC_STATUS_CONTINUE;
      break;
    case QUIC_STATUS_OUT_OF_MEMORY:
      eterm = ATOM_QUIC_STATUS_OUT_OF_MEMORY;
      break;
    case QUIC_STATUS_INVALID_PARAMETER:
      eterm = ATOM_QUIC_STATUS_INVALID_PARAMETER;
      break;
    case QUIC_STATUS_INVALID_STATE:
      eterm = ATOM_QUIC_STATUS_INVALID_STATE;
      break;
    case QUIC_STATUS_NOT_SUPPORTED:
      eterm = ATOM_QUIC_STATUS_NOT_SUPPORTED;
      break;
    case QUIC_STATUS_NOT_FOUND:
      eterm = ATOM_QUIC_STATUS_NOT_FOUND;
      break;
    case QUIC_STATUS_BUFFER_TOO_SMALL:
      eterm = ATOM_QUIC_STATUS_BUFFER_TOO_SMALL;
      break;
    case QUIC_STATUS_HANDSHAKE_FAILURE:
      eterm = ATOM_QUIC_STATUS_HANDSHAKE_FAILURE;
      break;
    case QUIC_STATUS_ABORTED:
      eterm = ATOM_QUIC_STATUS_ABORTED;
      break;
    case QUIC_STATUS_ADDRESS_IN_USE:
      eterm = ATOM_QUIC_STATUS_ADDRESS_IN_USE;
      break;
    case QUIC_STATUS_CONNECTION_TIMEOUT:
      eterm = ATOM_QUIC_STATUS_CONNECTION_TIMEOUT;
      break;
    case QUIC_STATUS_CONNECTION_IDLE:
      eterm = ATOM_QUIC_STATUS_CONNECTION_IDLE;
      break;
    case QUIC_STATUS_INTERNAL_ERROR:
      eterm = ATOM_QUIC_STATUS_INTERNAL_ERROR;
      break;
    case QUIC_STATUS_CONNECTION_REFUSED:
      eterm = ATOM_QUIC_STATUS_CONNECTION_REFUSED;
      break;
    case QUIC_STATUS_PROTOCOL_ERROR:
      eterm = ATOM_QUIC_STATUS_PROTOCOL_ERROR;
      break;
    case QUIC_STATUS_VER_NEG_ERROR:
      eterm = ATOM_QUIC_STATUS_VER_NEG_ERROR;
      break;
    case QUIC_STATUS_UNREACHABLE:
      eterm = ATOM_QUIC_STATUS_UNREACHABLE;
      break;
    case QUIC_STATUS_TLS_ERROR:
      eterm = ATOM_QUIC_STATUS_TLS_ERROR;
      break;
    case QUIC_STATUS_USER_CANCELED:
      eterm = ATOM_QUIC_STATUS_USER_CANCELED;
      break;
    case QUIC_STATUS_ALPN_NEG_FAILURE:
      eterm = ATOM_QUIC_STATUS_ALPN_NEG_FAILURE;
      break;
    case QUIC_STATUS_STREAM_LIMIT_REACHED:
      eterm = ATOM_QUIC_STATUS_STREAM_LIMIT_REACHED;
      break;
    default:
      eterm = enif_make_tuple2(
          env, ATOM_UNKNOWN_STATUS_CODE, ETERM_UINT_64(status));
    }
  return eterm;
}

ERL_NIF_TERM
controlling_process(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx = NULL;
  QuicerConnCTX *c_ctx = NULL;
  ErlNifPid target, caller;
  ERL_NIF_TERM new_owner = argv[1];
  ERL_NIF_TERM res = ATOM_OK;
  if (argc != 2)
    {
      return ATOM_BADARG;
    }

  // precheck
  if (!enif_get_local_pid(env, argv[1], &target))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_self(env, &caller))
    {
      // unlikely
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      enif_mutex_lock(s_ctx->lock);
      res = stream_controlling_process(env, s_ctx, &caller, &new_owner);
      enif_mutex_unlock(s_ctx->lock);
    }
  else if (enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {

      enif_mutex_lock(c_ctx->lock);
      res = connection_controlling_process(env, c_ctx, &caller, &new_owner);
      enif_mutex_unlock(c_ctx->lock);
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return res;
}

ERL_NIF_TERM
connection_controlling_process(ErlNifEnv *env,
                               QuicerConnCTX *c_ctx,
                               const ErlNifPid *caller,
                               const ERL_NIF_TERM *pid)
{
  TP_NIF_3(enter, (uintptr_t)c_ctx->Connection, (uintptr_t)&c_ctx);
  if (0 != enif_compare_pids(&c_ctx->owner->Pid, caller))
    {
      return ERROR_TUPLE_2(ATOM_NOT_OWNER);
    }

  if (!enif_get_local_pid(env, *pid, &c_ctx->owner->Pid))
    {

      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_demonitor_process(env, c_ctx, &c_ctx->owner_mon);

  if (0
      != enif_monitor_process(
          env, c_ctx, &c_ctx->owner->Pid, &c_ctx->owner_mon))
    {
      return ERROR_TUPLE_2(ATOM_OWNER_DEAD);
    }

  TP_NIF_3(exit, (uintptr_t)c_ctx->Connection, (uintptr_t)&c_ctx);
  return ATOM_OK;
}

ERL_NIF_TERM
stream_controlling_process(ErlNifEnv *env,
                           QuicerStreamCTX *s_ctx,
                           const ErlNifPid *caller,
                           const ERL_NIF_TERM *pid)
{

  TP_NIF_3(enter, (uintptr_t)s_ctx->Stream, (uintptr_t)&s_ctx->owner->Pid);
  if (0 != enif_compare_pids(&s_ctx->owner->Pid, caller))
    {
      return ERROR_TUPLE_2(ATOM_NOT_OWNER);
    }

  if (!enif_get_local_pid(env, *pid, &s_ctx->owner->Pid))
    {

      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_demonitor_process(env, s_ctx, &s_ctx->owner_mon);

  if (0
      != enif_monitor_process(
          env, s_ctx, &s_ctx->owner->Pid, &s_ctx->owner_mon))
    {
      return ERROR_TUPLE_2(ATOM_OWNER_DEAD);
    }

  TP_NIF_3(exit, (uintptr_t)s_ctx->Stream, (uintptr_t)&s_ctx->owner->Pid);
  return ATOM_OK;
}

/*
** Make an 4 tuple event
** note all keys&values of props belongs to 'env'
*/
ERL_NIF_TERM
make_event_with_props(ErlNifEnv *env,
                      ERL_NIF_TERM event_name,
                      ERL_NIF_TERM resource,
                      ERL_NIF_TERM *keys,
                      ERL_NIF_TERM *values,
                      size_t cnt)
{
  ERL_NIF_TERM prop = ATOM_UNDEFINED;

  // build prop
  if (!(0 == cnt || values == NULL || keys == NULL))
    {
      assert(values != NULL);
      assert(keys != NULL);
      enif_make_map_from_arrays(env, keys, values, cnt, &prop);
    }

  return enif_make_tuple4(env,
                          ATOM_QUIC,  // 1st element, :: quic
                          event_name, // 2nd element, event name :: atom()
                          resource,   // 3rd element, resource
                          prop);      // 4th element, event props :: map()) //
}

/*
** Make an 4 tuple event
*/
ERL_NIF_TERM
make_event(ErlNifEnv *env,
           ERL_NIF_TERM event_name,
           ERL_NIF_TERM resource,
           ERL_NIF_TERM prop)
{
  return enif_make_tuple4(env,
                          ATOM_QUIC,  // 1st element, :: quic
                          event_name, // 2nd element, event name :: atom()
                          resource,   // 3rd element, resource
                          prop);      // 4th element, event props :: any()) //
}

static ErlNifFunc nif_funcs[] = {
  /* |  name  | arity| funptr | flags|
   *
   */
  // clang-format off
  { "open_lib", 1, openLib, 0 },
  { "close_lib", 0, closeLib, 0 },
  { "reg_open", 0, registration, 0 },
  { "reg_open", 1, registration, 0 },
  { "reg_close", 0, deregistration, 0 },
  { "listen", 2, listen2, 0},
  { "close_listener", 1, close_listener1, 0},
  { "async_connect", 3, async_connect3, 0},
  { "async_accept", 2, async_accept2, 0},
  { "async_handshake", 1, async_handshake_1, 0},
  { "async_shutdown_connection", 3, shutdown_connection3, 0},
  { "async_accept_stream", 2, async_accept_stream2, 0},
  { "start_stream", 2, async_start_stream2, 0},
  { "send", 3, send3, 0},
  { "recv", 2, recv2, 0},
  { "send_dgram", 3, send_dgram, 0},
  { "async_shutdown_stream", 3, shutdown_stream3, 0},
  { "sockname", 1, sockname1, 0},
  { "getopt", 3, getopt3, 0},
  { "setopt", 4, setopt4, 0},
  { "controlling_process", 2, controlling_process, 0},
  /* for DEBUG */
  { "get_conn_rid", 1, get_conn_rid1, 1},
  { "get_stream_rid", 1, get_stream_rid1, 1}
  // clang-format on
};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
