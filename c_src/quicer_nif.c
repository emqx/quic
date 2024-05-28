/*--------------------------------------------------------------------
Copyright (c) 2021-2024 EMQ Technologies Co., Ltd. All Rights Reserved.

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
#include "quicer_vsn.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

static ERL_NIF_TERM connection_controlling_process(ErlNifEnv *env,
                                                   QuicerConnCTX *c_ctx,
                                                   const ErlNifPid *caller,
                                                   const ERL_NIF_TERM *pid);

static ERL_NIF_TERM stream_controlling_process(ErlNifEnv *env,
                                               QuicerStreamCTX *s_ctx,
                                               const ErlNifPid *caller,
                                               const ERL_NIF_TERM *pid);

static ERL_NIF_TERM
closeLib(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

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
ERL_NIF_TERM ATOM_LIB_UNINITIALIZED;
ERL_NIF_TERM ATOM_CONN_OPEN_ERROR;
ERL_NIF_TERM ATOM_CONN_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_OPEN_ERROR;
ERL_NIF_TERM ATOM_STREAM_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_SEND_ERROR;
ERL_NIF_TERM ATOM_DGRAM_SEND_ERROR;
ERL_NIF_TERM ATOM_SOCKNAME_ERROR;
ERL_NIF_TERM ATOM_OWNER_DEAD;
ERL_NIF_TERM ATOM_NOT_OWNER;
ERL_NIF_TERM ATOM_NO_PEERCERT;

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
ERL_NIF_TERM ATOM_UNKNOWN_TLS_STATUS_CODE;
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
ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_NO_CERT;
ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_REQUIRED;
ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_UNOBTAINABLE;

// option keys
ERL_NIF_TERM ATOM_CERT;
ERL_NIF_TERM ATOM_CERTFILE;
ERL_NIF_TERM ATOM_KEY;
ERL_NIF_TERM ATOM_KEYFILE;
ERL_NIF_TERM ATOM_PASSWORD;
ERL_NIF_TERM ATOM_ALPN;
ERL_NIF_TERM ATOM_HANDLE;
ERL_NIF_TERM ATOM_VERIFY;
ERL_NIF_TERM ATOM_PEER;
ERL_NIF_TERM ATOM_NONE;
ERL_NIF_TERM ATOM_CACERTFILE;

/*-------------------------------------------------------*/
/*         msquic  execution profile for registration    */
/*-------------------------------------------------------*/
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY; // Default
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_MAX_THROUGHPUT;
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_SCAVENGER;
ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_REAL_TIME;

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
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH;

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
ERL_NIF_TERM ATOM_QUIC_PARAM_LISTENER_CIBIR_ID;

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
ERL_NIF_TERM ATOM_TLS_PROTOCOL_VERSION;
ERL_NIF_TERM ATOM_CIPHER_ALGORITHM;
ERL_NIF_TERM ATOM_CIPHER_STRENGTH;
ERL_NIF_TERM ATOM_HASH_ALGORITHM;
ERL_NIF_TERM ATOM_HASH_STRENGTH;
ERL_NIF_TERM ATOM_KEY_EXCHANGE_ALGORITHM;
ERL_NIF_TERM ATOM_KEY_EXCHANGE_STRENGTH;
ERL_NIF_TERM ATOM_CIPHER_SUITE;

ERL_NIF_TERM ATOM_TLS_VSN_1_3;
/* Cipher Alg */
ERL_NIF_TERM ATOM_AES_128;
ERL_NIF_TERM ATOM_AES_256;
ERL_NIF_TERM ATOM_CHACHA20;
/* Hash Alg */
ERL_NIF_TERM ATOM_SHA_256;
ERL_NIF_TERM ATOM_SHA_384;
/* Cipher Suite */
ERL_NIF_TERM ATOM_AES_128_GCM_SHA256;
ERL_NIF_TERM ATOM_AES_128_GCM_SHA256;
ERL_NIF_TERM ATOM_AES_256_GCM_SHA384;
ERL_NIF_TERM ATOM_CHACHA20_POLY1305_SHA256;

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
ERL_NIF_TERM ATOM_SEND_SHUTDOWN_COMPLETE;
ERL_NIF_TERM ATOM_PEER_ACCEPTED;
ERL_NIF_TERM ATOM_LOCAL_ADDRESS_CHANGED;
ERL_NIF_TERM ATOM_STREAMS_AVAILABLE;
ERL_NIF_TERM ATOM_PEER_NEEDS_STREAMS;
ERL_NIF_TERM ATOM_START_COMPLETE;
ERL_NIF_TERM ATOM_SEND_COMPLETE;
ERL_NIF_TERM ATOM_DGRAM_SEND_STATE;
ERL_NIF_TERM ATOM_SEND_DGRAM_COMPLETE;
ERL_NIF_TERM ATOM_EINVAL;
ERL_NIF_TERM ATOM_QUIC;
ERL_NIF_TERM ATOM_PASSIVE;
ERL_NIF_TERM ATOM_QUIC_EVENT_MASK;
ERL_NIF_TERM ATOM_NST_RECEIVED;
ERL_NIF_TERM ATOM_NST;
ERL_NIF_TERM ATOM_DGRAM;
ERL_NIF_TERM ATOM_DGRAM_STATE_CHANGED;
ERL_NIF_TERM ATOM_DGRAM_MAX_LEN;
ERL_NIF_TERM ATOM_DGRAM_SEND_ENABLED;
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
ERL_NIF_TERM ATOM_TIME;
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
ERL_NIF_TERM ATOM_VERIFY;
ERL_NIF_TERM ATOM_VERIFY_NONE;
ERL_NIF_TERM ATOM_VERIFY_PEER;

/*----------------------------------------------------------*/
/* Used in messages to the owners */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_IS_RESUMED;
ERL_NIF_TERM ATOM_ALPNS;
ERL_NIF_TERM ATOM_IS_HANDSHAKE_COMPLETED;
ERL_NIF_TERM ATOM_IS_PEER_ACKED;
ERL_NIF_TERM ATOM_IS_APP_CLOSING;
ERL_NIF_TERM ATOM_IS_SHUTDOWN_BY_APP;
ERL_NIF_TERM ATOM_IS_CLOSED_REMOTELY;
ERL_NIF_TERM ATOM_IS_ORPHAN;
ERL_NIF_TERM ATOM_BIDI_STREAMS;
ERL_NIF_TERM ATOM_UNIDI_STREAMS;
ERL_NIF_TERM ATOM_STATUS;
ERL_NIF_TERM ATOM_STATE;
ERL_NIF_TERM ATOM_STREAM_ID;
ERL_NIF_TERM ATOM_IS_PEER_ACCEPTED;
ERL_NIF_TERM ATOM_IS_CONN_SHUTDOWN;
ERL_NIF_TERM ATOM_ABS_OFFSET;
ERL_NIF_TERM ATOM_LEN;
ERL_NIF_TERM ATOM_FLAGS;

ERL_NIF_TERM ATOM_VER;
ERL_NIF_TERM ATOM_LOCAL_ADDR;
ERL_NIF_TERM ATOM_REMOTE_ADDR;
ERL_NIF_TERM ATOM_SERVER_NAME;
ERL_NIF_TERM ATOM_CLIENT_ALPNS;
ERL_NIF_TERM ATOM_CRYPTO_BUFFER;
ERL_NIF_TERM ATOM_UNDEFINED;

// Datagram Send State
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_UNKNOWN;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_SENT;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_LOST_SUSPECT;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_LOST_DISCARDED;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS;
ERL_NIF_TERM ATOM_QUIC_DATAGRAM_SEND_CANCELED;

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
  ATOM(ATOM_LIB_UNINITIALIZED, lib_uninitialized);                            \
  ATOM(ATOM_CONN_OPEN_ERROR, conn_open_error);                                \
  ATOM(ATOM_CONN_START_ERROR, conn_start_error);                              \
  ATOM(ATOM_STREAM_OPEN_ERROR, stm_open_error);                               \
  ATOM(ATOM_STREAM_START_ERROR, stm_start_error);                             \
  ATOM(ATOM_STREAM_SEND_ERROR, stm_send_error);                               \
  ATOM(ATOM_DGRAM_SEND_ERROR, dgram_send_error);                              \
  ATOM(ATOM_OWNER_DEAD, owner_dead);                                          \
  ATOM(ATOM_NOT_OWNER, not_owner);                                            \
  ATOM(ATOM_NO_PEERCERT, no_peercert);                                        \
                                                                              \
  ATOM(ATOM_ERROR_NO_ERROR, no_error);                                        \
  ATOM(ATOM_ERROR_CONTINUE, continue);                                        \
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
  ATOM(ATOM_UNKNOWN_TLS_STATUS_CODE, unknown_quic_tls_status);                \
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
  ATOM(ATOM_QUIC_STATUS_CLOSE_NOTIFY, close_notify);                          \
  /*  TLS Error Status */                                                     \
  ATOM(ATOM_QUIC_STATUS_BAD_CERTIFICATE, bad_certificate);                    \
  ATOM(ATOM_QUIC_STATUS_UNSUPPORTED_CERTIFICATE, unsupported_certificate);    \
  ATOM(ATOM_QUIC_STATUS_REVOKED_CERTIFICATE, revoked_certificate);            \
  ATOM(ATOM_QUIC_STATUS_EXPIRED_CERTIFICATE, expired_certificate);            \
  ATOM(ATOM_QUIC_STATUS_UNKNOWN_CERTIFICATE, unknown_certificate);            \
  ATOM(ATOM_QUIC_STATUS_CERT_EXPIRED, cert_expired);                          \
  ATOM(ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT, cert_untrusted_root);            \
  ATOM(ATOM_QUIC_STATUS_CERT_NO_CERT, cert_no_cert);                          \
  ATOM(ATOM_QUIC_STATUS_CERT_REQUIRED, cert_required);                        \
  ATOM(ATOM_QUIC_STATUS_CERT_UNOBTAINABLE, cert_unobtainable);                \
  /*-------------------------------------------------------*/                 \
  /*         msquic  execution profile for reg             */                 \
  /*-------------------------------------------------------*/                 \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY,                               \
       quic_execution_profile_low_latency);                                   \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_MAX_THROUGHPUT,                            \
       quic_execution_profile_max_throughput);                                \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_SCAVENGER,                                 \
       quic_execution_profile_scavenger);                                     \
  ATOM(ATOM_QUIC_EXECUTION_PROFILE_REAL_TIME,                                 \
       quic_execution_profile_real_time);                                     \
  /*-----------------------------------------*/                               \
  /*         msquic params starts            */                               \
  /*-----------------------------------------*/                               \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_GLOBAL. */                              \
  ATOM(ATOM_QUIC_GLOBAL, quic_global);                                        \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT, retry_memory_percent);    \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS, supported_versions);        \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE, load_balacing_mode);        \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS, perf_counters);                  \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SETTINGS, settings);                            \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_VERSION, version);                              \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH, library_git_hash);            \
                                                                              \
  /*Parameters for QUIC_PARAM_LEVEL_REGISTRATION.*/                           \
  ATOM(ATOM_QUIC_REGISTRATION, quic_registration);                            \
  ATOM(ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX, cid_prefix);                  \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_CONFIGURATION. */                        \
  ATOM(ATOM_QUIC_CONFIGURATION, quic_configuration);                          \
  ATOM(ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS, settings);                     \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_LISTENER. */                             \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS, local_address);                \
  ATOM(ATOM_QUIC_PARAM_LISTENER_STATS, stats);                                \
  ATOM(ATOM_QUIC_PARAM_LISTENER_CIBIR_ID, cibir_id);                          \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */                           \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_QUIC_VERSION, quic_version);                      \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS, local_address);                    \
  ATOM(ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS, remote_address);                  \
  ATOM(ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR, ideal_processor);                \
  ATOM(ATOM_QUIC_PARAM_CONN_SETTINGS, settings);                              \
  ATOM(ATOM_QUIC_PARAM_CONN_STATISTICS, statistics);                          \
  ATOM(ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT, statistics_plat);                \
  ATOM(ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING, share_udp_binding);            \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT,                          \
       local_bidi_stream_count);                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT,                         \
       local_unidi_stream_count);                                             \
  ATOM(ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS, max_stream_ids);                  \
  ATOM(ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE, close_reason_phrase);        \
  ATOM(ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,                         \
       stream_scheduling_scheme);                                             \
  ATOM(ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,                         \
       datagram_receive_enabled);                                             \
  ATOM(ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED, datagram_send_enabled);    \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,                          \
       disable_1rtt_encryption);                                              \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET, resumption_ticket);            \
  ATOM(ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID, peer_certificate_valid);  \
  ATOM(ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE, local_interface);                \
  /* Parameters for QUIC_PARAM_LEVEL_TLS. */                                  \
  ATOM(ATOM_QUIC_TLS, quic_tls);                                              \
  ATOM(ATOM_TLS_PROTOCOL_VERSION, tls_protocol_version);                      \
  ATOM(ATOM_CIPHER_ALGORITHM, cipher_algorithm);                              \
  ATOM(ATOM_CIPHER_STRENGTH, cipher_strength);                                \
  ATOM(ATOM_HASH_ALGORITHM, hash_algorithm);                                  \
  ATOM(ATOM_HASH_STRENGTH, hash_strength);                                    \
  ATOM(ATOM_KEY_EXCHANGE_ALGORITHM, key_exchange_algorithm);                  \
  ATOM(ATOM_KEY_EXCHANGE_STRENGTH, key_exchange_strength);                    \
  ATOM(ATOM_CIPHER_SUITE, cipher_suite);                                      \
  ATOM(ATOM_TLS_VSN_1_3, tlsv1_3);                                            \
  /* Cipher Alg */                                                            \
  ATOM(ATOM_AES_128, aes_128);                                                \
  ATOM(ATOM_AES_256, aes_256);                                                \
  ATOM(ATOM_CHACHA20, chacha20);                                              \
  /* Hash Alg */                                                              \
  ATOM(ATOM_SHA_256, sha_256);                                                \
  ATOM(ATOM_SHA_384, sha_384);                                                \
  /* Cipher Suite */                                                          \
  ATOM(ATOM_AES_128_GCM_SHA256, aes_128_gcm_sha256);                          \
  ATOM(ATOM_AES_256_GCM_SHA384, aes_256_gcm_sha384);                          \
  ATOM(ATOM_CHACHA20_POLY1305_SHA256, chacha20_poly1305_sha256);              \
  ATOM(ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,                      \
       schannel_context_attribute_w);                                         \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO, handshake_info);                   \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN, negotiated_alpn);                 \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_STREAM.  */                             \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_STREAM_ID, stream_id);                                 \
  ATOM(ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH, 0rtt_length);                      \
  ATOM(ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,                         \
       ideal_send_buffer_size);                                               \
  ATOM(ATOM_QUIC_PARAM_STREAM_PRIORITY, priority);                            \
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
  ATOM(ATOM_CERTFILE, certfile);                                              \
  ATOM(ATOM_KEY, key);                                                        \
  ATOM(ATOM_KEYFILE, keyfile);                                                \
  ATOM(ATOM_PASSWORD, password);                                              \
  ATOM(ATOM_ALPN, alpn);                                                      \
  ATOM(ATOM_HANDLE, handle);                                                  \
  ATOM(ATOM_VERIFY, verify);                                                  \
  ATOM(ATOM_CACERTFILE, cacertfile);                                          \
  ATOM(ATOM_PEER, peer);                                                      \
  ATOM(ATOM_NONE, none);                                                      \
  ATOM(ATOM_CLOSED, closed);                                                  \
  ATOM(ATOM_STREAM_CLOSED, stream_closed);                                    \
  ATOM(ATOM_LISTENER_STOPPED, listener_stopped);                              \
  ATOM(ATOM_TRANS_SHUTDOWN, transport_shutdown);                              \
  ATOM(ATOM_SHUTDOWN, shutdown);                                              \
  ATOM(ATOM_PEER_SEND_SHUTDOWN, peer_send_shutdown);                          \
  ATOM(ATOM_PEER_SEND_ABORTED, peer_send_aborted);                            \
  ATOM(ATOM_PEER_RECEIVE_ABORTED, peer_receive_aborted);                      \
  ATOM(ATOM_PEER_ADDRESS_CHANGED, peer_address_changed);                      \
  ATOM(ATOM_SEND_SHUTDOWN_COMPLETE, send_shutdown_complete);                  \
  ATOM(ATOM_PEER_ACCEPTED, peer_accepted);                                    \
  ATOM(ATOM_LOCAL_ADDRESS_CHANGED, local_address_changed);                    \
  ATOM(ATOM_STREAMS_AVAILABLE, streams_available);                            \
  ATOM(ATOM_PEER_NEEDS_STREAMS, peer_needs_streams);                          \
  ATOM(ATOM_START_COMPLETE, start_completed);                                 \
  ATOM(ATOM_SEND_COMPLETE, send_complete);                                    \
  ATOM(ATOM_DGRAM_SEND_STATE, dgram_send_state);                              \
  ATOM(ATOM_SEND_DGRAM_COMPLETE, send_dgram_completed);                       \
  ATOM(ATOM_EINVAL, einval);                                                  \
  ATOM(ATOM_QUIC, quic);                                                      \
  ATOM(ATOM_PASSIVE, passive);                                                \
  ATOM(ATOM_QUIC_EVENT_MASK, quic_event_mask);                                \
  ATOM(ATOM_NST_RECEIVED, nst_received);                                      \
  ATOM(ATOM_NST, nst);                                                        \
  ATOM(ATOM_DGRAM, dgram);                                                    \
  ATOM(ATOM_DGRAM_STATE_CHANGED, dgram_state_changed);                        \
  ATOM(ATOM_DGRAM_MAX_LEN, dgram_max_len);                                    \
  ATOM(ATOM_DGRAM_SEND_ENABLED, dgram_send_enabled);                          \
  ATOM(ATOM_DEBUG, debug);                                                    \
  ATOM(ATOM_ONCE, once);                                                      \
  ATOM(ATOM_NEW_CONN, new_conn);                                              \
  ATOM(ATOM_CONNECTED, connected);                                            \
  ATOM(ATOM_CONN_RESUMED, connection_resumed);                                \
  ATOM(ATOM_NEW_STREAM, new_stream);                                          \
  ATOM(ATOM_SNABBKAFFE_COLLECTOR, snabbkaffe_collector);                      \
  ATOM(ATOM_TRACE, trace);                                                    \
  ATOM(ATOM_TIME, time);                                                      \
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
  ATOM(ATOM_VERIFY, verify);                                                  \
  ATOM(ATOM_VERIFY_NONE, verify_none);                                        \
  ATOM(ATOM_VERIFY_PEER, verify_peer);                                        \
  ATOM(ATOM_ALPNS, alpns);                                                    \
  ATOM(ATOM_IS_HANDSHAKE_COMPLETED, is_handshake_completed);                  \
  ATOM(ATOM_IS_PEER_ACKED, is_peer_acked);                                    \
  ATOM(ATOM_IS_APP_CLOSING, is_app_closing);                                  \
  ATOM(ATOM_IS_SHUTDOWN_BY_APP, is_shutdown_by_app);                          \
  ATOM(ATOM_IS_CLOSED_REMOTELY, is_closed_remotely);                          \
  ATOM(ATOM_IS_ORPHAN, is_orphan);                                            \
  ATOM(ATOM_BIDI_STREAMS, bidi_streams);                                      \
  ATOM(ATOM_UNIDI_STREAMS, unidi_streams);                                    \
  ATOM(ATOM_STATUS, status);                                                  \
  ATOM(ATOM_STATE, state);                                                    \
  ATOM(ATOM_STREAM_ID, stream_id);                                            \
  ATOM(ATOM_IS_PEER_ACCEPTED, is_peer_accepted);                              \
  ATOM(ATOM_IS_CONN_SHUTDOWN, is_conn_shutdown);                              \
  ATOM(ATOM_ABS_OFFSET, absolute_offset);                                     \
  ATOM(ATOM_LEN, len);                                                        \
  ATOM(ATOM_FLAGS, flags);                                                    \
  ATOM(ATOM_VER, version);                                                    \
  ATOM(ATOM_LOCAL_ADDR, local_addr);                                          \
  ATOM(ATOM_REMOTE_ADDR, remote_addr);                                        \
  ATOM(ATOM_SERVER_NAME, server_name);                                        \
  ATOM(ATOM_CLIENT_ALPNS, client_alpns);                                      \
  ATOM(ATOM_CRYPTO_BUFFER, crypto_buffer);                                    \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_UNKNOWN, dgram_send_unknown);                  \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_SENT, dgram_send_sent);                        \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_LOST_SUSPECT, dgram_send_lost_suspect);        \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_LOST_DISCARDED, dgram_send_lost_discarded);    \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED, dgram_send_acknowledged);        \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS,                         \
       dgram_send_acknowledged_spurious);                                     \
  ATOM(ATOM_QUIC_DATAGRAM_SEND_CANCELED, dgram_send_canceled);                \
  ATOM(ATOM_UNDEFINED, undefined);

extern QuicerRegistrationCTX *G_r_ctx;
extern pthread_mutex_t GRegLock;

const QUIC_API_TABLE *MsQuic = NULL;
// Mutex for MsQuic
pthread_mutex_t MsQuicLock = PTHREAD_MUTEX_INITIALIZER;

ErlNifResourceType *ctx_reg_t = NULL;
ErlNifResourceType *ctx_listener_t = NULL;
ErlNifResourceType *ctx_connection_t = NULL;
ErlNifResourceType *ctx_stream_t = NULL;
ErlNifResourceType *ctx_config_t = NULL;

QUIC_REGISTRATION_CONFIG GRegConfig
    = { "quicer_nif", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

void
resource_listener_down_callback(__unused_parm__ ErlNifEnv *env,
                                void *ctx,
                                __unused_parm__ ErlNifPid *pid,
                                __unused_parm__ ErlNifMonitor *mon)
{
  QuicerListenerCTX *l_ctx = (QuicerListenerCTX *)ctx;
  TP_CB_3(start, (uintptr_t)l_ctx->Listener, 0);
  // Hold lock for the race of ListenerClose and ListenerStop call
  enif_mutex_lock(l_ctx->lock);
  if (!l_ctx->is_closed && !l_ctx->is_stopped && l_ctx->Listener
      && get_listener_handle(l_ctx))
    {
      l_ctx->is_stopped = TRUE;
      /*
      // We only stop here, but not close it, because possible subsequent
      // scenarios:
      // a. Some pid could still start the stopped listener with nif
      // handle.
      // b. Some pid could still close the stopped listener with nif
      // handle.
      // c. We close it in resource_listener_dealloc_callback anyway when
      // Listener term get GCed.
      */
      MsQuic->ListenerStop(l_ctx->Listener);
      put_listener_handle(l_ctx);
    }
  enif_mutex_unlock(l_ctx->lock);
  TP_CB_3(end, (uintptr_t)l_ctx->Listener, 0);
}

/*
** Listener NIF handle, end of world...
*/
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
  else
    {
      TP_CB_3(skip, (uintptr_t)l_ctx->Listener, 0);
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
  // This ensures no callbacks during cleanup here.
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
                            ErlNifPid *DeadPid,
                            __unused_parm__ ErlNifMonitor *mon)
{
  QuicerConnCTX *c_ctx = ctx;
  enif_mutex_lock(c_ctx->lock);
  if (c_ctx && c_ctx->owner && DeadPid
      && !enif_compare_pids(&c_ctx->owner->Pid, DeadPid)
      && get_conn_handle(c_ctx))
    {
      TP_CB_3(start, (uintptr_t)c_ctx->Connection, (uintptr_t)ctx);
      MsQuic->ConnectionShutdown(
          c_ctx->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      put_conn_handle(c_ctx);
      TP_CB_3(end, (uintptr_t)c_ctx->Connection, (uintptr_t)ctx);
    }
  enif_mutex_unlock(c_ctx->lock);
}

void
resource_stream_dealloc_callback(__unused_parm__ ErlNifEnv *env, void *obj)
{
  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)obj;
  TP_CB_3(start, (uintptr_t)s_ctx->Stream, s_ctx->is_closed);
  assert(s_ctx->is_closed == TRUE);
  if (s_ctx->Stream && !s_ctx->is_closed)
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
                              ErlNifPid *DeadPid,
                              __unused_parm__ ErlNifMonitor *mon)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  QuicerStreamCTX *s_ctx = ctx;

  enif_mutex_lock(s_ctx->lock);
  if (s_ctx && s_ctx->owner && DeadPid
      && !enif_compare_pids(&s_ctx->owner->Pid, DeadPid)
      && get_stream_handle(s_ctx))
    {
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
      put_stream_handle(s_ctx);
    }
  enif_mutex_unlock(s_ctx->lock);
}

void
resource_config_dealloc_callback(__unused_parm__ ErlNifEnv *env,
                                 __unused_parm__ void *obj)
{
  TP_CB_3(start, (uintptr_t)obj, 0);
  QuicerConfigCTX *config_ctx = (QuicerConfigCTX *)obj;
  // Check if Registration is closed or not
  if (G_r_ctx && config_ctx->Configuration)
    {
      MsQuic->ConfigurationClose(config_ctx->Configuration);
    }
  deinit_config_ctx(config_ctx);
  TP_CB_3(end, (uintptr_t)obj, 0);
}

void
resource_reg_dealloc_callback(__unused_parm__ ErlNifEnv *env, void *obj)
{
  TP_CB_3(start, (uintptr_t)obj, 0);
  QuicerRegistrationCTX *reg_ctx = (QuicerRegistrationCTX *)obj;
  deinit_r_ctx(reg_ctx);
  if (MsQuic && reg_ctx->Registration)
    {
      MsQuic->RegistrationClose(reg_ctx->Registration);
    }
  TP_CB_3(end, (uintptr_t)obj, 0);
}

static void
init_atoms(ErlNifEnv *env)
{
  // init atoms in use.
#define ATOM(name, val)                                                       \
  {                                                                           \
    (name) = enif_make_atom(env, #val);                                       \
  }
  INIT_ATOMS
#undef ATOM
}

static void
open_resources(ErlNifEnv *env)
{
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

  ErlNifResourceTypeInit regInit
      = { .dtor = resource_reg_dealloc_callback, .down = NULL, .stop = NULL };

  ctx_reg_t = enif_open_resource_type_x(env,
                                        "registration_context_resource",
                                        &regInit, // init callbacks
                                        flags,
                                        NULL);

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
}

/*
** on_load is called when the NIF library is loaded and no previously loaded
*  library exists for this module.
*/
static int
on_load(ErlNifEnv *env,
        __unused_parm__ void **priv_data,
        ERL_NIF_TERM loadinfo)
{
  int ret_val = 0;
  unsigned load_vsn = 0;

  TP_NIF_3(start, &MsQuic, 0);
  if (!enif_get_uint(env, loadinfo, &load_vsn))
    {
      load_vsn = 0;
    }

  // This check avoid erlang module loaded
  // incompatible NIF library
  if (load_vsn != QUICER_ABI_VERSION)
    {
      TP_NIF_3(end, &MsQuic, 1);
      return 1; // any value except 0 is error
    }

  init_atoms(env);
  open_resources(env);

  TP_NIF_3(end, &MsQuic, 0);
  return ret_val;
}

/*
 * on_upgrade is called when the NIF library is loaded and there is old code of
 *  this module with a loaded NIF library.
 *
 *  But new code could be the same as old code, that is, the same msquic
 *  library is mapped into process memory. To distinguish the two cases, the
 *  `MsQuic` API handle is checked since it is init as NULL for new loading. If
 *  MsQuic is NULL, then it is a new load, that two msquic libraries (new and
 *  old) are mapped into process memory, If MsQuic is not NULL, then it is
 *  already initilized and there is still one msquic library in process memory.
 *
 *  In any case above, we return success.
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
** on_unload is called when the module code that the NIF library belongs to is
*  purged as old.
*
*  New code of the same module may or may not exist.
*
*  But there are three cases:
*
*  Case A: No new code of the same module exists.
*          arg `priv_data` is not NULL.
*
*          It is ok to teardown the MsQuic with API handle and then close the
*          API handle.
*
*  Case B: New code of the same module exists and it uses the same NIF DSO.
*          arg `priv_data` is NULL.
*
*          It could be checked with `quicer:nif_mapped()`
*
*          It is *NOT* ok to teardown the MsQuic since the new code is
*          still using it.
*
*  Case C: New code of the same module exists and it uses different NIF DSO.
*          arg `priv_data` is not NULL.
*          AND
*          &MsQuic != the 'lib_api_ptr' in priv_data
*
*          This could be checked with `quicer:nif_mapped()`
*
*          It is ok to teardown the MsQuic with API handle and then close the
*          API handle.

*
*  @NOTE 1. This callback will *NOT* be called when the module is purged
*           while there are opening resources.
*           When new code of the same module exists, the resources will be
*           taken over by the new code thus it will get called for the
*           old code.
*
*  @NOTE 2. The `MsQuic` and `GRegistration` are in library scope.
*
*  @NOTE 3: It is very important to shutdown all the MsQuic Registrations
*           before return to avoid unexpected behaviour after NIF DSO is
*           unmapped by OS.
*
*  @NOTE 4: For safty, it is ok to dlopen the shared library by calling
*           quicer:dlopen/1, so we will have a refcnt on it and it won't
*           be unmapped by OS.
*
*  @NOTE 5: 'same NIF DSO' means same shared library file that is managed
*           by OS.
*           Two copies of the same shared library in OS are different NIF DSOs.
*  */
static void
on_unload(__unused_parm__ ErlNifEnv *env, __unused_parm__ void *priv_data)
{
  // @TODO clean all the leakages before close the lib
  closeLib(env, 0, NULL);
}

static ERL_NIF_TERM
openLib(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  CXPLAT_FRE_ASSERT(argc == 1);
  TP_NIF_3(enter, 0, 1);
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM res = ATOM_FALSE;
  char lttngPath[PATH_MAX] = { 0 };
  unsigned int lb_mode = 0;

  pthread_mutex_lock(&MsQuicLock);
  if (MsQuic)
    {
      // already opened
      TP_NIF_3(skip, 0, 2);
      res = SUCCESS(res);
      goto exit;
    }

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(status = MsQuicOpen2(&MsQuic)))
    {
      MsQuic = NULL;
      res = ERROR_TUPLE_3(ATOM_OPEN_FAILED, ATOM_STATUS(status));
      goto exit;
    }

  TP_NIF_3(success, 0, 2);

  res = SUCCESS(ATOM_TRUE);

  ERL_NIF_TERM eterm = ATOM_UNDEFINED;

  if (enif_get_map_value(
          env, argv[0], ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE, &eterm)
      && enif_get_uint(env, eterm, &lb_mode))
    {
      MsQuic->SetParam(NULL,
                       QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,
                       sizeof(uint16_t),
                       (uint16_t *)&lb_mode);
    }

  if (enif_get_map_value(env, argv[0], ATOM_TRACE, &eterm)
      && enif_get_string(env, eterm, lttngPath, PATH_MAX, ERL_NIF_LATIN1))
    {
      // loading lttng lib is optional, ok to fail
      if (dlopen(lttngPath, (unsigned)RTLD_NOW | (unsigned)RTLD_GLOBAL))
        {
          res = SUCCESS(ATOM_DEBUG);
        }
    }

exit:
  pthread_mutex_unlock(&MsQuicLock);
  return res;
}

static ERL_NIF_TERM
closeLib(__unused_parm__ ErlNifEnv *env,
         __unused_parm__ int argc,
         __unused_parm__ const ERL_NIF_TERM argv[])
{
  pthread_mutex_lock(&MsQuicLock);
  if (MsQuic)
    {
      TP_NIF_3(do_close, MsQuic, 0);

      pthread_mutex_lock(&GRegLock);
      // end of the world
      if (G_r_ctx && !G_r_ctx->is_released)
        {
          // Make MsQuic debug check pass:
          //   Zero Registration when closing MsQuic
          MsQuic->RegistrationClose(G_r_ctx->Registration);
          G_r_ctx->Registration = NULL;
          G_r_ctx->is_released = TRUE;
          destroy_r_ctx(G_r_ctx);
          G_r_ctx = NULL;
        }
      pthread_mutex_unlock(&GRegLock);

      MsQuicClose(MsQuic);
      MsQuic = NULL;
    }

  pthread_mutex_unlock(&MsQuicLock);
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
    case QUIC_STATUS_BAD_CERTIFICATE:
      eterm = ATOM_QUIC_STATUS_BAD_CERTIFICATE;
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
    case QUIC_STATUS_CERT_EXPIRED:
      eterm = ATOM_QUIC_STATUS_CERT_EXPIRED;
      break;
    case QUIC_STATUS_CERT_UNTRUSTED_ROOT:
      eterm = ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT;
      break;
    /*
    case ATOM_QUIC_STATUS_CERT_NO_CERT:
      eterm = ATOM_QUIC_STATUS_CERT_NO_CERT;
      break;
    */
    default:
      if ((status & (TLS_ERROR_BASE)) == (TLS_ERROR_BASE))
        {
          // These may be different on various OS and the
          // list is not complete. Room for improvement.
          int tlserror = (int)(status - (TLS_ERROR_BASE));
          switch (tlserror)
            {
            case TLS1_AD_UNKNOWN_CA:
              eterm = ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT;
              break;
            case TLS13_AD_CERTIFICATE_REQUIRED:
              eterm = ATOM_QUIC_STATUS_CERT_REQUIRED;
              break;
            case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
              eterm = ATOM_QUIC_STATUS_CERT_UNOBTAINABLE;
              break;
            case TLS1_AD_UNRECOGNIZED_NAME:
              eterm = ATOM_QUIC_STATUS_BAD_CERTIFICATE;
              break;
            case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
              eterm = ATOM_QUIC_STATUS_BAD_CERTIFICATE;
              break;
            case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
              eterm = ATOM_QUIC_STATUS_BAD_CERTIFICATE;
              break;
            case SSL_AD_DECRYPT_ERROR:
              eterm = ATOM_QUIC_STATUS_HANDSHAKE_FAILURE;
              break;
            default:
              eterm = enif_make_tuple2(
                  env, ATOM_UNKNOWN_TLS_STATUS_CODE, ETERM_UINT_64(tlserror));
            }
        }
      else
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
      if (!get_stream_handle(s_ctx))
        {
          return ERROR_TUPLE_2(ATOM_CLOSED);
        }

      enif_mutex_lock(s_ctx->lock);
      res = stream_controlling_process(env, s_ctx, &caller, &new_owner);
      enif_mutex_unlock(s_ctx->lock);
      put_stream_handle(s_ctx);
    }
  else if (enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      if (!get_conn_handle(c_ctx))
        {
          return ERROR_TUPLE_2(ATOM_CLOSED);
        }
      enif_mutex_lock(c_ctx->lock);
      res = connection_controlling_process(env, c_ctx, &caller, &new_owner);
      enif_mutex_unlock(c_ctx->lock);
      put_conn_handle(c_ctx);
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
      // rollback, must success
      enif_self(env, &c_ctx->owner->Pid);
      enif_monitor_process(env, c_ctx, caller, &c_ctx->owner_mon);
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
      // rollback, must success
      enif_self(env, &s_ctx->owner->Pid);
      flush_sig_buffer(env, s_ctx);
      enif_monitor_process(env, s_ctx, caller, &s_ctx->owner_mon);
      return ERROR_TUPLE_2(ATOM_OWNER_DEAD);
    }
  flush_sig_buffer(env, s_ctx);
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

  return make_event(env,
                    event_name, // 2nd element, event name :: atom()
                    resource,   // 3rd element, resource handle
                    prop);      // 4th element, event props :: map()
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
  { "reg_close", 0, deregistration, 1 },
  { "new_registration", 2, new_registration2, 0},
  { "shutdown_registration", 1, shutdown_registration_x, 0},
  { "shutdown_registration", 3, shutdown_registration_x, 0},
  { "close_registration", 1, close_registration, 1},
  { "get_registration_name", 1, get_registration_name1, 0},
  { "listen", 2, listen2, 0},
  { "start_listener", 3, start_listener3, 0},
  { "stop_listener", 1, stop_listener1, 0},
  { "close_listener", 1, close_listener1, 0},
  { "open_connection", 0, open_connectionX, 0},
  { "open_connection", 1, open_connectionX, 0},
  { "async_connect", 3, async_connect3, 0},
  { "async_accept", 2, async_accept2, 0},
  { "async_handshake", 1, async_handshake_1, 0},
  { "async_shutdown_connection", 3, shutdown_connection3, 0},
  { "async_accept_stream", 2, async_accept_stream2, 0},
  { "start_stream", 2, async_start_stream2, 0},
  { "send", 3, send3, 0},
  { "csend", 4, csend4, 0},
  { "recv", 2, recv2, 0},
  { "send_dgram", 3, send_dgram, 0},
  { "async_shutdown_stream", 3, shutdown_stream3, 0},
  { "sockname", 1, sockname1, 0},
  { "getopt", 3, getopt3, 0},
  { "setopt", 4, setopt4, 0},
  { "controlling_process", 2, controlling_process, 0},
  { "peercert", 1, peercert1, 0},
  { "enable_sig_buffer", 1, enable_sig_buffer, 0},
  { "flush_stream_buffered_sigs", 1, flush_stream_buffered_sigs, 0},
  /* for DEBUG */
  { "get_conn_rid", 1, get_conn_rid1, 1},
  { "get_stream_rid", 1, get_stream_rid1, 1},
  { "get_listeners", 0, get_listenersX, 0},
  { "get_listeners", 1, get_listenersX, 0},
  { "get_connections", 0, get_connectionsX, 0},
  { "get_connections", 1, get_connectionsX, 0},
  { "get_conn_owner", 1, get_conn_owner1, 0},
  { "get_stream_owner", 1, get_stream_owner1, 0},
  { "get_listener_owner", 1, get_listener_owner1, 0},
  /* for testing */
  { "mock_buffer_sig", 3, mock_buffer_sig, 0}
  // clang-format on
};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
