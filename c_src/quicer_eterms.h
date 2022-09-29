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

#ifndef __QUICER_ETERMS_H_
#define __QUICER_ETERMS_H_
#include <erl_nif.h>

extern ERL_NIF_TERM ATOM_TRUE;
extern ERL_NIF_TERM ATOM_FALSE;

// quicer internal 'errors'
extern ERL_NIF_TERM ATOM_OK;
extern ERL_NIF_TERM ATOM_ERROR;
extern ERL_NIF_TERM ATOM_REG_FAILED;
extern ERL_NIF_TERM ATOM_OPEN_FAILED;
extern ERL_NIF_TERM ATOM_CTX_INIT_FAILED;
extern ERL_NIF_TERM ATOM_BAD_PID;
extern ERL_NIF_TERM ATOM_CONFIG_ERROR;
extern ERL_NIF_TERM ATOM_PARAM_ERROR;
extern ERL_NIF_TERM ATOM_CERT_ERROR;
extern ERL_NIF_TERM ATOM_BAD_MON;
extern ERL_NIF_TERM ATOM_LISTENER_OPEN_ERROR;
extern ERL_NIF_TERM ATOM_LISTENER_START_ERROR;
extern ERL_NIF_TERM ATOM_BADARG;
extern ERL_NIF_TERM ATOM_CONN_OPEN_ERROR;
extern ERL_NIF_TERM ATOM_CONN_START_ERROR;
extern ERL_NIF_TERM ATOM_STREAM_OPEN_ERROR;
extern ERL_NIF_TERM ATOM_STREAM_START_ERROR;
extern ERL_NIF_TERM ATOM_STREAM_SEND_ERROR;
extern ERL_NIF_TERM ATOM_DGRAM_SEND_ERROR;
extern ERL_NIF_TERM ATOM_SOCKNAME_ERROR;
extern ERL_NIF_TERM ATOM_OWNER_DEAD;
extern ERL_NIF_TERM ATOM_NOT_OWNER;

// msquic_linux.h 'errors'
extern ERL_NIF_TERM ATOM_ERROR_NO_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_CONTINUE;
extern ERL_NIF_TERM ATOM_ERROR_NOT_READY;
extern ERL_NIF_TERM ATOM_ERROR_NOT_ENOUGH_MEMORY;
extern ERL_NIF_TERM ATOM_ERROR_INVALID_STATE;
extern ERL_NIF_TERM ATOM_ERROR_INVALID_PARAMETER;
extern ERL_NIF_TERM ATOM_ERROR_NOT_SUPPORTED;
extern ERL_NIF_TERM ATOM_ERROR_NOT_FOUND;
extern ERL_NIF_TERM ATOM_ERROR_BUFFER_OVERFLOW;
extern ERL_NIF_TERM ATOM_ERROR_CONNECTION_REFUSED;
extern ERL_NIF_TERM ATOM_ERROR_OPERATION_ABORTED;
extern ERL_NIF_TERM ATOM_ERROR_HANDSHAKE_FAILURE;
extern ERL_NIF_TERM ATOM_ERROR_NETWORK_UNREACHABLE;
extern ERL_NIF_TERM ATOM_ERROR_CONNECTION_IDLE;
extern ERL_NIF_TERM ATOM_ERROR_INTERNAL_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_PROTOCOL_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_VER_NEG_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_EPOLL_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_DNS_RESOLUTION_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_SOCKET_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_SSL_ERROR;
extern ERL_NIF_TERM ATOM_ERROR_USER_CANCELED;
extern ERL_NIF_TERM ATOM_ERROR_ALPN_NEG_FAILURE;

extern ERL_NIF_TERM ATOM_UNKNOWN_STATUS_CODE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_SUCCESS;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_PENDING;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CONTINUE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_OUT_OF_MEMORY;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_INVALID_PARAMETER;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_INVALID_STATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_NOT_SUPPORTED;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_NOT_FOUND;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_BUFFER_TOO_SMALL;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_HANDSHAKE_FAILURE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_ABORTED;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_ADDRESS_IN_USE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_TIMEOUT;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_IDLE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_INTERNAL_ERROR;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CONNECTION_REFUSED;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_PROTOCOL_ERROR;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_VER_NEG_ERROR;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_UNREACHABLE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_TLS_ERROR;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_USER_CANCELED;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_ALPN_NEG_FAILURE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_STREAM_LIMIT_REACHED;
// TLS ERRORS
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CLOSE_NOTIFY;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_BAD_CERTIFICATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_UNSUPPORTED_CERTIFICATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_REVOKED_CERTIFICATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_EXPIRED_CERTIFICATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_UNKNOWN_CERTIFICATE;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_EXPIRED;
extern ERL_NIF_TERM ATOM_QUIC_STATUS_CERT_UNTRUSTED_ROOT;

// option keys
extern ERL_NIF_TERM ATOM_CERT;
extern ERL_NIF_TERM ATOM_KEY;
extern ERL_NIF_TERM ATOM_PASSWORD;
extern ERL_NIF_TERM ATOM_ALPN;
extern ERL_NIF_TERM ATOM_HANDLER;

/*-------------------------------------------------------*/
/*         msquic  execution profile for registration    */
/*-------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY; // Default
extern ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
extern ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
extern ERL_NIF_TERM ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;

/*-----------------------------------------*/
/*         msquic params starts             */
/*-----------------------------------------*/

// Parameters for QUIC_PARAM_LEVEL_GLOBAL.
//
extern ERL_NIF_TERM ATOM_QUIC_GLOBAL;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SETTINGS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_VERSION;

//
// Parameters for QUIC_PARAM_LEVEL_REGISTRATION.
//
extern ERL_NIF_TERM ATOM_QUIC_REGISTRATION;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX;

//
// Parameters for QUIC_PARAM_LEVEL_CONFIGURATION.
//
extern ERL_NIF_TERM ATOM_QUIC_CONFIGURATION;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS;

//
// Parameters for QUIC_PARAM_LEVEL_LISTENER.
//
extern ERL_NIF_TERM ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_LISTENER_STATS;

//
// Parameters for QUIC_PARAM_LEVEL_CONNECTION.
//
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_QUIC_VERSION;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_SETTINGS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STATISTICS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;

extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION;

extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE;

//
// Parameters for QUIC_PARAM_LEVEL_TLS.
//
extern ERL_NIF_TERM ATOM_QUIC_TLS;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN;

//
// Parameters for QUIC_PARAM_LEVEL_STREAM.
//
extern ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_ID;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE;
extern ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_PRIORITY;

/*-----------------------*/
/* msquic params ends     */
/*-----------------------*/

/*----------------------------------------------------------*/
/* QUIC_SETTINGS starts                                     */
/*----------------------------------------------------------*/

extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxBytesPerKey;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_HandshakeIdleTimeoutMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_IdleTimeoutMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_TlsServerMaxSendBuffer;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_StreamRecvWindowDefault;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_StreamRecvBufferDefault;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_ConnFlowControlWindow;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxWorkerQueueDelayUs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxStatelessOperations;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_InitialWindowPackets;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_SendIdleTimeoutMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_InitialRttMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxAckDelayMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_DisconnectTimeoutMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_KeepAliveIntervalMs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_PeerBidiStreamCount;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_PeerUnidiStreamCount;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_RetryMemoryLimit;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_LoadBalancingMode;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxOperationsPerDrain;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_SendBufferingEnabled;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_PacingEnabled;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MigrationEnabled;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_DatagramReceiveEnabled;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_ServerResumptionLevel;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_VersionNegotiationExtEnabled;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_DesiredVersionsList;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_DesiredVersionsListLength;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MinimumMtu;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaximumMtu;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MtuDiscoverySearchCompleteTimeoutUs;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MtuDiscoveryMissingProbeCount;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_MaxBindingStatelessOperations;
extern ERL_NIF_TERM ATOM_QUIC_SETTINGS_StatelessOperationExpirationMs;

/*----------------------------------------------------------*/
/* QUIC_SETTINGS ends                                       */
/*----------------------------------------------------------*/

/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS starts                                  */
/*----------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_ACTIVE;
extern ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_OPEN_FLAG;
extern ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_START_FLAG;
/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS ends                                    */
/*----------------------------------------------------------*/

/*----------------------------------------------------------*/
/* Terms for message sending                                */
/*----------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_CLOSED;
extern ERL_NIF_TERM ATOM_STREAM_CLOSED;
extern ERL_NIF_TERM ATOM_LISTENER_STOPPED;
extern ERL_NIF_TERM ATOM_TRANS_SHUTDOWN;
extern ERL_NIF_TERM ATOM_SHUTDOWN;
extern ERL_NIF_TERM ATOM_PEER_SEND_SHUTDOWN;
extern ERL_NIF_TERM ATOM_PEER_SEND_ABORTED;
extern ERL_NIF_TERM ATOM_PEER_RECEIVE_ABORTED;
extern ERL_NIF_TERM ATOM_PEER_ADDRESS_CHANGED;
extern ERL_NIF_TERM ATOM_PEER_ACCEPTED;
extern ERL_NIF_TERM ATOM_LOCAL_ADDRESS_CHANGED;
extern ERL_NIF_TERM ATOM_STREAMS_AVAILABLE;
extern ERL_NIF_TERM ATOM_PEER_NEEDS_STREAMS;
extern ERL_NIF_TERM ATOM_START_COMPLETE;
extern ERL_NIF_TERM ATOM_SEND_COMPLETE;
extern ERL_NIF_TERM ATOM_SEND_DGRAM_COMPLETE;
extern ERL_NIF_TERM ATOM_EINVAL;
extern ERL_NIF_TERM ATOM_QUIC;
extern ERL_NIF_TERM ATOM_DGRAM;
extern ERL_NIF_TERM ATOM_DGRAM_MAX_LEN;
extern ERL_NIF_TERM ATOM_PASSIVE;
extern ERL_NIF_TERM ATOM_QUIC_EVENT_MASK;
extern ERL_NIF_TERM ATOM_NST_RECEIVED;
extern ERL_NIF_TERM ATOM_NST;
extern ERL_NIF_TERM ATOM_DEBUG;
extern ERL_NIF_TERM ATOM_ONCE;
extern ERL_NIF_TERM ATOM_NEW_CONN;
extern ERL_NIF_TERM ATOM_CONNECTED;
extern ERL_NIF_TERM ATOM_CONN_RESUMED;
extern ERL_NIF_TERM ATOM_NEW_STREAM;

/*----------------------------------------------------------*/
/* Terms for tracing                                        */
/*----------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_SNABBKAFFE_COLLECTOR;
extern ERL_NIF_TERM ATOM_TRACE;
// Trace point Context, nif for callback
extern ERL_NIF_TERM ATOM_CONTEXT;
extern ERL_NIF_TERM ATOM_NIF;
extern ERL_NIF_TERM ATOM_CALLBACK;
extern ERL_NIF_TERM ATOM_TAG;
extern ERL_NIF_TERM ATOM_RESOURCE_ID;
extern ERL_NIF_TERM ATOM_MARK;
extern ERL_NIF_TERM ATOM_KIND;
extern ERL_NIF_TERM ATOM_GEN_CAST;
extern ERL_NIF_TERM ATOM_SNK_KIND;
extern ERL_NIF_TERM ATOM_SNK_META;
extern ERL_NIF_TERM ATOM_FUNCTION;
extern ERL_NIF_TERM ATOM_SNABBKAFFE_NEMESIS;

/*----------------------------------------------------------*/
/* Additional Connection Opt                                */
/*----------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_SSL_KEYLOGFILE_NAME;
extern ERL_NIF_TERM ATOM_ALLOW_INSECURE;

/*----------------------------------------------------------*/
/* Used in messages to the owners */
/*----------------------------------------------------------*/
extern ERL_NIF_TERM ATOM_IS_RESUMED;
extern ERL_NIF_TERM ATOM_ALPNS;
extern ERL_NIF_TERM ATOM_IS_HANDSHAKE_COMPLETED;
extern ERL_NIF_TERM ATOM_IS_PEER_ACKED;
extern ERL_NIF_TERM ATOM_IS_APP_CLOSING;
extern ERL_NIF_TERM ATOM_BIDI_STREAMS;
extern ERL_NIF_TERM ATOM_UNIDI_STREAMS;
extern ERL_NIF_TERM ATOM_STATUS;
extern ERL_NIF_TERM ATOM_STREAM_ID;
extern ERL_NIF_TERM ATOM_IS_PEER_ACCEPTED;
extern ERL_NIF_TERM ATOM_IS_CONN_SHUTDOWN;
extern ERL_NIF_TERM ATOM_ABS_OFFSET;
extern ERL_NIF_TERM ATOM_LEN;
extern ERL_NIF_TERM ATOM_FLAGS;
extern ERL_NIF_TERM ATOM_VER;
extern ERL_NIF_TERM ATOM_LOCAL_ADDR;
extern ERL_NIF_TERM ATOM_REMOTE_ADDR;
extern ERL_NIF_TERM ATOM_SERVER_NAME;
extern ERL_NIF_TERM ATOM_CLIENT_ALPNS;
extern ERL_NIF_TERM ATOM_CRYPTO_BUFFER;

extern ERL_NIF_TERM ATOM_UNDEFINED;
/*----------------------------------------------------------*/
/* ATOMS ends here                                          */
/*----------------------------------------------------------*/

#define SUCCESS(Term) enif_make_tuple(env, 2, ATOM_OK, Term)
#define ERROR_TUPLE_2(Err) enif_make_tuple2(env, ATOM_ERROR, Err)
#define ERROR_TUPLE_3(Err1, Err2) enif_make_tuple3(env, ATOM_ERROR, Err1, Err2)

#define ATOM_STATUS(status) atom_status(env, status)

#define OK_TUPLE_2(Term) enif_make_tuple2(env, ATOM_OK, Term)

#define ETERM_INT(i) enif_make_int(env, i)

#define ETERM_UINT_64(i) enif_make_int(env, (uint64_t)i)

#define ETERM_BOOL(i) ((i) > 0 ? ATOM_TRUE : ATOM_FALSE)

#define IS_SAME_TERM(x, y) enif_is_identical(x, y)

#define PropTupleStrInt(S, I)                                                 \
  enif_make_tuple2(env,                                                       \
                   enif_make_string(env, #S, ERL_NIF_LATIN1),                 \
                   enif_make_uint64(env, (uint64_t)I))

#define PropTupleAtomInt(A, I)                                                \
  enif_make_tuple2(env, A, enif_make_uint64(env, (uint64_t)I))

#define PropTupleAtomBool(A, I) enif_make_tuple2(env, A, ETERM_BOOL(I))

#endif // __QUICER_ETERMS_H_
