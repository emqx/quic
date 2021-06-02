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
ERL_NIF_TERM ATOM_PARM_ERROR;
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
ERL_NIF_TERM ATOM_SOCKNAME_ERROR;
ERL_NIF_TERM ATOM_OWNER_DEAD;

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
ERL_NIF_TERM ATOM_QUIC_STATUS_PERMISSION_DENIED;
ERL_NIF_TERM ATOM_QUIC_STATUS_EPOLL_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_DNS_RESOLUTION_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_SOCKET_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_TLS_ERROR;
ERL_NIF_TERM ATOM_QUIC_STATUS_USER_CANCELED;
ERL_NIF_TERM ATOM_QUIC_STATUS_ALPN_NEG_FAILURE;

// option keys
ERL_NIF_TERM ATOM_CERT;
ERL_NIF_TERM ATOM_KEY;
ERL_NIF_TERM ATOM_ALPN;

/*-----------------------------------------*/
/*         msquic parms starts             */
/*-----------------------------------------*/

// Parameters for QUIC_PARAM_LEVEL_GLOBAL.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS;
ERL_NIF_TERM ATOM_QUIC_PARAM_GLOBAL_SETTINGS;

//
// Parameters for QUIC_PARAM_LEVEL_REGISTRATION.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX;

//
// Parameters for QUIC_PARAM_LEVEL_CONFIGURATION.
//
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

//
// Parameters for QUIC_PARAM_LEVEL_TLS.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W;

//
// Parameters for QUIC_PARAM_LEVEL_STREAM.
//
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_ID;
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH;
ERL_NIF_TERM ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE;

/*-----------------------*/
/* msquic parms ends     */
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

/*----------------------------------------------------------*/
/* QUIC_SETTINGS ends      */
/*----------------------------------------------------------*/

/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS starts */
/*----------------------------------------------------------*/
ERL_NIF_TERM ATOM_QUIC_STREAM_OPTS_ACTIVE;
/*----------------------------------------------------------*/
/* QUIC_STREAM_OPTS ends  */
/*----------------------------------------------------------*/

ERL_NIF_TERM ATOM_CLOSED;
ERL_NIF_TERM ATOM_SHUTDOWN;
ERL_NIF_TERM ATOM_PEER_SEND_SHUTDOWN;
ERL_NIF_TERM ATOM_PEER_SEND_ABORTED;
ERL_NIF_TERM ATOM_EINVAL;
ERL_NIF_TERM ATOM_QUIC;

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
  ATOM(ATOM_PARM_ERROR, parm_error);                                          \
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
  ATOM(ATOM_OWNER_DEAD, owner_dead);                                          \
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
  ATOM(ATOM_QUIC_STATUS_PERMISSION_DENIED, permission_denied);                \
  ATOM(ATOM_QUIC_STATUS_EPOLL_ERROR, epoll_error);                            \
  ATOM(ATOM_QUIC_STATUS_DNS_RESOLUTION_ERROR, dns_resolution_error);          \
  ATOM(ATOM_QUIC_STATUS_SOCKET_ERROR, socket_error);                          \
  ATOM(ATOM_QUIC_STATUS_TLS_ERROR, tls_error);                                \
  ATOM(ATOM_QUIC_STATUS_USER_CANCELED, user_canceled);                        \
  ATOM(ATOM_QUIC_STATUS_ALPN_NEG_FAILURE, alpn_neg_failure);                  \
  /*-----------------------------------------*/                               \
  /*         msquic parms starts             */                               \
  /*-----------------------------------------*/                               \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_GLOBAL. */                              \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,                           \
       param_global_retry_memory_percent);                                    \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS,                             \
       param_global_supported_versions);                                      \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE,                             \
       param_global_load_balacing_mode);                                      \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS, param_global_perf_counters);     \
  ATOM(ATOM_QUIC_PARAM_GLOBAL_SETTINGS, param_global_settings);               \
                                                                              \
  /*Parameters for QUIC_PARAM_LEVEL_REGISTRATION.*/                           \
  ATOM(ATOM_QUIC_PARAM_REGISTRATION_CID_PREFIX,                               \
       param_registration_cid_prefix);                                        \
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_CONFIGURATION. */                        \
                                                                              \
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
                                                                              \
  /* Parameters for QUIC_PARAM_LEVEL_TLS. */                                  \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,                      \
       param_tls_schannel_context_attribute_w);                               \
                                                                              \
  /*  Parameters for QUIC_PARAM_LEVEL_STREAM.  */                             \
                                                                              \
  ATOM(ATOM_QUIC_PARAM_STREAM_ID, param_stream_id);                           \
  ATOM(ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH, param_stream_0rtt_length);         \
  ATOM(ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE,                         \
       param_stream_ideal_send_buffer_size);                                  \
                                                                              \
  /*-----------------------*/                                                 \
  /* msquic parms ends     */                                                 \
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
  /*                  QUIC_SETTINGS end                        */             \
  /*                  QUIC_STREAM_OPTS start                        */        \
  ATOM(ATOM_QUIC_STREAM_OPTS_ACTIVE, active)                                  \
  /*                  QUIC_STREAM_OPTS end                        */          \
  ATOM(ATOM_CERT, cert);                                                      \
  ATOM(ATOM_KEY, key);                                                        \
  ATOM(ATOM_ALPN, alpn);                                                      \
  ATOM(ATOM_CLOSED, closed);                                                  \
  ATOM(ATOM_SHUTDOWN, shutdown);                                              \
  ATOM(ATOM_PEER_SEND_SHUTDOWN, peer_send_shutdown);                          \
  ATOM(ATOM_PEER_SEND_ABORTED, peer_send_aborted);                            \
  ATOM(ATOM_EINVAL, einval);                                                  \
  ATOM(ATOM_QUIC, quic);

HQUIC Registration;
const QUIC_API_TABLE *MsQuic;

// @todo, these flags are not threads safe, wrap it in a context
BOOLEAN isRegistered = false;
BOOLEAN isLibOpened = false;

ErlNifResourceType *ctx_listener_t = NULL;
ErlNifResourceType *ctx_connection_t = NULL;
ErlNifResourceType *ctx_stream_t = NULL;

const QUIC_REGISTRATION_CONFIG RegConfig
    = { "quicer_nif", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

void
resource_listener_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                                __unused_parm__ void *obj,
                                __unused_parm__ ErlNifPid *pid,
                                __unused_parm__ ErlNifMonitor *mon)
{
  // todo
}

void
resource_conn_dealloc_callback(__unused_parm__ ErlNifEnv *caller_env,
                               void *obj)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)obj;
  enif_demonitor_process(c_ctx->env, c_ctx, c_ctx->owner_mon);
  AcceptorQueueDestroy(c_ctx->acceptor_queue);
  enif_free_env(c_ctx->env);
  enif_mutex_destroy(c_ctx->lock);
  CXPLAT_FREE(c_ctx->owner_mon, QUICER_OWNER_MON);
  AcceptorDestroy(c_ctx->owner);
}

void
resource_conn_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                            __unused_parm__ void *obj,
                            __unused_parm__ ErlNifPid *pid,
                            __unused_parm__ ErlNifMonitor *mon)
{
  // todo
}

void
resource_stream_dealloc_callback(__unused_parm__ ErlNifEnv *caller_env,
                                 void *obj)
{
  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)obj;
  enif_free_env(s_ctx->env);
  enif_mutex_destroy(s_ctx->lock);
}

void
resource_stream_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                              __unused_parm__ void *obj,
                              __unused_parm__ ErlNifPid *pid,
                              __unused_parm__ ErlNifMonitor *mon)
{
  // @todo
}

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
  ErlNifResourceTypeInit connInit
      = { .dtor = NULL, .down = resource_conn_down_callback, .stop = NULL };
  ErlNifResourceTypeInit listenerInit = {
    .dtor = NULL, .down = resource_listener_down_callback, .stop = NULL
  };
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

static int
on_upgrade(__unused_parm__ ErlNifEnv *env,
           __unused_parm__ void **priv_data,
           __unused_parm__ void **old_priv_data,
           __unused_parm__ ERL_NIF_TERM load_info)
{
  return 0;
}

static void
on_unload(__unused_parm__ ErlNifEnv *env, __unused_parm__ void *priv_data)
{
}

static ERL_NIF_TERM
openLib(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  assert(1 == argc);
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM lttngLib = argv[0];
  char lttngPath[PATH_MAX] = { 0 };

  // @todo external call for static link
  CxPlatSystemLoad();
  MsQuicLibraryLoad();
  if (enif_get_string(env, lttngLib, lttngPath, PATH_MAX, ERL_NIF_LATIN1))
    {
      // loading lttng lib is optional, ok to fail
      dlopen(lttngPath, (unsigned)RTLD_NOW | (unsigned)RTLD_GLOBAL);
    }

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(status = MsQuicOpen(&MsQuic)))
    {
      return ERROR_TUPLE_3(ATOM_OPEN_FAILED, ETERM_INT(status));
    }

  isLibOpened = true;
  return ATOM_OK;
}

static ERL_NIF_TERM
closeLib(__unused_parm__ ErlNifEnv *env,
         __unused_parm__ int argc,
         __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isLibOpened && MsQuic)
    {
      MsQuicClose(MsQuic);
      isLibOpened = false;
    }

  return ATOM_OK;
}

static ERL_NIF_TERM
registration(ErlNifEnv *env,
             __unused_parm__ int argc,
             __unused_parm__ const ERL_NIF_TERM argv[])
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(status
                  = MsQuic->RegistrationOpen(&RegConfig, &Registration)))
    {
      return ERROR_TUPLE_3(ATOM_REG_FAILED, ETERM_INT(status));
    }
  isRegistered = true;
  return ATOM_OK;
}

static ERL_NIF_TERM
deregistration(__unused_parm__ ErlNifEnv *env,
               __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isRegistered && Registration)
    {
      MsQuic->RegistrationClose(Registration);
      isRegistered = false;
    }
  return ATOM_OK;
}

ERL_NIF_TERM
atom_status(QUIC_STATUS status)
{
  ERL_NIF_TERM eterm = ATOM_OK;
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
    case QUIC_STATUS_PERMISSION_DENIED:
      eterm = ATOM_QUIC_STATUS_PERMISSION_DENIED;
      break;
    case QUIC_STATUS_EPOLL_ERROR:
      eterm = ATOM_QUIC_STATUS_EPOLL_ERROR;
      break;
    case QUIC_STATUS_DNS_RESOLUTION_ERROR:
      eterm = ATOM_QUIC_STATUS_DNS_RESOLUTION_ERROR;
      break;
    case QUIC_STATUS_SOCKET_ERROR:
      eterm = ATOM_QUIC_STATUS_SOCKET_ERROR;
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
    }
  return eterm;
}

ERL_NIF_TERM
atom_errno(int errno)
{
  ERL_NIF_TERM eterm = ATOM_OK;

  switch (errno)
    {
    case NO_ERROR:
      eterm = ATOM_ERROR_NO_ERROR;
      break;
    case ERROR_CONTINUE:
      eterm = ATOM_ERROR_CONTINUE;
      break;
    case ERROR_NOT_READY:
      eterm = ATOM_ERROR_NOT_READY;
      break;
    case ERROR_NOT_ENOUGH_MEMORY:
      eterm = ATOM_ERROR_NOT_ENOUGH_MEMORY;
      break;
    case ERROR_INVALID_STATE:
      eterm = ATOM_ERROR_INVALID_STATE;
      break;
    case ERROR_INVALID_PARAMETER:
      eterm = ATOM_ERROR_INVALID_PARAMETER;
      break;
    case ERROR_NOT_SUPPORTED:
      eterm = ATOM_ERROR_NOT_SUPPORTED;
      break;
    case ERROR_NOT_FOUND:
      eterm = ATOM_ERROR_NOT_FOUND;
      break;
    case ERROR_BUFFER_OVERFLOW:
      eterm = ATOM_ERROR_BUFFER_OVERFLOW;
      break;
    case ERROR_CONNECTION_REFUSED:
      eterm = ATOM_ERROR_CONNECTION_REFUSED;
      break;
    case ERROR_OPERATION_ABORTED:
      eterm = ATOM_ERROR_OPERATION_ABORTED;
      break;
    case ERROR_HANDSHAKE_FAILURE:
      eterm = ATOM_ERROR_HANDSHAKE_FAILURE;
      break;
    case ERROR_NETWORK_UNREACHABLE:
      eterm = ATOM_ERROR_NETWORK_UNREACHABLE;
      break;
    case ERROR_CONNECTION_IDLE:
      eterm = ATOM_ERROR_CONNECTION_IDLE;
      break;
    case ERROR_INTERNAL_ERROR:
      eterm = ATOM_ERROR_INTERNAL_ERROR;
      break;
    case ERROR_PROTOCOL_ERROR:
      eterm = ATOM_ERROR_PROTOCOL_ERROR;
      break;
    case ERROR_VER_NEG_ERROR:
      eterm = ATOM_ERROR_VER_NEG_ERROR;
      break;
    case ERROR_EPOLL_ERROR:
      eterm = ATOM_ERROR_EPOLL_ERROR;
      break;
    case ERROR_DNS_RESOLUTION_ERROR:
      eterm = ATOM_ERROR_DNS_RESOLUTION_ERROR;
      break;
    case ERROR_SOCKET_ERROR:
      eterm = ATOM_ERROR_SOCKET_ERROR;
      break;
    case ERROR_SSL_ERROR:
      eterm = ATOM_ERROR_SSL_ERROR;
      break;
    case ERROR_USER_CANCELED:
      eterm = ATOM_ERROR_USER_CANCELED;
      break;
    case ERROR_ALPN_NEG_FAILURE:
      eterm = ATOM_ERROR_ALPN_NEG_FAILURE;
      break;
    }
  return eterm;
}

static ErlNifFunc nif_funcs[] = {
  /* |  name  | arity| funptr | flags|
   *
   */
  // clang-format off
  { "open_lib", 1, openLib, 0 },
  { "close_lib", 0, closeLib, 0 },
  { "reg_open", 0, registration, 0 },
  { "reg_close", 0, deregistration, 0 },
  { "listen", 2, listen2, 0},
  { "close_listener", 1, close_listener1, 0},
  { "async_connect", 3, async_connect3, 0},
  { "async_accept", 2, async_accept2, 0},
  { "async_close_connection", 1, close_connection1, 0},
  { "async_accept_stream", 2, async_accept_stream2, 0},
  { "start_stream", 2, async_start_stream2, 0},
  { "send", 2, send2, 0},
  { "recv", 2, recv2, 0},
  { "async_close_stream", 1, close_stream1, 0},
  { "sockname", 1, sockname1, 0},
  { "getopt", 3, getopt3, 0},
  { "setopt", 3, setopt3, 0}
  // clang-format on
};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
