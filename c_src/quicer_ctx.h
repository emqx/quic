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

#ifndef __QUICER_CTX_H_
#define __QUICER_CTX_H_

#include "quicer_nif.h"
#include "quicer_owner_queue.h"
#include "quicer_queue.h"
#include <msquichelper.h>
#include <openssl/x509.h>

#define _CTX_CALLBACK_WRITE_
#define _CTX_CALLBACK_READ_
#define _CTX_NIF_WRITE_
#define _CTX_NIF_READ_

#define CONN_LINK_REGISTRATION(CTX, RCTX)                                     \
  LINK_REGISTRATION(CTX, RCTX, Connections)

#define LISTENER_LINK_REGISTRATION(CTX, RCTX)                                 \
  LINK_REGISTRATION(CTX, RCTX, Listeners)
#define PUT_UNLINK_REGISTRATION(CTX, RCTX)                                    \
  do                                                                          \
    {                                                                         \
      UNLINK_REGISTRATION(CTX, RCTX);                                         \
      put_reg_handle(RCTX);                                                   \
    }                                                                         \
  while (0)

#define UNLINK_REGISTRATION(CTX, RCTX)                                        \
  do                                                                          \
    {                                                                         \
      enif_mutex_lock(RCTX->lock);                                            \
      CxPlatListEntryRemove(&CTX->RegistrationLink);                          \
      enif_mutex_unlock(RCTX->lock);                                          \
    }                                                                         \
  while (0)

#define LINK_REGISTRATION(CTX, RCTX, LISTNAME)                                \
  do                                                                          \
    {                                                                         \
      enif_mutex_lock(RCTX->lock);                                            \
      CxPlatListInsertTail(&RCTX->LISTNAME, &CTX->RegistrationLink);          \
      enif_mutex_unlock(RCTX->lock);                                          \
      CTX->r_ctx = RCTX;                                                      \
    }                                                                         \
  while (0)

#define LOCAL_REFCNT(XX) XX
#define DESTRUCT_REFCNT(XX) XX
#define CALLBACK_DESTRUCT_REFCNT(XX) DESTRUCT_REFCNT(XX)
/*
 * Registration
 */
typedef struct QuicerRegistrationCTX
{
  ErlNifEnv *env;
  HQUIC Registration;
  // Tracking lifetime of Registration handle
  CXPLAT_REF_COUNT ref_count;
  BOOLEAN is_closed;
  char name[UINT8_MAX + 1];
  ErlNifMutex *lock;
  CXPLAT_LIST_ENTRY Listeners;
  CXPLAT_LIST_ENTRY Connections;
} QuicerRegistrationCTX;

/*
 * Configuration
 */
typedef struct QuicerConfigCTX
{
  ErlNifEnv *env;
  HQUIC Configuration;
  CXPLAT_REF_COUNT ref_count;
} QuicerConfigCTX;

typedef struct QuicerListenerCTX
{
  // config_ctx is allocated in 'init_l_ctx'
  QuicerConfigCTX *config_ctx;
  QuicerRegistrationCTX *r_ctx;
  HQUIC Listener;
  // track lifetime of Connection handle
  CXPLAT_REF_COUNT ref_count;
  QUICER_ACCEPTOR_QUEUE *acceptor_queue;
  ErlNifPid listenerPid;
  BOOLEAN is_monitored;
  ErlNifMonitor owner_mon;
  ErlNifEnv *env;
  ErlNifMutex *lock;
#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE *trusted_store;
#endif
  // Listener handle closed flag
  // false means the handle is invalid
  BOOLEAN is_closed;
  BOOLEAN is_stopped;
  BOOLEAN allow_insecure;
  CXPLAT_LIST_ENTRY RegistrationLink;
  void *reserved1;
  void *reserved2;
  void *reserved3;
} QuicerListenerCTX;

typedef struct QuicerConnCTX
{
  uint32_t magic;
  // config_ctx
  // for server, inherited and shared with l_ctx
  // for client, alloc on its own
  QuicerConfigCTX *config_ctx;
  QuicerRegistrationCTX *r_ctx;
  CXPLAT_LIST_ENTRY RegistrationLink;
  HQUIC Connection;
  QUICER_ACCEPTOR_QUEUE *acceptor_queue;
  ACCEPTOR *owner;
  BOOLEAN is_monitored;
  ErlNifMonitor owner_mon;
  ErlNifEnv *env;
  ErlNifMutex *lock;
#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE *trusted;
#endif // QUICER_USE_TRUSTED_STORE
  QUIC_TLS_SECRETS *TlsSecrets;
  QUIC_BUFFER *ResumptionTicket;
  // Connection handle closed flag
  // false means the handle is invalid
  BOOLEAN is_closed;
  // track lifetime of Connection handle
  CXPLAT_REF_COUNT ref_count;
  uint32_t event_mask;
  char *ssl_keylogfile;
  X509 *peer_cert;
  void *reserved2;
  void *reserved3;
} QuicerConnCTX;

typedef struct QuicerStreamCTX
{
  uint32_t magic;
  QuicerConnCTX *c_ctx;
  HQUIC Stream;
  uint64_t StreamID;
  ACCEPTOR *owner;
  BOOLEAN is_monitored;
  ErlNifMonitor owner_mon;
  ErlNifEnv *env;
  // Immutable env,
  // eTerms in imm_env should never be changed once set
  // eTerms in imm_env survives after each callback
  // imm_env should be freed in ctx destroy fun.
  ErlNifEnv *imm_env;
  // Set once
  ERL_NIF_TERM eHandle;
  ErlNifMutex *lock;
  _CTX_CALLBACK_WRITE_ _CTX_NIF_READ_ QUIC_BUFFER Buffers[2];
  _CTX_CALLBACK_WRITE_ _CTX_NIF_READ_ uint64_t TotalBufferLength;
  _CTX_CALLBACK_WRITE_ _CTX_NIF_READ_ uint32_t BufferCount;
  _CTX_CALLBACK_READ_ BOOLEAN is_wait_for_data;
  _CTX_CALLBACK_WRITE_ BOOLEAN is_recv_pending;
  BOOLEAN is_closed;
  // Track lifetime of Stream handle
  CXPLAT_REF_COUNT ref_count;
  uint32_t event_mask;
  // for ownership handoff
  OWNER_SIGNAL_QUEUE *sig_queue;
  void *reserved1;
  void *reserved2;
  void *reserved3;
} QuicerStreamCTX;

typedef struct QuicerStreamSendCTX
{
  QuicerStreamCTX *s_ctx;
  ErlNifEnv *env;
  ErlNifPid caller;
  BOOLEAN is_sync;
  QUIC_BUFFER Buffer;
  ErlNifBinary bin;
} QuicerStreamSendCTX;

typedef struct QuicerStreamSendCTX QuicerDgramSendCTX;

QuicerRegistrationCTX *init_r_ctx(QuicerRegistrationCTX *r_ctx);
void deinit_r_ctx(QuicerRegistrationCTX *r_ctx);

QuicerListenerCTX *init_l_ctx();
void deinit_l_ctx(QuicerListenerCTX *l_ctx);
void destroy_l_ctx(QuicerListenerCTX *l_ctx);

QuicerConnCTX *init_c_ctx();
void deinit_c_ctx(QuicerConnCTX *c_ctx);
void destroy_c_ctx(QuicerConnCTX *c_ctx);

QuicerConfigCTX *init_config_ctx();
void deinit_config_ctx(QuicerConfigCTX *config_ctx);
void destroy_config_ctx(QuicerConfigCTX *config_ctx);

QuicerStreamCTX *init_s_ctx();
void deinit_s_ctx(QuicerStreamCTX *s_ctx);
void destroy_s_ctx(QuicerStreamCTX *s_ctx);

QuicerStreamSendCTX *init_send_ctx();
void destroy_send_ctx(QuicerStreamSendCTX *send_ctx);

QuicerDgramSendCTX *init_dgram_send_ctx();
void destroy_dgram_send_ctx(QuicerDgramSendCTX *dgram_send_ctx);

void put_stream_handle(QuicerStreamCTX *s_ctx);
BOOLEAN get_stream_handle(QuicerStreamCTX *s_ctx);

void put_conn_handle(QuicerConnCTX *c_ctx);
BOOLEAN get_conn_handle(QuicerConnCTX *c_ctx);

void put_listener_handle(QuicerListenerCTX *l_ctx);
BOOLEAN get_listener_handle(QuicerListenerCTX *l_ctx);

void put_reg_handle(QuicerRegistrationCTX *r_ctx);
BOOLEAN get_reg_handle(QuicerRegistrationCTX *r_ctx);

void put_config_handle(QuicerConfigCTX *config_ctx);
BOOLEAN get_config_handle(QuicerConfigCTX *config_ctx);

void cache_stream_id(QuicerStreamCTX *s_ctx);

void cleanup_owner_signals(QuicerStreamCTX *s_ctx);

ERL_NIF_TERM
copy_stream_handle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif // __QUICER_CTX_H_
