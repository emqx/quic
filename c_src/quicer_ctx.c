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

#include "quicer_ctx.h"

// alloc/dealloc ctx should be done in the callbacks.
extern QuicerRegistrationCTX G_r_ctx;

QuicerRegistrationCTX *
init_r_ctx(QuicerRegistrationCTX *r_ctx)
{
  if (!r_ctx)
    {
      r_ctx = enif_alloc_resource(ctx_reg_t, sizeof(QuicerRegistrationCTX));
      CxPlatZeroMemory(r_ctx, sizeof(QuicerRegistrationCTX));
      // Only for none global registration
      CxPlatRefInitialize(&r_ctx->ref_count);
    }
  else
    {
      // G_r_ctx
      CXPLAT_FRE_ASSERT(r_ctx == &G_r_ctx);
      CXPLAT_FRE_ASSERT(r_ctx->ref_count == 0);
    }
  if (!r_ctx)
    {
      return NULL;
    }
  r_ctx->env = enif_alloc_env();
  r_ctx->Registration = NULL;
  r_ctx->is_closed = TRUE;
  r_ctx->lock = enif_mutex_create("quicer:r_ctx");
  CxPlatListInitializeHead(&r_ctx->Listeners);
  CxPlatListInitializeHead(&r_ctx->Connections);
  return r_ctx;
}

void
deinit_r_ctx(QuicerRegistrationCTX *r_ctx)
{
  r_ctx->is_closed = TRUE;
  enif_free_env(r_ctx->env);
  enif_mutex_destroy(r_ctx->lock);
}

QuicerListenerCTX *
init_l_ctx()
{
  QuicerListenerCTX *l_ctx
      = enif_alloc_resource(ctx_listener_t, sizeof(QuicerListenerCTX));
  if (!l_ctx)
    {
      return NULL;
    }
  CxPlatZeroMemory(l_ctx, sizeof(QuicerListenerCTX));
  l_ctx->env = enif_alloc_env();
  l_ctx->config_ctx = NULL;
  l_ctx->acceptor_queue = AcceptorQueueNew();
  l_ctx->lock = enif_mutex_create("quicer:l_ctx");
#if defined(QUICER_USE_TRUSTED_STORE)
  l_ctx->trusted_store = NULL;
#endif
  l_ctx->is_closed = TRUE;
  l_ctx->allow_insecure = FALSE;
  CxPlatListInitializeHead(&l_ctx->RegistrationLink);
  CxPlatRefInitialize(&l_ctx->ref_count);
  return l_ctx;
}

void
deinit_l_ctx(QuicerListenerCTX *l_ctx)
{
#if defined(QUICER_USE_TRUSTED_STORE)
  if (l_ctx->trusted_store)
    {
      X509_STORE_free(l_ctx->trusted_store);
    }
#endif // QUICER_USE_TRUSTED_STORE

  AcceptorQueueDestroy(l_ctx->acceptor_queue);
  enif_mutex_destroy(l_ctx->lock);
  enif_free_env(l_ctx->env);
}

void
destroy_l_ctx(QuicerListenerCTX *l_ctx)
{

  // @note, Destroy config asap as it holds rundown
  // ref count in registration
  if (l_ctx->is_monitored)
    {
      enif_demonitor_process(l_ctx->env, l_ctx, &l_ctx->owner_mon);
      l_ctx->is_monitored = FALSE;
    }
  enif_release_resource(l_ctx);
}

QuicerConnCTX *
init_c_ctx()
{
  QuicerConnCTX *c_ctx
      = enif_alloc_resource(ctx_connection_t, sizeof(QuicerConnCTX));
  if (!c_ctx)
    {
      return NULL;
    }
  CxPlatZeroMemory(c_ctx, sizeof(QuicerConnCTX));
  c_ctx->magic = 0xcfcfcfcf;
  c_ctx->env = enif_alloc_env();
  c_ctx->acceptor_queue = AcceptorQueueNew();
  c_ctx->Connection = NULL;
  c_ctx->lock = enif_mutex_create("quicer:c_ctx");
#if defined(QUICER_USE_TRUSTED_STORE)
  c_ctx->trusted = NULL;
#endif // QUICER_USE_TRUSTED_STORE
  c_ctx->TlsSecrets = NULL;
  c_ctx->ResumptionTicket = NULL;
  c_ctx->event_mask = 0;
  c_ctx->ssl_keylogfile = NULL;
  c_ctx->is_closed = TRUE; // init
  c_ctx->config_ctx = NULL;
  c_ctx->peer_cert = NULL;
  CxPlatListInitializeHead(&c_ctx->RegistrationLink);
  CxPlatRefInitialize(&c_ctx->ref_count);
  return c_ctx;
}

void
deinit_c_ctx(QuicerConnCTX *c_ctx)
{
  enif_free_env(c_ctx->env);
#if defined(QUICER_USE_TRUSTED_STORE)
  if (c_ctx->trusted != NULL)
    {
      X509_STORE_free(c_ctx->trusted);
      c_ctx->trusted = NULL;
    }
#endif // QUICER_USE_TRUSTED_STORE
  // @note, for the conn failed to get opened/started
  if (c_ctx->config_ctx)
    {
      put_config_handle(c_ctx->config_ctx);
    }
  AcceptorQueueDestroy(c_ctx->acceptor_queue);

  if (c_ctx->r_ctx)
    {
      PUT_UNLINK_REGISTRATION(c_ctx, c_ctx->r_ctx);
    }

  if (c_ctx->peer_cert)
    {
      X509_free(c_ctx->peer_cert);
    }
  enif_mutex_destroy(c_ctx->lock);
}

void
destroy_c_ctx(QuicerConnCTX *c_ctx)
{
// Since enif_release_resource is async call,
// we should demon the owner now!
#if defined(QUICER_USE_TRUSTED_STORE)
  if (c_ctx->trusted != NULL)
    {
      X509_STORE_free(c_ctx->trusted);
      c_ctx->trusted = NULL;
    }
#endif // QUICER_USE_TRUSTED_STORE

  if (c_ctx->is_monitored)
    {
      enif_demonitor_process(c_ctx->env, c_ctx, &c_ctx->owner_mon);
      c_ctx->is_monitored = FALSE;
    }

  // maybe we should move it to put_conn_handle
  enif_release_resource(c_ctx);
}

QuicerConfigCTX *
init_config_ctx()
{
  QuicerConfigCTX *config_ctx
      = enif_alloc_resource(ctx_config_t, sizeof(QuicerConfigCTX));
  if (!config_ctx)
    {
      return NULL;
    }
  CxPlatZeroMemory(config_ctx, sizeof(QuicerConfigCTX));
  config_ctx->env = enif_alloc_env();
  config_ctx->Configuration = NULL;
  CxPlatRefInitialize(&config_ctx->ref_count);
  return config_ctx;
}

void
deinit_config_ctx(QuicerConfigCTX *config_ctx)
{
  enif_free_env(config_ctx->env);
}

void
destroy_config_ctx(QuicerConfigCTX *config_ctx)
{
  if (config_ctx)
    {
      enif_release_resource(config_ctx);
    }
}

QuicerStreamCTX *
init_s_ctx()
{
  QuicerStreamCTX *s_ctx
      = enif_alloc_resource(ctx_stream_t, sizeof(QuicerStreamCTX));
  if (!s_ctx)
    {
      return NULL;
    }
  CxPlatZeroMemory(s_ctx, sizeof(QuicerStreamCTX));
  s_ctx->magic = 0xefefefef; // 4025479151
  s_ctx->StreamID = UNSET_STREAMID;
  s_ctx->env = enif_alloc_env();
  s_ctx->imm_env = enif_alloc_env();
  s_ctx->lock = enif_mutex_create("quicer:s_ctx");
  s_ctx->is_wait_for_data = FALSE;
  s_ctx->Buffers[0].Buffer = NULL;
  s_ctx->Buffers[0].Length = 0;
  s_ctx->Buffers[1].Buffer = NULL;
  s_ctx->Buffers[1].Length = 0;
  s_ctx->TotalBufferLength = 0;
  s_ctx->is_recv_pending = FALSE;
  s_ctx->is_closed = TRUE; // init
  s_ctx->event_mask = 0;
  s_ctx->sig_queue = NULL;
  return s_ctx;
}

void
deinit_s_ctx(QuicerStreamCTX *s_ctx)
{
  cleanup_owner_signals(s_ctx);
  enif_mutex_destroy(s_ctx->lock);
  enif_free_env(s_ctx->env);
}

void
destroy_s_ctx(QuicerStreamCTX *s_ctx)
{
  enif_free_env(s_ctx->imm_env);
  enif_release_resource(s_ctx);
}

QuicerStreamSendCTX *
init_send_ctx()
{
  QuicerStreamSendCTX *send_ctx
      = CXPLAT_ALLOC_NONPAGED(sizeof(QuicerStreamSendCTX), QUICER_SEND_CTX);

  if (send_ctx)
    {
      CxPlatZeroMemory(send_ctx, sizeof(QuicerStreamSendCTX));
      send_ctx->env = enif_alloc_env();
    }
  return send_ctx;
}

void
destroy_send_ctx(QuicerStreamSendCTX *send_ctx)
{
  enif_free_env(send_ctx->env);
  CXPLAT_FREE(send_ctx, QUICER_SEND_CTX);
}

QuicerDgramSendCTX *
init_dgram_send_ctx()
{
  QuicerDgramSendCTX *dgram_send_ctx = CXPLAT_ALLOC_NONPAGED(
      sizeof(QuicerDgramSendCTX), QUICER_DGRAM_SEND_CTX);

  if (dgram_send_ctx)
    {
      CxPlatZeroMemory(dgram_send_ctx, sizeof(QuicerDgramSendCTX));
      dgram_send_ctx->env = enif_alloc_env();
    }
  return dgram_send_ctx;
}
void
destroy_dgram_send_ctx(QuicerDgramSendCTX *dgram_send_ctx)
{
  enif_free_env(dgram_send_ctx->env);
  CXPLAT_FREE(dgram_send_ctx, QUICER_DGRAM_SEND_CTX);
}

inline void
put_stream_handle(QuicerStreamCTX *s_ctx)
{
  if (CxPlatRefDecrement(&s_ctx->ref_count) && s_ctx->Stream)
    {
      HQUIC Stream = s_ctx->Stream;
      Stream = s_ctx->Stream;
      s_ctx->Stream = NULL;
      s_ctx->is_closed = TRUE;
      MsQuic->SetCallbackHandler(Stream, NULL, NULL);
      MsQuic->StreamClose(Stream);
      assert(s_ctx->c_ctx != NULL);
      put_conn_handle(s_ctx->c_ctx);
    }
}

inline BOOLEAN
get_stream_handle(QuicerStreamCTX *s_ctx)
{
  return CxPlatRefIncrementNonZero(&s_ctx->ref_count, 1);
}

inline void
put_conn_handle(QuicerConnCTX *c_ctx)
{
  if (CxPlatRefDecrement(&c_ctx->ref_count))
    {
      HQUIC Connection = c_ctx->Connection;
      QuicerRegistrationCTX *r_ctx = c_ctx->r_ctx;
      QuicerConfigCTX *config_ctx = c_ctx->config_ctx;
      CXPLAT_DBG_ASSERT(c_ctx->is_closed);
      c_ctx->Connection = NULL;
      c_ctx->config_ctx = NULL;
      c_ctx->is_closed = TRUE;
      c_ctx->r_ctx = NULL;

      // Close connection handle
      if (Connection)
        {
          MsQuic->SetCallbackHandler(Connection, NULL, NULL);
          MsQuic->ConnectionClose(Connection);
        }

      // Deref config_ctx
      if (config_ctx)
        {
          put_config_handle(config_ctx);
        }

      // Unlink from registration
      // @NOTE: maybe not yet linked
      if (r_ctx)
        {
          PUT_UNLINK_REGISTRATION(c_ctx, r_ctx);
        }
    }
}

inline BOOLEAN
get_conn_handle(QuicerConnCTX *c_ctx)
{
  return CxPlatRefIncrementNonZero(&c_ctx->ref_count, 1);
}

inline void
put_listener_handle(QuicerListenerCTX *l_ctx)
{
  if (CxPlatRefDecrement(&l_ctx->ref_count))
    {
      QuicerRegistrationCTX *r_ctx = l_ctx->r_ctx;
      HQUIC Listener = l_ctx->Listener;
      l_ctx->Listener = NULL;
      CXPLAT_DBG_ASSERT(l_ctx->is_closed);
      l_ctx->is_closed = TRUE;
      l_ctx->r_ctx = NULL;

      // Close listener handle
      MsQuic->ListenerClose(Listener);

      // Deref config_ctx as it has shared ownership.
      put_config_handle(l_ctx->config_ctx);
      l_ctx->config_ctx = NULL;

      // Deref Registration Handle
      CXPLAT_DBG_ASSERT(r_ctx->ref_count > 0);

      PUT_UNLINK_REGISTRATION(l_ctx, r_ctx);

      // destroy l_ctx
      destroy_l_ctx(l_ctx);
    }
}

inline BOOLEAN
get_listener_handle(QuicerListenerCTX *l_ctx)
{
  return CxPlatRefIncrementNonZero(&l_ctx->ref_count, 1);
}

inline void
put_reg_handle(QuicerRegistrationCTX *r_ctx)
{
  if (CxPlatRefDecrement(&r_ctx->ref_count))
    {
      HQUIC Registration = r_ctx->Registration;
      CXPLAT_DBG_ASSERT(r_ctx->is_closed);
      r_ctx->is_closed = TRUE;
      r_ctx->Registration = NULL;
      MsQuic->RegistrationShutdown(
          Registration, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      MsQuic->RegistrationClose(Registration);
      if (r_ctx == &G_r_ctx)
        {
          deinit_r_ctx(r_ctx);
        }
      else
        {
          enif_release_resource(r_ctx);
        }
    }
}

inline BOOLEAN
get_reg_handle(QuicerRegistrationCTX *r_ctx)
{
  BOOLEAN res = CxPlatRefIncrementNonZero(&r_ctx->ref_count, 1);
  return res;
}

inline void
put_config_handle(QuicerConfigCTX *config_ctx)
{
  if (CxPlatRefDecrement(&config_ctx->ref_count))
    {
      MsQuic->ConfigurationClose(config_ctx->Configuration);
      config_ctx->Configuration = NULL;
      enif_release_resource(config_ctx);
    }
}

inline BOOLEAN
get_config_handle(QuicerConfigCTX *config_ctx)
{
  return CxPlatRefIncrementNonZero(&config_ctx->ref_count, 1);
}

void
cache_stream_id(QuicerStreamCTX *s_ctx)
{
  uint32_t bufferlen = sizeof(s_ctx->StreamID);
  if (QUIC_FAILED(MsQuic->GetParam(
          s_ctx->Stream, QUIC_PARAM_STREAM_ID, &bufferlen, &s_ctx->StreamID)))
    {
      s_ctx->StreamID = UNSET_STREAMID;
    }
}

void
cleanup_owner_signals(QuicerStreamCTX *s_ctx)
{
  OWNER_SIGNAL *sig;

  if (!s_ctx->sig_queue)
    {
      return;
    }
  while ((sig = OwnerSignalDequeue(s_ctx->sig_queue)))
    {
      CxPlatFree(sig, QUICER_OWNER_SIGNAL);
    }

  OwnerSignalQueueDestroy(s_ctx->sig_queue);
  s_ctx->sig_queue = NULL;
}

ERL_NIF_TERM
copy_stream_handle(ErlNifEnv *env,
                   __unused_parm__ int argc,
                   const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *ctx = NULL;
  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&ctx))
    {
      return enif_make_badarg(env);
    }
  assert(ctx != NULL);
  enif_make_copy(ctx->env, ctx->eHandle);
  return ATOM_OK;
}
