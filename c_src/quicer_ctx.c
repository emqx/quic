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

#include "quicer_ctx.h"

// alloc/dealloc ctx should be done in the callbacks.

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
  l_ctx->acceptor_queue = AcceptorQueueNew();
  l_ctx->lock = enif_mutex_create("quicer:l_ctx");
  l_ctx->is_closed = FALSE;
  l_ctx->allow_insecure = FALSE;
  return l_ctx;
}

void
destroy_l_ctx(QuicerListenerCTX *l_ctx)
{
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
  c_ctx->env = enif_alloc_env();
  c_ctx->acceptor_queue = AcceptorQueueNew();
  c_ctx->Connection = NULL;
  c_ctx->lock = enif_mutex_create("quicer:c_ctx");
  c_ctx->TlsSecrets = NULL;
  c_ctx->ResumptionTicket = NULL;
  c_ctx->ssl_keylogfile = NULL;
  c_ctx->l_ctx = NULL;
  return c_ctx;
}

void
destroy_c_ctx(QuicerConnCTX *c_ctx)
{
  // Since enif_release_resource is async call,
  // we should demon the owner now!
  enif_demonitor_process(c_ctx->env, c_ctx, &c_ctx->owner_mon);
  enif_release_resource(c_ctx);
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

  s_ctx->env = enif_alloc_env();
  s_ctx->lock = enif_mutex_create("quicer:s_ctx");
  s_ctx->is_wait_for_data = FALSE;
  s_ctx->Buffers[0].Buffer = NULL;
  s_ctx->Buffers[0].Length = 0;
  s_ctx->Buffers[1].Buffer = NULL;
  s_ctx->Buffers[1].Length = 0;
  s_ctx->TotalBufferLength = 0;
  s_ctx->is_buff_ready = FALSE;
  return s_ctx;
}

void
destroy_s_ctx(QuicerStreamCTX *s_ctx)
{
  // Since enif_release_resource is async call,
  // we should demon the owner now!
  enif_demonitor_process(s_ctx->env, s_ctx, &s_ctx->owner_mon);
  enif_release_resource(s_ctx->c_ctx);
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
