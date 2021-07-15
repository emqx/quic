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
  l_ctx->env = enif_alloc_env();
  l_ctx->acceptor_queue = AcceptorQueueNew();
  l_ctx->lock = enif_mutex_create("quicer:l_ctx");
  l_ctx->ssl_key_log_file = NULL;
  return l_ctx;
}

void
destroy_l_ctx(QuicerListenerCTX *l_ctx)
{
  AcceptorQueueDestroy(l_ctx->acceptor_queue);
  enif_free_env(l_ctx->env);
  enif_mutex_destroy(l_ctx->lock);
  enif_release_resource(l_ctx);
}

QuicerConnCTX *
init_c_ctx()
{
  //@todo return NULL if error.
  QuicerConnCTX *c_ctx
      = enif_alloc_resource(ctx_connection_t, sizeof(QuicerConnCTX));
  c_ctx->env = enif_alloc_env();
  c_ctx->acceptor_queue = AcceptorQueueNew();
  c_ctx->Connection = NULL;
  //@todo handle if NULL
  c_ctx->owner_mon
      = CXPLAT_ALLOC_NONPAGED(sizeof(ErlNifMonitor), QUICER_OWNER_MON);
  c_ctx->lock = enif_mutex_create("quicer:c_ctx");
  c_ctx->is_closed = FALSE;
  c_ctx->TlsSecrets = NULL;
  return c_ctx;
}

void
destroy_c_ctx(QuicerConnCTX *c_ctx)
{
  enif_release_resource(c_ctx);
}

QuicerStreamCTX *
init_s_ctx()
{
  QuicerStreamCTX *s_ctx
      = enif_alloc_resource(ctx_stream_t, sizeof(QuicerStreamCTX));
  // @todo would be better to useacceptor's env.
  s_ctx->env = enif_alloc_env();
  s_ctx->lock = enif_mutex_create("quicer:s_ctx");
  s_ctx->is_closed = FALSE;
  s_ctx->is_wait_for_data = FALSE;
  s_ctx->Buffer = NULL;
  s_ctx->BufferLen = 0;
  s_ctx->is_buff_ready = FALSE;
  return s_ctx;
}

void
destroy_s_ctx(QuicerStreamCTX *s_ctx)
{
  // note, see resource_stream_dealloc_callback
  enif_release_resource(s_ctx);
}
