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
      = QUIC_ALLOC_NONPAGED(sizeof(ErlNifMonitor), QUICER_OWNER_MON);
  c_ctx->lock = enif_mutex_create("quicer:c_ctx");
  return c_ctx;
}

void
destroy_c_ctx(QuicerConnCTX *c_ctx)
{
  AcceptorQueueDestroy(c_ctx->acceptor_queue);
  enif_free_env(c_ctx->env);
  enif_mutex_destroy(c_ctx->lock);
  if (0 != enif_demonitor_process(c_ctx->env, c_ctx, c_ctx->owner_mon))
    {
      //@todo handle ret valus, for
      // - never created for this resource
      // - already cancelled
      // - already triggered
      // - just about to be triggered by a concurrent thread
    }
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
  return s_ctx;
}

void
destroy_s_ctx(QuicerStreamCTX *s_ctx)
{
  enif_free_env(s_ctx->env);
  enif_mutex_destroy(s_ctx->lock);
  enif_release_resource(s_ctx);
}
