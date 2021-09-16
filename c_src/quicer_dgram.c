#include "quicer_dgram.h"

ERL_NIF_TERM
send_dgram(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  ERL_NIF_TERM econn = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  ERL_NIF_TERM eFlags = argv[2];
  uint32_t sendflags;

  if (3 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, econn, ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerDgramSendCTX *dgram_send_ctx = init_dgram_send_ctx();
  if (!dgram_send_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  ebin = enif_make_copy(dgram_send_ctx->env, ebin);

  ErlNifBinary *bin = &dgram_send_ctx->bin;

  if (enif_get_uint(env, eFlags, &sendflags))
    {
      enif_self(env, &dgram_send_ctx->caller);

      if ((sendflags & 1UL) > 0)
        {
          dgram_send_ctx->is_sync = TRUE;
        }
      else
        {
          dgram_send_ctx->is_sync = FALSE;
        }
    }
  else
    {
      destroy_dgram_send_ctx(dgram_send_ctx);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_inspect_binary(env, ebin, bin) || bin->size > UINT32_MAX)
    {
      destroy_dgram_send_ctx(dgram_send_ctx);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(c_ctx->lock);

  if (c_ctx->is_closed)
    {
      destroy_dgram_send_ctx(dgram_send_ctx);
      enif_mutex_unlock(c_ctx->lock);
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  HQUIC Connection = c_ctx->Connection;

  //
  // Allocates and builds the buffer to send in the datagram.
  //

  assert(bin->data != NULL);
  dgram_send_ctx->Buffer.Buffer = (uint8_t *)bin->data;
  dgram_send_ctx->Buffer.Length = (uint32_t)bin->size;

  QUIC_STATUS Status;
  if (QUIC_FAILED(Status = MsQuic->DatagramSend(Connection,
                                                &dgram_send_ctx->Buffer,
                                                1,
                                                QUIC_SEND_FLAG_NONE,
                                                dgram_send_ctx)))
    {
      destroy_dgram_send_ctx(dgram_send_ctx);
      enif_mutex_unlock(c_ctx->lock);
      return ERROR_TUPLE_3(ATOM_DGRAM_SEND_ERROR, atom_status(Status));
    }
  else
    {
      enif_mutex_unlock(c_ctx->lock);
      return SUCCESS(ETERM_UINT_64(bin->size));
    }
}
