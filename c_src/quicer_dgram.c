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

#include "quicer_dgram.h"

static ERL_NIF_TERM atom_dgram_send_state(uint16_t state);

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

  ebin = enif_make_copy(dgram_send_ctx->env, ebin);
  if (!(enif_inspect_iolist_as_binary(dgram_send_ctx->env, ebin, bin)
        || enif_inspect_binary(dgram_send_ctx->env, ebin, bin))
      || bin->size > UINT32_MAX)
    {
      destroy_dgram_send_ctx(dgram_send_ctx);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(c_ctx->lock);

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
      return ERROR_TUPLE_3(ATOM_DGRAM_SEND_ERROR, ATOM_STATUS(Status));
    }
  else
    {
      enif_mutex_unlock(c_ctx->lock);
      return SUCCESS(ETERM_UINT_64(bin->size));
    }
}

void
handle_dgram_state_changed_event(QuicerConnCTX *c_ctx,
                                 QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED == Event->Type);
  ErlNifEnv *env = c_ctx->env;
  uint16_t max_len = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;

  ERL_NIF_TERM ConnHandle = enif_make_resource(c_ctx->env, c_ctx);
  ERL_NIF_TERM props_name[] = { ATOM_DGRAM_MAX_LEN, ATOM_DGRAM_SEND_ENABLED };
  ERL_NIF_TERM props_value[]
      = { enif_make_uint(env, max_len),
          ATOM_BOOLEAN(Event->DATAGRAM_STATE_CHANGED.SendEnabled) };

  ERL_NIF_TERM report = make_event_with_props(c_ctx->env,
                                              ATOM_DGRAM_STATE_CHANGED,
                                              ConnHandle,
                                              props_name,
                                              props_value,
                                              2);

  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
}

void
handle_dgram_send_state_event(QuicerConnCTX *c_ctx,
                              QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED == Event->Type);
  // result of previous unreliable datagram send
  QUIC_DATAGRAM_SEND_STATE state = Event->DATAGRAM_SEND_STATE_CHANGED.State;
  QuicerDgramSendCTX *dgram_send_ctx
      = (QuicerDgramSendCTX *)(Event->DATAGRAM_SEND_STATE_CHANGED
                                   .ClientContext);

  ERL_NIF_TERM ConnHandle = enif_make_resource(c_ctx->env, c_ctx);
  ERL_NIF_TERM props_name[] = { ATOM_STATE };
  ERL_NIF_TERM props_value[] = { atom_dgram_send_state(state) };
  ERL_NIF_TERM report = make_event_with_props(c_ctx->env,
                                              ATOM_DGRAM_SEND_STATE,
                                              ConnHandle,
                                              props_name,
                                              props_value,
                                              1);
  enif_send(NULL, &dgram_send_ctx->caller, NULL, report);

  if (QUIC_DATAGRAM_SEND_LOST_DISCARDED == state
      || QUIC_DATAGRAM_SEND_ACKNOWLEDGED == state
      || QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS == state
      || QUIC_DATAGRAM_SEND_CANCELED == state)
    {
      // Destroy only when in final state
      destroy_dgram_send_ctx(dgram_send_ctx);
    }
}

ERL_NIF_TERM
atom_dgram_send_state(uint16_t state)
{
  ERL_NIF_TERM ret = ATOM_UNDEFINED;
  switch (state)
    {
    case QUIC_DATAGRAM_SEND_UNKNOWN:
      ret = ATOM_QUIC_DATAGRAM_SEND_UNKNOWN;
      break;
    case QUIC_DATAGRAM_SEND_SENT:
      ret = ATOM_QUIC_DATAGRAM_SEND_SENT;
      break;
    case QUIC_DATAGRAM_SEND_LOST_SUSPECT:
      ret = ATOM_QUIC_DATAGRAM_SEND_LOST_SUSPECT;
      break;
    case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
      ret = ATOM_QUIC_DATAGRAM_SEND_LOST_DISCARDED;
      break;
    case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
      ret = ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED;
      break;
    case QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
      ret = ATOM_QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS;
      break;
    case QUIC_DATAGRAM_SEND_CANCELED:
      ret = ATOM_QUIC_DATAGRAM_SEND_CANCELED;
      break;
    default:
      ret = ATOM_UNDEFINED;
      break;
    }
  return ret;
}
