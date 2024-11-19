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

#include "quicer_stream.h"
#include "quicer_queue.h"

#include "quicer_tp.h"

static uint64_t recvbuffer_flush(QuicerStreamCTX *stream_ctx,
                                 ErlNifBinary *bin,
                                 uint64_t req_len);

static QUIC_STATUS
handle_stream_event_start_complete(QuicerStreamCTX *s_ctx,
                                   QUIC_STREAM_EVENT *Event);

static QUIC_STATUS handle_stream_event_recv(HQUIC Stream,
                                            QuicerStreamCTX *s_ctx,
                                            QUIC_STREAM_EVENT *Event);

static QUIC_STATUS
handle_stream_event_peer_send_shutdown(QuicerStreamCTX *s_ctx,
                                       QUIC_STREAM_EVENT *Event);

static QUIC_STATUS
handle_stream_event_peer_send_aborted(QuicerStreamCTX *s_ctx,
                                      QUIC_STREAM_EVENT *Event);

static QUIC_STATUS
handle_stream_event_peer_receive_aborted(QuicerStreamCTX *s_ctx,
                                         QUIC_STREAM_EVENT *Event);

static QUIC_STATUS
handle_stream_event_shutdown_complete(QuicerStreamCTX *s_ctx,
                                      QUIC_STREAM_EVENT *Event);

static QUIC_STATUS handle_stream_event_peer_accepted(QuicerStreamCTX *s_ctx,
                                                     QUIC_STREAM_EVENT *Event);

static QUIC_STATUS handle_stream_event_send_complete(QuicerStreamCTX *s_ctx,
                                                     QUIC_STREAM_EVENT *Event);

static QUIC_STATUS
handle_stream_event_send_shutdown_complete(QuicerStreamCTX *s_ctx,
                                           QUIC_STREAM_EVENT *Event);

static void reset_stream_recv(QuicerStreamCTX *s_ctx);

static int
signal_or_buffer(QuicerStreamCTX *s_ctx, ErlNifPid *owner, ERL_NIF_TERM sig);

QUIC_STATUS
ServerStreamCallback(HQUIC Stream, void *Context, QUIC_STREAM_EVENT *Event)
{

  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)Context;
  ErlNifEnv *env = s_ctx->env;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  BOOLEAN is_destroy = FALSE;

  enif_mutex_lock(s_ctx->lock);

  TP_CB_3(event, (uintptr_t)Stream, Event->Type);
  switch (Event->Type)
    {

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      //
      status = handle_stream_event_send_complete(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      status = handle_stream_event_recv(Stream, s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      status = handle_stream_event_peer_send_shutdown(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_send_aborted(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_receive_aborted(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      // we don't use trylock since we are in callback context
      status = handle_stream_event_shutdown_complete(s_ctx, Event);
      is_destroy = TRUE;
      break;

    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      status = handle_stream_event_send_shutdown_complete(s_ctx, Event);
      // note, dont set is_destroy to TRUE,
      // let QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE fly in.
      break;
    default:
      break;
    }

  enif_clear_env(env);

  if (is_destroy)
    {
      flush_sig_buffer(NULL, s_ctx);
      s_ctx->is_closed = TRUE;
    }

  enif_mutex_unlock(s_ctx->lock);

  if (is_destroy)
    {
      // must be called after mutex unlock
      CALLBACK_DESTRUCT_REFCNT(put_stream_handle(s_ctx));
    }
  return status;
}

// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream,
                         _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ErlNifEnv *env;
  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)Context;
  enif_mutex_lock(s_ctx->lock);
  env = s_ctx->env;
  BOOLEAN is_destroy = FALSE;
  TP_CB_3(event, (uintptr_t)Stream, Event->Type);
  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_START_COMPLETE:
      status = handle_stream_event_start_complete(s_ctx, Event);
      break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      status = handle_stream_event_send_complete(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      status = handle_stream_event_recv(Stream, s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer gracefully shutdown its send direction of the stream.
      //
      status = handle_stream_event_peer_send_aborted(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_receive_aborted(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_send_shutdown(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      status = handle_stream_event_shutdown_complete(s_ctx, Event);
      // Then we destroy the ctx without holding lock.
      is_destroy = TRUE;
      break;
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_accepted(s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
      TP_CB_3(event_ideal_send_buffer_size,
              (uintptr_t)Stream,
              Event->IDEAL_SEND_BUFFER_SIZE.ByteCount);
      break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
      status = handle_stream_event_send_shutdown_complete(s_ctx, Event);
      // note, dont set is_destroy to TRUE,
      // let QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE fly in.
      break;
    default:
      break;
    }

  enif_clear_env(env);

  if (is_destroy)
    {
      s_ctx->is_closed = TRUE;
      flush_sig_buffer(NULL, s_ctx);
      MsQuic->SetCallbackHandler(Stream, NULL, NULL);
    }

  enif_mutex_unlock(s_ctx->lock);

  if (is_destroy)
    {
      // must be called after mutex unlock,
      CALLBACK_DESTRUCT_REFCNT(put_stream_handle(s_ctx));
    }
  return status;
}

ERL_NIF_TERM
async_start_stream2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  QuicerConnCTX *c_ctx = NULL;
  ERL_NIF_TERM res = ATOM_ERROR_INTERNAL_ERROR;
  ERL_NIF_TERM active_val;
  ERL_NIF_TERM estart_flag;
  unsigned int start_flag = QUIC_STREAM_START_FLAG_NONE; // default
  ERL_NIF_TERM eopen_flag;
  unsigned int open_flag = QUIC_STREAM_OPEN_FLAG_NONE; // default

  CXPLAT_FRE_ASSERT(2 == argc);

  ERL_NIF_TERM eoptions = argv[1];

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_ACTIVE, &active_val))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // optional open_flag,
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_OPEN_FLAG, &eopen_flag))
    {
      if (!enif_get_uint(env, eopen_flag, &open_flag))
        {
          // if set must be valid.
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  // optional start_flag,
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_START_FLAG, &estart_flag))
    {
      if (!enif_get_uint(env, estart_flag, &start_flag))
        {
          // if set must be valid.
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
      // @TODO set event mask for some flags
    }

  if (!get_conn_handle(c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  QuicerStreamCTX *s_ctx = init_s_ctx();

  if (!s_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  // This is optional
  get_uint32_from_map(env, eoptions, ATOM_QUIC_EVENT_MASK, &s_ctx->event_mask);

  s_ctx->c_ctx = c_ctx;
  // Caller should be the owner of this stream.
  s_ctx->owner = AcceptorAlloc();

  if (!s_ctx->owner)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto ErrorExit;
    }

  if (!enif_self(env, &(s_ctx->owner->Pid)))
    {
      res = ERROR_TUPLE_2(ATOM_BAD_PID);
      goto ErrorExit;
    }

  if (!set_owner_recv_mode(s_ctx->owner, env, active_val))
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  Status = MsQuic->StreamOpen(c_ctx->Connection,
                              open_flag,
                              ClientStreamCallback,
                              s_ctx,
                              &(s_ctx->Stream));

  if (QUIC_FAILED(Status))
    {
      res = ERROR_TUPLE_3(ATOM_STREAM_OPEN_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }
  // Now we have Stream handle
  s_ctx->eHandle = enif_make_resource(s_ctx->imm_env, s_ctx);
  res = enif_make_copy(env, s_ctx->eHandle);

  //
  // Starts the stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  //
  //
  // We need to take a refcnt to avoid handle get closed as the StreamStart
  // may trigger callback in another thread.
  if (!LOCAL_REFCNT(get_stream_handle(s_ctx)))
    {
      res = ERROR_TUPLE_2(ATOM_CLOSED);
      goto ErrorExit;
    }
  HQUIC Stream = s_ctx->Stream;
  Status = MsQuic->StreamStart(Stream, start_flag);
  cache_stream_id(s_ctx);
  LOCAL_REFCNT(put_stream_handle(s_ctx));

  if (QUIC_FAILED(Status))
    {
      // revert the enif_make_resource...
      enif_release_resource(s_ctx);
      res = ERROR_TUPLE_3(ATOM_STREAM_START_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }

  int mon_res = enif_monitor_process(
      env, s_ctx, &s_ctx->owner->Pid, &s_ctx->owner_mon);
  CXPLAT_FRE_ASSERT(mon_res == 0);
  // NOTE: Set is_closed to FALSE (s_ctx->is_closed = FALSE;)
  // must be done in the worker callback (for
  // QUICER_STREAM_EVENT_MASK_START_COMPLETE) to avoid race cond.
  return SUCCESS(res);

ErrorExit:
  s_ctx->is_closed = TRUE;
  // destruct as no return to the NIF caller
  DESTRUCT_REFCNT(put_stream_handle(s_ctx));
  return res;
}

// accept streams on top of connection.
ERL_NIF_TERM
async_accept_stream2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  ERL_NIF_TERM active_val;
  CXPLAT_FRE_ASSERT(2 == argc);

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_map_value(
          env, argv[1], ATOM_QUIC_STREAM_OPTS_ACTIVE, &active_val))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  ACCEPTOR *acceptor = AcceptorAlloc();
  if (!acceptor)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
    }

  if (!enif_self(env, &(acceptor->Pid)))
    {
      CXPLAT_FREE(acceptor, QUICER_ACCEPTOR);
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  //@todo this is assertion
  if (!enif_is_process_alive(env, &(acceptor->Pid)))
    {
      CXPLAT_FREE(acceptor, QUICER_ACCEPTOR);
      return ERROR_TUPLE_2(ATOM_OWNER_DEAD);
    }

  if (!set_owner_recv_mode(acceptor, env, active_val))
    {
      CXPLAT_FREE(acceptor, QUICER_ACCEPTOR);
      return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
    }

  AcceptorEnqueue(c_ctx->acceptor_queue, acceptor);
  ERL_NIF_TERM connectionHandle = enif_make_resource(env, c_ctx);
  return SUCCESS(connectionHandle);
}

ERL_NIF_TERM
csend4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM res = ATOM_ERROR_INTERNAL_ERROR;
  QuicerConnCTX *c_ctx = NULL;
  ERL_NIF_TERM active_val;
  ERL_NIF_TERM eopen_flag;
  ERL_NIF_TERM estart_flag;
  unsigned int open_flag = QUIC_STREAM_OPEN_FLAG_NONE; // default
  uint32_t sendflags = 0;

  CXPLAT_FRE_ASSERT(4 == argc);
  ERL_NIF_TERM eHandle = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  ERL_NIF_TERM eoptions = argv[2];
  ERL_NIF_TERM eFlags = argv[3]; // Send flags

  // Check connection handle
  if (!enif_get_resource(env, eHandle, ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Check active mode, mandatory
  if (!enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_ACTIVE, &active_val))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Check stream open flag
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_OPEN_FLAG, &eopen_flag))
    {
      if (!enif_get_uint(env, eopen_flag, &open_flag))
        {
          // if set, must be valid.
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  // Disallow stream start flag
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_STREAM_OPTS_START_FLAG, &estart_flag))
    {
      // We do not allow start flag here.
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!get_conn_handle(c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  // Allocate s_ctx
  QuicerStreamCTX *s_ctx = init_s_ctx();
  if (!s_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  s_ctx->c_ctx = c_ctx;

  QuicerStreamSendCTX *send_ctx = init_send_ctx();

  if (!send_ctx)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto ErrorExit;
    }

  // Caller should be the owner of this stream.
  s_ctx->owner = AcceptorAlloc();

  if (!s_ctx->owner)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto ErrorExit;
    }

  send_ctx->s_ctx = s_ctx;

  // unlikely to fail
  if (!enif_self(env, &(s_ctx->owner->Pid)))
    {
      res = ERROR_TUPLE_2(ATOM_BAD_PID);
      goto ErrorExit;
    }

  enif_self(env, &send_ctx->caller);

  // SYNC/ASYNC send
  if (enif_get_uint(env, eFlags, &sendflags))
    {
      if ((sendflags & QUICER_SEND_FLAGS_SYNC) > 0)
        {
          send_ctx->is_sync = TRUE;
          sendflags &= ~QUICER_SEND_FLAGS_SYNC;
        }
      else
        {
          send_ctx->is_sync = FALSE;
        }
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  // Optional event mask
  get_uint32_from_map(env, eoptions, ATOM_QUIC_EVENT_MASK, &s_ctx->event_mask);

  if (!set_owner_recv_mode(s_ctx->owner, env, active_val))
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  ErlNifBinary *bin = &send_ctx->bin;

  // Open stream
  if (QUIC_FAILED(Status = MsQuic->StreamOpen(c_ctx->Connection,
                                              open_flag,
                                              ClientStreamCallback,
                                              s_ctx,
                                              &(s_ctx->Stream))))
    {

      res = ERROR_TUPLE_3(ATOM_STREAM_OPEN_ERROR, ATOM_STATUS(Status));
      s_ctx->Stream = NULL;
      goto ErrorExit;
    }
  // Now we have Stream handle
  s_ctx->eHandle = enif_make_resource(s_ctx->imm_env, s_ctx);

  ebin = enif_make_copy(send_ctx->env, ebin);

  //
  // Allocates and builds the buffer to send over the stream.
  //
  if (!(enif_inspect_binary(send_ctx->env, ebin, bin)
        || enif_inspect_iolist_as_binary(send_ctx->env, ebin, bin))
      || bin->size > UINT32_MAX)
    {

      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  assert(bin->data != NULL);
  send_ctx->Buffer.Buffer = (uint8_t *)bin->data;
  send_ctx->Buffer.Length = (uint32_t)bin->size;

  enif_mutex_lock(s_ctx->lock);
  // note, SendBuffer as sendcontext, free the buffer while message is sent
  // confirmed.
  if (QUIC_FAILED(Status = MsQuic->StreamSend(s_ctx->Stream,
                                              &send_ctx->Buffer,
                                              1,
                                              // must set QUIC_SEND_FLAG_START
                                              sendflags | QUIC_SEND_FLAG_START,
                                              send_ctx)))
    {
      enif_mutex_unlock(s_ctx->lock);
      res = ERROR_TUPLE_3(ATOM_STREAM_SEND_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }
  else
    {
      // NOTE: Set is_closed to FALSE (s_ctx->is_closed = FALSE;)
      // must be done in the worker callback (for
      // QUICER_STREAM_EVENT_MASK_START_COMPLETE) to avoid race cond.
      res = SUCCESS(enif_make_copy(env, s_ctx->eHandle));
    }

  enif_mutex_unlock(s_ctx->lock);
  return res;

ErrorExit:
  destroy_send_ctx(send_ctx);
  s_ctx->is_closed = TRUE;
  DESTRUCT_REFCNT(put_stream_handle(s_ctx));
  return res;
}

ERL_NIF_TERM
send3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx = NULL;
  ERL_NIF_TERM estream = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  ERL_NIF_TERM eFlags = argv[2];
  ERL_NIF_TERM res = ATOM_OK;
  uint32_t sendflags = 0;

  CXPLAT_FRE_ASSERT(3 == argc);

  if (!enif_get_resource(env, estream, ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!LOCAL_REFCNT(get_stream_handle(s_ctx)))
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  QuicerStreamSendCTX *send_ctx = init_send_ctx();
  if (!send_ctx)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto Exit;
    }

  ErlNifBinary *bin = &send_ctx->bin;

  if (enif_get_uint(env, eFlags, &sendflags))
    {
      enif_self(env, &send_ctx->caller);

      if ((sendflags & QUICER_SEND_FLAGS_SYNC) > 0)
        {
          send_ctx->is_sync = TRUE;
          sendflags &= ~QUICER_SEND_FLAGS_SYNC;
        }
      else
        {
          send_ctx->is_sync = FALSE;
        }
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  ebin = enif_make_copy(send_ctx->env, ebin);
  if (!(enif_inspect_binary(send_ctx->env, ebin, bin)
        || enif_inspect_iolist_as_binary(send_ctx->env, ebin, bin))
      || bin->size > UINT32_MAX)
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto ErrorExit;
    }

  //
  // Allocates and builds the buffer to send over the stream.
  //
  send_ctx->s_ctx = s_ctx;
  assert(bin->data != NULL);
  send_ctx->Buffer.Buffer = (uint8_t *)bin->data;
  send_ctx->Buffer.Length = (uint32_t)bin->size;
  uint32_t bin_size = (uint32_t)bin->size;

  assert(s_ctx->Stream);

  QUIC_STATUS Status;
  // note, SendBuffer as sendcontext, free the buffer while message is sent
  // confirmed.
  if (QUIC_FAILED(
          Status = MsQuic->StreamSend(
              s_ctx->Stream, &send_ctx->Buffer, 1, sendflags, send_ctx)))
    {
      res = ERROR_TUPLE_3(ATOM_STREAM_SEND_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }

  else
    {
      res = SUCCESS(ETERM_UINT_64(bin_size));
      goto Exit;
    }
ErrorExit:
  destroy_send_ctx(send_ctx);
Exit:
  LOCAL_REFCNT(put_stream_handle(s_ctx));
  return res;
}

ERL_NIF_TERM
recv2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  CXPLAT_FRE_ASSERT(argc == 2);
  QuicerStreamCTX *s_ctx;
  ErlNifBinary bin;
  ERL_NIF_TERM estream = argv[0];
  ErlNifUInt64 size_req = 0;
  ERL_NIF_TERM res;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;

  if (!enif_get_resource(env, estream, ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_uint64(env, argv[1], &size_req))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  TP_NIF_3(start, (uintptr_t)s_ctx->Stream, size_req);
  enif_mutex_lock(s_ctx->lock);

  if (!s_ctx->Stream)
    {
      res = ERROR_TUPLE_2(ATOM_CLOSED);
      goto Exit;
    }

  if (ACCEPTOR_RECV_MODE_PASSIVE != s_ctx->owner->active)
    {
      res = ERROR_TUPLE_2(ATOM_EINVAL);
      goto Exit;
    }

  // We have checked that the Stream is not closed/closing
  // it is safe to use the s_ctx->Stream in following MsQuic API calls

  if (s_ctx->is_recv_pending && s_ctx->TotalBufferLength > 0)
    {
      //
      // Buffer is ready
      //
      uint64_t size_consumed = recvbuffer_flush(
          s_ctx,
          &bin,
          size_req > s_ctx->TotalBufferLength ? s_ctx->TotalBufferLength
                                              : size_req);
      TP_NIF_3(consume, (uintptr_t)s_ctx->Stream, size_consumed);
      reset_stream_recv(s_ctx);

      if (size_consumed > 0)
        {
          s_ctx->is_wait_for_data = FALSE;
        }

      // call only when is_recv_pending is TRUE
      MsQuic->StreamReceiveComplete(s_ctx->Stream, size_consumed);

      res = SUCCESS(enif_make_binary(env, &bin));
    }
  else
    { // want more data in buffer
      TP_NIF_3(more, (uintptr_t)s_ctx->Stream, size_req);
      s_ctx->is_wait_for_data = TRUE;

      // Finish the stream recv callback
      if (s_ctx->is_recv_pending)
        {
          MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
        }
      //
      // Ensure stream recv is enabled while it is in passive mode.
      // because we are waiting for more data
      //
      if (QUIC_FAILED(status
                      = MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE)))
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }
      else
        {
          // NIF caller will get {ok, not_ready}
          // this is an ack to its call
          res = SUCCESS(ATOM_ERROR_NOT_READY);
        }
    }

Exit:
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

ERL_NIF_TERM
shutdown_stream3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
  ERL_NIF_TERM ret = ATOM_OK;
  QuicerStreamCTX *s_ctx;
  uint32_t app_errcode = 0, flags = 0;

  CXPLAT_FRE_ASSERT(3 == argc);

  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // only check type, actual flag will be validated by msquic
  if (!enif_get_uint(env, argv[1], &flags))
    {
      ret = ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_uint(env, argv[2], &app_errcode))
    {
      ret = ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!LOCAL_REFCNT(get_stream_handle(s_ctx)))
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  if (QUIC_FAILED(Status
                  = MsQuic->StreamShutdown(s_ctx->Stream, flags, app_errcode)))
    {
      ret = ERROR_TUPLE_2(ATOM_STATUS(Status));
    }
  LOCAL_REFCNT(put_stream_handle(s_ctx));
  return ret;
}

static uint64_t
recvbuffer_flush(QuicerStreamCTX *s_ctx, ErlNifBinary *bin, uint64_t req_len)
{
  // note, make sure ownership of bin should be transferred, after call
  uint64_t size = 0;
  assert(req_len <= s_ctx->TotalBufferLength);

  if (req_len == 0)
    { // we need more data than buffer has
      size = s_ctx->TotalBufferLength;
    }
  else
    { // buffer size is larger than we want
      size = req_len;
    }

  enif_alloc_binary(size, bin);
  assert(size == bin->size);
  assert(size > 0);

  unsigned char *dest = bin->data;

  for (uint32_t i = 0; size > 0; ++i)
    {
      if (s_ctx->Buffers[i].Length <= size)
        { // copy whole buffer
          CxPlatCopyMemory(
              dest, s_ctx->Buffers[i].Buffer, s_ctx->Buffers[i].Length);
          dest += s_ctx->Buffers[i].Length;
          size -= s_ctx->Buffers[i].Length;
        }
      else
        { // copy part of the buffer, end of copy
          CxPlatCopyMemory(dest, s_ctx->Buffers[i].Buffer, size);
          size = 0;
        }
    }
  return bin->size;
}

QUIC_STATUS
handle_stream_event_recv(HQUIC Stream,
                         QuicerStreamCTX *s_ctx,
                         QUIC_STREAM_EVENT *Event)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ErlNifEnv *env = s_ctx->env;
  ErlNifBinary bin;

  assert(QUIC_STREAM_EVENT_RECEIVE == Event->Type);

  assert(Event->RECEIVE.BufferCount > 0
         || Event->RECEIVE.Flags == QUIC_RECEIVE_FLAG_FIN);

  s_ctx->Buffers[0].Buffer = Event->RECEIVE.Buffers[0].Buffer;
  s_ctx->Buffers[0].Length = Event->RECEIVE.Buffers[0].Length;
  s_ctx->Buffers[1].Buffer = Event->RECEIVE.Buffers[1].Buffer;
  s_ctx->Buffers[1].Length = Event->RECEIVE.Buffers[1].Length;
  s_ctx->BufferCount = Event->RECEIVE.BufferCount;
  s_ctx->TotalBufferLength = Event->RECEIVE.TotalBufferLength;

  if (Event->RECEIVE.Flags != 0)
    {
      TP_CB_3(event_recv_flag, (uintptr_t)Stream, Event->RECEIVE.Flags);
    }

  if (0 == Event->RECEIVE.TotalBufferLength)
    {
      return status;
    }

  if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active)
    { // passive receive
      /* important:
         for passive receive, it is not ok to call
         MsQuic->StreamReceiveSetEnabled to enable receiving
         because it can cause busy spinning:
         trigger event and handle event in a loop
      */
      TP_CB_3(handle_stream_event_recv, (uintptr_t)Stream, 0);
      s_ctx->is_recv_pending = TRUE;
      status = QUIC_STATUS_PENDING;

      if (s_ctx->is_wait_for_data)
        { // Owner is waiting for data
          // notify owner to trigger async recv
          //
          if (!enif_send(NULL,
                         &(s_ctx->owner->Pid),
                         NULL,
                         make_event(env,
                                    ATOM_QUIC_STATUS_CONTINUE,
                                    enif_make_copy(env, s_ctx->eHandle),
                                    ATOM_UNDEFINED)))
            {
              // App down, shutdown stream
              MsQuic->StreamShutdown(Stream,
                                     QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                     QUIC_STATUS_UNREACHABLE);
            }
        }
    }
  else
    { // active receive
      TP_CB_3(handle_stream_event_recv, (uintptr_t)Stream, 1);
      recvbuffer_flush(s_ctx, &bin, (uint64_t)0);
      BOOLEAN is_report_passive = FALSE;
      ERL_NIF_TERM eHandle = enif_make_copy(env, s_ctx->eHandle);
      ERL_NIF_TERM props_name[] = { ATOM_ABS_OFFSET, ATOM_LEN, ATOM_FLAGS };
      ERL_NIF_TERM props_value[]
          = { enif_make_uint64(env, Event->RECEIVE.AbsoluteOffset),
              enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
              enif_make_int(env, Event->RECEIVE.Flags) };
      ERL_NIF_TERM report_active
          = make_event_with_props(env,
                                  enif_make_binary(env, &bin),
                                  eHandle,
                                  props_name,
                                  props_value,
                                  3);

      assert(ACCEPTOR_RECV_MODE_PASSIVE != s_ctx->owner->active);
      if (ACCEPTOR_RECV_MODE_ONCE == s_ctx->owner->active)
        {
          s_ctx->owner->active_count = 0;
          s_ctx->owner->active = ACCEPTOR_RECV_MODE_PASSIVE;
        }
      else if (ACCEPTOR_RECV_MODE_MULTI == s_ctx->owner->active)
        {
          assert(s_ctx->owner->active_count > 0);

          s_ctx->owner->active_count--;

          TP_CB_3(is_report_passive,
                  (uintptr_t)s_ctx->Stream,
                  s_ctx->owner->active_count);

          if (s_ctx->owner->active_count == 0)
            {
              s_ctx->owner->active = ACCEPTOR_RECV_MODE_PASSIVE;

              is_report_passive = TRUE;

              // *async* disable the recv callback, so you might still get recv
              // callback after this call to put stream back to active mode,
              // you should call 1) MsQuic->StreamReceiveSetEnabled 2)
              // MsQuic->StreamReceiveComplete
              MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, FALSE);
            }
        }

      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report_active);

      if (is_report_passive)
        {
          ERL_NIF_TERM report_passive
              = make_event(env, ATOM_PASSIVE, eHandle, ATOM_UNDEFINED);
          enif_send(NULL, &(s_ctx->owner->Pid), NULL, report_passive);
        }
    }

  return status;
}

// @doc Only for *Local* initiated stream
static QUIC_STATUS
handle_stream_event_start_complete(QuicerStreamCTX *s_ctx,
                                   __unused_parm__ QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  TP_CB_3(peer_start_complete, (uintptr_t)s_ctx->Stream, 0);
  assert(env);
  assert(QUIC_STREAM_EVENT_START_COMPLETE == Event->Type);
  // Only for Local initiated stream
  if (s_ctx->event_mask & QUICER_STREAM_EVENT_MASK_START_COMPLETE)
    {
      ERL_NIF_TERM props_name[]
          = { ATOM_STATUS, ATOM_STREAM_ID, ATOM_IS_PEER_ACCEPTED };
      ERL_NIF_TERM props_value[]
          = { atom_status(env, Event->START_COMPLETE.Status),
              enif_make_uint64(env, Event->START_COMPLETE.ID),
              ATOM_BOOLEAN(Event->START_COMPLETE.PeerAccepted) };
      cache_stream_id(s_ctx);
      report = make_event_with_props(env,
                                     ATOM_START_COMPLETE,
                                     enif_make_copy(env, s_ctx->eHandle),
                                     props_name,
                                     props_value,
                                     3);
      signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
    }
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_peer_send_shutdown(
    QuicerStreamCTX *s_ctx, __unused_parm__ QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  TP_CB_3(peer_send_shutdown, (uintptr_t)s_ctx->Stream, 0);
  assert(env);
  assert(QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN == Event->Type);
  report = make_event(env,
                      ATOM_PEER_SEND_SHUTDOWN,
                      enif_make_copy(env, s_ctx->eHandle),
                      ATOM_UNDEFINED);

  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_peer_send_aborted(QuicerStreamCTX *s_ctx,
                                      QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_PEER_SEND_ABORTED == Event->Type);
  TP_CB_3(peer_send_aborted,
          (uintptr_t)s_ctx->Stream,
          Event->PEER_SEND_ABORTED.ErrorCode);
  assert(env);
  report
      = make_event(env,
                   ATOM_PEER_SEND_ABORTED,
                   enif_make_copy(env, s_ctx->eHandle),
                   enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_peer_receive_aborted(QuicerStreamCTX *s_ctx,
                                         QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED == Event->Type);
  TP_CB_3(peer_receive_aborted,
          (uintptr_t)s_ctx->Stream,
          Event->PEER_RECEIVE_ABORTED.ErrorCode);
  assert(env);
  report = make_event(
      env,
      ATOM_PEER_RECEIVE_ABORTED,
      enif_make_copy(env, s_ctx->eHandle),
      enif_make_uint64(env, Event->PEER_RECEIVE_ABORTED.ErrorCode));
  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_shutdown_complete(QuicerStreamCTX *s_ctx,
                                      QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE == Event->Type);
  TP_CB_3(shutdown_complete,
          (uintptr_t)s_ctx->Stream,
          Event->SHUTDOWN_COMPLETE.ConnectionShutdown);
  assert(env);

  ERL_NIF_TERM props_name[] = {
    ATOM_IS_CONN_SHUTDOWN,   ATOM_IS_APP_CLOSING, ATOM_IS_SHUTDOWN_BY_APP,
    ATOM_IS_CLOSED_REMOTELY, ATOM_ERROR,          ATOM_STATUS
  };
  ERL_NIF_TERM props_value[]
      = { ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.ConnectionShutdown),
          ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.AppCloseInProgress),
          ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.ConnectionShutdownByApp),
          ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.ConnectionClosedRemotely),
          enif_make_uint64(env, Event->SHUTDOWN_COMPLETE.ConnectionErrorCode),
          ATOM_STATUS(Event->SHUTDOWN_COMPLETE.ConnectionCloseStatus) };
  report = make_event_with_props(env,
                                 ATOM_STREAM_CLOSED,
                                 enif_make_copy(env, s_ctx->eHandle),
                                 props_name,
                                 props_value,
                                 6);
  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_peer_accepted(QuicerStreamCTX *s_ctx,
                                  __unused_parm__ QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_PEER_ACCEPTED == Event->Type);
  TP_CB_3(peer_accepted, (uintptr_t)s_ctx->Stream, 0);
  assert(env);
  report = make_event(env,
                      ATOM_PEER_ACCEPTED,
                      enif_make_copy(env, s_ctx->eHandle),
                      ATOM_UNDEFINED);
  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_send_complete(QuicerStreamCTX *s_ctx,
                                  QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_SEND_COMPLETE == Event->Type);
  QuicerStreamSendCTX *send_ctx
      = (QuicerStreamSendCTX *)(Event->SEND_COMPLETE.ClientContext);

  if (!send_ctx)
    {
      return QUIC_STATUS_INVALID_STATE;
    }

  if (send_ctx->is_sync)
    {
      report = make_event(env,
                          ATOM_SEND_COMPLETE,
                          enif_make_copy(env, s_ctx->eHandle),
                          ATOM_BOOLEAN(Event->SEND_COMPLETE.Canceled));

      // note, report to caller instead of stream owner
      enif_send(NULL, &send_ctx->caller, NULL, report);
    }

  destroy_send_ctx(send_ctx);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_stream_event_send_shutdown_complete(QuicerStreamCTX *s_ctx,
                                           QUIC_STREAM_EVENT *Event)
{
  ERL_NIF_TERM report;
  ErlNifEnv *env = s_ctx->env;
  assert(QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE == Event->Type);
  BOOLEAN is_graceful = Event->SEND_SHUTDOWN_COMPLETE.Graceful;
  TP_CB_3(send_shutdown_complete, (uintptr_t)s_ctx->Stream, is_graceful);
  assert(env);
  report = make_event(env,
                      ATOM_SEND_SHUTDOWN_COMPLETE,
                      enif_make_copy(env, s_ctx->eHandle),
                      ATOM_BOOLEAN(is_graceful));

  signal_or_buffer(s_ctx, &(s_ctx->owner->Pid), report);
  return QUIC_STATUS_SUCCESS;
}

ERL_NIF_TERM
get_stream_rid1(ErlNifEnv *env, int args, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx;
  if (1 != args)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return SUCCESS(enif_make_ulong(env, (unsigned long)s_ctx->Stream));
}

static void
reset_stream_recv(QuicerStreamCTX *s_ctx)
{
  s_ctx->Buffers[0].Buffer = NULL;
  s_ctx->Buffers[0].Length = 0;
  s_ctx->Buffers[1].Buffer = NULL;
  s_ctx->Buffers[1].Length = 0;

  s_ctx->is_recv_pending = FALSE;
  s_ctx->TotalBufferLength = 0;
}

ERL_NIF_TERM
get_stream_owner1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx;
  ERL_NIF_TERM res = ATOM_UNDEFINED;
  CXPLAT_FRE_ASSERT(argc == 1);
  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(s_ctx->lock);
  if (!s_ctx->owner)
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto exit;
    }
  res = SUCCESS(enif_make_pid(env, &(s_ctx->owner->Pid)));
exit:
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

// s_ctx MUST be locked
int
signal_or_buffer(QuicerStreamCTX *s_ctx,
                 ErlNifPid *owner_pid,
                 ERL_NIF_TERM msg)
{
  if (s_ctx && s_ctx->sig_queue != NULL)
    {
      ErlNifEnv *q_env = s_ctx->sig_queue->env;
      OWNER_SIGNAL *sig = OwnerSignalAlloc();
      sig->msg = enif_make_copy(q_env, msg);
      sig->orig_owner = enif_make_pid(q_env, owner_pid);
      OwnerSignalEnqueue(s_ctx->sig_queue, sig);
      return TRUE;
    }
  else
    {
      return enif_send(NULL, owner_pid, NULL, msg);
    }
}

// s_ctx MUST be locked
BOOLEAN
flush_sig_buffer(ErlNifEnv *env, QuicerStreamCTX *s_ctx)
{
  OWNER_SIGNAL *sig = NULL;
  if (!s_ctx->sig_queue)
    {
      return FALSE;
    }

  while ((sig = OwnerSignalDequeue(s_ctx->sig_queue)))
    {
      // if send failed, msg will be cleared in `OwnerSignalQueueDestroy`
      enif_send(env, &(s_ctx->owner->Pid), NULL, sig->msg);

      OwnerSignalFree(sig);
    }
  OwnerSignalQueueDestroy(s_ctx->sig_queue);
  s_ctx->sig_queue = NULL;
  return TRUE;
}

ERL_NIF_TERM
mock_buffer_sig(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx;
  ErlNifPid orig_pid;
  ERL_NIF_TERM res = ATOM_OK;

  CXPLAT_FRE_ASSERT(argc == 3);

  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_local_pid(env, argv[1], &orig_pid))
    {
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  enif_mutex_lock(s_ctx->lock);
  if (!s_ctx->sig_queue)
    {
      res = ERROR_TUPLE_2(ATOM_NONE);
      goto Exit;
    }

  if (!signal_or_buffer(s_ctx, &orig_pid, argv[2]))
    {
      res = ERROR_TUPLE_2(ATOM_FALSE);
    }
Exit:
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

ERL_NIF_TERM
flush_stream_buffered_sigs(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx = NULL;
  ERL_NIF_TERM res = ATOM_OK;

  CXPLAT_FRE_ASSERT(argc == 1);

  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  enif_mutex_lock(s_ctx->lock);
  if (!flush_sig_buffer(env, s_ctx))
    {
      res = ERROR_TUPLE_2(ATOM_NONE);
    }
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

/*
** Enable signal buffering.
** Signals are buffered instead of being sent to the owner.
** call `flush_stream_buffered_sigs` to flush the buffer.
*/
ERL_NIF_TERM
enable_sig_buffer(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx = NULL;
  ERL_NIF_TERM res = ATOM_OK;

  CXPLAT_FRE_ASSERT(argc == 1);

  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(s_ctx->lock);
  if (!s_ctx->sig_queue)
    {
      s_ctx->owner->active = ACCEPTOR_RECV_MODE_PASSIVE;
      s_ctx->sig_queue = OwnerSignalQueueNew();
      OwnerSignalQueueInit(s_ctx->sig_queue);
    }
  enif_mutex_unlock(s_ctx->lock);

  return res;
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
