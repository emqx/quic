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
    case QUIC_STREAM_EVENT_START_COMPLETE:
      // Only for Local initiated stream
      status = handle_stream_event_start_complete(s_ctx, Event);
      break;

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
    case QUIC_STREAM_EVENT_PEER_ACCEPTED:
      //
      // The peer aborted its send direction of the stream.
      //
      status = handle_stream_event_peer_accepted(s_ctx, Event);
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
    default:
      break;
    }

  enif_clear_env(env);

  if (is_destroy)
    {
      s_ctx->is_closed = TRUE;
    }

  enif_mutex_unlock(s_ctx->lock);

  if (is_destroy)
    {
      // must be called after mutex unlock
      destroy_s_ctx(s_ctx);
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
    default:
      break;
    }

  enif_clear_env(env);

  if (is_destroy)
    {
      s_ctx->is_closed = TRUE;
    }

  enif_mutex_unlock(s_ctx->lock);

  if (is_destroy)
    {
      // must be called after mutex unlock,
      destroy_s_ctx(s_ctx);
    }
  return status;
}

ERL_NIF_TERM
async_start_stream2(ErlNifEnv *env,
                    __unused_parm__ int argc,
                    const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  QuicerConnCTX *c_ctx = NULL;
  ERL_NIF_TERM res = ATOM_ERROR_INTERNAL_ERROR;
  ERL_NIF_TERM active_val;
  ERL_NIF_TERM estart_flag;
  unsigned int start_flag = QUIC_STREAM_START_FLAG_NONE; // default
  ERL_NIF_TERM eopen_flag;
  unsigned int open_flag = QUIC_STREAM_OPEN_FLAG_NONE; // default

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
      // @TODO set event mask for some flags
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

  //
  // note, s_ctx is not shared yet, thus no locking is needed.
  //
  QuicerStreamCTX *s_ctx = init_s_ctx();

  // This is optional
  get_uint32_from_map(env, eoptions, ATOM_QUIC_EVENT_MASK, &s_ctx->event_mask);

  enif_keep_resource(c_ctx);
  s_ctx->c_ctx = c_ctx;

  if (!s_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

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

  if (QUIC_FAILED(Status = MsQuic->StreamOpen(c_ctx->Connection,
                                              open_flag,
                                              ClientStreamCallback,
                                              s_ctx,
                                              &(s_ctx->Stream))))
    {

      res = ERROR_TUPLE_3(ATOM_STREAM_OPEN_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }

  // Now we have Stream handler
  s_ctx->eHandler = enif_make_resource(s_ctx->imm_env, s_ctx);

  //
  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  //
  if (QUIC_FAILED(Status = MsQuic->StreamStart(s_ctx->Stream, start_flag)))
    {
      // note, stream call back would close the stream
      // destroy_s_ctx should not be called here
      return ERROR_TUPLE_3(ATOM_STREAM_START_ERROR, ATOM_STATUS(Status));
    }

  s_ctx->is_closed = FALSE;
  res = enif_make_copy(env, s_ctx->eHandler);

  return SUCCESS(res);

ErrorExit:
  destroy_s_ctx(s_ctx);
  return res;
}

// accept streams on top of connection.
ERL_NIF_TERM
async_accept_stream2(ErlNifEnv *env,
                     __unused_parm__ int argc,
                     const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  ERL_NIF_TERM active_val;

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

  acceptor->active = IS_SAME_TERM(active_val, ATOM_TRUE);

  AcceptorEnqueue(c_ctx->acceptor_queue, acceptor);
  ERL_NIF_TERM connectionHandler = enif_make_resource(env, c_ctx);
  return SUCCESS(connectionHandler);
}

ERL_NIF_TERM
send3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx = NULL;
  ERL_NIF_TERM estream = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  ERL_NIF_TERM eFlags = argv[2];
  ERL_NIF_TERM res = ATOM_OK;
  uint32_t sendflags;

  if (3 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, estream, ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerStreamSendCTX *send_ctx = init_send_ctx();
  if (!send_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  ErlNifBinary *bin = &send_ctx->bin;

  if (enif_get_uint(env, eFlags, &sendflags))
    {
      enif_self(env, &send_ctx->caller);

      if ((sendflags & 1UL) > 0)
        {
          send_ctx->is_sync = TRUE;
        }
      else
        {
          send_ctx->is_sync = FALSE;
        }
    }
  else
    {
      destroy_send_ctx(send_ctx);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  ebin = enif_make_copy(send_ctx->env, ebin);
  if (!(enif_inspect_iolist_as_binary(send_ctx->env, ebin, bin)
        || enif_inspect_binary(send_ctx->env, ebin, bin))
      || bin->size > UINT32_MAX)
    {
      destroy_send_ctx(send_ctx);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(s_ctx->lock);

  send_ctx->s_ctx = s_ctx;

  HQUIC Stream = s_ctx->Stream;

  //
  // Allocates and builds the buffer to send over the stream.
  //

  assert(bin->data != NULL);
  send_ctx->Buffer.Buffer = (uint8_t *)bin->data;
  send_ctx->Buffer.Length = (uint32_t)bin->size;

  QUIC_STATUS Status;
  // note, SendBuffer as sendcontext, free the buffer while message is sent
  // confirmed.
  if (QUIC_FAILED(
          Status = MsQuic->StreamSend(
              Stream, &send_ctx->Buffer, 1, QUIC_SEND_FLAG_NONE, send_ctx)))
    {
      res = ERROR_TUPLE_3(ATOM_STREAM_SEND_ERROR, ATOM_STATUS(Status));
      goto ErrorExit;
    }

  else
    {
      res = SUCCESS(ETERM_UINT_64(bin->size));
      goto Exit;
    }
ErrorExit:
  destroy_send_ctx(send_ctx);
Exit:
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

ERL_NIF_TERM
recv2(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{

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

  enif_mutex_lock(s_ctx->lock);

  if (ACCEPTOR_RECV_MODE_PASSIVE != s_ctx->owner->active)
    {
      res = ERROR_TUPLE_2(ATOM_EINVAL);
      goto Exit;
    }

  // We have checked that the Stream is not closed/closing
  // it is safe to use the s_ctx->Stream in following MsQuic API calls

  if (s_ctx->is_buff_ready && s_ctx->TotalBufferLength > 0
      && (0 == size_req || size_req <= s_ctx->TotalBufferLength))
    { // buffer is ready to consume
      uint64_t size_consumed = recvbuffer_flush(s_ctx, &bin, size_req);

      s_ctx->is_wait_for_data = FALSE;

      MsQuic->StreamReceiveComplete(s_ctx->Stream, size_consumed);

      if (size_consumed != s_ctx->TotalBufferLength)
        {
          // explicit enable recv since we have some data left unconusmed
          //
          MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, true);
        }

      if (0 == s_ctx->TotalBufferLength - size_consumed || 0 == size_req)
        {
          // Buffer has perfect bytes consumed

          s_ctx->Buffers[0].Buffer = NULL;
          s_ctx->Buffers[0].Length = 0;
          s_ctx->Buffers[1].Buffer = NULL;
          s_ctx->Buffers[1].Length = 0;

          s_ctx->TotalBufferLength = 0;
          s_ctx->is_buff_ready = FALSE;
        }
      else
        {
          // Buffer has more data than we need
          s_ctx->Buffers[0].Buffer = NULL;
          s_ctx->Buffers[0].Length = 0;
          s_ctx->Buffers[1].Buffer = NULL;
          s_ctx->Buffers[1].Length = 0;

          s_ctx->is_buff_ready = FALSE;
          s_ctx->TotalBufferLength = 0;
        }

      res = SUCCESS(enif_make_binary(env, &bin));
    }
  else
    { // want more data in buffer
      s_ctx->is_wait_for_data = TRUE;

      // let msquic buffer more and explicit enable recv
      //
      MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);

      if (QUIC_FAILED(status
                      = MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE)))
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }

      // NIF caller will get {ok, not_ready}
      // this is an ack to its call
      res = SUCCESS(ATOM_ERROR_NOT_READY);
    }

Exit:
  enif_mutex_unlock(s_ctx->lock);
  return res;
}

ERL_NIF_TERM
shutdown_stream3(ErlNifEnv *env,
                 __unused_parm__ int argc,
                 const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
  ERL_NIF_TERM ret = ATOM_OK;
  QuicerStreamCTX *s_ctx;
  uint32_t app_errcode = 0, flags = 0;
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

  if (QUIC_FAILED(Status
                  = MsQuic->StreamShutdown(s_ctx->Stream, flags, app_errcode)))
    {
      ret = ERROR_TUPLE_2(ATOM_STATUS(Status));
    }

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

  assert(NULL != Event->RECEIVE.Buffers[0].Buffer);
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
      s_ctx->is_buff_ready = TRUE;
      status = QUIC_STATUS_PENDING;

      if (s_ctx->is_wait_for_data)
        { // Owner is waiting for data
          // notify owner to trigger async recv
          if (!enif_send(NULL,
                         &(s_ctx->owner->Pid),
                         s_ctx->env,
                         enif_make_tuple3(env,
                                          ATOM_QUIC,
                                          enif_make_copy(env, s_ctx->eHandler),
                                          ATOM_QUIC_STATUS_CONTINUE)))
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
      ERL_NIF_TERM eHandler = enif_make_copy(env, s_ctx->eHandler);
      ERL_NIF_TERM report_active = enif_make_tuple6(
          env,
          ATOM_QUIC,
          enif_make_binary(env, &bin),
          eHandler,
          enif_make_uint64(env, Event->RECEIVE.AbsoluteOffset),
          enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
          enif_make_int(env, Event->RECEIVE.Flags) // @todo handle fin flag.
      );

      if (!enif_send(NULL, &(s_ctx->owner->Pid), s_ctx->env, report_active))
        {
          // App down, shutdown stream
          MsQuic->StreamShutdown(Stream,
                                 QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                 QUIC_STATUS_UNREACHABLE);
          return status;
        }

      // report passive
      if (ACCEPTOR_RECV_MODE_ONCE == s_ctx->owner->active)
        {
          s_ctx->owner->active = ACCEPTOR_RECV_MODE_PASSIVE;
        }
      else if (ACCEPTOR_RECV_MODE_MULTI == s_ctx->owner->active)
        {
          assert(s_ctx->owner->active_count > 0);

          s_ctx->owner->active_count--;

          if (s_ctx->owner->active_count == 0)
            {
              s_ctx->owner->active = ACCEPTOR_RECV_MODE_PASSIVE;

              ERL_NIF_TERM report_passive
                  = enif_make_tuple2(env, ATOM_QUIC_PASSIVE, eHandler);

              if (!enif_send(
                      NULL, &(s_ctx->owner->Pid), s_ctx->env, report_passive))
                {
                  MsQuic->StreamShutdown(Stream,
                                         QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                         QUIC_STATUS_UNREACHABLE);
                  return status;
                }
            }
        }
    }

  return status;
}

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

      report = make_event_with_props(env,
                                     ATOM_START_COMPLETE,
                                     enif_make_copy(env, s_ctx->eHandler),
                                     props_name,
                                     props_value,
                                     3);
      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
  report = enif_make_tuple3(env,
                            ATOM_QUIC,
                            ATOM_PEER_SEND_SHUTDOWN,
                            enif_make_copy(env, s_ctx->eHandler));

  enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_PEER_SEND_ABORTED,
      enif_make_copy(env, s_ctx->eHandler),
      enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

  enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_PEER_RECEIVE_ABORTED,
      enif_make_copy(env, s_ctx->eHandler),
      enif_make_uint64(env, Event->PEER_RECEIVE_ABORTED.ErrorCode));
  enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_STREAM_CLOSED,
      enif_make_copy(env, s_ctx->eHandler),
      enif_make_uint64(env, Event->SHUTDOWN_COMPLETE.ConnectionShutdown));
  enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
  report = enif_make_tuple3(env,
                            ATOM_QUIC,
                            ATOM_PEER_ACCEPTED,
                            enif_make_copy(env, s_ctx->eHandler));
  enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
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
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_SEND_COMPLETE,
          enif_make_copy(env, s_ctx->eHandler),
          enif_make_uint64(env, Event->SEND_COMPLETE.Canceled));

      // note, report to caller instead of stream owner
      enif_send(NULL, &send_ctx->caller, NULL, report);
    }

  destroy_send_ctx(send_ctx);
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

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
