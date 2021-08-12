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
static QUIC_STATUS handle_stream_recv_event(HQUIC Stream,
                                            QuicerStreamCTX *s_ctx,
                                            QUIC_STREAM_EVENT *Event);

QUIC_STATUS
ServerStreamCallback(HQUIC Stream, void *Context, QUIC_STREAM_EVENT *Event)
{
  ErlNifEnv *env;
  QuicerStreamCTX *s_ctx;
  ERL_NIF_TERM report;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  QuicerStreamSendCTX *send_ctx = NULL;
  s_ctx = (QuicerStreamCTX *)Context;

  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);

  env = s_ctx->env;

  TP_CB_3(event, Stream, Event->Type);
  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      //
      send_ctx = (QuicerStreamSendCTX *)(Event->SEND_COMPLETE.ClientContext);

      if (!send_ctx)
        {
          status = QUIC_STATUS_INVALID_STATE;
          break;
        }

      if (send_ctx->is_sync)
        {
          report = enif_make_tuple4(
              env,
              ATOM_QUIC,
              ATOM_SEND_COMPLETE,
              enif_make_resource(env, s_ctx),
              enif_make_uint64(env, Event->SEND_COMPLETE.Canceled));

          // note, report to caller instead of stream owner
          if (!enif_send(NULL, &send_ctx->caller, NULL, report))
            {
              // Owner is gone, we shutdown the stream as well.
              TP_CB_3(owner_die, Stream, Event->Type);
              MsQuic->StreamShutdown(
                  Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
              // @todo return proper bad status
            }
        }

      destroy_send_ctx(send_ctx);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      status = handle_stream_recv_event(Stream, s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      report = enif_make_tuple3(env,
                                ATOM_QUIC,
                                ATOM_PEER_SEND_SHUTDOWN,
                                enif_make_resource(env, s_ctx));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // App down, close it.
          TP_CB_3(app_down, Stream, Event->Type);
          MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer aborted its send direction of the stream.
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_PEER_SEND_ABORTED,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          TP_CB_3(app_down, Stream, Event->Type);
          MsQuic->StreamShutdown(
              Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      // we don't use trylock since we are in callback context
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_CLOSED,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->SEND_SHUTDOWN_COMPLETE.Graceful));

      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
      MsQuic->StreamClose(Stream);
      s_ctx->is_closed = true;

      destroy_s_ctx(s_ctx);
      break;
    default:
      break;
    }
  enif_mutex_unlock(s_ctx->lock);
  enif_mutex_unlock(s_ctx->c_ctx->lock);
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
  QuicerStreamSendCTX *send_ctx = NULL;
  ERL_NIF_TERM report;
  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);
  env = s_ctx->env;
  TP_CB_3(event, Stream, Event->Type);
  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      send_ctx = (QuicerStreamSendCTX *)(Event->SEND_COMPLETE.ClientContext);

      if (!send_ctx)
        {
          status = QUIC_STATUS_INVALID_STATE;
        }

      if (send_ctx->is_sync)
        {
          report = enif_make_tuple4(
              env,
              ATOM_QUIC,
              ATOM_SEND_COMPLETE,
              enif_make_resource(env, s_ctx),
              enif_make_uint64(env, Event->SEND_COMPLETE.Canceled));

          // note, report to caller instead of stream owner
          if (!enif_send(NULL, &send_ctx->caller, NULL, report))
            {
              TP_CB_3(app_down, Stream, 0);
              // Owner is gone, we shutdown the stream as well.
              MsQuic->StreamShutdown(
                  Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
              // @todo return proper bad status
            }
        }

      destroy_send_ctx(send_ctx);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      if (0 == Event->RECEIVE.TotalBufferLength)
        {
          break;
        }
      status = handle_stream_recv_event(Stream, s_ctx, Event);
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_PEER_SEND_ABORTED,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          MsQuic->StreamShutdown(
              Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer aborted its send direction of the stream.
      //
      report = enif_make_tuple3(env,
                                ATOM_QUIC,
                                ATOM_PEER_SEND_SHUTDOWN,
                                enif_make_resource(env, s_ctx));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // App down, close it.
          MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_CLOSED,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->SEND_SHUTDOWN_COMPLETE.Graceful));

      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
      MsQuic->StreamClose(Stream);
      destroy_s_ctx(s_ctx);
      break;
    default:
      break;
    }
  enif_mutex_unlock(s_ctx->lock);
  enif_mutex_unlock(s_ctx->c_ctx->lock);
  return status;
}

ERL_NIF_TERM
async_start_stream2(ErlNifEnv *env,
                    __unused_parm__ int argc,
                    const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
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

  //
  // note, ctx is not shared yet, thus no locking is needed.
  //
  QuicerStreamCTX *s_ctx = init_s_ctx();
  s_ctx->c_ctx = c_ctx;

  // Caller should be the owner of this stream.
  s_ctx->owner = AcceptorAlloc();
  if (!enif_self(env, &(s_ctx->owner->Pid)))
    {
      destroy_s_ctx(s_ctx);
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  if (!set_owner_recv_mode(s_ctx->owner, env, active_val))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // @todo check if stream is null
  if (QUIC_FAILED(Status = MsQuic->StreamOpen(c_ctx->Connection,
                                              QUIC_STREAM_OPEN_FLAG_NONE,
                                              ClientStreamCallback,
                                              s_ctx,
                                              &(s_ctx->Stream))))
    {
      destroy_s_ctx(s_ctx);
      return ERROR_TUPLE_3(ATOM_STREAM_OPEN_ERROR, enif_make_int(env, Status));
    }

  //
  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  //
  if (QUIC_FAILED(Status = MsQuic->StreamStart(s_ctx->Stream,
                                               // @todo flag in options
                                               QUIC_STREAM_START_FLAG_NONE)))
    {
      // note, stream call back would close the stream.
      // return ERROR_TUPLE_2(ATOM_STREAM_OPEN_ERROR);
      return ERROR_TUPLE_2(ATOM_STREAM_START_ERROR);
    }

  return SUCCESS(enif_make_resource(env, s_ctx));
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
      free(acceptor);
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  //@todo this is assertion
  if (!enif_is_process_alive(env, &(acceptor->Pid)))
    {
      free(acceptor);
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
  QuicerStreamCTX *s_ctx;
  ErlNifBinary bin;
  ERL_NIF_TERM estream = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  ERL_NIF_TERM eFlags = argv[2];
  uint32_t sendflags;

  if (3 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerStreamSendCTX *send_ctx = init_send_ctx();
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
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_inspect_binary(env, ebin, &bin))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, estream, ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);

  send_ctx->s_ctx = s_ctx;

  if (s_ctx->is_closed || s_ctx->c_ctx->is_closed)
    {
      enif_mutex_unlock(s_ctx->c_ctx->lock);
      enif_mutex_unlock(s_ctx->lock);
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  HQUIC Stream = s_ctx->Stream;

  //
  // Allocates and builds the buffer to send over the stream.
  //

  assert(bin.data != NULL);
  QUIC_BUFFER *SendBuffer
      = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + bin.size, QUICER_SND_BUFF);

  if (SendBuffer == NULL)
    {
      enif_mutex_unlock(s_ctx->lock);
      enif_mutex_unlock(s_ctx->c_ctx->lock);
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  send_ctx->Buffer = SendBuffer;
  /*
    Fast path plan A, requires caller holds the ref to the binary
     so that it won't get GCed.
     SendBuffer->Buffer = bin.data;
  */

  /*
    Fast path plan B, make a term copy of bin term to stream ctx env, and
    *release* it in callback enif_make_copy(s_ctx->env, argv[1]);
    SendBuffer->Buffer = bin.data;
  */

  /*
  **  Slow path, safe but requires memcpy copy
  */
  SendBuffer->Buffer = (uint8_t *)SendBuffer + sizeof(QUIC_BUFFER);
  CxPlatCopyMemory(SendBuffer->Buffer, bin.data, bin.size);
  SendBuffer->Length = (uint32_t)bin.size;

  QUIC_STATUS Status;
  // note, SendBuffer as sendcontext, free the buffer while message is sent
  // confirmed.
  if (QUIC_FAILED(Status = MsQuic->StreamSend(
                      Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, send_ctx)))
    {
      free(SendBuffer);
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      enif_mutex_unlock(s_ctx->lock);
      enif_mutex_unlock(s_ctx->c_ctx->lock);
      //@todo return error code
      return ERROR_TUPLE_3(ATOM_STREAM_SEND_ERROR, ETERM_INT(Status));
    }
  uint64_t len = bin.size;
  enif_mutex_unlock(s_ctx->lock);
  enif_mutex_unlock(s_ctx->c_ctx->lock);
  return SUCCESS(ETERM_UINT_64(len));
}

ERL_NIF_TERM
recv2(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{

  QuicerStreamCTX *s_ctx;
  ErlNifBinary bin;
  ERL_NIF_TERM estream = argv[0];
  ErlNifUInt64 size_req = 0;
  ERL_NIF_TERM res;

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
      // follow otp behavior
      enif_mutex_unlock(s_ctx->lock);
      return ERROR_TUPLE_2(ATOM_EINVAL);
    }

  if (s_ctx->is_buff_ready && s_ctx->Buffer && s_ctx->BufferLen > 0
      && (0 == size_req || size_req <= s_ctx->BufferLen))
    { // buffer is ready to consume
      uint64_t size_consumed = recvbuffer_flush(s_ctx, &bin, size_req);
      s_ctx->is_wait_for_data = FALSE;
      MsQuic->StreamReceiveComplete(s_ctx->Stream, size_consumed);

      if (size_consumed != s_ctx->BufferLen)
        {
          // explicit enable recv since we have some data left unconusmed
          MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, true);
        }

      if (0 == s_ctx->BufferLen - size_consumed || 0 == size_req)
        {
          // Buffer has perfect bytes consumed
          s_ctx->Buffer = NULL;
          s_ctx->BufferLen = 0;
          s_ctx->is_buff_ready = FALSE;
        }
      else
        {
          // Buffer has more data than we need
          s_ctx->is_buff_ready = FALSE;
          s_ctx->Buffer = NULL;
          s_ctx->BufferLen = 0;
        }

      res = SUCCESS(enif_make_binary(env, &bin));
    }
  else
    { // want more data in buffer
      s_ctx->is_wait_for_data = TRUE;

      // let msquic buffer more and explicit enable recv
      MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
      MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE);

      // nif caller will get {ok, not_ready}
      // this is a ack to its call
      res = SUCCESS(ATOM_ERROR_NOT_READY);
    }
  enif_mutex_unlock(s_ctx->lock);

  return res;
}

ERL_NIF_TERM
close_stream1(ErlNifEnv *env,
              __unused_parm__ int argc,
              const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
  ERL_NIF_TERM ret = ATOM_OK;
  QuicerStreamCTX *s_ctx;
  if (!enif_get_resource(env, argv[0], ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  //@todo support application specific error code.
  // we don't use trylock since we are in NIF call.
  enif_mutex_lock(s_ctx->lock);
  enif_keep_resource(s_ctx);
  if (!s_ctx->is_closed)
    {
      if (QUIC_FAILED(
              Status = MsQuic->StreamShutdown(
                  s_ctx->Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0)))
        {
          ret = ERROR_TUPLE_2(ETERM_INT(Status));
        }
      s_ctx->is_closed = TRUE;
    }
  enif_mutex_unlock(s_ctx->lock);
  enif_release_resource(s_ctx);
  return ret;
}

uint64_t
recvbuffer_flush(QuicerStreamCTX *s_ctx, ErlNifBinary *bin, uint64_t req_len)
{
  // note, make sure ownership of bin should be transfered, after call
  uint64_t bin_size = 0;
  assert(req_len <= s_ctx->BufferLen);
  // Decide binary size
  if (req_len == 0)
    { // we need more data than buffer has
      bin_size = s_ctx->BufferLen;
    }
  else
    { // buffer size is larger than we want
      bin_size = req_len;
    }

  enif_alloc_binary(bin_size, bin);

  CxPlatCopyMemory(bin->data, s_ctx->Buffer, bin_size);
  return bin_size;
}

QUIC_STATUS
handle_stream_recv_event(HQUIC Stream,
                         QuicerStreamCTX *s_ctx,
                         QUIC_STREAM_EVENT *Event)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ErlNifEnv *env = s_ctx->env;
  ErlNifBinary bin;

  s_ctx->Buffer = Event->RECEIVE.Buffers->Buffer;
  s_ctx->BufferLen = Event->RECEIVE.TotalBufferLength;

  if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active)
    { // passive receive
      /* important:
         for passive receive, it is not ok to call
         MsQuic->StreamReceiveSetEnabled to enable receiving
         becasue it can casue busy spinning:
         trigger event and handle event in a loop
      */
      s_ctx->is_buff_ready = TRUE;
      status = QUIC_STATUS_PENDING;

      if (s_ctx->is_wait_for_data)
        { // Owner is waiting for data
          // notify owner to trigger async recv
          // @todo, can we expect some owner to take over?
          if (!enif_send(NULL,
                         &(s_ctx->owner->Pid),
                         NULL,
                         enif_make_tuple3(env,
                                          ATOM_QUIC,
                                          enif_make_resource(env, s_ctx),
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
      recvbuffer_flush(s_ctx, &bin, (uint64_t)0);

      ERL_NIF_TERM report_active = enif_make_tuple6(
          env,
          ATOM_QUIC,
          enif_make_binary(env, &bin),
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->RECEIVE.AbsoluteOffset),
          enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
          enif_make_int(env, Event->RECEIVE.Flags) // @todo handle fin flag.
      );

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report_active))
        {
          // App down, shutdown stream
          MsQuic->StreamShutdown(Stream,
                                 QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                 QUIC_STATUS_UNREACHABLE);
          return status;
        }

      // report pasive
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

              ERL_NIF_TERM report_passive = enif_make_tuple2(
                  env, ATOM_QUIC_PASSIVE, enif_make_resource(env, s_ctx));

              if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report_passive))
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
