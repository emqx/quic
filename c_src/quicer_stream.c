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
  s_ctx = (QuicerStreamCTX *)Context;

  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);

  env = s_ctx->env;
  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_SEND_COMPLETE,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->SEND_COMPLETE.Canceled));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          MsQuic->StreamShutdown(
              Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      free(Event->SEND_COMPLETE.ClientContext);
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
      s_ctx->closed = true;

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
  ERL_NIF_TERM report;
  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);
  env = s_ctx->env;
  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_SEND_COMPLETE,
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->SEND_COMPLETE.Canceled));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          MsQuic->StreamShutdown(
              Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      free(Event->SEND_COMPLETE.ClientContext);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
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

  s_ctx->owner->active = IS_SAME_TERM(active_val, ATOM_TRUE);

  // @todo check if stream is null
  if (QUIC_FAILED(Status = MsQuic->StreamOpen(c_ctx->Connection,
                                              QUIC_STREAM_OPEN_FLAG_NONE,
                                              ClientStreamCallback,
                                              s_ctx,
                                              &(s_ctx->Stream))))
    {
      destroy_s_ctx(s_ctx);
      return ERROR_TUPLE_2(ATOM_STREAM_OPEN_ERROR);
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
send2(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  QuicerStreamCTX *s_ctx;
  ErlNifBinary bin;
  ERL_NIF_TERM estream = argv[0];
  ERL_NIF_TERM ebin = argv[1];
  if (!enif_get_resource(env, estream, ctx_stream_t, (void **)&s_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  enif_mutex_lock(s_ctx->c_ctx->lock);
  enif_mutex_lock(s_ctx->lock);
  HQUIC Stream = s_ctx->Stream;

  if (!enif_inspect_binary(env, ebin, &bin))
    {
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
      enif_mutex_unlock(s_ctx->lock);
      enif_mutex_unlock(s_ctx->c_ctx->lock);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  //
  // Allocates and builds the buffer to send over the stream.
  //

  // ensure type of ErlNifBinary.size
  assert(sizeof(size_t) == sizeof(uint64_t));
  assert(bin.data != NULL);
  QUIC_BUFFER *SendBuffer
      = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + bin.size, QUICER_SND_BUFF);

  if (SendBuffer == NULL)
    {
      enif_mutex_unlock(s_ctx->lock);
      enif_mutex_unlock(s_ctx->c_ctx->lock);
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

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
                      Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer)))
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

  if (s_ctx->owner->active)
    {
      // follow otp behavior
      enif_mutex_unlock(s_ctx->lock);
      return ERROR_TUPLE_2(ATOM_EINVAL);
    }

  if (s_ctx->Buffer && s_ctx->BufferLen > 0 && s_ctx->is_buff_ready
      && (0 == size_req || size_req <= s_ctx->BufferLen - s_ctx->BufferOffset))
    {
      uint64_t size_consumed = recvbuffer_flush(s_ctx, &bin, size_req);
      s_ctx->passive_recv_bytes -= size_consumed;
      s_ctx->is_wait_for_data = false;

      // if we have some remaining bytes
      // @todo disable receving when it is over some threshold.
      //MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, true);

      if (0 == s_ctx->BufferLen - s_ctx->BufferOffset - size_consumed || 0 == size_req)
      { // perfect match
         //MsQuic->StreamReceiveComplete(s_ctx->Stream, s_ctx->BufferLen);
         printf("Buffer has perfect bytes consumed: %lu\n", size_consumed);
         MsQuic->StreamReceiveComplete(s_ctx->Stream, size_consumed);
         MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, true);
          s_ctx->BufferOffset = 0;
          s_ctx->Buffer = NULL;
          s_ctx->BufferLen = 0;
          s_ctx->passive_recv_bytes = 0;
          s_ctx->is_wait_for_data = FALSE;
          s_ctx->is_buff_ready = FALSE;
        }
      else
      {
        printf("Buffer has more data than we need, consumed %lu\n", size_consumed);
        MsQuic->StreamReceiveComplete(s_ctx->Stream, size_consumed);
        MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, true);
        s_ctx->is_buff_ready = FALSE;
        s_ctx->is_wait_for_data = FALSE;
        //s_ctx->BufferOffset += size_consumed;
        s_ctx->Buffer = NULL;
      }

      res = SUCCESS(enif_make_binary(env, &bin));
    }
  else
    { // we want more data
      printf("We want more data: %lu\n", size_req);
      s_ctx->is_wait_for_data = TRUE;
      s_ctx->passive_recv_bytes = size_req;

      // to complete a async handling, complete recv with 0 bytes
      //MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);

      // reenable receving so new data can flow in since we consumed 0
      MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
      MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE);

      // nif caller will get {ok, not_ready}
      // which means its call is acked and it should wait for
      // recv the data in async.
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
  if (!s_ctx->closed)
    {
      if (QUIC_FAILED(Status = MsQuic->StreamShutdown(
                          s_ctx->Stream,
                          QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                          NO_ERROR)))
        {
          ret = ERROR_TUPLE_2(ETERM_INT(Status));
        }
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
  uint64_t offset = s_ctx->BufferOffset;
  // Decide binary size
  if (req_len == 0 || req_len >= s_ctx->BufferLen - s_ctx->BufferOffset)
    { // we need more data than buffer can provide
      bin_size = s_ctx->BufferLen - s_ctx->BufferOffset;
      req_len = bin_size; // cover the case of req_len = 0
    }
  else if (req_len < s_ctx->BufferLen)
    { // buffer size is larger than we want
      bin_size = req_len;
    }

  enif_alloc_binary(bin_size, bin);

  CxPlatCopyMemory(bin->data, s_ctx->Buffer + offset, bin_size);
  req_len -= bin_size;
  assert(req_len == 0);
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

  if (false == s_ctx->owner->active)
    { // passive receive
      // important:
      // for passive receive, it is not ok to call
      // MsQuic->StreamReceiveSetEnabled to enable receiving
      if (!s_ctx->is_wait_for_data)
      { //no one is waiting
          // msquic actually use only one buffer for API calls
          //assert(1 == Event->RECEIVE.BufferCount);
          s_ctx->is_buff_ready = TRUE;
          Event->RECEIVE.TotalBufferLength = 0;
          status = QUIC_STATUS_SUCCESS;
        }
      else /* if (s_ctx->is_wait_for_data && Event->RECEIVE.BufferCount > 0 */
           /*     && (0 == s_ctx->passive_recv_bytes // 0 means size unspecified */
           /*         || s_ctx->passive_recv_bytes */
           /*                <= Event->RECEIVE.TotalBufferLength)) */
        { // Owner is waiting for data and we just report that
          printf("We have new data: wanted %lu vs buffer %lu\n",
                 s_ctx->passive_recv_bytes,
                 Event->RECEIVE.TotalBufferLength);//
          enif_send(NULL,
                    &(s_ctx->owner->Pid),
                    NULL,
                    enif_make_tuple3(env,
                                     ATOM_QUIC,
                                     enif_make_resource(env, s_ctx),
                                     ATOM_QUIC_STATUS_CONTINUE));
          // so we hand over data to the owner, aka async handling,
          // add we mark status pending to block the receiving.
          //s_ctx->is_wait_for_data = false;
          s_ctx->is_buff_ready = TRUE;
          //Event->RECEIVE.TotalBufferLength = 0;
          //status = QUIC_STATUS_SUCCESS;
          status = QUIC_STATUS_PENDING;
        }
      /* else */
      /*   { // Owner is waiting but need more date to poll, */
      /*     // mark we handled 0 bytes and let it contitune to recv. */
      /*     printf("Owner is waiting more data: %lu\n", s_ctx->passive_recv_bytes); */
      /*     Event->RECEIVE.TotalBufferLength = 0; */
      /*     s_ctx->is_buff_ready = TRUE; */
      /*     status = QUIC_STATUS_SUCCESS; */
      /*   } */
    }
  else
    { // active receive

      recvbuffer_flush(s_ctx, &bin, (uint64_t)0);

      ERL_NIF_TERM report = enif_make_tuple6(
          env,
          // reserved for port
          ATOM_QUIC,
          enif_make_binary(env, &bin),
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->RECEIVE.AbsoluteOffset),
          enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
          enif_make_int(env, Event->RECEIVE.Flags) // @todo handle fin flag.
      );

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // App down, shutdown stream
          MsQuic->StreamShutdown(Stream,
                                 QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                 QUIC_STATUS_UNREACHABLE);
        }
    }
  return status;
}
///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
