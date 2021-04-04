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

QUIC_STATUS
ServerStreamCallback(HQUIC Stream, void *Context, QUIC_STREAM_EVENT *Event)
{
  ErlNifEnv *env;
  QuicerStreamCTX *s_ctx;
  ErlNifBinary bin;
  s_ctx = (QuicerStreamCTX *)Context;
  env = s_ctx->env;

  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      free(Event->SEND_COMPLETE.ClientContext);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //

      // ownership is transfered to var: report
      if (!enif_alloc_binary(Event->RECEIVE.TotalBufferLength, &bin))
        {
          //@todo error handling
          return QUIC_STATUS_OUT_OF_MEMORY;
        }
      // @todo check can we skip copy?
      // @todo handle multi buffer copy
      uint32_t offset = 0;
      for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i)
        {
          CxPlatCopyMemory(bin.data + offset, Event->RECEIVE.Buffers[i].Buffer,
                         Event->RECEIVE.Buffers[i].Length);
          offset += Event->RECEIVE.Buffers[i].Length;
        }
      ERL_NIF_TERM report = enif_make_tuple6(
          env,
          // reserved for port
          ATOM_QUIC, enif_make_binary(env, &bin),
          enif_make_resource(env, s_ctx),
          enif_make_uint64(
              env, Event->RECEIVE.AbsoluteOffset),
          enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
          enif_make_int(env, Event->RECEIVE.Flags) // @todo handle fin flag.
      );

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // App down, shutdown stream
          MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                                 QUIC_STATUS_UNREACHABLE);
        }
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      report = enif_make_tuple3(env,
        ATOM_QUIC, ATOM_PEER_SEND_SHUTDOWN,
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
      report = enif_make_tuple4(env,
                                ATOM_QUIC, ATOM_PEER_SEND_ABORTED,
                                enif_make_resource(env, s_ctx),
                                enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      //
      // Both directions of the stream have been shut down and MsQuic is done
      // with the stream. It can now be safely cleaned up.
      //
      // we don't use trylock since we are in callback context
      enif_mutex_lock(s_ctx->lock);
      report = enif_make_tuple4(env,
                                ATOM_QUIC, ATOM_CLOSED,
                                enif_make_resource(env, s_ctx),
                                enif_make_uint64(env, Event->SEND_SHUTDOWN_COMPLETE.Graceful));

      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
      MsQuic->StreamClose(Stream);
      s_ctx->closed = true;
      enif_mutex_unlock(s_ctx->lock);
      destroy_s_ctx(s_ctx);
      break;
    default:
      break;
    }
  return QUIC_STATUS_SUCCESS;
}

// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
    ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event)
{
  ErlNifEnv *env;
  ErlNifBinary bin;
  QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)Context;
  ERL_NIF_TERM report;
  env = s_ctx->env;

  switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
      //
      // A previous StreamSend call has completed, and the context is being
      // returned back to the app.
      //
      free(Event->SEND_COMPLETE.ClientContext);
      break;
    case QUIC_STREAM_EVENT_RECEIVE:
      //
      // Data was received from the peer on the stream.
      //
      //printf("[strm][%p] Data received\n", Stream);

      if (!enif_alloc_binary(Event->RECEIVE.TotalBufferLength, &bin))
        {
          printf("[strm][%p] Failed to build recv buffer\n", Stream);
          return QUIC_STATUS_OUT_OF_MEMORY;
        }
      // @todo check can we skip copy?
      // @todo handle multi buffer copy
      uint32_t offset = 0;
      for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i)
        {
          CxPlatCopyMemory(bin.data + offset, Event->RECEIVE.Buffers[i].Buffer,
                         Event->RECEIVE.Buffers[i].Length);
          offset += Event->RECEIVE.Buffers[i].Length;
        }

      report = enif_make_tuple6(
          env,
          // reserved for port
          ATOM_QUIC, enif_make_binary(env, &bin),
          enif_make_resource(env, s_ctx),
          enif_make_uint64(env, Event->RECEIVE.AbsoluteOffset),
          enif_make_uint64(env, Event->RECEIVE.TotalBufferLength),
          enif_make_int(env, Event->RECEIVE.Flags)
      );

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // App down, close it.
          // @todo free context as well
          printf("[strm][%p] failed to report data\n", Stream);
          MsQuic->StreamClose(Stream);
          // @todo return proper bad status
        }
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
      //
      // The peer gracefully shut down its send direction of the stream.
      //
      report = enif_make_tuple4(env,
                                ATOM_QUIC, ATOM_PEER_SEND_ABORTED,
                                enif_make_resource(env, s_ctx),
                                enif_make_uint64(env, Event->PEER_SEND_ABORTED.ErrorCode));

      if (!enif_send(NULL, &(s_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown the stream as well.
          MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
          // @todo return proper bad status
        }
      break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
      //
      // The peer aborted its send direction of the stream.
      //
      report = enif_make_tuple3(env,
        ATOM_QUIC, ATOM_PEER_SEND_SHUTDOWN,
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
      report = enif_make_tuple4(env,
        ATOM_QUIC, ATOM_CLOSED,
        enif_make_resource(env, s_ctx),
        enif_make_uint64(env, Event->SEND_SHUTDOWN_COMPLETE.Graceful));

      enif_send(NULL, &(s_ctx->owner->Pid), NULL, report);
      MsQuic->StreamClose(Stream);
      destroy_s_ctx(s_ctx);
      break;
    default:
      break;
    }
  return QUIC_STATUS_SUCCESS;
}

ERL_NIF_TERM
async_start_stream2(ErlNifEnv *env, __unused_parm__ int argc,
                    const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
  QuicerConnCTX *c_ctx;

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  //
  // note, ctx is not shared yet, thus no locking needed.
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

  // @todo check if stream is null
  if (QUIC_FAILED(Status = MsQuic->StreamOpen(
                      c_ctx->Connection, QUIC_STREAM_OPEN_FLAG_NONE,
                      ClientStreamCallback, s_ctx, &(s_ctx->Stream))))
    {
      destroy_s_ctx(s_ctx);
      return ERROR_TUPLE_2(ATOM_STREAM_OPEN_ERROR);
    }

  //
  // Starts the bidirectional stream. By default, the peer is not notified of
  // the stream being started until data is sent on the stream.
  //
  if (QUIC_FAILED(Status = MsQuic->StreamStart(s_ctx->Stream,
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
async_accept_stream2(ErlNifEnv *env, __unused_parm__ int argc,
                     const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
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
  HQUIC Stream = s_ctx->Stream;

  if (!enif_inspect_binary(env, ebin, &bin))
    {
      MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
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
      //@todo return error code
      return ERROR_TUPLE_3(ATOM_STREAM_SEND_ERROR, ETERM_INT(Status));
    }
  uint64_t len = bin.size;
  return SUCCESS(ETERM_UINT_64(len));
}

ERL_NIF_TERM
close_stream1(ErlNifEnv *env, __unused_parm__ int argc,
              const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = 0;
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
    if (QUIC_FAILED(
          Status = MsQuic->StreamShutdown(
              s_ctx->Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, NO_ERROR)))
    {
       ret =  ERROR_TUPLE_2(ETERM_INT(Status));
    }
  }
  enif_release_resource(s_ctx);
  enif_mutex_unlock(s_ctx->lock);
  return ret;
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
