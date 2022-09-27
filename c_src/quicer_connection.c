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
#include "quicer_connection.h"
#include "quicer_ctx.h"
#include <assert.h>
#include <unistd.h>

extern inline void
EncodeHexBuffer(uint8_t *Buffer, uint8_t BufferLen, char *HexString);

extern inline const char *QuicStatusToString(QUIC_STATUS Status);

static void handle_dgram_state_event(QuicerConnCTX *c_ctx,
                                     QUIC_CONNECTION_EVENT *Event);

static void handle_dgram_send_state_event(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event);

static void handle_dgram_recv_event(QuicerConnCTX *c_ctx,
                                    QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_connected(QuicerConnCTX *c_ctx,
                                  QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_shutdown_initiated_by_transport(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_shutdown_initiated_by_peer(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_shutdown_complete(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_local_address_changed(QuicerConnCTX *c_ctx,
                                              QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_peer_address_changed(QuicerConnCTX *c_ctx,
                                             QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_peer_stream_started(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event, void *stream_callback);

static QUIC_STATUS
handle_connection_event_streams_available(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_peer_needs_streams(QuicerConnCTX *c_ctx,
                                           QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_ideal_processor_changed(QuicerConnCTX *c_ctx,
                                                QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_datagram_state_changed(QuicerConnCTX *c_ctx,
                                               QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_datagram_received(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_datagram_send_state_changed(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS
handle_connection_event_resumed(QuicerConnCTX *c_ctx,
                                QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_resumption_ticket_received(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event);

static QUIC_STATUS handle_connection_event_peer_certificate_received(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event);

void
dump_sslkeylogfile(_In_z_ const char *FileName,
                   _In_ QUIC_TLS_SECRETS TlsSecrets)
{
  FILE *File = NULL;
#ifdef _WIN32
  if (fopen_s(&File, FileName, "ab"))
    {
      printf("Failed to open sslkeylogfile %s\n", FileName);
      return;
    }
#else
  File = fopen(FileName, "ab");
#endif

  if (File == NULL)
    {
      printf("Failed to open sslkeylogfile %s\n", FileName);
      return;
    }
  if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0)
    {
      fprintf(File, "# TLS 1.3 secrets log file\n");
    }
  char
      ClientRandomBuffer[(2 * sizeof(((QUIC_TLS_SECRETS *)NULL)->ClientRandom))
                         + 1]
      = { 0 };
  char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = { 0 };
  if (TlsSecrets.IsSet.ClientRandom)
    {
      EncodeHexBuffer(TlsSecrets.ClientRandom,
                      (uint8_t)sizeof(TlsSecrets.ClientRandom),
                      ClientRandomBuffer);
    }

  if (TlsSecrets.IsSet.ClientEarlyTrafficSecret)
    {
      EncodeHexBuffer(TlsSecrets.ClientEarlyTrafficSecret,
                      TlsSecrets.SecretLength,
                      TempHexBuffer);
      fprintf(File,
              "CLIENT_EARLY_TRAFFIC_SECRET %s %s\n",
              ClientRandomBuffer,
              TempHexBuffer);
    }

  if (TlsSecrets.IsSet.ClientHandshakeTrafficSecret)
    {
      EncodeHexBuffer(TlsSecrets.ClientHandshakeTrafficSecret,
                      TlsSecrets.SecretLength,
                      TempHexBuffer);
      fprintf(File,
              "CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
              ClientRandomBuffer,
              TempHexBuffer);
    }

  if (TlsSecrets.IsSet.ServerHandshakeTrafficSecret)
    {
      EncodeHexBuffer(TlsSecrets.ServerHandshakeTrafficSecret,
                      TlsSecrets.SecretLength,
                      TempHexBuffer);
      fprintf(File,
              "SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
              ClientRandomBuffer,
              TempHexBuffer);
    }

  if (TlsSecrets.IsSet.ClientTrafficSecret0)
    {
      EncodeHexBuffer(TlsSecrets.ClientTrafficSecret0,
                      TlsSecrets.SecretLength,
                      TempHexBuffer);
      fprintf(File,
              "CLIENT_TRAFFIC_SECRET_0 %s %s\n",
              ClientRandomBuffer,
              TempHexBuffer);
    }

  if (TlsSecrets.IsSet.ServerTrafficSecret0)
    {
      EncodeHexBuffer(TlsSecrets.ServerTrafficSecret0,
                      TlsSecrets.SecretLength,
                      TempHexBuffer);
      fprintf(File,
              "SERVER_TRAFFIC_SECRET_0 %s %s\n",
              ClientRandomBuffer,
              TempHexBuffer);
    }

  fflush(File);
  fclose(File);
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection,
                             _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)Context;
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  BOOLEAN is_destroy = FALSE;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;

  assert(Connection == c_ctx->Connection);
  if (!(Connection == c_ctx->Connection))
    {
      c_ctx->Connection = Connection;
    }

  enif_mutex_lock(c_ctx->lock);
  TP_CB_3(event, (uintptr_t)Connection, Event->Type);
  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      // A monitor is automatically removed when it triggers or when the
      // resource is deallocated.
      status = handle_connection_event_connected(c_ctx, Event);
      // Client dump SSL KEY
      if (NULL != c_ctx->TlsSecrets && NULL != c_ctx->ssl_keylogfile)
        {
          dump_sslkeylogfile(c_ctx->ssl_keylogfile, *(c_ctx->TlsSecrets));
        }
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      //
      // The peer has started/created a new stream. The app MUST set the
      // callback handler before returning.
      //
      status = handle_connection_event_peer_stream_started(
          c_ctx, Event, ClientStreamCallback);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      status = handle_connection_event_shutdown_initiated_by_transport(c_ctx,
                                                                       Event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      status
          = handle_connection_event_shutdown_initiated_by_peer(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      // This is special case for client,
      // it could happen that the connection is opened but never get started.
      // @see async_connect3
      // in this case, we don't need to report closed to the owner
      if (!c_ctx->is_closed) // owner doesn't know it is closed
        {
          report = enif_make_tuple3(
              env, ATOM_QUIC, ATOM_CLOSED, enif_make_resource(env, c_ctx));

          enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
        }
      is_destroy = TRUE;
      c_ctx->is_closed = TRUE; // client shutdown completed
      break;

    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
      status = handle_connection_event_peer_address_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
      status = handle_connection_event_local_address_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
      status = handle_connection_event_streams_available(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
      status = handle_connection_event_peer_needs_streams(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      //
      // A resumption ticket (also called New Session Ticket or NST) was
      // received from the server.
      //
      //
      // The client wants to recv new session ticket in the mailbox
      status
          = handle_connection_event_resumption_ticket_received(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
      status = handle_connection_event_peer_certificate_received(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
      status = handle_connection_event_datagram_state_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      status
          = handle_connection_event_datagram_send_state_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
      status = handle_connection_event_datagram_received(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED:
      status = handle_connection_event_ideal_processor_changed(c_ctx, Event);
    default:
      break;
    }
  enif_clear_env(c_ctx->env);
  enif_mutex_unlock(c_ctx->lock);

  if (is_destroy)
    {
      destroy_c_ctx(c_ctx);
    }
  return status;
}

QUIC_STATUS
ServerConnectionCallback(HQUIC Connection,
                         void *Context,
                         QUIC_CONNECTION_EVENT *Event)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)Context;
  ErlNifEnv *env = c_ctx->env;
  BOOLEAN is_destroy = FALSE;

  assert(Connection == c_ctx->Connection);

  if (!(Connection == c_ctx->Connection))
    {
      c_ctx->Connection = Connection;
    }

  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  enif_mutex_lock(c_ctx->lock);
  TP_CB_3(event, (uintptr_t)Connection, Event->Type);
  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      status = handle_connection_event_connected(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      status = handle_connection_event_shutdown_initiated_by_transport(c_ctx,
                                                                       Event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      status
          = handle_connection_event_shutdown_initiated_by_peer(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      status = handle_connection_event_shutdown_complete(c_ctx, Event);
      c_ctx->is_closed = TRUE; // server shutdown_complete
      is_destroy = TRUE;
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      //
      // The peer has started/created a new stream. The app MUST set the
      // callback handler before returning.
      //
      status = handle_connection_event_peer_stream_started(
          c_ctx, Event, (void *)ServerStreamCallback);
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      //
      // The connection succeeded in doing a TLS resumption of a previous
      // connection's session.
      //
      status = handle_connection_event_resumed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
      status = handle_connection_event_datagram_state_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
      status
          = handle_connection_event_datagram_send_state_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
      status = handle_connection_event_datagram_received(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
      status = handle_connection_event_peer_address_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
      status = handle_connection_event_local_address_changed(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
      status = handle_connection_event_streams_available(c_ctx, Event);
      break;
    case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
      status = handle_connection_event_peer_needs_streams(c_ctx, Event);
      break;

    default:
      break;
    }
  enif_clear_env(env);
  enif_mutex_unlock(c_ctx->lock);

  if (is_destroy)
    {
      destroy_c_ctx(c_ctx);
    }

  return status;
}

ERL_NIF_TERM
async_connect3(ErlNifEnv *env,
               __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;

  ERL_NIF_TERM ehost = argv[0];
  ERL_NIF_TERM eport = argv[1];
  ERL_NIF_TERM eoptions = argv[2];
  ERL_NIF_TERM NST; // New Session Ticket
  // Usually we should not get this error
  // If we get it is internal logic error
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);

  int port = 0;
  char host[256] = { 0 };

  if (!enif_get_int(env, eport, &port) && port > 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (enif_get_string(env, ehost, host, 256, ERL_NIF_LATIN1) <= 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerConnCTX *c_ctx = init_c_ctx();

  // allocate config_resource for client connection
  c_ctx->config_resource
      = enif_alloc_resource(ctx_config_t, sizeof(QuicerConfigCTX));

  if ((c_ctx->owner = AcceptorAlloc()) == NULL)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto Error;
    }

  if (!enif_self(env, &(c_ctx->owner->Pid)))
    {
      res = ERROR_TUPLE_2(ATOM_BAD_PID);
      goto Error;
    }

  enif_monitor_process(NULL, c_ctx, &c_ctx->owner->Pid, &c_ctx->owner_mon);

  // convert eoptions to Configuration
  ERL_NIF_TERM estatus = ClientLoadConfiguration(
      env, &eoptions, &(c_ctx->config_resource->Configuration), true);
  if (!IS_SAME_TERM(ATOM_OK, estatus))
    {
      res = ERROR_TUPLE_2(ATOM_CONFIG_ERROR);
      goto Error;
    }

  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(GRegistration,
                                                  ClientConnectionCallback,
                                                  c_ctx,
                                                  &(c_ctx->Connection))))
    {
      res = ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
      goto Error;
    }

  ERL_NIF_TERM essl_keylogfile;
  if (enif_get_map_value(
          env, eoptions, ATOM_SSL_KEYLOGFILE_NAME, &essl_keylogfile))
    {
      char *keylogfile = CXPLAT_ALLOC_NONPAGED(PATH_MAX, QUICER_TRACE);
      if (enif_get_string(
              env, essl_keylogfile, keylogfile, PATH_MAX, ERL_NIF_LATIN1)
          > 0)
        {
          QUIC_TLS_SECRETS *TlsSecrets = CXPLAT_ALLOC_NONPAGED(
              sizeof(QUIC_TLS_SECRETS), QUICER_TLS_SECRETS);

          CxPlatZeroMemory(TlsSecrets, sizeof(QUIC_TLS_SECRETS));
          Status = MsQuic->SetParam(c_ctx->Connection,
                                    QUIC_PARAM_CONN_TLS_SECRETS,
                                    sizeof(QUIC_TLS_SECRETS),
                                    TlsSecrets);
          if (QUIC_FAILED(Status))
            {
              fprintf(stderr,
                      "failed to enable secret logging: %s",
                      QuicStatusToString(Status));
            }
          c_ctx->TlsSecrets = TlsSecrets;
          c_ctx->ssl_keylogfile = keylogfile;
        }

      else
        {
          fprintf(stderr, "failed to read string ssl_keylogfile");
        }
    }

  ERL_NIF_TERM evalue;
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS, &evalue))
    {
      if (!IS_SAME_TERM(ATOM_OK,
                        set_connection_opt(env,
                                           c_ctx,
                                           ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS,
                                           evalue,
                                           ATOM_FALSE)))
        {
          res = ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
          goto Error;
        }
    }

  if (enif_get_map_value(env,
                         eoptions,
                         ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                         &evalue))
    {
      if (!IS_SAME_TERM(
              ATOM_OK,
              set_connection_opt(env,
                                 c_ctx,
                                 ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                                 evalue,
                                 ATOM_FALSE)))
        {
          res = ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
          goto Error;
        }
    }

  if (enif_get_map_value(env, eoptions, ATOM_HANDLER, &NST))
    {
      // Resume connection with Old Connection Handler
      //
      QuicerConnCTX *old_c_ctx = NULL;
      if (!enif_get_resource(env, NST, ctx_connection_t, (void **)&old_c_ctx))
        {
          return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
        }
      else
        {
          // lock it, we need go to Error in case of Error to release the lock
          enif_mutex_lock(old_c_ctx->lock);
          QUIC_BUFFER *ticket = old_c_ctx->ResumptionTicket;
          if (QUIC_FAILED(Status
                          = MsQuic->SetParam(c_ctx->Connection,
                                             QUIC_PARAM_CONN_RESUMPTION_TICKET,
                                             ticket->Length,
                                             ticket->Buffer)))
            {
              res = ERROR_TUPLE_3(ATOM_ERROR_NOT_FOUND, ATOM_STATUS(Status));
              enif_mutex_unlock(old_c_ctx->lock);
              goto Error;
            }
          enif_mutex_unlock(old_c_ctx->lock);
        }
    }
  else if (enif_get_map_value(env, eoptions, ATOM_NST, &NST))
    {
      // Resume connection with NST binary
      //
      //
      ErlNifBinary ticket;
      if (!enif_inspect_binary(env, NST, &ticket) || ticket.size > UINT32_MAX)
        {
          res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
          goto Error;
        }
      else
        {
          if (QUIC_FAILED(Status
                          = MsQuic->SetParam(c_ctx->Connection,
                                             QUIC_PARAM_CONN_RESUMPTION_TICKET,
                                             ticket.size,
                                             ticket.data)))
            {
              res = ERROR_TUPLE_3(ATOM_ERROR_NOT_FOUND, ATOM_STATUS(Status));
              goto Error;
            }
        }
    }

  // This is optional
  get_uint32_from_map(env, eoptions, ATOM_QUIC_EVENT_MASK, &c_ctx->event_mask);

  // @TODO client async_connect_3 should able to take a config_resource as
  // input ERL TERM so that we don't need to call ClientLoadConfiguration
  //
  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(
                      c_ctx->Connection,
                      c_ctx->config_resource->Configuration,
                      QUIC_ADDRESS_FAMILY_UNSPEC,
                      host,
                      port)))
    {
      res = ERROR_TUPLE_2(ATOM_CONN_START_ERROR);
      enif_release_resource(c_ctx->config_resource);
      goto Error;
    }
  c_ctx->is_closed = FALSE; // connection started
  ERL_NIF_TERM eHandler = enif_make_resource(env, c_ctx);

  return SUCCESS(eHandler);

Error:
  // Error exit, it must not be started!
  assert(c_ctx->is_closed);

  if (c_ctx->Connection)
    { // when is opened

      /*
       We should not call *destroy_c_ctx* from here.
       because it could cause race cond:

       MsQuic Worker:

         Connection close job will trigger ClientConnectionCallback with event:
         QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE

       Beam Schedler:
         release c_ctx by calling *destroy_c_ctx* will trigger
       *resource_conn_dealloc_callback*

       The c_ctx could be freed (unprotectable) by beam while
       ClientConnectionCallback can still access it.

       So the side effect chain will be:

       'MsQuic->ConnectionClose' triggers 'ClientConnectionCallback' triggers
       'release c_ctx resource' triggers resource_conn_dealloc_callback' and
       then 'free c_ctx'. At this point both resources in beam and MsQuic is
        released.

       note 1:

       If we only call *destroy_c_ctx* triggers
       *resource_conn_dealloc_callback* triggers  'MsQuic->ConnectionClose'
       triggers ClientConnectionCallback here it can casue race cond. since
       c_ctx has been freed by beam already after
       resource_conn_dealloc_callback is finished.

       note 2:
       We could not call MsQuic->SetCallbackHandler to set callback to NULL
       becasue this function is async, not thread safe.

       */
      MsQuic->ConnectionClose(c_ctx->Connection);
      // prevent double ConnectionClose
      c_ctx->Connection = NULL;
    }
  return res;
}

ERL_NIF_TERM
async_accept2(ErlNifEnv *env,
              __unused_parm__ int argc,
              const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM listener = argv[0];
  ERL_NIF_TERM conn_opts = argv[1];
  QuicerListenerCTX *l_ctx = NULL;
  if (!enif_get_resource(env, listener, ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  ACCEPTOR *acceptor = AcceptorAlloc();
  if (!acceptor)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  if (!enif_self(env, &(acceptor->Pid)))
    {
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  if (!create_settings(env, &conn_opts, &acceptor->Settings))
    {
      AcceptorDestroy(acceptor);
      return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
    }

  AcceptorEnqueue(l_ctx->acceptor_queue, acceptor);

  assert(enif_is_process_alive(env, &(acceptor->Pid)));

  ERL_NIF_TERM listenHandler = enif_make_resource(env, l_ctx);
  return SUCCESS(listenHandler);
}

ERL_NIF_TERM
shutdown_connection3(ErlNifEnv *env,
                     __unused_parm__ int argc,
                     const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  uint32_t app_errcode = 0, flags = 0;
  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!c_ctx->Connection)
    {
      // already closed
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }

  if (!enif_get_uint(env, argv[1], &flags))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_uint(env, argv[2], &app_errcode))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  MsQuic->ConnectionShutdown(c_ctx->Connection, flags, app_errcode);
  return ATOM_OK;
}

ERL_NIF_TERM
sockname1(ErlNifEnv *env, __unused_parm__ int args, const ERL_NIF_TERM argv[])
{
  void *q_ctx;
  HQUIC Handle = NULL;
  uint32_t Param;

  if (enif_get_resource(env, argv[0], ctx_connection_t, &q_ctx))
    {
      enif_mutex_lock(((QuicerConnCTX *)q_ctx)->lock);
      enif_mutex_unlock(((QuicerConnCTX *)q_ctx)->lock);
      Handle = (((QuicerConnCTX *)q_ctx))->Connection;
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
    }
  else if (enif_get_resource(env, argv[0], ctx_listener_t, &q_ctx))
    {
      Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QUIC_STATUS status;
  QUIC_ADDR addr;
  uint32_t addrSize = sizeof(addr);

  if (QUIC_FAILED(status = MsQuic->GetParam(Handle, Param, &addrSize, &addr)))
    {
      return ERROR_TUPLE_2(ATOM_SOCKNAME_ERROR); // @TODO is this err useful?
                                                 // use ATOM_STATUS instead?
    }

  return SUCCESS(addr2eterm(env, &addr));
}

ERL_NIF_TERM
addr2eterm(ErlNifEnv *env, QUIC_ADDR *addr)
{
  if (addr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6)
    {
      uint16_t *ip = (uint16_t *)&addr->Ipv6.sin6_addr;
      return enif_make_tuple2(
          env,
          enif_make_tuple8(env,
                           enif_make_int(env, ntohs(ip[0])),
                           enif_make_int(env, ntohs(ip[1])),
                           enif_make_int(env, ntohs(ip[2])),
                           enif_make_int(env, ntohs(ip[3])),
                           enif_make_int(env, ntohs(ip[4])),
                           enif_make_int(env, ntohs(ip[5])),
                           enif_make_int(env, ntohs(ip[6])),
                           enif_make_int(env, ntohs(ip[7]))),
          enif_make_int(env, addr->Ipv6.sin6_port));
    }
  else
    {
      uint8_t *ip = (uint8_t *)&addr->Ipv4.sin_addr.s_addr;
      return enif_make_tuple2(env,
                              enif_make_tuple4(env,
                                               enif_make_int(env, ip[0]),
                                               enif_make_int(env, ip[1]),
                                               enif_make_int(env, ip[2]),
                                               enif_make_int(env, ip[3])),
                              enif_make_int(env, ntohs(addr->Ipv4.sin_port)));
    }
}

ERL_NIF_TERM
get_conn_rid1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  if (1 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return SUCCESS(enif_make_ulong(env, (unsigned long)c_ctx->Connection));
}

QUIC_STATUS
continue_connection_handshake(QuicerConnCTX *c_ctx)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  if (!c_ctx)
    {
      return QUIC_STATUS_INTERNAL_ERROR;
    }

  if (QUIC_FAILED(
          Status = MsQuic->ConnectionSetConfiguration(
              c_ctx->Connection, c_ctx->config_resource->Configuration)))
    {
      return Status;
    }

  // Apply connection owners' option overrides
  if (QUIC_FAILED(Status = MsQuic->SetParam(c_ctx->Connection,
                                            QUIC_PARAM_CONN_SETTINGS,
                                            sizeof(QUIC_SETTINGS),
                                            &c_ctx->owner->Settings)))
    {
      return Status;
    }
  return Status;
}

ERL_NIF_TERM
async_handshake_1(ErlNifEnv *env,
                  __unused_parm__ int argc,
                  const ERL_NIF_TERM argv[])

{
  QuicerConnCTX *c_ctx;
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM res = ATOM_OK;
  if (1 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  TP_NIF_3(start, (uintptr_t)c_ctx->Connection, 0);

  if (QUIC_FAILED(Status = continue_connection_handshake(c_ctx)))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(Status));
    }
  return res;
}

void
handle_dgram_state_event(QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event)
{
  if (Event->DATAGRAM_STATE_CHANGED.SendEnabled == 1)
    {
      ErlNifEnv *env = c_ctx->env;
      int max_len = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
      enif_send(NULL,
                &(c_ctx->owner->Pid),
                NULL,
                enif_make_tuple3(env,
                                 ATOM_QUIC,
                                 ATOM_DGRAM_MAX_LEN,
                                 enif_make_int(env, max_len)));
    }
}

void
handle_dgram_send_state_event(QuicerConnCTX *c_ctx,
                              QUIC_CONNECTION_EVENT *Event)
{
  ErlNifEnv *env = c_ctx->env;
  if (Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT)
    {
      QuicerDgramSendCTX *dgram_send_ctx
          = (QuicerDgramSendCTX *)(Event->DATAGRAM_SEND_STATE_CHANGED
                                       .ClientContext);
      enif_send(NULL,
                &dgram_send_ctx->caller,
                NULL,
                enif_make_tuple3(env,
                                 ATOM_QUIC,
                                 ATOM_SEND_DGRAM_COMPLETE,
                                 enif_make_resource(env, c_ctx)));
      destroy_dgram_send_ctx(dgram_send_ctx);
    }
}

void
handle_dgram_recv_event(QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event)
{
  ErlNifEnv *env = c_ctx->env;
  ErlNifBinary bin;
  ERL_NIF_TERM report;
  enif_alloc_binary(Event->DATAGRAM_RECEIVED.Buffer->Length, &bin);
  CxPlatCopyMemory(bin.data,
                   Event->DATAGRAM_RECEIVED.Buffer->Buffer,
                   Event->DATAGRAM_RECEIVED.Buffer->Length);
  bin.size = Event->DATAGRAM_RECEIVED.Buffer->Length;
  report = enif_make_tuple3(
      env, ATOM_QUIC, ATOM_DGRAM, enif_make_binary(env, &bin));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
}

static QUIC_STATUS
handle_connection_event_connected(QuicerConnCTX *c_ctx,
                                  __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_CONNECTED == Event->Type);
  assert(c_ctx->Connection);
  ACCEPTOR *acc = c_ctx->owner;
  assert(acc);
  ErlNifPid *acc_pid = &(acc->Pid);

  // A monitor is automatically removed when it triggers or when the
  // resource is deallocated.
  enif_monitor_process(NULL, c_ctx, acc_pid, &c_ctx->owner_mon);

  ERL_NIF_TERM ConnHandler = enif_make_resource(c_ctx->env, c_ctx);
  // testing this, just unblock accecptor
  // should pick a 'acceptor' here?
  if (!enif_send(NULL,
                 acc_pid,
                 NULL,
                 enif_make_tuple3(
                     c_ctx->env, ATOM_QUIC, ATOM_CONNECTED, ConnHandler)))
    {
      return QUIC_STATUS_UNREACHABLE;
    }

  MsQuic->ConnectionSendResumptionTicket(
      c_ctx->Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_shutdown_initiated_by_transport(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_TRANS_SHUTDOWN,
      enif_make_resource(env, c_ctx),
      ATOM_STATUS(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));

  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_shutdown_initiated_by_peer(
    QuicerConnCTX *c_ctx, __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  report = enif_make_tuple3(
      env, ATOM_QUIC, ATOM_SHUTDOWN, enif_make_resource(env, c_ctx));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_shutdown_complete(
    QuicerConnCTX *c_ctx, __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  // For Server Only
  assert(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;

  TP_CB_3(shutdown_complete,
          (uintptr_t)c_ctx->Connection,
          Event->SHUTDOWN_COMPLETE.AppCloseInProgress);
  report = enif_make_tuple3(
      env, ATOM_QUIC, ATOM_CLOSED, enif_make_resource(env, c_ctx));

  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_local_address_changed(QuicerConnCTX *c_ctx,
                                              QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  QUIC_ADDR_STR addrStr = { 0 };
  QuicAddrToString(Event->LOCAL_ADDRESS_CHANGED.Address, &addrStr);
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_LOCAL_ADDRESS_CHANGED,
      enif_make_resource(env, c_ctx),
      enif_make_string(env, addrStr.Address, ERL_NIF_LATIN1));

  if (!enif_send(NULL, &(c_ctx->owner->Pid), NULL, report))
    {
      // Owner is gone, we shutdown our side as well.
      MsQuic->ConnectionShutdown(c_ctx->Connection,
                                 QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 QUIC_STATUS_UNREACHABLE);
    }
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_peer_address_changed(QuicerConnCTX *c_ctx,
                                             QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  QUIC_ADDR_STR addrStr = { 0 };
  QuicAddrToString(Event->PEER_ADDRESS_CHANGED.Address, &addrStr);
  report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_PEER_ADDRESS_CHANGED,
      enif_make_resource(env, c_ctx),
      enif_make_string(env, addrStr.Address, ERL_NIF_LATIN1));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_peer_stream_started(QuicerConnCTX *c_ctx,
                                            QUIC_CONNECTION_EVENT *Event,
                                            void *stream_callback)

{
  assert(QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ErlNifPid *acc_pid = NULL;

  QuicerStreamCTX *s_ctx = init_s_ctx();
  enif_keep_resource(c_ctx);
  s_ctx->c_ctx = c_ctx;
  s_ctx->eHandler = enif_make_resource(s_ctx->imm_env, s_ctx);

  env = s_ctx->env;
  s_ctx->Stream = Event->PEER_STREAM_STARTED.Stream;

  ACCEPTOR *acc = AcceptorDequeue(c_ctx->acceptor_queue);

  if (!acc)
    {
      // If we don't have available process
      // fallback to the connection owner
      acc = AcceptorAlloc();
      if (!acc)
        {
          return QUIC_STATUS_UNREACHABLE;
        }
      // We must copy here, otherwise it will become double free
      // in resource dealloc callbacks (for Stream and Connection)
      memcpy(acc, c_ctx->owner, sizeof(ACCEPTOR));

      // @TODO we could set it to passive and let new owner set it to
      // active
      //  then old owner and new owner do not need to do handoff
      //  but that will buffer more in quic stack and hit limit control
      //  credit unsure what is the better solution.

      // acc->active = ACCEPTOR_RECV_MODE_PASSIVE;
    }

  assert(acc);
  acc_pid = &(acc->Pid);

  s_ctx->owner = acc;
  s_ctx->is_closed = FALSE;

  ERL_NIF_TERM report = enif_make_tuple4(
      env,
      ATOM_QUIC,
      ATOM_NEW_STREAM,
      enif_make_resource(env, s_ctx),
      enif_make_uint(env, Event->PEER_STREAM_STARTED.Flags));

  if (enif_send(NULL, acc_pid, NULL, report))
    {
      MsQuic->SetCallbackHandler(
          Event->PEER_STREAM_STARTED.Stream, stream_callback, s_ctx);
      // We should return success only when callback is set
      return QUIC_STATUS_SUCCESS;
    }
  else
    {
      return QUIC_STATUS_UNREACHABLE;
    }
}

static QUIC_STATUS
handle_connection_event_streams_available(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  report = enif_make_tuple5(
      env,
      ATOM_QUIC,
      ATOM_STREAMS_AVAILABLE,
      enif_make_resource(env, c_ctx),
      enif_make_uint(env, Event->STREAMS_AVAILABLE.BidirectionalCount),
      enif_make_uint(env, Event->STREAMS_AVAILABLE.UnidirectionalCount));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_peer_needs_streams(
    QuicerConnCTX *c_ctx, __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;
  report = enif_make_tuple3(
      env, ATOM_QUIC, ATOM_PEER_NEEDS_STREAMS, enif_make_resource(env, c_ctx));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_ideal_processor_changed(
    __unused_parm__ QuicerConnCTX *c_ctx,
    __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED == Event->Type);
  // @TODO ideal_processor_changed
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_datagram_state_changed(QuicerConnCTX *c_ctx,
                                               QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED == Event->Type);
  handle_dgram_state_event(c_ctx, Event);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_datagram_received(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED == Event->Type);
  handle_dgram_recv_event(c_ctx, Event);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_datagram_send_state_changed(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED == Event->Type);
  handle_dgram_send_state_event(c_ctx, Event);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_resumed(QuicerConnCTX *c_ctx,
                                QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_RESUMED == Event->Type);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM edata;
  ERL_NIF_TERM report;

  if (Event->RESUMED.ResumptionStateLength > 0
      && !Event->RESUMED.ResumptionState)
    {
      unsigned char *binbuff = enif_make_new_binary(
          env, Event->RESUMED.ResumptionStateLength, &edata);
      memcpy(binbuff,
             Event->RESUMED.ResumptionState,
             Event->RESUMED.ResumptionStateLength);
    }
  else
    {
      edata = ATOM_FALSE;
    }

  report = enif_make_tuple4(env,
                            ATOM_QUIC,
                            ATOM_CONN_RESUMED,
                            enif_make_resource(env, c_ctx),
                            edata);
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_resumption_ticket_received(
    QuicerConnCTX *c_ctx, QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED == Event->Type);
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;

  if (c_ctx->event_mask & QUICER_CONNECTION_EVENT_MASK_NST)
    {
      ERL_NIF_TERM ticket;
      unsigned char *ticket_buff = enif_make_new_binary(
          env,
          Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength,
          &ticket);
      if (ticket_buff && ticket)
        {

          CxPlatCopyMemory(
              ticket_buff,
              Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
              Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);

          report = enif_make_tuple4(env,
                                    ATOM_QUIC,
                                    ATOM_NST_RECEIVED,
                                    enif_make_resource(env, c_ctx),
                                    ticket);

          enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
        }
    }
  else // if QUICER_CONNECTION_EVENT_MASK_NST is unset in event_mask, we
       // just store it in the c_ctx
    {
      if (c_ctx->ResumptionTicket)
        {
          CXPLAT_FREE(c_ctx->ResumptionTicket, QUICER_RESUME_TICKET);
        }
      c_ctx->ResumptionTicket = (QUIC_BUFFER *)CXPLAT_ALLOC_NONPAGED(
          sizeof(QUIC_BUFFER)
              + Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength,
          QUICER_RESUME_TICKET);

      if (c_ctx->ResumptionTicket)
        {
          c_ctx->ResumptionTicket->Buffer
              = (uint8_t *)(c_ctx->ResumptionTicket + 1);
          c_ctx->ResumptionTicket->Length
              = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
          CxPlatCopyMemory(
              c_ctx->ResumptionTicket->Buffer,
              Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
              Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        }
    }
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_peer_certificate_received(
    __unused_parm__ QuicerConnCTX *c_ctx,
    __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  // @TODO peer_certificate_received
  // Only with QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED set
  assert(QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED == Event->Type);
  return QUIC_STATUS_SUCCESS;
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
