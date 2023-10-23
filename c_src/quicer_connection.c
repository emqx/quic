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
#include "quicer_config.h"
#include "quicer_ctx.h"
#include "quicer_dgram.h"
#include "quicer_tls.h"
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <unistd.h>

extern QuicerRegistrationCTX *G_r_ctx;

#if defined(DEBUG) && !defined(QUICER_LOGGING_STDOUT)
extern inline void
EncodeHexBuffer(uint8_t *Buffer, uint8_t BufferLen, char *HexString);
#endif

extern inline const char *QuicStatusToString(QUIC_STATUS Status);

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

BOOLEAN
parse_registration(ErlNifEnv *env,
                   ERL_NIF_TERM options,
                   QuicerRegistrationCTX **r_ctx);

ERL_NIF_TERM parse_conn_local_address(ErlNifEnv *env,
                                      ERL_NIF_TERM eoptions,
                                      QuicerConnCTX *c_ctx);

ERL_NIF_TERM parse_conn_resume_ticket(ErlNifEnv *env,
                                      ERL_NIF_TERM eoptions,
                                      QuicerConnCTX *c_ctx);

ERL_NIF_TERM parse_conn_disable_1rtt_encryption(ErlNifEnv *env,
                                                ERL_NIF_TERM eoptions,
                                                QuicerConnCTX *c_ctx);

ERL_NIF_TERM parse_conn_event_mask(ErlNifEnv *env,
                                   ERL_NIF_TERM eoptions,
                                   QuicerConnCTX *c_ctx);

ERL_NIF_TERM
peercert1(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM DerCert;
  ERL_NIF_TERM res = ATOM_UNDEFINED;
  void *q_ctx;
  QuicerConnCTX *c_ctx;
  int len = 0;
  unsigned char *tmp;
  if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      c_ctx = ((QuicerStreamCTX *)q_ctx)->c_ctx;
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      c_ctx = (QuicerConnCTX *)q_ctx;
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  assert(c_ctx);
  enif_mutex_lock(c_ctx->lock);
  if (!c_ctx->peer_cert)
    {
      res = ERROR_TUPLE_2(ATOM_NO_PEERCERT);
      goto exit;
    }

  if ((len = i2d_X509(c_ctx->peer_cert, NULL)) < 0)
    {
      // unlikely to happen
      res = ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
      goto exit;
    }

  unsigned char *data = enif_make_new_binary(env, len, &DerCert);

  if (!data)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto exit;
    }

  // note, using tmp is mandatory, see doc for i2d_X590
  tmp = data;

  i2d_X509(c_ctx->peer_cert, &tmp);
  res = SUCCESS(DerCert);

exit:
  enif_mutex_unlock(c_ctx->lock);
  return res;
}

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
  BOOLEAN is_destroy = FALSE;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;

  // Connecion Handle must match unless NULL (closed)
  assert(Connection == c_ctx->Connection || NULL == c_ctx->Connection);

  if (Connection == NULL)
    {
      return status;
    }

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
      // @see async_connect3
      status = handle_connection_event_shutdown_complete(c_ctx, Event);
      is_destroy = TRUE;
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
  enif_clear_env(env);

  QuicerConfigCTX *conf_ctx = c_ctx->config_resource;
  if (is_destroy)
    {
      enif_mutex_lock(c_ctx->lock);
      c_ctx->is_closed = TRUE; // client shutdown completed
      c_ctx->config_resource = NULL;
      enif_mutex_unlock(c_ctx->lock);

      put_conn_handle(c_ctx);
      if (conf_ctx)
        {
          enif_release_resource(conf_ctx);
        }
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
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;

  // Connecion Handle must match unless NULL (closed)
  assert(Connection == c_ctx->Connection || NULL == c_ctx->Connection);

  if (Connection == NULL)
    {
      return status;
    }

  TP_CB_3(event, (uintptr_t)Connection, Event->Type);

  // dbg("server connection event: %d", Event->Type);

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
    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
      status = handle_connection_event_peer_certificate_received(c_ctx, Event);
      break;
    default:
      break;
    }
  enif_clear_env(env);

  QuicerConfigCTX *conf_ctx = c_ctx->config_resource;

  if (is_destroy)
    {
      enif_mutex_lock(c_ctx->lock);
      c_ctx->is_closed = TRUE; // server shutdown_complete
      c_ctx->config_resource = NULL;
      enif_mutex_unlock(c_ctx->lock);

      put_conn_handle(c_ctx);
      if (conf_ctx)
        {
          enif_release_resource(conf_ctx);
        }
      destroy_c_ctx(c_ctx);
    }
  return status;
}

/*
** Open connection handle only
** Set ownership but no monitoring.
*/
ERL_NIF_TERM
open_connectionX(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM eHandle;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
  QuicerRegistrationCTX *r_ctx = NULL;
  ERL_NIF_TERM options = argv[0];

  if (argc == 1)
    {
      // with validate quic_registration arg
      if (!parse_registration(env, options, &r_ctx))
        {
          return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
        }
    }

  // If r_ctx is unset, default to use global registration
  if (!r_ctx && !G_r_ctx)
    {
      return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
    }
  else
    {
      r_ctx = G_r_ctx;
    }

  if (!get_reg_handle(r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
    }

  QuicerConnCTX *c_ctx = init_c_ctx();

  if (!c_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  c_ctx->owner = AcceptorAlloc();
  if (!c_ctx->owner)
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto exit;
    }

  if (!enif_self(env, &(c_ctx->owner->Pid)))
    {
      res = ERROR_TUPLE_2(ATOM_BAD_PID);
      goto exit;
    }

  // It is safe to use r_ctx here since
  // a) it is passed as argument which beam still has reference to
  // b) G_r_ctx is only destroyed when code is unloaded.

  enif_keep_resource(r_ctx);
  c_ctx->r_ctx = r_ctx;
  enif_mutex_lock(r_ctx->lock);

  if (!r_ctx->Registration)
    {
      res = ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
      enif_mutex_unlock(r_ctx->lock);
      goto exit;
    }

  Status = MsQuic->ConnectionOpen(r_ctx->Registration,
                                  ClientConnectionCallback,
                                  c_ctx,
                                  &(c_ctx->Connection));
  enif_mutex_unlock(r_ctx->lock);

  if (QUIC_FAILED(Status))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(Status));
      goto exit;
    }

  if (!IS_SAME_TERM(ATOM_OK,
                    (res = parse_conn_resume_ticket(env, options, c_ctx))))
    {
      goto exit;
    }

  CxPlatRefInitialize(&(c_ctx->ref_count));
  eHandle = enif_make_resource(env, c_ctx);
  return SUCCESS(eHandle);

exit:
  enif_release_resource(r_ctx);
  enif_release_resource(c_ctx);
  return res;
}

ERL_NIF_TERM
async_connect3(ErlNifEnv *env,
               __unused_parm__ int argc,
               const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;
  ERL_NIF_TERM ehost = argv[0];
  ERL_NIF_TERM eport = argv[1];
  ERL_NIF_TERM eoptions = argv[2];
  ERL_NIF_TERM eHandle = ATOM_UNDEFINED;
  // Usually we should not get this error
  // If we get it is internal logic error
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);

  QuicerConnCTX *c_ctx = NULL;
  QuicerRegistrationCTX *r_ctx = NULL;
  BOOLEAN is_reuse_handle = FALSE;

  int port = 0;
  char host[256] = { 0 };

  HQUIC Registration = NULL;

  // Check Port
  if (!enif_get_int(env, eport, &port) && port > 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Check host
  if (enif_get_string(env, ehost, host, 256, ERL_NIF_LATIN1) <= 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Check option 'handle' for opened connection
  if (enif_get_map_value(env, eoptions, ATOM_HANDLE, &eHandle))
    {
      /* Reuse c_ctx from existing connecion handle */
      if (enif_get_resource(env, eHandle, ctx_connection_t, (void **)&c_ctx))
        {
          assert(c_ctx->is_closed);
          assert(c_ctx->owner);
          // r_ctx is already kept in open_connectionX
          r_ctx = c_ctx->r_ctx;
          is_reuse_handle = TRUE;
          if (!get_reg_handle(r_ctx))
            {
              return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
            }
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
        }
    }
  else
    {
      /* Alloc new c_ctx */
      assert(!is_reuse_handle);
      assert(!c_ctx);
      assert(!r_ctx);

      c_ctx = init_c_ctx();

      // Get Reg for c_ctx, quic_registration is optional
      if (!parse_registration(env, eoptions, &c_ctx->r_ctx))
        {
          enif_release_resource(c_ctx);
          return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
        }

      r_ctx = c_ctx->r_ctx ? c_ctx->r_ctx : G_r_ctx;

      if ((c_ctx->owner = AcceptorAlloc()) == NULL)
        {
          enif_release_resource(c_ctx);
          return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
        }

      // set owner
      if (!enif_self(env, &(c_ctx->owner->Pid)))
        {
          enif_release_resource(c_ctx);
          return ERROR_TUPLE_2(ATOM_BAD_PID);
        }

      if (!get_reg_handle(r_ctx))
        {
          enif_release_resource(c_ctx);
          return ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
        }
      enif_keep_resource(r_ctx);
    }

  assert(r_ctx);
  assert(c_ctx);

  // Now we have c_ctx either
  // a) passed in as handle
  // b) newly allocated
  if (is_reuse_handle)
    {
      enif_mutex_lock(c_ctx->lock);
    }

  Registration = r_ctx->Registration;
  assert(c_ctx->owner);

  // Allocate config_resource for client connection
  // @TODO client config handle should be reused if needed.
  if (NULL == (c_ctx->config_resource = init_config_ctx()))
    {
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
      goto Error;
    }

  // parse opt cacertfile
  char *cacertfile = NULL;
  if (!parse_cacertfile_option(env, eoptions, &cacertfile))
    {
      // TLS opt error not file content error
      res = ERROR_TUPLE_2(ATOM_CACERTFILE);
      goto Error;
    }

  if (cacertfile)
    {
      if (!build_trustedstore(cacertfile, &c_ctx->trusted))
        {
          free(cacertfile);
          res = ERROR_TUPLE_2(ATOM_CERT_ERROR);
          goto Error;
        }
      free(cacertfile);
      cacertfile = NULL;
    }

  // convert eoptions to Configuration
  ERL_NIF_TERM estatus = ClientLoadConfiguration(
      env, &eoptions, Registration, &(c_ctx->config_resource->Configuration));

  if (!IS_SAME_TERM(ATOM_OK, estatus))
    {
      res = ERROR_TUPLE_2(estatus);
      goto Error;
    }

  if (!is_reuse_handle)
    {
      if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
                                                      ClientConnectionCallback,
                                                      c_ctx,
                                                      &(c_ctx->Connection))))
        {
          assert(c_ctx->Connection == NULL);
          res = ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
        }
      else
        {
          assert(c_ctx->is_closed);
          CxPlatRefInitialize(&c_ctx->ref_count);
          res = parse_conn_resume_ticket(env, eoptions, c_ctx);
          // we could only lock it after resume ticket is set
          enif_mutex_lock(c_ctx->lock);
        }
      if (!IS_SAME_TERM(ATOM_OK, res))
        {
          goto Error;
        }
    }
  c_ctx->is_closed = FALSE; // connection opened.

  // optional set sslkeylogfile
  parse_sslkeylogfile_option(env, eoptions, c_ctx);

  if (!IS_SAME_TERM(ATOM_OK,
                    (res = parse_conn_local_address(env, eoptions, c_ctx))))
    {
      goto Error;
    }

  if (!IS_SAME_TERM(
          ATOM_OK,
          (res = parse_conn_disable_1rtt_encryption(env, eoptions, c_ctx))))
    {
      goto Error;
    }

  if (!IS_SAME_TERM(ATOM_OK,
                    (res = parse_conn_event_mask(env, eoptions, c_ctx))))
    {
      goto Error;
    }

  // @TODO client async_connect_3 should able to take a config_resource as
  // input ERL TERM so that we don't need to call ClientLoadConfiguration
  assert(!c_ctx->is_closed && c_ctx->Connection);

  assert(c_ctx->owner);

  // Monitor owner before start, so we don't need to race with callbacks
  // after start the connection
  enif_monitor_process(NULL, c_ctx, &c_ctx->owner->Pid, &c_ctx->owner_mon);

  // c_ctx->lock should be taken to prevent parallel access from callback as
  // work trigged by starting of the connection.
  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(
                      c_ctx->Connection,
                      c_ctx->config_resource->Configuration,
                      QUIC_ADDRESS_FAMILY_UNSPEC,
                      host,
                      port)))
    {
      AcceptorDestroy(c_ctx->owner);
      c_ctx->owner = NULL;

      if (Status != QUIC_STATUS_INVALID_PARAMETER)
        {
          c_ctx->Connection = NULL;
        }

      if (c_ctx->config_resource)
        {
          destroy_config_ctx(c_ctx->config_resource);
        }

      res = ERROR_TUPLE_2(ATOM_CONN_START_ERROR);
      TP_NIF_3(start_fail, (uintptr_t)(c_ctx->Connection), Status);
      goto Error;
    }

  eHandle = enif_make_resource(env, c_ctx);

  enif_mutex_unlock(c_ctx->lock);
  return SUCCESS(eHandle);

Error:
  put_reg_handle(r_ctx);
  HQUIC Connection = c_ctx->Connection;
  if (Connection)
    {
      /*
       Prevent double ConnectionClose
       @NOTE:
       We could not call MsQuic->SetCallbackHandler to set callback to NULL
       becasue this function is async, not thread safe.
       */
      c_ctx->Connection = NULL;
      c_ctx->is_closed = TRUE;
    }

  // Error exit, it must be closed or Handle is NULL
  assert(c_ctx->is_closed || NULL == c_ctx->Connection);
  enif_mutex_unlock(c_ctx->lock);

  if (Connection)
    {
      // @NOTE:
      // It will trigger 'connection shutdown completed' callback
      // thus it is important to not release the resource c_ctx for callback
      // to access the c_ctx
      MsQuic->ConnectionClose(Connection);
    }

  if (!is_reuse_handle)
    {
      enif_release_resource(r_ctx);
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
  ERL_NIF_TERM active_val = ATOM_TRUE;
  if (!enif_get_resource(env, listener, ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Set parm active is optional
  enif_get_map_value(
      env, conn_opts, ATOM_QUIC_STREAM_OPTS_ACTIVE, &active_val);

  ACCEPTOR *acceptor = AcceptorAlloc();
  if (!acceptor)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  if (!enif_self(env, &(acceptor->Pid)))
    {
      AcceptorDestroy(acceptor);
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  if (!set_owner_recv_mode(acceptor, env, active_val))
    {
      AcceptorDestroy(acceptor);
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!create_settings(env, &conn_opts, &acceptor->Settings))
    {
      AcceptorDestroy(acceptor);
      return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
    }

  AcceptorEnqueue(l_ctx->acceptor_queue, acceptor);

  assert(enif_is_process_alive(env, &(acceptor->Pid)));

  ERL_NIF_TERM listenHandle = enif_make_resource(env, l_ctx);
  return SUCCESS(listenHandle);
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

  if (get_conn_handle(c_ctx))
    {
      MsQuic->ConnectionShutdown(c_ctx->Connection, flags, app_errcode);
      put_conn_handle(c_ctx);
      return ATOM_OK;
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
}

ERL_NIF_TERM
sockname1(ErlNifEnv *env, __unused_parm__ int args, const ERL_NIF_TERM argv[])
{
  void *q_ctx;
  HQUIC Handle = NULL;
  uint32_t Param;
  QUIC_STATUS Status;
  QUIC_ADDR addr;
  uint32_t addrSize = sizeof(addr);

  if (enif_get_resource(env, argv[0], ctx_connection_t, &q_ctx))
    {
      if (!get_conn_handle((QuicerConnCTX *)q_ctx))
        {
          return ERROR_TUPLE_2(ATOM_CLOSED);
        }
      Handle = (((QuicerConnCTX *)q_ctx))->Connection;
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
      Status = MsQuic->GetParam(Handle, Param, &addrSize, &addr);
      put_conn_handle((QuicerConnCTX *)q_ctx);
    }
  else if (enif_get_resource(env, argv[0], ctx_listener_t, &q_ctx))
    {
      enif_mutex_lock(((QuicerListenerCTX *)q_ctx)->lock);
      Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
      Status = MsQuic->GetParam(Handle, Param, &addrSize, &addr);
      enif_mutex_unlock(((QuicerListenerCTX *)q_ctx)->lock);
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (QUIC_FAILED(Status))
    {
      return ERROR_TUPLE_2(ATOM_STATUS(Status));
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

  if (!c_ctx->Connection)
    {
      return QUIC_STATUS_INVALID_STATE;
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

/* handle conn connected event and deliver the message to the conn owner
   {quic, connected, connection_handle(), #{ is_resumed := boolean()
                                            , alpns = binary() | undefined
                                         }}
*/
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
  enif_mutex_lock(c_ctx->lock);
  enif_monitor_process(NULL, c_ctx, acc_pid, &c_ctx->owner_mon);
  enif_mutex_unlock(c_ctx->lock);

  ERL_NIF_TERM ConnHandle = enif_make_resource(c_ctx->env, c_ctx);

  uint8_t alpn_size = Event->CONNECTED.NegotiatedAlpnLength;
  const uint8_t *alpn_buff = Event->CONNECTED.NegotiatedAlpn;
  ERL_NIF_TERM ealpns;

  if (alpn_size > 0 && alpn_buff)
    {
      CxPlatCopyMemory(enif_make_new_binary(c_ctx->env, alpn_size, &ealpns),
                       alpn_buff,
                       alpn_size);
    }
  else
    {
      ealpns = ATOM_UNDEFINED;
    }

  ERL_NIF_TERM props_name[] = { ATOM_IS_RESUMED, ATOM_ALPNS };
  ERL_NIF_TERM props_value[]
      = { ATOM_BOOLEAN(Event->CONNECTED.SessionResumed), ealpns };

  ERL_NIF_TERM report = make_event_with_props(
      c_ctx->env, ATOM_CONNECTED, ConnHandle, props_name, props_value, 2);

  // testing this, just unblock acceptor
  // should pick a 'acceptor' here?
  if (!enif_send(NULL, acc_pid, NULL, report))
    {
      return QUIC_STATUS_UNREACHABLE;
    }
  // @TODO make it configurable
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

  ERL_NIF_TERM props_name[] = { ATOM_STATUS, ATOM_ERROR };
  ERL_NIF_TERM props_value[] = {
    ATOM_STATUS(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status),
    enif_make_uint64(env, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode),
  };

  ERL_NIF_TERM report = make_event_with_props(env,
                                              ATOM_TRANS_SHUTDOWN,
                                              enif_make_resource(env, c_ctx),
                                              props_name,
                                              props_value,
                                              2);
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
  ERL_NIF_TERM report
      = make_event(env,
                   ATOM_SHUTDOWN,
                   enif_make_resource(env, c_ctx),
                   ATOM_STATUS(Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_shutdown_complete(QuicerConnCTX *c_ctx,
                                          QUIC_CONNECTION_EVENT *Event)
{
  // For Server Only
  assert(QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE == Event->Type);
  assert(c_ctx->acceptor_queue);
  ACCEPTOR *acc = NULL;
  ErlNifEnv *env = c_ctx->env;
  TP_CB_3(shutdown_complete,
          (uintptr_t)c_ctx->Connection,
          Event->SHUTDOWN_COMPLETE.AppCloseInProgress);

  ERL_NIF_TERM props_name[] = { ATOM_IS_HANDSHAKE_COMPLETED,
                                ATOM_IS_PEER_ACKED,
                                ATOM_IS_APP_CLOSING };
  ERL_NIF_TERM props_value[]
      = { ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.HandshakeCompleted),
          ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown),
          ATOM_BOOLEAN(Event->SHUTDOWN_COMPLETE.AppCloseInProgress) };

  ERL_NIF_TERM report = make_event_with_props(env,
                                              ATOM_CLOSED,
                                              enif_make_resource(env, c_ctx),
                                              props_name,
                                              props_value,
                                              3);

  if (c_ctx->owner)
    {
      enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
    }
  //
  // Now inform the stream acceptors
  //
  assert(c_ctx->acceptor_queue);
  while ((acc = AcceptorDequeue(c_ctx->acceptor_queue)))
    {
      TP_CB_3(acceptor_bye, (uintptr_t)c_ctx->Connection, 0);
      report = make_event(env, ATOM_CLOSED, ATOM_UNDEFINED, ATOM_UNDEFINED);
      enif_send(NULL, &acc->Pid, NULL, report);
      AcceptorDestroy(acc);
    }
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_local_address_changed(QuicerConnCTX *c_ctx,
                                              QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  QUIC_ADDR_STR addrStr = { 0 };
  QuicAddrToString(Event->LOCAL_ADDRESS_CHANGED.Address, &addrStr);
  ERL_NIF_TERM report
      = make_event(env,
                   ATOM_LOCAL_ADDRESS_CHANGED,
                   enif_make_resource(env, c_ctx),
                   enif_make_string(env, addrStr.Address, ERL_NIF_LATIN1));
  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_peer_address_changed(QuicerConnCTX *c_ctx,
                                             QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED == Event->Type);
  assert(c_ctx->Connection);
  ErlNifEnv *env = c_ctx->env;
  QUIC_ADDR_STR addrStr = { 0 };
  QuicAddrToString(Event->PEER_ADDRESS_CHANGED.Address, &addrStr);
  ERL_NIF_TERM report
      = make_event(env,
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
  BOOLEAN is_orphan = FALSE;
  enif_keep_resource(c_ctx);
  s_ctx->c_ctx = c_ctx;
  s_ctx->eHandle = enif_make_resource(s_ctx->imm_env, s_ctx);

  // @TODO Generally, we rely on outer caller to clean the env,
  // or we should clean the env in this function.
  env = s_ctx->env;
  get_conn_handle(c_ctx);
  s_ctx->Stream = Event->PEER_STREAM_STARTED.Stream;
  CxPlatRefInitialize(&(s_ctx->ref_count));

  ACCEPTOR *acc = AcceptorDequeue(c_ctx->acceptor_queue);

  if (!acc)
    {
      // If we don't have available process
      // fallback to the connection owner
      TP_CB_3(no_acceptor, (uintptr_t)c_ctx->Connection, 0);
      is_orphan = TRUE;
      acc = AcceptorAlloc();
      if (!acc)
        {
          return QUIC_STATUS_UNREACHABLE;
        }
      // We must copy here, otherwise it will become double free
      // in resource dealloc callbacks (for Stream and Connection)
      CxPlatCopyMemory(acc, c_ctx->owner, sizeof(ACCEPTOR));

      // We set it to passive and let new owner set it to active after handoff
      // but that will buffer more in msquic stack and hit control limit.
      acc->active = ACCEPTOR_RECV_MODE_PASSIVE;
    }

  assert(acc);
  acc_pid = &(acc->Pid);

  s_ctx->owner = acc;
  s_ctx->is_closed = FALSE;

  ERL_NIF_TERM props_name[] = { ATOM_FLAGS, ATOM_IS_ORPHAN };
  ERL_NIF_TERM props_value[]
      = { enif_make_uint(env, Event->PEER_STREAM_STARTED.Flags),
          ATOM_BOOLEAN(is_orphan) };

  ERL_NIF_TERM report = make_event_with_props(env,
                                              ATOM_NEW_STREAM,
                                              enif_make_resource(env, s_ctx),
                                              props_name,
                                              props_value,
                                              2);
  if (enif_send(NULL, acc_pid, NULL, report))
    {
      MsQuic->SetCallbackHandler(
          Event->PEER_STREAM_STARTED.Stream, stream_callback, s_ctx);
      // We should return success only when callback is set
      return QUIC_STATUS_SUCCESS;
    }
  else
    {
      // NOTE: we must return non sucess status
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

  ERL_NIF_TERM props_name[] = { ATOM_BIDI_STREAMS, ATOM_UNIDI_STREAMS };
  ERL_NIF_TERM props_value[]
      = { enif_make_uint64(env, Event->STREAMS_AVAILABLE.BidirectionalCount),
          enif_make_uint64(env,
                           Event->STREAMS_AVAILABLE.UnidirectionalCount) };

  ERL_NIF_TERM report = make_event_with_props(env,
                                              ATOM_STREAMS_AVAILABLE,
                                              enif_make_resource(env, c_ctx),
                                              props_name,
                                              props_value,
                                              2);
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
  ERL_NIF_TERM report = make_event(env,
                                   ATOM_PEER_NEEDS_STREAMS,
                                   enif_make_resource(env, c_ctx),
                                   Event->PEER_NEEDS_STREAMS.Bidirectional
                                       ? ATOM_BIDI_STREAMS
                                       : ATOM_UNIDI_STREAMS);

  enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_ideal_processor_changed(
    __unused_parm__ QuicerConnCTX *c_ctx,
    __unused_parm__ QUIC_CONNECTION_EVENT *Event)
{
  assert(QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED == Event->Type);
  // @NOTE: improve performance if we could move owner proc closer to
  // the 'ideal processor'
  return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
handle_connection_event_datagram_state_changed(QuicerConnCTX *c_ctx,
                                               QUIC_CONNECTION_EVENT *Event)
{
  handle_dgram_state_changed_event(c_ctx, Event);
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
  if (Event->RESUMED.ResumptionStateLength > 0
      && !Event->RESUMED.ResumptionState)
    {
      unsigned char *binbuff = enif_make_new_binary(
          env, Event->RESUMED.ResumptionStateLength, &edata);
      CxPlatCopyMemory(binbuff,
                       Event->RESUMED.ResumptionState,
                       Event->RESUMED.ResumptionStateLength);
    }
  else
    {
      edata = ATOM_FALSE;
    }

  ERL_NIF_TERM report = make_event(
      env, ATOM_CONN_RESUMED, enif_make_resource(env, c_ctx), edata);
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

          report = make_event(
              env, ATOM_NST_RECEIVED, enif_make_resource(env, c_ctx), ticket);
          enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);
        }
    }
  else // if QUICER_CONNECTION_EVENT_MASK_NST is unset in event_mask, we
       // just store it in the c_ctx
       // @TODO:TBD maybe we don't need it at all.
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
handle_connection_event_peer_certificate_received(QuicerConnCTX *c_ctx,
                                                  QUIC_CONNECTION_EVENT *Event)
{
  // Only with QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED set
  assert(QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED == Event->Type);
  // Validate against CA certificates using OpenSSL API:s
  X509 *cert = (X509 *)Event->PEER_CERTIFICATE_RECEIVED.Certificate;

  // Preserve cert in ctx
  if (c_ctx->peer_cert)
    {
      X509_free(c_ctx->peer_cert);
    }
  c_ctx->peer_cert = X509_dup(cert);

  X509_STORE_CTX *x509_ctx
      = (X509_STORE_CTX *)Event->PEER_CERTIFICATE_RECEIVED.Chain;

  if (cert == NULL)
    return QUIC_STATUS_BAD_CERTIFICATE;

  STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(x509_ctx);

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, c_ctx->trusted, cert, untrusted);
  int res = X509_verify_cert(ctx);
  X509_STORE_CTX_free(ctx);

  if (res <= 0)
    return QUIC_STATUS_BAD_CERTIFICATE;
  else
    return QUIC_STATUS_SUCCESS;

  /* @TODO validate SNI */
}

/*
** parse optional conn opt: local addr
*/
ERL_NIF_TERM
parse_conn_local_address(ErlNifEnv *env,
                         ERL_NIF_TERM eoptions,
                         QuicerConnCTX *c_ctx)
{

  ERL_NIF_TERM evalue;
  ERL_NIF_TERM res = ATOM_OK;
  if (enif_get_map_value(
          env, eoptions, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS, &evalue))
    {
      return set_connection_opt(
          env, c_ctx, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS, evalue, ATOM_FALSE);
    }
  return res;
}

/*
** parse optional conn opt: disable_1rtt_encryption
*/
ERL_NIF_TERM
parse_conn_disable_1rtt_encryption(ErlNifEnv *env,
                                   ERL_NIF_TERM eoptions,
                                   QuicerConnCTX *c_ctx)
{
  ERL_NIF_TERM evalue;
  if (enif_get_map_value(env,
                         eoptions,
                         ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                         &evalue))
    {
      return set_connection_opt(env,
                                c_ctx,
                                ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                                evalue,
                                ATOM_FALSE);
    }
  return ATOM_OK;
}

/*
** parse optional conn opt: nst (resume_ticket)
**
** resume connection with NST binary
*/
ERL_NIF_TERM
parse_conn_resume_ticket(ErlNifEnv *env,
                         ERL_NIF_TERM eoptions,
                         QuicerConnCTX *c_ctx)
{
  ERL_NIF_TERM evalue;
  if (enif_get_map_value(env, eoptions, ATOM_NST, &evalue))
    {
      return set_connection_opt(env,
                                c_ctx,
                                ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET,
                                evalue,
                                ATOM_FALSE);
    }
  return ATOM_OK;
}

/*
 * parse optional conn opt: quic_event_mask
 *
 */
ERL_NIF_TERM
parse_conn_event_mask(ErlNifEnv *env,
                      ERL_NIF_TERM eoptions,
                      QuicerConnCTX *c_ctx)
{
  ERL_NIF_TERM evalue;
  if (enif_get_map_value(env, eoptions, ATOM_QUIC_EVENT_MASK, &evalue))
    {
      if (!enif_get_uint(env, evalue, &(c_ctx->event_mask)))
        {
          return ERROR_TUPLE_2(ATOM_QUIC_EVENT_MASK);
        }
    }
  return ATOM_OK;
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
