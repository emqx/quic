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

void
dump_sslkeylogfile(_In_z_ const char *FileName,
                   _In_ CXPLAT_TLS_SECRETS TlsSecrets)
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
  char ClientRandomBuffer
      [(2 * sizeof(((CXPLAT_TLS_SECRETS *)NULL)->ClientRandom)) + 1]
      = { 0 };
  char TempHexBuffer[(2 * CXPLAT_TLS_SECRETS_MAX_SECRET_LEN) + 1] = { 0 };
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
  QuicerStreamCTX *s_ctx = NULL;
  ErlNifEnv *env = c_ctx->env;
  ERL_NIF_TERM report;

  enif_mutex_lock(c_ctx->lock);
  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      // A monitor is automatically removed when it triggers or when the
      // resource is deallocated.
      enif_monitor_process(NULL, c_ctx, &c_ctx->owner->Pid, &c_ctx->owner_mon);
      if (!enif_send(NULL,
                     &(c_ctx->owner->Pid),
                     NULL,
                     enif_make_tuple3(env,
                                      ATOM_QUIC,
                                      ATOM_CONNECTED,
                                      enif_make_resource(env, c_ctx))))
        {
          enif_mutex_unlock(c_ctx->lock);
          return QUIC_STATUS_INTERNAL_ERROR;
        }
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
      // maybe alloc later
      s_ctx = init_s_ctx();

      // @fixit Stream context shouldn't be shared.
      s_ctx->Stream = Event->PEER_STREAM_STARTED.Stream;
      ACCEPTOR *acc = AcceptorDequeue(c_ctx->acceptor_queue);

      if (!acc)
        {
          destroy_s_ctx(s_ctx);
          enif_mutex_unlock(c_ctx->lock);
          return QUIC_STATUS_UNREACHABLE;
        }
      s_ctx->owner = acc;

      enif_monitor_process(NULL, s_ctx, &s_ctx->owner->Pid, &s_ctx->owner_mon);

      if (!enif_send(NULL,
                     &(acc->Pid),
                     NULL,
                     enif_make_tuple3(env,
                                      ATOM_QUIC,
                                      ATOM_NEW_STREAM,
                                      enif_make_resource(env, s_ctx))))
        {
          // @todo log and step counter
          MsQuic->ConnectionShutdown(Connection,
                                     QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                     QUIC_STATUS_ABORTED);
        }

      MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                 (void *)ClientStreamCallback,
                                 s_ctx);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      report = enif_make_tuple4(
          env,
          ATOM_QUIC,
          ATOM_TRANS_SHUTDOWN,
          enif_make_resource(env, c_ctx),
          enif_make_uint(env, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
      enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      report = enif_make_tuple3(
          env, ATOM_QUIC, ATOM_SHUTDOWN, enif_make_resource(env, c_ctx));

      if (!enif_send(NULL, &(c_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown our side as well.
          MsQuic->ConnectionShutdown(Connection,
                                     QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                     QUIC_STATUS_UNREACHABLE);
        }
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      report = enif_make_tuple3(
          env, ATOM_QUIC, ATOM_CLOSED, enif_make_resource(env, c_ctx));

      enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);

      if (!c_ctx->is_closed && !Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
          MsQuic->ConnectionClose(Connection);
          c_ctx->is_closed = TRUE;
        }

      destroy_c_ctx(c_ctx);
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      //
      // A resumption ticket (also called New Session Ticket or NST) was
      // received from the server.
      //
      //
      // @todo
      break;
    default:
      break;
    }
  enif_mutex_unlock(c_ctx->lock);
  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ServerConnectionCallback(HQUIC Connection,
                         void *Context,
                         QUIC_CONNECTION_EVENT *Event)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)Context;
  ACCEPTOR *acc = NULL;
  ErlNifPid *acc_pid = NULL;
  ERL_NIF_TERM report;
  ErlNifEnv *env = c_ctx->env;
  enif_mutex_lock(c_ctx->lock);
  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //

      assert(c_ctx->Connection == Connection);
      c_ctx->Connection = Connection;
      acc = c_ctx->owner;
      acc_pid = &(acc->Pid);

      if (!(acc && enif_is_process_alive(c_ctx->env, acc_pid)))
        {
          acc = AcceptorDequeue(
              c_ctx->l_ctx->acceptor_queue); // dequeue from listener queue!
          acc_pid = &(acc->Pid);
          if (!(acc && acc_pid && enif_is_process_alive(c_ctx->env, acc_pid)))
            {
              enif_mutex_unlock(c_ctx->lock);
              return QUIC_STATUS_UNREACHABLE;
            }
        }

      assert(acc);
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
          enif_mutex_unlock(c_ctx->lock);
          return QUIC_STATUS_UNREACHABLE;
        }

      MsQuic->ConnectionSendResumptionTicket(
          Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      /* printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, */
      /*        Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status); */
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      report = enif_make_tuple3(
          env, ATOM_QUIC, ATOM_SHUTDOWN, enif_make_resource(env, c_ctx));

      if (!enif_send(NULL, &(c_ctx->owner->Pid), NULL, report))
        {
          // Owner is gone, we shutdown our side as well.
          // connection shutdown could result a connection close
          if (!c_ctx->is_closed)
            {
              MsQuic->ConnectionShutdown(Connection,
                                         QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                         QUIC_STATUS_UNREACHABLE);
            }
        }

      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      report = enif_make_tuple3(
          env, ATOM_QUIC, ATOM_CLOSED, enif_make_resource(env, c_ctx));

      enif_send(NULL, &(c_ctx->owner->Pid), NULL, report);

      if (!c_ctx->is_closed && !Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
          MsQuic->ConnectionClose(Connection);
          c_ctx->is_closed = TRUE;
        }
      destroy_c_ctx(c_ctx);
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        // maybe alloc later
        ;
      QuicerStreamCTX *s_ctx = init_s_ctx();
      ErlNifEnv *env = s_ctx->env;
      s_ctx->Stream = Event->PEER_STREAM_STARTED.Stream;
      s_ctx->c_ctx = c_ctx;
      s_ctx->l_ctx = c_ctx->l_ctx;

      acc = AcceptorDequeue(c_ctx->acceptor_queue);

      if (!acc)
        {
          acc = c_ctx->owner;
        }

      assert(acc);
      acc_pid = &(acc->Pid);

      s_ctx->owner = acc;

      // @todo add monitor here.
      if (!enif_send(NULL,
                     acc_pid,
                     NULL,
                     enif_make_tuple3(env,
                                      ATOM_QUIC,
                                      ATOM_NEW_STREAM,
                                      enif_make_resource(env, s_ctx))))
        {
          // @todo log and step counter
          // @todo, maybe we should just return error code and let msquic
          // shutdown the connection gracefully.
          // @todo, check rfc for the error code
          MsQuic->ConnectionShutdown(
              Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
          enif_mutex_unlock(s_ctx->lock);
          return QUIC_STATUS_UNREACHABLE;
        }
      else
        {
          MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                     (void *)ServerStreamCallback,
                                     s_ctx);
        }
      break;
    case QUIC_CONNECTION_EVENT_RESUMED:
      //
      // The connection succeeded in doing a TLS resumption of a previous
      // connection's session.
      //
      break;
    default:
      break;
    }

  enif_mutex_unlock(c_ctx->lock);
  return QUIC_STATUS_SUCCESS;
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

  int port = 0;
  char host[256] = { 0 };

  if (!enif_get_int(env, eport, &port) && port > 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_string(env, ehost, host, 256, ERL_NIF_LATIN1))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerConnCTX *c_ctx = init_c_ctx();
  c_ctx->owner = AcceptorAlloc();

  if (!enif_self(env, &(c_ctx->owner->Pid)))
    {
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  ERL_NIF_TERM estatus
      = ClientLoadConfiguration(env, &eoptions, &(c_ctx->Configuration), true);
  if (!IS_SAME_TERM(ATOM_OK, estatus))
    {
      return ERROR_TUPLE_2(ATOM_CONFIG_ERROR);
    }

  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
                                                  ClientConnectionCallback,
                                                  c_ctx,
                                                  &(c_ctx->Connection))))
    {
      destroy_c_ctx(c_ctx);
      return ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
    }

  ERL_NIF_TERM essl_keylogfile;
  if (enif_get_map_value(
          env, eoptions, ATOM_SSL_KEYLOGFILE_NAME, &essl_keylogfile))
    {
      char *keylogfile = CXPLAT_ALLOC_NONPAGED(PATH_MAX, QUICER_TRACE);
      if (enif_get_string(
              env, essl_keylogfile, keylogfile, PATH_MAX, ERL_NIF_LATIN1))
        {
          CXPLAT_TLS_SECRETS *TlsSecrets = CXPLAT_ALLOC_NONPAGED(
              sizeof(CXPLAT_TLS_SECRETS), QUICER_TLS_SECRETS);

          CxPlatZeroMemory(TlsSecrets, sizeof(CXPLAT_TLS_SECRETS));
          Status = MsQuic->SetParam(c_ctx->Connection,
                                    QUIC_PARAM_LEVEL_CONNECTION,
                                    QUIC_PARAM_CONN_TLS_SECRETS,
                                    sizeof(CXPLAT_TLS_SECRETS),
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

  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(c_ctx->Connection,
                                                   c_ctx->Configuration,
                                                   QUIC_ADDRESS_FAMILY_UNSPEC,
                                                   host,
                                                   port)))
    {
      MsQuic->ConnectionClose(c_ctx->Connection);
      destroy_c_ctx(c_ctx);
      return ERROR_TUPLE_2(ATOM_CONN_START_ERROR);
    }

  ERL_NIF_TERM eHandler = enif_make_resource(env, c_ctx);

  return SUCCESS(eHandler);
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
      return ERROR_TUPLE_2(ATOM_PARM_ERROR);
    }

  ERL_NIF_TERM IsFastConn;
  if (enif_get_map_value(env, conn_opts, ATOM_FAST_CONN, &IsFastConn))
    {
      acceptor->fast_conn = IS_SAME_TERM(IsFastConn, ATOM_TRUE);
    }

  AcceptorEnqueue(l_ctx->acceptor_queue, acceptor);

  assert(enif_is_process_alive(env, &(acceptor->Pid)));

  ERL_NIF_TERM listenHandler = enif_make_resource(env, l_ctx);
  return SUCCESS(listenHandler);
}

//@todo,  shutdown with error
ERL_NIF_TERM
close_connection1(ErlNifEnv *env,
                  __unused_parm__ int argc,
                  const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  enif_mutex_lock(c_ctx->lock);
  if (!c_ctx->is_closed)
    {
      c_ctx->is_closed = TRUE;
      MsQuic->ConnectionShutdown(c_ctx->Connection,
                                 //@todo, check rfc for the error code
                                 QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                 0);
    }
  enif_mutex_unlock(c_ctx->lock);
  return ATOM_OK;
}

ERL_NIF_TERM
sockname1(ErlNifEnv *env, __unused_parm__ int args, const ERL_NIF_TERM argv[])
{
  void *q_ctx;
  HQUIC Handle = NULL;
  uint32_t Param;
  QUIC_PARAM_LEVEL Level;

  if (enif_get_resource(env, argv[0], ctx_connection_t, &q_ctx))
    {
      Handle = ((QuicerConnCTX *)q_ctx)->Connection;
      Level = QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
    }
  else if (enif_get_resource(env, argv[0], ctx_listener_t, &q_ctx))
    {
      Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
      Level = QUIC_PARAM_LEVEL_LISTENER;
      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
    }
  else if (enif_get_resource(env, argv[0], ctx_stream_t, &q_ctx))
    {
      Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
      Level = QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QUIC_STATUS status;
  QUIC_ADDR addr;
  uint32_t addrSize = sizeof(addr);

  if (QUIC_FAILED(status
                  = MsQuic->GetParam(Handle, Level, Param, &addrSize, &addr)))
    {
      return ERROR_TUPLE_2(ATOM_SOCKNAME_ERROR);
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

  if (!c_ctx || !(c_ctx->l_ctx))
    {
      return QUIC_STATUS_INTERNAL_ERROR;
    }

  if (QUIC_FAILED(Status = MsQuic->ConnectionSetConfiguration(
                      c_ctx->Connection, c_ctx->l_ctx->Configuration)))
    {
      return Status;
    }

  // Apply connection owners' option overrides
  if (QUIC_FAILED(Status = MsQuic->SetParam(c_ctx->Connection,
                                            QUIC_PARAM_LEVEL_CONNECTION,
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
  if (1 != argc)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  TP_NIF_3(start, c_ctx->Connection, 0);

  if (QUIC_FAILED(Status = continue_connection_handshake(c_ctx)))
    {
      return ERROR_TUPLE_2(atom_status(Status));
    }

  return ATOM_OK;
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
