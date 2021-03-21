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
#include <assert.h>
#include <unistd.h>

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
    ClientConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
                             _Inout_ QUIC_CONNECTION_EVENT *Event)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)Context;
  QuicerStreamCTX *s_ctx = NULL;
  ErlNifEnv *env = c_ctx->env;
  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      // A monitor is automatically removed when it triggers or when the
      // resource is deallocated.
      enif_monitor_process(NULL, c_ctx, &c_ctx->owner->Pid, c_ctx->owner_mon);
      if (!enif_send(NULL, &(c_ctx->owner->Pid), NULL,
                     enif_make_tuple3(env, enif_make_atom(env, "quic"),
                                      enif_make_atom(env, "connected"),
                                      enif_make_resource(env, c_ctx))))
        {
          // @todo find yet another acceptor?
          return QUIC_STATUS_INTERNAL_ERROR;
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
          return QUIC_STATUS_UNREACHABLE;
        }
      s_ctx->owner = acc;

      enif_monitor_process(NULL, s_ctx, &s_ctx->owner->Pid, s_ctx->owner_mon);

      if (!enif_send(NULL, &(acc->Pid), NULL,
                     enif_make_tuple3(env, enif_make_atom(env, "quic"),
                                      enif_make_atom(env, "new_stream"),
                                      enif_make_resource(env, s_ctx))))
        {
          // @todo log and step counter
          MsQuic->ConnectionShutdown(Connection,
                                     QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                     ERROR_OPERATION_ABORTED);
        }

      MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                 (void *)ClientStreamCallback, s_ctx);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      //
      // The connection has been shut down by the transport. Generally, this
      // is the expected way for the connection to shut down with this
      // protocol, since we let idle timeout kill the connection.
      //
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
          MsQuic->ConnectionClose(Connection);
        }
      destroy_c_ctx(c_ctx);
      break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
      //
      // A resumption ticket (also called New Session Ticket or NST) was
      // received from the server.
      //
      for (uint32_t i = 0;
           i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
        {
          printf(
              "%.2X",
              (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
      printf("\n");
      break;
    default:
      break;
    }
  return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ServerConnectionCallback(HQUIC Connection, void *Context,
                         QUIC_CONNECTION_EVENT *Event)
{
  QuicerConnCTX *c_ctx;
  ACCEPTOR *acc = NULL;
  ErlNifPid *acc_pid = NULL;

  switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
      //
      // The handshake has completed for the connection.
      //
      c_ctx = (QuicerConnCTX *)Context;
      assert(c_ctx->Connection == NULL);
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
              return QUIC_STATUS_UNREACHABLE;
            }
        }

      assert(acc);
      // A monitor is automatically removed when it triggers or when the
      // resource is deallocated.
      enif_monitor_process(NULL, c_ctx, acc_pid, c_ctx->owner_mon);

      ERL_NIF_TERM ConnHandler = enif_make_resource(c_ctx->env, c_ctx);
      // testing this, just unblock accecptor
      // should pick a 'acceptor' here?
      if (!enif_send(NULL, acc_pid, NULL,
                     enif_make_tuple(c_ctx->env, 2,
                                     enif_make_atom(c_ctx->env, "new_conn"),
                                     ConnHandler)))
        {
          //@todo close connection
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
      printf("[conn][%p] Shut down by transport, 0x%x\n", Connection,
             Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      //
      // The connection was explicitly shut down by the peer.
      //
      break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      //
      // The connection has completed the shutdown process and is ready to be
      // safely cleaned up.
      //
      //
      if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
          MsQuic->ConnectionClose(Connection);
        }
      break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      //
      // The peer has started/created a new stream. The app MUST set the
      // callback handler before returning.
      //
      c_ctx = (QuicerConnCTX *)Context;
      // maybe alloc later
      QuicerStreamCTX *s_ctx = init_s_ctx();
      ErlNifEnv *env = s_ctx->env;
      s_ctx->Stream = Event->PEER_STREAM_STARTED.Stream;
      s_ctx->c_ctx = c_ctx;
      s_ctx->l_ctx = c_ctx->l_ctx;
      int retry = 100;
      // @todo, not nice to spin here, need new method to sync with connection
      // owner1
      while (!(acc && acc_pid && enif_is_process_alive(env, acc_pid)))
        {
          acc = AcceptorDequeue(c_ctx->acceptor_queue);
          acc_pid = &(acc->Pid);

          usleep(10000);
          if (retry < 0)
            {
              destroy_s_ctx(s_ctx);
              return QUIC_STATUS_UNREACHABLE;
            }
          retry--;
        }
      s_ctx->owner = acc;

      // @todo add monitor here.
      if (!enif_send(NULL, acc_pid, NULL,
                     enif_make_tuple3(env, enif_make_atom(env, "quic"),
                                      enif_make_atom(env, "new_stream"),
                                      enif_make_resource(env, s_ctx))))
        {
          // @todo log and step counter
          // @todo, maybe we should just return error code and let msquic
          // shutdown the connection gracefully.
          // @todo, check rfc for the error code
          MsQuic->ConnectionShutdown(
            Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, NO_ERROR);
          return QUIC_STATUS_UNREACHABLE;
        }
      else
        {
          MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                     (void *)ServerStreamCallback, s_ctx);
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
  return QUIC_STATUS_SUCCESS;
}

ERL_NIF_TERM
async_connect3(ErlNifEnv *env, __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status;

  ERL_NIF_TERM ehost = argv[0];
  ERL_NIF_TERM eport = argv[1];
  // ERL_NIF_TERM eoptions = argv[2];

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

  if (!ClientLoadConfiguration(&(c_ctx->Configuration), true))
    {
      return ERROR_TUPLE_2(ATOM_CONFIG_ERROR);
    }

  if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(
                      Registration, ClientConnectionCallback, c_ctx,
                      &(c_ctx->Connection))))
    {
      destroy_c_ctx(c_ctx);
      return ERROR_TUPLE_2(ATOM_CONN_OPEN_ERROR);
    }

  if (QUIC_FAILED(Status = MsQuic->ConnectionStart(
                      c_ctx->Connection, c_ctx->Configuration,
                      QUIC_ADDRESS_FAMILY_UNSPEC, host, port)))
    {
      MsQuic->ConnectionClose(c_ctx->Connection);
      destroy_c_ctx(c_ctx);
      return ERROR_TUPLE_2(ATOM_CONN_START_ERROR);
    }

  ERL_NIF_TERM eHandler = enif_make_resource(env, c_ctx);

  return SUCCESS(eHandler);
}

ERL_NIF_TERM
async_accept2(ErlNifEnv *env, __unused_parm__ int argc,
              const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
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

  AcceptorEnqueue(l_ctx->acceptor_queue, acceptor);

  assert(enif_is_process_alive(env, &(acceptor->Pid)));

  ERL_NIF_TERM listenHandler = enif_make_resource(env, l_ctx);
  return SUCCESS(listenHandler);
}

//@todo,  shutdown with error
ERL_NIF_TERM
close_connection1(ErlNifEnv *env, __unused_parm__ int argc,
                  const ERL_NIF_TERM argv[])
{
  QuicerConnCTX *c_ctx;
  if (!enif_get_resource(env, argv[0], ctx_connection_t, (void **)&c_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  MsQuic->ConnectionShutdown(c_ctx->Connection,
                             //@todo, check rfc for the error code
                             QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, NO_ERROR);
  return ATOM_OK;
}

ERL_NIF_TERM
sockname1(ErlNifEnv *env, __unused_parm__ int args,
          const ERL_NIF_TERM argv[])
{
  void *q_ctx;
  HQUIC Handle = NULL;
  uint32_t Param = -1;
  QUIC_PARAM_LEVEL Level = -1;

  if (enif_get_resource(env, argv[0], ctx_connection_t, &q_ctx)) {
    Handle = ((QuicerConnCTX *)q_ctx)->Connection;
    Level = QUIC_PARAM_LEVEL_CONNECTION;
    Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
  } else if (enif_get_resource(env, argv[0], ctx_listener_t, &q_ctx)) {
    Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
    Level = QUIC_PARAM_LEVEL_LISTENER;
    Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
  } else if (enif_get_resource(env, argv[0], ctx_stream_t, &q_ctx)) {
    Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
    Level = QUIC_PARAM_LEVEL_CONNECTION;
    Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
  } else {
    return ERROR_TUPLE_2(ATOM_BADARG);
  }

  QUIC_STATUS status;
  QUIC_ADDR addr;
  uint32_t addrSize = sizeof(addr);

  if (QUIC_FAILED(status = MsQuic->GetParam(
                                       Handle,
                                       Level,
                                       Param,
                                       &addrSize,
                                       &addr)))
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
          enif_make_tuple8(
            env,
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
                              enif_make_int(env, addr->Ipv4.sin_port));
    }
}
///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
