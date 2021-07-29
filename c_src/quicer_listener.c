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

#include "quicer_listener.h"
#include "quicer_config.h"
#include "quicer_tp.h"

QUIC_STATUS
ServerListenerCallback(__unused_parm__ HQUIC Listener,
                       void *Context,
                       QUIC_LISTENER_EVENT *Event)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  QuicerListenerCTX *l_ctx = (QuicerListenerCTX *)Context;
  ErlNifEnv *env = l_ctx->env;
  QuicerConnCTX *c_ctx = NULL;

  switch (Event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        // printf("new connection\n");
        ;
      //
      // Note, c_ctx is newly init here, don't grab lock.
      //
      c_ctx = init_c_ctx();

      if (!c_ctx)
        {
          return QUIC_STATUS_OUT_OF_MEMORY;
        }

      c_ctx->Connection = Event->NEW_CONNECTION.Connection;

      c_ctx->l_ctx = l_ctx;

      ACCEPTOR *conn_owner = AcceptorDequeue(l_ctx->acceptor_queue);

      if (!conn_owner)
        {
          destroy_c_ctx(c_ctx);
          // make msquic close the connection.
          return QUIC_STATUS_NOT_FOUND;
        }
      c_ctx->owner = conn_owner;

      //
      // A new connection is being attempted by a client. For the handshake to
      // proceed, the server must provide a configuration for QUIC to use. The
      // app MUST set the callback handler before returning.
      //
      MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                                 (void *)ServerConnectionCallback,
                                 c_ctx);

      if (conn_owner->fast_conn)
        {
          TP_CB_3(fast_conn, c_ctx->Connection, 1);
          if (QUIC_FAILED(Status = continue_connection_handshake(c_ctx)))
            {
              destroy_c_ctx(c_ctx);
              return Status;
            }
        }
      else
        {
          TP_CB_3(fast_conn, c_ctx->Connection, 0);
          if (!enif_send(
                  NULL,
                  &(c_ctx->owner->Pid),
                  NULL,
                  enif_make_tuple3(c_ctx->env,
                                   ATOM_QUIC,
                                   enif_make_atom(c_ctx->env, "init_conn"),
                                   enif_make_resource(c_ctx->env, c_ctx))))
            {
              enif_mutex_unlock(c_ctx->lock);
              return QUIC_STATUS_INTERNAL_ERROR;
            }
        }
      break;
    default:
      break;
    }
  return Status;
}

ERL_NIF_TERM
listen2(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  ERL_NIF_TERM port = argv[0];
  ERL_NIF_TERM options = argv[1];

  // @todo argc checks
  // @todo read from argv
  QUIC_ADDR Address = {};
  int UdpPort = 0;
  if (!enif_get_int(env, port, &UdpPort) && UdpPort >= 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);

  QuicAddrSetPort(&Address, (uint16_t)UdpPort);

  QuicerListenerCTX *l_ctx = init_l_ctx();

  // @todo is listenerPid useless?
  if (!enif_self(env, &(l_ctx->listenerPid)))
    {
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  QUIC_CREDENTIAL_CONFIG_HELPER *Config = NewCredConfig(env, &options);

  if (!Config)
    {
      return ERROR_TUPLE_2(ATOM_PARM_ERROR);
    }
  if (!ServerLoadConfiguration(env, &options, &l_ctx->Configuration, Config))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_CONFIG_ERROR, ETERM_INT(Status));
    }

  if (!ReloadCertConfig(l_ctx->Configuration, Config))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_2(ATOM_CERT_ERROR);
    }

  // mon will be removed when triggered or when l_ctx is dealloc.
  ErlNifMonitor mon;

  if (0 != enif_monitor_process(env, l_ctx, &l_ctx->listenerPid, &mon))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_2(ATOM_BAD_MON);
    }

  if (QUIC_FAILED(
          Status = MsQuic->ListenerOpen(
              Registration, ServerListenerCallback, l_ctx, &l_ctx->Listener)))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_LISTENER_OPEN_ERROR, ETERM_INT(Status));
    }

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER alpn_buffers[MAX_ALPN];

  if (!load_alpn(env, &options, &alpn_buffer_length, alpn_buffers))
    {
      return false;
    }

  if (QUIC_FAILED(
          Status = MsQuic->ListenerStart(
              l_ctx->Listener, alpn_buffers, alpn_buffer_length, &Address)))
    {
      MsQuic->ListenerClose(l_ctx->Listener);
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_LISTENER_START_ERROR, ETERM_INT(Status));
    }

  DestroyCredConfig(Config);

  ERL_NIF_TERM listenHandler = enif_make_resource(env, l_ctx);
  return OK_TUPLE_2(listenHandler);
}

ERL_NIF_TERM
close_listener1(ErlNifEnv *env,
                __unused_parm__ int argc,
                const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // @todo error handling here
  MsQuic->ListenerStop(l_ctx->Listener);
  MsQuic->ListenerClose(l_ctx->Listener);
  enif_release_resource(l_ctx);
  return ATOM_OK;
}
