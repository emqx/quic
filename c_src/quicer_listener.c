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
#include "quicer_tls.h"
#include "quicer_tp.h"
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

extern QuicerRegistrationCTX *G_r_ctx;
extern pthread_mutex_t GRegLock;

BOOLEAN parse_registration(ErlNifEnv *env,
                           ERL_NIF_TERM options,
                           QuicerRegistrationCTX **r_ctx);

QUIC_STATUS
ServerListenerCallback(__unused_parm__ HQUIC Listener,
                       void *Context,
                       QUIC_LISTENER_EVENT *Event)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  QuicerListenerCTX *l_ctx = (QuicerListenerCTX *)Context;
  QuicerConnCTX *c_ctx = NULL;
  BOOLEAN is_destroy = FALSE;

  switch (Event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      enif_mutex_lock(l_ctx->lock);
      //
      // Note, c_ctx is newly init here, don't grab lock.
      //
      c_ctx = init_c_ctx();
      c_ctx->r_ctx = l_ctx->r_ctx;
      ErlNifEnv *env = c_ctx->env;

      if (!c_ctx)
        {
          Status = QUIC_STATUS_OUT_OF_MEMORY;
          goto Error;
        }

      c_ctx->Connection = Event->NEW_CONNECTION.Connection;
      CxPlatRefInitialize(&(c_ctx->ref_count));

#if defined(QUICER_USE_TRUSTED_STORE)
      if (l_ctx->trusted_store)
        {
          X509_STORE_up_ref(l_ctx->trusted_store);
          c_ctx->trusted = l_ctx->trusted_store;
        }
#endif // QUICER_USE_TRUSTED_STORE
      assert(l_ctx->config_resource);
      // Keep resource for c_ctx
      enif_keep_resource(l_ctx->config_resource);
      c_ctx->config_resource = l_ctx->config_resource;

      ACCEPTOR *conn_owner = AcceptorDequeue(l_ctx->acceptor_queue);

      if (!conn_owner)
        {
          TP_CB_3(no_acceptor, (uintptr_t)c_ctx->Connection, 0);
          Status = QUIC_STATUS_UNREACHABLE;
          // We are going to reject the connection,
          // we will not be the owner of this connection
          // msquic will close the Connection Handle internally.
          // Set it to NULL to avoid close it in resource_conn_dealloc_callback
          // or in the put_conn_handle.
          c_ctx->Connection = NULL;
          put_conn_handle(c_ctx);
          // However, we still need to free the c_ctx
          // @NOTE: we don't hold the lock of c_ctx since it is new conn.
          enif_release_resource(c_ctx);
          goto Error;
        }
      TP_CB_3(acceptor_hit, (uintptr_t)c_ctx->Connection, 0);
      c_ctx->owner = conn_owner;

      if (l_ctx->allow_insecure)
        {
          BOOLEAN value = TRUE;
          MsQuic->SetParam(Event->NEW_CONNECTION.Connection,
                           // 0x0500000F,
                           QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                           sizeof(value),
                           &value);
        }

      // @TODO check ret values of  memcpy and addr to string...
      QUIC_ADDR_STR addrStr_local = { 0 };
      QuicAddrToString(Event->NEW_CONNECTION.Info->LocalAddress,
                       &addrStr_local);
      QUIC_ADDR_STR addrStr_remote = { 0 };
      QuicAddrToString(Event->NEW_CONNECTION.Info->RemoteAddress,
                       &addrStr_remote);

      ERL_NIF_TERM eserver_name;
      CxPlatCopyMemory(
          enif_make_new_binary(env,
                               Event->NEW_CONNECTION.Info->ServerNameLength,
                               &eserver_name),
          Event->NEW_CONNECTION.Info->ServerName,
          Event->NEW_CONNECTION.Info->ServerNameLength);

      ERL_NIF_TERM ealpns;
      CxPlatCopyMemory(
          enif_make_new_binary(
              env, Event->NEW_CONNECTION.Info->NegotiatedAlpnLength, &ealpns),
          Event->NEW_CONNECTION.Info->NegotiatedAlpn,
          Event->NEW_CONNECTION.Info->NegotiatedAlpnLength);

      ERL_NIF_TERM eclient_alpns;
      CxPlatCopyMemory(enif_make_new_binary(
                           env,
                           Event->NEW_CONNECTION.Info->ClientAlpnListLength,
                           &eclient_alpns),
                       Event->NEW_CONNECTION.Info->ClientAlpnList,
                       Event->NEW_CONNECTION.Info->ClientAlpnListLength);

      ERL_NIF_TERM ecrypto_buffer;
      CxPlatCopyMemory(
          enif_make_new_binary(env,
                               Event->NEW_CONNECTION.Info->CryptoBufferLength,
                               &ecrypto_buffer),
          Event->NEW_CONNECTION.Info->CryptoBuffer,
          Event->NEW_CONNECTION.Info->CryptoBufferLength);

      ERL_NIF_TERM props_name[] = {
        ATOM_VER,           // version
        ATOM_LOCAL_ADDR,    // local addr
        ATOM_REMOTE_ADDR,   // remote addr
        ATOM_SERVER_NAME,   // server name
        ATOM_ALPNS,         // alpns
        ATOM_CLIENT_ALPNS,  // client alpns
        ATOM_CRYPTO_BUFFER, // crypto buffer
      };

      ERL_NIF_TERM props_value[] = {
        enif_make_uint(env,
                       Event->NEW_CONNECTION.Info->QuicVersion), // version
        // @TODO:TBD Binary is better?
        enif_make_string(
            env, addrStr_local.Address, ERL_NIF_LATIN1), // local addr
        enif_make_string(
            env, addrStr_remote.Address, ERL_NIF_LATIN1), // remote addr //
        eserver_name,                                     // server name
        ealpns,                                           // alpns
        eclient_alpns,                                    // client alpns
        ecrypto_buffer,                                   // crypto buffer
      };

      ERL_NIF_TERM report
          = make_event_with_props(env,
                                  ATOM_NEW_CONN,
                                  enif_make_resource(env, c_ctx),
                                  props_name,
                                  props_value,
                                  7);
      if (!enif_send(NULL, &(c_ctx->owner->Pid), NULL, report))
        {
          Status = QUIC_STATUS_INTERNAL_ERROR;

          // We are going to reject the connection,
          // we will not be the owner this connection
          // msquic will close the Connection Handle internally.
          // Set it to NULL to avoid close it in resource_conn_dealloc_callback
          c_ctx->Connection = NULL;

          // However, we still need to free the c_ctx
          // note, we don't hold the lock of c_ctx since it is new conn.
          enif_release_resource(c_ctx);
          goto Error;
        }

      //
      // A new connection is being attempted by a client. For the handshake to
      // proceed, the server must provide a configuration for QUIC to use. The
      // app MUST set the callback handler before returning.
      //
      MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                                 (void *)ServerConnectionCallback,
                                 c_ctx);

      QuicerRegistrationCTX *r_ctx;
      if (l_ctx->r_ctx)
        {
          r_ctx = l_ctx->r_ctx;
        }
      else
        {
          r_ctx = G_r_ctx;
        }

      if (r_ctx)
        {
          enif_mutex_lock(r_ctx->lock);
          CxPlatListInsertTail(&r_ctx->Connections, &c_ctx->RegistrationLink);
          enif_mutex_unlock(r_ctx->lock);
        }

      c_ctx->is_closed = FALSE; // new connection
      enif_clear_env(env);
      break;

    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
      // **Note**, the callback in msquic for this event is called in the
      // MsQuicListenerClose or MsQuicListenerStop. we assume caller should
      // ensure the thread safty thus we don't hold lock
      env = l_ctx->env;
      enif_send(NULL,
                &(l_ctx->listenerPid),
                NULL,
                enif_make_tuple3(env,
                                 ATOM_QUIC,
                                 ATOM_LISTENER_STOPPED,
                                 enif_make_resource(env, l_ctx)));
      if (!l_ctx->Listener)
        {
          // @NOTE This callback is part of the listener *close* process
          // Listener is already closing, we can destroy the l_ctx now
          // as the handle is NULL no subsequent msquic API is allowed/possible
          assert(!l_ctx->is_stopped);
          is_destroy = TRUE;
        }
      enif_clear_env(env);
      goto Exit2;
    default:
      break;
    }

Error:
  enif_mutex_unlock(l_ctx->lock);
Exit2:
  if (is_destroy)
    {
      destroy_l_ctx(l_ctx);
    }
  return Status;
}

ERL_NIF_TERM
listen2(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM ret = ATOM_OK;

  ERL_NIF_TERM elisten_on = argv[0];
  ERL_NIF_TERM options = argv[1];

  QUIC_ADDR Address = {};
  HQUIC Registration = NULL;

  QuicerRegistrationCTX *target_r_ctx = NULL;

  if (!enif_is_map(env, options))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Check ListenOn string
  if (!parse_listen_on(env, elisten_on, &Address))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Start build CredConfig from with listen opts
  QUIC_CREDENTIAL_CONFIG CredConfig;

#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE *trusted_store = NULL;
  ret = eoptions_to_cred_config(env, options, &CredConfig, &trusted_store);
#else
  ret = eoptions_to_cred_config(env, options, &CredConfig, NULL);
#endif // QUICER_USE_TRUSTED_STORE

  if (!IS_SAME_TERM(ret, ATOM_OK))
    {
      return ERROR_TUPLE_2(ret);
    }

  // Now build l_ctx
  QuicerListenerCTX *l_ctx = init_l_ctx();

  if (!l_ctx)
    {
      free_certificate(&CredConfig);
#if defined(QUICER_USE_TRUSTED_STORE)
      X509_STORE_free(trusted_store);
#endif // QUICER_USE_TRUSTED_STORE
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }
#if defined(QUICER_USE_TRUSTED_STORE)
  l_ctx->trusted_store = trusted_store;
#endif // QUICER_USE_TRUSTED_STORE
  CxPlatRefInitialize(&l_ctx->ref_count);

  // *********  ANY ERROR below this line should goto `exit`   **************

  // Set owner for l_ctx
  if (!enif_self(env, &(l_ctx->listenerPid)))
    {
      ret = ERROR_TUPLE_2(ATOM_BAD_PID);
      goto exit;
    }

  // Get Reg for l_ctx, quic_registration is optional
  if (!parse_registration(env, options, &l_ctx->r_ctx))
    {
      ret = ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
      goto exit;
    }

  if (l_ctx->r_ctx)
    {
      // quic_registration is set
      enif_keep_resource(l_ctx->r_ctx);
      if (!get_reg_handle(l_ctx->r_ctx))
        {
          ret = ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
          goto exit;
        }
      Registration = l_ctx->r_ctx->Registration;
      target_r_ctx = l_ctx->r_ctx;
    }
  else
    {
      // quic_registration is not set, use global registration
      target_r_ctx = G_r_ctx;
      pthread_mutex_lock(&GRegLock);

      if (!G_r_ctx)
        {
          pthread_mutex_unlock(&GRegLock);
          ret = ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
          goto exit;
        }

      enif_keep_resource(G_r_ctx);
      if (!get_reg_handle(G_r_ctx))
        {
          ret = ERROR_TUPLE_2(ATOM_QUIC_REGISTRATION);
          goto exit;
        }
      Registration = G_r_ctx->Registration;
      pthread_mutex_unlock(&GRegLock);
    }

  // Now load server config
  ret = ServerLoadConfiguration(env,
                                &options,
                                Registration,
                                &l_ctx->config_resource->Configuration,
                                &CredConfig);
  if (!IS_SAME_TERM(ATOM_OK, ret))
    {
      // @TODO unsure 3 elem tuple is the best way to return error
      ret = ERROR_TUPLE_3(ATOM_CONFIG_ERROR, ret);
      goto exit;
    }

  // mon will be removed when triggered or when l_ctx is dealloc.
  if (0
      != enif_monitor_process(
          env, l_ctx, &l_ctx->listenerPid, &l_ctx->owner_mon))
    {
      ret = ERROR_TUPLE_2(ATOM_BAD_MON);
      goto exit;
    }

  // Now open listener
  if (QUIC_FAILED(Status = MsQuic->ListenerOpen(
                      // Listener registration
                      Registration,
                      ServerListenerCallback,
                      l_ctx,
                      &l_ctx->Listener)))
    {
      // Server Configuration should be destroyed
      // @FIXME here leaks config?
      // enif_release_resource(l_ctx->config_resource);
      l_ctx->config_resource->Configuration = NULL;
      ret = ERROR_TUPLE_3(ATOM_LISTENER_OPEN_ERROR, ATOM_STATUS(Status));
      goto exit;
    }
  l_ctx->is_closed = FALSE;

  // Link to registration only when ListenerOpen success
  if (target_r_ctx)
    {
      enif_mutex_lock(target_r_ctx->lock);
      CxPlatListInsertTail(&target_r_ctx->Listeners, &l_ctx->RegistrationLink);
      enif_mutex_unlock(target_r_ctx->lock);
    }

  // Now try to start listener
  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER *alpn_buffers = NULL;

  // Allow insecure, default is false
  ERL_NIF_TERM eisInsecure;
  if (enif_get_map_value(env, options, ATOM_ALLOW_INSECURE, &eisInsecure)
      && IS_SAME_TERM(eisInsecure, ATOM_TRUE))
    {
      l_ctx->allow_insecure = TRUE;
    }

  if (!load_alpn(env, &options, &alpn_buffer_length, &alpn_buffers))
    {
      ret = ERROR_TUPLE_2(ATOM_ALPN);
      goto exit;
    }

  // Start Listener
  Status = MsQuic->ListenerStart(
      l_ctx->Listener, alpn_buffers, alpn_buffer_length, &Address);
  free_alpn_buffers(alpn_buffers, alpn_buffer_length);

  if (QUIC_FAILED(Status))
    {
      TP_NIF_3(start_fail, (uintptr_t)(l_ctx->Listener), Status);
      HQUIC Listener = l_ctx->Listener;
      l_ctx->Listener = NULL;
      MsQuic->ListenerClose(Listener);
      ret = ERROR_TUPLE_3(ATOM_LISTENER_START_ERROR, ATOM_STATUS(Status));
      goto exit;
    }

  ERL_NIF_TERM listenHandle = enif_make_resource(env, l_ctx);
  // @TODO move it to earlier?
  free_certificate(&CredConfig);
  return OK_TUPLE_2(listenHandle);

exit: // errors..
#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE_free(trusted_store);
#endif // QUICER_USE_TRUSTED_STORE
  free_certificate(&CredConfig);
  destroy_l_ctx(l_ctx);
  return ret;
}

ERL_NIF_TERM
close_listener1(ErlNifEnv *env,
                __unused_parm__ int argc,
                const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  BOOLEAN is_destroy = FALSE;
  ERL_NIF_TERM ret = ATOM_OK;
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(l_ctx->lock);
  if (l_ctx->is_closed)
    {
      enif_mutex_unlock(l_ctx->lock);
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  HQUIC l = l_ctx->Listener;
  // set before destroy_l_ctx
  l_ctx->Listener = NULL;
  l_ctx->is_closed = TRUE;

  // If is_stopped, it means the listener is already stopped.
  // there will be no callback for QUIC_LISTENER_EVENT_STOP_COMPLETE
  // so we need to destroy the l_ctx otherwise it will leak.
  is_destroy = l_ctx->is_stopped;

  enif_mutex_unlock(l_ctx->lock);

  MsQuic->ListenerClose(l);
  if (is_destroy)
    {
      destroy_l_ctx(l_ctx);
    }
  return ret;
}

ERL_NIF_TERM
stop_listener1(ErlNifEnv *env,
               __unused_parm__ int argc,
               const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  ERL_NIF_TERM ret = ATOM_OK;
  assert(argc == 1);
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  if (!get_listener_handle(l_ctx))
    {
      ret = ERROR_TUPLE_2(ATOM_CLOSED);
      return ret; // follow otp behaviour?
    }
  l_ctx->is_stopped = TRUE;
  MsQuic->ListenerStop(l_ctx->Listener);
  put_listener_handle(l_ctx);
  return ret;
}

// For simplicity, we do not support to switch the Registration
ERL_NIF_TERM
start_listener3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM listener_handle = argv[0];
  ERL_NIF_TERM elisten_on = argv[1];
  ERL_NIF_TERM options = argv[2];

  QuicerListenerCTX *l_ctx;
  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER *alpn_buffers = NULL;
  QUIC_ADDR Address = {};
  int UdpPort = 0;

  // Return value
  ERL_NIF_TERM ret = ATOM_OK;
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

  CXPLAT_FRE_ASSERT(argc == 3);

  if (!enif_get_resource(
          env, listener_handle, ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  char listen_on[INET6_ADDRSTRLEN + 6] = { 0 };
  if (enif_get_string(
          env, elisten_on, listen_on, INET6_ADDRSTRLEN + 6, ERL_NIF_LATIN1)
      > 0)
    {
      if (!(QuicAddr4FromString(listen_on, &Address)
            || QuicAddr6FromString(listen_on, &Address)))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }
  else if (enif_get_int(env, elisten_on, &UdpPort) && UdpPort >= 0)
    {
      QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
      QuicAddrSetPort(&Address, (uint16_t)UdpPort);
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerConfigCTX *new_config_ctx = init_config_ctx();
  if (!new_config_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  QUIC_CREDENTIAL_CONFIG CredConfig = { 0 };
#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE *trusted_store = NULL;
  ret = eoptions_to_cred_config(env, options, &CredConfig, &trusted_store);
#else
  ret = eoptions_to_cred_config(env, options, &CredConfig, NULL);
#endif // QUICER_USE_TRUSTED_STORE

  if (!IS_SAME_TERM(ret, ATOM_OK))
    {
      return ERROR_TUPLE_2(ret);
    }

  // ===================================================
  // Safe to access l_ctx  now
  // ===================================================
  enif_mutex_lock(l_ctx->lock);

  if (!l_ctx->Listener)
    {
      ret = ERROR_TUPLE_2(ATOM_CLOSED);
      goto exit;
    }

  QuicerRegistrationCTX *target_r_ctx = NULL;

  // This is a read, do not need to bump the ref count
  target_r_ctx = l_ctx->r_ctx ? l_ctx->r_ctx : G_r_ctx;

  ret = ServerLoadConfiguration(env,
                                &options,
                                target_r_ctx->Registration,
                                &new_config_ctx->Configuration,
                                &CredConfig);
  free_certificate(&CredConfig);

  if (!IS_SAME_TERM(ret, ATOM_OK))
    {
      enif_release_resource(new_config_ctx);
      ret = ERROR_TUPLE_2(ret);
      goto exit;
    }

  QuicerConfigCTX *old_config_ctx = l_ctx->config_resource;
  l_ctx->config_resource = new_config_ctx;

#if defined(QUICER_USE_TRUSTED_STORE)
  X509_STORE_free(l_ctx->trusted_store);
  l_ctx->trusted_store = trusted_store;
#endif // QUICER_USE_TRUSTED_STORE
  // Now we swap the config

  if (!load_alpn(env, &options, &alpn_buffer_length, &alpn_buffers))
    {
      enif_release_resource(new_config_ctx);
      ret = ERROR_TUPLE_2(ATOM_ALPN);
      goto exit;
    }
  Status = MsQuic->ListenerStart(
      l_ctx->Listener, alpn_buffers, alpn_buffer_length, &Address);

  free_alpn_buffers(alpn_buffers, alpn_buffer_length);

  if (QUIC_FAILED(Status))
    {
      TP_NIF_3(start_fail, (uintptr_t)(l_ctx->Listener), Status);
      ret = ERROR_TUPLE_3(ATOM_LISTENER_START_ERROR, ATOM_STATUS(Status));
      enif_release_resource(new_config_ctx);
      goto exit;
    }
  l_ctx->is_stopped = FALSE;

  // the ongoing handshake will be completed with the old config
  enif_release_resource(old_config_ctx);

exit:
  enif_mutex_unlock(l_ctx->lock);
  return ret;
}

ERL_NIF_TERM
get_listenersX(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ERL_NIF_TERM res = enif_make_list(env, 0);
  if (argc == 0) // use global registration
    {
      pthread_mutex_lock(&GRegLock);
      if (!G_r_ctx)
        {
          pthread_mutex_unlock(&GRegLock);
          return res;
        }
      r_ctx = G_r_ctx;
    }
  else
    {
      if (!enif_get_resource(env, argv[0], ctx_reg_t, (void **)&r_ctx))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }
  enif_mutex_lock(r_ctx->lock);
  CXPLAT_LIST_ENTRY *Entry = r_ctx->Listeners.Flink;
  while (Entry != &r_ctx->Listeners)
    {
      QuicerListenerCTX *l_ctx = CXPLAT_CONTAINING_RECORD(
          Entry, QuicerListenerCTX, RegistrationLink);
      res = enif_make_list_cell(env, enif_make_resource(env, l_ctx), res);
      Entry = Entry->Flink;
    }
  enif_mutex_unlock(r_ctx->lock);

  if (argc == 0) // use global registration
    {
      pthread_mutex_unlock(&GRegLock);
    }
  return res;
}

ERL_NIF_TERM
get_listener_owner1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  ERL_NIF_TERM res = ATOM_UNDEFINED;
  CXPLAT_FRE_ASSERT(argc == 1);
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  enif_mutex_lock(l_ctx->lock);
  res = SUCCESS(enif_make_pid(env, &(l_ctx->listenerPid)));
  enif_mutex_unlock(l_ctx->lock);
  return res;
}
