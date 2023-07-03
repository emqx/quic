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
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

QUIC_STATUS
ServerListenerCallback(__unused_parm__ HQUIC Listener,
                       void *Context,
                       QUIC_LISTENER_EVENT *Event)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  QuicerListenerCTX *l_ctx = (QuicerListenerCTX *)Context;
  QuicerConnCTX *c_ctx = NULL;
  BOOLEAN is_destroy = FALSE;

  enif_mutex_lock(l_ctx->lock);
  // dbg("server listener event: %d", Event->Type);
  switch (Event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
      //
      // Note, c_ctx is newly init here, don't grab lock.
      //
      c_ctx = init_c_ctx();
      ErlNifEnv *env = c_ctx->env;

      if (!c_ctx)
        {
          Status = QUIC_STATUS_OUT_OF_MEMORY;
          goto Error;
        }

      c_ctx->Connection = Event->NEW_CONNECTION.Connection;

      /* reload trusted store very time to make sure we incorporate
       * any changes to the file
       */
      if (l_ctx->cacertfile)
        {
          X509_STORE *trusted = NULL;
          X509_LOOKUP *lookup = NULL;
          trusted = X509_STORE_new();

          if (trusted != NULL)
            {
              lookup = X509_STORE_add_lookup(trusted, X509_LOOKUP_file());
              if (lookup != NULL)
                {
                  if (!X509_LOOKUP_load_file(
                          lookup, l_ctx->cacertfile, X509_FILETYPE_PEM))
                    {
                      X509_STORE_free(trusted);
                      trusted = NULL;
                    }
                }
              else
                {
                  X509_STORE_free(trusted);
                  trusted = NULL;
                }
            }
          c_ctx->trusted = trusted;
        }

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
          // we will not be the owner this connection
          // msquic will close the Connection Handle internally.
          // Set it to NULL to avoid close it in resource_conn_dealloc_callback
          c_ctx->Connection = NULL;

          // However, we still need to free the c_ctx
          // note, we don't hold the lock of c_ctx since it is new conn.
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

      c_ctx->is_closed = FALSE; // new connection
      enif_clear_env(env);
      break;

    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
      env = l_ctx->env;

      // Close listener in NIF CTX leads to NULL Listener HQUIC
      assert(l_ctx->Listener == NULL);

      // Dummy call to prevent leakage if handle is not NULL
      // @TODO they should be removed when we support ListenerStop call
      MsQuic->ListenerClose(l_ctx->Listener);
      l_ctx->Listener = NULL;

      enif_send(NULL,
                &(l_ctx->listenerPid),
                NULL,
                enif_make_tuple3(env,
                                 ATOM_QUIC,
                                 ATOM_LISTENER_STOPPED,
                                 enif_make_resource(env, l_ctx)));
      is_destroy = TRUE;
      enif_clear_env(env);
      break;
    default:
      break;
    }

Error:
  enif_mutex_unlock(l_ctx->lock);
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

  ERL_NIF_TERM elisten_on = argv[0];
  ERL_NIF_TERM options = argv[1];
  QUIC_ADDR Address = {};
  int UdpPort = 0;

  if (!enif_is_map(env, options))
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


  // Build CredConfig
  QUIC_CREDENTIAL_CONFIG CredConfig;
  CxPlatZeroMemory(&CredConfig, sizeof(QUIC_CREDENTIAL_CONFIG));
  char password[256] = { 0 };
  char cert_path[PATH_MAX + 1] = { 0 };
  char key_path[PATH_MAX + 1] = { 0 };
  ERL_NIF_TERM tmp_term;

  if (get_str_from_map(env, ATOM_CERTFILE, &options, cert_path, PATH_MAX + 1)
          <= 0
      && get_str_from_map(env, ATOM_CERT, &options, cert_path, PATH_MAX + 1)
             <= 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (get_str_from_map(env, ATOM_KEYFILE, &options, key_path, PATH_MAX + 1)
          <= 0
      && get_str_from_map(env, ATOM_KEY, &options, key_path, PATH_MAX + 1)
             <= 0)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerListenerCTX *l_ctx = init_l_ctx();

  if (!enif_self(env, &(l_ctx->listenerPid)))
    {
      return ERROR_TUPLE_2(ATOM_BAD_PID);
    }

  ERL_NIF_TERM ecacertfile;
  if (enif_get_map_value(env, options, ATOM_CACERTFILE, &ecacertfile))
    {
      unsigned len;
      if (enif_get_list_length(env, ecacertfile, &len))
        {
          l_ctx->cacertfile
              = (char *)CXPLAT_ALLOC_NONPAGED(len + 1, QUICER_CACERTFILE);
          if (!enif_get_string(env,
                               ecacertfile,
                               l_ctx->cacertfile,
                               len + 1,
                               ERL_NIF_LATIN1))
            {
              CXPLAT_FREE(l_ctx->cacertfile, QUICER_CACERTFILE);
              l_ctx->cacertfile = NULL;
              enif_release_resource(l_ctx);
              return ERROR_TUPLE_2(ATOM_BADARG);
            }
        }
      else
        {
          enif_release_resource(l_ctx);
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  if (enif_get_map_value(env, options, ATOM_PASSWORD, &tmp_term))
    {
      if (get_str_from_map(env, ATOM_PASSWORD, &options, password, 256) <= 0)
        {
          enif_release_resource(l_ctx);
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      QUIC_CERTIFICATE_FILE_PROTECTED *CertFile
          = (QUIC_CERTIFICATE_FILE_PROTECTED *)CXPLAT_ALLOC_NONPAGED(
              sizeof(QUIC_CERTIFICATE_FILE_PROTECTED),
              QUICER_CERTIFICATE_FILE);

      CertFile->CertificateFile = cert_path;
      CertFile->PrivateKeyFile = key_path;
      CertFile->PrivateKeyPassword = password;
      CredConfig.CertificateFileProtected = CertFile;
      CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
    }
  else
    {
      QUIC_CERTIFICATE_FILE *CertFile
          = (QUIC_CERTIFICATE_FILE *)CXPLAT_ALLOC_NONPAGED(
              sizeof(QUIC_CERTIFICATE_FILE), QUICER_CERTIFICATE_FILE);
      CertFile->CertificateFile = cert_path;
      CertFile->PrivateKeyFile = key_path;
      CredConfig.CertificateFile = CertFile;
      CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    }

  bool Verify = load_verify(env, &options, false);

  if (!Verify)
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  else
    {
      CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
      if (l_ctx->cacertfile)
        {
          // We do our own certificate verification agains the certificates
          // in cacertfile
          CredConfig.Flags
              |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
          CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        }
    }

  ERL_NIF_TERM estatus = ServerLoadConfiguration(
      env, &options, &l_ctx->config_resource->Configuration, &CredConfig);

  // Cleanup CredConfig
  if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE == CredConfig.Type)
    {
      CxPlatFree(CredConfig.CertificateFile, QUICER_CERTIFICATE_FILE);
    }
  else if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED == CredConfig.Type)
    {
      CxPlatFree(CredConfig.CertificateFileProtected,
                 QUICER_CERTIFICATE_FILE_PROTECTED);
    }

  if (!IS_SAME_TERM(ATOM_OK, estatus))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_CONFIG_ERROR, estatus);
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
              GRegistration, ServerListenerCallback, l_ctx, &l_ctx->Listener)))
    {
      l_ctx->config_resource->Configuration = NULL;
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_LISTENER_OPEN_ERROR, ATOM_STATUS(Status));
    }
  l_ctx->is_closed = FALSE;

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER alpn_buffers[MAX_ALPN];

  // Allow insecure
  ERL_NIF_TERM eisInsecure;
  if (enif_get_map_value(env, options, ATOM_ALLOW_INSECURE, &eisInsecure)
      && IS_SAME_TERM(eisInsecure, ATOM_TRUE))
    {
      l_ctx->allow_insecure = TRUE;
    }

  if (!load_alpn(env, &options, &alpn_buffer_length, alpn_buffers))
    {
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_2(ATOM_ALPN);
    }

  // Start Listener
  if (QUIC_FAILED(
          Status = MsQuic->ListenerStart(
              l_ctx->Listener, alpn_buffers, alpn_buffer_length, &Address)))
    {
      TP_NIF_3(start_fail, (uintptr_t)(l_ctx->Listener), Status);
      destroy_l_ctx(l_ctx);
      return ERROR_TUPLE_3(ATOM_LISTENER_START_ERROR, ATOM_STATUS(Status));
    }
  ERL_NIF_TERM listenHandle = enif_make_resource(env, l_ctx);
  return OK_TUPLE_2(listenHandle);
}

ERL_NIF_TERM
close_listener1(ErlNifEnv *env,
                __unused_parm__ int argc,
                const ERL_NIF_TERM argv[])
{
  QuicerListenerCTX *l_ctx;
  ERL_NIF_TERM ret = ATOM_OK;
  if (!enif_get_resource(env, argv[0], ctx_listener_t, (void **)&l_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(l_ctx->lock);
  HQUIC l = l_ctx->Listener;
  l_ctx->Listener = NULL;

  if (l_ctx->is_closed)
  {
    ret = ERROR_TUPLE_2(ATOM_CLOSED);
  }
  l_ctx->is_closed = TRUE;
  enif_mutex_unlock(l_ctx->lock);

  // It is safe to close it without holding the lock
  // This also ensures no ongoing listener callbacks
  // This is a blocking call.
  //
  MsQuic->ListenerClose(l);

  return ret;
}
