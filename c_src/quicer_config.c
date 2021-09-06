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

#include "quicer_config.h"
#include "quicer_internal.h"
#include "quicer_queue.h"
#include <msquichelper.h>

extern BOOLEAN isRegistered;

bool
ReloadCertConfig(HQUIC Configuration, QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config->CredConfig)))
    {
      return false;
    }
  return true;
}

// @todo return status instead
QUIC_CREDENTIAL_CONFIG_HELPER *
NewCredConfig(ErlNifEnv *env, const ERL_NIF_TERM *option)
{
  ERL_NIF_TERM cert;
  ERL_NIF_TERM key;
  QUIC_CREDENTIAL_CONFIG_HELPER *Config;

  char *cert_path = malloc(PATH_MAX);
  char *key_path = malloc(PATH_MAX);

  if (!enif_get_map_value(env, *option, ATOM_CERT, &cert))
    {
      return NULL;
    }

  if (!enif_get_map_value(env, *option, ATOM_KEY, &key))
    {
      return NULL;
    }

  if (!enif_get_string(env, cert, cert_path, PATH_MAX, ERL_NIF_LATIN1))
    {
      return NULL;
    }

  if (!enif_get_string(env, key, key_path, PATH_MAX, ERL_NIF_LATIN1))
    {
      return NULL;
    }

  Config = (QUIC_CREDENTIAL_CONFIG_HELPER *)CXPLAT_ALLOC_NONPAGED(
      sizeof(QUIC_CREDENTIAL_CONFIG_HELPER), QUICER_CREDENTIAL_CONFIG_HELPER);

  CxPlatZeroMemory(Config, sizeof(QUIC_CREDENTIAL_CONFIG_HELPER));
  Config->CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  //
  // Loads the server's certificate from the file.
  //
  Config->CertFile.CertificateFile = cert_path;
  Config->CertFile.PrivateKeyFile = key_path;
  Config->CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  Config->CredConfig.CertificateFile = &Config->CertFile;
  // @todo set flag
  // Config->CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS;
  // Config->CredConfig.AsyncHandler = DestroyCredConfig;
  return Config;
}

void
DestroyCredConfig(QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  free((char *)Config->CertFile.CertificateFile);
  free((char *)Config->CertFile.PrivateKeyFile);
  CXPLAT_FREE(Config, QUICER_CREDENTIAL_CONFIG_HELPER);
}

// @todo support per registration.
ERL_NIF_TERM
ServerLoadConfiguration(ErlNifEnv *env,
                        const ERL_NIF_TERM *option,
                        HQUIC *Configuration,
                        QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  QUIC_SETTINGS Settings = { 0 };

  if (!isRegistered)
    {
      return ATOM_REG_FAILED;
    }

  if (!create_settings(env, option, &Settings))
    {
      return ATOM_BADARG;
    }

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER alpn_buffers[MAX_ALPN] = { 0 };

  if (!load_alpn(env, option, &alpn_buffer_length, alpn_buffers))
    {
      return ATOM_ALPN;
    }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration,
                                                     alpn_buffers,
                                                     alpn_buffer_length,
                                                     &Settings,
                                                     sizeof(Settings),
                                                     NULL,
                                                     Configuration)))
    {
      return atom_status(Status);
    }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      *Configuration, &Config->CredConfig)))
    {
      return atom_status(Status);
    }

  return ATOM_OK;
}

// @todo return status instead
ERL_NIF_TERM
ClientLoadConfiguration(ErlNifEnv *env,
                        const ERL_NIF_TERM *option,
                        HQUIC *Configuration,
                        bool Unsecure)
{
  QUIC_SETTINGS Settings = { 0 };
  //
  // Configures the client's idle timeout.
  //

  if (!create_settings(env, option, &Settings))
    {
      return ATOM_BADARG;
    }

  // Uncomment to make client prefer to use Draft-29
  // This is for Draft-29 version in HOST byte order.
  /* const uint32_t DesiredVersion = 0xff00001dU; */
  /* Settings.DesiredVersionsList = &DesiredVersion; */
  /* Settings.DesiredVersionsListLength = 1; */
  /* Settings.IsSet.DesiredVersionsList = TRUE; */

  //
  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  //
  QUIC_CREDENTIAL_CONFIG CredConfig;
  CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure)
    {
      CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER alpn_buffers[MAX_ALPN];

  if (!load_alpn(env, option, &alpn_buffer_length, alpn_buffers))
    {
      return ATOM_ALPN;
    }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration,
                                                     alpn_buffers,
                                                     alpn_buffer_length,
                                                     &Settings,
                                                     sizeof(Settings),
                                                     NULL,
                                                     Configuration)))
    {
      return atom_status(Status);
    }

  //
  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(*Configuration,
                                                               &CredConfig)))
    {
      return atom_status(Status);
    }

  return ATOM_OK;
}

bool
load_alpn(ErlNifEnv *env,
          const ERL_NIF_TERM *option,
          unsigned *alpn_buffer_length,
          QUIC_BUFFER alpn_buffers[])
{
  ERL_NIF_TERM alpn_list;
  if (!enif_get_map_value(env, *option, ATOM_ALPN, &alpn_list))
    {
      return false;
    }

  if (!enif_get_list_length(env, alpn_list, alpn_buffer_length))
    {
      return false;
    }

  ERL_NIF_TERM head, tail;

  if (!enif_get_list_cell(env, alpn_list, &head, &tail))
    {
      return false;
    }

  for (int i = 0; i < (int)(*alpn_buffer_length); i++)
    {
      // @todo check if PATH_MAX is the correct length
      char str[PATH_MAX];
      if (!enif_get_string(env, head, str, PATH_MAX, ERL_NIF_LATIN1))
        {
          return false;
        }

      alpn_buffers[i].Buffer = (uint8_t *)str;
      alpn_buffers[i].Length = strlen(str);

      if (!enif_get_list_cell(env, tail, &head, &tail)
          && i + 1 < (int)(*alpn_buffer_length))
        {
          return false;
        }
    }

  return true;
}

bool
get_uint8_from_map(ErlNifEnv *env,
                   const ERL_NIF_TERM map,
                   ERL_NIF_TERM key,
                   uint8_t *value)
{
  ERL_NIF_TERM evalue;
  if (!enif_get_map_value(env, map, key, &evalue))
    {
      return false;
    }

  unsigned int value0 = 0;

  if (!enif_get_uint(env, evalue, &value0))
    {
      return false;
    }

  if (value0 > UINT8_MAX)
    {
      return false;
    }

  *value = (uint8_t)value0;

  return true;
}

bool
get_uint16_from_map(ErlNifEnv *env,
                    const ERL_NIF_TERM map,
                    ERL_NIF_TERM key,
                    uint16_t *value)
{
  ERL_NIF_TERM evalue;
  if (!enif_get_map_value(env, map, key, &evalue))
    {
      return false;
    }

  unsigned int value0 = 0;
  if (!enif_get_uint(env, evalue, &value0))
    {
      return false;
    }

  if (value0 > UINT16_MAX)
    {
      return false;
    }

  *value = (uint16_t)value0;
  return true;
}

bool
get_uint32_from_map(ErlNifEnv *env,
                    const ERL_NIF_TERM map,
                    ERL_NIF_TERM key,
                    uint32_t *value)
{
  ERL_NIF_TERM evalue;
  if (!enif_get_map_value(env, map, key, &evalue))
    {
      return false;
    }

  return enif_get_uint(env, evalue, value);
}

bool
get_uint64_from_map(ErlNifEnv *env,
                    const ERL_NIF_TERM map,
                    ERL_NIF_TERM key,
                    uint64_t *value)
{
  ERL_NIF_TERM evalue;
  if (!enif_get_map_value(env, map, key, &evalue))
    {
      return false;
    }

#ifdef __APPLE__
  return enif_get_uint64(env, evalue, (unsigned long *)value);
#else
  return enif_get_uint64(env, evalue, value);
#endif
}

ERL_NIF_TERM
encode_parm_to_eterm(ErlNifEnv *env,
                     QUIC_PARAM_LEVEL Level,
                     uint32_t Param,
                     uint32_t BufferLength,
                     void *Buffer)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  if (QUIC_PARAM_CONN_STATISTICS == Param
      && QUIC_PARAM_LEVEL_CONNECTION == Level
      && sizeof(QUIC_STATISTICS) == BufferLength)
    {
      QUIC_STATISTICS *statics = (QUIC_STATISTICS *)Buffer;
      res = SUCCESS(enif_make_list(
          env,
          20,
          PropTupleStrInt(Timing.Start, statics->Timing.Start),
          PropTupleStrInt(
              Timing.InitialFlightEnd,
              statics->Timing
                  .InitialFlightEnd), // Processed all peer's Initial packets
          PropTupleStrInt(
              Timing.HandshakeFlightEnd,
              statics->Timing.HandshakeFlightEnd), // Processed all peer's
                                                   // Handshake packets
          PropTupleStrInt(Send.PathMtu,
                          statics->Send.PathMtu), // Current path MTU.
          PropTupleStrInt(
              Send.TotalPackets,
              statics->Send
                  .TotalPackets), // QUIC packets, statics.Send.TotalPackets;
                                  // // QUIC packets), could be coalesced into
                                  // fewer UDP datagrams.
          PropTupleStrInt(Send.RetransmittablePackets,
                          statics->Send.RetransmittablePackets),
          PropTupleStrInt(Send.SuspectedLostPackets,
                          statics->Send.SuspectedLostPackets),
          PropTupleStrInt(
              Send.SpuriousLostPackets,
              statics->Send.SpuriousLostPackets), // Actual lost is
                                                  // (SuspectedLostPackets -
                                                  // SpuriousLostPackets)
          PropTupleStrInt(Send.TotalBytes,
                          statics->Send.TotalBytes), // Sum of UDP payloads
          PropTupleStrInt(
              Send.TotalStreamBytes,
              statics->Send.TotalStreamBytes), // Sum of stream payloads
          PropTupleStrInt(
              Send.CongestionCount,
              statics->Send.CongestionCount), // Number of congestion events
          PropTupleStrInt(
              Send.PersistentCongestionCount,
              statics->Send.PersistentCongestionCount), // Number of persistent
                                                        // congestion events
          PropTupleStrInt(
              Recv.TotalPackets,
              statics->Recv
                  .TotalPackets), // QUIC packets, statics->Recv.TotalPackets;
                                  // // QUIC packets), could be coalesced into
                                  // fewer UDP datagrams.
          PropTupleStrInt(
              Recv.ReorderedPackets,
              statics->Recv.ReorderedPackets), // Packets where packet number
                                               // is less than highest seen.
          PropTupleStrInt(
              Recv.DroppedPackets,
              statics->Recv.DroppedPackets), // Includes DuplicatePackets.
          PropTupleStrInt(Recv.DuplicatePackets,
                          statics->Recv.DuplicatePackets),
          PropTupleStrInt(Recv.TotalBytes,
                          statics->Recv.TotalBytes), // Sum of UDP payloads
          PropTupleStrInt(
              Recv.TotalStreamBytes,
              statics->Recv.TotalStreamBytes), // Sum of stream payloads
          PropTupleStrInt(
              Recv.DecryptionFailures,
              statics->Recv
                  .DecryptionFailures), // Count of packet decryption failures.
          PropTupleStrInt(
              Recv.ValidAckFrames,
              statics->Recv.ValidAckFrames) // Count of receive ACK frames.
          ));
    }
  else if (QUIC_PARAM_CONN_SETTINGS == Param
           && QUIC_PARAM_LEVEL_CONNECTION == Level)
    {
      QUIC_SETTINGS *Settings = (QUIC_SETTINGS *)Buffer;
      res = SUCCESS(enif_make_list(
          env,
          26,
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_MaxBytesPerKey,
                           Settings->MaxBytesPerKey),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_HandshakeIdleTimeoutMs,
                           Settings->HandshakeIdleTimeoutMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_IdleTimeoutMs,
                           Settings->IdleTimeoutMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer,
                           Settings->TlsClientMaxSendBuffer),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_TlsServerMaxSendBuffer,
                           Settings->TlsServerMaxSendBuffer),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_StreamRecvWindowDefault,
                           Settings->StreamRecvWindowDefault),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_StreamRecvBufferDefault,
                           Settings->StreamRecvBufferDefault),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_ConnFlowControlWindow,
                           Settings->ConnFlowControlWindow),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_MaxWorkerQueueDelayUs,
                           Settings->MaxWorkerQueueDelayUs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_MaxStatelessOperations,
                           Settings->MaxStatelessOperations),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_InitialWindowPackets,
                           Settings->InitialWindowPackets),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_SendIdleTimeoutMs,
                           Settings->SendIdleTimeoutMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_InitialRttMs,
                           Settings->InitialRttMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_MaxAckDelayMs,
                           Settings->MaxAckDelayMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_DisconnectTimeoutMs,
                           Settings->DisconnectTimeoutMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_KeepAliveIntervalMs,
                           Settings->KeepAliveIntervalMs),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_PeerBidiStreamCount,
                           Settings->PeerBidiStreamCount),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_PeerUnidiStreamCount,
                           Settings->PeerBidiStreamCount),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_RetryMemoryLimit,
                           Settings->RetryMemoryLimit),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_LoadBalancingMode,
                           Settings->LoadBalancingMode),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_MaxOperationsPerDrain,
                           Settings->MaxOperationsPerDrain),
          PropTupleAtomBool(ATOM_QUIC_SETTINGS_SendBufferingEnabled,
                            Settings->SendBufferingEnabled),
          PropTupleAtomBool(ATOM_QUIC_SETTINGS_PacingEnabled,
                            Settings->PacingEnabled),
          PropTupleAtomBool(ATOM_QUIC_SETTINGS_MigrationEnabled,
                            Settings->MigrationEnabled),
          PropTupleAtomBool(ATOM_QUIC_SETTINGS_DatagramReceiveEnabled,
                            Settings->DatagramReceiveEnabled),
          PropTupleAtomInt(ATOM_QUIC_SETTINGS_ServerResumptionLevel,
                           Settings->ServerResumptionLevel)));
    }
  else if (QUIC_PARAM_STREAM_ID == Param && QUIC_PARAM_LEVEL_STREAM == Level)
    {
      res = SUCCESS(ETERM_UINT_64(*(uint64_t *)Buffer));
    }
  else if (QUIC_PARAM_CONN_REMOTE_ADDRESS == Param
           && QUIC_PARAM_LEVEL_CONNECTION == Level)
    {
      res = SUCCESS(addr2eterm(env, (QUIC_ADDR *)Buffer));
    }

  return res;
}

ERL_NIF_TERM
getopt3(ErlNifEnv *env,
        __unused_parm__ int argc,
        __unused_parm__ const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM eopt = argv[1];
  ERL_NIF_TERM eisRaw = argv[2];

  HQUIC Handle = NULL;
  uint32_t Param;
  QUIC_PARAM_LEVEL Level;
  uint32_t BufferLength = 0;
  ErlNifBinary bin;
  bool isReturnRaw = true;
  bool isLevelOK = false;
  bool isMalloc = false;

  void *q_ctx;
  void *Buffer = NULL;
  /* QuicerListenerCTX *l_ctx = NULL; */
  /* QuicerConnCTX *c_ctx = NULL; */
  /* QuicerStreamCTX *s_ctx = NULL; */

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (eisRaw == ATOM_FALSE)
    {
      isReturnRaw = false;
    }

  if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      Handle = ((QuicerStreamCTX *)q_ctx)->Stream;
      Level = QUIC_PARAM_LEVEL_STREAM;
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      Handle = ((QuicerConnCTX *)q_ctx)->Connection;
      Level = QUIC_PARAM_LEVEL_CONNECTION;
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
      Level = QUIC_PARAM_LEVEL_LISTENER;
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // Matching PARMs in a hard way...
  if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_QUIC_VERSION))
    {
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_QUIC_VERSION;
      // QUIC_CONNECTION.stats.QuicVersion
      BufferLength = sizeof(u_int32_t);
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_STATISTICS))
    {
      if (q_ctx && Level == QUIC_PARAM_LEVEL_STREAM)
        {
          // msquic has no stats on stream level, Lets fallback to connection
          // for now
          Level = QUIC_PARAM_LEVEL_CONNECTION;
          Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
        }
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_STATISTICS;
      BufferLength = sizeof(QUIC_STATISTICS);
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_SETTINGS))
    {
      if (q_ctx && Level == QUIC_PARAM_LEVEL_STREAM)
        {
          // fallback to connection for now
          Level = QUIC_PARAM_LEVEL_CONNECTION;
          Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
        }
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_SETTINGS;
      BufferLength = sizeof(QUIC_SETTINGS);
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_STREAM_ID))
    {
      isLevelOK = Level == QUIC_PARAM_LEVEL_STREAM;
      Param = QUIC_PARAM_STREAM_ID;
      BufferLength = sizeof(uint64_t);
      uint64_t stream_id = 0;
      Buffer = &stream_id;
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS))
    {
      QUIC_ADDR addr;
      if (q_ctx && Level == QUIC_PARAM_LEVEL_STREAM)
        {
          // Lets fallback to connection for now
          Level = QUIC_PARAM_LEVEL_CONNECTION;
          Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
        }
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_REMOTE_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
    }
  else if (Level == QUIC_PARAM_LEVEL_STREAM
           && IS_SAME_TERM(eopt, ATOM_QUIC_STREAM_OPTS_ACTIVE))
    {
      QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)q_ctx;
      ERL_NIF_TERM eterm = ATOM_FALSE;
      enif_mutex_lock(s_ctx->lock);
      if (!(ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active))
        {
          eterm = ATOM_TRUE;
        }
      enif_mutex_unlock(s_ctx->lock);
      return SUCCESS(eterm);
    }
  else
    {
      return ERROR_TUPLE_2(ATOM_PARM_ERROR);
    }

  if (!isLevelOK)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  // precheck before calling msquic api
  if (Level < 0)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
    }

  if (isReturnRaw)
    {
      // If true, we return binary.
      // @todo consider use enif_make_new_binary ?
      if (!enif_alloc_binary(BufferLength, &bin))
        {
          return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
        }
      else
        {
          Buffer = bin.data;
        }
    }
  else if (!Buffer)
    { // when Buffer is not initialized.
      Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUICER_OPT_BUFF);
      isMalloc = true;
    }

  QUIC_STATUS status
      = MsQuic->GetParam(Handle, Level, Param, &BufferLength, Buffer);

  if (!QUIC_SUCCEEDED(status))
    {
      if (isReturnRaw)
        {
          enif_release_binary(&bin);
        }
      return ERROR_TUPLE_2(atom_status(status));
    }

  if (isReturnRaw)
    {
      return SUCCESS(enif_make_binary(env, &bin));
    }
  else
    {
      ERL_NIF_TERM res
          = encode_parm_to_eterm(env, Level, Param, BufferLength, Buffer);
      if (isMalloc)
        {
          CXPLAT_FREE(Buffer, QUICER_OPT_BUFF);
        }
      return res;
    }
}

ERL_NIF_TERM
setopt3(ErlNifEnv *env,
        __unused_parm__ int argc,
        __unused_parm__ const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM eopt = argv[1];
  ERL_NIF_TERM evalue = argv[2];

  HQUIC Handle = NULL;
  QUIC_PARAM_LEVEL Level;
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;

  void *q_ctx;

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      Handle = ((QuicerStreamCTX *)q_ctx)->Stream;
      Level = QUIC_PARAM_LEVEL_STREAM;
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      Handle = ((QuicerConnCTX *)q_ctx)->Connection;
      Level = QUIC_PARAM_LEVEL_CONNECTION;
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      Handle = ((QuicerListenerCTX *)q_ctx)->Listener;
      Level = QUIC_PARAM_LEVEL_LISTENER;
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_SETTINGS))
    {
      if (q_ctx && Level == QUIC_PARAM_LEVEL_STREAM)
        {
          // Lets fallback to connection for now
          Level = QUIC_PARAM_LEVEL_CONNECTION;
          Handle = ((QuicerStreamCTX *)q_ctx)->c_ctx->Connection;
        }

      if (Level != QUIC_PARAM_LEVEL_CONNECTION)
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      QUIC_SETTINGS Settings = { 0 };
      if (!create_settings(env, &evalue, &Settings))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      if (QUIC_FAILED(MsQuic->SetParam(Handle,
                                       QUIC_PARAM_LEVEL_CONNECTION,
                                       QUIC_PARAM_CONN_SETTINGS,
                                       sizeof(Settings),
                                       &Settings)))
        {
          return ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
        }
      return ATOM_OK;
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_STREAM_OPTS_ACTIVE)
           && Level == QUIC_PARAM_LEVEL_STREAM)
    {
      QuicerStreamCTX *s_ctx = (QuicerStreamCTX *)q_ctx;
      enif_mutex_lock(s_ctx->lock);

      if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active
          && s_ctx->is_buff_ready && s_ctx->TotalBufferLength > 0)
        {
          // trigger callback of event recv.
          MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
          MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE);
        }
      if (!set_owner_recv_mode(s_ctx->owner, env, evalue))
        {
          enif_mutex_unlock(s_ctx->lock);
          return ERROR_TUPLE_2(ATOM_PARM_ERROR);
        }

      enif_mutex_unlock(s_ctx->lock);
      return ATOM_OK;
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS))
    {
      QUIC_ADDR Address;
      if (!parse_listen_on(env, evalue, &Address))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      if (QUIC_FAILED(status = MsQuic->SetParam(Handle,
                                                QUIC_PARAM_LEVEL_CONNECTION,
                                                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                                                sizeof(QUIC_ADDR),
                                                &Address)))
        {
          return ERROR_TUPLE_2(atom_status(status));
        }
      else
        {
          return ATOM_OK;
        }
    }
  else
    { //@todo support more param
      return ERROR_TUPLE_2(ATOM_PARM_ERROR);
    }
}

bool
create_settings(ErlNifEnv *env,
                const ERL_NIF_TERM *emap,
                QUIC_SETTINGS *Settings)
{
  if (!enif_is_map(env, *emap))
    {
      return false;
    }

  CxPlatZeroMemory(Settings, sizeof(QUIC_SETTINGS));

  if (get_uint64_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_MaxBytesPerKey,
                          &Settings->MaxBytesPerKey))
    {
      Settings->IsSet.MaxBytesPerKey = TRUE;
    }
  if (get_uint64_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_HandshakeIdleTimeoutMs,
                          &Settings->HandshakeIdleTimeoutMs))
    {
      Settings->IsSet.HandshakeIdleTimeoutMs = TRUE;
    }
  if (get_uint64_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_IdleTimeoutMs,
                          &Settings->IdleTimeoutMs))
    {
      Settings->IsSet.IdleTimeoutMs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer,
                          &Settings->TlsClientMaxSendBuffer))
    {
      Settings->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_TlsClientMaxSendBuffer,
                          &Settings->TlsClientMaxSendBuffer))
    {
      Settings->IsSet.TlsClientMaxSendBuffer = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_TlsServerMaxSendBuffer,
                          &Settings->TlsServerMaxSendBuffer))
    {
      Settings->IsSet.TlsServerMaxSendBuffer = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_StreamRecvWindowDefault,
                          &Settings->StreamRecvWindowDefault))
    {
      Settings->IsSet.StreamRecvWindowDefault = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_StreamRecvBufferDefault,
                          &Settings->StreamRecvBufferDefault))
    {
      Settings->IsSet.StreamRecvBufferDefault = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_ConnFlowControlWindow,
                          &Settings->ConnFlowControlWindow))
    {
      Settings->IsSet.ConnFlowControlWindow = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_MaxWorkerQueueDelayUs,
                          &Settings->MaxWorkerQueueDelayUs))
    {
      Settings->IsSet.MaxWorkerQueueDelayUs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_MaxStatelessOperations,
                          &Settings->MaxStatelessOperations))
    {
      Settings->IsSet.MaxStatelessOperations = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_InitialWindowPackets,
                          &Settings->InitialWindowPackets))
    {
      Settings->IsSet.InitialWindowPackets = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_SendIdleTimeoutMs,
                          &Settings->SendIdleTimeoutMs))
    {
      Settings->IsSet.SendIdleTimeoutMs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_InitialRttMs,
                          &Settings->InitialRttMs))
    {
      Settings->IsSet.InitialRttMs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_MaxAckDelayMs,
                          &Settings->MaxAckDelayMs))
    {
      Settings->IsSet.MaxAckDelayMs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_DisconnectTimeoutMs,
                          &Settings->DisconnectTimeoutMs))
    {
      Settings->IsSet.DisconnectTimeoutMs = TRUE;
    }
  if (get_uint32_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_KeepAliveIntervalMs,
                          &Settings->KeepAliveIntervalMs))
    {
      Settings->IsSet.KeepAliveIntervalMs = TRUE;
    }
  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_PeerBidiStreamCount,
                          &Settings->PeerBidiStreamCount))
    {
      Settings->IsSet.PeerBidiStreamCount = TRUE;
    }
  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_PeerUnidiStreamCount,
                          &Settings->PeerUnidiStreamCount))
    {
      Settings->IsSet.PeerUnidiStreamCount = TRUE;
    }
  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_RetryMemoryLimit,
                          &Settings->RetryMemoryLimit))
    {
      Settings->IsSet.RetryMemoryLimit = TRUE;
    }
  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_LoadBalancingMode,
                          &Settings->LoadBalancingMode))
    {
      Settings->IsSet.LoadBalancingMode = TRUE;
    }

  // bit fields
  uint8_t MaxOperationsPerDrain = 0;
  uint8_t SendBufferingEnabled = 0;
  uint8_t PacingEnabled = 0;
  uint8_t MigrationEnabled = 0;
  uint8_t DatagramReceiveEnabled = 0;
  uint8_t ServerResumptionLevel = 0;
  if (get_uint8_from_map(env,
                         *emap,
                         ATOM_QUIC_SETTINGS_MaxOperationsPerDrain,
                         &MaxOperationsPerDrain))
    {
      Settings->MaxOperationsPerDrain = MaxOperationsPerDrain;
      Settings->IsSet.MaxOperationsPerDrain = TRUE;
    }
  if (get_uint8_from_map(env,
                         *emap,
                         ATOM_QUIC_SETTINGS_SendBufferingEnabled,
                         &SendBufferingEnabled))
    {
      Settings->SendBufferingEnabled = SendBufferingEnabled;
      Settings->IsSet.SendBufferingEnabled = TRUE;
    }
  if (get_uint8_from_map(
          env, *emap, ATOM_QUIC_SETTINGS_PacingEnabled, &PacingEnabled))
    {
      Settings->PacingEnabled = PacingEnabled;
      Settings->IsSet.PacingEnabled = TRUE;
    }
  if (get_uint8_from_map(
          env, *emap, ATOM_QUIC_SETTINGS_MigrationEnabled, &MigrationEnabled))
    {
      Settings->MigrationEnabled = MigrationEnabled;
      Settings->IsSet.MigrationEnabled = TRUE;
    }
  if (get_uint8_from_map(env,
                         *emap,
                         ATOM_QUIC_SETTINGS_DatagramReceiveEnabled,
                         &DatagramReceiveEnabled))
    {
      Settings->DatagramReceiveEnabled = DatagramReceiveEnabled;
      Settings->IsSet.DatagramReceiveEnabled = TRUE;
    }
  if (get_uint8_from_map(env,
                         *emap,
                         ATOM_QUIC_SETTINGS_ServerResumptionLevel,
                         &ServerResumptionLevel))
    {
      Settings->ServerResumptionLevel = ServerResumptionLevel;
      Settings->IsSet.ServerResumptionLevel = TRUE;
    }

  return true;
}

bool
parse_listen_on(ErlNifEnv *env, ERL_NIF_TERM elisten_on, QUIC_ADDR *Address)
{
  char listen_on[INET6_ADDRSTRLEN + 6] = { 0 };
  if (enif_get_string(
          env, elisten_on, listen_on, INET6_ADDRSTRLEN + 6, ERL_NIF_LATIN1)
      > 0)
    {
      if ((QuicAddr4FromString(listen_on, Address)
           || QuicAddr6FromString(listen_on, Address)))
        {
          return TRUE;
        }
    }
  return FALSE;
}
