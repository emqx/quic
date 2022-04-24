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

static ERL_NIF_TERM get_stream_opt(ErlNifEnv *env,
                                   QuicerStreamCTX *s_ctx,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM elevel);
static ERL_NIF_TERM set_stream_opt(ErlNifEnv *env,
                                   QuicerStreamCTX *s_ctx,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM optval,
                                   ERL_NIF_TERM elevel);

static ERL_NIF_TERM get_connection_opt(ErlNifEnv *env,
                                       QuicerConnCTX *c_ctx,
                                       ERL_NIF_TERM optname,
                                       ERL_NIF_TERM elevel);

static ERL_NIF_TERM get_listener_opt(ErlNifEnv *env,
                                     QuicerListenerCTX *l_ctx,
                                     ERL_NIF_TERM optname,
                                     ERL_NIF_TERM elevel);
static ERL_NIF_TERM set_listener_opt(ErlNifEnv *env,
                                     QuicerListenerCTX *l_ctx,
                                     ERL_NIF_TERM optname,
                                     ERL_NIF_TERM optval,
                                     ERL_NIF_TERM elevel);

static ERL_NIF_TERM
get_config_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_config_opt(ErlNifEnv *env,
                                   HQUIC Hanlder,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM optval);

static ERL_NIF_TERM
get_tls_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_tls_opt(ErlNifEnv *env,
                                HQUIC Hanlder,
                                ERL_NIF_TERM optname,
                                ERL_NIF_TERM optval);

static ERL_NIF_TERM
get_global_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_global_opt(ErlNifEnv *env,
                                   HQUIC Hanlder,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM optval);

static ERL_NIF_TERM get_level_param(ErlNifEnv *env,
                                    HQUIC Handle,
                                    ERL_NIF_TERM level,
                                    ERL_NIF_TERM eopt);
static ERL_NIF_TERM set_level_param(ErlNifEnv *env,
                                    HQUIC Handle,
                                    ERL_NIF_TERM level,
                                    ERL_NIF_TERM eopt,
                                    ERL_NIF_TERM optval);

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
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(GRegistration,
                                                     alpn_buffers,
                                                     alpn_buffer_length,
                                                     &Settings,
                                                     sizeof(Settings),
                                                     NULL,
                                                     Configuration)))
    {
      return ATOM_STATUS(Status);
    }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      *Configuration, &Config->CredConfig)))
    {
      return ATOM_STATUS(Status);
    }

  return ATOM_OK;
}

// @todo return status instead
ERL_NIF_TERM
ClientLoadConfiguration(ErlNifEnv *env,
                        const ERL_NIF_TERM *option, // map
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
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(GRegistration,
                                                     alpn_buffers,
                                                     alpn_buffer_length,
                                                     &Settings,
                                                     sizeof(Settings),
                                                     NULL,
                                                     Configuration)))
    {
      return ATOM_STATUS(Status);
    }

  //
  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(*Configuration,
                                                               &CredConfig)))
    {
      return ATOM_STATUS(Status);
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
get_uint16(ErlNifEnv *env, const ERL_NIF_TERM term, uint16_t *value)
{
  unsigned int value0 = 0;
  if (!enif_get_uint(env, term, &value0))
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
                     uint32_t Param,
                     uint32_t BufferLength,
                     void *Buffer)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  if (QUIC_PARAM_CONN_STATISTICS == Param
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
  else if (QUIC_PARAM_CONN_SETTINGS == Param)
    {
      QUIC_SETTINGS *Settings = (QUIC_SETTINGS *)Buffer;
      res = SUCCESS(enif_make_list(
          env,
          24,
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
  else if (QUIC_PARAM_STREAM_ID == Param)
    {
      res = SUCCESS(ETERM_UINT_64(*(uint64_t *)Buffer));
    }
  else if (QUIC_PARAM_CONN_REMOTE_ADDRESS == Param)
    {
      res = SUCCESS(addr2eterm(env, (QUIC_ADDR *)Buffer));
    }
  else if (QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION == Param)
    {
      res = SUCCESS(ETERM_BOOL(*(BOOLEAN *)Buffer));
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
  ERL_NIF_TERM elevel = argv[2];

  void *q_ctx;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (IS_SAME_TERM(ATOM_QUIC_GLOBAL, ctx))
    {
      res = get_global_opt(env, NULL, eopt);
    }

  if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      res = get_stream_opt(env, (QuicerStreamCTX *)q_ctx, eopt, elevel);
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      res = get_connection_opt(env, (QuicerConnCTX *)q_ctx, eopt, elevel);
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      res = get_listener_opt(env, (QuicerListenerCTX *)q_ctx, eopt, elevel);
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return res;
}

ERL_NIF_TERM
get_level_param(ErlNifEnv *env,
                HQUIC Handle,
                ERL_NIF_TERM eopt,
                ERL_NIF_TERM level)
{
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;
  if (IS_SAME_TERM(ATOM_QUIC_CONFIGURATION, level))
    {
      res = get_config_opt(env, Handle, eopt);
    }
  if (IS_SAME_TERM(ATOM_QUIC_TLS, level))
    {
      res = get_tls_opt(env, Handle, eopt);
    }

  return res;
}

ERL_NIF_TERM
set_level_param(ErlNifEnv *env,
                HQUIC Handle,
                ERL_NIF_TERM level,
                ERL_NIF_TERM eopt,
                ERL_NIF_TERM eval)
{
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;
  if (IS_SAME_TERM(ATOM_QUIC_CONFIGURATION, level))
    {
      res = set_config_opt(env, Handle, eopt, eval);
    }
  if (IS_SAME_TERM(ATOM_QUIC_TLS, level))
    {
      res = set_tls_opt(env, Handle, eopt, eval);
    }

  return res;
}

ERL_NIF_TERM
setopt4(ErlNifEnv *env,
        __unused_parm__ int argc,
        __unused_parm__ const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM eopt = argv[1];
  ERL_NIF_TERM evalue = argv[2];
  ERL_NIF_TERM elevel = argv[3];

  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;
  void *q_ctx = NULL;

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (IS_SAME_TERM(ATOM_QUIC_GLOBAL, ctx))
    {
      res = set_global_opt(env, NULL, eopt, evalue);
    }
  if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      res = set_stream_opt(
          env, (QuicerStreamCTX *)q_ctx, eopt, evalue, elevel);
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      res = set_connection_opt(
          env, (QuicerConnCTX *)q_ctx, eopt, evalue, elevel);
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      res = set_listener_opt(
          env, (QuicerListenerCTX *)q_ctx, eopt, evalue, elevel);
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return res;
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
  if (get_uint16_from_map(
          env, *emap, ATOM_QUIC_SETTINGS_MinimumMtu, &Settings->MinimumMtu))
    {
      Settings->IsSet.MinimumMtu = TRUE;
    }
  if (get_uint16_from_map(
          env, *emap, ATOM_QUIC_SETTINGS_MaximumMtu, &Settings->MaximumMtu))
    {
      Settings->IsSet.MaximumMtu = TRUE;
    }
  if (get_uint64_from_map(
          env,
          *emap,
          ATOM_QUIC_SETTINGS_MtuDiscoverySearchCompleteTimeoutUs,
          &Settings->MtuDiscoverySearchCompleteTimeoutUs))
    {
      Settings->IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE;
    }

  if (get_uint8_from_map(env,
                         *emap,
                         ATOM_QUIC_SETTINGS_MtuDiscoveryMissingProbeCount,
                         &Settings->MtuDiscoveryMissingProbeCount))
    {
      Settings->IsSet.MtuDiscoveryMissingProbeCount = TRUE;
    }

  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_MaxBindingStatelessOperations,
                          &Settings->MaxBindingStatelessOperations))
    {
      Settings->IsSet.MaxBindingStatelessOperations = TRUE;
    }

  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_StatelessOperationExpirationMs,
                          &Settings->StatelessOperationExpirationMs))
    {
      Settings->IsSet.StatelessOperationExpirationMs = TRUE;
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

static ERL_NIF_TERM
get_stream_opt(ErlNifEnv *env,
               QuicerStreamCTX *s_ctx,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = get_level_param(env, s_ctx->Stream, optname, elevel);
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_ID == optname)
    {
      uint64_t stream_id = 0;
      Param = QUIC_PARAM_STREAM_ID;
      BufferLength = sizeof(uint64_t);
      Buffer = &stream_id;
    }
  else if (ATOM_QUIC_STREAM_OPTS_ACTIVE == optname)
    {
      if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active)
        {
          res = SUCCESS(ATOM_FALSE);
        }
      else
        {
          res = SUCCESS(ATOM_TRUE);
        }
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH == optname)
    {
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE == optname)
    {
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (s_ctx->c_ctx)
    {
      res = get_connection_opt(env, s_ctx->c_ctx, optname, elevel);
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  status = MsQuic->GetParam(s_ctx->Stream, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }

Exit:
  return res;
}

static ERL_NIF_TERM
set_stream_opt(ErlNifEnv *env,
               QuicerStreamCTX *s_ctx,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM optval,
               ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  // Non Msquic Opts
  if (IS_SAME_TERM(optname, ATOM_QUIC_STREAM_OPTS_ACTIVE))
    {
      enif_mutex_lock(s_ctx->lock);

      if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active
          && s_ctx->is_buff_ready && s_ctx->TotalBufferLength > 0)
        {
          // trigger callback of event recv.
          MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
          MsQuic->StreamReceiveSetEnabled(s_ctx->Stream, TRUE);
        }
      if (!set_owner_recv_mode(s_ctx->owner, env, optval))
        {
          enif_mutex_unlock(s_ctx->lock);
          return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
        }

      enif_mutex_unlock(s_ctx->lock);
      return ATOM_OK;
    }

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = set_level_param(env, s_ctx->Stream, optname, optval, elevel);
      goto Exit;
    }

  else if (ATOM_QUIC_PARAM_STREAM_ID == optname)
    {
      uint64_t stream_id = 0;
      Param = QUIC_PARAM_STREAM_ID;
      BufferLength = sizeof(uint64_t);
      Buffer = &stream_id;
    }
  else if (ATOM_QUIC_STREAM_OPTS_ACTIVE == optname)
    {
      if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active)
        {
          res = SUCCESS(ATOM_FALSE);
        }
      else
        {
          res = SUCCESS(ATOM_TRUE);
        }
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH == optname)
    {
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE == optname)
    {
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_PRIORITY == optname)
    {
      Param = QUIC_PARAM_STREAM_PRIORITY;
      uint16_t priority;
      if (get_uint16(env, optval, &priority))
        {
          BufferLength = sizeof(uint16_t);
          Buffer = &priority;
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
        }
    }
  else if (s_ctx->c_ctx)
    {
      res = set_connection_opt(env, s_ctx->c_ctx, optname, optval, elevel);
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  status = MsQuic->SetParam(s_ctx->Stream, Param, BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }

Exit:
  return res;
}

static ERL_NIF_TERM
get_connection_opt(ErlNifEnv *env,
                   QuicerConnCTX *c_ctx,
                   ERL_NIF_TERM optname,
                   ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  bool isMalloc = FALSE;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = get_level_param(env, c_ctx->Connection, optname, elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_QUIC_VERSION))
    {
      Param = QUIC_PARAM_CONN_QUIC_VERSION;
      // QUIC_CONNECTION.stats.QuicVersion
      BufferLength = sizeof(u_int32_t);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS))
    {
      QUIC_ADDR addr;
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS))
    {
      QUIC_ADDR addr;
      Param = QUIC_PARAM_CONN_REMOTE_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR))
    {
      Param = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SETTINGS))
    {
      Param = QUIC_PARAM_CONN_SETTINGS;
      BufferLength = sizeof(QUIC_SETTINGS);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_STATISTICS))
    {
      Param = QUIC_PARAM_CONN_STATISTICS;
      BufferLength = sizeof(QUIC_STATISTICS);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT))
    {
      Param = QUIC_PARAM_CONN_STATISTICS_PLAT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING))
    {
      Param = QUIC_PARAM_CONN_SHARE_UDP_BINDING;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS))
    {
      Param = QUIC_PARAM_CONN_MAX_STREAM_IDS;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE))
    {
      Param = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME))
    {
      Param = QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION))
    {
      Param = QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION;
      BufferLength = sizeof(BOOLEAN);
      BOOLEAN BoolVal = FALSE;
      Buffer = &BoolVal;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET))
    {
      Param = QUIC_PARAM_CONN_RESUMPTION_TICKET;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID))
    {
      Param = QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE))
    {
      Param = QUIC_PARAM_CONN_LOCAL_INTERFACE;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (c_ctx->l_ctx)
    {
      res = get_listener_opt(env, c_ctx->l_ctx, optname, elevel);
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  if (!Buffer && !isMalloc)
    { // when Buffer is not initialized.
      Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUICER_OPT_BUFF);
      if (!Buffer)
        {
          goto Exit;
        }
      isMalloc = TRUE;
    }

  status = MsQuic->GetParam(c_ctx->Connection, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }

  if (isMalloc == TRUE)
    {
      free(Buffer);
    }

Exit:
  return res;
}

ERL_NIF_TERM
set_connection_opt(ErlNifEnv *env,
                   QuicerConnCTX *c_ctx,
                   ERL_NIF_TERM optname,
                   ERL_NIF_TERM optval,
                   ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  bool isMalloc = FALSE;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = set_level_param(env, c_ctx->Connection, optname, optval, elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_QUIC_VERSION))
    {
      Param = QUIC_PARAM_CONN_QUIC_VERSION;
      // QUIC_CONNECTION.stats.QuicVersion
      BufferLength = sizeof(u_int32_t);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS))
    {
      QUIC_ADDR addr;
      if (!parse_listen_on(env, optval, &addr))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS))
    {
      QUIC_ADDR addr;
      Param = QUIC_PARAM_CONN_REMOTE_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR))
    {
      Param = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SETTINGS))
    {
      Param = QUIC_PARAM_CONN_SETTINGS;
      BufferLength = sizeof(QUIC_SETTINGS);
      QUIC_SETTINGS Settings = { 0 };
      if (!create_settings(env, &optval, &Settings))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &Settings;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_STATISTICS))
    {
      Param = QUIC_PARAM_CONN_STATISTICS;
      BufferLength = sizeof(QUIC_STATISTICS);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_STATISTICS_PLAT))
    {
      Param = QUIC_PARAM_CONN_STATISTICS_PLAT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING))
    {
      Param = QUIC_PARAM_CONN_SHARE_UDP_BINDING;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS))
    {
      Param = QUIC_PARAM_CONN_MAX_STREAM_IDS;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE))
    {
      Param = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME))
    {
      Param = QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION))
    {
      Param = QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION;
      BOOLEAN value = TRUE;

      if (IS_SAME_TERM(ATOM_TRUE, optval))
        {
          value = TRUE;
        }
      else if (IS_SAME_TERM(ATOM_FALSE, optval))
        {
          value = FALSE;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }

      if (QUIC_SUCCEEDED(
              MsQuic->SetParam(c_ctx->Connection,
                               QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                               sizeof(value),
                               &value)))
        {
          res = ATOM_OK;
          goto Exit;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET))
    {
      Param = QUIC_PARAM_CONN_RESUMPTION_TICKET;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID))
    {
      Param = QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE))
    {
      Param = QUIC_PARAM_CONN_LOCAL_INTERFACE;
      // @TODO
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (c_ctx->l_ctx)
    { // Server
      res = set_listener_opt(env, c_ctx->l_ctx, optname, optval, elevel);
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  if (!Buffer && !isMalloc)
    { // when Buffer is not initialized.
      Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUICER_OPT_BUFF);
      if (!Buffer)
        {
          goto Exit;
        }
      isMalloc = TRUE;
    }

  status = MsQuic->SetParam(c_ctx->Connection, Param, BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }

Exit:
  return res;
}

static ERL_NIF_TERM
get_listener_opt(ErlNifEnv *env,
                 QuicerListenerCTX *l_ctx,
                 ERL_NIF_TERM optname,
                 ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!l_ctx)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(l_ctx->lock);
  if (l_ctx->is_closed)
    {
      enif_mutex_unlock(l_ctx->lock);
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  enif_keep_resource(l_ctx);
  enif_mutex_unlock(l_ctx->lock);

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = get_level_param(env, l_ctx->Listener, optname, elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS))
    {
      // @TODO
      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_STATS))
    {
      // @TODO
      Param = QUIC_PARAM_LISTENER_STATS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(l_ctx->Listener, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  enif_release_resource(l_ctx);
  return res;
}

static ERL_NIF_TERM
set_listener_opt(ErlNifEnv *env,
                 QuicerListenerCTX *l_ctx,
                 ERL_NIF_TERM optname,
                 ERL_NIF_TERM optval,
                 ERL_NIF_TERM elevel)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (!l_ctx)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(l_ctx->lock);
  if (l_ctx->is_closed)
    {
      enif_mutex_unlock(l_ctx->lock);
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  enif_keep_resource(l_ctx);
  enif_mutex_unlock(l_ctx->lock);

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = set_level_param(env, l_ctx->Listener, optname, optval, elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS))
    {
      // @TODO
      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_STATS))
    {
      // @TODO
      Param = QUIC_PARAM_LISTENER_STATS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->SetParam(l_ctx->Listener, Param, BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  enif_release_resource(l_ctx);
  return res;
}

static ERL_NIF_TERM
get_tls_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO))
    {
      // @TODO
      Param = QUIC_PARAM_TLS_HANDSHAKE_INFO;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN))
    {
      // @TODO
      Param = QUIC_PARAM_TLS_NEGOTIATED_ALPN;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Hanlder, Param, &BufferLength, Buffer);
  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}

static ERL_NIF_TERM
set_tls_opt(ErlNifEnv *env,
            HQUIC Hanlder,
            ERL_NIF_TERM optname,
            __unused_parm__ ERL_NIF_TERM optval)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO))
    {
      // @TODO
      Param = QUIC_PARAM_TLS_HANDSHAKE_INFO;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN))
    {
      // @TODO
      Param = QUIC_PARAM_TLS_NEGOTIATED_ALPN;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->SetParam(Hanlder, Param, BufferLength, Buffer);
  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}

static ERL_NIF_TERM
get_global_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_PERF_COUNTERS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SETTINGS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_SETTINGS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_VERSION))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_VERSION_SETTINGS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Hanlder, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}

static ERL_NIF_TERM
set_global_opt(ErlNifEnv *env,
               HQUIC Hanlder,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM optval)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT))
    {
      Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
      uint32_t percent = 0;
      BufferLength = sizeof(uint32_t);
      if (!enif_get_uint(env, optval, &percent) || percent > UINT16_MAX)
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &percent;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_PERF_COUNTERS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SETTINGS))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_SETTINGS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_VERSION))
    {
      // @TODO
      Param = QUIC_PARAM_GLOBAL_VERSION_SETTINGS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->SetParam(Hanlder, Param, BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}

static ERL_NIF_TERM
get_config_opt(ErlNifEnv *env, HQUIC Hanlder, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS))
    {
      // @TODO
      Param = QUIC_PARAM_CONFIGURATION_SETTINGS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Hanlder, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(env, Param, BufferLength, Buffer);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}

static ERL_NIF_TERM
set_config_opt(ErlNifEnv *env,
               HQUIC Hanlder,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM optval)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ATOM_ERROR_NOT_FOUND;

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS))
    {
      Param = QUIC_PARAM_CONFIGURATION_SETTINGS;
      QUIC_SETTINGS Settings = { 0 };
      if (!create_settings(env, &optval, &Settings))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
      BufferLength = sizeof(Settings);
      Buffer = &Settings;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->SetParam(Hanlder, Param, BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = ATOM_OK;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
    }
Exit:
  return res;
}
