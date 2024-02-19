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
#include "quicer_tls.h"
#include <msquichelper.h>

extern QuicerRegistrationCTX *G_r_ctx;
extern pthread_mutex_t MsQuicLock;

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
get_config_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_config_opt(ErlNifEnv *env,
                                   HQUIC Handle,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM optval);

static ERL_NIF_TERM
get_tls_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_tls_opt(ErlNifEnv *env,
                                HQUIC Handle,
                                ERL_NIF_TERM optname,
                                ERL_NIF_TERM optval);

static ERL_NIF_TERM
get_global_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname);
static ERL_NIF_TERM set_global_opt(ErlNifEnv *env,
                                   HQUIC Handle,
                                   ERL_NIF_TERM optname,
                                   ERL_NIF_TERM optval);

static ERL_NIF_TERM get_level_param(ErlNifEnv *env,
                                    HQUIC Handle,
                                    HQUIC ConfigHandle,
                                    ERL_NIF_TERM eopt,
                                    ERL_NIF_TERM level);
static ERL_NIF_TERM set_level_param(ErlNifEnv *env,
                                    HQUIC Handle,
                                    HQUIC ConfigHandle,
                                    ERL_NIF_TERM eopt,
                                    ERL_NIF_TERM optval,
                                    ERL_NIF_TERM level);

// Prepare for Async CredConfig loading
/* static void CompleteCredconfigLoadHook(HQUIC Configuration, */
/*                                        void *Context, */
/*                                        QUIC_STATUS Status); */

BOOLEAN
ReloadCertConfig(HQUIC Configuration, QUIC_CREDENTIAL_CONFIG *CredConfig)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration,
                                                               CredConfig)))
    {
      return false;
    }
  return true;
}

/*
void
CompleteCredconfigLoadHook(HQUIC Configuration,
                           void *Context,
                           QUIC_STATUS Status)
{

  if (!Configuration || QUIC_FAILED(Status))
    {
      fprintf(stderr, "async load of configuration error!\n");
    }

  DestroyCredConfig((QUIC_CREDENTIAL_CONFIG *)Context);
}

void
DestroyCredConfig(QUIC_CREDENTIAL_CONFIG *Config)
{
  switch (Config->Type)
    {
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
      free((char *)Config->CertificateFile->CertificateFile);
      free((char *)Config->CertificateFile->PrivateKeyFile);
      CXPLAT_FREE(Config->CertificateFile, QUICER_CERTIFICATE_FILE);
      break;

    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
      free((char *)Config->CertificateFileProtected->CertificateFile);
      free((char *)Config->CertificateFileProtected->PrivateKeyFile);
      CXPLAT_FREE(Config->CertificateFileProtected,
                  QUICER_CERTIFICATE_FILE_PROTECTED);
      break;

    default:
      break;
    }
  CXPLAT_FREE(Config, QUICER_CREDENTIAL_CONFIG);
}
*/

ERL_NIF_TERM
atom_proto_vsn(QUIC_TLS_PROTOCOL_VERSION vsn)
{
  if (vsn == QUIC_TLS_PROTOCOL_1_3)
    return ATOM_TLS_VSN_1_3;
  else
    {
      return ATOM_NONE;
    }
}
ERL_NIF_TERM
atom_cipher_algorithm(QUIC_CIPHER_ALGORITHM alg)
{
  switch (alg)
    {
    case QUIC_CIPHER_ALGORITHM_NONE:
      return ATOM_NONE;
    case QUIC_CIPHER_ALGORITHM_AES_128:
      return ATOM_AES_128;
    case QUIC_CIPHER_ALGORITHM_AES_256:
      return ATOM_AES_256;
    case QUIC_CIPHER_ALGORITHM_CHACHA20:
      return ATOM_CHACHA20;
    default:
      return ATOM_UNDEFINED;
    }
}
ERL_NIF_TERM
atom_hash_algorithm(QUIC_HASH_ALGORITHM alg)
{
  switch (alg)
    {
    case QUIC_HASH_ALGORITHM_NONE:
      return ATOM_NONE;
    case QUIC_HASH_ALGORITHM_SHA_256:
      return ATOM_SHA_256;
    case QUIC_HASH_ALGORITHM_SHA_384:
      return ATOM_SHA_384;
    default:
      return ATOM_UNDEFINED;
    }
}

ERL_NIF_TERM
atom_key_exchange_algorithm(QUIC_KEY_EXCHANGE_ALGORITHM alg)
{
  if (alg == QUIC_KEY_EXCHANGE_ALGORITHM_NONE)
    return ATOM_NONE;
  else
    {
      return ATOM_UNDEFINED;
    }
}

ERL_NIF_TERM
atom_cipher_suite(QUIC_CIPHER_SUITE suite)
{
  switch (suite)
    {
    case QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256:
      return ATOM_AES_128_GCM_SHA256;
    case QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384:
      return ATOM_AES_256_GCM_SHA384;
    case QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256:
      return ATOM_CHACHA20_POLY1305_SHA256;
    default:
      return ATOM_UNDEFINED;
    }
}

// @todo support per registration.
ERL_NIF_TERM
ServerLoadConfiguration(ErlNifEnv *env,
                        const ERL_NIF_TERM *option,
                        HQUIC Registration,
                        HQUIC *Configuration,
                        QUIC_CREDENTIAL_CONFIG *CredConfig)
{
  QUIC_SETTINGS Settings = { 0 };

  if (!G_r_ctx)
    {
      return ATOM_REG_FAILED;
    }

  if (!create_settings(env, option, &Settings))
    {
      return ATOM_BADARG;
    }

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER *alpn_buffers = NULL;

  if (!load_alpn(env, option, &alpn_buffer_length, &alpn_buffers))
    {
      return ATOM_ALPN;
    }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = MsQuic->ConfigurationOpen(Registration,
                                                 alpn_buffers,
                                                 alpn_buffer_length,
                                                 &Settings,
                                                 sizeof(Settings),
                                                 CredConfig, // Context
                                                 Configuration);
  free_alpn_buffers(alpn_buffers, alpn_buffer_length);
  if (QUIC_FAILED(Status))
    {
      return ATOM_STATUS(Status);
    }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(*Configuration,
                                                               CredConfig)))
    {
      return ATOM_STATUS(Status);
    }

  return ATOM_OK;
}

// @todo return status instead
ERL_NIF_TERM
ClientLoadConfiguration(ErlNifEnv *env,
                        const ERL_NIF_TERM *options, // map
                        HQUIC Registration,
                        HQUIC *Configuration)
{
  QUIC_SETTINGS Settings = { 0 };
  ERL_NIF_TERM ret = ATOM_OK;

  if (!G_r_ctx)
    {
      return ATOM_REG_FAILED;
    }

  //
  // Configures the client's idle timeout.
  //

  if (!create_settings(env, options, &Settings))
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
  // Configures a default client configuration
  //
  QUIC_CREDENTIAL_CONFIG CredConfig;
  CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;

  // certs and keys are optional at client side
  parse_cert_options(env, *options, &CredConfig);

  // If Verify Peer...
  if (!parse_verify_options(env, *options, &CredConfig, FALSE, NULL))
    {
      return ERROR_TUPLE_2(ATOM_VERIFY);
    }

  unsigned alpn_buffer_length = 0;
  QUIC_BUFFER *alpn_buffers = NULL;

  if (!load_alpn(env, options, &alpn_buffer_length, &alpn_buffers))
    {
      ret = ATOM_ALPN;
      goto done;
    }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = MsQuic->ConfigurationOpen(Registration,
                                                 alpn_buffers,
                                                 alpn_buffer_length,
                                                 &Settings,
                                                 sizeof(Settings),
                                                 NULL,
                                                 Configuration);
  free_alpn_buffers(alpn_buffers, alpn_buffer_length);
  if (QUIC_FAILED(Status))
    {
      ret = ATOM_STATUS(Status);
      goto done;
    }

  //
  // Loads the TLS credential part of the configuration. This is required
  // even on client side, to indicate if a certificate is required or not.
  //

  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(*Configuration,
                                                               &CredConfig)))
    {
      ret = ATOM_STATUS(Status);
      goto done;
    }

done:

  // Cleanup CredConfig
  free_certificate(&CredConfig);
  return ret;
}

/*
** load alpn from eterm options to the alpn_buffers
** @NOTE 1:caller must call free_alpn_buffers after use
*/
bool
load_alpn(ErlNifEnv *env,
          const ERL_NIF_TERM *options,
          unsigned *alpn_buffer_length,
          QUIC_BUFFER **alpn_buffers)
{
  ERL_NIF_TERM alpn_list;
  assert(*alpn_buffers == NULL);
  if (!enif_get_map_value(env, *options, ATOM_ALPN, &alpn_list))
    {
      return false;
    }

  if (!enif_get_list_length(env, alpn_list, alpn_buffer_length)
      || alpn_buffer_length == 0)
    {
      return false;
    }

  *alpn_buffers = malloc((*alpn_buffer_length) * sizeof(QUIC_BUFFER));

  if (!*alpn_buffers)
    {
      return false;
    }

  CxPlatZeroMemory(*alpn_buffers, (*alpn_buffer_length) * sizeof(QUIC_BUFFER));

  ERL_NIF_TERM list, head, tail;
  unsigned i = 0;
  list = alpn_list;
  while (enif_get_list_cell(env, list, &head, &tail))
    {
      unsigned len = 0;
#if ERL_NIF_MINOR_VERSION > 16
      if (!enif_get_string_length(env, head, &len, ERL_NIF_LATIN1))
#else
      if (!enif_get_list_length(env, head, &len))
#endif
        {
          goto exit;
        }
      len++; // for '\0'
      char *str = malloc(len * sizeof(char));

      if (enif_get_string(env, head, str, len, ERL_NIF_LATIN1) <= 0)
        {
          free(str);
          str = NULL;
          goto exit;
        }

      (*alpn_buffers)[i].Buffer = (uint8_t *)str;
      (*alpn_buffers)[i].Length = len - 1; // msquic doesn't need '\0'
      i++;
      list = tail;
    }
  return true;

exit:
  free_alpn_buffers(*alpn_buffers, i);
  return false;
}

void
free_alpn_buffers(QUIC_BUFFER *alpn_buffers, unsigned len)
{
  for (unsigned i = 0; i < len; i++)
    {
      free(alpn_buffers[i].Buffer);
    }
  free(alpn_buffers);
  alpn_buffers = NULL;
}

bool
load_verify(ErlNifEnv *env, const ERL_NIF_TERM *options, bool default_verify)
{
  ERL_NIF_TERM verify_atom;
  if (!enif_get_map_value(env, *options, ATOM_VERIFY, &verify_atom))
    return default_verify;

  if (verify_atom == ATOM_PEER || verify_atom == ATOM_VERIFY_PEER)
    return true;
  else if (verify_atom == ATOM_NONE || verify_atom == ATOM_VERIFY_NONE)
    return false;
  else
    return default_verify;
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
                     QUICER_PARAM_HANDLE_TYPE Type,
                     uint32_t Param,
                     uint32_t BufferLength,
                     void *Buffer)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  if (QUICER_PARAM_HANDLE_TYPE_CONN == Type
      && QUIC_PARAM_CONN_STATISTICS == Param
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
  else if ((QUIC_PARAM_CONN_SETTINGS == Param
            && QUICER_PARAM_HANDLE_TYPE_CONN == Type)
           || (QUIC_PARAM_CONFIGURATION_SETTINGS == Param
               && QUICER_PARAM_HANDLE_TYPE_CONFIG == Type)
           || (QUIC_PARAM_GLOBAL_SETTINGS == Param
               && QUICER_PARAM_HANDLE_TYPE_GLOBAL == Type))
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
                           Settings->PeerUnidiStreamCount),
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
  else if ((QUICER_PARAM_HANDLE_TYPE_STREAM == Type
            && (QUIC_PARAM_STREAM_ID == Param
                || QUIC_PARAM_STREAM_PRIORITY == Param
                || QUIC_PARAM_STREAM_0RTT_LENGTH == Param
                || QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE == Param))
           || (QUICER_PARAM_HANDLE_TYPE_CONN == Type
               && (QUIC_PARAM_CONN_IDEAL_PROCESSOR == Param
                   || QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT == Param
                   || QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT == Param
                   || QUIC_PARAM_CONN_QUIC_VERSION == Param
                   || QUIC_PARAM_CONN_LOCAL_INTERFACE == Param
                   || QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME == Param))
           || (QUICER_PARAM_HANDLE_TYPE_GLOBAL == Type
               && (QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE == Param
                   || QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT == Param)))
    {
      if (BufferLength == sizeof(uint64_t))
        {
          res = SUCCESS(ETERM_UINT_64(*(uint64_t *)Buffer));
        }
      else if (BufferLength == sizeof(uint32_t))
        {
          res = SUCCESS(ETERM_INT(*(uint32_t *)Buffer));
        }
      else if (BufferLength == sizeof(uint16_t))
        {
          res = SUCCESS(ETERM_INT(*(uint16_t *)Buffer));
        }
    }
  else if ((QUICER_PARAM_HANDLE_TYPE_CONN == Type
            && (QUIC_PARAM_CONN_REMOTE_ADDRESS == Param
                || QUIC_PARAM_CONN_LOCAL_ADDRESS == Param))
           || (QUICER_PARAM_HANDLE_TYPE_LISTENER == Type
               && QUIC_PARAM_LISTENER_LOCAL_ADDRESS == Param))
    {
      res = SUCCESS(addr2eterm(env, (QUIC_ADDR *)Buffer));
    }
  else if (QUICER_PARAM_HANDLE_TYPE_CONN == Type
           && (QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION == Param
               || QUIC_PARAM_CONN_SHARE_UDP_BINDING == Param
               || QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED == Param
               || QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED == Param
               || QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID == Param))
    {
      res = SUCCESS(ETERM_BOOL(*(BOOLEAN *)Buffer));
    }
  else if ((QUIC_PARAM_LISTENER_CIBIR_ID == Param
            && QUICER_PARAM_HANDLE_TYPE_LISTENER == Type)
           || (QUIC_PARAM_TLS_NEGOTIATED_ALPN == Param
               && QUICER_PARAM_HANDLE_TYPE_TLS == Type)
           || (QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH == Param
               && QUICER_PARAM_HANDLE_TYPE_GLOBAL == Type)
           || (QUIC_PARAM_CONN_CLOSE_REASON_PHRASE == Param
               && QUICER_PARAM_HANDLE_TYPE_CONN == Type))
    {
      ERL_NIF_TERM ebin;
      if (QUIC_PARAM_CONN_CLOSE_REASON_PHRASE == Param && BufferLength > 1)
        {
          BufferLength -= 1; // remove \0
        }
      unsigned char *bin_data = enif_make_new_binary(env, BufferLength, &ebin);
      if (!bin_data)
        {
          res = ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
        }

      CxPlatCopyMemory(bin_data, Buffer, BufferLength);
      res = SUCCESS(ebin);
    }
  else if (QUIC_PARAM_LISTENER_STATS == Param
           && QUICER_PARAM_HANDLE_TYPE_LISTENER == Type)
    {
      QUIC_LISTENER_STATISTICS *stats = (QUIC_LISTENER_STATISTICS *)Buffer;
      res = SUCCESS(
          enif_make_list(env,
                         3,
                         PropTupleStrInt(total_accepted_connection,
                                         stats->TotalAcceptedConnections),
                         PropTupleStrInt(total_rejected_connection,
                                         stats->TotalRejectedConnections),
                         PropTupleStrInt(binding_recv_dropped_packets,
                                         stats->BindingRecvDroppedPackets)));
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
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (IS_SAME_TERM(ATOM_QUIC_GLOBAL, ctx))
    {
      pthread_mutex_lock(&MsQuicLock);
      // In a env that while there is no allocated NIF resources (reg, conf,
      // listener, conn, stream), VM may unload the module causes unloading DSO
      // in parallel.
      if (MsQuic)
        {
          res = get_global_opt(env, NULL, eopt);
        }
      pthread_mutex_unlock(&MsQuicLock);
    }
  else if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      if (ATOM_QUIC_PARAM_STREAM_ID == eopt
          && ((QuicerStreamCTX *)q_ctx)->StreamID != UNSET_STREAMID)
        {
          return SUCCESS(ETERM_UINT_64(((QuicerStreamCTX *)q_ctx)->StreamID));
        }
      if (!get_stream_handle(q_ctx))
        {
          goto Exit;
        }
      res = get_stream_opt(env, (QuicerStreamCTX *)q_ctx, eopt, elevel);
      put_stream_handle(q_ctx);
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      if (!get_conn_handle(q_ctx))
        {
          goto Exit;
        }
      res = get_connection_opt(env, (QuicerConnCTX *)q_ctx, eopt, elevel);
      put_conn_handle(q_ctx);
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      if (!get_listener_handle(q_ctx))
        {
          goto Exit;
        }
      res = get_listener_opt(env, (QuicerListenerCTX *)q_ctx, eopt, elevel);
      put_listener_handle(q_ctx);
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  return res;
Exit:
  return ERROR_TUPLE_2(ATOM_CLOSED);
}

ERL_NIF_TERM
get_level_param(ErlNifEnv *env,
                HQUIC Handle,
                HQUIC ConfigHandle,
                ERL_NIF_TERM eopt,
                ERL_NIF_TERM level)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  if (IS_SAME_TERM(ATOM_QUIC_CONFIGURATION, level))
    {
      res = get_config_opt(env, ConfigHandle, eopt);
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
                HQUIC ConfigHandle,
                ERL_NIF_TERM eopt,
                ERL_NIF_TERM eval,
                ERL_NIF_TERM level)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  if (IS_SAME_TERM(ATOM_QUIC_CONFIGURATION, level))
    {
      res = set_config_opt(env, ConfigHandle, eopt, eval);
    }
  if (IS_SAME_TERM(ATOM_QUIC_TLS, level))
    {
      res = set_tls_opt(env, Handle, eopt, eval);
    }

  return res;
}

ERL_NIF_TERM
setopt4(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM eopt = argv[1];
  ERL_NIF_TERM evalue = argv[2];
  ERL_NIF_TERM elevel = argv[3];

  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  void *q_ctx = NULL;

  if (!enif_is_atom(env, eopt))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (IS_SAME_TERM(ATOM_QUIC_GLOBAL, ctx))
    {
      res = set_global_opt(env, NULL, eopt, evalue);
    }
  else if (enif_get_resource(env, ctx, ctx_stream_t, &q_ctx))
    {
      if (!get_stream_handle(q_ctx))
        {
          goto Exit;
        }
      res = set_stream_opt(
          env, (QuicerStreamCTX *)q_ctx, eopt, evalue, elevel);
      put_stream_handle(q_ctx);
    }
  else if (enif_get_resource(env, ctx, ctx_connection_t, &q_ctx))
    {
      if (!get_conn_handle(q_ctx))
        {
          goto Exit;
        }
      res = set_connection_opt(
          env, (QuicerConnCTX *)q_ctx, eopt, evalue, elevel);
      put_conn_handle(q_ctx);
    }
  else if (enif_get_resource(env, ctx, ctx_listener_t, &q_ctx))
    {
      if (!get_listener_handle(q_ctx))
        {
          goto Exit;
        }
      res = set_listener_opt(
          env, (QuicerListenerCTX *)q_ctx, eopt, evalue, elevel);
      put_listener_handle(q_ctx);
    }
  else
    { //@todo support GLOBAL, REGISTRATION and CONFIGURATION
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  return res;
Exit:
  return ERROR_TUPLE_2(ATOM_CLOSED);
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
  if (get_uint64_from_map(
          env,
          *emap,
          ATOM_QUIC_SETTINGS_MtuDiscoverySearchCompleteTimeoutUs,
          &Settings->MtuDiscoverySearchCompleteTimeoutUs))
    {
      Settings->IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE;
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

  if (get_uint16_from_map(env,
                          *emap,
                          ATOM_QUIC_SETTINGS_PeerBidiStreamCount,
                          &Settings->PeerBidiStreamCount))
    {
      Settings->IsSet.PeerBidiStreamCount = TRUE;
    }

  return true;
}

bool
parse_listen_on(ErlNifEnv *env, ERL_NIF_TERM elisten_on, QUIC_ADDR *Address)
{
  char listen_on[INET6_ADDRSTRLEN + 6] = { 0 };
  int UdpPort = 0;

  ErlNifTermType type = enif_term_type(env, elisten_on);
  switch (type)
    {
    case ERL_NIF_TERM_TYPE_LIST:
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
      break;
    case ERL_NIF_TERM_TYPE_INTEGER:
      if (enif_get_int(env, elisten_on, &UdpPort) && UdpPort >= 0)
        {
          QuicAddrSetFamily(Address, QUIC_ADDRESS_FAMILY_UNSPEC);
          QuicAddrSetPort(Address, (uint16_t)UdpPort);
          return TRUE;
        }
      break;
    default:
      break;
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
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  uint64_t BuffUint64 = 0;
  uint16_t BuffUint16 = 0;

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = get_level_param(env,
                            s_ctx->Stream,
                            s_ctx->c_ctx->config_resource->Configuration,
                            optname,
                            elevel);
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_ID == optname)
    {
      Param = QUIC_PARAM_STREAM_ID;
      BufferLength = sizeof(uint64_t);
      Buffer = &BuffUint64;
    }
  else if (ATOM_QUIC_PARAM_STREAM_PRIORITY == optname)
    {
      Param = QUIC_PARAM_STREAM_PRIORITY;
      BufferLength = sizeof(uint16_t);
      Buffer = &BuffUint16;
    }
  else if (ATOM_QUIC_STREAM_OPTS_ACTIVE == optname)
    {
      switch (s_ctx->owner->active)
        {
        case ACCEPTOR_RECV_MODE_PASSIVE:
          res = SUCCESS(ATOM_FALSE);
          break;
        case ACCEPTOR_RECV_MODE_MULTI:
          res = SUCCESS(enif_make_int(env, s_ctx->owner->active_count));
          break;
        case ACCEPTOR_RECV_MODE_ONCE:
          res = SUCCESS(ATOM_ONCE);
          break;
        case ACCEPTOR_RECV_MODE_ACTIVE:
          res = SUCCESS(ATOM_TRUE);
          break;
        }
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH == optname)
    {
      Param = QUIC_PARAM_STREAM_0RTT_LENGTH;
      Buffer = &BuffUint64;
      BufferLength = sizeof(uint64_t);
    }
  else if (ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE == optname)
    {
      Param = QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE;
      Buffer = &BuffUint64;
      BufferLength = sizeof(uint64_t);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  status = MsQuic->GetParam(s_ctx->Stream, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_STREAM, Param, BufferLength, Buffer);
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
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  uint16_t BuffUint16 = 0;

  // Non Msquic Opts
  if (IS_SAME_TERM(optname, ATOM_QUIC_STREAM_OPTS_ACTIVE))
    {
      enif_mutex_lock(s_ctx->lock);

      if (ACCEPTOR_RECV_MODE_PASSIVE == s_ctx->owner->active
          && !IS_SAME_TERM(ATOM_FALSE, optval) && s_ctx->TotalBufferLength > 0)
        {
          // Trigger callback of event recv.
          if (s_ctx->is_recv_pending)
            {
              MsQuic->StreamReceiveComplete(s_ctx->Stream, 0);
            }
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
      res = set_level_param(env,
                            s_ctx->Stream,
                            s_ctx->c_ctx->config_resource->Configuration,
                            optname,
                            optval,
                            elevel);
      goto Exit;
    }

  else if (IS_SAME_TERM(ATOM_QUIC_PARAM_STREAM_ID, optname))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_0RTT_LENGTH == optname)
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE == optname)
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (ATOM_QUIC_PARAM_STREAM_PRIORITY == optname)
    {
      Param = QUIC_PARAM_STREAM_PRIORITY;
      Buffer = &BuffUint16;
      if (get_uint16(env, optval, Buffer))
        {
          BufferLength = sizeof(uint16_t);
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_PARAM_ERROR);
        }
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
  BOOLEAN vIsEnabled = FALSE;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  uint32_t Value = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      if (!c_ctx->config_resource)
        {
          goto Exit;
        }
      res = get_level_param(env,
                            c_ctx->Connection,
                            c_ctx->config_resource->Configuration,
                            optname,
                            elevel);
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
      Param = QUIC_PARAM_CONN_LOCAL_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_REMOTE_ADDRESS))
    {
      Param = QUIC_PARAM_CONN_REMOTE_ADDRESS;
      BufferLength = sizeof(QUIC_ADDR);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR))
    {
      Param = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
      BufferLength = sizeof(uint16_t);
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
      BufferLength = sizeof(BOOLEAN);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
      BufferLength = sizeof(uint16_t);
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT))
    {
      Param = QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
      BufferLength = sizeof(uint16_t);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS))
    {
      uint64_t ids[4] = { 0 };
      Param = QUIC_PARAM_CONN_MAX_STREAM_IDS;
      BufferLength = sizeof(ids);
      if (QUIC_FAILED((status = MsQuic->GetParam(
                           c_ctx->Connection, Param, &BufferLength, &ids))))
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }
      res = SUCCESS(enif_make_list(env,
                                   4,
                                   enif_make_uint64(env, ids[0]),
                                   enif_make_uint64(env, ids[1]),
                                   enif_make_uint64(env, ids[2]),
                                   enif_make_uint64(env, ids[3])));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE))
    {
      Param = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
      BufferLength = 512; // max
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME))
    {
      Param = QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
      Buffer = &Value;
      BufferLength = sizeof(Value);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;
      Buffer = &vIsEnabled;
      BufferLength = sizeof(BOOLEAN);
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
      Buffer = &vIsEnabled;
      BufferLength = sizeof(BOOLEAN);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION))
    {
      Param = QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION;
      BufferLength = sizeof(BOOLEAN);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_RESUMPTION_TICKET))
    {
      Param = QUIC_PARAM_CONN_RESUMPTION_TICKET;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID))
    {
      Param = QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
      Buffer = &vIsEnabled;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE))
    {
      Param = QUIC_PARAM_CONN_LOCAL_INTERFACE;
      BufferLength = sizeof(uint32_t);
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

  assert(Buffer);
  status = MsQuic->GetParam(c_ctx->Connection, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_CONN, Param, BufferLength, Buffer);
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
  uint32_t Value = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  QUIC_ADDR addr;
  uint8_t phrase[512] = { 0 };
  ErlNifBinary ticket;

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      if (!c_ctx->config_resource)
        {
          goto Exit;
        }
      res = set_level_param(env,
                            c_ctx->Connection,
                            c_ctx->config_resource->Configuration,
                            optname,
                            optval,
                            elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_QUIC_VERSION))
    {
      Param = QUIC_PARAM_CONN_QUIC_VERSION;
      // QUIC_CONNECTION.stats.QuicVersion
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_SUPPORTED);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_ADDRESS))
    {
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
      Param = QUIC_PARAM_CONN_REMOTE_ADDRESS;
      // @TODO fun name is missleading
      if (!parse_listen_on(env, optval, &addr))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
      BufferLength = sizeof(QUIC_ADDR);
      Buffer = &addr;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_IDEAL_PROCESSOR))
    {
      Param = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
      res = ERROR_TUPLE_2(ATOM_ERROR_NOT_SUPPORTED);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SETTINGS))
    {
      Param = QUIC_PARAM_CONN_SETTINGS;
      BufferLength = sizeof(QUIC_SETTINGS);
      Buffer = malloc(sizeof(QUIC_SETTINGS));
      isMalloc = TRUE;
      if (!create_settings(env, &optval, Buffer))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_SHARE_UDP_BINDING))
    {
      BOOLEAN value = TRUE;
      BufferLength = sizeof(BOOLEAN);
      if (IS_SAME_TERM(ATOM_FALSE, optval))
        {
          value = FALSE;
        }
      else if (IS_SAME_TERM(ATOM_TRUE, optval))
        {
          value = TRUE;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      if (QUIC_SUCCEEDED(status
                         = MsQuic->SetParam(c_ctx->Connection,
                                            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                                            sizeof(value),
                                            &value)))
        {
          res = ATOM_OK;
          goto Exit;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT))
    {
      uint32_t value = 0;
      if (!enif_get_uint(env, optval, &value))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
        }
      if (QUIC_SUCCEEDED(status = MsQuic->SetParam(
                             c_ctx->Connection,
                             QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT,
                             sizeof(uint32_t),
                             &value)))
        {
          res = ATOM_OK;
          goto Exit;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT))
    {
      uint32_t value = 0;
      if (!enif_get_uint(env, optval, &value))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
        }
      if (QUIC_SUCCEEDED(status = MsQuic->SetParam(
                             c_ctx->Connection,
                             QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT,
                             sizeof(uint32_t),
                             &value)))
        {
          res = ATOM_OK;
          goto Exit;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_MAX_STREAM_IDS))
    {
      Param = QUIC_PARAM_CONN_MAX_STREAM_IDS;
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_CLOSE_REASON_PHRASE))
    {
      Param = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
      BufferLength = sizeof(phrase);
      Buffer = &phrase;
      if (!enif_get_string(env, optval, Buffer, BufferLength, ERL_NIF_LATIN1))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME))
    {
      Param = QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME;
      if (!enif_get_uint(env, optval, &Value))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
        }
      Buffer = &Value;
      BufferLength = sizeof(Value);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED;

      if (IS_SAME_TERM(ATOM_TRUE, optval))
        {
          Value = TRUE;
        }
      else if (IS_SAME_TERM(ATOM_FALSE, optval))
        {
          Value = FALSE;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &Value;
      BufferLength = sizeof(uint8_t);
    }
  else if (IS_SAME_TERM(optname,
                        ATOM_QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED))
    {
      Param = QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED;
      if (IS_SAME_TERM(ATOM_TRUE, optval))
        {
          Value = TRUE;
        }
      else if (IS_SAME_TERM(ATOM_FALSE, optval))
        {
          Value = FALSE;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &Value;
      BufferLength = sizeof(uint8_t);
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
      if (!enif_inspect_binary(env, optval, &ticket)
          || ticket.size > UINT32_MAX)
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = ticket.data;
      BufferLength = ticket.size;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID))
    {
      Param = QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID;
      if (IS_SAME_TERM(ATOM_TRUE, optval))
        {
          Value = TRUE;
        }
      else if (IS_SAME_TERM(ATOM_FALSE, optval))
        {
          Value = FALSE;
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &Value;
      BufferLength = sizeof(uint8_t);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONN_LOCAL_INTERFACE))
    {
      Param = QUIC_PARAM_CONN_LOCAL_INTERFACE;
      if (!enif_get_uint(env, optval, &Value))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
        }
      Buffer = &Value;
      BufferLength = sizeof(Value);
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
  if (isMalloc && Buffer)
    {
      CXPLAT_FREE(Buffer, QUICER_OPT_BUFF);
    }
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
  bool isMalloc = FALSE;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  QUIC_ADDR q_addr = { 0 };
  QUIC_LISTENER_STATISTICS stats = { 65535, 65535, 65535 };
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  if (!l_ctx)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (l_ctx->is_closed)
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  enif_keep_resource(l_ctx);

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = get_level_param(env,
                            l_ctx->Listener,
                            l_ctx->config_resource->Configuration,
                            optname,
                            elevel);
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_LOCAL_ADDRESS))
    {

      Param = QUIC_PARAM_LISTENER_LOCAL_ADDRESS;
      Buffer = &q_addr;
      BufferLength = sizeof(q_addr);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_STATS))
    {
      Param = QUIC_PARAM_LISTENER_STATS;
      Buffer = &stats;
      BufferLength = sizeof(stats);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_CIBIR_ID))
    {
      Param = QUIC_PARAM_LISTENER_CIBIR_ID;
      // Not Supported in MsQUIC
      res = ERROR_TUPLE_2(ATOM_STATUS(QUIC_STATUS_NOT_SUPPORTED));
      goto Exit;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  if (!Buffer && !isMalloc)
    { // when Buffer is not initialized.
      Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUICER_OPT_BUFF);
      if (!Buffer)
        {
          goto Exit;
        }
      isMalloc = TRUE;
    }

  assert(!isMalloc);
  status = MsQuic->GetParam(l_ctx->Listener, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_LISTENER, Param, BufferLength, Buffer);
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
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  ErlNifBinary bin;
  if (!l_ctx)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(l_ctx->lock);

  if (l_ctx->is_closed)
    {
      res = ERROR_TUPLE_2(ATOM_CLOSED);
      goto Exit;
    }

  if (!IS_SAME_TERM(ATOM_FALSE, elevel))
    {
      res = set_level_param(env,
                            l_ctx->Listener,
                            l_ctx->config_resource->Configuration,
                            optname,
                            optval,
                            elevel);
      goto Exit;
    }
  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_LISTENER_CIBIR_ID))
    {
      Param = QUIC_PARAM_LISTENER_CIBIR_ID;
      if (!enif_inspect_binary(env, optval, &bin))
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      else
        {
          BufferLength = (uint32_t)bin.size;
          Buffer = (uint8_t *)bin.data;
        }
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
  enif_mutex_unlock(l_ctx->lock);
  return res;
}

static ERL_NIF_TERM
get_tls_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  uint8_t alpn[255] = { 0 };

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_HANDSHAKE_INFO))
    {
      QUIC_HANDSHAKE_INFO info = {};
      BufferLength = sizeof(QUIC_HANDSHAKE_INFO);
      ERL_NIF_TERM einfo;
      if (QUIC_SUCCEEDED(status
                         = MsQuic->GetParam(Handle,
                                            QUIC_PARAM_TLS_HANDSHAKE_INFO,
                                            &BufferLength,
                                            &info)))
        {
          assert(BufferLength == sizeof(QUIC_HANDSHAKE_INFO));
          ERL_NIF_TERM props_name[]
              = { ATOM_TLS_PROTOCOL_VERSION,  ATOM_CIPHER_ALGORITHM,
                  ATOM_CIPHER_STRENGTH,       ATOM_HASH_ALGORITHM,
                  ATOM_HASH_STRENGTH,         ATOM_KEY_EXCHANGE_ALGORITHM,
                  ATOM_KEY_EXCHANGE_STRENGTH, ATOM_CIPHER_SUITE };
          ERL_NIF_TERM props_value[]
              = { atom_proto_vsn(info.TlsProtocolVersion),
                  atom_cipher_algorithm(info.CipherAlgorithm),
                  enif_make_uint64(env, (uint64_t)info.CipherStrength),
                  atom_hash_algorithm(info.Hash),
                  enif_make_uint64(env, (uint64_t)info.HashStrength),
                  atom_key_exchange_algorithm(info.KeyExchangeAlgorithm),
                  enif_make_uint64(env, (uint64_t)info.KeyExchangeStrength),
                  atom_cipher_suite(info.CipherSuite) };
          if (enif_make_map_from_arrays(
                  env, props_name, props_value, 8, &einfo))
            {
              res = SUCCESS(einfo);
            }
          else
            {
              res = ERROR_TUPLE_2(ATOM_ERROR_INTERNAL_ERROR);
            }
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
        }
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_TLS_NEGOTIATED_ALPN))
    {
      Param = QUIC_PARAM_TLS_NEGOTIATED_ALPN;
      BufferLength = 255;
      Buffer = alpn;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Handle, Param, &BufferLength, Buffer);
  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_TLS, Param, BufferLength, Buffer);
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
            __unused_parm__ HQUIC Handle,
            __unused_parm__ ERL_NIF_TERM optname,
            __unused_parm__ ERL_NIF_TERM optval)
{
  // Currently no writable opts
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_SUPPORTED);
  return res;
}

static ERL_NIF_TERM
get_global_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  uint32_t percent = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  QUIC_SETTINGS Settings = { 0 };
  uint8_t githash[41] = { 0 }; // git hash 40 chars + \0

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT))
    {
      Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
      Buffer = &percent;
      BufferLength = sizeof(uint32_t);
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
      Param = QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
      Buffer = &percent;
      BufferLength = sizeof(uint32_t);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_PERF_COUNTERS))
    {
      uint64_t counters[QUIC_PERF_COUNTER_MAX] = { 0 };
      uint32_t Length = sizeof(counters);
      status = MsQuic->GetParam(
          NULL, QUIC_PARAM_GLOBAL_PERF_COUNTERS, &Length, &counters);
      if (QUIC_SUCCEEDED(status))
        {
          ERL_NIF_TERM eCounters[30] = {
            /* clang-format off */
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_CREATED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_APP_REJECT]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_ACTIVE]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_CONNECTED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_NO_ALPN]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_STRM_ACTIVE]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_PKTS_DROPPED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_RECV]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_SEND]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_RECV_BYTES]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_SEND_BYTES]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_RECV_EVENTS]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_UDP_SEND_CALLS]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_APP_SEND_BYTES]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_APP_RECV_BYTES]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_OPER_QUEUED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_CONN_OPER_COMPLETED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_WORK_OPER_QUEUED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_WORK_OPER_COMPLETED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_PATH_VALIDATED]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_PATH_FAILURE]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_SEND_STATELESS_RESET]),
            enif_make_uint64(env, counters[QUIC_PERF_COUNTER_SEND_STATELESS_RETRY])

            /* clang-format on */
          };
          res = SUCCESS(enif_make_list_from_array(env, eCounters, 30));
        }
      else
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
        }
      goto Exit;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SETTINGS))
    {
      Param = QUIC_PARAM_GLOBAL_SETTINGS;
      Buffer = &Settings;
      BufferLength = sizeof(QUIC_SETTINGS);
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH))
    {
      Param = QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH;
      BufferLength = sizeof(githash);
      Buffer = &githash;
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Handle, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_GLOBAL, Param, BufferLength, Buffer);
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
               HQUIC Handle,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM optval)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  uint32_t percent = 0;
  uint32_t lbmode = 0;
  QUIC_SETTINGS Settings = { 0 };
  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT))
    {
      Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
      BufferLength = sizeof(uint16_t);
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
      Param = QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE;
      // not sure if msquic checks it
      BufferLength = sizeof(lbmode);
      if (!enif_get_uint(env, optval, &lbmode)
          || lbmode >= QUIC_LOAD_BALANCING_COUNT)
        {
          res = ERROR_TUPLE_2(ATOM_BADARG);
          goto Exit;
        }
      Buffer = &lbmode;
    }
  else if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_GLOBAL_SETTINGS))
    {
      Param = QUIC_PARAM_GLOBAL_SETTINGS;
      if (!create_settings(env, &optval, &Settings))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
      BufferLength = sizeof(Settings);
      Buffer = &Settings;
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
  status = MsQuic->SetParam(Handle, Param, BufferLength, Buffer);

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
get_config_opt(ErlNifEnv *env, HQUIC Handle, ERL_NIF_TERM optname)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  QUIC_SETTINGS Settings = { 0 };
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS))
    {
      Param = QUIC_PARAM_CONFIGURATION_SETTINGS;
      Buffer = &Settings;
      BufferLength = sizeof(QUIC_SETTINGS);
    }
  else
    {
      res = ERROR_TUPLE_2(ATOM_PARAM_ERROR);
      goto Exit;
    }

  assert(Param);
  status = MsQuic->GetParam(Handle, Param, &BufferLength, Buffer);

  if (QUIC_SUCCEEDED(status))
    {
      res = encode_parm_to_eterm(
          env, QUICER_PARAM_HANDLE_TYPE_CONFIG, Param, BufferLength, Buffer);
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
               HQUIC Handle,
               ERL_NIF_TERM optname,
               ERL_NIF_TERM optval)
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  void *Buffer = NULL;
  uint32_t BufferLength = 0;
  uint32_t Param = 0;
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  QUIC_SETTINGS Settings = { 0 };

  if (IS_SAME_TERM(optname, ATOM_QUIC_PARAM_CONFIGURATION_SETTINGS))
    {
      Param = QUIC_PARAM_CONFIGURATION_SETTINGS;
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
  status = MsQuic->SetParam(Handle, Param, BufferLength, Buffer);

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

/*
** Fill str_buffer with string value of key in map.
** In case str_buffer is NULL, then new memory will be allocated,
** and caller should free it after use.
**
** Returns NULL on error.
*/
char *
str_from_map(ErlNifEnv *env,
             ERL_NIF_TERM key,
             const ERL_NIF_TERM *map,
             char *str_buffer,
             unsigned int max_len)
{
  unsigned int len = 0;
  ERL_NIF_TERM tmp_term;
  BOOLEAN is_alloc = str_buffer == NULL;

  if (!enif_get_map_value(env, *map, key, &tmp_term))
    {
      goto exit;
    }

  if (ERL_NIF_TERM_TYPE_LIST != enif_term_type(env, tmp_term))
    {
      goto exit;
    }

  if ((!str_buffer && !enif_get_list_length(env, tmp_term, &len))
      || len > max_len)
    {
      goto exit;
    }
  else
    {
      len = max_len;
    }

  if (is_alloc)
    {
      str_buffer = (char *)malloc(len + 1);
    }

  if (enif_get_string(env, tmp_term, str_buffer, len + 1, ERL_NIF_LATIN1))
    {
      return str_buffer;
    }
  else if (is_alloc)
    {
      free(str_buffer);
    }

exit:
  return NULL;
}

/*
 * parse optional quic_registration, and store it in r_ctx
 * return TRUE if quic_registration is present and valid or not present
 * */
BOOLEAN
parse_registration(ErlNifEnv *env,
                   ERL_NIF_TERM options,
                   QuicerRegistrationCTX **r_ctx)
{
  ERL_NIF_TERM tmp_term;
  assert(*r_ctx == NULL);
  if (enif_get_map_value(env, options, ATOM_QUIC_REGISTRATION, &tmp_term))
    {
      if (!enif_get_resource(env, tmp_term, ctx_reg_t, (void **)r_ctx))
        {
          return FALSE;
        }
    }

  return TRUE;
}
