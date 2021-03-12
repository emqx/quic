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

const uint64_t IdleTimeoutMs = 5000;

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

  Config = (QUIC_CREDENTIAL_CONFIG_HELPER *)QUIC_ALLOC_NONPAGED(
      sizeof(QUIC_CREDENTIAL_CONFIG_HELPER), QUICER_CREDENTIAL_CONFIG_HELPER);

  memset(Config, 0, sizeof(QUIC_CREDENTIAL_CONFIG_HELPER));
  Config->CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  //
  // Loads the server's certificate from the file.
  //
  Config->CertFile.CertificateFile = cert_path;
  Config->CertFile.PrivateKeyFile = key_path;
  Config->CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  Config->CredConfig.CertificateFile = &Config->CertFile;
  return Config;
}

void
DestroyCredConfig(QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  // free((char *)Config->CertFile.CertificateFile);
  // free((char *)Config->CertFile.PrivateKeyFile);
  free(Config);
}

// @todo support per registration.
bool
ServerLoadConfiguration(HQUIC *Configuration,
                        QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  QUIC_SETTINGS Settings = { 0 };
  //
  // Configures the server's idle timeout.
  //
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;
  //
  // Configures the server's resumption level to allow for resumption and
  // 0-RTT.
  //
  Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
  Settings.IsSet.ServerResumptionLevel = TRUE;
  //
  // Configures the server's settings to allow for the peer to open a single
  // bidirectional stream. By default connections are not configured to allow
  // any streams from the peer.
  //
  Settings.PeerBidiStreamCount = 1;
  Settings.IsSet.PeerBidiStreamCount = TRUE;

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings),
                      NULL, Configuration)))
    {
      return false;
    }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      *Configuration, &Config->CredConfig)))
    {
      return false;
    }

  return true;
}

// @todo return status instead
bool
ClientLoadConfiguration(HQUIC *Configuration, bool Unsecure)
{
  QUIC_SETTINGS Settings = { 0 };
  //
  // Configures the client's idle timeout.
  //
  Settings.IdleTimeoutMs = IdleTimeoutMs;
  Settings.IsSet.IdleTimeoutMs = TRUE;

  // This is to enable the ability of server initialized stream
  Settings.IsSet.PeerUnidiStreamCount = TRUE;
  Settings.PeerUnidiStreamCount = 1;
  Settings.IsSet.PeerBidiStreamCount = TRUE;
  Settings.PeerBidiStreamCount = 1;
  //
  // Configures a default client configuration, optionally disabling
  // server certificate validation.
  //
  QUIC_CREDENTIAL_CONFIG CredConfig;
  memset(&CredConfig, 0, sizeof(CredConfig));
  CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
  CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
  if (Unsecure)
    {
      CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

  //
  // Allocate/initialize the configuration object, with the configured ALPN
  // and settings.
  //
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(
                      Registration, &Alpn, 1, &Settings, sizeof(Settings),
                      NULL, Configuration)))
    {
      return false;
    }

  //
  // Loads the TLS credential part of the configuration. This is required even
  // on client side, to indicate if a certificate is required or not.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(*Configuration,
                                                               &CredConfig)))
    {
      return false;
    }

  return true;
}

ERL_NIF_TERM
encode_parm_to_eterm(ErlNifEnv *env, QUIC_PARAM_LEVEL Level, uint32_t Param,
                     uint32_t BufferLength, void *Buffer)
{
  ERL_NIF_TERM res = ERROR_TUPLE_2(ATOM_ERROR_NOT_FOUND);
  if (QUIC_PARAM_CONN_STATISTICS == Param
      && QUIC_PARAM_LEVEL_CONNECTION == Level
      && sizeof(QUIC_STATISTICS) == BufferLength)
    {
      QUIC_STATISTICS *statics = (QUIC_STATISTICS *)Buffer;
      res = SUCCESS(enif_make_list(
          env, 20, PropTupleInt(Timing.Start, statics->Timing.Start),
          PropTupleInt(
              Timing.InitialFlightEnd,
              statics->Timing
                  .InitialFlightEnd), // Processed all peer's Initial packets
          PropTupleInt(
              Timing.HandshakeFlightEnd,
              statics->Timing.HandshakeFlightEnd), // Processed all peer's
                                                   // Handshake packets
          PropTupleInt(Send.PathMtu,
                       statics->Send.PathMtu), // Current path MTU.
          PropTupleInt(
              Send.TotalPackets,
              statics->Send
                  .TotalPackets), // QUIC packets, statics.Send.TotalPackets;
                                  // // QUIC packets), could be coalesced into
                                  // fewer UDP datagrams.
          PropTupleInt(Send.RetransmittablePackets,
                       statics->Send.RetransmittablePackets),
          PropTupleInt(Send.SuspectedLostPackets,
                       statics->Send.SuspectedLostPackets),
          PropTupleInt(
              Send.SpuriousLostPackets,
              statics->Send.SpuriousLostPackets), // Actual lost is
                                                  // (SuspectedLostPackets -
                                                  // SpuriousLostPackets)
          PropTupleInt(Send.TotalBytes,
                       statics->Send.TotalBytes), // Sum of UDP payloads
          PropTupleInt(
              Send.TotalStreamBytes,
              statics->Send.TotalStreamBytes), // Sum of stream payloads
          PropTupleInt(
              Send.CongestionCount,
              statics->Send.CongestionCount), // Number of congestion events
          PropTupleInt(
              Send.PersistentCongestionCount,
              statics->Send.PersistentCongestionCount), // Number of persistent
                                                        // congestion events
          PropTupleInt(
              Recv.TotalPackets,
              statics->Recv
                  .TotalPackets), // QUIC packets, statics->Recv.TotalPackets;
                                  // // QUIC packets), could be coalesced into
                                  // fewer UDP datagrams.
          PropTupleInt(
              Recv.ReorderedPackets,
              statics->Recv.ReorderedPackets), // Packets where packet number
                                               // is less than highest seen.
          PropTupleInt(
              Recv.DroppedPackets,
              statics->Recv.DroppedPackets), // Includes DuplicatePackets.
          PropTupleInt(Recv.DuplicatePackets, statics->Recv.DuplicatePackets),
          PropTupleInt(Recv.TotalBytes,
                       statics->Recv.TotalBytes), // Sum of UDP payloads
          PropTupleInt(
              Recv.TotalStreamBytes,
              statics->Recv.TotalStreamBytes), // Sum of stream payloads
          PropTupleInt(
              Recv.DecryptionFailures,
              statics->Recv
                  .DecryptionFailures), // Count of packet decryption failures.
          PropTupleInt(
              Recv.ValidAckFrames,
              statics->Recv.ValidAckFrames) // Count of receive ACK frames.
          ));
    }
  else if (QUIC_PARAM_STREAM_ID == Param && QUIC_PARAM_LEVEL_STREAM == Level)
    {
      res = SUCCESS(ETERM_UINT_64(*(uint64_t *)Buffer));
    }

  return res;
}

ERL_NIF_TERM
getopt3(ErlNifEnv *env, __unused_parm__ int argc,
        __unused_parm__ const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ctx = argv[0];
  ERL_NIF_TERM eopt = argv[1];
  ERL_NIF_TERM eisRaw = argv[2];

  HQUIC Handle = NULL;
  uint32_t Param = -1;
  QUIC_PARAM_LEVEL Level = -1;
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

  if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_QUIC_VERSION))
    {
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_QUIC_VERSION;
      // QUIC_CONNECTION.stats.QuicVersion
      BufferLength = sizeof(u_int32_t);
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_CONN_STATISTICS))
    {
      isLevelOK = Level == QUIC_PARAM_LEVEL_CONNECTION;
      Param = QUIC_PARAM_CONN_STATISTICS;
      BufferLength = sizeof(QUIC_STATISTICS);
    }
  else if (IS_SAME_TERM(eopt, ATOM_QUIC_PARAM_STREAM_ID))
    {
      isLevelOK = Level == QUIC_PARAM_LEVEL_STREAM;
      Param = QUIC_PARAM_STREAM_ID;
      BufferLength = sizeof(uint64_t);
      uint64_t stream_id = 0;
      Buffer = &stream_id;
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
  if (BufferLength == 0 || Param < 0 || Level < 0)
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
      Buffer = QUIC_ALLOC_NONPAGED(BufferLength, QUICER_OPT_BUFF);
      isMalloc = true;
    }

  QUIC_STATUS status
      = MsQuic->GetParam(Handle, Level, Param, &BufferLength, Buffer);

  if (!QUIC_SUCCEEDED(status))
    {
      enif_release_binary(&bin);
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
          free(Buffer);
        }
      return res;
    }
}
