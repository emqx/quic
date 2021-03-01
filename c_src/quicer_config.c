#include "quicer_config.h"

const uint64_t IdleTimeoutMs = 5000;

bool
ReloadCertConfig(HQUIC Configuration, QUIC_CREDENTIAL_CONFIG_HELPER *Config)
{
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config->CredConfig)))
    {
      printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
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

// todo support per registration.
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
      printf("ConfigurationOpen failed, 0x%x!\n", Status);
      return false;
    }

  //
  // Loads the TLS credential part of the configuration.
  //
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      *Configuration, &Config->CredConfig)))
    {
      printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
      return false;
    }

  return true;
}
