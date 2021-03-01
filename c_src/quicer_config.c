#include "quicer_config.h"

const uint64_t IdleTimeoutMs = 5000;

bool
ReloadCertConfig(HQUIC Configuration)
{
  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  // @todo remove hardcoded keys
  const char *Cert = "/tmp/quicer/cert.pem";
  const char *KeyFile = "/tmp/quicer/key.pem";
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
  Config.CertFile.CertificateFile = (char *)Cert;
  Config.CertFile.PrivateKeyFile = (char *)KeyFile;
  Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  Config.CredConfig.CertificateFile = &Config.CertFile;
  QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
                      Configuration, &Config.CredConfig)))
    {
      printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
      return false;
    }
  return true;
}

// todo support per registration.
bool
ServerLoadConfiguration(HQUIC *Configuration)
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

  QUIC_CREDENTIAL_CONFIG_HELPER Config;
  memset(&Config, 0, sizeof(Config));
  Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

  const char *Cert = "/tmp/quicer/cert.pem";
  const char *KeyFile = "/tmp/quicer/key.pem";
  //
  // Loads the server's certificate from the file.
  //
  Config.CertFile.CertificateFile = (char *)Cert;
  Config.CertFile.PrivateKeyFile = (char *)KeyFile;
  Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  Config.CredConfig.CertificateFile = &Config.CertFile;

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
                      *Configuration, &Config.CredConfig)))
    {
      printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
      return false;
    }

  return true;
}
