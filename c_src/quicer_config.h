#ifndef __QUICER_CONFIG_H_
#define __QUICER_CONFIG_H_

#include "quicer_nif.h"

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER
{
  QUIC_CREDENTIAL_CONFIG CredConfig;
  union
  {
    QUIC_CERTIFICATE_HASH CertHash;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    QUIC_CERTIFICATE_FILE CertFile;
  };
} QUIC_CREDENTIAL_CONFIG_HELPER;

bool ReloadCertConfig(HQUIC Configuration,
                      QUIC_CREDENTIAL_CONFIG_HELPER *Config);
QUIC_CREDENTIAL_CONFIG_HELPER *NewCredConfig(ErlNifEnv *env,
                                             const ERL_NIF_TERM *option);
void DestroyCredConfig(QUIC_CREDENTIAL_CONFIG_HELPER *);
bool ServerLoadConfiguration(HQUIC *Configuration,
                             QUIC_CREDENTIAL_CONFIG_HELPER *Config);
bool ClientLoadConfiguration(HQUIC *Configuration, bool Unsecure);

#endif // __QUICER_CONFIG_H_
