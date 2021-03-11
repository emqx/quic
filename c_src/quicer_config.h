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

#ifndef __QUICER_CONFIG_H_
#define __QUICER_CONFIG_H_

#include "quicer_nif.h"

// @todo check if we can make use of it.
//#include <msquichelper.h>

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

ERL_NIF_TERM getopt2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif // __QUICER_CONFIG_H_
