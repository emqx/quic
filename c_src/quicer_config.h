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

#include "quicer_internal.h"
#include "quicer_nif.h"
#include <msquichelper.h>

BOOLEAN ReloadCertConfig(HQUIC Configuration, QUIC_CREDENTIAL_CONFIG *Config);
QUIC_STATUS UpdateCredConfig(ErlNifEnv *env,
                             QUIC_CREDENTIAL_CONFIG *config,
                             const ERL_NIF_TERM *option,
                             BOOLEAN is_server);
void DestroyCredConfig(QUIC_CREDENTIAL_CONFIG *);
ERL_NIF_TERM ServerLoadConfiguration(ErlNifEnv *env,
                                     const ERL_NIF_TERM *option,
                                     HQUIC *Configuration,
                                     QUIC_CREDENTIAL_CONFIG *Config);
ERL_NIF_TERM ClientLoadConfiguration(ErlNifEnv *env,
                                     const ERL_NIF_TERM *option,
                                     HQUIC *Configuration);

bool load_alpn(ErlNifEnv *env,
               const ERL_NIF_TERM *option,
               unsigned *alpn_buffer_length,
               QUIC_BUFFER alpn_buffers[]);
bool get_uint8_from_map(ErlNifEnv *env,
                        const ERL_NIF_TERM map,
                        ERL_NIF_TERM key,
                        uint8_t *value);
bool get_uint16_from_map(ErlNifEnv *env,
                         const ERL_NIF_TERM map,
                         ERL_NIF_TERM key,
                         uint16_t *value);
bool get_uint32_from_map(ErlNifEnv *env,
                         const ERL_NIF_TERM map,
                         ERL_NIF_TERM key,
                         uint32_t *value);
bool get_uint64_from_map(ErlNifEnv *env,
                         const ERL_NIF_TERM map,
                         ERL_NIF_TERM key,
                         uint64_t *value);
int get_str_from_map(ErlNifEnv *env,
                     ERL_NIF_TERM key,
                     const ERL_NIF_TERM *map,
                     char *buff,
                     unsigned max_len);

ERL_NIF_TERM getopt3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM setopt4(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

bool create_settings(ErlNifEnv *env,
                     const ERL_NIF_TERM *emap,
                     QUIC_SETTINGS *Settings);

bool
parse_listen_on(ErlNifEnv *env, ERL_NIF_TERM elisten_on, QUIC_ADDR *Address);

ERL_NIF_TERM set_connection_opt(ErlNifEnv *env,
                                QuicerConnCTX *c_ctx,
                                ERL_NIF_TERM optname,
                                ERL_NIF_TERM optval,
                                ERL_NIF_TERM elevel);

#endif // __QUICER_CONFIG_H_
