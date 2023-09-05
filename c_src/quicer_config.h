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
#include <openssl/x509.h>

#ifdef DEBUG
#define dbg(fmt, ...)                                                         \
  do                                                                          \
    {                                                                         \
      if (DEBUG)                                                              \
        fprintf(stderr,                                                       \
                "%s:%d:%s(): " fmt "\r\n",                                    \
                __FILE__,                                                     \
                __LINE__,                                                     \
                __func__,                                                     \
                __VA_ARGS__);                                                 \
    }                                                                         \
  while (0)

#define dbg1(fmt)                                                             \
  do                                                                          \
    {                                                                         \
      if (DEBUG)                                                              \
        fprintf(                                                              \
            stderr, "%s:%d:%s(): " fmt "\r\n", __FILE__, __LINE__, __func__); \
    }                                                                         \
  while (0)

#endif

typedef enum QUICER_PARAM_HANDLE_TYPE
{
  QUICER_PARAM_HANDLE_TYPE_REG,
  QUICER_PARAM_HANDLE_TYPE_CONFIG,
  QUICER_PARAM_HANDLE_TYPE_LISTENER,
  QUICER_PARAM_HANDLE_TYPE_CONN,
  QUICER_PARAM_HANDLE_TYPE_STREAM,
  QUICER_PARAM_HANDLE_TYPE_TLS,
  QUICER_PARAM_HANDLE_TYPE_GLOBAL
} QUICER_PARAM_HANDLE_TYPE;

BOOLEAN ReloadCertConfig(HQUIC Configuration, QUIC_CREDENTIAL_CONFIG *Config);
QUIC_STATUS UpdateCredConfig(ErlNifEnv *env,
                             QUIC_CREDENTIAL_CONFIG *config,
                             const ERL_NIF_TERM *option,
                             BOOLEAN is_server);

ERL_NIF_TERM ServerLoadConfiguration(ErlNifEnv *env,
                                     const ERL_NIF_TERM *option,
                                     HQUIC Registration,
                                     HQUIC *Configuration,
                                     QUIC_CREDENTIAL_CONFIG *Config);
ERL_NIF_TERM ClientLoadConfiguration(ErlNifEnv *env,
                                     const ERL_NIF_TERM *option,
                                     HQUIC *Configuration,
                                     bool HasCaCertFile);

bool load_alpn(ErlNifEnv *env,
               const ERL_NIF_TERM *option,
               unsigned *alpn_buffer_length,
               QUIC_BUFFER alpn_buffers[]);
bool load_verify(ErlNifEnv *env,
                 const ERL_NIF_TERM *option,
                 const bool default_verify);
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
char *str_from_map(ErlNifEnv *env,
                   ERL_NIF_TERM key,
                   const ERL_NIF_TERM *map,
                   char *string_buffer,
                   unsigned int max_len);

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
