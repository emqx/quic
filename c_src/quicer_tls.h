/*--------------------------------------------------------------------
Copyright (c) 2023-2024 EMQ Technologies Co., Ltd. All Rights Reserved.

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
#ifndef QUICER_TLS_H_
#define QUICER_TLS_H_
#include "msquic.h"
#include "quicer_nif.h"

BOOLEAN parse_cert_options(ErlNifEnv *env,
                           ERL_NIF_TERM options,
                           QUIC_CREDENTIAL_CONFIG *CredConfig);

BOOLEAN
parse_verify_options(ErlNifEnv *env,
                     ERL_NIF_TERM options,
                     QUIC_CREDENTIAL_CONFIG *CredConfig,
                     BOOLEAN is_server,
                     _Out_ BOOLEAN *is_verify);

BOOLEAN
parse_cacertfile_option(ErlNifEnv *env,
                        ERL_NIF_TERM options,
                        char **cacertfile);

BOOLEAN
build_trustedstore(const char *cacertfile, X509_STORE **trusted_store);

void free_certificate(QUIC_CREDENTIAL_CONFIG *cc);

void parse_sslkeylogfile_option(ErlNifEnv *env,
                                ERL_NIF_TERM options,
                                QuicerConnCTX *c_ctx);

ERL_NIF_TERM
eoptions_to_cred_config(ErlNifEnv *env,
                        ERL_NIF_TERM eoptions,
                        QUIC_CREDENTIAL_CONFIG *CredConfig,
                        X509_STORE **trusted_store);

void set_conn_sslkeylogfile(QuicerConnCTX *c_ctx, char *keylogfile);

ERL_NIF_TERM
complete_cert_validation(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM x509_ctx_to_cert_chain(ErlNifEnv *env, X509_STORE_CTX *ctx);
#endif // QUICER_TLS_H_
