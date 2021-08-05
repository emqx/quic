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

#ifndef __QUICER_CONNECTION_H_
#define __QUICER_CONNECTION_H_
#include "quicer_internal.h"
#include "quicer_nif.h"
#include <msquichelper.h>

ERL_NIF_TERM
async_connect3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM
async_accept2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM
close_connection1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM sockname1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

QUIC_STATUS ServerConnectionCallback(HQUIC Connection,
                                     void *Context,
                                     QUIC_CONNECTION_EVENT *Event);

ERL_NIF_TERM addr2eterm(ErlNifEnv *env, QUIC_ADDR *addr);

ERL_NIF_TERM
get_conn_rid1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM
async_handshake_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

QUIC_STATUS continue_connection_handshake(QuicerConnCTX *c_ctx);

#endif // __QUICER_CONNECTION_H_
