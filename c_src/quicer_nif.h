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

#ifndef __QUICER_NIF_H_
#define __QUICER_NIF_H_
#include "quicer_internal.h"
#include <assert.h>
#include <erl_nif.h>
#include <msquic.h>
#include <msquichelper.h>
#include <stdbool.h>

#include "quicer_config.h"
#include "quicer_connection.h"
#include "quicer_ctx.h"
#include "quicer_eterms.h"
#include "quicer_queue.h"
#include "quicer_stream.h"
#include "quicer_tp.h"

// @todo is 16 enough?
#define MAX_ALPN 16

// Global registration
// @todo avoid use globals
extern HQUIC Registration;
extern const QUIC_API_TABLE *MsQuic;
extern const QUIC_REGISTRATION_CONFIG RegConfig;

// Context Types
extern ErlNifResourceType *ctx_listener_t;
extern ErlNifResourceType *ctx_connection_t;
extern ErlNifResourceType *ctx_stream_t;

// Externals from msquic obj.
extern void CxPlatSystemLoad(void);
extern void MsQuicLibraryLoad(void);

ERL_NIF_TERM atom_status(ErlNifEnv *env, QUIC_STATUS status);

// Compiler attributes
#define __unused_parm__ __attribute__((unused))

#endif // __QUICER_NIF_H_
