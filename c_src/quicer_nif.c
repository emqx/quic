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

#include "quicer_nif.h"
#include "quicer_listener.h"
#include <dlfcn.h>

/*
** atoms in use, initialized while load nif
*/
// quicer internal 'errors'
ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;
ERL_NIF_TERM ATOM_REG_FAILED;
ERL_NIF_TERM ATOM_OPEN_FAILED;
ERL_NIF_TERM ATOM_CTX_INIT_FAILED;
ERL_NIF_TERM ATOM_BAD_PID;
ERL_NIF_TERM ATOM_CONFIG_ERROR;
ERL_NIF_TERM ATOM_CERT_ERROR;
ERL_NIF_TERM ATOM_BAD_MON;
ERL_NIF_TERM ATOM_LISTENER_OPEN_ERROR;
ERL_NIF_TERM ATOM_LISTENER_START_ERROR;
ERL_NIF_TERM ATOM_BADARG;
ERL_NIF_TERM ATOM_CONN_OPEN_ERROR;
ERL_NIF_TERM ATOM_CONN_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_OPEN_ERROR;
ERL_NIF_TERM ATOM_STREAM_START_ERROR;
ERL_NIF_TERM ATOM_STREAM_SEND_ERROR;
ERL_NIF_TERM ATOM_SOCKNAME_ERROR;
ERL_NIF_TERM ATOM_OWNER_DEAD;

// Mirror 'errors' in msquic_linux.h
ERL_NIF_TERM ATOM_ERROR_NO_ERROR;
ERL_NIF_TERM ATOM_ERROR_CONTINUE;
ERL_NIF_TERM ATOM_ERROR_NOT_READY;
ERL_NIF_TERM ATOM_ERROR_NOT_ENOUGH_MEMORY;
ERL_NIF_TERM ATOM_ERROR_INVALID_STATE;
ERL_NIF_TERM ATOM_ERROR_INVALID_PARAMETER;
ERL_NIF_TERM ATOM_ERROR_NOT_SUPPORTED;
ERL_NIF_TERM ATOM_ERROR_NOT_FOUND;
ERL_NIF_TERM ATOM_ERROR_BUFFER_OVERFLOW;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_REFUSED;
ERL_NIF_TERM ATOM_ERROR_OPERATION_ABORTED;
ERL_NIF_TERM ATOM_ERROR_HANDSHAKE_FAILURE;
ERL_NIF_TERM ATOM_ERROR_NETWORK_UNREACHABLE;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_IDLE;
ERL_NIF_TERM ATOM_ERROR_INTERNAL_ERROR;
ERL_NIF_TERM ATOM_ERROR_PROTOCOL_ERROR;
ERL_NIF_TERM ATOM_ERROR_VER_NEG_ERROR;
ERL_NIF_TERM ATOM_ERROR_EPOLL_ERROR;
ERL_NIF_TERM ATOM_ERROR_DNS_RESOLUTION_ERROR;
ERL_NIF_TERM ATOM_ERROR_SOCKET_ERROR;
ERL_NIF_TERM ATOM_ERROR_SSL_ERROR;
ERL_NIF_TERM ATOM_ERROR_USER_CANCELED;
ERL_NIF_TERM ATOM_ERROR_ALPN_NEG_FAILURE;

// option keys
ERL_NIF_TERM ATOM_CERT;
ERL_NIF_TERM ATOM_KEY;

// Mirror 'status' in msquic_linux.h

/*
**  Helper macros
*/
#define INIT_ATOMS                                                            \
  ATOM(ATOM_OK, ok);                                                          \
  ATOM(ATOM_ERROR, error);                                                    \
  ATOM(ATOM_REG_FAILED, reg_failed);                                          \
  ATOM(ATOM_OPEN_FAILED, open_failed);                                        \
  ATOM(ATOM_CTX_INIT_FAILED, ctx_init_failed);                                \
  ATOM(ATOM_BAD_PID, bad_pid);                                                \
  ATOM(ATOM_CONFIG_ERROR, config_error);                                      \
  ATOM(ATOM_CERT_ERROR, cert_error);                                          \
  ATOM(ATOM_BAD_MON, bad_mon);                                                \
  ATOM(ATOM_LISTENER_OPEN_ERROR, listener_open_error);                        \
  ATOM(ATOM_LISTENER_START_ERROR, listener_start_error);                      \
  ATOM(ATOM_BADARG, badarg);                                                  \
  ATOM(ATOM_CONN_OPEN_ERROR, conn_open_error);                                \
  ATOM(ATOM_CONN_START_ERROR, conn_start_error);                              \
  ATOM(ATOM_STREAM_OPEN_ERROR, stm_open_error);                               \
  ATOM(ATOM_STREAM_START_ERROR, stm_start_error);                             \
  ATOM(ATOM_STREAM_SEND_ERROR, stm_send_error);                               \
  ATOM(ATOM_OWNER_DEAD, owner_dead);                                          \
                                                                              \
  ATOM(ATOM_ERROR_NO_ERROR, no_error);                                        \
  ATOM(ATOM_ERROR_CONTINUE, contiune);                                        \
  ATOM(ATOM_ERROR_NOT_READY, not_ready);                                      \
  ATOM(ATOM_ERROR_NOT_ENOUGH_MEMORY, not_enough_mem);                         \
  ATOM(ATOM_ERROR_INVALID_STATE, invalid_state);                              \
  ATOM(ATOM_ERROR_INVALID_PARAMETER, invalid_parm);                           \
  ATOM(ATOM_ERROR_NOT_SUPPORTED, not_supported);                              \
  ATOM(ATOM_ERROR_NOT_FOUND, not_found);                                      \
  ATOM(ATOM_ERROR_BUFFER_OVERFLOW, buffer_overflow);                          \
  ATOM(ATOM_ERROR_CONNECTION_REFUSED, connection_refused);                    \
  ATOM(ATOM_ERROR_OPERATION_ABORTED, operation_aborted);                      \
  ATOM(ATOM_ERROR_HANDSHAKE_FAILURE, handshake_failure);                      \
  ATOM(ATOM_ERROR_NETWORK_UNREACHABLE, network_unreachable);                  \
  ATOM(ATOM_ERROR_CONNECTION_IDLE, connection_idle);                          \
  ATOM(ATOM_ERROR_INTERNAL_ERROR, internal_error);                            \
  ATOM(ATOM_ERROR_PROTOCOL_ERROR, protocol_error);                            \
  ATOM(ATOM_ERROR_VER_NEG_ERROR, vsn_neg_error);                              \
  ATOM(ATOM_ERROR_EPOLL_ERROR, epoll_error);                                  \
  ATOM(ATOM_ERROR_DNS_RESOLUTION_ERROR, dns_resolution_error);                \
  ATOM(ATOM_ERROR_SOCKET_ERROR, socket_error);                                \
  ATOM(ATOM_ERROR_SSL_ERROR, ssl_error);                                      \
  ATOM(ATOM_ERROR_USER_CANCELED, user_canceled);                              \
  ATOM(ATOM_ERROR_ALPN_NEG_FAILURE, alpn_neg_failure);                        \
  ATOM(ATOM_CERT, cert);                                                      \
  ATOM(ATOM_KEY, key)

HQUIC Registration;
const QUIC_API_TABLE *MsQuic;

// @todo, these flags are not threads safe, wrap it in a context
BOOLEAN isRegistered = false;
BOOLEAN isLibOpened = false;

ErlNifResourceType *ctx_listener_t = NULL;
ErlNifResourceType *ctx_connection_t = NULL;
ErlNifResourceType *ctx_stream_t = NULL;

const QUIC_REGISTRATION_CONFIG RegConfig
    = { "quicer_nif", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t *)"sample" };

void
resource_listener_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                                __unused_parm__ void *obj,
                                __unused_parm__ ErlNifPid *pid,
                                __unused_parm__ ErlNifMonitor *mon)
{
  // todo
}

void
resource_conn_down_callback(__unused_parm__ ErlNifEnv *caller_env, void *obj,
                            __unused_parm__ ErlNifPid *pid,
                            __unused_parm__ ErlNifMonitor *mon)
{
  QuicerConnCTX *c_ctx = (QuicerConnCTX *)obj;
  assert(c_ctx->Connection != NULL);
  MsQuic->ConnectionShutdown(c_ctx->Connection,
                             //@todo, check rfc for the error code
                             QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                             ERROR_OPERATION_ABORTED);
}

void
resource_stream_down_callback(__unused_parm__ ErlNifEnv *caller_env,
                              __unused_parm__ void *obj,
                              __unused_parm__ ErlNifPid *pid,
                              __unused_parm__ ErlNifMonitor *mon)
{
  // @todo
}

static int
on_load(ErlNifEnv *env, __unused_parm__ void **priv_data,
        __unused_parm__ ERL_NIF_TERM loadinfo)
{
  int ret_val = 0;

// init atoms in use.
#define ATOM(name, val)                                                       \
  {                                                                           \
    (name) = enif_make_atom(env, #val);                                       \
  }
  INIT_ATOMS
#undef ATOM

  ErlNifResourceFlags flags
      = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

  ErlNifResourceTypeInit streamInit
      = { .dtor = NULL, .down = resource_stream_down_callback, .stop = NULL };
  ErlNifResourceTypeInit connInit
      = { .dtor = NULL, .down = resource_conn_down_callback, .stop = NULL };
  ErlNifResourceTypeInit listenerInit = {
    .dtor = NULL, .down = resource_listener_down_callback, .stop = NULL
  };
  ctx_listener_t = enif_open_resource_type_x(env, "listener_context_resource",
                                             &listenerInit, // init callbacks
                                             flags, NULL);
  ctx_connection_t
      = enif_open_resource_type_x(env, "connection_context_resource",
                                  &connInit, // init callbacks
                                  flags, NULL);
  ctx_stream_t = enif_open_resource_type_x(env, "stream_context_resource",
                                           &streamInit, // init callbacks
                                           flags, NULL);

  return ret_val;
}

static int
on_upgrade(__unused_parm__ ErlNifEnv *env, __unused_parm__ void **priv_data,
           __unused_parm__ void **old_priv_data,
           __unused_parm__ ERL_NIF_TERM load_info)
{
  return 0;
}

static void
on_unload(__unused_parm__ ErlNifEnv *env, __unused_parm__ void *priv_data)
{
}

static ERL_NIF_TERM
openLib(ErlNifEnv *env, __unused_parm__ int argc, const ERL_NIF_TERM argv[])
{
  assert(1 == argc);
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM lttngLib = argv[0];
  char lttngPath[PATH_MAX] = { 0 };

  // @todo external call for static link
  QuicPlatformSystemLoad();
  MsQuicLibraryLoad();
  if (enif_get_string(env, lttngLib, lttngPath, PATH_MAX, ERL_NIF_LATIN1))
    {
      // loading lttng lib is optional, ok to fail
      dlopen(lttngPath, (unsigned)RTLD_NOW | (unsigned)RTLD_GLOBAL);
    }

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(status = MsQuicOpen(&MsQuic)))
    {
      return ERROR_TUPLE_3(ATOM_OPEN_FAILED, ETERM_INT(status));
    }

  isLibOpened = true;
  return ATOM_OK;
}

static ERL_NIF_TERM
closeLib(__unused_parm__ ErlNifEnv *env, __unused_parm__ int argc,
         __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isLibOpened && MsQuic)
    {
      MsQuicClose(MsQuic);
      isLibOpened = false;
    }

  return ATOM_OK;
}

static ERL_NIF_TERM
registration(ErlNifEnv *env, __unused_parm__ int argc,
             __unused_parm__ const ERL_NIF_TERM argv[])
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  if (QUIC_FAILED(status
                  = MsQuic->RegistrationOpen(&RegConfig, &Registration)))
    {
      return ERROR_TUPLE_3(ATOM_REG_FAILED, ETERM_INT(status));
    }
  isRegistered = true;
  return ATOM_OK;
}

static ERL_NIF_TERM
deregistration(__unused_parm__ ErlNifEnv *env, __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  if (isRegistered && Registration)
    {
      MsQuic->RegistrationClose(Registration);
      isRegistered = false;
    }
  return ATOM_OK;
}

static ErlNifFunc nif_funcs[] = {
  /* |  name  | arity| funptr | flags|
   *
   */
  // clang-format off
  { "open_lib", 1, openLib, 0 },
  { "close_lib", 0, closeLib, 0 },
  { "reg_open", 0, registration, 0 },
  { "reg_close", 0, deregistration, 0 },
  { "listen", 2, listen2, 0},
  { "close_listener", 1, close_listener1, 0},
  { "async_connect", 3, async_connect3, 0},
  { "async_accept", 2, async_accept2, 0},
  { "close_connection", 1, close_connection1, 0},
  { "async_accept_stream", 2, async_accept_stream2, 0},
  { "start_stream", 2, async_start_stream2, 0},
  { "send", 2, send2, 0},
  { "close_stream", 1, close_stream1, 0},
  { "sockname", 1, sockname1, 0}
  // clang-format on
};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
