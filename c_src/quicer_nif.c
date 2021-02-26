#include "quicer_nif.h"
#include <dlfcn.h>
#include <linux/limits.h>

/*
** atoms in use, initialized while load nif
*/
// quicer internal 'errors'
ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;
ERL_NIF_TERM ATOM_REG_FAILED;
ERL_NIF_TERM ATOM_OPEN_FAILED;

// Mirror 'errors' in msquic_linux.h
ERL_NIF_TERM ATOM_ERROR_NO_ERROR  ;
ERL_NIF_TERM ATOM_ERROR_CONTINUE  ;
ERL_NIF_TERM ATOM_ERROR_NOT_READY ;
ERL_NIF_TERM ATOM_ERROR_NOT_ENOUGH_MEMORY;
ERL_NIF_TERM ATOM_ERROR_INVALID_STATE    ;
ERL_NIF_TERM ATOM_ERROR_INVALID_PARAMETER;
ERL_NIF_TERM ATOM_ERROR_NOT_SUPPORTED    ;
ERL_NIF_TERM ATOM_ERROR_NOT_FOUND        ;
ERL_NIF_TERM ATOM_ERROR_BUFFER_OVERFLOW  ;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_REFUSED;
ERL_NIF_TERM ATOM_ERROR_OPERATION_ABORTED ;
ERL_NIF_TERM ATOM_ERROR_HANDSHAKE_FAILURE ;
ERL_NIF_TERM ATOM_ERROR_NETWORK_UNREACHABLE;
ERL_NIF_TERM ATOM_ERROR_CONNECTION_IDLE    ;
ERL_NIF_TERM ATOM_ERROR_INTERNAL_ERROR     ;
ERL_NIF_TERM ATOM_ERROR_PROTOCOL_ERROR     ;
ERL_NIF_TERM ATOM_ERROR_VER_NEG_ERROR      ;
ERL_NIF_TERM ATOM_ERROR_EPOLL_ERROR        ;
ERL_NIF_TERM ATOM_ERROR_DNS_RESOLUTION_ERROR;
ERL_NIF_TERM ATOM_ERROR_SOCKET_ERROR        ;
ERL_NIF_TERM ATOM_ERROR_SSL_ERROR           ;
ERL_NIF_TERM ATOM_ERROR_USER_CANCELED       ;
ERL_NIF_TERM ATOM_ERROR_ALPN_NEG_FAILURE    ;

// Mirror 'status' in msquic_linux.h

/*
**  Helper macros
*/
#define INIT_ATOMS                                              \
  ATOM(ATOM_OK, ok);                                            \
  ATOM(ATOM_ERROR, error);                                      \
  ATOM(ATOM_REG_FAILED, reg_failed);                            \
  ATOM(ATOM_OPEN_FAILED, open_failed);                          \
                                                                \
                                                                \
  ATOM(ATOM_ERROR_NO_ERROR, no_error);                          \
  ATOM(ATOM_ERROR_CONTINUE, contiune);                          \
  ATOM(ATOM_ERROR_NOT_READY, not_ready);                        \
  ATOM(ATOM_ERROR_NOT_ENOUGH_MEMORY, not_enough_mem);           \
  ATOM(ATOM_ERROR_INVALID_STATE, invalid_state);                \
  ATOM(ATOM_ERROR_INVALID_PARAMETER, invalid_parm);             \
  ATOM(ATOM_ERROR_NOT_SUPPORTED, not_supported);                \
  ATOM(ATOM_ERROR_NOT_FOUND, not_found);                        \
  ATOM(ATOM_ERROR_BUFFER_OVERFLOW, buffer_overflow);            \
  ATOM(ATOM_ERROR_CONNECTION_REFUSED, connection_refused);      \
  ATOM(ATOM_ERROR_OPERATION_ABORTED , operation_aborted);       \
  ATOM(ATOM_ERROR_HANDSHAKE_FAILURE, handshake_failure);        \
  ATOM(ATOM_ERROR_NETWORK_UNREACHABLE, network_unreachable);    \
  ATOM(ATOM_ERROR_CONNECTION_IDLE, connection_idle);            \
  ATOM(ATOM_ERROR_INTERNAL_ERROR, internal_error);              \
  ATOM(ATOM_ERROR_PROTOCOL_ERROR, protocol_error);              \
  ATOM(ATOM_ERROR_VER_NEG_ERROR, vsn_neg_error);                \
  ATOM(ATOM_ERROR_EPOLL_ERROR, epoll_error);                    \
  ATOM(ATOM_ERROR_DNS_RESOLUTION_ERROR, dns_resolution_error);  \
  ATOM(ATOM_ERROR_SOCKET_ERROR, socket_error);                  \
  ATOM(ATOM_ERROR_SSL_ERROR, ssl_error);                        \
  ATOM(ATOM_ERROR_USER_CANCELED, user_canceled);                \
  ATOM(ATOM_ERROR_ALPN_NEG_FAILURE, alpn_neg_failure);

HQUIC Registration;
const QUIC_API_TABLE* MsQuic;

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicer_nif", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM loadinfo)
{
  int ret_val = 0;

  // init atoms in use.
  #define ATOM(name, val) { name = enif_make_atom(env, #val);}
  INIT_ATOMS
  #undef ATOM

  return ret_val;
}

static int on_upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
  return 0;
}

static void on_unload(ErlNifEnv* env, void* priv_data)
{
}


static ERL_NIF_TERM openLib(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM lttngLib = argv[0];
  char lttngPath[PATH_MAX] = {0};

  // @todo external call for static link
  QuicPlatformSystemLoad();
  MsQuicLibraryLoad();
  if (enif_get_string(env, lttngLib, lttngPath, PATH_MAX, ERL_NIF_LATIN1))
  {
    // loading lttng lib is optional, ok to fail
    dlopen(lttngPath, RTLD_NOW | RTLD_GLOBAL);
  }

  //
  // Open a handle to the library and get the API function table.
  //
  if (QUIC_FAILED(status = MsQuicOpen(&MsQuic))) {
    return ERROR_TUPLE_3(ATOM_OPEN_FAILED, ETERM_INT(status));
  }
  return ATOM_OK;
}

static ERL_NIF_TERM registration(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
      return ERROR_TUPLE_3(ATOM_REG_FAILED, ETERM_INT(status));
    }
    return ATOM_OK;
}

static ErlNifFunc nif_funcs[] =
{
/* |  name  | arity| funptr | flags|
 *
*/
    {"open_lib", 1, openLib,  0},
    {"reg_open", 0, registration, 0}
};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
