#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE
#include "quicer_tp.h"
#include "assert.h"

extern uint64_t CxPlatTimeUs64(void);
// Compiler attributes
#define __unused_parm__ __attribute__((unused))

// Global pid for snabbkaffe collector
ErlNifPid GLOBAL_SNAB_KC_PID;

// help macro to copy atom to env for debug emulator assertions
#define ATOM_IN_ENV(X) enif_make_copy(env, ATOM_##X)

// This is a helper function to set the pid of the snabbkaffe collector
// because enif_whereis_pid in resource dtor violates beam lock orderings.
ERL_NIF_TERM
set_snab_kc_pid(ErlNifEnv *env,
                __unused_parm__ int argc,
                const ERL_NIF_TERM argv[])
{
  assert(argc == 1);
  if (!enif_get_local_pid(env, argv[0], &GLOBAL_SNAB_KC_PID))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }
  return ATOM_OK;
}

ERL_NIF_TERM
get_snab_kc_pid(ErlNifEnv *env,
                __unused_parm__ int argc,
                __unused_parm__ const ERL_NIF_TERM argv[])
{
  assert(argc == 0);
  return enif_make_pid(env, &GLOBAL_SNAB_KC_PID);
}

void
tp_snk(ErlNifEnv *env,
       const char *ctx,
       const char *fun,
       const char *tag,
       uint64_t rid,
       uint64_t mark)
{
  ErlNifPid *pid = &GLOBAL_SNAB_KC_PID;

  env = enif_alloc_env();

  ERL_NIF_TERM snk_event;
  ERL_NIF_TERM snk_event_key_array[7]
      = { ATOM_IN_ENV(SNK_KIND),    ATOM_IN_ENV(CONTEXT),
          ATOM_IN_ENV(FUNCTION),    ATOM_IN_ENV(TAG),
          ATOM_IN_ENV(RESOURCE_ID), ATOM_IN_ENV(MARK),
          ATOM_IN_ENV(SNK_META) };

  ERL_NIF_TERM snk_evt_meta;
  ERL_NIF_TERM snk_evt_meta_key_array[1] = { ATOM_IN_ENV(TIME) };
  ERL_NIF_TERM snk_evt_meta_val_array[1]
      = { enif_make_uint64(env, CxPlatTimeUs64()) };

  // shall never fail
  enif_make_map_from_arrays(
      env, snk_evt_meta_key_array, snk_evt_meta_val_array, 1, &snk_evt_meta);

  ERL_NIF_TERM snk_event_val_array[7] = {
    ATOM_IN_ENV(DEBUG),                         // snk_kind
    enif_make_string(env, ctx, ERL_NIF_LATIN1), // context
    enif_make_string(env, fun, ERL_NIF_LATIN1), // fun
    enif_make_string(env, tag, ERL_NIF_LATIN1), // tag
    enif_make_uint64(env, rid),                 // rid
    enif_make_uint64(env, mark),                // mark
    snk_evt_meta                                // snk_meta
  };

  enif_make_map_from_arrays(
      env, snk_event_key_array, snk_event_val_array, 7, &snk_event);

  ERL_NIF_TERM report
      = enif_make_tuple2(env,
                         ATOM_IN_ENV(GEN_CAST),
                         enif_make_tuple2(env, ATOM_IN_ENV(TRACE), snk_event));
  enif_send(NULL, pid, env, report);
  enif_free_env(env);
}
