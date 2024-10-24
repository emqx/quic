#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER quicer_tp

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./quicer_tp.h"

#if !defined(_QUICER_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _QUICER_TP_H

#include "quicer_eterms.h"
#include <stdint.h>

#ifdef QUICER_USE_LTTNG
#include <lttng/tracepoint.h>

// clang-format off
TRACEPOINT_EVENT(
    quicer_tp,
    callback,
    TP_ARGS(
        const char *, fun,
        char *, tag,
        uint64_t, rid,
        int, mark),

    TP_FIELDS(
        ctf_string(fun, fun)
        ctf_integer_hex(int, rid, rid)
        ctf_string(tag, tag)
        ctf_integer(int, mark, mark)
    )
)

TRACEPOINT_EVENT(
    quicer_tp,
    nif,
    TP_ARGS(const char *, fun,
            char *, tag,
            uint64_t, rid,
            int, mark),
    TP_FIELDS(ctf_string(fun, fun)
              ctf_string(tag, tag)
              ctf_integer_hex(int, rid, rid)
              ctf_integer(int, mark, mark)
    )
)
// clang-format on

#define TP_NIF_3(TAG, RID, ARG)                                               \
  tracepoint(quicer_tp, nif, __func__, #TAG, (uint64_t)RID, ARG)
#define TP_CB_3(TAG, RID, ARG)                                                \
  tracepoint(quicer_tp, callback, __func__, #TAG, (uint64_t)RID, ARG)

/* END of ifdef QUICER_USE_LTTNG */

#elif defined(QUICER_USE_SNK)
extern ErlNifPid GLOBAL_SNAB_KC_PID;

#define TP_NIF_3(TAG, RID, ARG)                                               \
  tp_snk(env, "nif", __func__, #TAG, (uint64_t)RID, ARG)
#define TP_CB_3(TAG, RID, ARG)                                                \
  tp_snk(env, "callback", __func__, #TAG, (uint64_t)RID, ARG)

void tp_snk(ErlNifEnv *env,
            const char *ctx,
            const char *fun,
            const char *tag,
            uint64_t rid,
            uint64_t mark);

ERL_NIF_TERM
set_snab_kc_pid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM
get_snab_kc_pid(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
/* END of ifdef QUICER_USE_SNK */
#else /* NO TP is defined */

#define TP_NIF_3(Arg1, Arg2, Arg3)                                            \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#define TP_CB_3(Arg1, Arg2, Arg3)                                             \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)

#endif /* QUICER_USE_LTTNG */
#endif /* _QUICER_TP_H */

#ifdef QUICER_USE_LTTNG
#include <lttng/tracepoint-event.h>
#endif /* QUICER_USE_LTTNG */
