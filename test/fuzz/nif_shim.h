/*--------------------------------------------------------------------
Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-------------------------------------------------------------------*/

/*
 * Minimal, single-threaded erl_nif shim for libFuzzer harnesses.
 *
 * Rationale (see test/fuzz/FUZZING.md): quicer's NIF parsing functions take
 * `ErlNifEnv *` and `ERL_NIF_TERM` arguments and normally run inside the BEAM.
 * To fuzz them deterministically -- WITHOUT the BEAM scheduler/GC threads and
 * WITHOUT msquic worker threads interleaving -- we provide our own definitions
 * of the small subset of enif_* functions that the parsing paths use, backed
 * by a simple term arena. Every enif_* function the linked quicer objects
 * reference but the parsers never call at runtime is stubbed to abort().
 *
 * Terms (ERL_NIF_TERM is an integer in erl_nif.h) are indices into a global
 * arena that is reset between fuzzing iterations via nifshim_reset().
 */

#ifndef QUICER_FUZZ_NIF_SHIM_H
#define QUICER_FUZZ_NIF_SHIM_H

#include <erl_nif.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  // Reset the term arena. Call at the start of every fuzz iteration.
  void nifshim_reset(void);

  // The single env the harness threads through quicer's parser functions.
  ErlNifEnv *nifshim_env(void);

  // ---- Term builders used by the harness to construct fuzz inputs ----------
  ERL_NIF_TERM nifshim_atom(const char *name);
  ERL_NIF_TERM nifshim_int(int64_t v);
  ERL_NIF_TERM nifshim_uint(uint64_t v);
  ERL_NIF_TERM nifshim_binary(const uint8_t *data, size_t size);
  ERL_NIF_TERM nifshim_string(const char *cstr); // NUL-terminated latin1
  ERL_NIF_TERM nifshim_string_n(const uint8_t *data, size_t size);

  ERL_NIF_TERM nifshim_new_map(void);
  // returns a new map term with {key,val} added (immutable-ish copy semantics
  // are not needed: the harness just keeps the latest handle).
  ERL_NIF_TERM nifshim_map_put(ERL_NIF_TERM map,
                               ERL_NIF_TERM key,
                               ERL_NIF_TERM val);

  ERL_NIF_TERM nifshim_new_list(void); // empty list ([])
  ERL_NIF_TERM nifshim_list_cons(ERL_NIF_TERM head, ERL_NIF_TERM tail);

  // Intern quicer's atom table (ATOM_TRUE, ATOM_CERTFILE, ...). Defined in
  // c_src/quicer_nif.c behind -DQUICER_FUZZ.
  void quicer_fuzz_init_atoms(ErlNifEnv *env);

#ifdef __cplusplus
}
#endif

#endif // QUICER_FUZZ_NIF_SHIM_H
