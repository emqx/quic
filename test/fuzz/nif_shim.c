/*--------------------------------------------------------------------
Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-------------------------------------------------------------------*/

#include "nif_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Term arena. ERL_NIF_TERM == 0 is reserved as "no value".
 * Everything is single threaded; the harness is responsible for calling
 * nifshim_reset() between iterations.
 */

typedef enum
{
  T_FREE = 0,
  T_ATOM,
  T_INT,
  T_UINT,
  T_BINARY, // also used for Erlang "strings" (latin1 list of bytes)
  T_STRING,
  T_MAP,
  T_LIST_NIL,
  T_LIST_CELL,
} term_kind;

#define SHIM_MAX_TERMS 4096
#define SHIM_MAX_MAP_PAIRS 64
#define SHIM_MAX_ATOMS 1024

typedef struct
{
  term_kind kind;
  union
  {
    int64_t i;
    uint64_t u;
    struct
    {
      uint8_t *data;
      size_t size;
    } bin; // T_BINARY / T_STRING (NUL not stored for T_STRING bytes)
    struct
    {
      ERL_NIF_TERM keys[SHIM_MAX_MAP_PAIRS];
      ERL_NIF_TERM vals[SHIM_MAX_MAP_PAIRS];
      size_t n;
    } map;
    struct
    {
      ERL_NIF_TERM head;
      ERL_NIF_TERM tail;
    } cell;
    int atom_id;
  };
} shim_term;

static shim_term g_terms[SHIM_MAX_TERMS];
static size_t g_nterms = 1; // index 0 reserved

// Heap allocations made during an iteration, freed on reset.
static void *g_allocs[SHIM_MAX_TERMS];
static size_t g_nallocs = 0;

// Interned atom names (persist across resets so quicer's ATOM_* stay stable).
static char *g_atom_names[SHIM_MAX_ATOMS];
static int g_natoms = 0;

static ErlNifEnv *const g_env = (ErlNifEnv *)(void *)"quicer-fuzz-env";

static void *
shim_track(void *p)
{
  if (p && g_nallocs < SHIM_MAX_TERMS)
    {
      g_allocs[g_nallocs++] = p;
    }
  return p;
}

static ERL_NIF_TERM
shim_new(term_kind k)
{
  if (g_nterms >= SHIM_MAX_TERMS)
    {
      // Out of arena space: abort so libFuzzer can shrink the input.
      fprintf(stderr, "nifshim: term arena exhausted\n");
      abort();
    }
  ERL_NIF_TERM t = (ERL_NIF_TERM)g_nterms++;
  g_terms[t].kind = k;
  return t;
}

static shim_term *
shim_get(ERL_NIF_TERM t)
{
  if (t == 0 || t >= g_nterms)
    {
      return NULL;
    }
  return &g_terms[t];
}

void
nifshim_reset(void)
{
  for (size_t i = 0; i < g_nallocs; i++)
    {
      free(g_allocs[i]);
    }
  g_nallocs = 0;
  g_nterms = 1;
  // NOTE: interned atoms (g_atom_names / quicer ATOM_* term values) are kept.
  // To keep them valid we must keep their term slots stable, so atoms live in
  // a low, never-reset band. We re-create them lazily in nifshim_atom().
}

ErlNifEnv *
nifshim_env(void)
{
  return g_env;
}

// --------------------------------------------------------------------------
// Builders
// --------------------------------------------------------------------------

ERL_NIF_TERM
nifshim_atom(const char *name)
{
  for (int i = 0; i < g_natoms; i++)
    {
      if (strcmp(g_atom_names[i], name) == 0)
        {
          // Atom term value is encoded as a stable, high-band id so it never
          // collides with the resettable arena.
          return (ERL_NIF_TERM)(SHIM_MAX_TERMS + i);
        }
    }
  if (g_natoms >= SHIM_MAX_ATOMS)
    {
      fprintf(stderr, "nifshim: atom table exhausted\n");
      abort();
    }
  g_atom_names[g_natoms] = strdup(name);
  ERL_NIF_TERM t = (ERL_NIF_TERM)(SHIM_MAX_TERMS + g_natoms);
  g_natoms++;
  return t;
}

static int
shim_is_atom_term(ERL_NIF_TERM t, const char **name_out)
{
  if (t >= (ERL_NIF_TERM)SHIM_MAX_TERMS
      && t < (ERL_NIF_TERM)(SHIM_MAX_TERMS + g_natoms))
    {
      if (name_out)
        {
          *name_out = g_atom_names[t - SHIM_MAX_TERMS];
        }
      return 1;
    }
  return 0;
}

ERL_NIF_TERM
nifshim_int(int64_t v)
{
  ERL_NIF_TERM t = shim_new(T_INT);
  g_terms[t].i = v;
  return t;
}

ERL_NIF_TERM
nifshim_uint(uint64_t v)
{
  ERL_NIF_TERM t = shim_new(T_UINT);
  g_terms[t].u = v;
  return t;
}

ERL_NIF_TERM
nifshim_binary(const uint8_t *data, size_t size)
{
  ERL_NIF_TERM t = shim_new(T_BINARY);
  uint8_t *copy = (uint8_t *)shim_track(malloc(size ? size : 1));
  if (size)
    {
      memcpy(copy, data, size);
    }
  g_terms[t].bin.data = copy;
  g_terms[t].bin.size = size;
  return t;
}

ERL_NIF_TERM
nifshim_string_n(const uint8_t *data, size_t size)
{
  ERL_NIF_TERM t = shim_new(T_STRING);
  uint8_t *copy = (uint8_t *)shim_track(malloc(size + 1));
  if (size)
    {
      memcpy(copy, data, size);
    }
  copy[size] = '\0';
  g_terms[t].bin.data = copy;
  g_terms[t].bin.size = size;
  return t;
}

ERL_NIF_TERM
nifshim_string(const char *cstr)
{
  return nifshim_string_n((const uint8_t *)cstr, strlen(cstr));
}

ERL_NIF_TERM
nifshim_new_map(void)
{
  ERL_NIF_TERM t = shim_new(T_MAP);
  g_terms[t].map.n = 0;
  return t;
}

ERL_NIF_TERM
nifshim_map_put(ERL_NIF_TERM map, ERL_NIF_TERM key, ERL_NIF_TERM val)
{
  shim_term *m = shim_get(map);
  if (!m || m->kind != T_MAP || m->map.n >= SHIM_MAX_MAP_PAIRS)
    {
      return map;
    }
  // Replace if key already present (compare by term identity).
  for (size_t i = 0; i < m->map.n; i++)
    {
      if (m->map.keys[i] == key)
        {
          m->map.vals[i] = val;
          return map;
        }
    }
  m->map.keys[m->map.n] = key;
  m->map.vals[m->map.n] = val;
  m->map.n++;
  return map;
}

ERL_NIF_TERM
nifshim_new_list(void)
{
  return shim_new(T_LIST_NIL);
}

ERL_NIF_TERM
nifshim_list_cons(ERL_NIF_TERM head, ERL_NIF_TERM tail)
{
  ERL_NIF_TERM t = shim_new(T_LIST_CELL);
  g_terms[t].cell.head = head;
  g_terms[t].cell.tail = tail;
  return t;
}

// ==========================================================================
// erl_nif API implementations (the subset the parser paths actually use)
// ==========================================================================

ErlNifEnv *
enif_alloc_env(void)
{
  return g_env;
}

void
enif_free_env(ErlNifEnv *env)
{
  (void)env;
}

void
enif_clear_env(ErlNifEnv *env)
{
  (void)env;
}

int
enif_is_identical(ERL_NIF_TERM a, ERL_NIF_TERM b)
{
  return a == b;
}

ERL_NIF_TERM
enif_make_atom(ErlNifEnv *env, const char *name)
{
  (void)env;
  return nifshim_atom(name);
}

int
enif_is_atom(ErlNifEnv *env, ERL_NIF_TERM t)
{
  (void)env;
  return shim_is_atom_term(t, NULL);
}

int
enif_is_map(ErlNifEnv *env, ERL_NIF_TERM t)
{
  (void)env;
  shim_term *st = shim_get(t);
  return st && st->kind == T_MAP;
}

ErlNifTermType
enif_term_type(ErlNifEnv *env, ERL_NIF_TERM t)
{
  (void)env;
  shim_term *st = shim_get(t);
  if (shim_is_atom_term(t, NULL))
    {
      return ERL_NIF_TERM_TYPE_ATOM;
    }
  if (!st)
    {
      return ERL_NIF_TERM_TYPE_ATOM;
    }
  switch (st->kind)
    {
    case T_INT:
    case T_UINT:
      return ERL_NIF_TERM_TYPE_INTEGER;
    case T_BINARY:
      return ERL_NIF_TERM_TYPE_BITSTRING;
    case T_MAP:
      return ERL_NIF_TERM_TYPE_MAP;
    case T_STRING:    // Erlang strings ARE lists
    case T_LIST_NIL:
    case T_LIST_CELL:
      return ERL_NIF_TERM_TYPE_LIST;
    default:
      return ERL_NIF_TERM_TYPE_ATOM;
    }
}

int
enif_get_map_value(ErlNifEnv *env,
                   ERL_NIF_TERM map,
                   ERL_NIF_TERM key,
                   ERL_NIF_TERM *value)
{
  (void)env;
  shim_term *m = shim_get(map);
  if (!m || m->kind != T_MAP)
    {
      return 0;
    }
  for (size_t i = 0; i < m->map.n; i++)
    {
      if (m->map.keys[i] == key)
        {
          *value = m->map.vals[i];
          return 1;
        }
    }
  return 0;
}

int
enif_inspect_binary(ErlNifEnv *env, ERL_NIF_TERM term, ErlNifBinary *bin)
{
  (void)env;
  shim_term *st = shim_get(term);
  if (!st || st->kind != T_BINARY)
    {
      return 0;
    }
  memset(bin, 0, sizeof(*bin));
  bin->size = st->bin.size;
  bin->data = st->bin.data;
  return 1;
}

int
enif_inspect_iolist_as_binary(ErlNifEnv *env,
                              ERL_NIF_TERM term,
                              ErlNifBinary *bin)
{
  return enif_inspect_binary(env, term, bin);
}

int
enif_get_int(ErlNifEnv *env, ERL_NIF_TERM term, int *ip)
{
  (void)env;
  shim_term *st = shim_get(term);
  if (!st)
    {
      return 0;
    }
  if (st->kind == T_INT)
    {
      if (st->i < INT32_MIN || st->i > INT32_MAX)
        return 0;
      *ip = (int)st->i;
      return 1;
    }
  if (st->kind == T_UINT)
    {
      if (st->u > INT32_MAX)
        return 0;
      *ip = (int)st->u;
      return 1;
    }
  return 0;
}

int
enif_get_uint(ErlNifEnv *env, ERL_NIF_TERM term, unsigned int *ip)
{
  (void)env;
  shim_term *st = shim_get(term);
  if (!st)
    {
      return 0;
    }
  if (st->kind == T_UINT)
    {
      if (st->u > UINT32_MAX)
        return 0;
      *ip = (unsigned int)st->u;
      return 1;
    }
  if (st->kind == T_INT)
    {
      if (st->i < 0 || st->i > UINT32_MAX)
        return 0;
      *ip = (unsigned int)st->i;
      return 1;
    }
  return 0;
}

int
enif_get_uint64(ErlNifEnv *env, ERL_NIF_TERM term, ErlNifUInt64 *ip)
{
  (void)env;
  shim_term *st = shim_get(term);
  if (!st)
    {
      return 0;
    }
  if (st->kind == T_UINT)
    {
      *ip = st->u;
      return 1;
    }
  if (st->kind == T_INT && st->i >= 0)
    {
      *ip = (uint64_t)st->i;
      return 1;
    }
  return 0;
}

// Count for a list / string term.
static int
shim_list_length(ERL_NIF_TERM term, unsigned *len)
{
  shim_term *st = shim_get(term);
  if (!st)
    {
      return 0;
    }
  if (st->kind == T_STRING)
    {
      *len = (unsigned)st->bin.size;
      return 1;
    }
  unsigned n = 0;
  ERL_NIF_TERM cur = term;
  for (;;)
    {
      shim_term *c = shim_get(cur);
      if (!c)
        return 0;
      if (c->kind == T_LIST_NIL)
        break;
      if (c->kind != T_LIST_CELL)
        return 0;
      n++;
      cur = c->cell.tail;
      if (n > SHIM_MAX_TERMS)
        return 0; // cycle guard
    }
  *len = n;
  return 1;
}

int
enif_get_list_length(ErlNifEnv *env, ERL_NIF_TERM term, unsigned *len)
{
  (void)env;
  return shim_list_length(term, len);
}

#if defined(ERL_NIF_MINOR_VERSION) && ERL_NIF_MINOR_VERSION > 16
int
enif_get_string_length(ErlNifEnv *env,
                       ERL_NIF_TERM list,
                       unsigned *len,
                       ErlNifCharEncoding encoding)
{
  (void)env;
  (void)encoding;
  return shim_list_length(list, len);
}
#endif

int
enif_get_list_cell(ErlNifEnv *env,
                   ERL_NIF_TERM term,
                   ERL_NIF_TERM *head,
                   ERL_NIF_TERM *tail)
{
  (void)env;
  shim_term *st = shim_get(term);
  if (!st || st->kind != T_LIST_CELL)
    {
      return 0;
    }
  *head = st->cell.head;
  *tail = st->cell.tail;
  return 1;
}

int
enif_get_string(ErlNifEnv *env,
                ERL_NIF_TERM list,
                char *buf,
                unsigned size,
                ErlNifCharEncoding encoding)
{
  (void)env;
  (void)encoding;
  shim_term *st = shim_get(list);
  if (!st || st->kind != T_STRING || size == 0)
    {
      return 0;
    }
  size_t n = st->bin.size;
  if (n + 1 > size)
    {
      // truncated: erl_nif returns -size (negative). Match that contract.
      return -(int)size;
    }
  memcpy(buf, st->bin.data, n);
  buf[n] = '\0';
  return (int)(n + 1);
}

// ==========================================================================
// Stubs: referenced by the linked quicer objects but never reached by the
// parser fuzz targets. If a harness ever hits one, we abort loudly so the
// gap is obvious and can be implemented.
// ==========================================================================

#define SHIM_UNREACHABLE(name)                                                \
  do                                                                          \
    {                                                                         \
      fprintf(stderr, "nifshim: unimplemented %s reached\n", name);           \
      abort();                                                                \
    }                                                                         \
  while (0)

ERL_NIF_TERM
enif_make_badarg(ErlNifEnv *env)
{
  (void)env;
  return nifshim_atom("$badarg");
}

void *
enif_alloc_resource(ErlNifResourceType *type, size_t size)
{
  (void)type;
  return shim_track(calloc(1, size));
}

void
enif_release_resource(void *obj)
{
  (void)obj;
}

int
enif_get_resource(ErlNifEnv *env,
                  ERL_NIF_TERM term,
                  ErlNifResourceType *type,
                  void **objp)
{
  (void)env;
  (void)term;
  (void)type;
  (void)objp;
  return 0; // never a valid resource in the parser fuzzers
}

ERL_NIF_TERM
enif_make_copy(ErlNifEnv *dst, ERL_NIF_TERM src)
{
  (void)dst;
  return src;
}

// --- everything below is genuinely never called by the parser fuzzers -----
ErlNifMutex *
enif_mutex_create(char *name)
{
  (void)name;
  return (ErlNifMutex *)shim_track(calloc(1, 1));
}
void
enif_mutex_destroy(ErlNifMutex *mtx)
{
  (void)mtx;
}
void
enif_mutex_lock(ErlNifMutex *mtx)
{
  (void)mtx;
}
void
enif_mutex_unlock(ErlNifMutex *mtx)
{
  (void)mtx;
}

unsigned char *
enif_make_new_binary(ErlNifEnv *env, size_t size, ERL_NIF_TERM *t)
{
  (void)env;
  ERL_NIF_TERM term = shim_new(T_BINARY);
  uint8_t *p = (uint8_t *)shim_track(malloc(size ? size : 1));
  g_terms[term].bin.data = p;
  g_terms[term].bin.size = size;
  *t = term;
  return p;
}

int
enif_alloc_binary(size_t size, ErlNifBinary *bin)
{
  memset(bin, 0, sizeof(*bin));
  bin->data = (unsigned char *)shim_track(malloc(size ? size : 1));
  bin->size = size;
  return bin->data != NULL;
}

ERL_NIF_TERM
enif_make_binary(ErlNifEnv *env, ErlNifBinary *bin)
{
  (void)env;
  ERL_NIF_TERM term = shim_new(T_BINARY);
  g_terms[term].bin.data = bin->data;
  g_terms[term].bin.size = bin->size;
  return term;
}

ERL_NIF_TERM
enif_make_string(ErlNifEnv *env, const char *string, ErlNifCharEncoding enc)
{
  (void)env;
  (void)enc;
  return nifshim_string(string);
}

ERL_NIF_TERM
enif_make_int(ErlNifEnv *env, int v)
{
  (void)env;
  return nifshim_int(v);
}
// NOTE: erl_nif.h aliases enif_make_int64 -> enif_make_long and
// enif_make_uint64 -> enif_make_ulong on 64-bit, and defines the variadic
// enif_make_list()/enif_make_tupleN() as inline helpers. We therefore only
// define the underlying primitives here.
ERL_NIF_TERM
enif_make_long(ErlNifEnv *env, long v)
{
  (void)env;
  return nifshim_int((int64_t)v);
}
ERL_NIF_TERM
enif_make_uint(ErlNifEnv *env, unsigned v)
{
  (void)env;
  return nifshim_uint(v);
}
ERL_NIF_TERM
enif_make_ulong(ErlNifEnv *env, unsigned long v)
{
  (void)env;
  return nifshim_uint((uint64_t)v);
}
ERL_NIF_TERM
enif_make_list_cell(ErlNifEnv *env, ERL_NIF_TERM head, ERL_NIF_TERM tail)
{
  (void)env;
  return nifshim_list_cons(head, tail);
}
ERL_NIF_TERM
enif_make_tuple_from_array(ErlNifEnv *env,
                           const ERL_NIF_TERM arr[],
                           unsigned cnt)
{
  (void)env;
  (void)arr;
  (void)cnt;
  SHIM_UNREACHABLE("enif_make_tuple_from_array");
}

// Variadic API primitives. Unlike the enif_make_tupleN() helpers, these are
// real extern functions (their inline-vs-extern status varies across OTP
// versions, so the linked quicer objects may reference these symbols directly).
// The parser fuzz targets never build tuples/lists at runtime, so link-only
// abort() stubs are sufficient.
ERL_NIF_TERM
enif_make_tuple(ErlNifEnv *env, unsigned cnt, ...)
{
  (void)env;
  (void)cnt;
  SHIM_UNREACHABLE("enif_make_tuple");
}

ERL_NIF_TERM
enif_make_list(ErlNifEnv *env, unsigned cnt, ...)
{
  (void)env;
  if (cnt == 0)
    {
      return nifshim_new_list();
    }
  SHIM_UNREACHABLE("enif_make_list(cnt>0)");
}

ErlNifResourceType *
enif_open_resource_type_x(ErlNifEnv *env,
                          const char *name,
                          const ErlNifResourceTypeInit *init,
                          ErlNifResourceFlags flags,
                          ErlNifResourceFlags *tried)
{
  (void)env;
  (void)name;
  (void)init;
  (void)flags;
  (void)tried;
  return (ErlNifResourceType *)1;
}

ERL_NIF_TERM
enif_make_resource(ErlNifEnv *env, void *obj)
{
  (void)env;
  (void)obj;
  SHIM_UNREACHABLE("enif_make_resource");
}
ERL_NIF_TERM
enif_make_list_from_array(ErlNifEnv *e, const ERL_NIF_TERM arr[], unsigned cnt)
{
  (void)e;
  if (cnt == 0)
    {
      return nifshim_new_list();
    }
  (void)arr;
  SHIM_UNREACHABLE("enif_make_list_from_array(cnt>0)");
}
int
enif_make_map_from_arrays(ErlNifEnv *e,
                          ERL_NIF_TERM keys[],
                          ERL_NIF_TERM vals[],
                          size_t cnt,
                          ERL_NIF_TERM *map_out)
{
  (void)e;
  (void)keys;
  (void)vals;
  (void)cnt;
  (void)map_out;
  SHIM_UNREACHABLE("enif_make_map_from_arrays");
}
int
enif_get_local_pid(ErlNifEnv *e, ERL_NIF_TERM t, ErlNifPid *pid)
{
  (void)e;
  (void)t;
  (void)pid;
  return 0;
}
// enif_make_pid / enif_compare_pids are macros in erl_nif.h; enif_compare is
// the underlying primitive the latter expands to.
int
enif_compare(ERL_NIF_TERM a, ERL_NIF_TERM b)
{
  return a == b ? 0 : (a < b ? -1 : 1);
}
void
enif_set_pid_undefined(ErlNifPid *pid)
{
  (void)pid;
}
ErlNifPid *
enif_self(ErlNifEnv *e, ErlNifPid *pid)
{
  (void)e;
  return pid;
}
int
enif_send(ErlNifEnv *e, const ErlNifPid *to, ErlNifEnv *me, ERL_NIF_TERM msg)
{
  (void)e;
  (void)to;
  (void)me;
  (void)msg;
  return 0;
}
int
enif_monitor_process(ErlNifEnv *e,
                     void *obj,
                     const ErlNifPid *pid,
                     ErlNifMonitor *mon)
{
  (void)e;
  (void)obj;
  (void)pid;
  (void)mon;
  return 0;
}
int
enif_demonitor_process(ErlNifEnv *e, void *obj, const ErlNifMonitor *mon)
{
  (void)e;
  (void)obj;
  (void)mon;
  return 0;
}
int
enif_is_process_alive(ErlNifEnv *e, ErlNifPid *pid)
{
  (void)e;
  (void)pid;
  return 1;
}
int
enif_whereis_pid(ErlNifEnv *e, ERL_NIF_TERM name, ErlNifPid *pid)
{
  (void)e;
  (void)name;
  (void)pid;
  return 0;
}
int
enif_thread_type(void)
{
  return 0;
}
