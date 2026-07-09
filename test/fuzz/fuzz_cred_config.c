/*--------------------------------------------------------------------
Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-------------------------------------------------------------------*/

/*
 * libFuzzer harness for quicer's option-map parsers.
 *
 * Covers BOTH sides of a QUIC deployment:
 *   - server credential config  : eoptions_to_cred_config()  (cert/key/verify)
 *   - client credential config  : parse_verify_options(is_server=FALSE) +
 *                                 parse_cacertfile_option()
 *   - ALPN negotiation list      : load_alpn() (used by client and server)
 *   - transport settings         : create_settings()
 *
 * These functions take attacker-influenced option maps (e.g. ALPN strings,
 * cert blobs, cacert paths). They run entirely on the BEAM scheduler thread in
 * production, so fuzzing them through the nif_shim (single threaded, no msquic
 * worker threads) is deterministic and reproducible -- which is exactly the
 * property that the end-to-end / multithreaded paths lack.
 */

#include <stdint.h>
#include <string.h>

#include "quicer_nif.h"
#include "quicer_tls.h"
#include "quicer_config.h"
#include "quicer_eterms.h"

#include "nif_shim.h"

#include "quic_platform.h"

// -------------------- tiny fuzzed-data consumer ---------------------------
typedef struct
{
  const uint8_t *p;
  size_t left;
} Consumer;

static uint8_t
take_u8(Consumer *c)
{
  if (c->left == 0)
    return 0;
  c->left--;
  return *c->p++;
}

static uint32_t
take_u32(Consumer *c)
{
  uint32_t v = 0;
  for (int i = 0; i < 4; i++)
    v = (v << 8) | take_u8(c);
  return v;
}

// Consume a length-prefixed byte slice (length capped to remaining + cap).
static size_t
take_slice(Consumer *c, const uint8_t **out, size_t cap)
{
  size_t n = take_u8(c);
  if (n > cap)
    n = cap;
  if (n > c->left)
    n = c->left;
  *out = c->p;
  c->p += n;
  c->left -= n;
  return n;
}

static ERL_NIF_TERM
take_string(Consumer *c, size_t cap)
{
  const uint8_t *d;
  size_t n = take_slice(c, &d, cap);
  return nifshim_string_n(d, n);
}

static int g_atoms_ready = 0;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  CxPlatSystemLoad();
  CxPlatInitialize();
  quicer_fuzz_init_atoms(nifshim_env());
  g_atoms_ready = 1;
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (!g_atoms_ready)
    {
      LLVMFuzzerInitialize(NULL, NULL);
    }
  nifshim_reset();

  Consumer cc = { .p = data, .left = size };
  ErlNifEnv *env = nifshim_env();
  (void)env;

  uint32_t flags = take_u32(&cc);
  ERL_NIF_TERM opts = nifshim_new_map();

  // --- certificate material -------------------------------------------------
  if (flags & 0x1)
    {
      opts = nifshim_map_put(opts, ATOM_CERTFILE, take_string(&cc, 255));
    }
  if (flags & 0x2)
    {
      opts = nifshim_map_put(opts, ATOM_KEYFILE, take_string(&cc, 255));
    }
  if (flags & 0x4)
    {
      const uint8_t *blob;
      size_t n = take_slice(&cc, &blob, 256);
      opts = nifshim_map_put(opts, ATOM_CERTKEYASN1, nifshim_binary(blob, n));
    }
  if (flags & 0x8)
    {
      opts = nifshim_map_put(opts, ATOM_PASSWORD, take_string(&cc, 64));
    }

  // --- verify / cacert ------------------------------------------------------
  if (flags & 0x10)
    {
      ERL_NIF_TERM v;
      switch (take_u8(&cc) & 0x3)
        {
        case 0:
          v = ATOM_VERIFY_PEER;
          break;
        case 1:
          v = ATOM_VERIFY_NONE;
          break;
        case 2:
          v = ATOM_TRUE;
          break;
        default:
          v = ATOM_FALSE;
          break;
        }
      opts = nifshim_map_put(opts, ATOM_VERIFY, v);
    }
  if (flags & 0x20)
    {
      opts = nifshim_map_put(opts, ATOM_CACERTFILE, take_string(&cc, 255));
    }
  if (flags & 0x40)
    {
      opts = nifshim_map_put(
          opts, ATOM_CUSTOM_VERIFY, (take_u8(&cc) & 1) ? ATOM_TRUE : ATOM_FALSE);
    }

  // --- ALPN list ------------------------------------------------------------
  if (flags & 0x80)
    {
      ERL_NIF_TERM list = nifshim_new_list();
      unsigned cnt = take_u8(&cc) & 0x7; // up to 7 protocols
      for (unsigned i = 0; i < cnt; i++)
        {
          list = nifshim_list_cons(take_string(&cc, 32), list);
        }
      opts = nifshim_map_put(opts, ATOM_ALPN, list);
    }

  // --- a few transport settings --------------------------------------------
  if (flags & 0x100)
    {
      opts = nifshim_map_put(
          opts, ATOM_QUIC_SETTINGS_IdleTimeoutMs, nifshim_uint(take_u32(&cc)));
    }
  if (flags & 0x200)
    {
      opts = nifshim_map_put(opts,
                             ATOM_QUIC_SETTINGS_MaxBytesPerKey,
                             nifshim_uint(take_u32(&cc)));
    }
  if (flags & 0x400)
    {
      opts = nifshim_map_put(opts,
                             ATOM_QUIC_SETTINGS_DatagramReceiveEnabled,
                             nifshim_uint(take_u8(&cc)));
    }

  // ---- server-side credential config ----
  {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    ERL_NIF_TERM r = eoptions_to_cred_config(env, opts, &CredConfig);
    if (IS_SAME_TERM(r, ATOM_OK))
      {
        free_certificate(&CredConfig);
      }
  }

  // ---- client-side verify + cacert ----
  {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    BOOLEAN is_verify = FALSE;
    parse_verify_options(env, opts, &CredConfig, FALSE /*client*/, &is_verify);
    char *cacert = NULL;
    if (parse_cacertfile_option(env, opts, &cacert) && cacert)
      {
        free(cacert);
      }
    free_certificate(&CredConfig);
  }

  // ---- ALPN ----
  {
    unsigned alpn_len = 0;
    QUIC_BUFFER *alpn = NULL;
    if (load_alpn(env, &opts, &alpn_len, &alpn))
      {
        free_alpn_buffers(alpn, alpn_len);
      }
  }

  // ---- transport settings ----
  {
    QUIC_SETTINGS Settings;
    memset(&Settings, 0, sizeof(Settings));
    create_settings(env, &opts, &Settings);
  }

  return 0;
}
