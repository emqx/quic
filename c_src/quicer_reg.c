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
#include "quicer_reg.h"
#include "quicer_nif.h"

static BOOLEAN parse_reg_conf(ERL_NIF_TERM eprofile,
                              QUIC_REGISTRATION_CONFIG *RegConfig);

QuicerRegistrationCTX G_r_ctx = { .name = "global", .is_released = TRUE };
pthread_mutex_t GRegLock = PTHREAD_MUTEX_INITIALIZER;
extern pthread_mutex_t MsQuicLock;

/*
** Open global registration.
*/
ERL_NIF_TERM
registration(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM eprofile = ATOM_UNDEFINED;
  QUIC_REGISTRATION_CONFIG RegConfig
      = { "global", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
  QUIC_STATUS status;
  ERL_NIF_TERM res = ATOM_OK;

  if (!MsQuic)
    {
      return ERROR_TUPLE_2(ATOM_STATUS);
    }

  pthread_mutex_lock(&GRegLock);

  if (argc == 1)
    {
      eprofile = argv[0];
      if (!parse_reg_conf(eprofile, &RegConfig))
        {
          pthread_mutex_unlock(&GRegLock);
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  if (!get_reg_handle(&G_r_ctx))
    {
      // reg is closed
      CXPLAT_FRE_ASSERTMSG(G_r_ctx.ref_count == 0,
                           "G_r_ctx should have 0 user ");
      init_r_ctx(&G_r_ctx);
      QuicerRegistrationCTX *r_ctx = &G_r_ctx;
      if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig,
                                                        &r_ctx->Registration)))
        {
          res = ERROR_TUPLE_2(ATOM_STATUS(status));
          goto exit;
        }
      // Now it is safe for others to use
      CxPlatRefInitialize(&r_ctx->ref_count);
    }
  else
    {
      // already opened, deref now
      put_reg_handle(&G_r_ctx);
    }
  pthread_mutex_unlock(&GRegLock);
  return ATOM_OK;
exit:
  pthread_mutex_unlock(&GRegLock);
  return res;
}

/*
** For global registration only
*/
ERL_NIF_TERM
deregistration(ErlNifEnv *env,
               __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM res = ATOM_OK;
  pthread_mutex_lock(&MsQuicLock);
  if (!MsQuic)
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto exit;
    }

  CXPLAT_REF_COUNT expected = 1;
  if (!__atomic_compare_exchange_n(&G_r_ctx.ref_count,
                                   &expected,
                                   0,
                                   FALSE,
                                   __ATOMIC_SEQ_CST,
                                   __ATOMIC_SEQ_CST))
    {
      // @NOTE, if already closed, should return ATOM_OK
      if (expected != 0)
        {
          res = enif_make_int64(env, expected);
        }
    }
  else
    {
      HQUIC Registration = G_r_ctx.Registration;
      G_r_ctx.Registration = NULL;
      MsQuic->RegistrationClose(Registration);
      deinit_r_ctx(&G_r_ctx);
    }
exit:
  pthread_mutex_unlock(&MsQuicLock);
  return res;
}

ERL_NIF_TERM
new_registration2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  CXPLAT_FRE_ASSERT(argc >= 1);
  ERL_NIF_TERM ename = argv[0];
  ERL_NIF_TERM eprofile = argv[1];
  QUIC_REGISTRATION_CONFIG RegConfig
      = { NULL, QUIC_EXECUTION_PROFILE_LOW_LATENCY };

  QUIC_STATUS status;
  ERL_NIF_TERM res = ATOM_OK;

  if (!parse_reg_conf(eprofile, &RegConfig))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  QuicerRegistrationCTX *r_ctx = init_r_ctx(NULL);
  if (!r_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  if (argc == 2
      && (0 >= enif_get_string(
              env, ename, r_ctx->name, UINT8_MAX + 1, ERL_NIF_LATIN1)
          || strlen(r_ctx->name) == 0))
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto err_exit;
    }

  RegConfig.AppName = r_ctx->name;
  if (QUIC_FAILED(
          status = MsQuic->RegistrationOpen(&RegConfig, &r_ctx->Registration)))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
      goto err_exit;
    }
  return SUCCESS(enif_make_resource(env, r_ctx));

err_exit:
  put_reg_handle(r_ctx);
  return res;
}

ERL_NIF_TERM
shutdown_registration_x(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv)
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ErlNifUInt64 error_code = 0;
  BOOLEAN silent = FALSE;
  ERL_NIF_TERM ectx = argv[0];
  if (IS_SAME_TERM(ectx, ATOM_GLOBAL))
    {
      r_ctx = &G_r_ctx;
    }
  else if (!enif_get_resource(env, ectx, ctx_reg_t, (void **)&r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (argc == 3)
    {
      ERL_NIF_TERM esilent = argv[1];
      if (IS_SAME_TERM(ATOM_TRUE, esilent))
        {
          silent = TRUE;
        }
      else if (IS_SAME_TERM(ATOM_FALSE, esilent))
        {
          silent = FALSE;
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }

      if (!enif_get_uint64(env, argv[2], &error_code))
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  if (get_reg_handle(r_ctx))
    {
      // void return, trigger callback, no blocking
      MsQuic->RegistrationShutdown(r_ctx->Registration, silent, error_code);
      put_reg_handle(r_ctx);
    }
  else
    {
      return ATOM_STATUS;
    }
  return ATOM_OK;
}

ERL_NIF_TERM
close_registration(ErlNifEnv *env,
                   __unused_parm__ int argc,
                   const ERL_NIF_TERM argv[])
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ERL_NIF_TERM ectx = argv[0];
  ERL_NIF_TERM res = ATOM_OK;
  if (!enif_get_resource(env, ectx, ctx_reg_t, (void **)&r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  CXPLAT_REF_COUNT expected = 1;

  if (!__atomic_compare_exchange_n(&r_ctx->ref_count,
                                   &expected,
                                   0,
                                   FALSE,
                                   __ATOMIC_SEQ_CST,
                                   __ATOMIC_SEQ_CST))
    {
      // @NOTE, if already closed, should return default ATOM_OK
      if (expected != 0)
        {
          res = enif_make_int64(env, expected);
        }
    }
  else
    {
      HQUIC Registration = r_ctx->Registration;
      r_ctx->Registration = NULL;
      MsQuic->RegistrationClose(Registration);
      // @NOTE, we don't use put_reg_handle
      // because we are pretty sure that the ref_count is 0 now
      enif_release_resource(r_ctx);
    }
  return res;
}

ERL_NIF_TERM
get_registration_name1(ErlNifEnv *env,
                       __unused_parm__ int argc,
                       const ERL_NIF_TERM argv[])
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ERL_NIF_TERM ectx = argv[0];
  if (!enif_get_resource(env, ectx, ctx_reg_t, (void **)&r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(r_ctx->lock);
  ERL_NIF_TERM name = enif_make_string(env, r_ctx->name, ERL_NIF_LATIN1);
  enif_mutex_unlock(r_ctx->lock);
  return SUCCESS(name);
}

ERL_NIF_TERM
get_registration_refcnt(ErlNifEnv *env,
                        __unused_parm__ int argc,
                        const ERL_NIF_TERM *argv)
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ERL_NIF_TERM ectx = argv[0];
  CXPLAT_DBG_ASSERT(argc == 1);

  if (IS_SAME_TERM(ectx, ATOM_GLOBAL))
    {
      r_ctx = &G_r_ctx;
    }
  else if (!enif_get_resource(env, ectx, ctx_reg_t, (void **)&r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  if (!get_reg_handle(r_ctx))
    {
      return ERROR_TUPLE_2(ATOM_CLOSED);
    }
  CXPLAT_REF_COUNT cnt = r_ctx->ref_count;
  put_reg_handle(r_ctx);
  return enif_make_int64(env, cnt - 1);
}

BOOLEAN
parse_reg_conf(ERL_NIF_TERM eprofile, QUIC_REGISTRATION_CONFIG *RegConfig)
{
  if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
    }
  else if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_MAX_THROUGHPUT))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
    }
  else if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_SCAVENGER))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
    }
  else if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_REAL_TIME))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
    }
  else
    {
      return FALSE;
    }
  return TRUE;
}
