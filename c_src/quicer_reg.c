/*--------------------------------------------------------------------
Copyright (c) 2023 EMQ Technologies Co., Ltd. All Rights Reserved.

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

QuicerRegistrationCTX *G_r_ctx = NULL;
ErlNifMutex *GRegLock = NULL;

/*
** For global registration only
*/
ERL_NIF_TERM
registration(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM eprofile = ATOM_UNDEFINED;
  QUIC_REGISTRATION_CONFIG RegConfig
      = { "global", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
  QUIC_STATUS status;
  ERL_NIF_TERM res = ATOM_OK;

  if (!MsQuic || !GRegLock || G_r_ctx)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(GRegLock);
  if (argc == 1)
    {
      eprofile = argv[0];
      if (!parse_reg_conf(eprofile, &RegConfig))
        {
          enif_mutex_unlock(GRegLock);
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  QuicerRegistrationCTX *r_ctx = init_r_ctx();
  if (!r_ctx)
    {
      enif_mutex_unlock(GRegLock);
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  if (QUIC_FAILED(
          status = MsQuic->RegistrationOpen(&RegConfig, &r_ctx->Registration)))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
      goto exit;
    }

  G_r_ctx = r_ctx;
  enif_mutex_unlock(GRegLock);

  // nif owns the global registration
  // thus not return to the erlang side
  return ATOM_OK;

exit:
  destroy_r_ctx(r_ctx);
  enif_mutex_unlock(GRegLock);
  return res;
}

/*
** For global registration only
*/
ERL_NIF_TERM
deregistration(__unused_parm__ ErlNifEnv *env,
               __unused_parm__ int argc,
               __unused_parm__ const ERL_NIF_TERM argv[])
{
  int error_code = 0;
  if (!MsQuic || !GRegLock)
    {
      return ERROR_TUPLE_2(ATOM_BADARG);
    }

  enif_mutex_lock(GRegLock);
  if (G_r_ctx && !G_r_ctx->is_released)
    {
      MsQuic->RegistrationShutdown(G_r_ctx->Registration, FALSE, error_code);
      destroy_r_ctx(G_r_ctx);
      G_r_ctx = NULL;
    }
  enif_mutex_unlock(GRegLock);
  return ATOM_OK;
}

ERL_NIF_TERM
new_registration2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{

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

  QuicerRegistrationCTX *r_ctx = init_r_ctx();
  if (!r_ctx)
    {
      return ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }

  if (argc == 2
      && 0 >= enif_get_string(
             env, ename, r_ctx->name, UINT8_MAX + 1, ERL_NIF_LATIN1))
    {
      res = ERROR_TUPLE_2(ATOM_BADARG);
      goto exit;
    }

  RegConfig.AppName = r_ctx->name;
  if (QUIC_FAILED(
          status = MsQuic->RegistrationOpen(&RegConfig, &r_ctx->Registration)))
    {
      res = ERROR_TUPLE_2(ATOM_STATUS(status));
      goto exit;
    }

  return SUCCESS(enif_make_resource(env, r_ctx));

exit:
  destroy_r_ctx(r_ctx);
  return res;
}

ERL_NIF_TERM
shutdown_registration_x(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv)
{
  QuicerRegistrationCTX *r_ctx = NULL;
  ErlNifUInt64 error_code = 0;
  BOOLEAN silent = FALSE;
  ERL_NIF_TERM ectx = argv[0];
  if (!enif_get_resource(env, ectx, ctx_reg_t, (void **)&r_ctx))
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

  if (r_ctx->Registration && !r_ctx->is_released)
    {
      // void return, trigger callback, no blocking
      MsQuic->RegistrationShutdown(r_ctx->Registration, silent, error_code);
      destroy_r_ctx(r_ctx);
    }

  return ATOM_OK;
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

  return SUCCESS(enif_make_string(env, r_ctx->name, ERL_NIF_LATIN1));
}

BOOLEAN
parse_reg_conf(ERL_NIF_TERM eprofile, QUIC_REGISTRATION_CONFIG *RegConfig)
{
  if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
    }
  else if (IS_SAME_TERM(eprofile,
                        ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
    }
  else if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
    }
  else if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME))
    {
      RegConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
    }
  else
    {
      return FALSE;
    }
  return TRUE;
}
