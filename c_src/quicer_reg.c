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

ERL_NIF_TERM
new_registration2(ErlNifEnv *env,
                  __unused_parm__ int argc,
                  const ERL_NIF_TERM argv[])
{
  QUIC_STATUS status = QUIC_STATUS_SUCCESS;
  ERL_NIF_TERM ename = argv[0];
  QUIC_REGISTRATION_CONFIG RegConfig
      = { NULL, QUIC_EXECUTION_PROFILE_LOW_LATENCY };

  TP_NIF_3(start, 0, status);
  if (argc == 2)
    {
      ERL_NIF_TERM eprofile = argv[1];
      if (IS_SAME_TERM(eprofile, ATOM_QUIC_EXECUTION_PROFILE_LOW_LATENCY))
        {
          RegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
        }
      else if (IS_SAME_TERM(eprofile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT))
        {
          RegConfig.ExecutionProfile
              = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
        }
      else if (IS_SAME_TERM(eprofile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER))
        {
          RegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
        }
      else if (IS_SAME_TERM(eprofile,
                            ATOM_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME))
        {
          RegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
        }
      else
        {
          return ERROR_TUPLE_2(ATOM_BADARG);
        }
    }

  QuicerRegistrationCTX *r_ctx = init_r_ctx();
  if (!r_ctx)
    {
      ERROR_TUPLE_2(ATOM_ERROR_NOT_ENOUGH_MEMORY);
    }
  // Open Registration
  if (QUIC_FAILED(
          status = MsQuic->RegistrationOpen(&RegConfig, &r_ctx->Registration)))
    {
      // unlikely
      TP_NIF_3(fail, 0, status);
      deinit_r_ctx(r_ctx);
      destroy_r_ctx(r_ctx);
      return ERROR_TUPLE_2(ATOM_STATUS(status));
    }
  TP_NIF_3(success, 0, status);
  return SUCCESS(enif_make_resource(env, r_ctx));
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
