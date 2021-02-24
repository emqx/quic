#include "quicer_nif.h"

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM loadinfo)
{
  int ret_val = 0;
  return ret_val;
}

static int on_upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
  return 0;
}

static void on_unload(ErlNifEnv* env, void* priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{

};

ERL_NIF_INIT(quicer_nif, nif_funcs, &on_load, NULL, &on_upgrade, &on_unload);
