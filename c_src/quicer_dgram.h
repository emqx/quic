#ifndef __QUICER_DGRAM_H_
#define __QUICER_DGRAM_H_

#include "quicer_nif.h"

ERL_NIF_TERM send_dgram(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif // __QUICER_DGRAM_H_