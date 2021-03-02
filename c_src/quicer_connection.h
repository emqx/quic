#ifndef __QUICER_CONNECTION_H_
#define __QUICER_CONNECTION_H_
#include "quicer_nif.h"

ERL_NIF_TERM async_connect3(ErlNifEnv *env, int argc,
                            const ERL_NIF_TERM argv[]);
ERL_NIF_TERM async_accept2(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[]);
ERL_NIF_TERM close_connection1(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[]);

QUIC_STATUS ServerConnectionCallback(HQUIC Connection, void *Context,
                                     QUIC_CONNECTION_EVENT *Event);

#endif // __QUICER_CONNECTION_H_
