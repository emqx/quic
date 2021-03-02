#ifndef __QUICER_LISTENER_H_
#define __QUICER_LISTENER_H_

#include "quicer_nif.h"
//#include "quicer_config.h"

QUIC_STATUS ServerListenerCallback(HQUIC Listener, void *Context,
                                   QUIC_LISTENER_EVENT *Event);

ERL_NIF_TERM listen2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM close_listener1(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]);

#endif // __QUICER_LISTENER_H_
