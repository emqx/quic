#ifndef __QUICER_STREAM_H_
#define __QUICER_STREAM_H_

#include "quicer_config.h"
#include "quicer_nif.h"

QUIC_STATUS ServerStreamCallback(HQUIC Stream, void *Context,
                                 QUIC_STREAM_EVENT *Event);

ERL_NIF_TERM async_accept_stream2(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]);

ERL_NIF_TERM async_start_stream2(ErlNifEnv *env, int argc,
                                 const ERL_NIF_TERM argv[]);
ERL_NIF_TERM send2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM close_stream1(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[]);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
ClientStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
                         _Inout_ QUIC_STREAM_EVENT *Event);

#endif // __QUICER_STREAM_H_
