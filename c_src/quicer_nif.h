#ifndef __QUICER_NIF_H_
#define __QUICER_NIF_H_
#include <assert.h>
#include <stdbool.h>

#include <erl_nif.h>
#include <msquic.h>

#include "quicer_config.h"
#include "quicer_connection.h"
#include "quicer_ctx.h"
#include "quicer_eterms.h"
#include "quicer_queue.h"
#include "quicer_stream.h"

#include <linux/limits.h>

// Global registration
// @todo avoid use globals
extern HQUIC Registration;
extern const QUIC_API_TABLE *MsQuic;
extern const QUIC_REGISTRATION_CONFIG RegConfig;
extern const QUIC_BUFFER Alpn;

// Context Types
extern ErlNifResourceType *ctx_listener_t;
extern ErlNifResourceType *ctx_connection_t;
extern ErlNifResourceType *ctx_stream_t;

// Externals from msquic obj.
extern void QuicPlatformSystemLoad(void);
extern void MsQuicLibraryLoad(void);

extern const uint64_t IdleTimeoutMs;

// Compiler attributes
#define __unused_parm__ __attribute__((unused))

#endif // __QUICER_NIF_H_
