#ifndef __QUICER_NIF_H_
#define __QUICER_NIF_H_
#include <stdbool.h>
#include <assert.h>

#include <erl_nif.h>
#include <msquic.h>
#include "quicer_eterms.h"

// Global registration
// @todo avoid use globals
extern HQUIC Registration;
extern const QUIC_API_TABLE* MsQuic;
extern const QUIC_REGISTRATION_CONFIG RegConfig;

// Externals from msquic obj.
extern void QuicPlatformSystemLoad(void);
extern void MsQuicLibraryLoad(void);

// Compiler attributes
#define __unused_parm__ __attribute__((unused))

#endif // __QUICER_NIF_H_
