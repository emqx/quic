#!/bin/sh

## Resolve QUICER_TLS_VER=auto to a concrete TLS backend.
##
## Prints 'sys' when the build host provides OpenSSL 3.0 or newer, and
## 'quictls' otherwise.
##
## Linking the system libcrypto ('sys') is preferred where it is possible:
## the resulting NIF picks up the distribution's libcrypto security updates
## without rebuilding quicer. msquic requires OpenSSL >= 3.0 for that and
## fails the configure step on older systems, so those fall back to the
## bundled quictls submodule.
##
## Probe the development package rather than the `openssl` CLI: msquic
## resolves the system libcrypto through CMake's FindOpenSSL, which reads the
## headers and libraries, and a host can carry an OpenSSL 3 CLI alongside
## 1.1.1 development files.

set -eu

if command -v pkg-config >/dev/null 2>&1; then
    if pkg-config --atleast-version=3.0 libcrypto 2>/dev/null; then
        echo 'sys'
        exit 0
    fi
    ## pkg-config knows libcrypto and it is too old: no need to probe further.
    if pkg-config --exists libcrypto 2>/dev/null; then
        echo 'quictls'
        exit 0
    fi
fi

## No pkg-config, or it does not know libcrypto. Fall back to the CLI, which
## is a weaker signal but better than assuming.
if command -v openssl >/dev/null 2>&1; then
    case "$(openssl version 2>/dev/null)" in
        'OpenSSL 3.'* | 'OpenSSL '[4-9]*)
            echo 'sys'
            exit 0
            ;;
    esac
fi

echo 'quictls'
