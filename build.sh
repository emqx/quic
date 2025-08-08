#!/bin/bash

set -ueo pipefail

MSQUIC_VERSION="$1"
TARGET_SO='priv/libquicer_nif.so'
PKGNAME="$(./pkgname.sh)"

build() {
    # default: 4 concurrent jobs
    JOBS=4
    # if Ninja is installed, use it
    if command -v ninja; then
        GENERATOR=Ninja
        MakeCmd=ninja
    else
        GENERATOR="Unix Makefiles"
        MakeCmd=make
    fi
    if [ "$(uname -s)" = 'Darwin' ]; then
        JOBS="$(sysctl -n hw.ncpu)"
    else
        JOBS="$(nproc)"
    fi
    ./get-msquic.sh "$MSQUIC_VERSION"
    cmake -B c_build -G "${GENERATOR}"
    $MakeCmd -C c_build -j "$JOBS"

    ## Need lttng shared lib "libmsquic.lttng.so"
    [ "${QUIC_LOGGING_TYPE:-}" = "lttng" ]  \
        && $MakeCmd -C c_build install
    true
}

download() {
    TAG="$(git describe --tags | head -1)"
    URL="https://github.com/emqx/quic/releases/download/$TAG/$PKGNAME"
    mkdir -p _packages
    if [ ! -f "_packages/${PKGNAME}" ]; then
        if ! curl -f -L -o "_packages/${PKGNAME}" "${URL}"; then
            return 1
        fi
    fi

    if [ ! -f "_packages/${PKGNAME}.sha256" ]; then
        if ! curl -f -L -o "_packages/${PKGNAME}.sha256" "${URL}.sha256"; then
            return 1
        fi
    fi

    echo "$(cat "_packages/${PKGNAME}.sha256") _packages/${PKGNAME}" | sha256sum -c || return 1

    tar zxvf "_packages/${PKGNAME}" -C $(dirname "$TARGET_SO")

    erlc -I include -I priv src/quicer_nif.erl
    if erl -noshell -eval '[_|_]=quicer_nif:module_info(), halt(0).'; then
        res=0
    else
        # failed to load, build from source
        rm -f $TARGET_SO
        res=1
    fi
    rm -f quicer_nif.beam
    return $res
}

release() {
    local variant=${1:-""}
    if [ -z "$PKGNAME" ]; then
        echo "unable_to_resolve_release_package_name"
        exit 1
    fi
    mkdir -p _packages
    PKGNAME="$(basename $PKGNAME .gz)${variant}.gz"
    TARGET_PKG="_packages/${PKGNAME}"
    tar czvf "$TARGET_PKG" --dereference -C $(dirname "$TARGET_SO") \
        --exclude include --exclude share --exclude .gitignore \
        --exclude lib \
        .
    # use openssl but not sha256sum command because in some macos env it does not exist
    if command -v openssl; then
        openssl dgst -sha256 "${TARGET_PKG}" | cut -d ' ' -f 2  > "${TARGET_PKG}.sha256"
    else
        sha256sum "${TARGET_PKG}"  | cut -d ' ' -f 1 > "${TARGET_PKG}.sha256"
    fi
}

if [ "${BUILD_RELEASE:-}" = 1 ]; then
    build
    release
    ## build logging type variant
    QUIC_LOGGING_TYPE=stdout build
    release "logstdout"
else
    if [ "${QUICER_DOWNLOAD_FROM_RELEASE:-0}" = 1 ]; then
        if ! download; then
            echo "QUICER: Failed to download pre-built binary, building from source"
            build
        else
            echo "QUICER: NOTE! nif library is downloaded from prebuilt releases, not compiled from source!"
        fi
    else
        build
    fi
fi

