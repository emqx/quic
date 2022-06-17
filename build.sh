#!/bin/sh

set -ueo

MSQUIC_VERSION="$1"
TARGET_SO='priv/libquicer_nif.so'
PKGNAME="$(./pkgname.sh)"

build() {
    # default: 4 concurrent jobs
    JOBS=4
    if [ "$(uname -s)" = 'Darwin' ]; then
        JOBS="$(sysctl -n hw.ncpu)"
    else
        JOBS="$(nproc)"
    fi
    ./get-msquic.sh "$MSQUIC_VERSION"
    cmake -B c_build
    make -j "$JOBS" -C c_build
    ## MacOS
    if [ -f priv/libquicer_nif.dylib ]; then
        # TODO: why cp, but not mv ?
        cp priv/libquicer_nif.dylib "$TARGET_SO"
    fi
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

    gzip -c -d "_packages/${PKGNAME}" > "$TARGET_SO"
    erlc -I include src/quicer_nif.erl
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
    if [ -z "$PKGNAME" ]; then
        echo "unable_to_resolve_release_package_name"
        exit 1
    fi
    mkdir -p _packages
    TARGET_PKG="_packages/${PKGNAME}"
    gzip -c "$TARGET_SO" > "$TARGET_PKG"
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
