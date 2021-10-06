#!/bin/bash

set -euo pipefail

VERSION="$1"

if [ ! -d msquic ]; then
    git clone https://github.com/microsoft/msquic.git -b "$VERSION" --recursive --depth 1 --shallow-submodules msquic
fi

cd msquic

CURRENT_VSN="$(git describe --tags --exact-match 2>/dev/null || echo 'unknown')"

if [ "$CURRENT_VSN" = 'unknown' ]; then
    CURRENT_VSN="$(git rev-parse HEAD)"
fi

if [ "$CURRENT_VSN" != "$VERSION" ]; then
    echo "undesired_msquic_version, required=$VERSION, got=$CURRENT_VSN"
    exit 1
fi
