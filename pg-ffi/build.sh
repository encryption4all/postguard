#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building pg-ffi native library..."
cargo build --release

# Detect platform and copy to .NET runtimes directory
UNAME_S=$(uname -s)
UNAME_M=$(uname -m)

if [ "$UNAME_S" = "Darwin" ]; then
    LIB_EXT="dylib"
    if [ "$UNAME_M" = "arm64" ]; then
        RID="osx-arm64"
    else
        RID="osx-x64"
    fi
elif [ "$UNAME_S" = "Linux" ]; then
    LIB_EXT="so"
    if [ "$UNAME_M" = "aarch64" ]; then
        RID="linux-arm64"
    else
        RID="linux-x64"
    fi
else
    echo "Unsupported platform: $UNAME_S"
    exit 1
fi

RELEASE_DIR="target/release"

# If building as part of workspace, output goes to workspace root target/
if [ -f "../Cargo.toml" ] && grep -q '\[workspace\]' "../Cargo.toml"; then
    RELEASE_DIR="../target/release"
fi

echo "Built libpg_ffi.${LIB_EXT} at ${RELEASE_DIR}/"

# Copy to postguard-dotnet runtimes if the repo exists alongside this one
DOTNET_REPO="${PG_DOTNET_REPO:-../../postguard-dotnet}"
if [ -d "$DOTNET_REPO/src/E4A.PostGuard" ]; then
    DEST="${DOTNET_REPO}/src/E4A.PostGuard/runtimes/${RID}/native"
    mkdir -p "$DEST"
    cp "${RELEASE_DIR}/libpg_ffi.${LIB_EXT}" "$DEST/"
    echo "Copied to ${DEST}/"
else
    echo "Set PG_DOTNET_REPO to copy the native library to postguard-dotnet"
fi
