#!/bin/sh
set -e

KEYS_DIR=/keys

mkdir -p "$KEYS_DIR"

if [ -n "$PKG_IBE_SECRET" ] && [ -n "$PKG_IBE_PUBLIC" ] && [ -n "$PKG_IBS_SECRET" ] && [ -n "$PKG_IBS_PUBLIC" ]; then
    echo "Loading keys from environment variables..."
    chmod 600 "$KEYS_DIR/pkg_ibe.sec" "$KEYS_DIR/pkg_ibs.sec"
else
    echo "No key environment variables set. Generating new keys..."
    /usr/local/bin/pg-pkg gen \
        --ibe-secret-path "$KEYS_DIR/pkg_ibe.sec" \
        --ibe-public-path "$KEYS_DIR/pkg_ibe.pub" \
        --ibs-secret-path "$KEYS_DIR/pkg_ibs.sec" \
        --ibs-public-path "$KEYS_DIR/pkg_ibs.pub"
fi

exec /usr/local/bin/pg-pkg server \
    ${IRMA_TOKEN:+-t "$IRMA_TOKEN"} \
    -i "${IRMA_SERVER:-https://is.yivi.app}" \
    --ibe-secret-path "$KEYS_DIR/pkg_ibe.sec" \
    --ibe-public-path "$KEYS_DIR/pkg_ibe.pub" \
    --ibs-secret-path "$KEYS_DIR/pkg_ibs.sec" \
    --ibs-public-path "$KEYS_DIR/pkg_ibs.pub"
