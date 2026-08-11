#!/usr/bin/env bash
# ci/build-openssl.sh — build a static (no-shared) OpenSSL for a native or
# cross target. Used by CI for every architecture; also handy locally.
#
# usage: ci/build-openssl.sh <Configure-target> <cross-prefix> <prefix> [extra Configure args...]
#   <Configure-target>  OpenSSL Configure target, e.g. linux-x86_64,
#                       linux-aarch64, linux-armv4, linux-riscv64,
#                       linux-ppc64le, linux-s390x, mingw64, mingw
#   <cross-prefix>      compiler prefix, e.g. aarch64-linux-musl- or
#                       x86_64-w64-mingw32-; empty for native builds
#   <prefix>            install prefix (headers + libssl.a + libcrypto.a)
#   extra args...       appended to Configure, e.g. no-asm (required for
#                       mingw64: binutils' PE assembler rejects the ELF
#                       directives in perlasm-generated .s files)
#
# The OpenSSL source tarball is downloaded once (cached in /tmp) and each
# call works on its own copy, so several architectures can build from the
# same runner sequentially.
set -euo pipefail

VER="3.5.1"
TARGET="$1"
CROSS_PREFIX="$2"
PREFIX="$3"
shift 3

TGZ="/tmp/openssl-${VER}.tar.gz"
WORK="/tmp/openssl-work-${TARGET}-${CROSS_PREFIX//\//_}-$$"
trap 'rm -rf "$WORK"' EXIT

if [ ! -f "$TGZ" ]; then
    echo "== downloading OpenSSL ${VER} =="
    curl -sL --retry 3 --max-time 400 \
        "https://www.openssl.org/source/openssl-${VER}.tar.gz" -o "$TGZ"
fi

mkdir -p "$WORK"
tar xzf "$TGZ" -C "$WORK"
cd "$WORK/openssl-${VER}"

CONF_ARGS=(no-shared no-tests)
if [ -n "$CROSS_PREFIX" ]; then
    CONF_ARGS+=(--cross-compile-prefix="$CROSS_PREFIX")
fi
CONF_ARGS+=(--prefix="$PREFIX" "$@")

echo "== configuring OpenSSL ${TARGET} (${CROSS_PREFIX:-native}) =="
./Configure "$TARGET" "${CONF_ARGS[@]}"
make -j"$(nproc)" build_libs
make install_sw

# sanity: the static libs must exist (OpenSSL 64-bit targets install to
# lib64/, 32-bit and mingw to lib/)
if [ ! -f "$PREFIX/lib/libssl.a" ] && [ ! -f "$PREFIX/lib64/libssl.a" ]; then
    echo "error: libssl.a not found under $PREFIX/lib or $PREFIX/lib64" >&2
    exit 1
fi
echo "== OpenSSL ${TARGET} installed to ${PREFIX} =="
