#!/usr/bin/env bash
#
# Build the user-mode half (control library + iwannt-ctl) with MinGW-w64.
#
# This exists because the development host is Linux: the Windows runner in CI
# builds the same sources with cl, and this script is the fast local equivalent
# for edit/compile loops that do not touch kernel headers.
#
# Usage: tools/build-user.sh [output.exe]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/build/user/iwannt-ctl.exe}
cc=${CC:-x86_64-w64-mingw32-gcc}

if ! command -v "$cc" >/dev/null 2>&1; then
    echo "missing cross compiler: $cc" >&2
    exit 1
fi

mkdir -p "$(dirname "$out")"
"$cc" -std=c11 -Wall -Wextra -Werror -Wshadow -O2 -I "$root/driver" \
    -o "$out" \
    "$root/user/iwan_nt_control.c" \
    "$root/driver/iwan_nt_crypto.c" \
    "$root/user/iwan_nt_inet.c" \
    "$root/driver/iwan_nt_session.c" \
    "$root/driver/iwan_nt_peer.c" \
    "$root/user/iwannt_connect.c" \
    "$root/user/iwannt-ctl.c" \
    -lws2_32

echo "built $out"
