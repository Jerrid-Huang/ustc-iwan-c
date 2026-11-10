#!/usr/bin/env bash
# Fast local pre-filter for the iWAN NT driver sources.
# A pass here does not mean the driver builds; see tools/kernel-stubs/README.md.
set -u
cd "$(dirname "$0")/.." || exit 1

stub=tools/kernel-stubs
status=0

for src in driver/*.c; do
    case "$(basename "$src")" in
        # The NDIS miniport body needs far more of ndis.h than the stub
        # surface covers; it is validated by the WDK build only.
        iwan_nt_miniport.c) continue ;;
    esac
    printf '%-28s ' "$(basename "$src")"
    if out=$(gcc -fsyntax-only -std=c11 -DIWAN_NT_KERNEL -I"$stub" \
                -Wall -Wextra -Wshadow -Wdeclaration-after-statement \
                -Wno-unused-parameter "$src" 2>&1); then
        echo OK
    else
        echo FAIL
        printf '%s\n' "$out" | head -20
        status=1
    fi
done

# Every kernel-free module with a host unit test runs here. A module that is
# not listed is only syntax-checked above, which proves nothing about its
# behaviour.
run_host_test() {
    local name=$1
    local main=$2
    shift 2
    [ -f "$main" ] || return 0
    printf '%-28s ' "$main"
    if out=$(gcc -std=c11 -Wall -Wextra -Werror -I driver \
                "$main" "$@" -o "/tmp/iwan_nt_${name}_test" 2>&1) && \
       out=$("/tmp/iwan_nt_${name}_test" 2>&1); then
        echo "OK ($out)"
    else
        echo FAIL
        printf '%s\n' "$out" | head -20
        status=1
    fi
}

run_host_test frame tests/frame_test.c driver/iwan_nt_frame.c
run_host_test demux tests/demux_test.c driver/iwan_nt_demux.c driver/iwan_nt_frame.c
run_host_test ring tests/ring_test.c driver/iwan_nt_ring.c
run_host_test ingress tests/ingress_test.c driver/iwan_nt_ingress.c driver/iwan_nt_demux.c driver/iwan_nt_frame.c driver/iwan_nt_ring.c

if grep -rlP '[^\x00-\x7F]' driver tools 2>/dev/null | grep -v '\.vcxproj$' | grep -q .; then
    echo "non-ASCII source found:"
    grep -rlP '[^\x00-\x7F]' driver tools | grep -v '\.vcxproj$'
    status=1
fi

exit $status
