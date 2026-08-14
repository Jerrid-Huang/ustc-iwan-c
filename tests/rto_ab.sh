#!/usr/bin/env bash
# RTO tail-latency A/B: run N small HTTPS requests through a SOCKS5
# proxy, once per binary, and print the tail (>0.5s) distribution.
# Usage: sudo ./tests/rto_ab.sh <OLD_BIN> <NEW_BIN> [N]
set -uo pipefail

OLD="$1"; NEW="$2"; N=${3:-100}
PORT=${PORT:-1081}
OUT="${OUT:-$HOME/rto-ab.out}"

start() {   # $1 = binary
    pkill -f 'iwan-client-oidc --connect' 2>/dev/null; sleep 1
    nohup "$1" --connect --socks --socks-listen 127.0.0.1:$PORT \
        --allow-remote --socks-no-token --server 202.141.176.3:6001 \
        > "${LOG:-$HOME/oidc-ab.log}" 2>&1 &
    for _ in $(seq 1 30); do
        ss -tln 2>/dev/null | grep -q ":$PORT " && return 0
        sleep 0.5
    done
    echo "listener not up"; return 1
}

run_one() {   # $1 = binary  $2 = label
    start "$1" || return
    echo "== $2 ($N requests) =="
    local ntail=0
    local nfail=0
    local max="0.0"
    local ts=""
    for i in $(seq 1 "$N"); do
        t=$(curl -sS -o /dev/null --socks5-hostname 127.0.0.1:$PORT \
            -w '%{time_total}' https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
        rc=$?
        if [ $rc -ne 0 ] || [ -z "$t" ]; then
            # curl failure still prints -w output (0.000): use the
            # exit code, not the empty-string test, or a dead proxy
            # shows up as a fast "success"
            nfail=$((nfail + 1))
            echo "  req $i: FAILED (rc=$rc)"
            continue
        fi
        ts="$ts $t"
        max=$(awk -v t="$t" -v m="$max" 'BEGIN { if (t > m) print t; else print m }')
        awk -v i="$i" -v t="$t" 'BEGIN { if (t > 0.5) printf "  req %d: %.2fs\n", i, t }'
        awk -v t="$t" 'BEGIN { if (t > 0.5) exit 0; exit 1 }' && ntail=$((ntail + 1))
    done
    if [ -n "$ts" ]; then
        stats=$(echo "$ts" | tr ' ' '\n' | grep -v '^$' | \
            awk '{s+=$1; a[NR]=$1; if ($1>mx) mx=$1} END { printf "avg=%.3fs ", s/NR; for (i=1;i<=NR;i++) for (j=i+1;j<=NR;j++) if (a[i]>a[j]) {t=a[i];a[i]=a[j];a[j]=t}; p=NR*0.95; pi=int(p); if (pi<1) pi=1; printf "p95=%.3fs max=%.3fs", a[pi], mx }')
        echo "  $stats"
    fi
    echo "  failed: $nfail/$N | tails >0.5s: $ntail/$N"
    pkill -f 'iwan-client-oidc --connect' 2>/dev/null; sleep 1
}

exec > >(tee "$OUT") 2>&1
run_one "$OLD" "OLD"
run_one "$NEW" "NEW"
echo "== done: $OUT =="
