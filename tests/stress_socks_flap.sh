#!/usr/bin/env bash
# Session-flap stress: forces the SOCKS client through repeated tunnel
# session LOSS -> keepalive failure -> re-auth -> flow reset cycles while
# chaos traffic is in flight. This exercises the reconnect path
# (socks_reauth_flows / DNS generation bump / session_lost) that the
# steady-state chaos run never reaches -- the prime suspect for the
# reported "runs a while, then hangs at 100% CPU".
#
#   CYCLES=12 DOWN=8 ./run_flap_stress.sh
#
# Ports are distinct from the long-run and control harnesses so nothing
# interferes. SAFETY: pkills use anchored regexes that cannot match the
# user's production iwan-client-oidc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/bin"
CLIENT_BIN="$BIN/iwan-client"
SERVER_BIN="$BIN/iwan-server"

CYCLES="${CYCLES:-12}"
DOWN="${DOWN:-8}"          # seconds the server stays down per cycle
UP="${UP:-25}"            # seconds the server stays up per cycle
WORKERS="${WORKERS:-20}"
PORT=16021
SOCKS_ADDR="127.0.0.1:18086"
TARGET="100.64.0.1:17010"
OUTDIR="${OUTDIR:-$ROOT/stress-out/flap-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"

echo "=== session-flap stress: cycles=$CYCLES up=${UP}s down=${DOWN}s workers=$WORKERS ==="
echo "out=$OUTDIR"

export ASAN_OPTIONS="log_path=$OUTDIR/asan:halt_on_error=0:abort_on_error=0:detect_leaks=0:quarantine_size_mb=64"
export UBSAN_OPTIONS="log_path=$OUTDIR/ubsan:print_stacktrace=1:halt_on_error=0"

printf 'test:s3cret\n' > "$OUTDIR/users.txt"; chmod 600 "$OUTDIR/users.txt"

SRV_PID=""; CLI_PID=""; DOG_PID=""; SAMP_PID=""; CHAOS_PID=""
cleanup() {
    set +e
    [ -n "$CHAOS_PID" ] && kill "$CHAOS_PID" 2>/dev/null
    [ -n "$SAMP_PID" ] && kill "$SAMP_PID" 2>/dev/null
    [ -n "$DOG_PID" ] && kill "$DOG_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

start_server() {
    "$SERVER_BIN" --users "$OUTDIR/users.txt" --port "$PORT" --no-tun \
        --user "$(whoami)" >> "$OUTDIR/server.log" 2>&1 &
    SRV_PID=$!
    for _ in $(seq 1 40); do
        "$CLIENT_BIN" ping --server 127.0.0.1 --port "$PORT" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    return 1
}

# ISOLATION POLICY: never signal another process. An earlier version
# pkill'ed its own binary path here; because this harness shares ./bin with
# run_long_stress.sh, that pattern also matched -- and killed -- a
# concurrently running long test. Pre-flight the ports and abort on a
# collision instead: two harnesses can then never interfere.
if ss -uln 2>/dev/null | grep -q ":$PORT "; then
    echo "FATAL: UDP port $PORT already in use (another harness is running):"
    ss -ulnp 2>/dev/null | grep ":$PORT " || true
    exit 1
fi
for _p in $PORT "${SOCKS_ADDR##*:}"; do
    if ss -tln 2>/dev/null | grep -q ":$_p "; then
        echo "FATAL: TCP port $_p already in use (another harness is running):"
        ss -tlnp 2>/dev/null | grep ":$_p " || true
        exit 1
    fi
done

echo "--- start server + socks client ---"
start_server || { echo "FATAL: server never came up"; cat "$OUTDIR/server.log"; exit 1; }
"$CLIENT_BIN" socks --server 127.0.0.1 --port "$PORT" \
    --user test --pass s3cret --listen "$SOCKS_ADDR" > "$OUTDIR/client.log" 2>&1 &
CLI_PID=$!
for _ in $(seq 1 80); do
    ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} " && break
    sleep 0.25
done
ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} " || { echo "FATAL: socks port"; cat "$OUTDIR/client.log"; exit 1; }
echo "client pid=$CLI_PID server pid=$SRV_PID"

echo "--- start watchdog, sampler, chaos ---"
python3 tests/cpu_watchdog.py --pid "$CLI_PID" --threshold 85.0 \
    --duration-threshold 5 --timeout "$((CYCLES * (UP + DOWN) + 300))" \
    --output "$OUTDIR/spin_client.txt" > "$OUTDIR/dog.log" 2>&1 &
DOG_PID=$!
python3 tests/proc_sampler.py --pid "$CLI_PID" --pid "$SRV_PID" \
    --interval 5 --output "$OUTDIR/metrics.csv" > "$OUTDIR/sampler.log" 2>&1 &
SAMP_PID=$!
python3 tests/stress_chaos_socks.py --socks "$SOCKS_ADDR" --target "$TARGET" \
    --duration "$((CYCLES * (UP + DOWN) + 60))" --workers "$WORKERS" \
    > "$OUTDIR/chaos.log" 2>&1 &
CHAOS_PID=$!

echo "--- flap loop ---"
for c in $(seq 1 "$CYCLES"); do
    sleep "$UP"
    if ! kill -0 "$CLI_PID" 2>/dev/null; then
        echo "cycle $c: CLIENT DIED during up-phase -- see $OUTDIR/client.log"
        break
    fi
    echo "cycle $c: killing server (pid=$SRV_PID) for ${DOWN}s to force session loss"
    kill -9 "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    sleep "$DOWN"
    if ! kill -0 "$CLI_PID" 2>/dev/null; then
        echo "cycle $c: CLIENT DIED during outage -- see $OUTDIR/client.log"
        break
    fi
    if ! start_server; then
        echo "cycle $c: server restart FAILED"
    fi
    echo "cycle $c: server back (pid=$SRV_PID); client cpu now $(ps -o %cpu= -p "$CLI_PID" 2>/dev/null | tr -d ' ')%"
done

echo "=== results ==="
tail -2 "$OUTDIR/chaos.log" || true
echo "--- client alive: $(kill -0 "$CLI_PID" 2>/dev/null && echo YES || echo NO) ---"
for f in "$OUTDIR"/asan.* "$OUTDIR"/ubsan.*; do
    [ -e "$f" ] || continue
    echo "*** SANITIZER REPORT $f ***"; head -50 "$f"
done
if [ -f "$OUTDIR/spin_client.txt" ]; then
    echo "*** CPU BUSY-SPIN CAPTURED ***"; head -60 "$OUTDIR/spin_client.txt"
else
    echo "no CPU busy-spin detected"
fi
echo "--- client trend (last 12) ---"
awk -F, 'NR>1 && $3=="iwan-client" {printf "%ss rss=%.1fMB fds=%s thr=%s cpu=%s%%\n",$1,$5/1024,$6,$7,$4}' "$OUTDIR/metrics.csv" | tail -12
echo "--- client log tail (re-auth activity) ---"
grep -iE "re-?auth|session|reconnect|keepalive|loss" "$OUTDIR/client.log" | tail -12 || true
echo "FLAP_DONE $OUTDIR"
