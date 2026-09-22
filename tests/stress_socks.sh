#!/usr/bin/env bash
# Long-running SOCKS-only stress test with ASan+UBSan binaries.
#
#   DURATION=10800 WORKERS=40 ./run_long_stress.sh
#
# Components:
#   - bin/iwan-server --no-tun   (ASan+UBSan, TCP echo mirror)
#   - bin/iwan-client socks      (ASan+UBSan, the unit under test)
#   - tests/stress_chaos_socks.py  7-profile chaos generator
#   - tests/cpu_watchdog.py      captures a gdb backtrace if CPU pegs
#   - tests/proc_sampler.py      CSV of CPU%/RSS/fds/threads over time
#
# SAFETY: the pkills match argv[0] EXACTLY (absolute path, pkill -x -f) so
# the user's production `iwan-client-oidc` is never touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/bin"
CLIENT_BIN="$BIN/iwan-client"
SERVER_BIN="$BIN/iwan-server"

DURATION="${DURATION:-10800}"      # seconds (default 3 hours)
WORKERS="${WORKERS:-40}"
SOCKS_ADDR="127.0.0.1:18083"
TARGET="100.64.0.1:17010"
PORT=16001
OUTDIR="${OUTDIR:-$ROOT/stress-out/socks-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"

echo "=== long SOCKS stress: duration=${DURATION}s workers=$WORKERS out=$OUTDIR ==="
# The run is only meaningful with sanitizer-instrumented binaries; warn if the
# ones in bin/ are not (a plain Release build has no __asan_init).
if ! strings "$CLIENT_BIN" 2>/dev/null | grep -q __asan_init; then
    echo "NOTE: $CLIENT_BIN is NOT AddressSanitizer-instrumented."
    echo "      Build one first if you want sanitizer coverage:"
    echo "      cmake -B build-sanitize -DBUILD_TESTING=ON \\"
    echo "        -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' \\"
    echo "        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'"
    echo "      (bin/ is the fixed output dir, so that build overwrites it)"
fi

# --- sanitizer report files (log_path makes ASan/UBSan write to disk even
# --- when stderr is redirected; halt_on_error=0 keeps the run alive so we
# --- collect every report instead of only the first)
export ASAN_OPTIONS="log_path=$OUTDIR/asan:halt_on_error=0:abort_on_error=0:detect_leaks=0:quarantine_size_mb=64:malloc_context_size=10"
export UBSAN_OPTIONS="log_path=$OUTDIR/ubsan:print_stacktrace=1:halt_on_error=0"

printf 'test:s3cret\n' > "$OUTDIR/users.txt"
chmod 600 "$OUTDIR/users.txt"

SRV_PID=""; CLI_PID=""; DOG_PID=""; SAMP_PID=""
cleanup() {
    set +e
    [ -n "$SAMP_PID" ] && kill "$SAMP_PID" 2>/dev/null
    [ -n "$DOG_PID" ] && kill "$DOG_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    wait 2>/dev/null
    echo "=== teardown done; artifacts in $OUTDIR ==="
}
trap cleanup EXIT

# ISOLATION POLICY (learned the hard way): this harness NEVER signals another
# process. A previous version pkill'ed its own binary path as a "safety"
# measure, which killed a concurrently running harness that used the same
# ./bin paths (and its absolute pattern also made the check useless against
# the real production client, which runs as a different uid). Instead we
# pre-flight the ports and refuse to start on a collision, so two harnesses
# can never fight: the second one aborts loudly and changes nothing.
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
    echo "FATAL: TCP port $PORT is already in use (another harness is running):"
    ss -tlnp 2>/dev/null | grep ":$PORT " || true
    exit 1
fi
if ss -uln 2>/dev/null | grep -q ":$PORT "; then
    echo "FATAL: UDP port $PORT is already in use (another harness is running):"
    ss -ulnp 2>/dev/null | grep ":$PORT " || true
    exit 1
fi
if ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} "; then
    echo "FATAL: SOCKS port ${SOCKS_ADDR##*:} is already in use:"
    ss -tlnp 2>/dev/null | grep ":${SOCKS_ADDR##*:} " || true
    exit 1
fi

echo "--- start server ---"
"$SERVER_BIN" --users "$OUTDIR/users.txt" --port "$PORT" --no-tun \
    --user "$(whoami)" > "$OUTDIR/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 60); do
    "$CLIENT_BIN" ping --server 127.0.0.1 --port "$PORT" >/dev/null 2>&1 && break
    sleep 0.25
done

echo "--- start socks client ---"
"$CLIENT_BIN" socks --server 127.0.0.1 --port "$PORT" \
    --user test --pass s3cret --listen "$SOCKS_ADDR" \
    > "$OUTDIR/client.log" 2>&1 &
CLI_PID=$!
for _ in $(seq 1 80); do
    ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} " && break
    sleep 0.25
done
if ! ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} "; then
    echo "FATAL: SOCKS port did not open"; cat "$OUTDIR/client.log"; exit 1
fi
echo "socks listening on $SOCKS_ADDR (client pid=$CLI_PID, server pid=$SRV_PID)"

echo "--- start watchdog + sampler ---"
# watchdog on the client: on a sustained CPU peg it dumps all thread stacks
python3 tests/cpu_watchdog.py --pid "$CLI_PID" --threshold 85.0 \
    --duration-threshold 5 --timeout "$((DURATION + 300))" \
    --output "$OUTDIR/spin_client.txt" > "$OUTDIR/dog_client.log" 2>&1 &
DOG_PID=$!
python3 tests/proc_sampler.py --pid "$CLI_PID" --pid "$SRV_PID" \
    --interval 10 --output "$OUTDIR/metrics.csv" > "$OUTDIR/sampler.log" 2>&1 &
SAMP_PID=$!

echo "--- chaos workload ---"
CHAOS_RC=0
python3 tests/stress_chaos_socks.py --socks "$SOCKS_ADDR" --target "$TARGET" \
    --duration "$DURATION" --workers "$WORKERS" > "$OUTDIR/chaos.log" 2>&1 || CHAOS_RC=$?
echo "chaos rc=$CHAOS_RC"

echo "=== results ==="
tail -1 "$OUTDIR/chaos.log" || true
if [ -f "$OUTDIR/spin_client.txt" ]; then
    echo "*** CPU BUSY-SPIN CAPTURED -> $OUTDIR/spin_client.txt ***"
    head -60 "$OUTDIR/spin_client.txt"
else
    echo "no CPU busy-spin detected"
fi
for f in "$OUTDIR"/asan.* "$OUTDIR"/ubsan.*; do
    [ -e "$f" ] || continue
    echo "*** SANITIZER REPORT: $f ***"
    head -40 "$f"
done
echo "client alive: $(kill -0 "$CLI_PID" 2>/dev/null && echo YES || echo NO)"
echo "server alive: $(kill -0 "$SRV_PID" 2>/dev/null && echo YES || echo NO)"
echo "=== metrics tail ==="
tail -5 "$OUTDIR/metrics.csv" 2>/dev/null || true
echo "LONG_STRESS_COMPLETE"
