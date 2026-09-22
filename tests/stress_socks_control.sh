#!/usr/bin/env bash
# Control measurement for leak attribution: a NON-sanitized Release build of
# the CURRENT HEAD, run on its own ports under the same chaos workload as
# tests/stress_socks.sh.
#
# Why: AddressSanitizer's allocator/quarantine can make RSS climb for a while
# and then plateau, which looks exactly like a leak. Running the identical
# workload against an uninstrumented build separates a real leak from that
# warm-up. On the 3h SOCKS run this showed +36 KB over 240s (~0.02 KB/conn)
# versus the ASan build's far larger transient, i.e. no leak.
#
#   DURATION=240 WORKERS=40 ./tests/stress_socks_control.sh
#
# The control tree is built here (isolated copy of HEAD) because this repo
# hardcodes CMAKE_RUNTIME_OUTPUT_DIRECTORY to <source>/bin, so a second build
# directory inside the same source tree would overwrite bin/ -- and the tree
# itself must stay outside the repo so the copy's bin/ is its own.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DURATION="${DURATION:-240}"
WORKERS="${WORKERS:-15}"
OUTDIR="${OUTDIR:-$ROOT/stress-out/control-$(date +%Y%m%d-%H%M%S)}"
CTL="${CTL:-$OUTDIR/tree}"
PORT=16011
SOCKS_ADDR="127.0.0.1:18085"
TARGET="100.64.0.1:17010"
mkdir -p "$OUTDIR"

echo "=== control run: duration=${DURATION}s workers=$WORKERS out=$OUTDIR ==="

# --- isolated non-sanitized Release build of HEAD -------------------------
# -S is explicit and load-bearing: `cmake -B <dir>` alone takes the CURRENT
# directory as the source tree, which would configure this repo and write the
# "control" binaries into the real bin/ (this repo hardcodes
# CMAKE_RUNTIME_OUTPUT_DIRECTORY to <source>/bin).
if [ ! -x "$CTL/bin/iwan-client" ]; then
    echo "--- building isolated control tree at $CTL ---"
    mkdir -p "$CTL"
    git archive HEAD | tar -x -C "$CTL"
    if ! cmake -S "$CTL" -B "$CTL/build" -DCMAKE_BUILD_TYPE=Release \
            > "$OUTDIR/control-cfg.log" 2>&1 ||
       ! cmake --build "$CTL/build" -j"$(nproc)" \
            > "$OUTDIR/control-build.log" 2>&1; then
        echo "FATAL: control build failed; see $OUTDIR/control-build.log"
        tail -20 "$OUTDIR/control-build.log" 2>/dev/null
        exit 1
    fi
fi
CLIENT_BIN="$CTL/bin/iwan-client"
SERVER_BIN="$CTL/bin/iwan-server"
if [ ! -x "$CLIENT_BIN" ]; then
    echo "FATAL: $CLIENT_BIN missing after build; see $OUTDIR/control-build.log"
    exit 1
fi
if strings "$CLIENT_BIN" 2>/dev/null | grep -q __asan_init; then
    echo "FATAL: control binaries are sanitizer-instrumented; they must not be"; exit 1
fi
echo "binaries: $CTL/bin (NON-sanitized Release)"

# ISOLATION POLICY: never signal another process (see tests/stress_socks.sh).
for _p in $PORT "${SOCKS_ADDR##*:}"; do
    if ss -tln 2>/dev/null | grep -q ":$_p "; then
        echo "FATAL: TCP port $_p already in use (another harness is running):"
        ss -tlnp 2>/dev/null | grep ":$_p " || true
        exit 1
    fi
done
if ss -uln 2>/dev/null | grep -q ":$PORT "; then
    echo "FATAL: UDP port $PORT already in use (another harness is running):"; exit 1
fi

printf 'test:s3cret\n' > "$OUTDIR/users.txt"; chmod 600 "$OUTDIR/users.txt"

SRV_PID=""; CLI_PID=""; SAMP_PID=""
cleanup() {
    set +e
    [ -n "$SAMP_PID" ] && kill "$SAMP_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

"$SERVER_BIN" --users "$OUTDIR/users.txt" --port "$PORT" --no-tun \
    --user "$(whoami)" > "$OUTDIR/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 60); do
    "$CLIENT_BIN" ping --server 127.0.0.1 --port "$PORT" >/dev/null 2>&1 && break
    sleep 0.25
done

"$CLIENT_BIN" socks --server 127.0.0.1 --port "$PORT" \
    --user test --pass s3cret --listen "$SOCKS_ADDR" > "$OUTDIR/client.log" 2>&1 &
CLI_PID=$!
for _ in $(seq 1 80); do
    ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} " && break
    sleep 0.25
done
ss -tln 2>/dev/null | grep -q ":${SOCKS_ADDR##*:} " || { echo "FATAL: socks port"; cat "$OUTDIR/client.log"; exit 1; }
echo "control client pid=$CLI_PID server pid=$SRV_PID"

python3 tests/proc_sampler.py \
    --pid "$CLI_PID" --pid "$SRV_PID" --interval 10 \
    --output "$OUTDIR/metrics.csv" > "$OUTDIR/sampler.log" 2>&1 &
SAMP_PID=$!

python3 tests/stress_chaos_socks.py \
    --socks "$SOCKS_ADDR" --target "$TARGET" \
    --duration "$DURATION" --workers "$WORKERS" > "$OUTDIR/chaos.log" 2>&1 || true

echo "=== chaos result ==="; tail -1 "$OUTDIR/chaos.log"
echo "=== client trend (rss should be FLAT if the ASan growth was quarantine) ==="
awk -F, 'NR>1 && $3=="iwan-client" {print $1"s rss="$5"KB fds="$6" thr="$7" cpu="$4"%"}' "$OUTDIR/metrics.csv"
echo "=== server trend ==="
awk -F, 'NR>1 && $3=="iwan-server" {print $1"s rss="$5"KB fds="$6" thr="$7}' "$OUTDIR/metrics.csv" | tail -3
echo "CONTROL_DONE $OUTDIR"
