#!/usr/bin/env bash
# ci/bench-control.sh — rootless control-plane benchmark for CI.
#
# Starts a local iwan-server (--no-tun, no root/TUN needed) and measures
# the control plane end to end over real UDP:
#   - ping RTT (PING/PONG round trip), N rounds -> min/avg/max/p50/p95
#   - auth handshake latency (OPEN -> OPEN_ACK), N rounds
# Results are written as a markdown table to $OUT and printed.
#
# The data plane (socks/TUN throughput) requires TUN devices + root and
# therefore stays local: sudo tests/bench.sh (see README 性能基准).
#
# usage: ci/bench-control.sh [OUTFILE]     (default bench-results.md)
# env:  PING_ROUNDS (50)  AUTH_ROUNDS (10)  PORT (16001)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-bench-results.md}"
PING_ROUNDS="${PING_ROUNDS:-50}"
AUTH_ROUNDS="${AUTH_ROUNDS:-10}"
PORT="${PORT:-16001}"

WORK=$(mktemp -d)
SRV_PID=""
trap 'rm -rf "$WORK"; [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true' EXIT

[ -x ./bin/iwan-server ] || { echo "error: bin/iwan-server missing (build first)" >&2; exit 1; }

printf 'bench:s3cret\n' > "$WORK/users.txt"
chmod 600 "$WORK/users.txt"

./bin/iwan-server --users "$WORK/users.txt" --port "$PORT" --no-tun \
    --user "$(whoami)" > "$WORK/server.log" 2>&1 &
SRV_PID=$!

ready=0
for _ in $(seq 1 40); do
    if ./bin/iwan-client ping --server 127.0.0.1 --port "$PORT" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
if [ "$ready" != 1 ]; then
    echo "error: iwan-server did not become ready" >&2
    tail -20 "$WORK/server.log" >&2
    exit 1
fi

stats() {  # $1=label, $2=file with one decimal (ms) per line
    python3 - "$1" "$2" <<'EOF'
import sys
label, path = sys.argv[1], sys.argv[2]
with open(path) as f:
    vals = sorted(float(x) for x in f if x.strip())
if not vals:
    print(f"{label}: no samples"); raise SystemExit(2)
n = len(vals)
def pct(p):
    k = (n - 1) * p
    f, c = int(k), min(int(k) + 1, n - 1)
    return vals[f] + (vals[c] - vals[f]) * (k - f)
print(f"{label}: n={n} min={vals[0]:.4f} avg={sum(vals)/n:.4f} "
      f"max={vals[-1]:.4f} p50={pct(0.5):.4f} p95={pct(0.95):.4f} ms")
EOF
}

echo "== ping RTT ($PING_ROUNDS rounds) =="
PING_MS=""
PING_FAIL=0
for _ in $(seq 1 "$PING_ROUNDS"); do
    line=$(./bin/iwan-client ping --server 127.0.0.1 --port "$PORT" 2>/dev/null \
        | grep -oE 'RTT=[0-9.]+ ?(µs|us|ms|s)' || true)
    if [ -z "$line" ]; then
        PING_FAIL=$((PING_FAIL + 1))
        continue
    fi
    val=${line#RTT=}
    num=$(printf '%s' "$val" | grep -oE '^[0-9.]+')
    case "$val" in
        *µs|*us) ms=$(awk "BEGIN{print $num/1000}") ;;
        *ms)     ms=$num ;;
        *s)      ms=$(awk "BEGIN{print $num*1000}") ;;
        *)       continue ;;
    esac
    PING_MS="${PING_MS}${ms}\n"
done
if [ -z "$PING_MS" ]; then
    echo "error: all ping rounds failed" >&2
    tail -20 "$WORK/server.log" >&2
    exit 1
fi
printf '%b' "$PING_MS" > "$WORK/ping.txt"
PING_STAT=$(stats "ping RTT" "$WORK/ping.txt")

echo "== auth handshake ($AUTH_ROUNDS rounds) =="
AUTH_MS=""
for _ in $(seq 1 "$AUTH_ROUNDS"); do
    t0=$(date +%s%N)
    out=$(./bin/iwan-client auth --server 127.0.0.1 --port "$PORT" \
        --user bench --pass s3cret 2>&1) || true
    t1=$(date +%s%N)
    printf '%s\n' "$out" | grep -q 'OK sid=' || continue
    AUTH_MS="${AUTH_MS}$(awk "BEGIN{print ($t1-$t0)/1000000}")\n"
done
if [ -z "$AUTH_MS" ]; then
    echo "error: all auth rounds failed" >&2
    tail -20 "$WORK/server.log" >&2
    exit 1
fi
printf '%b' "$AUTH_MS" > "$WORK/auth.txt"
AUTH_STAT=$(stats "auth handshake" "$WORK/auth.txt")

{
    echo "### CI 控制面基准(本地回环, --no-tun 服务器)"
    echo
    echo "| 指标 | 结果 |"
    echo "|---|---|"
    echo "| ping RTT min / avg / max | $(echo "$PING_STAT" | awk '{print $4" / "$5" / "$6" ms"}') |"
    echo "| ping RTT p50 / p95 | $(echo "$PING_STAT" | awk '{print $7" / "$8" ms"}') |"
    echo "| ping 丢包 | ${PING_FAIL}/${PING_ROUNDS} |"
    echo "| auth 握手 min / avg / max | $(echo "$AUTH_STAT" | awk '{print $4" / "$5" / "$6" ms"}') |"
    if [ -n "${GITHUB_SHA:-}" ]; then
        echo "| 环境 | commit \`${GITHUB_SHA:0:12}\` · \`${GITHUB_RUN_ID:-?}\` · ubuntu-latest · 控制面(UDP 回环) |"
    fi
    echo
    echo "> 数据面吞吐基准需要 TUN 设备 + root,CI 无法运行;本地用 \`sudo tests/bench.sh\`(见 README 性能基准)。"
} | tee "$OUT"

echo "== done: $OUT =="
