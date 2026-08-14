#!/usr/bin/env bash
# Multi-client aggregate throughput: C independent iwan-client socks
# processes (distinct usernames -> distinct sessions) hammer ONE
# iwan-server simultaneously. Answers "how much total throughput can a
# single server sustain across many clients".
#
# Requires root (server TUN device). Output is written to
# bench-multi.out (and echoed). Run with sudo:
#     sudo ./tests/bench_multi.sh
#     CLIENTS_LIST="1 2 4 8" CONNS=1 DURATION=5 sudo ./tests/bench_multi.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# optional positional args: [THREADS] [CLIENTS_LIST] [debug] (like bench.sh)
if [ -n "${1:-}" ]; then
    export IWAN_SRV_THREADS="$1"
fi
if [ -n "${2:-}" ]; then
    CLIENTS_LIST="$2"
fi
if [ "${3:-}" = "debug" ]; then
    export IWAN_DEBUG=1   # server prints per-second uplink/drop stats
fi

CLIENTS_LIST=${CLIENTS_LIST:-"1 2 4 8"}
CONNS=${CONNS:-1}              # TCP conns per client
DURATION=${DURATION:-5}        # seconds per window
PORT=16001                     # VPN UDP port
BASE_SOCKS=18080               # first local SOCKS listener
SINK_PORT=17010                # upload discard target
SRV_IP=100.64.0.1
SUBNET=100.64.0.0/16
TUN_NAME=iwan-srv-mt
OUT=bench-multi.out
WORK=$(mktemp -d)

SERVER_PID=""; CLI_PIDS=""; BENCH_PIDS=""; BENCH_SRV_PID=""; INPUT_RULE_SRV=0

cleanup() {
    set +e
    [ -n "$BENCH_PIDS" ] && kill $BENCH_PIDS 2>/dev/null
    [ -n "$BENCH_SRV_PID" ] && kill "$BENCH_SRV_PID" 2>/dev/null
    [ -n "$CLI_PIDS" ] && kill $CLI_PIDS 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    if [ "$INPUT_RULE_SRV" = 1 ]; then
        iptables -D INPUT -i "$TUN_NAME" -j ACCEPT 2>/dev/null
    fi
    ip link del "$TUN_NAME" 2>/dev/null
    sleep 0.2
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# a leftover sink from an aborted run would hold the ports forever
pkill -f 'bench_server.py' 2>/dev/null || true
pkill -f 'bench_client.py' 2>/dev/null || true
sleep 0.3

echo "== build =="
cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j"$(nproc)" >/dev/null

# distinct users: one session per client (same-username re-OPEN would
# rebind the single session and thrash)
MAXC=0
for C in $CLIENTS_LIST; do
    [ "$C" -gt "$MAXC" ] && MAXC=$C
done
: > "$WORK/users.txt"
for i in $(seq 1 "$MAXC"); do
    printf 'u%s:s3cret\n' "$i" >> "$WORK/users.txt"
done
chmod 600 "$WORK/users.txt"

echo "== start iwan-server (TUN) =="
pkill -f 'bin/iwan-server' 2>/dev/null || true
sleep 0.5
stdbuf -oL -eL ./bin/iwan-server --users "$WORK/users.txt" --port "$PORT" \
    --tun "$TUN_NAME" --server-ip "$SRV_IP" --subnet "$SUBNET" \
    --dns 114.114.114.114 --nat-if lo &
SERVER_PID=$!
for _ in $(seq 1 30); do
    ip addr show "$TUN_NAME" 2>/dev/null | grep -q "$SRV_IP" && break
    sleep 0.5
done
ip addr show "$TUN_NAME" 2>/dev/null | grep -q "$SRV_IP" || {
    echo "error: server TUN not ready" >&2
    exit 1
}
if ! iptables -C INPUT -i "$TUN_NAME" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -i "$TUN_NAME" -j ACCEPT 2>/dev/null && \
        INPUT_RULE_SRV=1
fi

echo "== start bench server (sink) =="
stdbuf -oL -eL python3 tests/bench_server.py --bind "$SRV_IP" \
    --sink-port "$SINK_PORT" --source-port 17011 &
BENCH_SRV_PID=$!
sleep 0.5
if ! ss -tln 2>/dev/null | grep -q ":$SINK_PORT "; then
    echo "error: bench sink not up" >&2
    exit 1
fi

exec > >(tee "$OUT") 2>&1   # everything -> bench-multi.out + console
NCORES=$(nproc)
echo "=== multi-client aggregate bench ($(date -u +%FT%TZ)) ==="
echo "clients=$CLIENTS_LIST conns/client=$CONNS duration=${DURATION}s (${NCORES} cores)"

for C in $CLIENTS_LIST; do
    # start C client processes
    CLI_PIDS=""
    for i in $(seq 1 "$C"); do
        ./bin/iwan-client socks --server 127.0.0.1 --port "$PORT" \
            --user "u$i" --pass s3cret \
            --listen "127.0.0.1:$((BASE_SOCKS + i))" \
            --allow-remote --socks-no-token \
            > "$WORK/cli$i.log" 2>&1 &
        CLI_PIDS="$CLI_PIDS $!"
    done
    for i in $(seq 1 "$C"); do
        for _ in $(seq 1 40); do
            if ss -tln 2>/dev/null | grep -q ":$((BASE_SOCKS + i)) "; then
                break
            fi
            sleep 0.25
        done
        ss -tln 2>/dev/null | grep -q ":$((BASE_SOCKS + i)) " || {
            echo "error: client $i listener not up" >&2
            exit 1
        }
    done

    echo "--- clients=$C (${DURATION}s window) ---"
    # server CPU sampling: sum utime+stime ticks over ALL iwan-server
    # processes (fork+drop leaves the parent waiting) plus the system
    # total from /proc/stat, both as deltas across the window.
    srv_ticks() {
        local t=0 p
        for p in $(pgrep -f 'bin/iwan-server' 2>/dev/null); do
            t=$((t + $(awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null || echo 0)))
        done
        echo "$t"
    }
    cpu0=$(srv_ticks)
    st0=$(awk '/^cpu / {print $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9 + $10 + $11}' /proc/stat)
    id0=$(awk '/^cpu / {print $5}' /proc/stat)
    # kernel UDP drop counters (server-side rcvbuf overflow shows here,
    # not in the server's own drop= statistic). Udp: InDatagrams
    # NoPorts InErrors RcvbufErrors; the header line is skipped by the
    # digit-anchored sed.
    u0=$(sed -n 's/^Udp: \([0-9][0-9]*\) \([0-9][0-9]*\) \([0-9][0-9]*\) \([0-9][0-9]*\).*/\1 \2 \3 \4/p' /proc/net/snmp)
    # per-owner UDP drops from /proc/net/udp (drops column by uid):
    # tells whether the SERVER sockets (uid 0/nobody) or the CLIENT
    # sockets (the bench user) are overflowing. uid is column 10.
    d0=$(awk 'NR>1 {s[$10]+=$NF} END {for (u in s) printf "%s:%s ", u, s[u]}' /proc/net/udp 2>/dev/null)
    t0=$(date +%s%N)
    BENCH_PIDS=""
    for i in $(seq 1 "$C"); do
        python3 tests/bench_client.py --target "$SRV_IP:$SINK_PORT" \
            --conns "$CONNS" --duration "$DURATION" --direction up \
            --socks "127.0.0.1:$((BASE_SOCKS + i))" \
            > "$WORK/bench$i.out" 2>&1 &
        BENCH_PIDS="$BENCH_PIDS $!"
    done
    wait $BENCH_PIDS 2>/dev/null || true
    cpu1=$(srv_ticks)
    st1=$(awk '/^cpu / {print $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9 + $10 + $11}' /proc/stat)
    id1=$(awk '/^cpu / {print $5}' /proc/stat)
    u1=$(sed -n 's/^Udp: \([0-9][0-9]*\) \([0-9][0-9]*\) \([0-9][0-9]*\) \([0-9][0-9]*\).*/\1 \2 \3 \4/p' /proc/net/snmp)
    d1=$(awk 'NR>1 {s[$10]+=$NF} END {for (u in s) printf "%s:%s ", u, s[u]}' /proc/net/udp 2>/dev/null)
    t1=$(date +%s%N)
    if [ "$t1" -gt "$t0" ] && [ "$st1" -gt "$st0" ]; then
        dticks=$((st1 - st0))
        didle=$((id1 - id0))
        dserv=$((cpu1 - cpu0))
        hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
        srv_cpu=$(awk -v a="$dserv" -v d="$dticks" -v h="$hz" \
            'BEGIN { printf "%.1f", a * 1.0 / d }')
        sys_cpu=$(awk -v d="$didle" -v t="$dticks" \
            'BEGIN { printf "%.0f", 100.0 * (1 - d * 1.0 / t) }')
        echo "server CPU: ${srv_cpu} cores | system CPU: ${sys_cpu}% (${NCORES} cores)"
        # Udp: InDatagrams NoPorts InErrors RcvbufErrors (per window delta)
        du=""; for i in 1 2 3 4; do
            a=$(echo "$u0" | cut -d' ' -f$i); b=$(echo "$u1" | cut -d' ' -f$i)
            du="$du $((b - a))"
        done
        echo "kernel UDP delta: InDatagrams$du (NoPorts/RcvbufErrors>0 = drops)"
        # per-uid drops delta: server = uid 0 (parent) / 65534 (nobody
        # child), clients = the invoking user's uid
        if [ -n "$d0" ] && [ -n "$d1" ]; then
            dd=""
            for u in $(echo "$d1" | tr ' ' '\n' | cut -d: -f1 | sort -un); do
                a=$(echo "$d0" | tr ' ' '\n' | grep "^$u:" | cut -d: -f2)
                b=$(echo "$d1" | tr ' ' '\n' | grep "^$u:" | cut -d: -f2)
                dd="$dd uid$u:+$((b - ${a:-0}))"
            done
            echo "UDP drops by uid:$dd"
        fi
    fi
    total=0
    for i in $(seq 1 "$C"); do
        # "AGG up: 1879.8 MB in 5.00s = 3007 Mbit/s aggregate"
        v=$(grep '^AGG' "$WORK/bench$i.out" | sed -n \
            's/.*= \([0-9][0-9]*\) Mbit\/s aggregate.*/\1/p')
        [ -n "$v" ] || v=0
        echo "client $i: $v Mbit/s"
        total=$((total + v))
    done
    echo "TOTAL ($C clients): $total Mbit/s aggregate"
    # client-side send stalls (UDP sndbuf full) visible in cli logs
    ne=$(grep -l "EAGAIN" "$WORK"/cli*.log 2>/dev/null | wc -l)
    [ "$ne" -gt 0 ] && echo "WARN: $ne client(s) hit UDP send EAGAIN"

    [ -n "$CLI_PIDS" ] && kill $CLI_PIDS 2>/dev/null
    CLI_PIDS=""
    sleep 1
done

echo "BENCH MULTI DONE -> $OUT"
