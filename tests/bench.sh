#!/usr/bin/env bash
# iWAN throughput benchmark: client -> server TCP upload AND download
# through both client modes (socks, TUN), at 1/2/4/8 connections, each
# measured over a FIXED send window (DURATION, default 5s). Reports the
# aggregate throughput from the actual bytes transferred.
#
# Requires root (TUN devices). Run with sudo:
#     sudo ./tests/bench.sh
#     DURATION=10 CONNS="1 2 4 8" sudo ./tests/bench.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# optional positional args: [THREADS] [debug] [mini]
if [ -n "${1:-}" ]; then
    export IWAN_SRV_THREADS="$1"
fi
if [ "${2:-}" = "debug" ]; then
    export IWAN_DEBUG=1
fi
MINI=0
if [ "${3:-}" = "mini" ]; then
    MINI=1
fi

if [ "$(id -u)" != 0 ]; then
    echo "error: bench needs root (TUN devices); run with sudo" >&2
    exit 1
fi

PORT=16001            # VPN UDP port
SOCKS_PORT=18080      # local SOCKS5 listener
SINK_PORT=17010       # upload discard target
SOURCE_PORT=17011     # download data source
SRV_IP=100.64.0.1
SUBNET=100.64.0.0/16
TUN_NS=iwanns
TUN_NAME=iwantun0
VETH_IP=172.31.199.1
DURATION=${DURATION:-5}
CONNS_LIST=${CONNS_LIST:-"1 2 4 8"}
WORK=$(mktemp -d)

SERVER_PID=""; SOCKS_PID=""; PROXY_PID=""; BENCH_PID=""
INPUT_RULE_SRV=0; INPUT_RULE_VETH=0

cleanup() {
    set +e
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$SOCKS_PID" ] && kill "$SOCKS_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$BENCH_PID" ] && kill "$BENCH_PID" 2>/dev/null
    if [ "$INPUT_RULE_SRV" = 1 ]; then
        iptables -D INPUT -i iwan-srv-it -j ACCEPT 2>/dev/null
    fi
    if [ "$INPUT_RULE_VETH" = 1 ]; then
        iptables -D INPUT -i veth0 -j ACCEPT 2>/dev/null
    fi
    ip netns del "$TUN_NS" 2>/dev/null
    ip link del veth0 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build =="
cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j"$(nproc)" >/dev/null

printf 'test:s3cret\n' > "$WORK/users.txt"
chmod 600 "$WORK/users.txt"

echo "== start iwan-server =="
# a leftover server from an aborted run would share port 16001 via
# SO_REUSEPORT and answer OPENs with a stale session table — the client
# then gets a session whose data plane is dead (instant connect refused
# / benchmark traffic silently bypassing the tunnel). Make sure only our
# instance is up.
pkill -f 'bin/iwan-server' 2>/dev/null || true
sleep 0.5
stdbuf -oL -eL ./bin/iwan-server --users "$WORK/users.txt" --port "$PORT" \
    --tun iwan-srv-it --server-ip "$SRV_IP" --subnet "$SUBNET" \
    --dns 114.114.114.114 --nat-if lo &
SERVER_PID=$!
for _ in $(seq 1 30); do
    ip addr show iwan-srv-it 2>/dev/null | grep -q "$SRV_IP" && break
    sleep 0.5
done
ip addr show iwan-srv-it 2>/dev/null | grep -q "$SRV_IP" || {
    echo "error: server TUN not ready" >&2
    exit 1
}
if ! iptables -C INPUT -i iwan-srv-it -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -i iwan-srv-it -j ACCEPT 2>/dev/null && \
        INPUT_RULE_SRV=1
fi

echo "== start bench server (sink + source) =="
stdbuf -oL -eL python3 tests/bench_server.py --bind "$SRV_IP" \
    --sink-port "$SINK_PORT" --source-port "$SOURCE_PORT" &
BENCH_PID=$!
sleep 0.5

bench() {   # $1=label  $2=socks-arg(empty=direct)  $3=netns-exec(empty=host)
    local dir
    for C in $CONNS_LIST; do
        for dir in up down; do
            if [ "$dir" = up ]; then
                local tgt="$SRV_IP:$SINK_PORT"
            else
                local tgt="$SRV_IP:$SOURCE_PORT"
            fi
            local socks_args=()
            [ -n "$2" ] && socks_args=(--socks "$2")
            echo "--- $1 dir=$dir conns=$C (${DURATION}s window) ---"
            # shellcheck disable=SC2086
            $3 python3 tests/bench_client.py --target "$tgt" \
                --conns "$C" --duration "$DURATION" --direction "$dir" \
                "${socks_args[@]}"
            if [ "$MINI" = 1 ]; then
                return
            fi
        done
    done
}

echo "== mode 1: socks =="
stdbuf -oL -eL env IWAN_FLOWDBG=1 ./bin/iwan-client socks --server 127.0.0.1 --port "$PORT" \
    --user test --pass s3cret --listen "127.0.0.1:$SOCKS_PORT" &
SOCKS_PID=$!
# wait for the listener (a transient slow OPEN used to race this and
# surface as an instant ECONNREFUSED on the first bench connection)
for _ in $(seq 1 40); do
    if ! kill -0 "$SOCKS_PID" 2>/dev/null; then
        echo "error: socks client exited" >&2
        exit 1
    fi
    if ss -tln 2>/dev/null | grep -q ":$SOCKS_PORT "; then
        break
    fi
    sleep 0.25
done
kill -0 "$SOCKS_PID" 2>/dev/null || {
    echo "error: socks client exited" >&2
    exit 1
}
bench "socks" "127.0.0.1:$SOCKS_PORT" ""
kill "$SOCKS_PID" 2>/dev/null; wait "$SOCKS_PID" 2>/dev/null || true
SOCKS_PID=""

echo "== mode 2: TUN (netns) =="
ip netns add "$TUN_NS"
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$TUN_NS"
ip addr add "$VETH_IP/24" dev veth0
ip link set veth0 up
ip netns exec "$TUN_NS" ip addr add 172.31.199.2/24 dev veth1
ip netns exec "$TUN_NS" ip link set veth1 up
ip netns exec "$TUN_NS" ip link set lo up
ip netns exec "$TUN_NS" ip route add default via "$VETH_IP"
iptables -I INPUT -i veth0 -j ACCEPT 2>/dev/null && INPUT_RULE_VETH=1

ip netns exec "$TUN_NS" stdbuf -oL -eL ./bin/iwan-client proxy \
    --server "$VETH_IP" --port "$PORT" --user test --pass s3cret \
    --tun "$TUN_NAME" --proxy-cidr "$SUBNET" &
PROXY_PID=$!
# wait for the tunnel route: the proxy's auth can transiently lag (the
# listener/route appear only after OPEN_ACK), and a bench started before
# that would bypass the tunnel through the veth and report loopback
# speeds (measured: 55-211 Gbit/s garbage).
for _ in $(seq 1 40); do
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "error: proxy client exited" >&2
        exit 1
    fi
    if ip netns exec "$TUN_NS" ip route show 2>/dev/null | \
        grep -q "$SUBNET"; then
        break
    fi
    sleep 0.25
done
if ! ip netns exec "$TUN_NS" ip route show 2>/dev/null | \
    grep -q "$SUBNET"; then
    echo "error: tunnel route not established" >&2
    exit 1
fi
bench "tun" "" "ip netns exec $TUN_NS"

echo "BENCH DONE"
