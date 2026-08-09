#!/usr/bin/env bash
# iWAN integration test: builds the real client and server binaries, then
# exercises the data plane end to end in BOTH client modes — socks and
# TUN — with 4 concurrent TCP echo connections each.
#
# Requires root (TUN devices on both sides). Run with sudo:
#     sudo ./tests/integration.sh
#
# Topology (single host):
#   host    : iwan-server (tun0 198.18.0.1/16) + echo server on 198.18.0.1
#   mode 1  : iwan-client socks on 127.0.0.1 -> 4 echo conns via SOCKS5
#   mode 2  : iwan-client proxy inside netns $TUN_NS (client tun lives in
#             the netns, so the host kernel cannot short-circuit the
#             downlink via the local table) -> 4 direct echo conns
set -euo pipefail

cd "$(dirname "$0")/.."          # repo root

if [ "$(id -u)" != 0 ]; then
    echo "error: integration test needs root (TUN devices); run with sudo" >&2
    exit 1
fi

PORT=16001            # VPN UDP port
ECHO_PORT=17000       # echo server TCP port
SOCKS_PORT=18080      # local SOCKS5 listener (17080 collides with a
                      # pre-existing service on some hosts)
# Test subnet: 100.64.0.0/16 (CGNAT) instead of the production
# 198.18.0.0/16 — a pre-existing iWAN setup on the host may already own
# 198.18.0.1/16, which breaks the downlink routing assumptions.
SRV_IP=100.64.0.1
SUBNET=100.64.0.0/16
# streaming throughput phase, MiB per connection (0 disables; the small
# echo rounds are RTT-bound ping-pong and say nothing about bandwidth)
BULK_MB=${BULK_MB:-8}
# IWAN_TEST_DEBUG=1: run with IWAN_DEBUG/IWAN_RETX, tee everything to
# /tmp/iwan-test-debug.log, and on failure print a filtered diagnostic
# tail (flow/retx/drop lines + kernel UDP drop counters)
DIAG=${IWAN_TEST_DEBUG:-0}
if [ "$DIAG" = 1 ]; then
    export IWAN_DEBUG=1 IWAN_RETX=1 IWAN_RXDBG=1 IWAN_FLOWDBG=1
    DIAG_LOG=/tmp/iwan-test-debug.log
    exec > >(tee "$DIAG_LOG") 2>&1
fi
TUN_NS=iwanns
TUN_NAME=iwantun0
WORK=$(mktemp -d)

SERVER_PID=""
SOCKS_PID=""
PROXY_PID=""
ECHO_PID=""
INPUT_RULE_SRV=0    # -i iwan-srv-it ACCEPT added by us
INPUT_RULE_VETH=0   # -i veth0 ACCEPT added by us

cleanup() {
    set +e
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$SOCKS_PID" ] && kill "$SOCKS_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
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
    if [ "$DIAG" = 1 ] && [ "${1:-}" != "0" ]; then
        echo "===== diagnostic: flow lifecycle (count) ====="
        grep -ac 'flow .* closed' "$DIAG_LOG" 2>/dev/null | \
            xargs echo "flow-closed lines:"
        echo "===== diagnostic: server uplink stats / drops ====="
        grep -aE 'uplink:|udp send dropped|RcvbufErrors|SndbufErrors' \
            "$DIAG_LOG" /proc/net/snmp 2>/dev/null | tail -20
        echo "===== diagnostic: errors / aborts / resets ====="
        grep -avE 'flow .* closed' "$DIAG_LOG" 2>/dev/null | \
            grep -aE 'retx|RETX|abort|reset|RST|CLOSE|timed out|drop|err|NSSEND|TCP connect failed' \
            | tail -40
        echo "===== diagnostic: segment trace (last 40 RXDBG/NSSEND/RETX) ====="
        grep -aE 'RXDBG|NSSEND|NS RETX|seal' "$DIAG_LOG" 2>/dev/null | tail -40
        echo "===== diagnostic: raw tail (last 25 lines) ====="
        tail -25 "$DIAG_LOG" 2>/dev/null
    fi
}
trap 'cleanup $?' EXIT

echo "== build =="
make -B

printf 'test:s3cret\n' > "$WORK/users.txt"
chmod 600 "$WORK/users.txt"

echo "== start iwan-server =="
./bin/iwan-server --users "$WORK/users.txt" --port "$PORT" \
    --tun iwan-srv-it --server-ip "$SRV_IP" --subnet "$SUBNET" \
    --dns 114.114.114.114 --nat-if lo &
SERVER_PID=$!
# wait until the server's TUN carries the gateway address (its setup
# includes ip link/addr/up + optional iptables, then fork+drop)
for _ in $(seq 1 30); do
    ip addr show iwan-srv-it 2>/dev/null | grep -q "$SRV_IP" && break
    sleep 0.5
done
ip addr show iwan-srv-it 2>/dev/null | grep -q "$SRV_IP" || {
    echo "error: server TUN not ready" >&2
    exit 1
}
# the host's INPUT policy (UFW etc.) must accept the server's tun or the
# inner TCP handshakes get firewalled (README documents this rule)
if iptables -C INPUT -i iwan-srv-it -j ACCEPT 2>/dev/null; then
    INPUT_RULE_SRV=0   # already present: not ours to remove
else
    iptables -I INPUT -i iwan-srv-it -j ACCEPT 2>/dev/null && \
        INPUT_RULE_SRV=1
fi

echo "== start echo server on the tunnel gateway =="
python3 tests/echo_server.py --bind "$SRV_IP" --port "$ECHO_PORT" &
ECHO_PID=$!
sleep 0.5

echo "== mode 1: socks client, 4 TCP echo connections =="
./bin/iwan-client socks --server 127.0.0.1 --port "$PORT" \
    --user test --pass s3cret --listen "127.0.0.1:$SOCKS_PORT" &
SOCKS_PID=$!
sleep 1.5
if ! kill -0 "$SOCKS_PID" 2>/dev/null; then
    echo "error: socks client exited (listener port $SOCKS_PORT busy?)" >&2
    exit 1
fi
python3 tests/echo_client.py --target "$SRV_IP:$ECHO_PORT" \
    --socks "127.0.0.1:$SOCKS_PORT" --conns 4 --bulk-mb "$BULK_MB"
kill "$SOCKS_PID" 2>/dev/null
wait "$SOCKS_PID" 2>/dev/null || true
SOCKS_PID=""
echo "socks mode: PASS"

echo "== mode 2: TUN client in netns, 4 TCP echo connections =="
VETH_IP=172.31.199.1
ip netns add "$TUN_NS"
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$TUN_NS"
ip addr add "$VETH_IP/24" dev veth0
ip link set veth0 up
ip netns exec "$TUN_NS" ip addr add 172.31.199.2/24 dev veth1
ip netns exec "$TUN_NS" ip link set veth1 up
ip netns exec "$TUN_NS" ip link set lo up
ip netns exec "$TUN_NS" ip route add default via "$VETH_IP"
# the host INPUT policy may firewall the netns's control UDP; accept it
# (rule removed in cleanup)
iptables -I INPUT -i veth0 -j ACCEPT 2>/dev/null && \
    INPUT_RULE_VETH=1
# connectivity self-check: splits "veth broken" from "UDP firewalled".
# Warn-only: ICMP may itself be firewalled, and the OPEN handshake below
# is the authoritative signal.
if ! ip netns exec "$TUN_NS" ping -c1 -W2 "$VETH_IP" >/dev/null 2>&1; then
    echo "warning: netns ping to host failed (veth or ICMP firewall?)"
fi

ip netns exec "$TUN_NS" ./bin/iwan-client proxy \
    --server "$VETH_IP" --port "$PORT" --user test --pass s3cret \
    --tun "$TUN_NAME" --proxy-cidr "$SUBNET" &
PROXY_PID=$!
sleep 2
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "error: proxy client exited" >&2
    exit 1
fi
ip netns exec "$TUN_NS" python3 tests/echo_client.py \
    --target "$SRV_IP:$ECHO_PORT" --conns 4 --bulk-mb "$BULK_MB"
kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
echo "TUN mode: PASS"

echo "ALL TESTS PASSED"
