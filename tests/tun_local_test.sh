#!/usr/bin/env bash
# Root-required loopback TUN test: iwan-server (real TUN device) +
# iwan-client proxy on ONE machine, no real internet / no external routes.
#
# Topology (everything stays on the box):
#   client iwan0  (198.18.0.2/24 + fd00::c612:2/96)
#       |  inner IPv4: 198.18.0.2 -> 198.18.0.1 (server TUN IP, local)
#       |  inner IPv6: fd00::c612:2 -> fd00::c612:1 (server TUN ULA, local)
#       |  inner IPv6: fd00::c612:2 -> 2001:db8::1 (off-link target; the
#       |               server delivers it locally via an address on lo)
#       v
#   iwan-server TUN iwan-srv (198.18.0.1/16 + fd00::c612:1/96)
#
# The inner packets are terminated by TCP echo listeners on the server
# machine itself (tests/echo_server.py), so the data path is
# client-kernel -> iwan0 -> tunnel -> server kernel -> listener -> back.
# No packet ever leaves the machine; --nat-if lo keeps the MASQUERADE
# rule inert.
#
# Usage:
#   sudo ./tests/tun_local_test.sh
#
# Prints PASS/FAIL per assertion; exits non-zero on the first failure.
# On Ctrl-C / failure, tears down both TUNs and the routes.

set -euo pipefail

PORT=16061
LISTEN_PORT=17777
SRV_TUN=iwan-srv
CLI_TUN=iwan0
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

cleanup() {
    set +e
    [ -n "${CLI:-}" ] && kill -INT "$CLI" 2>/dev/null && wait "$CLI" 2>/dev/null
    [ -n "${SRV:-}" ] && kill -INT "$SRV" 2>/dev/null && wait "$SRV" 2>/dev/null
    [ -n "${E4:-}" ] && kill "$E4" 2>/dev/null
    [ -n "${E6:-}" ] && kill "$E6" 2>/dev/null
    [ -n "${E6B:-}" ] && kill "$E6B" 2>/dev/null
    ip -6 addr del 2001:db8::1/128 dev lo 2>/dev/null
    ip link del "$SRV_TUN" 2>/dev/null
    ip link del "$CLI_TUN" 2>/dev/null
    set -e
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0"; exit 1; }

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin"
USERS=/tmp/iwan-tun-users.txt
printf 'alice:s3cret-pass\n' > "$USERS"
chmod 600 "$USERS"

# ---- server: real TUN device -----------------------------------------
# stdbuf -oL: "server ready." is a bare printf; without line buffering it
# stays in the stdout block buffer until exit when redirected to a file.
stdbuf -oL "$BIN/iwan-server" --users "$USERS" --port "$PORT" \
    --tun "$SRV_TUN" --server-ip 198.18.0.1 --subnet 198.18.0.0/16 \
    --nat-if lo > /tmp/iwan-tun-srv.log 2>&1 &
SRV=$!
for _ in $(seq 1 50); do
    grep -q "server ready" /tmp/iwan-tun-srv.log && break
    sleep 0.2
done
grep -q "server ready" /tmp/iwan-tun-srv.log \
    && ok "server up with TUN $SRV_TUN" \
    || { bad "server failed to start"; tail -5 /tmp/iwan-tun-srv.log; exit 1; }

ip addr show dev "$SRV_TUN" | grep -q "198.18.0.1" && ok "server TUN has 198.18.0.1" \
    || bad "server TUN missing IPv4"

HAS_V6=1
if ip -6 addr show dev "$SRV_TUN" 2>/dev/null | grep -q "fd00::c612:1"; then
    ok "server TUN has fd00::c612:1/96 (derived ULA)"
else
    HAS_V6=0
    echo "NOTE: no IPv6 on $SRV_TUN; skipping IPv6 sub-tests"
fi

# ---- echo listeners on the server machine ----------------------------
"$BIN/../tests/echo_server.py" --bind 198.18.0.1 --port "$LISTEN_PORT" \
    > /tmp/iwan-tun-e4.log 2>&1 &
E4=$!
if [ "$HAS_V6" = 1 ]; then
    "$BIN/../tests/echo_server.py" --bind fd00::c612:1 --port "$LISTEN_PORT" \
        > /tmp/iwan-tun-e6.log 2>&1 &
    E6=$!
    # off-link target: make the server deliver it locally
    if ip -6 addr add 2001:db8::1/128 dev lo 2>/dev/null; then
        "$BIN/../tests/echo_server.py" --bind 2001:db8::1 --port "$LISTEN_PORT" \
            > /tmp/iwan-tun-e6b.log 2>&1 &
        E6B=$!
    else
        echo "NOTE: cannot add 2001:db8::1 on lo; skipping off-link sub-test"
    fi
fi
sleep 0.5

# ---- client: TUN proxy with v4 + v6 policy routes --------------------
"$BIN/iwan-client" proxy --server 127.0.0.1 --port "$PORT" \
    --user alice --pass 's3cret-pass' --tun "$CLI_TUN" \
    --proxy-ip 198.18.0.1 --proxy-cidr6 2001:db8::1 \
    > /tmp/iwan-tun-cli.log 2>&1 &
CLI=$!
for _ in $(seq 1 50); do
    grep -q "TUN proxy running" /tmp/iwan-tun-cli.log && break
    sleep 0.2
done
if grep -q "TUN proxy running" /tmp/iwan-tun-cli.log; then
    ok "client tunnel up on $CLI_TUN"
else
    bad "client failed to start"; tail -8 /tmp/iwan-tun-cli.log
    exit 1
fi

ip route show dev "$CLI_TUN" | grep -q "198.18.0.1" \
    && ok "route 198.18.0.1/32 -> iwan0" \
    || bad "missing v4 route"
if [ "$HAS_V6" = 1 ]; then
    ip -6 route show dev "$CLI_TUN" | grep -q "2001:db8::1" \
        && ok "route6 2001:db8::1/128 -> iwan0" \
        || bad "missing v6 route"
    ip -6 addr show dev "$CLI_TUN" 2>/dev/null | grep -q "fd00::c612:2" \
        && ok "client TUN has fd00::c612:2/96" \
        || bad "client TUN missing ULA"
fi

# ---- data path: byte-exact echo through the tunnel --------------------
echo_t() { # echo_t <addr> <family> <tag>
    local out
    out=$(python3 - "$1" <<'PYEOF'
import socket, sys
addr = sys.argv[1]
fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
s = socket.create_connection((addr, 17777), timeout=8)
s.sendall(b"tun-local-hello")
data = s.recv(64)
s.close()
print(data.decode(errors="replace"))
PYEOF
)
    [ "$out" = "tun-local-hello" ]
}

if echo_t 198.18.0.1 v4; then
    ok "IPv4 echo via tunnel (198.18.0.2 -> 198.18.0.1)"
else
    bad "IPv4 echo failed"; tail -5 /tmp/iwan-tun-cli.log
fi
if [ "$HAS_V6" = 1 ]; then
    if echo_t fd00::c612:1 v6; then
        ok "IPv6 echo via tunnel (fd00::c612:2 -> fd00::c612:1)"
    else
        bad "IPv6 ULA echo failed"
    fi
    if ip -6 addr show dev lo 2>/dev/null | grep -q "2001:db8::1"; then
        if echo_t 2001:db8::1 v6; then
            ok "IPv6 off-link echo via tunnel (--proxy-cidr6 2001:db8::1)"
        else
            bad "IPv6 off-link echo failed"
        fi
    fi
fi

# ---- teardown: routes and TUNs must be removed ------------------------
kill -INT "$CLI" 2>/dev/null || true
for _ in $(seq 1 30); do
    kill -0 "$CLI" 2>/dev/null || break
    sleep 0.2
done
CLI=""
if ip route show | grep -q "dev $CLI_TUN"; then
    bad "client v4 routes not torn down"
else
    ok "client v4 routes torn down"
fi
if [ "$HAS_V6" = 1 ] && ip -6 route show | grep -q "dev $CLI_TUN"; then
    bad "client v6 routes not torn down"
elif [ "$HAS_V6" = 1 ]; then
    ok "client v6 routes torn down"
fi
ip link show "$CLI_TUN" >/dev/null 2>&1 && bad "$CLI_TUN still exists" \
    || ok "client TUN removed"

kill -INT "$SRV" 2>/dev/null || true
for _ in $(seq 1 30); do
    kill -0 "$SRV" 2>/dev/null || break
    sleep 0.2
done
SRV=""
ip link show "$SRV_TUN" >/dev/null 2>&1 && bad "$SRV_TUN still exists" \
    || ok "server TUN removed"

echo "----"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
