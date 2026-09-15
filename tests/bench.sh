#!/usr/bin/env bash
# iWAN throughput benchmark: client -> server TCP upload AND download
# through both client modes (socks, TUN), at 1/2/4/8 connections, each
# measured over a FIXED send window (DURATION, default 5s). Reports the
# aggregate throughput from the actual bytes transferred.
#
# Requires root (TUN devices). Run with sudo:
#     sudo ./tests/bench.sh
#     DURATION=10 CONNS="1 2 4 8" sudo ./tests/bench.sh
# The optional [debug] argument (and any exported IWAN_DEBUG/IWAN_PROFILE/
# IWAN_PUMP_PROF) needs a -DIWAN_DEBUG_STRIP=OFF build; the script refuses
# to run and prints the reconfigure command otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."

# optional positional args: [THREADS] [debug] [mini]
# "debug" needs a build that still parses IWAN_DEBUG: configure with
# -DIWAN_DEBUG_STRIP=OFF (a Release build keeps the optimization but must
# not strip the diagnostics) — see the self-check below.
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

# --- L20 build-type self-check --------------------------------------
# IWAN_DEBUG / IWAN_PUMP_PROF / IWAN_PROFILE are not compiled into a
# build configured with IWAN_DEBUG_STRIP=ON, and CMakeLists.txt:48-58
# defaults that option to ON for EVERY non-Debug build type (Release
# included). Benchmarks that request those switches would then silently
# report empty [prof] / per-second output; refuse to run instead.
#
# R37 R5 WG-D (R4-L2): "non-empty" is NOT "diagnostics requested". An
# explicit off-spelling (the user turning the switch OFF) must not trip
# the abort below — that turned a legal benchmark into a hard failure
# with a misleading "this build cannot emit the diagnostics" message.
# The list must match the parsers:
#   IWAN_DEBUG   -> env_bool("IWAN_DEBUG", false)   src/common/util.c:75,
#                   called by debug_enabled() (util.c:69-79)
#   IWAN_PROFILE -> env_bool("IWAN_PROFILE", false) src/common/profile.c:18
#   env_bool() itself (src/common/util.c:51-65, R37 R5 R3-L17): unset or
#   exactly "" takes the caller's default (false here); the exact tokens
#   0/false/no/off, case-INSENSITIVELY, are OFF; EVERY other non-empty value
#   ("1", "0x", "0 ", $'0\n', $'\n') is ON. Nothing is trimmed, so a value
#   that merely contains/extends an off spelling ("offline", "no way") is
#   NOT off. Both diag variables go through that one helper, so one
#   predicate mirrors both.
#
# R37 R6 WG4 (R6-6): the predicate must not let the shell rewrite the
# value. The previous form piped it through $(printf | tr), and a command
# substitution strips TRAILING NEWLINES — "IWAN_DEBUG=$'0\n'" (the classic
# `export IWAN_DEBUG=$(cat file)` / backtick case) arrived at the case
# statement as "0" and was judged OFF, while env_bool() saw "0\n" and
# stayed ON. The guard then let a stripped build through and the run
# produced a silently EMPTY [prof] — exactly what this self-check exists to
# prevent. A pure `case` on the raw value (off spellings written as
# explicit case-insensitive globs) has neither the newline-eating
# substitution nor the external `tr`, whose absence under a minimal PATH
# made the old predicate fail OPEN for every value.
diag_on() {   # true when the value requests diagnostics
    case "$1" in
        "" | 0 | [Ff][Aa][Ll][Ss][Ee] | [Nn][Oo] | [Oo][Ff][Ff]) return 1 ;;
        *) return 0 ;;
    esac
}
DIAG_WANTED=0
if [ "${2:-}" = "debug" ]; then
    DIAG_WANTED=1
fi
# IWAN_PUMP_PROF is deliberately NOT in that predicate: proxy.c:65 (the
# one-shot gate in pump_prof_gate_init(), :61-70) and proxy.c:85 (the
# printout gate) only test getenv("IWAN_PUMP_PROF") != NULL, so SET AT ALL
# — "" and "0" included — switches the pump profiler on; only the unset
# variable leaves it off. Hence the existence test `${IWAN_PUMP_PROF+x}`
# (safe under `set -u`), NOT `${IWAN_PUMP_PROF:-}`, which folds the empty
# string into "unset" and under-reports by exactly one cell.
if diag_on "${IWAN_DEBUG:-}" || diag_on "${IWAN_PROFILE:-}" || \
   [ -n "${IWAN_PUMP_PROF+x}" ]; then
    DIAG_WANTED=1
fi
diag_build_check() {
    [ "$DIAG_WANTED" = 1 ] || return 0
    local strip=unknown
    if [ -f build/CMakeCache.txt ]; then
        strip=$(sed -n 's/^IWAN_DEBUG_STRIP:BOOL=//p' build/CMakeCache.txt)
    fi
    case "$strip" in
        OFF) return 0 ;;
        unknown) return 0 ;;   # not configured yet; the post-build call rechecks
    esac
    cat >&2 <<'EOF'
error: this build cannot emit the diagnostics this benchmark requested.
  IWAN_DEBUG / IWAN_PUMP_PROF / IWAN_PROFILE are only parsed when the
  build was configured with -DIWAN_DEBUG_STRIP=OFF (CMakeLists.txt makes
  the default ON for every non-Debug build type, Release included).
  Continuing would produce silently EMPTY [prof]/per-second output.
  Fix:  cmake -B build -DCMAKE_BUILD_TYPE=Release -DIWAN_DEBUG_STRIP=OFF
        cmake --build build -j"$(nproc)"
EOF
    exit 1
}
diag_build_check

if [ "$(id -u)" != 0 ]; then
    echo "error: bench needs root (TUN devices); run with sudo" >&2
    exit 1
fi

PORT=16001            # VPN UDP port
SOCKS_PORT=${SOCKS_PORT:-18083}   # local SOCKS5 listener (18080 is the user's supervised proxy)
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
diag_build_check   # authoritative re-check: build/ is configured now

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
# a leftover bench server from an aborted run would hold the ports forever;
# the new instance then dies on bind and a READY-looking poll would watch
# the stale sockets — the benchmark would silently hit the old instance
# (R30-B1-F2). Same upfront pkill as bench_multi.sh:176.
pkill -f 'bench_server.py' 2>/dev/null || true
sleep 0.3
stdbuf -oL -eL python3 tests/bench_server.py --bind "$SRV_IP" \
    --sink-port "$SINK_PORT" --source-port "$SOURCE_PORT" &
BENCH_PID=$!
# R30-B1-F2: wait for BOTH listeners before the first bench connection.
# A fixed sleep raced a slow startup and — worse — with a stale instance
# already holding the ports the new server dies on bind while the stale
# one keeps listening, so the bench silently hit the OLD instance; ss
# alone cannot tell (the port IS listening). kill -0 catches the dead
# new instance, ss catches the slow-bind case. Same ss-poll shape as
# bench_multi.sh:296-307 / bench.sh socks poll below.
for _ in $(seq 1 40); do
    if ! kill -0 "$BENCH_PID" 2>/dev/null; then
        echo "error: bench server exited" >&2
        exit 1
    fi
    if ss -tln 2>/dev/null | grep -q ":$SINK_PORT " && \
       ss -tln 2>/dev/null | grep -q ":$SOURCE_PORT "; then
        break
    fi
    sleep 0.25
done
kill -0 "$BENCH_PID" 2>/dev/null || {
    echo "error: bench server exited" >&2
    exit 1
}
if ! ss -tln 2>/dev/null | grep -q ":$SINK_PORT " || \
   ! ss -tln 2>/dev/null | grep -q ":$SOURCE_PORT "; then
    echo "error: bench server (ports $SINK_PORT/$SOURCE_PORT) not listening after 10s" >&2
    ss -tln 2>/dev/null | head -20 >&2
    exit 1
fi

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
