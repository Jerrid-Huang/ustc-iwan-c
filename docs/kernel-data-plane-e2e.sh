#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN client kernel data plane (--data-plane kernel) end-to-end acceptance -- needs root
#
#   sudo bash docs/kernel-data-plane-e2e.sh [--keep] [--extra] [--bind] [--life]
#
# --bind appends group B: the three carrier-NIC bind modes run over a **real NIC** (genetlink SESSION_UP carries
#   IWAN_A_OIF / IWAN_A_IP); the checkpoints complement tests/vm_bind.sh (the /proc fallback path)
#   -- what runs here is the control-plane entry point the client actually uses:
#   B1 --bind-ip <local outer address>   => resolved from the address table and pinned to veth-c at session setup,
#      inner TCP echo still round-trips (traffic really flows on the bound NIC);
#   B2 --bind-dev <local NIC>      => both oif and carrier are it;
#   B3 --bind-ip <non-local address>     => rejected at startup (userspace blocks it first);
#   B4 --bind-dev lo --bind-ip <local address> => rejected (the address is not on the given NIC);
#   B5 --bind-* together with the TUN data plane => rejected (no "silently ignored" option).
#
# --life appends group L: failure and recovery **with a real server** (the earlier groups only cover "set up -> run stable
#   -> clean shutdown"; this group is the actual measurement of the 1-second tick and the reconnect loop):
#   L1 --bind-dev: take the bound NIC down => the client reports "bind invalid" within the tick and closes the kernel
#      part (SESSION_DOWN: sid goes to 0, iwan0 is deleted => routes via iwan0 stop working,
#       inner traffic falls to the next route-table entry); NIC up => after the bind recovers, **re-handshake**,
#       inner TCP recovers;
#   L2 --bind-ip: delete the bound egress IP => disabled as above; add the address back => re-handshake, and
#       inner TCP recovers;
#   L3 outer link down (no binding involved) => death can only come from the "unanswered" budget (keepalive
#       sends fail every time) => link back => re-handshake, inner TCP recovers;
#   L4 server port blackhole (receive only, never reply: every send succeeds, no frame comes back) => the failure budget
#       never grows, so death can only come from the IWAN_RX_STALE_MS watchdog (the case sets 30s) => assert
#       "the watchdog declared death" and "no keepalive failure" => the two mechanisms are tested separately;
#   L5 TUN data plane (explicit --data-plane tun), same scenario (server disappears) => death comes from the receive-side
#       hard-error count of the same budget; server back => reconnect, inner TCP recovers.
#
#   Semantics of the two death mechanisms (corrected after the 2026-10-10 measurement, see src/common/proxy.h): the budget
#   counts "unanswered transport failures" and is **cleared only by a valid frame that passed the gate** (a successful send does not
#   count -- a connected UDP socket reports the ICMP error only every other time, so the send in between succeeds); the watchdog
#   is the outer fallback, covering the blackhole case of "receives fine but never answers".
#
# Division of labour with kernel/tests/netlink_test.sh: that one only checks the module's own control plane; this one checks
# the **real client** (iwan-client --data-plane kernel) and the **real server** (iwan-server,
# userspace TUN forwarding) interoperating on the kernel data plane -- in the client netns iwan-client itself does
# SESSION_UP, the module creates iwan0 and hands downlink frames to it; the server netns has **no** netlink
# session, so the module takes the "no-session fallback" (the behaviour before the control plane was introduced), which is why iwan-server's
# userspace UDP socket works normally.
#
# Topology (veth as the cable for the outer layer; a real outer 5-tuple is never installed in the init netns):
#
#   iwc: veth-c 10.100.0.1/24   iwan0 = created on demand by the module, mtu 1400,
#                               address = the tun ip in the OPEN_ACK reply (198.18.0.x/24)
#   iws: veth-s 10.100.0.2/24   iwan-srv = iwan-server's own TUN (198.18.0.1/16)
#
#   iwc inner TCP 198.18.0.x -> 198.18.0.1:19099 (python3 echo inside iws)
#   outer     10.100.0.1:<random> -> 10.100.0.2:16200
#
# Cases and their **expected output** (all print PASS/FAIL; exit code = number of FAILs):
#
#   C1  /dev/iwan exists after module load; neither side has iwan0 (configuration can only come via netlink)
#   C2  iwan-server starts: log shows "server ready.", iwan-srv is a tun device
#   C3  client starts: log shows "kernel data plane: session established dev=iwan0 mtu=1400",
#       followed by "kernel data plane running (dev iwan0)"
#   C4  iwc's iwan0: kind=iwan, state UP, mtu=1400, address == the ip from the server's reply
#   C5  iws has no iwan0 (the server has no kernel session, only its own iwan-srv)
#   C6  inner TCP echo (iwc -> iws 198.18.0.1:19099) echoes back identical
#   C7  /dev/iwan dump: version=1, enabled=1, last_rx_ms non-zero (a peer frame has been received)
#   C8  iwan_ctl get-stats: sid/tok match the client log, rx_frames grows (inner packets
#       really go through the kernel data plane)
#   C9  Ctrl-C exit: client rc=0, and it prints "kernel data plane stopped (user stop)"
#   C10 after exit iwan0 is deleted, get-stats session zeroed (sid=0 tok=0), and the default route and
#       the iwc route table have no leftovers (no --proxy-cidr, so the default route must not be touched);
#       C10e: server log shows "[peer] session 0x.... closed" -- PT_CLOSE really crossed the wire
#
#   --extra (optional, separate, for easier diagnosis):
#   E1  iwan0 occupied by another device (dummy): the client must report
#       "already exists, but it is not a device created by the iwan kernel module" and exit non-zero; dummy untouched
#   E2  SIGKILL leftovers (known regression): device/session still there; clean up with iwan_ctl session-down
#   E3  iwan0 deleted externally: the client reports "device iwan0 deleted externally" within 2s and recreates it
#
#   --plane (optional): default data plane + fallback + the pre-handshake rejection of "this netns already has a kernel session/device taken"
#   P1  no --data-plane (default auto): log "data plane: default kernel", really uses the kernel plane,
#       iwan0 is created by the module, inner echo works
#   P2  kernel plane unavailable (iwan0 taken by dummy) => automatic fallback to TUN (--tun iwan9): the kernel-plane
#       reason is reported, the fallback log appears, the TUN plane comes up, inner echo still works
#   P3  both planes unavailable (iwan0 taken by dummy and no replacement device name given) => non-zero exit; the log has both
#       "falling back to the TUN data plane" and the TUN name-rejected text (no longer the misleading
#       "must be root"), and finally "TUN data plane also unavailable, exiting"
#   P4  when this netns already has a live session, the second client (no data plane given) is rejected **before the handshake**:
#       log has "this netns already has a kernel session/device taken" and no "session established" (proof it never handshook),
#       and states "not falling back to TUN"; the first session's sid is unchanged and echo still works
#   P6  outer IPv6 (slice 2): the client picks the outer family automatically from the --server **literal's address family**,
#       the server listens on v4/v6 on the same port at the same time:
#       P6a the kernel plane builds a session with --server [v6]; P6b the log declares the outer v6 endpoint;
#       P6c the server log has a v6 listen line; P6d the kernel really has the session;
#       P6e inner v4 really round-trips over outer v6 (cross-version -> netif_rx re-injection);
#       P6f/P6g inner v6 really round-trips over outer v6 (same version -> in-place delivery);
#       P6h/P6i inner MTU + v6 encapsulation exceeding the carrier MTU is rejected (outer v6 does not fragment);
#       P6j giving both v4/v6 address pairs at once is rejected; P6k a bound egress v6 IP that is not local is rejected;
#       P6l the three rejected cases leave no leftovers. If the host has no usable IPv6 the whole group explicitly says "skipped".
#       (addresses/prefixes are in place at C0 and do not overlap P5's --proxy-cidr6 or the derived ULA)
#   P5  inner IPv6 (--proxy-cidr6) really works on both data planes (since slice 1 the kernel module also
#       decapsulates inner v6 per version; v6 in v4 goes through netif_rx re-injection):
#       P5a/P5b auto + --proxy-cidr6 is still the kernel plane (the default choice is no longer changed by the v6 need);
#       P5c the kernel plane installs the --proxy-cidr6 IPv6 route; P5d iwan0 has the session-derived ULA
#       (fd00::/96 + inner IPv4, ip6_derive_ula in protocol.h); P5e inner IPv6
#       TCP echo **round-trips identically** through the kernel plane (the core assertion of this round, not "the route is installed");
#       P5f inner IPv4 still works in the same session (dual stack coexists); P5g the v6 route is rolled back after exit;
#       P5h/P5h2/P5i explicit --data-plane kernel + v6 builds a session normally and v6 echo works
#       (the slice-0 usage-error rejection has flipped); P5j/P5j2/P5k NIC binding (forces the kernel plane)
#       coexists with v6 and v6 echo works (the slice-0 mutual exclusion has flipped); P5l/P5l2/P5l3 the TUN plane
#       still installs/removes the IPv6 route as before (regression). Setting the reserved FLAGS bit1 must be rejected by the module --
#       the same parameters without it build a session (P5m/P5m2), with it it must fail and leave no leftovers (P5n/P5o),
#       the only difference being that one bit
#
# Note: every process the script starts/stops is anchored by "--port $PORT" (this script's dedicated port and netns names),
# with one pkill fallback at the start and one at exit cleanup; the user's own tunnels are on other ports and are not affected.
# Needs root: module + netns + veth + TUN. Running as non-root exits 1 immediately.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
KO="$ROOT/kernel/iwan.ko"
BIN="$ROOT/bin"
NS_C=iwc-kdp
NS_S=iws-kdp
# Third netns and "non-carrier NIC" used by the reply-route groups (R1/R2). Must be at top level:
# cleanup() is an EXIT trap and the script runs set -u, so NS_L must already be bound even when that group never runs.
NS_L=iwl-kdp
VETH_LC=veth-rr-c
VETH_LL=veth-rr-l
RR_CIDR=203.0.113.0/24
RR_SERVED=203.0.113.1
RR_PEER=203.0.113.9
RR_PORT=19101
RR_PORT2=19102
RR_INNER=198.18.0.2
RR_MARK=0x1
RR_TABLE=100
VETH_C=veth-kdp-c
VETH_S=veth-kdp-s
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
# Outer IPv6 (slice 2): v6 addresses added on the same veth pair. The prefix deliberately does
# not overlap the --proxy-cidr6 (2001:db8:beef::/48) used by P5 or the derived ULA (fd00::/96) --
# the outer route must never be overridden by a route the tunnel itself hijacks.
OUTER6_C=2001:db8:1ce::1
OUTER6_S=2001:db8:1ce::2
PORT="${PORT:-16200}"
ECHO_PORT=19099
USERS=/tmp/iwan-kdp-e2e-users.txt
LOG_C=/tmp/iwan-kdp-e2e-client.log
LOG_S=/tmp/iwan-kdp-e2e-server.log
WORK=""

KEEP=0
EXTRA=0
BIND=0
LIFE=0
PLANE=0
for a in "$@"; do
    case "$a" in
    --keep)  KEEP=1 ;;
    --extra) EXTRA=1 ;;
    --bind)  BIND=1 ;;
    --life)  LIFE=1 ;;
    --plane) PLANE=1 ;;
    *) echo "unknown argument: $a"; exit 2 ;;
    esac
done

PASS=0
FAIL=0
CLI=""
SRV=""
ECHO=""
# The reply-route group's two python listeners (served address / session inner address on NS_C)
RRLAN=""
RRTUN=""
# PID of the inner v6 echo listener (used by P5/P6): it must be defined before cleanup, otherwise the script
# failing **before it gets going** (e.g. iwan_ctl does not compile) makes cleanup report under set -u
# "ECHO6: unbound variable", drowning out the real failure cause.
ECHO6=""
LOADED_MODULE=0

say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
die()  { printf 'fatal: %s\n' "$*" >&2; exit 1; }

# Stop a background process with a time bound: SIGINT first, wait at most $2 seconds; SIGKILL if it does not exit. Returns the final exit code,
# 124 if it had to be killed on timeout. **The cleanup path must never wait forever** -- field lesson: the client does not exit after SIGINT
# (cause unknown), so the script's `wait` and the EXIT trap both hang and leave a full set of leftovers on the machine.
# Deciding "it exited" needs /proc state, not kill -0: between exiting and being reaped, kill -0 still succeeds.
# SIGINT first, then a time-limited SIGKILL. Two known details:
#   * a SIGINT sent before the target "installs its handler" is simply dropped (inherited SIG_IGN), showing up as
#     waiting the full t seconds for nothing, rc=124. Measured: send right after start = 124, send after 0.3s = 0. C9 signals the client
#     only after it has run for a few seconds, so it is outside the window.
#   * the target may be the grandchild resolved by the resolve_pid fallback (the shell-wrapped case); waiting on it
#     returns 127 (not a child) -- that is not an abnormal exit code, count it as 0 (see below).
stop_pid() {
    local p="$1" t="${2:-10}" i=0 st

    [ -n "$p" ] || return 0
    kill -INT "$p" 2>/dev/null
    while [ "$i" -lt $((t * 10)) ]; do
        st="$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$p/stat" 2>/dev/null)"
        if [ -z "$st" ] || [ "$st" = "Z" ]; then
            # Only your own child yields an exit code from wait. The resolve_pid fallback may resolve a grand-
            # child (the shell-wrapped case), and waiting on it returns 127 (not a child),
            # which is not an "abnormal exit code" -- the process really did exit on its own after SIGINT, record 0.
            local wrc
            wait "$p" 2>/dev/null
            wrc=$?
            [ "$wrc" = "127" ] && return 0
            return "$wrc"
        fi
        sleep 0.1
        i=$((i + 1))
    done
    kill -9 "$p" 2>/dev/null
    wait "$p" 2>/dev/null
    return 124
}

cleanup() {
    set +e
    stop_pid "$CLI" 10
    if [ -n "$ECHO" ]; then
        kill -9 "$ECHO" 2>/dev/null
        wait "$ECHO" 2>/dev/null   # reap it, so bash does not print a "Killed" line on the terminal
    fi
    if [ -n "$ECHO6" ]; then
        kill -9 "$ECHO6" 2>/dev/null
        wait "$ECHO6" 2>/dev/null
    fi
    # The two listeners the reply-route group starts itself: if not reaped they leave python processes in odd places
    for _rrp in "${RRLAN:-}" "${RRTUN:-}"; do
        [ -n "$_rrp" ] || continue
        kill -9 "$_rrp" 2>/dev/null
        wait "$_rrp" 2>/dev/null
    done
    stop_pid "$SRV" 10
    ip netns del "$NS_C" 2>/dev/null
    ip netns del "$NS_S" 2>/dev/null
    ip netns del "$NS_L" 2>/dev/null
    # Fallback: kill this script's own processes, all anchored by "--port $PORT" (beyond the TUN pump, no
    # other process uses this port; the user's own tunnels are on other ports and are not affected).
    pkill -9 -f "iwan-client proxy .*--port $PORT" 2>/dev/null || true
    pkill -9 -f "iwan-server .*--port $PORT" 2>/dev/null || true
    # Unload only the one **we insmodded ourselves** (the header states it: a module already loaded is left alone).
    # An unload failure is not swallowed -- leftover sessions/devices make the next insmod report EEXIST.
    if [ "$KEEP" = 1 ]; then
        printf '  KEEP=1: module iwan kept loaded\n'
    elif [ "$LOADED_MODULE" = 1 ]; then
        rmmod iwan 2>/dev/null \
            || printf '  warning: rmmod iwan failed (sessions/devices still holding it? run sudo iwan_ctl session-down first)\n'
    else
        printf '  module iwan was loaded before the script started: by convention it is not unloaded\n'
    fi
    [ -n "$WORK" ] && [ "$KEEP" = 0 ] && rm -rf "$WORK"
    set -e
}
trap cleanup EXIT

# Wait for a substring to appear in the log (at most $3 seconds)
wait_log() {
    local f="$1" pat="$2" t="${3:-20}" i=0

    while [ "$i" -lt $((t * 10)) ]; do
        grep -q -- "$pat" "$f" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# Wait for the $3-th occurrence of a substring in the log (default 2nd, at most $4 seconds). Recovery cases use the same
# text as the setup ("session established"), so only checking "it appeared" would take a pre-recovery old line as evidence for this round.
wait_log_n() {
    local f="$1" pat="$2" n="${3:-2}" t="${4:-20}" i=0

    while [ "$i" -lt $((t * 10)) ]; do
        [ "$(grep -c -- "$pat" "$f" 2>/dev/null)" -ge "$n" ] && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

nsx() { ip netns exec "$1" "${@:2}"; }

# Stop a client with a time bound: a client in the reconnect loop may be stuck in a handshake timeout, and a plain
# wait would hang the case (the first round measured two minutes of silence).
stop_cli() {
    local p="$1" i=0

    kill -INT "$p" 2>/dev/null
    while [ "$i" -lt 40 ]; do
        kill -0 "$p" 2>/dev/null || break
        sleep 0.25
        i=$((i + 1))
    done
    kill -9 "$p" 2>/dev/null
    wait "$p" 2>/dev/null
}

# Whether the module is loaded: read /proc/modules directly (does not rely on lsmod being in root's PATH).
module_loaded() { grep -q '^iwan ' /proc/modules 2>/dev/null; }

# Resolve the **real target process** PID of a background job. Two kinds of timing gap must be tolerated:
#   * exec timing gap: `ip netns exec` / `env` exec in place, so the PID does not change, but /proc/PID/comm
#     takes a while to become the target name -- asserting too early reports "it is wrapped" (hit once, a pure false report);
#   * shell wrapping: using `&` on a shell function forks a subshell, and by POSIX the subshell sets
#     SIGINT/SIGQUIT to ignore => signalling it is the same as not signalling, and `wait` keeps waiting for its child.
#     In that case the target process is its **child**, so use that directly.
# Field lesson: C9 once appeared dead for 20 minutes because the signal went to the wrapping subshell, and was briefly misdiagnosed as a client defect.
resolve_pid() {
    local p="$1" want="$2" i=0 got kid

    while [ "$i" -lt 40 ]; do
        got="$(cat "/proc/$p/comm" 2>/dev/null)"
        [ "$got" = "$want" ] && { printf '%s' "$p"; return 0; }
        kid="$(pgrep -P "$p" -x "$want" 2>/dev/null | head -n1)"
        [ -n "$kid" ] && { printf '%s' "$kid"; return 0; }
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

# Usage: <background command> & bg_resolve <variable name> <target process name>
# It reads $! inside the function, so call sites contain no $! -- one fewer "easy to forget, and silent when forgotten" step.
# Hit once: while editing the script a text replacement also deleted ECHO=$! / CLI=$!, resolve_pid got an empty string,
# spun all 40 rounds before reporting "PID resolution failed", wasting a whole round.
bg_resolve() {
    local __var="$1" __want="$2" __job __real

    __job="$!"
    [ -n "$__job" ] || die "bg_resolve $__var: no background job to take (\$! is empty)"
    if [ ! -e "/proc/$__job" ]; then
        # Exited instantly: the most common cause is a redirection that cannot be opened (log file owned by root / no permission). Do not just say "resolution failed".
        die "background $__want process $__job has exited (redirection or startup failed? check its log)"
    fi
    __real="$(resolve_pid "$__job" "$__want")" \
        || die "failed to resolve $__want process PID (job=$__job comm=$(cat "/proc/$__job/comm" 2>/dev/null))"
    printf -v "$__var" '%s' "$__real"
}

# Device kind: the leading token of the **first detail line that does not start with link/** in `ip -d link show dev X`.
# Do not take the second line: that is the ARPHRD rendering (link/ipip, link/none, link/ether), not the kind;
# kind has its own detail line (`iwan addrgenmode ...`, `tun type tap ...`, `veth addrgenmode ...`).
# Empty output when the device does not exist. Taking the wrong line causes false FAILs: the module's iwan0 reads as "link/ipip",
# a TUN reads as "link/none".
dev_kind() {
    nsx "$1" ip -d link show dev "$2" 2>/dev/null \
        | sed -n '2,$s/^[ \t]*\([^ \t]*\)[ \t].*/\1/p' \
        | grep -v '^link/' | head -n1
}

# Device flags (contents of <> on the first line): a DOWN device does not contain UP
dev_flags() {
    nsx "$1" ip -d link show dev "$2" 2>/dev/null | sed -n '1{s/.*<\([^>]*\)>.*/\1/p;q}'
}

dev_mtu() {
    nsx "$1" ip -o link show dev "$2" 2>/dev/null | sed -n 's/.* mtu \([0-9]*\).*/\1/p;q'
}

dev_ip4() {
    nsx "$1" ip -o -4 addr show dev "$2" 2>/dev/null | awk '{print $4; exit}'
}

# First "usable" v6 address: excludes fe80:: (present on every NIC, not an inner address) and
# tentative (DAD incomplete, cannot be used as a source address)
dev_ip6() {
    nsx "$1" ip -o -6 addr show dev "$2" 2>/dev/null \
        | awk '$4 !~ /^fe80:/ && $0 !~ /tentative/ {print $4; exit}'
}

# Derived ULA: same algorithm as ip6_derive_ula() in protocol.h (fd00::/96 + the low
# 32 bits of the inner IPv4). That is where inner v6 addresses come from -- client and server each map
# the inner IPv4 it was given into a ULA, and the admission filter on both sides validates against it.
ula_of() {
    python3 -c "
import ipaddress, sys
print(ipaddress.IPv6Address(b'\xfd' + b'\x00' * 11 +
      ipaddress.IPv4Address(sys.argv[1]).packed))
" "$1"
}

# KEY=value from get-stats (empty when the key is absent)
# Inner echo probe (same path as C6): whether the TCP round-trip via iwan0 works
echo_probe() {
    nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'bind-probe')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
}

# Inner IPv6 echo probe: the target is the **server's derived ULA** (the two endpoints of inner v6
# are each side's own ULA; the client side is configured automatically by the v6 side of route_iface_up, see P5d)
echo_probe6() {
    nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('$ULA_S6', $ECHO_PORT), 5)
s.sendall(b'v6-probe')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
}

# During DAD (~1s) a freshly added ULA is tentative and cannot be a source address: wait until it is usable before probing.
# Both the kernel plane and the TUN plane run DAD, and DAD's NS source is the unspecified address, which the peer's ULA admission
# filter drops (no reply ever comes -> it turns preferred after the timeout), so this has to wait.
wait_ula_ready() {
    for _ in $(seq 1 40); do
        [ -n "$(dev_ip6 "$NS_C" iwan0)" ] && return 0
        sleep 0.25
    done
    return 1
}

stat_of() {
    nsx "$1" "$WORK/iwan_ctl" get-stats 2>/dev/null | sed -n "s/^$2=//p" | head -1
}

# Context on inner v6 echo failure: module counters (tx_bad_inner/rx_bad_inner point straight at "the module
# judged inner v6 a bad packet", rx_delivered/tx_pkts at "not received / not sent") + the tail
# of both logs. Without it, "echo failed" leaves only a riddle that must be investigated from scratch.
v6_fail_hint() {
    printf '    module counters (client netns): %s\n' \
        "$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>/dev/null | tr '\n' ' ' | cut -c1-240)"
    printf '    client log tail:\n'
    tail -n 3 "$1" 2>/dev/null | sed 's/^/      /'
    printf '    server log tail:\n'
    tail -n 3 "$LOG_S" 2>/dev/null | sed 's/^/      /'
}

# ---------------------------------------------------------------- prerequisites

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
command -v ip >/dev/null   || die "iproute2 missing"
command -v cc >/dev/null   || die "cc missing (needed to build the two read-only tools under kernel/tests)"
[ -f "$KO" ]               || die "missing $KO: run make -C kernel first"
[ -x "$BIN/iwan-client" ]  || die "missing $BIN/iwan-client: run cmake -B build -DIWAN_WERROR=ON -DIWAN_STRICT=ON && cmake --build build first"
[ -x "$BIN/iwan-server" ]  || die "missing $BIN/iwan-server: same as above"
# Build-profile prerequisite: the kernel module's max_mtu defaults to 1500, while a jumbo MTU tier build (cmake -DIWAN_JUMBO_MTU=N)
# raises the client's **default** inner MTU to the cap (e.g. 65499) -- such a client without --mtu
# is always rejected by the module with -EINVAL (log "SESSION_UP invalid params ... mtu=65499"). The default data plane
# is exactly the "no --mtu" path, so this must be blocked here, or a profile mismatch will masquerade as a plane-selection failure.
CLI_MTU_DEFAULT="$("$BIN/iwan-client" proxy --help 2>/dev/null \
                   | sed -n 's/.*--mtu <MTU> *\[default: \([0-9]*\)\].*/\1/p' | head -1)"
[ "$CLI_MTU_DEFAULT" = "1400" ] \
    || die "the client's default inner MTU is ${CLI_MTU_DEFAULT:-unknown} (expected 1400): this is the jumbo MTU tier build (IWAN_JUMBO_MTU), which the kernel module cannot hold. Use a normal build: cmake -B build -DIWAN_WERROR=ON -DIWAN_STRICT=ON && cmake --build build"

WORK="$(mktemp -d /tmp/iwan-kdp-e2e.XXXXXX)"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$WORK/iwan_ctl"  "$ROOT/kernel/tests/iwan_ctl.c"  || die "failed to compile iwan_ctl"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$WORK/iwan_shm"  "$ROOT/kernel/tests/iwan_shm.c"  || die "failed to compile iwan_shm"

# One account per case: the server replies OPEN_REJECT to concurrent/differently-addressed sessions for the same account
# ("session active elsewhere"), so separate accounts keep cases from interfering with each other
printf 'alice:s3cret-pass\nbob:s3cret-pass\ncarol:s3cret-pass\ndave:s3cret-pass\n' > "$USERS"
chmod 600 "$USERS"

# Idempotent prerequisite: a previous round that hung (e.g. the wrapping subshell was killed hard and the real client became an orphan) leaves
# netns + session + iwan0 behind, and the next insmod fails with "File exists" so the script never starts. Here only
# **this script's own** leftovers are cleaned: the netns names and port are exclusive to this script and cannot touch the user's own tunnels.
pkill -9 -f "iwan-client proxy .*--port $PORT" 2>/dev/null || true
pkill -9 -f "iwan-server .*--port $PORT" 2>/dev/null || true
sleep 0.3
ip netns del "$NS_C" 2>/dev/null || true
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_L" 2>/dev/null || true

if module_loaded; then
    say "module iwan is already loaded (it must have been loaded without session parameters; it is not rmmodded on exit either)"
    sid0="$(awk '$1=="sid"{print $2}' /proc/net/iwan 2>/dev/null)"
    [ -z "$sid0" ] || [ "$sid0" = "0" ] \
        || die "init netns already has a kernel session (sid=$sid0): run sudo iwan_ctl session-down or sudo rmmod iwan first"
    # The loaded module must be **a build of this source tree**: module-side assertions (e.g. P5n's reserved
    # FLAGS bit, C4's MTU semantics) silently verify the old behaviour on an old module, making one think the change did not
    # take effect. The mtime of /sys/module/<name> is the load time; compare it with the .ko on disk.
    if [ "$KO" -nt /sys/module/iwan ]; then
        die "the loaded iwan is older than $KO (disk build: $(date -r "$KO" '+%F %T'), module load: $(date -r /sys/module/iwan '+%F %T')): run sudo rmmod iwan && sudo insmod $KO first, otherwise the module-side assertions verify old code"
    fi
else
    say "loading the module (without any session parameters)"
    # The previous round's rmmod and this insmod race: a module being unloaded is already gone from /proc/modules, but
    # init_module may still get EEXIST. Retry a few times before declaring failure; do not let one race waste the whole acceptance round.
    loaded=""
    for _ in 1 2 3 4 5 6; do
        if insmod "$KO" 2>"$WORK/insmod.err"; then
            loaded=ours
            break
        fi
        if module_loaded; then
            loaded=theirs
            break
        fi
        sleep 0.3
    done
    case "$loaded" in
        ours)   LOADED_MODULE=1 ;;
        theirs) say "insmod reports it already exists, but iwan is loaded and has no session -- continue with the loaded module" ;;
        *)      die "insmod still fails after 6 retries: $(cat "$WORK/insmod.err" 2>/dev/null) (check dmesg | tail for the cause)" ;;
    esac
fi

say "C1 module and initial state"
[ -e /dev/iwan ] && ok "C1a /dev/iwan exists" || bad "C1a /dev/iwan does not exist"

# When the previous round was interrupted /run/netns/<name> is left behind, and ip netns add then fails with "File exists"
# (hit on the bench on 2026-10-11). Delete by name first; if that does not work, treat it as a mount leftover, unmount
# and delete that one file (only these two concrete paths), and only report an error if it still fails.
mk_netns() {
    local n="$1"

    ip netns add "$n" 2>/dev/null && return 0
    echo "warning: ip netns add $n failed (leftover?) -- delete first and retry" >&2
    ip netns del "$n" 2>/dev/null
    if [ -e "/run/netns/$n" ]; then
        umount "/run/netns/$n" 2>/dev/null
        rm -f "/run/netns/$n" 2>/dev/null
    fi
    ip netns add "$n"
}
mk_netns "$NS_C" || die "ip netns add $NS_C failed"
mk_netns "$NS_S" || die "ip netns add $NS_S failed"
ip link add "$VETH_C" type veth peer name "$VETH_S" || die "failed to create veth"
ip link set "$VETH_C" netns "$NS_C"
ip link set "$VETH_S" netns "$NS_S"
nsx "$NS_C" ip addr add "$OUTER_C/24" dev "$VETH_C"
nsx "$NS_S" ip addr add "$OUTER_S/24" dev "$VETH_S"
# Outer v6: nodad skips the DAD wait (otherwise the address is tentative for ~1s and cannot be an outer
# source address). If the host has IPv6 disabled globally this fails -- set V6_OK=0; the whole P6 group is skipped
# and explicitly says "skipped", never disguised as a pass.
V6_OK=1
nsx "$NS_C" ip -6 addr add "$OUTER6_C/64" dev "$VETH_C" nodad 2>/dev/null || V6_OK=0
nsx "$NS_S" ip -6 addr add "$OUTER6_S/64" dev "$VETH_S" nodad 2>/dev/null || V6_OK=0
nsx "$NS_C" ip -6 addr show dev "$VETH_C" 2>/dev/null | grep -q "$OUTER6_C" || V6_OK=0
[ "$V6_OK" = 1 ] && say "C0 outer v6 addresses in place ($OUTER6_C / $OUTER6_S)" \
                 || say "C0 outer v6 unavailable: the P6 group will be skipped"
nsx "$NS_C" ip link set lo up
nsx "$NS_S" ip link set lo up
nsx "$NS_C" ip link set "$VETH_C" up
nsx "$NS_S" ip link set "$VETH_S" up
nsx "$NS_C" ping -c1 -W1 "$OUTER_S" >/dev/null 2>&1 \
    && ok "C1b veth reachable ($OUTER_C -> $OUTER_S)" \
    || bad "C1b veth unreachable"
[ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "C1c iwc has no iwan0 yet (configuration can only come via netlink)" \
                                   || bad "C1c iwc already has an iwan0"
[ "$(stat_of "$NS_C" sid)" = "0" ] && [ "$(stat_of "$NS_C" tok)" = "0" ] \
    && ok "C1d iwc get-stats: no session (sid=0 tok=0)" \
    || bad "C1d iwc initial session is not empty"

# ---------------------------------------------------------------- server (iws)

say "C2 server (userspace TUN forwarding, no kernel session)"
ip netns exec "$NS_S" "$BIN/iwan-server" --port "$PORT" --tun iwan-srv \
    --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --nat-if "$VETH_S" \
    --dns 198.18.0.1 --users "$USERS" >"$LOG_S" 2>&1 &
bg_resolve SRV iwan-server
wait_log "$LOG_S" "server ready." 15 && ok "C2a server ready" \
    || { bad "C2a server did not start"; tail -5 "$LOG_S"; }
[ "$(dev_kind "$NS_S" iwan-srv)" = "tun" ] && ok "C2b iws iwan-srv is a tun device" \
                                          || bad "C2b iws iwan-srv is not a tun"
[ -z "$(dev_kind "$NS_S" iwan0)" ] && ok "C2c iws has no iwan0 (the server does not use the kernel data plane)" \
                                   || bad "C2c an iwan0 appeared in iws"

# The inner echo inside iws (target of the client's TCP)
ip netns exec "$NS_S" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('198.18.0.1', $ECHO_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
bg_resolve ECHO python3

# Same-port listener for inner IPv6: binds the server's derived ULA (iws configures it on
# iwan-srv itself at startup). The kernel-plane inner v6 assertions (P5e/P5i/P5k) rely on it for echo; it must be
# IPV6_V6ONLY, otherwise :: would fight the v4 socket above for the same port.
ULA_S6="$(ula_of 198.18.0.1)"
ip netns exec "$NS_S" python3 -c "
import socket
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(('$ULA_S6', $ECHO_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
bg_resolve ECHO6 python3

# ---------------------------------------------------------------- client (iwc)

say "C3 client (--data-plane kernel)"
ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
    --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
    --data-plane kernel --mtu 1400 >"$LOG_C" 2>&1 &
bg_resolve CLI iwan-client
if wait_log "$LOG_C" "kernel data plane running" 25; then
    ok "C3a client reached the kernel data plane running state"
else
    bad "C3a client did not reach the running state"; tail -12 "$LOG_C"
fi
grep -q "kernel data plane: session established dev=iwan0 mtu=1400" "$LOG_C" \
    && ok "C3b log: session established dev=iwan0 mtu=1400" \
    || bad "C3b session establishment log mismatch (see $LOG_C)"

SRV_TUN_IP="$(sed -n 's/.*OPEN_ACK -> alice .* ip=\([0-9.]*\).*/\1/p' "$LOG_S" | head -1)"
[ -n "$SRV_TUN_IP" ] && ok "C3c tun ip assigned by the server reply = $SRV_TUN_IP" \
                     || bad "C3c no OPEN_ACK tun ip in the server log"

say "C4 iwc iwan0 is created by the module and configured"
[ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "C4a kind=iwan (NIC created by the module)" \
                                        || bad "C4a kind=$(dev_kind "$NS_C" iwan0)"
case "$(dev_flags "$NS_C" iwan0)" in
*UP*) ok "C4b flags contain UP ($(dev_flags "$NS_C" iwan0))" ;;
*)    bad "C4b device not UP (flags=$(dev_flags "$NS_C" iwan0))" ;;
esac
[ "$(dev_mtu "$NS_C" iwan0)" = "1400" ]  && ok "C4c mtu=1400" || bad "C4c mtu=$(dev_mtu "$NS_C" iwan0)"
[ "$(dev_ip4 "$NS_C" iwan0)" = "$SRV_TUN_IP/24" ] \
    && ok "C4d address = $SRV_TUN_IP/24 (matches the reply)" \
    || bad "C4d address = $(dev_ip4 "$NS_C" iwan0), expected $SRV_TUN_IP/24"

say "C5 no kernel session on the iws side"
[ -z "$(dev_kind "$NS_S" iwan0)" ] && ok "C5a iws still has no iwan0" || bad "C5a iws has iwan0"

say "C6 inner TCP over the kernel data plane (iwc -> iws 198.18.0.1:$ECHO_PORT)"
OUT="$(nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'hello-kernel-data-plane')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1)"
[ "$OUT" = "hello-kernel-data-plane" ] && ok "C6a TCP echo roundtrip matches: $OUT" \
                                       || bad "C6a TCP echo failed/mismatch: $OUT"

say "C7 /dev/iwan shared memory (read-only mmap)"
SHM="$(nsx "$NS_C" "$WORK/iwan_shm" dump 2>&1)"
printf '%s\n' "$SHM" | sed 's/^/    /'
printf '%s\n' "$SHM" | grep -q '^version=1$'  && ok "C7a version=1"  || bad "C7a version != 1"
printf '%s\n' "$SHM" | grep -q '^enabled=1$'  && ok "C7b enabled=1"  || bad "C7b enabled != 1"
LRX="$(printf '%s\n' "$SHM" | sed -n 's/^last_rx_ms=//p' | head -1)"
[ -n "$LRX" ] && [ "$LRX" != "0" ] && ok "C7c last_rx_ms=$LRX (peer frames received)" \
                                   || bad "C7c last_rx_ms=$LRX, expected non-zero"

say "C8 kernel counters (iwan_ctl get-stats, iwc)"
GS1="$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>&1)"
printf '%s\n' "$GS1" | sed 's/^/    /'
CLI_SID_HEX="$(sed -n 's/.*session established .*sid=\(0x[0-9a-f]*\).*/\1/p' "$LOG_C" | head -1)"
CLI_SID_DEC=$((CLI_SID_HEX))
GS_SID="$(printf '%s\n' "$GS1" | sed -n 's/^sid=//p' | head -1)"
[ -n "$CLI_SID_HEX" ] && [ "$GS_SID" = "$CLI_SID_DEC" ] \
    && ok "C8a sid matches (log $CLI_SID_HEX = kernel $GS_SID)" \
    || bad "C8a sid: client $CLI_SID_HEX ($CLI_SID_DEC) vs kernel $GS_SID"
RX1="$(printf '%s\n' "$GS1" | sed -n 's/^rx_frames=//p' | head -1)"
nsx "$NS_C" python3 -c "
import socket
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'x' * 32)
s.recv(64)
s.close()
" >/dev/null 2>&1
sleep 1
GS2="$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>&1)"
RX2="$(printf '%s\n' "$GS2" | sed -n 's/^rx_frames=//p' | head -1)"
[ -n "$RX1" ] && [ -n "$RX2" ] && [ "$RX2" -gt "$RX1" ] \
    && ok "C8b rx_frames grew: $RX1 -> $RX2" \
    || bad "C8b rx_frames did not grow: $RX1 -> $RX2"

say "C9 Ctrl-C exit (tri-state return code 0 = user stop)"
DEFAULT_BEFORE="$(nsx "$NS_C" ip route show default)"
# Bounded wait + on-site capture: do not hang the script here when the client will not exit (`wait` hung forever once,
# dragging the EXIT trap down with it). On timeout, print process state/signal masks/log tail first, then kill -9,
# so the "failure" itself carries the diagnostic context.
kill -INT "$CLI" 2>/dev/null || true
i=0
RC=""
while [ "$i" -lt 100 ]; do
    st="$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$CLI/stat" 2>/dev/null || true)"
    if [ -z "$st" ] || [ "$st" = "Z" ]; then
        wait "$CLI" 2>/dev/null || true
        RC=$?
        break
    fi
    sleep 0.1
    i=$((i + 1))
done
if [ -z "$RC" ]; then
    bad "C9a client did not exit within 10s after SIGINT (state below, then killed)"
    ps -o pid=,stat=,etime=,time=,args= -p "$CLI" 2>/dev/null \
        | cut -c1-150 | sed 's/^/    process: /' || true
    grep -E '^State|^Sig(Blk|Ign|Cgt)|^Threads' "/proc/$CLI/status" 2>/dev/null \
        | sed 's/^/    /' || true
    printf '    client log tail:\n'
    tail -n 4 "$LOG_C" 2>/dev/null | sed 's/^/      /' || true
    kill -9 "$CLI" 2>/dev/null || true
    wait "$CLI" 2>/dev/null || true
    RC=124
else
    [ "$RC" = 0 ] && ok "C9a client exit code 0" || bad "C9a client exit code $RC"
fi
CLI=""
grep -q "kernel data plane stopped (user stop)" "$LOG_C" \
    && ok "C9b log: kernel data plane stopped (user stop)" \
    || bad "C9b log has no stopped (user stop)"

say "C10 exit cleanup"
[ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "C10a iwan0 deleted" \
                                   || bad "C10a iwan0 still present: kind=$(dev_kind "$NS_C" iwan0)"
[ "$(stat_of "$NS_C" sid)" = "0" ] && [ "$(stat_of "$NS_C" tok)" = "0" ] \
    && ok "C10b session cleared (sid=0 tok=0)" \
    || bad "C10b session leftover: sid=$(stat_of "$NS_C" sid) tok=$(stat_of "$NS_C" tok)"
grep -q "CLOSE sent" "$LOG_C" && ok "C10c client sent PT_CLOSE (farewell frame)" \
                              || bad "C10c no CLOSE sent in the client log"
# The client log only proves "sent"; "the peer really received it and tore the session down" must come from the server -- server.c's PT_CLOSE
# branch unconditionally srv_log("[peer] session 0x.... (ip ...) closed") when the token is correct (stdout+fflush,
# independent of the debug switch). The server log is cleared at the start of this script, so this line can only come from C9's farewell frame.
if wait_log "$LOG_S" " closed" 3; then
    ok "C10e server confirmed session closed: $(grep -m1 -- " closed" "$LOG_S")"
else
    bad "C10e no session close record on the server (PT_CLOSE not delivered? see $LOG_S)"
fi
[ "$(nsx "$NS_C" ip route show default)" = "$DEFAULT_BEFORE" ] \
    && ok "C10d default route untouched (no --proxy-cidr)" \
    || bad "C10d default route changed: $DEFAULT_BEFORE -> $(nsx "$NS_C" ip route show default)"

# ---------------------------------------------------------------- --extra

if [ "$EXTRA" = 1 ]; then
    say "E1 iwan0 taken by another device (dummy)"
    nsx "$NS_C" ip link add iwan0 type dummy || bad "E1a failed to create dummy"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user bob --pass s3cret-pass --data-plane kernel >"$LOG_C.e1" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "E1b client exited non-zero ($RC)" || bad "E1b client unexpectedly succeeded"
    grep -q "already exists, but it is not a device created by the iwan kernel module" "$LOG_C.e1" \
        && ok "E1c wrong-owner error reported" || bad "E1c error text mismatch (see $LOG_C.e1)"
    [ "$(dev_kind "$NS_C" iwan0)" = "dummy" ] && ok "E1d dummy not deleted/taken over" \
                                             || bad "E1d dummy was touched"
    nsx "$NS_C" ip link del iwan0

    say "E2 SIGKILL leftovers (known regression) and their cleanup"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user carol --pass s3cret-pass \
        --data-plane kernel >"$LOG_C.e2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.e2" "kernel data plane running" 25 || bad "E2a client did not come up"
    kill -9 "$CLI" 2>/dev/null
    wait "$CLI" 2>/dev/null
    CLI=""
    sleep 0.5
    [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] \
        && ok "E2b iwan0 still present after SIGKILL (regression: the TUN mode leaves no leftovers)" \
        || bad "E2b iwan0 unexpectedly gone after SIGKILL"
    [ "$(stat_of "$NS_C" sid)" != "0" ] && ok "E2c session still in the kernel (the hook keeps swallowing packets)" \
                                       || bad "E2c session gone"
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    sleep 0.5
    [ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "E2d session-down cleared session and device" \
                                       || bad "E2d iwan0 still present after session-down"

    say "E3 external deletion of iwan0 -> client recreates it"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane kernel >"$LOG_C.e3" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.e3" "kernel data plane running" 25 || bad "E3a client did not come up"
    nsx "$NS_C" ip link del iwan0 2>/dev/null
    if wait_log "$LOG_C.e3" "recreated" 6; then
        ok "E3b log: iwan0 recreated after external deletion"
        [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "E3c the device really is back" \
                                                 || bad "E3c device did not come back"
    else
        bad "E3b no recreation seen (see $LOG_C.e3)"
    fi
    kill -INT "$CLI" 2>/dev/null
    wait "$CLI" 2>/dev/null
    CLI=""
fi

# ------------------------------------------------- plane selection, fallback and pre-handshake rejection (--plane)

if [ "$PLANE" = 1 ]; then
    say "P1 default data plane (no --data-plane) = kernel plane"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        >"$LOG_C.p1" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p1" "kernel data plane running" 25; then
        ok "P1a default selection reached the kernel plane"
    else
        bad "P1a default did not use the kernel plane (see $LOG_C.p1)"
    fi
    grep -q "data plane: default kernel" "$LOG_C.p1" && ok "P1b log declares the default selection" \
        || bad "P1b missing default-selection log (see $LOG_C.p1)"
    [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "P1c iwan0 created by the module" \
        || bad "P1c iwan0 kind=$(dev_kind "$NS_C" iwan0)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P1d inner TCP echo roundtrip matches" \
        || bad "P1d inner echo failed: $OUT"
    stop_cli "$CLI"; CLI=""
    # Wait until the kernel session and device are really gone, then let P2 take iwan0 with a dummy
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    say "P2 kernel plane unavailable (iwan0 taken by dummy) => automatic TUN fallback"
    if nsx "$NS_C" ip link add iwan0 type dummy; then
        ok "P2 precondition: dummy takes iwan0"
    else
        bad "P2 precondition: dummy cannot be created (iwan0 leftover?)"
    fi
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --tun iwan9 >"$LOG_C.p2" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p2" "TUN proxy running" 25; then
        ok "P2a TUN plane came up after the fallback"
    else
        bad "P2a fallback failed (see $LOG_C.p2)"
    fi
    grep -q "already exists, but it is not a device created by the iwan kernel module" "$LOG_C.p2" \
        && ok "P2b reason the kernel plane is unavailable was reported" || bad "P2b missing kernel-plane reason (see $LOG_C.p2)"
    grep -q "falling back to the TUN data plane" "$LOG_C.p2" && ok "P2c fallback log appeared" \
        || bad "P2c missing fallback log (see $LOG_C.p2)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P2d inner TCP echo matches after the fallback" \
        || bad "P2d echo failed after the fallback: $OUT"
    stop_cli "$CLI"; CLI=""
    nsx "$NS_C" ip link del iwan0

    say "P3 both data planes unavailable => non-zero exit (the TUN error text no longer says must be root)"
    nsx "$NS_C" ip link add iwan0 type dummy
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass >"$LOG_C.p3" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P3a non-zero exit ($RC)" || bad "P3a unexpectedly succeeded"
    grep -q "falling back to the TUN data plane" "$LOG_C.p3" && ok "P3b the fallback was really attempted" \
        || bad "P3b fallback not attempted (see $LOG_C.p3)"
    grep -q "the kernel rejected this name" "$LOG_C.p3" \
        && ok "P3c TUN error text says the kernel rejected the name" \
        || bad "P3c TUN error text mismatch (see $LOG_C.p3)"
    grep -q "TUN data plane also unavailable, exiting" "$LOG_C.p3" && ok "P3d both sides are reported unavailable" \
        || bad "P3d missing the "both unavailable" conclusion (see $LOG_C.p3)"
    grep -q "must be root" "$LOG_C.p3" && bad "P3e still uses the misleading must be root" \
        || ok "P3e must be root no longer appears"
    nsx "$NS_C" ip link del iwan0

    say "P4 this netns already has a live session => the second client is rejected before the handshake"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        >"$LOG_C.p4a" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p4a" "kernel data plane running" 25; then
        ok "P4a the first client reached the kernel data plane running state"
    else
        bad "P4a the first one did not come up (see $LOG_C.p4a)"
    fi
    # The liveness input is last_rx_ms in shared memory: a just-established session still has 0 (the first
    # keepalive only goes out at 10s). Send one inner echo first so the kernel receives a gated frame,
    # then last_rx_ms becomes "fresh" (within the liveness window of < 2x keepalive).
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P4a2 inner echo works (creates a recent receive)" \
        || bad "P4a2 inner echo failed: $OUT"
    SHM4="$(nsx "$NS_C" "$WORK/iwan_shm" dump 2>&1)"
    printf '%s\n' "$SHM4" | grep -q '^enabled=1$' \
        && ok "P4a3 shared memory enabled=1 (liveness input ready)" \
        || bad "P4a3 enabled != 1: $(printf '%s\n' "$SHM4" | grep '^enabled' )"
    SID_A="$(stat_of "$NS_C" sid)"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass >"$LOG_C.p4b" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P4b the second one exited non-zero ($RC)" || bad "P4b the second one unexpectedly succeeded"
    grep -q "already has a kernel session/device taken" "$LOG_C.p4b" \
        && ok "P4c error text: this netns already has a live session" \
        || bad "P4c error text mismatch (see $LOG_C.p4b)"
    grep -q "not falling back to TUN" "$LOG_C.p4b" && ok "P4d explicitly does not fall back to TUN" \
        || bad "P4d missing the "no fallback" note (see $LOG_C.p4b)"
    # A note is not enough: the busy class must **not even try** the TUN plane -- P3 already proved
    # that a taken TUN reports "failed to open TUN device...", so the absence of that line means TUN was never reached.
    grep -q "failed to open TUN device\|TUN proxy running" "$LOG_C.p4b" \
        && bad "P4d2 it actually tried the TUN plane (see $LOG_C.p4b)" \
        || ok "P4d2 the TUN plane was never touched"
    grep -q "session established\|SESSION_UP conflicts with the existing session" "$LOG_C.p4b" \
        && bad "P4e the second one still handshook (liveness check not before the handshake)" \
        || ok "P4e no handshake, no SESSION_UP (liveness check before the handshake)"
    [ "$(stat_of "$NS_C" sid)" = "$SID_A" ] && ok "P4f the first session was not evicted (sid unchanged)" \
        || bad "P4f sid changed: $SID_A -> $(stat_of "$NS_C" sid)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P4g the first one still forwards normally" \
        || bad "P4g the first one's echo failed: $OUT"
    stop_cli "$CLI"; CLI=""

    say "P5 inner IPv6 (--proxy-cidr6) really works on both data planes"
    # Background (slice 1): like the userspace pump, the kernel module decapsulates by version -- v4/v6 both accepted.
    #   * egress: TX validates inner header consistency with one shared criterion (v4: tot_len, v6:
    #     payload_len + extension header chain);
    #   * ingress: RX uses the same criterion. When the inner version != outer version (v6 in v4), "let the current stack
    #     path continue" (NF_ACCEPT) would necessarily be misparsed as the outer version, so such frames go to
    #     netif_rx re-injection, where skb->protocol re-selects the handler by inner version.
    # Assertion stance: not "routes installed" but a **real roundtrip** -- the two inner v6 endpoints are
    # each side's derived ULA (fd00::/96 + the low 32 bits of the inner IPv4, protocol.h's
    # ip6_derive_ula). A silent blackhole is exactly "routes installed but not working".
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --proxy-cidr6 2001:db8:beef::/48 >"$LOG_C.p5a" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5a" "kernel data plane running" 25; then
        ok "P5a auto + --proxy-cidr6 still the kernel plane (the v6 need did not change the default selection)"
    else
        bad "P5a did not come up (see $LOG_C.p5a)"
    fi
    grep -q "data plane: default kernel" "$LOG_C.p5a" \
        && ok "P5b log declares the default selection (no more talk of switching to TUN)" \
        || bad "P5b missing default-selection log (see $LOG_C.p5a)"
    V6_RT=""
    for _ in $(seq 1 20); do
        V6_RT="$(nsx "$NS_C" ip -6 route show 2>/dev/null \
                 | grep "2001:db8:beef::/48")"
        [ -n "$V6_RT" ] && break
        sleep 0.25
    done
    [ -n "$V6_RT" ] && ok "P5c the kernel plane installed the --proxy-cidr6 IPv6 route" \
        || bad "P5c the kernel plane did not install the IPv6 route"
    if wait_ula_ready; then
        TUN_IP_C="$(dev_ip4 "$NS_C" iwan0)"
        WANT_ULA="$(ula_of "${TUN_IP_C%%/*}")/96"
        [ "$(dev_ip6 "$NS_C" iwan0)" = "$WANT_ULA" ] \
            && ok "P5d the kernel plane also configured the derived ULA $WANT_ULA (the v6 side of route_iface_up)" \
            || bad "P5d iwan0 v6 address is $(dev_ip6 "$NS_C" iwan0), expected $WANT_ULA"
    else
        bad "P5d no usable derived ULA on iwan0 (DAD failed or the address was not configured)"
    fi
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] \
        && ok "P5e inner IPv6 TCP echo roundtrips over the kernel data plane (new capability this round)" \
        || { bad "P5e inner IPv6 echo failed: $OUT"; v6_fail_hint "$LOG_C.p5a"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P5f inner IPv4 still works in the same session (dual-stack coexistence)" \
        || bad "P5f inner IPv4 echo failed: $OUT"
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 20); do
        nsx "$NS_C" ip -6 route show 2>/dev/null \
            | grep -q "2001:db8:beef::/48" || break
        sleep 0.25
    done
    nsx "$NS_C" ip -6 route show 2>/dev/null | grep -q "2001:db8:beef::/48" \
        && bad "P5g IPv6 route still present after exit (not rolled back)" \
        || ok "P5g IPv6 route rolled back after exit"

    say "P5h explicit --data-plane kernel + --proxy-cidr6 (the slice-0 rejection is flipped)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user bob --pass s3cret-pass \
        --data-plane kernel --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p5h" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5h" "kernel data plane running" 25; then
        ok "P5h explicit kernel plane + --proxy-cidr6 establishes a session normally (no longer rejected as a usage error)"
    else
        bad "P5h explicit kernel plane + v6 did not come up (see $LOG_C.p5h)"
    fi
    grep -q "valid only with --data-plane tun\|silent blackhole" "$LOG_C.p5h" \
        && bad "P5h2 still reports 'v6 is valid only on the TUN plane' (slice-0 guard not fully removed)" \
        || ok "P5h2 no longer shows the 'kernel plane does not support inner v6' rejection text"
    wait_ula_ready || true
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] && ok "P5i inner IPv6 echo also works on the explicit kernel plane" \
        || { bad "P5i inner IPv6 echo failed: $OUT"; v6_fail_hint "$LOG_C.p5h"; }
    stop_cli "$CLI"; CLI=""

    say "P5j bind NIC + --proxy-cidr6 (the slice-0 mutual exclusion is flipped)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user carol --pass s3cret-pass \
        --bind-dev "$VETH_C" --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p5j" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5j" "kernel data plane running" 25; then
        ok "P5j bind NIC (forces the kernel plane) no longer conflicts with --proxy-cidr6"
    else
        bad "P5j bind + v6 did not come up (see $LOG_C.p5j)"
    fi
    grep -q "bind mode=bind NIC $VETH_C" "$LOG_C.p5j" \
        && ok "P5j2 the binding really took effect" \
        || bad "P5j2 bind log mismatch: $(grep "bind mode" "$LOG_C.p5j" | head -1)"
    wait_ula_ready || true
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] && ok "P5k inner IPv6 echo roundtrips in the bound session" \
        || { bad "P5k inner IPv6 echo failed: $OUT"; v6_fail_hint "$LOG_C.p5j"; }
    stop_cli "$CLI"; CLI=""

    say "P5l TUN plane + --proxy-cidr6 still installs the IPv6 route as before (regression)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane tun --proxy-cidr6 2001:db8:beef::/48 --tun iwan9 \
        >"$LOG_C.p5l" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5l" "TUN proxy running" 25; then
        ok "P5l the TUN plane came up"
    else
        bad "P5l the TUN plane did not come up (see $LOG_C.p5l)"
    fi
    V6_RT=""
    for _ in $(seq 1 20); do
        V6_RT="$(nsx "$NS_C" ip -6 route show 2>/dev/null \
                 | grep "2001:db8:beef::/48")"
        [ -n "$V6_RT" ] && break
        sleep 0.25
    done
    [ -n "$V6_RT" ] && ok "P5l2 the TUN plane still installs the IPv6 route (capability not broken)" \
        || bad "P5l2 the TUN plane did not install the IPv6 route"
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 20); do
        nsx "$NS_C" ip -6 route show 2>/dev/null \
            | grep -q "2001:db8:beef::/48" || break
        sleep 0.25
    done
    nsx "$NS_C" ip -6 route show 2>/dev/null | grep -q "2001:db8:beef::/48" \
        && bad "P5l3 IPv6 route still present after the TUN plane exited" \
        || ok "P5l3 IPv6 route rolled back after the TUN plane exited"

    # The reserved FLAGS bit (bit1 = the once-planned "kernel answers PT_PING_REQ") must be rejected:
    # the ABI defines only CREATE_DEV, so reject rather than pretend to support it. The same parameter set without the reserved
    # bit succeeds and with it must fail -- the only difference is that one bit, so this criterion does not depend on text.
    # --no-create-dev keeps these cases from creating iwan0 or touching the veth.
    nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
        --key 0000000000000000 --outer-src 127.0.0.1 --outer-dst 127.0.0.2 \
        --dport 1234 --no-create-dev >"$LOG_C.p5m" 2>&1 \
        && ok "P5m control group: a session can be established without the reserved bit" \
        || bad "P5m the control group itself failed (see $LOG_C.p5m)"
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    [ "$(stat_of "$NS_C" sid)" = "0" ] \
        && [ -z "$(dev_kind "$NS_C" iwan0)" ] \
        && ok "P5m2 the control group cleaned up (no session, no iwan0)" \
        || bad "P5m2 control group leftovers: sid=$(stat_of "$NS_C" sid) kind=$(dev_kind "$NS_C" iwan0)"
    nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
        --key 0000000000000000 --outer-src 127.0.0.1 --outer-dst 127.0.0.2 \
        --dport 1234 --no-create-dev --reserved-flag-bit1 \
        >"$LOG_C.p5n" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P5n setting the reserved bit is rejected (rc=$RC)" \
        || bad "P5n the reserved bit was unexpectedly accepted"
    [ "$(stat_of "$NS_C" sid)" = "0" ] && ok "P5o no session left after the rejection" \
        || bad "P5o sid non-zero: $(stat_of "$NS_C" sid)"

    # ------------------------------------------------- P6 outer IPv6 (slice 2)
    #
    # The server listens on both v4/v6 (same port); the client picks the outer from the **literal address family** of --server
    # automatically: this session's outer header is IPv6, and the kernel module's v6 hook/parsing/sending
    # whole chain goes through a real roundtrip. The two data-plane cases cover the two delivery paths:
    #   * inner v4 over outer v6 = different versions -> netif_rx re-injection;
    #   * inner v6 over outer v6 = same version -> NF_ACCEPT on the v6 hook continues in place.
    say "P6 outer IPv6: pick the outer automatically from the --server literal address family"
    if [ "$V6_OK" != 1 ]; then
        say "P6 skipped: this host has no usable outer IPv6 (see C0)"
    else
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "[$OUTER6_S]" --port "$PORT" --user carol --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.p6" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p6" "kernel data plane running" 25; then
        ok "P6a outer v6 session established (--server [v6] picks outer v6 automatically)"
    else
        bad "P6a outer v6 session did not come up (see $LOG_C.p6)"
        tail -8 "$LOG_C.p6"
    fi
    grep -q "outerv6" "$LOG_C.p6" && ok "P6b client log declares the outer v6 endpoint" \
        || bad "P6b missing outer v6 declaration (see $LOG_C.p6)"
    grep -q "\[::\]:$PORT" "$LOG_S" && ok "P6c server v6 listen socket is open" \
        || bad "P6c no v6 listen line in the server log (see $LOG_S)"
    [ "$(stat_of "$NS_C" sid)" != "0" ] && ok "P6d the kernel really has a session (sid non-zero)" \
        || bad "P6d no session in the kernel"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] \
        && ok "P6e inner v4 over outer v6 roundtrips (cross-version -> netif_rx re-injection)" \
        || { bad "P6e inner v4 over outer v6 failed: $OUT"; v6_fail_hint "$LOG_C.p6"; }
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "[$OUTER6_S]" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p6b" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p6b" "kernel data plane running" 25; then
        ok "P6f outer v6 session + --proxy-cidr6 established"
    else
        bad "P6f did not come up (see $LOG_C.p6b)"
        tail -8 "$LOG_C.p6b"
    fi
    if wait_ula_ready; then
        OUT="$(echo_probe6)"
        [ "$OUT" = "v6-probe" ] \
            && ok "P6g inner v6 over outer v6 roundtrips (same version -> in-place delivery)" \
            || { bad "P6g inner v6 over outer v6 failed: $OUT"; v6_fail_hint "$LOG_C.p6b"; }
    else
        bad "P6g no derived v6 address (ULA) on client iwan0"
        v6_fail_hint "$LOG_C.p6b"
    fi
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    # ABI criteria (no NIC created; clean the previous session first so P6l reflects only the three cases of this block)
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    for _ in $(seq 1 20); do
        [ "$(stat_of "$NS_C" sid)" = "0" ] && break
        sleep 0.25
    done
    # Outer v6 reachability precondition. Why it is required: without a bound IP the kernel **deliberately tolerates** outer
    # route resolution failure (that is the "device first, route later" escape hatch); once resolution fails,
    # iwan_carrier_resolve6 returns before the MTU criterion, so P6h becomes "the criterion was not reached"
    # rather than "the criterion was overturned". Pin the address and resolution state into the log so the case does not become a riddle.
    nsx "$NS_C" ip -6 addr show dev "$VETH_C" >"$LOG_C.p6rt" 2>&1
    nsx "$NS_C" ip -6 route get "$OUTER6_S" >>"$LOG_C.p6rt" 2>&1
    if grep -q "$OUTER6_C" "$LOG_C.p6rt" && grep -q "dev $VETH_C" "$LOG_C.p6rt"; then
        ok "P6m precondition: outer v6 address and resolved route still present ($OUTER6_C via $VETH_C)"
    else
        bad "P6m precondition failed: outer v6 address/route gone (see $LOG_C.p6rt)"
    fi
    VETH_MTU="$(nsx "$NS_C" cat "/sys/class/net/$VETH_C/mtu" 2>/dev/null)"
    VETH_C_OIF="$(nsx "$NS_C" cat "/sys/class/net/$VETH_C/ifindex" 2>/dev/null)"
    # Outer v6 encap overhead = IWAN_OVERHEAD_V6 = 8B frame header + 8B UDP + 40B IPv6 = 56
    # (kernel/iwan.h; neither v4's 36 nor the mistaken 72 in early docs).
    OW6=56
    GOOD_MTU=$(( ${VETH_MTU:-1500} - OW6 ))
    BAD_MTU=$(( GOOD_MTU + 1 ))
    # Boundary case: exactly fitting must still establish -- an over-strict criterion is equally wrong; testing only "1 more is rejected"
    # cannot tell "criterion correct" from "criterion rejects everything".
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --mtu "$GOOD_MTU" \
            --no-create-dev >"$LOG_C.p6c0" 2>&1; then
        ok "P6h0 boundary: inner MTU $GOOD_MTU + overhead $OW6 = carrier MTU $VETH_MTU, exactly fits -> established"
    else
        bad "P6h0 boundary: inner MTU $GOOD_MTU + overhead $OW6 = $VETH_MTU but rejected (criterion too strict)"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --mtu "$BAD_MTU" \
            --no-create-dev >"$LOG_C.p6c" 2>&1; then
        P6H_RC=0
    else
        P6H_RC=$?
    fi
    # Kernel-side state: capture both establishment and rejection -- on rejection we need to know why
    dmesg 2>/dev/null | grep "outer v6" | tail -6 >"$LOG_C.p6dmesg" 2>&1 || true
    if [ "$P6H_RC" = 0 ]; then
        bad "P6h inner MTU $BAD_MTU + overhead $OW6 exceeds carrier MTU $VETH_MTU but was accepted"
        printf '    carrier= in the reply (non-empty = resolved, reached the MTU criterion): %s\n' \
            "$(grep -o 'carrier=[0-9]*' "$LOG_C.p6c" 2>/dev/null | head -1)"
        printf '    kernel-side outer v6 resolution records: %s\n' \
            "$(tr '\n' '|' <"$LOG_C.p6dmesg" 2>/dev/null | cut -c1-300)"
        printf '    outer v6 resolution state: %s\n' \
            "$(tr '\n' '|' <"$LOG_C.p6rt" 2>/dev/null | cut -c1-200)"
        printf '    iwan_ctl reply: %s\n' \
            "$(tr '\n' ' ' <"$LOG_C.p6c" 2>/dev/null | cut -c1-200)"
    else
        ok "P6h inner MTU + v6 overhead exceeds the carrier NIC MTU, rejected (outer v6 does not fragment)"
    fi
    # The criterion's "plain words" have two outlets: EXTACK (iwan_ctl only prints the errno text, the client prints
    # the kernel's explanation) and the kernel log (iwan_carrier_resolve6's rejection line). Either one
    # counts as the explanation being in place.
    if grep -q "does not fit\|exceeds .*carrier" "$LOG_C.p6c" ||
       grep -q "exceeds carrier" "$LOG_C.p6dmesg"; then
        ok "P6i rejection reason points at MTU/encap overhead (EXTACK or kernel log)"
    else
        bad "P6i rejection reason has no MTU explanation (see $LOG_C.p6c and $LOG_C.p6dmesg)"
    fi
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src "$OUTER_C" \
            --outer-dst "$OUTER_S" --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --no-create-dev \
            >"$LOG_C.p6d" 2>&1; then
        bad "P6j both address pairs v4/v6 given at once but accepted"
    else
        ok "P6j both outer address families given at once, rejected (the family must be unique)"
    fi
    # The "carrier NIC bound" version of the same criterion: the bind path does not tolerate resolution errors, so this one does not depend on
    # "whether resolution worked at the time". Both together reveal whether the criterion was not evaluated or overturned.
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --oif "$VETH_C_OIF" \
            --dport 1234 --mtu "$BAD_MTU" --no-create-dev \
            >"$LOG_C.p6c2" 2>&1; then
        bad "P6h2 carrier NIC $VETH_C bound (MTU $VETH_MTU) still accepts inner MTU $BAD_MTU"
    else
        ok "P6h2 the bound-carrier-NIC version is also rejected (the bind path does not tolerate resolution errors)"
    fi
    # A rejected request must not leave a session (both P6h/P6h2 count); assert first, then clean up,
    # otherwise the final P6l would be cleared by us and lose its meaning.
    if [ "$(stat_of "$NS_C" sid)" = "0" ]; then
        ok "P6h3 the rejected outer v6 request left no session"
    else
        bad "P6h3 leftovers after rejection: sid=$(stat_of "$NS_C" sid)"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    # The default for a v6 session with --mtu omitted must use the **v6** overhead: 1500 - 56 = 1444.
    # Using v4's 36 gives 1464, and 1464 + 56 > 1500 -- the default itself would violate the rule,
    # and the MTU criterion would reject it. So "it establishes and the reply says MTU=1444" is the regression test for this fix.
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --no-create-dev \
            >"$LOG_C.p6n" 2>&1 && grep -q "MTU=1444" "$LOG_C.p6n"; then
        ok "P6n the default for a v6 session with --mtu omitted uses the v6 overhead (1444 = 1500 - 56)"
    else
        bad "P6n v6 default MTU is not 1444: $(tr '\n' ' ' <"$LOG_C.p6n" 2>/dev/null | cut -c1-160)"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --ip6 2001:db8:1ce::9 --dport 1234 \
            --no-create-dev >"$LOG_C.p6e" 2>&1; then
        bad "P6k the bound egress v6 IP does not belong to this host but was accepted"
    else
        ok "P6k the bound egress v6 IP is not in the local address table, rejected"
    fi
    [ "$(stat_of "$NS_C" sid)" = "0" ] && ok "P6l none of the three rejected cases left a session behind" \
        || bad "P6l leftover: sid=$(stat_of "$NS_C" sid)"
    fi

    # ======================================================== reply route (R1)
    # Scenario: a host in the served prefix 203.0.113.0/24 is **not** behind the far side of the tunnel but
    # attached directly to another local NIC (its /32 connected route is more specific than --proxy-cidr's /24).
    # Connections from it: destination inside the served set, but entering on a non-carrier NIC -- they must
    # bypass iwan as expected (no conntrack mark, replies not pushed into the tunnel).
    say "R1 reply route (conntrack): connections from the served prefix arriving on a non-carrier NIC bypass iwan"

    mk_netns "$NS_L" || die "ip netns add $NS_L failed"
    ip link add "$VETH_LC" type veth peer name "$VETH_LL" || die "creating the LAN veth failed"
    ip link set "$VETH_LC" netns "$NS_C"
    ip link set "$VETH_LL" netns "$NS_L"
    nsx "$NS_C" ip link set lo up
    nsx "$NS_L" ip link set lo up
    nsx "$NS_C" ip addr add "$RR_SERVED/32" dev "$VETH_LC"
    nsx "$NS_C" ip link set "$VETH_LC" up
    nsx "$NS_C" ip route add "$RR_PEER/32" dev "$VETH_LC"
    nsx "$NS_L" ip addr add "$RR_PEER/32" dev "$VETH_LL"
    nsx "$NS_L" ip link set "$VETH_LL" up
    nsx "$NS_L" ip route add "$RR_SERVED/32" dev "$VETH_LL"
    if nsx "$NS_L" ping -c 1 -W 3 "$RR_SERVED" >/dev/null 2>&1; then
        ok "R1a LAN side /32 point-to-point connectivity works ($RR_PEER -> $RR_SERVED)"
    else
        bad "R1a LAN side /32 connectivity is broken"
    fi

    # Listener on the served address: where the replies go is the whole point of this case
    ip netns exec "$NS_C" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$RR_SERVED', $RR_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
    bg_resolve RRLAN python3

    # A v4 --proxy-cidr* switches the client to the "take over the default route" model: startup calls capture_default() first
    # to record the original default (restored on exit); with no default route it refuses to start (kdp.c).
    # This netns was created without a default route (so C10d said "untouched"); add one here.
    # Note the client takes it over as "default via iwan0" -- see R2a2 below; the R wrap-up deletes it.
    nsx "$NS_C" ip route add default via "$OUTER_S" dev "$VETH_C" 2>/dev/null || true
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --reply-via-tunnel >"$LOG_C.rr" 2>&1 &
    bg_resolve RRCLI iwan-client
    RR_UP=0
    if wait_log "$LOG_C.rr" "kernel data plane running" 25; then
        RR_UP=1
        ok "R1b running with --reply-via-tunnel + --proxy-cidr"
    else
        bad "R1b the client did not start (see $LOG_C.rr)"; tail -14 "$LOG_C.rr"
    fi
    # Rules are installed after SESSION_UP, so their order against the "running" log is not guaranteed: wait a bit
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        grep -q "reply route" "$LOG_C.rr" && break
        sleep 0.3
    done
    grep -q "reply route: enabled" "$LOG_C.rr" \
        && ok "R1c reply route rules installed (the client log says so)" \
        || bad "R1c the log says nothing about the reply route (see $LOG_C.rr)"

    RR_RT="$(nsx "$NS_C" ip route get "$RR_PEER" from "$RR_SERVED" 2>&1)"
    if [ "$RR_UP" = 1 ] && printf '%s' "$RR_RT" | grep -q "dev $VETH_LC"; then
        ok "R1d counter-case route: $RR_SERVED -> $RR_PEER goes via $VETH_LC (not dragged into the tunnel by the proxy prefix)"
    else
        bad "R1d counter-case route goes elsewhere: $RR_RT"
    fi

    RR_ECHO="$(nsx "$NS_L" python3 -c "
import socket, sys
s = socket.create_connection(('$RR_SERVED', $RR_PORT), 5)
s.sendall(b'reply-bypass')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1)"
    [ "$RR_UP" = 1 ] && [ "$RR_ECHO" = "reply-bypass" ] \
        && ok "R1e counter-case connection really works (replies reach the peer, they are not shoved into the tunnel)" \
        || bad "R1e counter-case connection failed: $RR_ECHO"

    # mark= in /proc/net/nf_conntrack is **decimal** (only ip rule prints 0x1),
    # and the flow must be located first -- checking only "no mark=" passes vacuously.
    # The "bypass as expected" criterion is the rule set: the mark covers only the carrier NIC half. Do not use
    # /proc/net/nf_conntrack as the criterion -- in a netns that never triggered ct evaluation it may
    # be absent entirely, and "cannot read" is neither a pass nor a failure.
    RR_RULES="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null || true)"
    [ -n "$RR_RULES" ] || RR_RULES="$(nsx "$NS_C" iptables -t mangle -S 2>/dev/null || true)"
    if [ "$RR_UP" = 1 ] && printf '%s' "$RR_RULES" | grep -q "$VETH_C" &&
       ! printf '%s' "$RR_RULES" | grep -q "$VETH_LC"; then
        ok "R1f rules match only the carrier NIC $VETH_C, not the LAN NIC $VETH_LC (that is the source of the bypass)"
    else
        bad "R1f wrong rule criterion: $(printf '%s' "$RR_RULES" | tr '\n' '|' | cut -c1-200)"
    fi
    # Extra (only when the proc file exists): this flow really carries no mark
    if [ "$RR_UP" = 1 ] && nsx "$NS_C" test -r /proc/net/nf_conntrack; then
        RR_CT="$(nsx "$NS_C" sh -c "grep '$RR_PEER' /proc/net/nf_conntrack 2>/dev/null" || true)"
        if [ -n "$RR_CT" ] && printf '%s' "$RR_CT" | grep -q "mark=1\b"; then
            bad "R1f2 the direct connection from the served prefix got marked"
        else
            ok "R1f2 no mark for this flow in conntrack (extra confirmation)"
        fi
    fi

    stop_cli "$RRCLI"
    RR_RULE_L="$(nsx "$NS_C" ip rule show 2>/dev/null | grep -c "fwmark $RR_MARK" || true)"
    RR_TBL_L="$(nsx "$NS_C" ip route show table "$RR_TABLE" 2>/dev/null | grep -c . || true)"
    RR_NFT_L="$(nsx "$NS_C" nft list tables 2>/dev/null | grep -c iwan_reply || true)"
    [ "$RR_UP" = 1 ] && [ "${RR_RULE_L:-1}" = "0" ] && [ "${RR_TBL_L:-1}" = "0" ] && [ "${RR_NFT_L:-1}" = "0" ] \
        && ok "R1g after exit rule/table/nft are all rolled back (rule=$RR_RULE_L table=$RR_TBL_L nft=$RR_NFT_L)" \
        || bad "R1g leftovers: rule=$RR_RULE_L table=$RR_TBL_L nft=$RR_NFT_L"

    # ---- (d) precondition: the kernel plane hook must run before conntrack (or reinject=1)
    # What changes is **the parameter value itself**, which is exactly what the check reads; registered
    # hooks do not move, so only this check is affected, not live traffic. Restore the value right after.
    RR_P_HOOK="$(cat /sys/module/iwan/parameters/hooknum 2>/dev/null)"
    RR_P_REIN="$(cat /sys/module/iwan/parameters/reinject 2>/dev/null)"
    if [ -n "$RR_P_HOOK" ] && [ -n "$RR_P_REIN" ]; then
        echo 1 >/sys/module/iwan/parameters/hooknum 2>/dev/null || true
        echo 0 >/sys/module/iwan/parameters/reinject 2>/dev/null || true
        RR_REF="$(timeout 20 ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
            --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
            --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
            --reply-via-tunnel 2>&1 </dev/null | head -40 || true)"
        echo "$RR_P_HOOK" >/sys/module/iwan/parameters/hooknum 2>/dev/null || true
        echo "$RR_P_REIN" >/sys/module/iwan/parameters/reinject 2>/dev/null || true
        printf '%s' "$RR_REF" | grep -q "hook is not before conntrack" \
            && ok "R1h hook after conntrack: startup refused with a reason" \
            || bad "R1h no refusal or no reason: $(printf '%s' "$RR_REF" | tr '\n' '|' | cut -c1-200)"
        sleep 1
        [ "$(stat_of "$NS_C" sid)" = "0" ] && [ -z "$(dev_kind "$NS_C" iwan0)" ] \
            && ok "R1h2 the refusal left no session and no iwan0" \
            || bad "R1h2 leftovers after the refusal: sid=$(stat_of "$NS_C" sid) iwan0=$(dev_kind "$NS_C" iwan0)"
    else
        bad "R1h cannot read /sys/module/iwan/parameters/{hooknum,reinject}"
    fi

    # ---- (b) connections arriving through the tunnel: replies must go back the way they came, and **without it they truly cannot be sent**
    say "R2 reply route: connections arriving through the tunnel get replies back the way they came (the mark is mandatory, not cosmetic)"
    # The peer is beyond the tunnel; take a source in the inner /16 that is **not on iwan0's /24**:
    # the main table has no route to 198.18.7.7 (neither in the 198.18.0.0/24 connected route nor
    # covered by --proxy-cidr), so replies can only fall through to the default route -- the physical NIC. Thus
    # "reply route does not work" = replies truly cannot be sent, not "it happens to work".
    # The connection terminates on **the session's own inner address** 198.18.0.2, not on the served
    # 203.0.113.1: the reply source is the connection's local address, and the server enforces
    # source admission on inner tunnel packets, dropping spoofed sources not assigned to the session. So the served set
    # additionally gets 198.18.0.2/32 (the -d half still holds), while the peer still originates from 198.18.7.7.
    nsx "$NS_S" ip addr add 198.18.7.7/32 dev iwan-srv 2>/dev/null || true

    # Peer probe: bind 198.18.7.7 and connect (returns FAIL:<exception name> on failure, not treated as a crash)
    rr_peer_probe() {
        # Before each probe re-read **this** session's inner address: a reconnect of the same account gets a
        # different inner IP (run5 field data: R2a was .14, R2b got another one), and reusing the previous address hits
        # "this address belongs to no session", which the server drops as unclaimed -- the symptom is
        # the listener never accepting once and the probe timing out.
        RR_INNER="$(nsx "$NS_C" ip -4 -o addr show dev iwan0 2>/dev/null |
            awk '{print $4}' | cut -d/ -f1 | head -1)"
        nsx "$NS_S" python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(6)
s.bind(('198.18.7.7', 0))
try:
    s.connect(('$RR_INNER', $RR_PORT2))
except Exception as e:
    sys.stdout.write('FAIL:' + type(e).__name__)
    raise SystemExit(0)
s.sendall(b'reply-via-tunnel')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
    }

    # R2a negative case: without --reply-via-tunnel replies truly must not get out
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --proxy-cidr 198.18.0.0/24 >"$LOG_C.rr2a" 2>&1 &
    bg_resolve RRCLI2A iwan-client
    RR2A_UP=0
    if wait_log "$LOG_C.rr2a" "kernel data plane running" 25; then
        RR2A_UP=1
    else
        bad "R2 precondition: the client without the reply route did not start"; tail -8 "$LOG_C.rr2a"
    fi
    sleep 1
    RR_INNER_RT="$(nsx "$NS_C" ip -4 -o addr show dev iwan0 2>/dev/null |
        awk '{print $4}' | cut -d/ -f1 | head -1)"
    if [ -n "$RR_INNER_RT" ]; then
        RR_INNER="$RR_INNER_RT"
        ok "R2 precondition: inner address of this session = $RR_INNER"
    else
        bad "R2 precondition: cannot read iwan0's inner address, falling back to $RR_INNER"
    fi
    ip netns exec "$NS_C" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $RR_PORT2))
s.listen(8)
while True:
    c, a = s.accept()
    open('$LOG_C.rrtun.accept', 'a').write('accept from %s -> %s\n' % (a, c.getsockname()))
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
    bg_resolve RRTUN python3
    sleep 0.3
    # Note (this used to assert "without the mark it does not go via iwan0", which does not hold here and should not):
    # A v4 --proxy-cidr makes the client take over the default route => the main table default already points at iwan0,
    # so for an address like 198.18.7.7 with "no more specific route", traffic goes through the tunnel even unmarked.
    # That is not a defect: with everything in the tunnel the reply rules are redundant (see docs/reply-routing.md
    # "decided items"). The case that really needs reply rules is "proxy a few prefixes only, keep the default route
    # on the physical NIC", which needs a v6 version of this case (v6 --proxy-cidr6 does not trigger the takeover),
    # tracked as follow-up. Here we only record the observation, no assertion.
    RR_NOMARK_RT="$(nsx "$NS_C" ip route get 198.18.7.7 from "$RR_INNER" 2>&1)"
    printf '    R2a2 observation: main table route lookup without the mark => %s\n' \
        "$(printf '%s' "$RR_NOMARK_RT" | head -1 | cut -c1-120)"
    RR_NOFLAG="$(rr_peer_probe)"
    # This does **not** assert "it must be unreachable": in this e2e the client's physical NIC and the server are the same
    # veth, so replies leaking out (unencapsulated) land on the server host, and the server's iwan-srv happens to
    # own 198.18.7.7 -- so even a "leak" arrives by luck. In a real network the physical NIC leads
    # elsewhere and a leak means it cannot be sent. Only the two deterministic criteria are used (R2a2 the unmarked route,
    # R2a3 no conntrack mark without the flag); below we only record the observation.
    case "$RR_NOFLAG" in
        FAIL:*) printf '    R2a observation: peer unreachable with the switch off (%s)\n' "$RR_NOFLAG" ;;
        *) printf '    R2a observation: peer still reachable with the switch off (%s) -- topology limitation, see comment\n' "$RR_NOFLAG" ;;
    esac
    # Do not use "no mark found in /proc/net/nf_conntrack" as the criterion: this kernel does not enable
    # that compat procfs, the file does not exist at all, and "cannot read" would always pass (vacuously).
    # Query the rules directly: with the switch off there must be **no** reply route rule/table at all.
    RR_RULES_A="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null || true)"
    [ -n "$RR_RULES_A" ] || RR_RULES_A="$(nsx "$NS_C" iptables -t mangle -S 2>/dev/null | grep -i connmark || true)"
    if [ "$RR2A_UP" = 1 ] && [ -z "$RR_RULES_A" ]; then
        ok "R2a3 no reply route rules with the switch off (they really were not installed)"
    else
        bad "R2a3 rules installed although the switch is off: $(printf '%s' "$RR_RULES_A" | tr '\n' '|' | cut -c1-160)"
    fi
    stop_cli "$RRCLI2A"

    # R2b/R2c/R2d positive cases
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --proxy-cidr 198.18.0.0/24 --reply-via-tunnel >"$LOG_C.rr2b" 2>&1 &
    bg_resolve RRCLI2B iwan-client
    RR2B_UP=0
    if wait_log "$LOG_C.rr2b" "kernel data plane running" 25; then
        RR2B_UP=1
    else
        bad "R2 precondition: the client with the reply route did not start"; tail -8 "$LOG_C.rr2b"
    fi
    sleep 1
    # Observe the mark directly: this host has no /proc/net/nf_conntrack (compat procfs not enabled),
    # and no conntrack tool either. So append one rule to the end of the client's own nft table
    # that counts "marked packets" -- it sits after the marking rule, so hits > 0 prove the mark
    # is really applied. The client deletes the whole table on exit, no extra cleanup needed.
    RR_CNT_OK=0
    nsx "$NS_C" nft add rule inet iwan_reply pre ct mark 0x1 counter \
        >/dev/null 2>&1 && RR_CNT_OK=1
    RR_FLAG="$(rr_peer_probe)"
    [ "$RR2B_UP" = 1 ] && [ "$RR_FLAG" = "reply-via-tunnel" ] \
        && ok "R2b connections arriving through the tunnel get replies back the way they came (replies reach the peer via iwan0)" \
        || bad "R2b still unreachable with the reply route on: $RR_FLAG"
    printf '    R2 live rule: %s\n' \
        "$(nsx "$NS_C" ip rule show 2>&1 | tr '\n' '|' | cut -c1-200)"
    printf '    R2 live table %s: %s\n' "$RR_TABLE" \
        "$(nsx "$NS_C" ip route show table "$RR_TABLE" 2>&1 | tr '\n' '|' | cut -c1-200)"
    printf '    R2 live connections seen by the listener: %s\n' \
        "$(tr '\n' '|' <"$LOG_C.rrtun.accept" 2>/dev/null | cut -c1-200)"
    # nft prints the mark normalized to 0x00000001 (not 0x1), so never match "ct mark 0x1";
    # take the count from a line containing both "ct mark" and "counter".
    RR_CNT="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null |
        grep "ct mark" | grep "counter" | grep -o "packets [0-9]*" |
        head -1 | awk '{print $2}')"
    printf '    R2c evidence: counting rule installed=%s, marked packets=%s\n' "$RR_CNT_OK" "${RR_CNT:-none}"
    printf '    R2c evidence: table content=%s\n' \
        "$(nsx "$NS_C" nft list table inet iwan_reply 2>&1 | tr '\n' '|' | tr -s ' ' | cut -c1-400)"
    if [ "$RR2B_UP" = 1 ] && [ "$RR_CNT_OK" = 1 ] && [ -n "$RR_CNT" ] && [ "$RR_CNT" -gt 0 ]; then
        ok "R2c the mark is really applied (the nft counter rule counted $RR_CNT marked packets)"
    elif [ "$RR_CNT_OK" != 1 ]; then
        # Without nft (iptables fallback) this evidence is unavailable: fall back to the rule criterion
        if printf '%s' "$RR_RULES" | grep -q "$VETH_C"; then
            ok "R2c no nft, cannot count directly; rule criterion instead: the rules match the carrier NIC $VETH_C"
        else
            bad "R2c cannot observe the mark, and the rule criterion is wrong too"
        fi
    else
        bad "R2c the counting rule exists but counted no marked packet (the mark is not applied)"
    fi
    RR_RT2="$(nsx "$NS_C" ip route get 198.18.7.7 mark 1 2>&1)"
    [ "$RR2B_UP" = 1 ] && printf '%s' "$RR_RT2" | grep -q "dev iwan0" \
        && ok "R2d route lookup with the mark goes via iwan0 (the reply rules really are wired up)" \
        || bad "R2d still not via iwan0 with the mark: $RR_RT2 (rule/table above)"
    stop_cli "$RRCLI2B"
    # R wrap-up: delete the default route added for the v4 takeover model so later groups see the original state
    nsx "$NS_C" ip route del default 2>/dev/null || true
    [ -z "$(nsx "$NS_C" ip route show default 2>/dev/null)" ] \
        && ok "R2e R wrap-up: default route restored (later groups see the original state)" \
        || bad "R2e leftover default route: $(nsx "$NS_C" ip route show default 2>&1)"
fi

# ---------------------------------------------------------------- the three bind modes (--bind)

if [ "$BIND" = 1 ]; then
    OIF_C="$(nsx "$NS_C" cat /sys/class/net/$VETH_C/ifindex)"

    say "B1 bind egress IP (--bind-ip $OUTER_C, genetlink IWAN_A_IP)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-ip "$OUTER_C" \
        >"$LOG_C.b1" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.b1" "kernel data plane running" 25; then
        ok "B1a running on the kernel data plane"
    else
        bad "B1a not running"; tail -8 "$LOG_C.b1"
    fi
    grep -q "bind mode=egress IP $OUTER_C" "$LOG_C.b1" \
        && ok "B1b client log: bind mode=egress IP $OUTER_C" \
        || bad "B1b bind log mismatch: $(grep 'bind mode=' "$LOG_C.b1" | head -1)"
    [ "$(stat_of "$NS_C" bind_ip)" = "$OUTER_C" ] \
        && ok "B1c kernel snapshot bind_ip=$OUTER_C" \
        || bad "B1c bind_ip=$(stat_of "$NS_C" bind_ip), expected $OUTER_C"
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "B1d actual carrier NIC=$VETH_C($OIF_C): resolved from the address table and pinned at session setup" \
        || bad "B1d carrier=$(stat_of "$NS_C" carrier), expected $OIF_C"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "B1e inner TCP echo round-trips over the bound carrier NIC" \
                              || bad "B1e inner echo failed: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""
    [ "$(stat_of "$NS_C" carrier)" = "0" ] \
        && ok "B1f carrier NIC unpinned again after the session ends (carrier=0)" \
        || bad "B1f carrier=$(stat_of "$NS_C" carrier), expected 0"

    say "B2 bind NIC (--bind-dev $VETH_C, genetlink IWAN_A_OIF)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-dev "$VETH_C" \
        >"$LOG_C.b2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.b2" "kernel data plane running" 25 && ok "B2a running on the kernel data plane" \
        || { bad "B2a not running"; tail -8 "$LOG_C.b2"; }
    [ "$(stat_of "$NS_C" oif)" = "$OIF_C" ] && [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "B2b requested oif=$OIF_C and actual carrier NIC=$OIF_C" \
        || bad "B2b oif=$(stat_of "$NS_C" oif) carrier=$(stat_of "$NS_C" carrier), expected $OIF_C"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "B2c inner TCP echo round-trips" || bad "B2c inner echo failed: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    say "B3 negative: bind an address that is not on this host => refused at startup"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane kernel \
        --bind-ip 192.0.2.1 >"$LOG_C.b3" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B3a non-zero exit ($RC)" || bad "B3a unexpectedly succeeded"
    grep -q "no longer in the local address table" "$LOG_C.b3" && ok "B3b error text: address not in the local address table" \
        || bad "B3b error text mismatch: $(tail -1 "$LOG_C.b3")"

    say "B4 negative: address and NIC are not the same one => refused"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane kernel \
        --bind-dev lo --bind-ip "$OUTER_C" >"$LOG_C.b4" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B4a non-zero exit ($RC)" || bad "B4a unexpectedly succeeded"
    grep -q "is not on carrier NIC" "$LOG_C.b4" && ok "B4b error text: the address is not on the given NIC" \
        || bad "B4b error text mismatch: $(tail -1 "$LOG_C.b4")"

    say "B5 negative: TUN data plane + binding => refused (never silently ignored)"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane tun \
        --bind-dev "$VETH_C" >"$LOG_C.b5" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B5a non-zero exit ($RC)" || bad "B5a unexpectedly succeeded"
    grep -q "valid only with --data-plane kernel" "$LOG_C.b5" && ok "B5b error text: kernel data plane only" \
        || bad "B5b error text mismatch: $(tail -1 "$LOG_C.b5")"
fi

# ---------------------------------------------------------------- failure and recovery (--life)

if [ "$LIFE" = 1 ]; then
    OIF_C="$(nsx "$NS_C" cat /sys/class/net/$VETH_C/ifindex)"
    SID0=""

    # Wait until the kernel session is really gone (the client logs first, then SESSION_DOWN; there is a race)
    wait_sid0() {
        local i=0

        while [ "$i" -lt 40 ]; do
            [ "$(stat_of "$NS_C" sid)" = "0" ] && return 0
            sleep 0.25
            i=$((i + 1))
        done
        return 1
    }

    # Stop the server with a bound (graceful exit has a window; do not let wait hang)
    stop_srv() {
        local i=0

        [ -n "$SRV" ] || return 0
        kill -INT "$SRV" 2>/dev/null
        while [ "$i" -lt 20 ]; do
            kill -0 "$SRV" 2>/dev/null || break
            sleep 0.25
            i=$((i + 1))
        done
        kill -9 "$SRV" 2>/dev/null
        wait "$SRV" 2>/dev/null
        SRV=""
    }

    # Restart the server and wait for the **next** "server ready." (the log is appended, so only checking "it appeared"
    # would take the previous start's line as evidence). The previous instance's TUN device normally disappears with
    # the process; delete any leftover first so the restart does not report it busy.
    SRV_READY_N=1
    srv_start() {
        nsx "$NS_S" ip link del iwan-srv 2>/dev/null || true
        ip netns exec "$NS_S" "$BIN/iwan-server" --port "$PORT" --tun iwan-srv \
            --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --nat-if "$VETH_S" \
            --dns 198.18.0.1 --users "$USERS" >>"$LOG_S" 2>&1 &
        bg_resolve SRV iwan-server
        SRV_READY_N=$((SRV_READY_N + 1))
        wait_log_n "$LOG_S" "server ready." "$SRV_READY_N" 20
    }

    say "L1 bind NIC failure and recovery (--bind-dev $VETH_C)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-dev "$VETH_C" >"$LOG_C.l1" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l1" "kernel data plane running" 25 && ok "L1a running in bound state" \
        || { bad "L1a not running"; tail -8 "$LOG_C.l1"; }
    SID0="$(stat_of "$NS_C" sid)"
    [ -n "$SID0" ] && [ "$SID0" != "0" ] && ok "L1b session established (sid=$SID0)" \
                                      || bad "L1b sid=$SID0"

    nsx "$NS_C" ip link set "$VETH_C" down
    if wait_log "$LOG_C.l1" "bind invalid" 8; then
        ok "L1c bind invalid detected within the 1 s tick: $(grep 'bind invalid' "$LOG_C.l1" | head -1)"
    else
        bad "L1c no bind invalid seen (see $LOG_C.l1)"
    fi
    wait_sid0 && ok "L1d kernel side is down (sid=0)" || bad "L1d sid=$(stat_of "$NS_C" sid) is still not 0"
    [ -z "$(dev_kind "$NS_C" iwan0)" ] \
        && ok "L1e iwan0 deleted (routes via it are gone; inner traffic falls to the routing table's next hop)" \
        || bad "L1e iwan0 is still there: $(dev_kind "$NS_C" iwan0)"

    nsx "$NS_C" ip link set "$VETH_C" up
    if wait_log_n "$LOG_C.l1" "kernel data plane: session established" 2 30; then
        ok "L1f handshake succeeds again after the binding recovers"
    else
        bad "L1f no re-handshake (see $LOG_C.l1)"
    fi
    SID1="$(stat_of "$NS_C" sid)"
    [ -n "$SID1" ] && [ "$SID1" != "0" ] && ok "L1g new session sid=$SID1 (old $SID0)" \
                                      || bad "L1g sid=$SID1"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L1h inner TCP round-trips over the recovered session" \
                              || bad "L1h inner echo failed: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    say "L2 bind egress IP failure and recovery (--bind-ip $OUTER_C)"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-ip "$OUTER_C" >"$LOG_C.l2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l2" "kernel data plane running" 25 && ok "L2a running in bound state" \
        || { bad "L2a not running"; tail -8 "$LOG_C.l2"; }
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "L2b carrier NIC pinned by the egress IP (carrier=$OIF_C)" \
        || bad "L2b carrier=$(stat_of "$NS_C" carrier)"

    nsx "$NS_C" ip addr del "$OUTER_C/24" dev "$VETH_C"
    if wait_log "$LOG_C.l2" "bind invalid" 8; then
        ok "L2c bind invalid declared after the egress IP was deleted: $(grep 'bind invalid' "$LOG_C.l2" | head -1)"
    else
        bad "L2c no bind invalid seen (see $LOG_C.l2)"
    fi
    wait_sid0 && ok "L2d kernel side is down (sid=0)" || bad "L2d sid=$(stat_of "$NS_C" sid) is still not 0"

    nsx "$NS_C" ip addr add "$OUTER_C/24" dev "$VETH_C"
    if wait_log_n "$LOG_C.l2" "kernel data plane: session established" 2 30; then
        ok "L2e handshake succeeds again after the address comes back"
    else
        bad "L2e no re-handshake (see $LOG_C.l2)"
    fi
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "L2f carrier NIC pinned again after the re-handshake (carrier=$OIF_C)" \
        || bad "L2f carrier=$(stat_of "$NS_C" carrier)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L2g inner TCP round-trips over the recovered session" \
                              || bad "L2g inner echo failed: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    # ---- L3 outer link down: death can only come from the "nobody answers" budget (no binding involved) ----
    say "L3 outer link down (no binding) => death comes from the keepalive failure budget"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.l3" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l3" "kernel data plane running" 25 && ok "L3a running" \
        || { bad "L3a not running"; tail -8 "$LOG_C.l3"; }

    # link down => every send returns ENETUNREACH (not an ICMP reported every other send), and the three-failure budget
    # at a 10s cadence => death in about 30s; the watchdog is 120s, so the budget always wins here
    nsx "$NS_C" ip link set "$VETH_C" down
    if wait_log "$LOG_C.l3" "keepalive failed" 45; then
        ok "L3b death came from the failure budget: $(grep 'keepalive failed' "$LOG_C.l3" | head -1)"
    else
        bad "L3b the budget did not declare death (see $LOG_C.l3)"
    fi
    grep -q "IWAN_RX_STALE_MS" "$LOG_C.l3" \
        && bad "L3c the budget declared death first; the watchdog must not appear" \
        || ok "L3c the watchdog never fired (the budget declared death first)"
    wait_sid0 && ok "L3d kernel session cleared (sid=0)" || bad "L3d sid=$(stat_of "$NS_C" sid) is still not 0"

    nsx "$NS_C" ip link set "$VETH_C" up
    wait_log_n "$LOG_C.l3" "kernel data plane: session established" 2 30 \
        && ok "L3e handshake succeeds again after the link comes back" || bad "L3e no re-handshake (see $LOG_C.l3)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L3f inner TCP round-trips after reconnect" \
                              || bad "L3f inner echo failed: $OUT"
    stop_cli "$CLI"; CLI=""

    # ---- L4 server port black hole: every send succeeds, not one reply frame => only the watchdog is left ----
    say "L4 server port black hole (receives but never replies) => death comes from the IWAN_RX_STALE_MS watchdog"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 IWAN_RX_STALE_MS=30000 \
        "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.l4" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l4" "kernel data plane running" 25 && ok "L4a running" \
        || { bad "L4a not running"; tail -8 "$LOG_C.l4"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L4b inner TCP round-trips while the server is up" \
                              || bad "L4b inner echo failed: $OUT"

    stop_srv
    ip netns exec "$NS_S" python3 -c "
# IWAN_SINK_MARKER
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT))
while True:
    s.recvfrom(65535)
" >/dev/null 2>&1 &
    SINK_JOB=$!
    sleep 1
    if wait_log "$LOG_C.l4" "IWAN_RX_STALE_MS=30000" 45; then
        ok "L4c death came from the watchdog: $(grep IWAN_RX_STALE_MS "$LOG_C.l4" | head -1)"
    else
        bad "L4c the watchdog did not declare death (see $LOG_C.l4)"
    fi
    grep -q "keepalive failed" "$LOG_C.l4" \
        && bad "L4d the failure budget appeared although all sends succeeded (wrong criterion)" \
        || ok "L4d no failure budget at all (so the sends really all succeeded)"
    wait_sid0 && ok "L4e kernel session cleared (sid=0)" || bad "L4e sid=$(stat_of "$NS_C" sid) is still not 0"
    stop_cli "$CLI"; CLI=""
    pkill -9 -f "IWAN_SINK_MARKER" 2>/dev/null || true
    wait "$SINK_JOB" 2>/dev/null   # reap it so bash does not print a "Killed" line

    # ---- L5 TUN data plane: same budget, the failure event comes from receive-side hard errors ----
    say "L5 TUN data plane: the server disappears => death comes from the receive-side hard error count"
    srv_start && ok "L5a server restarted" || bad "L5a the server did not start"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane tun --mtu 1400 >"$LOG_C.l5" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l5" "TUN proxy running" 25 && ok "L5b TUN session established (the pump is running)" \
        || { bad "L5b not established (see $LOG_C.l5)"; tail -8 "$LOG_C.l5"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L5c inner TCP round-trips on the TUN data plane" \
                              || bad "L5c inner echo failed: $OUT"

    stop_srv
    # Waiting only for "peer not answering" stops at the first count (1/3) and passes wrongly; wait for the budget
    # exhausted line "N unanswered transport failures ... session lost".
    if wait_log "$LOG_C.l5" "unanswered transport failures" 60; then
        ok "L5d death: $(grep 'unanswered transport failures' "$LOG_C.l5" | tail -1)"
    else
        bad "L5d no death (see $LOG_C.l5)"
    fi
    grep -q "IWAN_RX_STALE_MS" "$LOG_C.l5" \
        && bad "L5e the budget declared death first; the watchdog must not appear" \
        || ok "L5e the watchdog never fired (the budget declared death first)"

    srv_start && ok "L5f server restarted again" || bad "L5f the server did not start"
    wait_log_n "$LOG_C.l5" "TUN proxy running" 2 40 \
        && ok "L5g TUN client reconnected (pump run 2)" \
        || bad "L5g no reconnect (see $LOG_C.l5)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L5h inner TCP round-trips after reconnect" \
                              || bad "L5h inner echo failed: $OUT"
    stop_cli "$CLI"; CLI=""
fi

# ---------------------------------------------------------------- summary

printf '\n== summary: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$KEEP" = 1 ]; then
    printf '   --keep: keeping %s and both netns (%s / %s); the module is not unloaded\n' "$WORK" "$NS_C" "$NS_S"
fi
[ "$FAIL" = 0 ] || exit "$FAIL"
