#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN control plane (genetlink) acceptance test -- requires root
#
#   sudo bash kernel/tests/netlink_test.sh [--keep] [--any-dir] [--extra]
#
# Division of labor with tcp_echo_test.sh: that one configures the data plane via module params + /proc, this one uses netlink only
# (insmod with no session params, proving netlink is the only config source), per CONTROL-PLANE.md
# frozen ABI acceptance:
#
#   SESSION_UP -> inner data -> control frame events -> GET_STATS -> SESSION_DOWN
#
# Topology (veth acts as the outer cable, inner addresses on lo, iwan0 created on demand by SESSION_UP):
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#
# Sessions (IWAN_A_OUTER_SRC = local outer address, IWAN_A_OUTER_DST = peer outer address):
#   iwc: --outer-src 10.100.0.1 --outer-dst 10.100.0.2 --dport 6100
#   iws: --outer-src 10.100.0.2 --outer-dst 10.100.0.1 --dport 6100
#
# Direction note: events are delivered per netns (CONTROL-PLANE.md section 9), so observing events/keepalive in iwc
# requires iwc to receive the frames -- control frames go from iws to iwc:6100,
# events/get-stats both run in iwc; inner data is tested once per direction (T4).
#
# Test cases:
#   T1 insmod with no session params: neither side has iwan0 before configuration, /proc creds are 0
#   T2 SESSION_UP: both sides create iwan0 on demand, state UP, MTU matches the reply
#   T3 GET_STATS config snapshot matches the configured values (sid/tok/enc/outer-src/outer-dst/dport)
#   T4 inner UDP both directions: iws->iwc asserts iwc rx_* grows and the iwc userspace socket receives;
#      then iwc->iws asserts iws rx_* grows
#   T5 control frame PT_PING_REQ -> IWAN_EV_CTRL_FRAME (prints frame type and hex)
#   T6 last_keepalive_ms is nonzero after receiving PING
#   T7 PT_CLOSE -> IWAN_EV_CTRL_FRAME + IWAN_EV_PEER_CLOSE
#   T8 SESSION_DOWN: iwan0 is deleted, a second GET_STATS shows creds cleared/session absent
#   T9/T10 (--extra, optional) SET_PEER peer drift, SET_ENABLED stop/start data plane
#
# Depends only on ip / cc / python3 (no ethtool / tcpdump / ss / nc needed).

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
SRC="$HERE/iwan_ctl.c"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
OUTER_S2=10.100.0.9	# --extra: second outer address used for SET_PEER peer drift
PORT=6100		# outer tunnel port
INNER_PORT=9999		# inner UDP destination port (T4 receives via the iwc python3 socket)
INNER_PORT2=9998	# used for the T4 reverse direction (no listener, counters only)
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 => outer is not fragmented
KEEP=0
ANY_DIR=0
EXTRA=0

for a in "$@"; do
	case "$a" in
	--keep)    KEEP=1 ;;
	--any-dir) ANY_DIR=1 ;;
	--extra)   EXTRA=1 ;;
	*) echo "unknown argument: $a"; exit 2 ;;
	esac
done

PASS=0
FAIL=0
declare -a RESULTS=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  - %s\n' "$*"; }
hint() { printf '  \033[33mHINT\033[0m %s\n' "$*"; }
die()  { printf '\033[31mFATAL: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# ---------------------------------------------------------------- helpers

# get-stats snapshot: stdout goes to a KEY=value file for repeated greps
snap() { # snap <netns> <tag>  -> echoes the iwan_ctl exit code
	nsx "$1" "$CTL" get-stats >"$WORK/stats-$2.txt" 2>"$WORK/stats-$2.err"
	echo $?
}

val() { # val <snapshot file> <key>
	sed -n "s/^$2=//p" "$1" | head -n1
}

num() { # num <value>: anything non-numeric is treated as 0
	case "${1:-}" in
	''|*[!0-9]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# Hint when dport and friends are byte-swapped (classic be16 vs host byte order bug)
revport() { echo $(( (($1 >> 8) | (($1 & 0xff) << 8)) & 0xffff )); }

link_exists() { nsx "$1" ip link show dev "$2" >/dev/null 2>&1; }

link_flags() { # <netns> <dev> -> flag string inside angle brackets
	nsx "$1" ip -o link show dev "$2" 2>/dev/null \
		| sed -n 's/^[0-9]*: [^:]*: <\([^>]*\)>.*/\1/p' | head -n1
}

link_mtu() { # <netns> <dev>
	nsx "$1" ip -o link show dev "$2" 2>/dev/null \
		| awk '{for (i = 1; i <= NF; i++) if ($i == "mtu") print $(i + 1)}' \
		| head -n1
}

is_up() { # <netns> <dev>
	case ",$(link_flags "$1" "$2")," in
	*,UP,*) return 0 ;;
	*) return 1 ;;
	esac
}

# Start an inner UDP receiver in a netns; print RECV_READY=1 before recvfrom to avoid races
start_udp_recv() { # <netns> <bind_ip> <port> <log>
	nsx "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(6)
s.bind((sys.argv[1], int(sys.argv[2])))
print("RECV_READY=1", flush=True)
try:
    d, a = s.recvfrom(4096)
    print("INNER_RX_FROM=%s:%d" % (a[0], a[1]))
    print("INNER_RX_LEN=%d" % len(d))
except Exception as e:
    print("INNER_RX_TIMEOUT=%s" % e)
' "$2" "$3" >"$4" 2>&1 &
	echo $!
}

# Send one inner UDP packet from a netns (source address bound explicitly to follow the iwan0 route)
send_udp() { # <netns> <src_ip> <dst_ip> <dport>
	nsx "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"iwan-netlink-test", (sys.argv[2], int(sys.argv[3])))
print("INNER_TX_OK")
' "$2" "$3" "$4"
}

# Background events listener: the script sends frames only after READY=1, avoiding the "send before joining" race
start_events() { # <netns> <log> <count> <timeout>
	: >"$2"
	nsx "$1" "$CTL" events --count "$3" --timeout "$4" >"$2" 2>&1 &
	echo $!
}

# Wait for the background process to print its ready line. The two ready markers differ; do not wait for one with the other's pattern:
#   UDP receiver -> RECV_READY=1      iwan_ctl events -> READY=1
# We got this wrong once: waiting on the receiver log but matching ^READY=1$ always timed out, reporting "receiver did not start",
# while the real consequence was that the send step was skipped entirely in the if branch, looking like "the module does not send".
wait_ready() { # <log> [pattern]
	local pat="${2:-^READY=1$}"
	for _ in $(seq 1 60); do
		grep -q "$pat" "$1" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

# ---------------------------------------------------------------- cleanup

# Delete only iwan0 created by this module. The iwan0 in the init netns may not be ours: this
# project's iwan-client runs a real tunnel over a TUN iwan0, and deleting it would break a live tunnel. The test is
# whether the detail line of `ip -d link show` shows this module's kind (iwan), not the device name,
# and not ARPHRD either -- TUN and iwan are both 65534.
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

cleanup() {
	if [ "$KEEP" = 0 ]; then
		# Let the module tear down the session first (also verifies idempotence: the device may be gone)
		[ -n "${WORK:-}" ] && [ -x "${CTL:-}" ] && {
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		}
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# The module may have created iwan0 in every netns; the one in the init netns must be deleted explicitly,
		# otherwise the device holds a module reference and the kernel rejects rmmod (Module iwan is in use).
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- prerequisites

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
command -v ip >/dev/null || die "iproute2 missing"
command -v cc >/dev/null || die "cc missing"
command -v python3 >/dev/null || die "python3 missing (needed to build control frames / send and receive inner UDP)"
[ -f "$SRC" ] || die "$SRC missing"

WORK="$(mktemp -d /tmp/iwan-netlink-test.XXXXXX)"
CTL="$WORK/iwan_ctl"

say "Building kernel module and userspace tool"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "module build failed"; }
[ -f "$KO" ] || die "$KO was not generated"
info "module build complete: $KO"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$CTL" "$SRC" \
	>"$WORK/ctl-build.log" 2>&1 \
	|| { cat "$WORK/ctl-build.log"; die "iwan_ctl build failed"; }
info "tool build complete: $CTL ($(grep -c . "$WORK/ctl-build.log") lines of compiler output, 0 lines means no warnings)"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# ---------------------------------------------------------------- topology

say "T1 build topology and load module (without any session parameters)"

rmmod iwan 2>/dev/null
ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
del_iwan0_if_ours
ip netns add "$NS_C" || die "failed to create netns $NS_C"
ip netns add "$NS_S" || die "failed to create netns $NS_S"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "failed to create veth"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# The inner packet source address (10.9.0.x) after decapsulation routes back via iwan0, but the packet came in on veth;
	# strict mode (rp_filter=1) would drop it. New netns default to 0; set it explicitly here
	# so the host sysctl cannot affect it.
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

INSMOD_ARGS=()
[ "$ANY_DIR" = 1 ] && INSMOD_ARGS+=(any_dir=1)
# Key point: no sid/tok/key/enc/dport/outer_* -- the session can only come from netlink
insmod "$KO" ${INSMOD_ARGS[@]+"${INSMOD_ARGS[@]}"} \
	|| die "insmod failed (see dmesg | tail for the reason)"
if grep -q '^iwan ' /proc/modules; then
	info "insmod complete${INSMOD_ARGS[0]+ (${INSMOD_ARGS[*]})}: iwan loaded"
else
	info "insmod complete${INSMOD_ARGS[0]+ (${INSMOD_ARGS[*]})} (iwan not visible in /proc/modules?)"
fi

if link_exists "$NS_C" iwan0 || link_exists "$NS_S" iwan0; then
	bad "T1 iwan0 already exists before any session was pushed (module params / auto device creation not disabled?)"
else
	ok "T1 no session pushed after insmod: neither side has iwan0 (config can only come from netlink)"
fi
pc_sid=$(nsx "$NS_C" awk '$1=="sid"{print $2}' /proc/net/iwan 2>/dev/null)
pc_tok=$(nsx "$NS_C" awk '$1=="tok"{print $2}' /proc/net/iwan 2>/dev/null)
info "iwc /proc/net/iwan sid=${pc_sid:-unreadable} tok=${pc_tok:-unreadable} (should be 0 with no session pushed)"

# ---------------------------------------------------------------- T1b (device type gate)

# A device with the same name but **not** created by this module must be refused for reuse (kernel/iwan_netlink.c
# iwan_dev_ensure gate). This is a safety floor, not neatness: this project's iwan-client does
# create an iwan0 over TUN for a real tunnel, and TUN and iwan share ARPHRD 65534, so looking only at
# the name and link type cannot tell them apart; the old implementation only pr_warn'ed then **kept reusing it**, and even
# changed its MTU -- which would directly break the user's running tunnel.
say "T1b device type gate: pre-create a non-iwan iwan0; SESSION_UP must fail and must not touch it"

GATE_ERR="$(sed -n 's/.*: //p' "$WORK/gate-add.err" 2>/dev/null | head -n1)"
if link_exists "$NS_C" iwan0; then
	bad "T1b precondition not met: iwc already has iwan0 (which earlier step created it?)"
elif nsx "$NS_C" ip link add iwan0 type veth peer name iwan0x \
		2>"$WORK/gate-add.err"; then
	# Deliberately set it DOWN + non-default MTU: if the session "takes over" this device, the MTU would be changed to
	# the requested value and UP would appear in the flags; both are observable.
	nsx "$NS_C" ip link set iwan0 mtu 1300 2>/dev/null
	gate_mtu0=$(link_mtu "$NS_C" iwan0)
	gate_flags0=$(link_flags "$NS_C" iwan0)
	nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
		--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
		--dport "$PORT" --mtu "$MTU" >"$WORK/gate-up.out" 2>"$WORK/gate-up.err"
	rc=$?
	if [ "$rc" != 0 ]; then
		ok "T1b SESSION_UP refused while a non-iwan iwan0 exists (rc=$rc, expected -EBUSY=16)"
	else
		bad "T1b non-iwan iwan0 was reused (SESSION_UP unexpectedly succeeded: got $(val "$WORK/gate-up.out" DEVNAME))"
	fi
	gate_detail=$(nsx "$NS_C" ip -d link show dev iwan0 2>/dev/null)
	if printf '%s\n' "$gate_detail" | grep -qE '^[[:space:]]+iwan[[:space:]]'; then
		bad "T1b the pre-created veth was changed into an iwan kind device (should not happen)"
	elif printf '%s\n' "$gate_detail" | grep -qE '^[[:space:]]+veth[[:space:]]'; then
		ok "T1b pre-created device is still veth (not taken over by this module)"
	else
		bad "T1b cannot find the detail line of the pre-created veth (assertion has no evidence)"
	fi
	if [ "$(link_mtu "$NS_C" iwan0)" = "$gate_mtu0" ] &&
	   [ "$(link_flags "$NS_C" iwan0)" = "$gate_flags0" ]; then
		ok "T1b pre-created device MTU/state unchanged ($gate_mtu0 / $gate_flags0: neither MTU changed nor set UP)"
	else
		bad "T1b pre-created device was touched: MTU $(link_mtu "$NS_C" iwan0)<-$gate_mtu0, flags $(link_flags "$NS_C" iwan0)<-$gate_flags0"
	fi
	# Remove it so T2 takes the normal path (this veth is ours; deleting it cannot hit someone else's device)
	nsx "$NS_C" ip link del iwan0 2>/dev/null
	nsx "$NS_C" ip link del iwan0x 2>/dev/null
else
	info "skipping T1b: cannot create the pre-created veth in iwc (${GATE_ERR:-unknown reason}) -- gate not verified"
fi

# ---------------------------------------------------------------- T2

say "T2 SESSION_UP (both sides; commands always run inside their own netns)"

up_out=$(nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-c.err")
rc=$?
DEV_C=iwan0
MTU_C="$MTU"
if [ "$rc" != 0 ]; then
	bad "T2 iwc: iwan_ctl session-up failed (rc=$rc)"
	sed 's/^/    /' "$WORK/up-c.err"
else
	DEV_C=$(printf '%s\n' "$up_out" | sed -n 's/^DEVNAME=//p' | head -n1)
	MTU_C=$(printf '%s\n' "$up_out" | sed -n 's/^MTU=//p' | head -n1)
	MTU_FROM_REPLY=$(printf '%s\n' "$up_out" | sed -n 's/^MTU_FROM_REPLY=//p' | head -n1)
	DEV_OWNED=$(printf '%s\n' "$up_out" | sed -n 's/^DEV_OWNED=//p' | head -n1)
	[ -n "$DEV_C" ] || DEV_C=iwan0
	[ -n "$MTU_C" ] || MTU_C="$MTU"
	info "iwc reply: DEVNAME=$DEV_C MTU=$MTU_C MTU_FROM_REPLY=${MTU_FROM_REPLY:-0} DEV_OWNED=${DEV_OWNED:-not reported}"
	if link_exists "$NS_C" "$DEV_C"; then
		ok "T2a iwc: $DEV_C created on demand after SESSION_UP"
	else
		bad "T2a iwc: no $DEV_C after SESSION_UP"
	fi
	# New attribute IWAN_A_DEV_OWNED: 1 = this iwan0 was created/claimed by the module
	# (SESSION_DOWN deletes it), 0 = not created by us. This checks the normal path:
	# the netns is fresh and the T1b pre-created veth is gone, so the device can only come from this
	# SESSION_UP, so it must be 1.
	if [ "$DEV_OWNED" = 1 ]; then
		ok "T2e iwc: reply DEV_OWNED=1 (device created by the module; SESSION_DOWN will delete it)"
	else
		bad "T2e iwc: reply DEV_OWNED=${DEV_OWNED:-missing}, expected 1 (new attribute not returned, or ownership check is wrong)"
	fi
	if is_up "$NS_C" "$DEV_C"; then
		ok "T2b iwc: $DEV_C state UP"
	else
		bad "T2b iwc: $DEV_C is not UP (flags=$(link_flags "$NS_C" "$DEV_C"))"
		nsx "$NS_C" ip link set "$DEV_C" up 2>/dev/null \
			&& info "set UP manually to continue (T2b still recorded as FAIL)"
	fi
	real_mtu=$(link_mtu "$NS_C" "$DEV_C")
	if [ "$real_mtu" = "$MTU_C" ]; then
		ok "T2c iwc: device MTU=$real_mtu matches the reply"
	else
		bad "T2c iwc: device MTU=$real_mtu differs from reply MTU=$MTU_C"
	fi
fi

up_out=$(nsx "$NS_S" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-s.err")
rc=$?
DEV_S=iwan0
if [ "$rc" != 0 ]; then
	bad "T2d iws: iwan_ctl session-up failed (rc=$rc)"
	sed 's/^/    /' "$WORK/up-s.err"
else
	DEV_S=$(printf '%s\n' "$up_out" | sed -n 's/^DEVNAME=//p' | head -n1)
	[ -n "$DEV_S" ] || DEV_S=iwan0
	if link_exists "$NS_S" "$DEV_S" && is_up "$NS_S" "$DEV_S"; then
		ok "T2d iws: $DEV_S created and UP (peer session ready, so T4/T5 have a receive side)"
	else
		bad "T2d iws: $DEV_S does not exist or is not UP (flags=$(link_flags "$NS_S" "$DEV_S"))"
		nsx "$NS_S" ip link set "$DEV_S" up 2>/dev/null
	fi
fi

# Inner addresses and routes: the device must exist before routes can be added, so this is after SESSION_UP
nsx "$NS_C" ip addr add "$INNER_C/32" dev lo 2>/dev/null
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo 2>/dev/null
nsx "$NS_C" ip link set "$DEV_C" up 2>/dev/null
nsx "$NS_S" ip link set "$DEV_S" up 2>/dev/null
nsx "$NS_C" ip route add "$INNER_S/32" dev "$DEV_C" 2>/dev/null \
	|| info "iwc: failed to add inner route $INNER_S dev $DEV_C (T4 may fail later)"
nsx "$NS_S" ip route add "$INNER_C/32" dev "$DEV_S" 2>/dev/null \
	|| info "iws: failed to add inner route $INNER_C dev $DEV_S (T4 may fail later)"
info "topology ready: $NS_C $INNER_C <-> $NS_S $INNER_S (outer $OUTER_C/$OUTER_S port $PORT)"

# ---------------------------------------------------------------- T3

say "T3 GET_STATS config snapshot matches configured values (iwc)"
snap "$NS_C" snap1 >/dev/null
for k in sid tok enc key outer_src outer_dst sport dport mtu devname enabled \
	last_keepalive_ms peer_state; do
	info "$k=$(val "$WORK/stats-snap1.txt" "$k")"
done

mism=""
for kv in "sid=$SID" "tok=$TOK" "enc=$ENC" "outer_src=$OUTER_C" \
	  "outer_dst=$OUTER_S" "dport=$PORT"; do
	k=${kv%%=*}
	e=${kv#*=}
	g=$(val "$WORK/stats-snap1.txt" "$k")
	[ "$g" = "$e" ] || mism="$mism $k(got \"$g\" expected \"$e\")"
done
if [ -z "$mism" ]; then
	ok "T3 config snapshot matches configured values (sid/tok/enc/outer-src/outer-dst/dport)"
else
	bad "T3 config snapshot mismatch:$mism"
	sed 's/^/    /' "$WORK/stats-snap1.err"
	gd=$(val "$WORK/stats-snap1.txt" dport)
	if [ -n "$gd" ] && [ "$gd" = "$(revport "$PORT")" ]; then
		hint "dport echo $gd is exactly the byte swap of $PORT: check whether IWAN_A_DPORT is decoded as be16 (iwan_genl.h says be16)"
	fi
	gi=$(val "$WORK/stats-snap1.txt" outer_src)
	if [ "$gi" = "$(echo "$OUTER_C" | awk -F. '{print $4"."$3"."$2"."$1}')" ]; then
		hint "outer_src echo $gi is the byte swap of $OUTER_C: check whether IWAN_A_OUTER_SRC/DST are decoded as be32"
	fi
fi

# ---------------------------------------------------------------- T4

say "T4 inner UDP both directions (iws->iwc first, then iwc->iws)"

snap "$NS_C" c1 >/dev/null
snap "$NS_S" s1 >/dev/null
rpid=$(start_udp_recv "$NS_C" "$INNER_C" "$INNER_PORT" "$WORK/recv-c.log")
if wait_ready "$WORK/recv-c.log" '^RECV_READY=1$'; then
	# Judge send failure separately: a sender-side failure must not be recorded as "receiver did not start"
	tx_out=$(send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" 2>&1)
	case "$tx_out" in
	*INNER_TX_OK*) : ;;
	*) bad "T4a iws inner send failed (python3 exception?)"
	   echo "$tx_out" | sed 's/^/    /' ;;
	esac
	sleep 0.5
	wait "$rpid" 2>/dev/null
else
	bad "T4a iwc inner UDP receiver did not start (python3 exception?)"
	sed 's/^/    /' "$WORK/recv-c.log"
	kill "$rpid" 2>/dev/null
fi
snap "$NS_C" c2 >/dev/null
snap "$NS_S" s2 >/dev/null

d_pkts=$(( $(num "$(val "$WORK/stats-c2.txt" rx_pkts)") - $(num "$(val "$WORK/stats-c1.txt" rx_pkts)") ))
d_frames=$(( $(num "$(val "$WORK/stats-c2.txt" rx_frames)") - $(num "$(val "$WORK/stats-c1.txt" rx_frames)") ))
d_deliv=$(( $(num "$(val "$WORK/stats-c2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-c1.txt" rx_delivered)") ))
d_outer=$(( $(num "$(val "$WORK/stats-c2.txt" rx_outer)") - $(num "$(val "$WORK/stats-c1.txt" rx_outer)") ))
d_tx_s=$(( $(num "$(val "$WORK/stats-s2.txt" tx_pkts)") - $(num "$(val "$WORK/stats-s1.txt" tx_pkts)") ))
info "iws->iwc: iwc rx_pkts $(val "$WORK/stats-c1.txt" rx_pkts) -> $(val "$WORK/stats-c2.txt" rx_pkts) (+$d_pkts), rx_outer +$d_outer, rx_frames +$d_frames, rx_delivered +$d_deliv"
info "iws tx_pkts $(val "$WORK/stats-s1.txt" tx_pkts) -> $(val "$WORK/stats-s2.txt" tx_pkts) (+$d_tx_s)"

if [ "$d_pkts" -gt 0 ] || [ "$d_frames" -gt 0 ] || [ "$d_deliv" -gt 0 ]; then
	ok "T4a iws->iwc: at least one of iwc rx_pkts/rx_frames/rx_delivered grew (+$d_pkts/+$d_frames/+$d_deliv)"
else
	bad "T4a iws->iwc: none of the three iwc counters grew (send side or ingress hook is not working)"
	hint "check iws tx_pkts (+$d_tx_s), the iwc outer address direction (IWAN_A_OUTER_SRC=local/OUTER_DST=peer), and dport byte order"
fi
if grep -q "^INNER_RX_FROM=$INNER_S" "$WORK/recv-c.log" 2>/dev/null; then
	ok "T4b iws->iwc: iwc userspace socket received the inner datagram (decapsulated and really delivered to the stack)"
else
	bad "T4b iws->iwc: iwc userspace socket received no inner datagram"
	sed 's/^/    /' "$WORK/recv-c.log" 2>/dev/null
fi

snap "$NS_S" s3 >/dev/null
send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
sleep 0.5
snap "$NS_S" s4 >/dev/null
e_pkts=$(( $(num "$(val "$WORK/stats-s4.txt" rx_pkts)") - $(num "$(val "$WORK/stats-s3.txt" rx_pkts)") ))
e_frames=$(( $(num "$(val "$WORK/stats-s4.txt" rx_frames)") - $(num "$(val "$WORK/stats-s3.txt" rx_frames)") ))
e_deliv=$(( $(num "$(val "$WORK/stats-s4.txt" rx_delivered)") - $(num "$(val "$WORK/stats-s3.txt" rx_delivered)") ))
info "iwc->iws: iws rx_pkts $(val "$WORK/stats-s3.txt" rx_pkts) -> $(val "$WORK/stats-s4.txt" rx_pkts) (+$e_pkts), rx_frames +$e_frames, rx_delivered +$e_deliv"
if [ "$e_pkts" -gt 0 ] || [ "$e_frames" -gt 0 ] || [ "$e_deliv" -gt 0 ]; then
	ok "T4c iwc->iws: at least one of iws rx_pkts/rx_frames/rx_delivered grew (+$e_pkts/+$e_frames/+$e_deliv)"
else
	bad "T4c iwc->iws: none of the three iws counters grew"
fi

# ---------------------------------------------------------------- control frames

# 24B control frame: 8B header (type,enc,sid BE,tok BE) + 16B MD5(header||"mw") signature
cat >"$WORK/send_ctrl.py" <<'PYEOF'
import hashlib, socket, struct, sys
# argv: <type> <enc> <sid> <tok> <src_ip> <dst_ip> <port>
typ, enc, sid, tok = (int(x, 0) for x in sys.argv[1:5])
src, dst, port = sys.argv[5], sys.argv[6], int(sys.argv[7])
hdr = struct.pack("!BBHI", typ, enc, sid, tok)
frame = hdr + hashlib.md5(hdr + b"mw").digest()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, port))		# source port is the tunnel port too (packets the module itself sends use sport=dport)
s.sendto(frame, (dst, port))
print("CTRL_TX type=0x%02x len=%d %s:%d -> %s:%d" % (typ, len(frame), src, port, dst, port))
PYEOF

snap "$NS_C" ctrl1 >/dev/null

say "T5 control frame event: PT_PING_REQ (0x29)"
# --count 2 (only one frame is sent) is for tolerance: extra events (such as KEEPALIVE) will not make us
# stop because --count is satisfied before the expected event arrives
ep=$(start_events "$NS_C" "$WORK/ev-ping.log" 2 3)
if wait_ready "$WORK/ev-ping.log"; then
	grep -E 'family|multicast group' "$WORK/ev-ping.log" | sed 's/^/    /'
	# PING uses the fixed protocol credentials IWAN_PING_SID/TOK = 0xFFFF/0xFFFFFFFF (not the session
	# credentials; see the iwan_ctrl_cred_ok comment in kernel/iwan.h), enc=0 matches the real client
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 0 65535 4294967295 "$OUTER_S" "$OUTER_C" "$PORT"
	sleep 0.3
	wait "$ep" 2>/dev/null
	if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-ping.log" \
	   && grep -q '^FRAME_TYPE_NAME=PT_PING_REQ$' "$WORK/ev-ping.log"; then
		ok "T5 events received IWAN_EV_CTRL_FRAME (PT_PING_REQ, frame bytes printed as hex)"
		grep -E '^(EVENT|SID|OUTER_SRC|OUTER_DST|SPORT|DPORT|FRAME_LEN|FRAME_TYPE|FRAME_TYPE_NAME|FRAME_HEX)=' \
			"$WORK/ev-ping.log" | sed 's/^/    /'
	else
		bad "T5 did not receive IWAN_EV_CTRL_FRAME for PT_PING_REQ"
		sed 's/^/    /' "$WORK/ev-ping.log"
	fi
else
	bad "T5 events did not print READY=1 (multicast group join failed)"
	sed 's/^/    /' "$WORK/ev-ping.log"
	kill "$ep" 2>/dev/null
fi
snap "$NS_C" ctrl2 >/dev/null
info "iwc rx_ctrl_frame $(val "$WORK/stats-ctrl1.txt" rx_ctrl_frame) -> $(val "$WORK/stats-ctrl2.txt" rx_ctrl_frame)"

# ---------------------------------------------------------------- T6

say "T6 keepalive: last_keepalive_ms nonzero after receiving PING (iwc)"
snap "$NS_C" ka >/dev/null
ka=$(num "$(val "$WORK/stats-ka.txt" last_keepalive_ms)")
pstate=$(val "$WORK/stats-ka.txt" peer_state_name)
info "last_keepalive_ms=$ka peer_state=${pstate:-unknown} (peer_state=1 means IWAN_PEER_UP)"
if [ "$ka" -gt 0 ]; then
	ok "T6 last_keepalive_ms=$ka (PT_PING_REQ updated the keepalive timestamp)"
else
	bad "T6 last_keepalive_ms is still 0: the kernel received PING but did not update the timestamp"
fi

# ---------------------------------------------------------------- T7

say "T7 control frame event: PT_CLOSE (0x17) -> CTRL_FRAME + PEER_CLOSE"
ep=$(start_events "$NS_C" "$WORK/ev-close.log" 3 3)
if wait_ready "$WORK/ev-close.log"; then
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x17 "$ENC" "$SID" "$TOK" "$OUTER_S" "$OUTER_C" "$PORT"
	sleep 0.3
	wait "$ep" 2>/dev/null
	if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-close.log" \
	   && grep -q '^FRAME_TYPE_NAME=PT_CLOSE$' "$WORK/ev-close.log"; then
		ok "T7a events received IWAN_EV_CTRL_FRAME for PT_CLOSE"
	else
		bad "T7a did not receive IWAN_EV_CTRL_FRAME for PT_CLOSE"
	fi
	if grep -q '^EVENT=IWAN_EV_PEER_CLOSE$' "$WORK/ev-close.log"; then
		ok "T7b events received IWAN_EV_PEER_CLOSE"
	else
		bad "T7b did not receive IWAN_EV_PEER_CLOSE"
	fi
	grep -E '^(EVENT|SID|FRAME_TYPE|FRAME_TYPE_NAME|FRAME_HEX)=' "$WORK/ev-close.log" | sed 's/^/    /'
else
	bad "T7 events did not print READY=1 (multicast group join failed)"
	sed 's/^/    /' "$WORK/ev-close.log"
	kill "$ep" 2>/dev/null
fi

# ---------------------------------------------------------------- snapshot before summary

say "counters and config summary (before SESSION_DOWN)"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns get-stats ---"
	nsx "$ns" "$CTL" get-stats 2>/dev/null | sed 's/^/    /'
done

# ---------------------------------------------------------------- --extra

if [ "$EXTRA" = 1 ]; then
	say "T9 SET_PEER: peer outer address drift (--extra)"
	nsx "$NS_S" ip addr add "$OUTER_S2/24" dev veth-s 2>/dev/null
	nsx "$NS_C" "$CTL" set-peer --outer-dst "$OUTER_S2" >"$WORK/setpeer.log" 2>&1
	rc=$?
	snap "$NS_C" peer >/dev/null
	got=$(val "$WORK/stats-peer.txt" outer_dst)
	if [ "$rc" = 0 ] && [ "$got" = "$OUTER_S2" ]; then
		ok "T9a config snapshot outer_dst=$got after SET_PEER (rc=0)"
	else
		bad "T9a SET_PEER failed or the snapshot was not updated (rc=$rc outer_dst=$got expected $OUTER_S2)"
		sed 's/^/    /' "$WORK/setpeer.log"
	fi
	ep=$(start_events "$NS_C" "$WORK/ev-peer.log" 3 3)
	if wait_ready "$WORK/ev-peer.log"; then
		nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 0 65535 4294967295 "$OUTER_S2" "$OUTER_C" "$PORT"
		sleep 0.3
		wait "$ep" 2>/dev/null
		if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-peer.log"; then
			ok "T9b control frames from the new peer address $OUTER_S2 are still received (drift took effect)"
		else
			bad "T9b control frames from the new peer address $OUTER_S2 were not received"
			sed 's/^/    /' "$WORK/ev-peer.log"
		fi
	else
		bad "T9b events did not print READY=1"
		kill "$ep" 2>/dev/null
	fi
	nsx "$NS_C" "$CTL" set-peer --outer-dst "$OUTER_S" >/dev/null 2>&1
	nsx "$NS_S" ip addr del "$OUTER_S2/24" dev veth-s 2>/dev/null

	say "T10 SET_ENABLED: stop the data plane then re-enable it (--extra)"
	snap "$NS_S" en1 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en2 >/dev/null
	g1=$(( $(num "$(val "$WORK/stats-en2.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en1.txt" rx_pkts)") ))
	nsx "$NS_C" "$CTL" set-enabled 0 >"$WORK/dis.log" 2>&1 || bad "T10 set-enabled 0 failed"
	nsx "$NS_S" "$CTL" set-enabled 0 >/dev/null 2>&1
	snap "$NS_S" en3 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en4 >/dev/null
	d1=$(( $(num "$(val "$WORK/stats-en4.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en3.txt" rx_pkts)") ))
	nsx "$NS_C" "$CTL" set-enabled 1 >/dev/null 2>&1
	nsx "$NS_S" "$CTL" set-enabled 1 >"$WORK/en.log" 2>&1 || bad "T10 set-enabled 1 failed"
	snap "$NS_S" en5 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en6 >/dev/null
	g2=$(( $(num "$(val "$WORK/stats-en6.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en5.txt" rx_pkts)") ))
	info "iws rx_pkts delta: +$g1 while enabled, +$d1 during set-enabled 0, +$g2 after re-enabling"
	if [ "$g2" -gt 0 ]; then
		ok "T10 data plane recovered after set-enabled 1 (rx_pkts +$g2)"
	else
		bad "T10 data plane did not recover after set-enabled 1 (rx_pkts +$g2)"
	fi
fi

# ---------------------------------------------------------------- T8

say "T8 SESSION_DOWN: delete device, clear credentials (iwc)"
nsx "$NS_C" "$CTL" session-down >"$WORK/down-c.log" 2>&1
rc=$?
if [ "$rc" = 0 ]; then
	ok "T8a iwan_ctl session-down returned 0"
else
	bad "T8a iwan_ctl session-down failed (rc=$rc)"
	sed 's/^/    /' "$WORK/down-c.log"
fi
if link_exists "$NS_C" "$DEV_C"; then
	bad "T8b $DEV_C still exists after SESSION_DOWN"
else
	ok "T8b $DEV_C was deleted after SESSION_DOWN"
fi
rc=$(snap "$NS_C" down)
d_sid=$(val "$WORK/stats-down.txt" sid)
d_tok=$(val "$WORK/stats-down.txt" tok)
d_err=$(val "$WORK/stats-down.txt" error)
d_ka=$(num "$(val "$WORK/stats-down.txt" last_keepalive_ms)")
info "get-stats after down: rc=$rc sid=${d_sid:-empty} tok=${d_tok:-empty} error=${d_err:-none} last_keepalive_ms=$d_ka"
if { [ -z "$d_sid" ] || [ "$d_sid" = 0 ]; } && { [ -z "$d_tok" ] || [ "$d_tok" = 0 ]; }; then
	ok "T8c second GET_STATS: credentials cleared (sid=${d_sid:-empty} tok=${d_tok:-empty})"
elif [ -n "$d_err" ]; then
	ok "T8c second GET_STATS: session does not exist (kernel reply error=$d_err)"
else
	bad "T8c second GET_STATS still reads credentials (sid=$d_sid tok=$d_tok)"
fi
nsx "$NS_S" "$CTL" session-down >/dev/null 2>&1
if link_exists "$NS_S" "$DEV_S"; then
	info "iws: $DEV_S still exists (SESSION_DOWN in that netns may have failed; it disappears with the netns during cleanup)"
else
	info "iws: $DEV_S was also deleted after SESSION_DOWN"
fi

# ---------------------------------------------------------------- results

say "results"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	echo "all passed: netlink session setup/config snapshot/bidirectional data plane/control frame events/keepalive/teardown all match the frozen ABI."
	exit 0
fi
echo "some test cases failed. Debug hints: dmesg | tail -30;"
echo "  1) family/multicast group resolution info is on iwan_ctl stderr (family \"iwan\" id / multicast group \"events\" id);"
echo "  2) config snapshot mismatch -> first check whether sid/tok order or dport/address byte order (be16/be32) is decoded wrong;"
echo "  3) T4 counters flat -> did each netns establish its own session (this script runs SESSION_UP once on each side),"
echo "     and the mapping between IWAN_A_OUTER_SRC=local / OUTER_DST=peer and the RX 5-tuple direction;"
echo "  4) T5/T7 no events -> are events delivered to the netns where the receive socket lives (this script runs events in iwc)."
exit 1
