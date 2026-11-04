#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN /dev/iwan shared memory page acceptance test -- requires root
#
#   sudo bash kernel/tests/shm_test.sh [--keep]
#
# Target: the read-only shared memory page, one per netns (kernel/iwan_shm.{h,c}, ABI in
# CONTROL-PLANE.md section 11). For every frame that passes the credential gate (data or control)
# the kernel writes the current monotonic ms into this page; PT_CLOSE(0x17) zeroes it; userspace
# polls read-only, and a timeout means link down. This script observes only /dev/iwan, not netlink timestamps.
#
# Test cases (numbers follow the given semantics; execution order below):
#   T1 after insmod /dev/iwan exists; before any session version=1, enabled=0, last_rx_ms=0
#   T2 a session in each of two netns + one inner UDP packet: RX side timestamp advances, other side untouched
#   T3 peer sends PT_CLOSE: timestamp becomes 0, peer_state=CLOSED, no netlink call at all
#   T4 SESSION_DOWN: whole page zeroed (version kept), enabled=0
#   T5 mmap then delete the netns: mapping still readable, values keep the last content, fd close clean
#   T6 timestamp monotonically non-decreasing between two consecutive inner packets
#
# Execution order = T1 T2 T6 T3 T4 T5: T6 needs "live session + non-zero timestamp", so it must run
# before T3 (CLOSE zeroing) and T4 (session teardown); T5 destroys the iwc netns, so it goes last.
#
# Topology (same as netlink_test.sh: outer veth as the wire, inner addresses on lo, iwan0 created
# on demand by SESSION_UP):
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   session --outer-src 10.100.0.1
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   session --outer-src 10.100.0.2
# Both ends use --dport 6100 and no --sport (receive port = dport, same as the old convention).
# IPv6 is disabled in both netns: when iwan0 comes up the kernel sends IPv6 RS automatically,
# which is encapsulated to the peer and adds noise to the "other side untouched" assertion.
#
# Depends only on ip / cc / python3 (no nc / tcpdump / ss needed).

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
CTL_SRC="$HERE/iwan_ctl.c"
SHM_SRC="$HERE/iwan_shm.c"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
PORT=6100		# outer tunnel port (same on both ends, receive port = dport)
INNER_PORT=9999		# inner UDP destination port (received by the iwc python3 socket)
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 => no outer fragmentation
KEEP=0

for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
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
hint() { printf '  \033[33mNOTE\033[0m %s\n' "$*"; }
die()  { printf '\033[31mFATAL: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# ---------------------------------------------------------------- helpers

SHM=""			# userspace tool path (filled after build)
CTL=""
WORK=""
WP=""			# T5 watch process (must be reaped by cleanup)

# Shared memory snapshot: <netns> <tag> -> $WORK/shm-<tag>.txt (KEY=value),
# return value = iwan_shm exit code (0 means open+read succeeded)
shm_snap() {
	nsx "$1" "$SHM" dump >"$WORK/shm-$2.txt" 2>"$WORK/shm-$2.err"
}

sval() { sed -n "s/^$2=//p" "$1" | head -n1; }		# take one field from a snapshot file

# Compare fields of two snapshots (excluding dev/method/map_len/page_size/ready runtime info)
shm_fields() { grep -v -E '^(dev|method|map_len|page_size|ready)=' "$1"; }

num() { # anything non-numeric counts as 0
	case "${1:-}" in
	''|*[!0-9]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# Inner UDP receiver: print RECV_READY=1 first, then recvfrom, to avoid a race
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

# Send one inner UDP datagram from the netns (source is bound explicitly so it routes via iwan0)
send_udp() { # <netns> <src_ip> <dst_ip> <dport>
	nsx "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"iwan-shm-test", (sys.argv[2], int(sys.argv[3])))
print("INNER_TX_OK")
' "$2" "$3" "$4"
}

# Wait for a readiness line in the log. The two markers differ; do not wait for one using the other:
#   UDP receiver -> RECV_READY=1     iwan_shm watch -> left_netns=1
wait_ready() { # <log> <pattern>
	local pat="${2:-^READY=1$}"
	for _ in $(seq 1 80); do
		grep -q "$pat" "$1" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

# Send an inner UDP packet and confirm it really reached iwc's socket (avoids ICMP return noise,
# and avoids mistaking "never sent" for "timestamp did not advance").
inner_one() { # <tag>
	local rlog="$WORK/recv-$1.log" rp
	rp=$(start_udp_recv "$NS_C" "$INNER_C" "$INNER_PORT" "$rlog")
	if ! wait_ready "$rlog" '^RECV_READY=1$'; then
		info "iwc inner receiver did not start"
		kill "$rp" 2>/dev/null
		return 1
	fi
	send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" >/dev/null 2>&1
	for _ in $(seq 1 60); do
		grep -q '^INNER_RX_FROM=' "$rlog" && break
		sleep 0.05
	done
	wait "$rp" 2>/dev/null
	grep -q '^INNER_RX_FROM=' "$rlog"
}

# Inner addresses/routes: each side adds only its own inner address on lo, peer inner addr routes via iwan0.
# Must be **repeatable**: SESSION_DOWN deletes iwan0, and routes on it disappear with it;
# if not restored after the session is recreated, inner packets are dropped by rp_filter for lack
# of a return route -- showing as "inner packet never reached the socket", while the shm timestamp
# has in fact been updated (easily misread as a kernel bug).
setup_inner_routes() { # <netns>
	local ns="$1" own peer
	if [ "$ns" = "$NS_C" ]; then own="$INNER_C"; peer="$INNER_S"
	else own="$INNER_S"; peer="$INNER_C"; fi
	nsx "$ns" ip addr add "$own/32" dev lo 2>/dev/null
	nsx "$ns" ip route replace "$peer/32" dev iwan0 2>/dev/null
}

# watch log parsing
iter_last() { sed -n 's/^iter=\([0-9]*\) .*/\1/p' "$1" | tail -n1; }
iter_rx()   { sed -n 's/^iter=[0-9]* t_ms=[0-9]* last_rx_ms=\([0-9]*\) .*/\1/p' "$1" | tail -n1; }

modrefcnt() { awk '$1 == "iwan" { print $3 }' /proc/modules 2>/dev/null | head -n1; }

dmesg_oops_count() {
	dmesg 2>/dev/null | grep -c -E 'BUG:|Oops|general protection fault|use-after-free|KASAN' || true
}

# Wait for a child to exit; timeout (0.1s granularity) returns 124
wait_pid_timeout() { # <pid> <seconds>
	local pid="$1" secs="$2" i
	for ((i = 0; i < secs * 10; i++)); do
		if ! kill -0 "$pid" 2>/dev/null; then
			wait "$pid"
			return $?
		fi
		sleep 0.1
	done
	kill -9 "$pid" 2>/dev/null
	return 124
}

# ---------------------------------------------------------------- cleanup

cleanup() {
	[ -n "$WP" ] && kill "$WP" 2>/dev/null
	if [ "$KEEP" = 0 ]; then
		if [ -n "$WORK" ] && [ -x "$CTL" ]; then
			# Let the module tear down its sessions first (also tests idempotency: dev/netns may be gone)
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		fi
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# The module may have created iwan0 in every netns; the one in init netns must be deleted
		# explicitly, otherwise the device holds the module and rmmod is refused (Module iwan is in use).
		ip link del iwan0 2>/dev/null
		rmmod iwan 2>/dev/null
		[ -n "$WORK" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- preconditions

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
command -v ip >/dev/null || die "missing iproute2"
command -v cc >/dev/null || die "missing cc"
command -v python3 >/dev/null || die "missing python3 (needed to build control frames / inner UDP)"
[ -f "$CTL_SRC" ] || die "missing $CTL_SRC"
[ -f "$SHM_SRC" ] || die "missing $SHM_SRC"

WORK="$(mktemp -d /tmp/iwan-shm-test.XXXXXX)"
CTL="$WORK/iwan_ctl"
SHM="$WORK/iwan_shm"

say "Building the kernel module and userspace tools"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "module build failed"; }
[ -f "$KO" ] || die "$KO was not generated"
WARN=$(grep -c -i 'warning' "$WORK/build.log" \
	| head -n1)
info "module build done: $KO (build log warning lines: $WARN, compiler hints from the kernel build system)"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$CTL" "$CTL_SRC" \
	>"$WORK/ctl-build.log" 2>&1 \
	|| { cat "$WORK/ctl-build.log"; die "iwan_ctl build failed"; }
info "iwan_ctl build done ($(grep -c . "$WORK/ctl-build.log") lines of compiler output, 0 means no warnings)"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$SHM" "$SHM_SRC" \
	>"$WORK/shm-build.log" 2>&1 \
	|| { cat "$WORK/shm-build.log"; die "iwan_shm build failed" ; }
info "iwan_shm build done ($(grep -c . "$WORK/shm-build.log") lines of compiler output, 0 means no warnings)"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# Control frame construction (same as netlink_test.sh: 8B header + 16B MD5(header||"mw") signature)
cat >"$WORK/send_ctrl.py" <<'PYEOF'
import hashlib, socket, struct, sys
# argv: <type> <enc> <sid> <tok> <src_ip> <dst_ip> <port>
typ, enc, sid, tok = (int(x, 0) for x in sys.argv[1:5])
src, dst, port = sys.argv[5], sys.argv[6], int(sys.argv[7])
hdr = struct.pack("!BBHI", typ, enc, sid, tok)
frame = hdr + hashlib.md5(hdr + b"mw").digest()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, port))		# the source port is the tunnel port too (the module's own packets use sport=dport)
s.sendto(frame, (dst, port))
print("CTRL_TX type=0x%02x len=%d %s:%d -> %s:%d" % (typ, len(frame), src, port, dst, port))
PYEOF

# ---------------------------------------------------------------- topology + insmod

say "Topology and load (insmod with no session parameters)"
rmmod iwan 2>/dev/null
ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
ip link del iwan0 2>/dev/null
ip netns add "$NS_C" || die "failed to create netns $NS_C"
ip netns add "$NS_S" || die "failed to create netns $NS_S"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "failed to create veth"
for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# The decapsulated inner packet source (10.9.0.x) has its return route via iwan0 while the packet
	# arrived on veth; strict mode (rp_filter=1) drops it. A new netns defaults to 0, set it
	# explicitly to avoid host sysctl influence.
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
	# Disable IPv6: when iwan0 comes up the kernel sends an IPv6 RS automatically, which is
	# encapsulated to the peer and advances its timestamp, polluting the "other side untouched" assertion.
	nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up
insmod "$KO" || die "insmod failed (check dmesg | tail for the reason)"
info "insmod done: $(grep -c '^iwan ' /proc/modules) iwan module instance(s)"

# ---------------------------------------------------------------- T1

say "T1 /dev/iwan exists; before any session version=1, enabled=0, last_rx_ms=0"

if [ -c /dev/iwan ]; then
	ok "T1a /dev/iwan exists (misc_register + devtmpfs create the node automatically)"
	ls -l /dev/iwan | sed 's/^/    /'
else
	bad "T1a /dev/iwan does not exist (misc_register failed? check dmesg)"
fi

if shm_snap "$NS_C" t1 >/dev/null; then
	F="$WORK/shm-t1.txt"
	v=$(num "$(sval "$F" version)")
	lr=$(num "$(sval "$F" last_rx_ms)")
	en=$(num "$(sval "$F" enabled)")
	ps=$(num "$(sval "$F" peer_state)")
	rf=$(num "$(sval "$F" rx_frames)")
	rc=$(num "$(sval "$F" rx_ctrl_frame)")
	info "iwc before any session: version=$v last_rx_ms=$lr enabled=$en peer_state=$ps rx_frames=$rf rx_ctrl_frame=$rc"
	if [ "$v" = 1 ] && [ "$lr" = 0 ] && [ "$en" = 0 ] && [ "$ps" = 0 ] \
	   && [ "$rf" = 0 ] && [ "$rc" = 0 ]; then
		ok "T1b initial page correct: version=1, enabled=0, last_rx_ms=0, peer_state=0, both counters 0"
	else
		bad "T1b initial page fields mismatch (expected version=1 enabled=0 last_rx_ms=0 peer_state=0 counters=0)"
		sed 's/^/    /' "$F"
	fi
else
	bad "T1b iwan_shm dump failed inside iwc"
	sed 's/^/    /' "$WORK/shm-t1.err"
fi

# The two read paths, mmap and pread, must return the same data
if nsx "$NS_C" "$SHM" dump --pread >"$WORK/shm-t1-pread.txt" 2>&1; then
	if diff -u <(shm_fields "$WORK/shm-t1.txt") \
		   <(shm_fields "$WORK/shm-t1-pread.txt") >"$WORK/shm-t1-diff.txt"; then
		ok "T1c mmap view and pread view match field by field (the node supports both read-only paths)"
	else
		bad "T1c mmap and pread views differ"
		sed 's/^/    /' "$WORK/shm-t1-diff.txt"
	fi
else
	bad "T1c iwan_shm dump --pread failed"
	sed 's/^/    /' "$WORK/shm-t1-pread.txt"
fi

# ---------------------------------------------------------------- T2

say "T2 SESSION_UP on both ends + one inner UDP packet (RX side advances, other side untouched)"

up_ok=1
for spec in "$NS_C:$OUTER_C:$OUTER_S" "$NS_S:$OUTER_S:$OUTER_C"; do
	ns="${spec%%:*}"; rest="${spec#*:}"; osrc="${rest%%:*}"; odst="${rest##*:}"
	if nsx "$ns" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
		--key "$KEY" --outer-src "$osrc" --outer-dst "$odst" \
		--dport "$PORT" --mtu "$MTU" >"$WORK/up-$ns.txt" 2>&1; then
		info "$ns SESSION_UP: $(sed -n 's/^DEVNAME=/dev=/p;s/^MTU=/mtu=/p' "$WORK/up-$ns.txt" | tr '\n' ' ')"
	else
		bad "T2 $ns SESSION_UP failed"; sed 's/^/    /' "$WORK/up-$ns.txt"; up_ok=0
	fi
	# Inner addresses/routes: both netns used to carry both addresses, so the peer address also became
	# a "local address" and inner packets short-circuited at local delivery, never leaving iwan0 (root
	# cause of T2c/T6/T3/T5a all failing though the kernel side was fine). Now always use this helper.
	setup_inner_routes "$ns"
done

if [ "$up_ok" = 1 ]; then
	ok "T2a SESSION_UP succeeded on both ends (iwan0 created on demand by the session)"
	# Session just established: timestamp starts at 0, enabled=1
	shm_snap "$NS_C" t2a >/dev/null; shm_snap "$NS_S" t2b >/dev/null
	base_c=$(num "$(sval "$WORK/shm-t2a.txt" last_rx_ms)")
	base_s=$(num "$(sval "$WORK/shm-t2b.txt" last_rx_ms)")
	en_c=$(num "$(sval "$WORK/shm-t2a.txt" enabled)")
	en_s=$(num "$(sval "$WORK/shm-t2b.txt" enabled)")
	fr_c0=$(num "$(sval "$WORK/shm-t2a.txt" rx_frames)")
	info "baseline (before the inner packet): iwc last_rx_ms=$base_c enabled=$en_c rx_frames=$fr_c0; iws last_rx_ms=$base_s enabled=$en_s"
	if [ "$base_c" = 0 ] && [ "$base_s" = 0 ] && [ "$en_c" = 1 ] && [ "$en_s" = 1 ]; then
		ok "T2b after SESSION_UP: enabled=1 on both ends, last_rx_ms=0 (new session starts from zero)"
	else
		bad "T2b initial page after SESSION_UP mismatch (expected enabled=1 and last_rx_ms=0)"
	fi

	if inner_one t2; then
		sleep 0.2
		shm_snap "$NS_C" t2c >/dev/null; shm_snap "$NS_S" t2d >/dev/null
		new_c=$(num "$(sval "$WORK/shm-t2c.txt" last_rx_ms)")
		new_s=$(num "$(sval "$WORK/shm-t2d.txt" last_rx_ms)")
		fr_c1=$(num "$(sval "$WORK/shm-t2c.txt" rx_frames)")
		info "iws->iwc after one inner packet: iwc last_rx_ms=$base_c->$new_c (rx_frames $fr_c0->$fr_c1); iws last_rx_ms=$base_s->$new_s"
		if [ "$new_c" -gt "$base_c" ] && [ "$new_c" -gt 0 ]; then
			ok "T2c RX side iwc timestamp advanced ($base_c->$new_c, monotonic ms)"
		else
			bad "T2c RX side iwc timestamp did not advance ($base_c->$new_c)"
		fi
		if [ "$new_s" = "$base_s" ]; then
			ok "T2d other side iws untouched (last_rx_ms still $new_s): pages are isolated per netns"
		else
			bad "T2d other side iws timestamp changed too ($base_s->$new_s): not isolated per netns!"
		fi
		if [ "$fr_c1" -gt "$fr_c0" ]; then
			ok "T2e page rx_frames grew in sync (+$((fr_c1 - fr_c0)), same source as /proc and GET_STATS)"
		else
			bad "T2e page rx_frames did not grow ($fr_c0->$fr_c1)"
		fi
	else
		bad "T2c inner packet did not reach iwc's socket (test environment issue; later assertions unreliable)"
	fi
else
	bad "T2 session not established, skipping later assertions"
fi

# ---------------------------------------------------------------- T6

say "T6 timestamp monotonically non-decreasing between two consecutive inner packets (run before T3/T4: needs a live session)"

if inner_one t6a; then
	sleep 0.25
	t1=$(num "$(nsx "$NS_C" "$SHM" dump 2>/dev/null | sed -n 's/^last_rx_ms=//p')")
	if inner_one t6b; then
		sleep 0.25
		t2=$(num "$(nsx "$NS_C" "$SHM" dump 2>/dev/null | sed -n 's/^last_rx_ms=//p')")
		info "two inner packets: t1=$t1 t2=$t2 (delta $((t2 - t1)) ms)"
		if [ "$t1" -gt 0 ] && [ "$t2" -ge "$t1" ]; then
			ok "T6 timestamp non-decreasing (t1=$t1 > 0, t2=$t2 >= t1)"
		else
			bad "T6 timestamp is not monotonically non-decreasing (t1=$t1 t2=$t2)"
		fi
	else
		bad "T6 second inner packet did not reach iwc"
	fi
else
	bad "T6 first inner packet did not reach iwc"
fi

# ---------------------------------------------------------------- T3

say "T3 peer sends PT_CLOSE(0x17): timestamp becomes 0, peer_state=CLOSED (observed via mmap only)"

shm_snap "$NS_C" t3a >/dev/null
pre_rx=$(num "$(sval "$WORK/shm-t3a.txt" last_rx_ms)")
pre_ctrl=$(num "$(sval "$WORK/shm-t3a.txt" rx_ctrl_frame)")
pre_state=$(num "$(sval "$WORK/shm-t3a.txt" peer_state)")
info "before CLOSE: last_rx_ms=$pre_rx peer_state=$pre_state rx_ctrl_frame=$pre_ctrl"
if [ "$pre_rx" -gt 0 ]; then
	ok "T3a precondition holds: timestamp non-zero before CLOSE ($pre_rx)"
	# Note: between here and reading the result the script calls only iwan_shm (/dev/iwan mmap),
	# no iwan_ctl netlink command at all -- the kernel writes shared memory directly on arrival.
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x17 "$ENC" "$SID" "$TOK" \
		"$OUTER_S" "$OUTER_C" "$PORT" | sed 's/^/    /'
	sleep 0.3
	shm_snap "$NS_C" t3b >/dev/null
	post_rx=$(num "$(sval "$WORK/shm-t3b.txt" last_rx_ms)")
	post_state=$(num "$(sval "$WORK/shm-t3b.txt" peer_state)")
	post_ctrl=$(num "$(sval "$WORK/shm-t3b.txt" rx_ctrl_frame)")
	post_name=$(sval "$WORK/shm-t3b.txt" peer_state_name)
	info "after CLOSE: last_rx_ms=$post_rx peer_state=$post_state ($post_name) rx_ctrl_frame=$pre_ctrl->$post_ctrl"
	if [ "$post_rx" = 0 ]; then
		ok "T3b timestamp zeroed after PT_CLOSE (userspace declares link down on this)"
	else
		bad "T3b timestamp still $post_rx after PT_CLOSE (should be 0)"
	fi
	if [ "$post_state" = 3 ]; then
		ok "T3c peer_state=CLOSED($post_state)"
	else
		bad "T3c peer_state=$post_state (expected 3=CLOSED)"
	fi
	if [ "$post_ctrl" -gt "$pre_ctrl" ]; then
		ok "T3d page rx_ctrl_frame grew ($pre_ctrl->$post_ctrl): the kernel really received this frame"
	else
		bad "T3d page rx_ctrl_frame did not grow ($pre_ctrl->$post_ctrl)"
	fi
	info "this case ran only iwan_shm dump/watch (/dev/iwan mmap), no get-stats/events call at all"
else
	bad "T3a precondition fails: timestamp was already 0 before CLOSE (T2/T6 packets not recorded)"
fi

# ---------------------------------------------------------------- T4

say "T4 SESSION_DOWN: whole page zeroed (version kept), enabled=0"

if nsx "$NS_C" "$CTL" session-down >"$WORK/down-c.txt" 2>&1; then
	ok "T4a iwc SESSION_DOWN succeeded (netlink only tears down the session; timestamp still read from shm)"
else
	bad "T4a iwc SESSION_DOWN failed"
	sed 's/^/    /' "$WORK/down-c.txt"
fi
shm_snap "$NS_C" t4 >/dev/null
F="$WORK/shm-t4.txt"
v=$(num "$(sval "$F" version)"); lr=$(num "$(sval "$F" last_rx_ms)")
en=$(num "$(sval "$F" enabled)"); ps=$(num "$(sval "$F" peer_state)")
rf=$(num "$(sval "$F" rx_frames)"); rc=$(num "$(sval "$F" rx_ctrl_frame)")
info "after SESSION_DOWN: version=$v last_rx_ms=$lr enabled=$en peer_state=$ps rx_frames=$rf rx_ctrl_frame=$rc"
if [ "$v" = 1 ] && [ "$lr" = 0 ] && [ "$en" = 0 ] && [ "$ps" = 0 ] \
   && [ "$rf" = 0 ] && [ "$rc" = 0 ]; then
	ok "T4b whole page zeroed and version=1 kept (enabled=0, timestamp/state/counters all 0)"
else
	bad "T4b page fields after SESSION_DOWN mismatch (expected version=1, all else 0)"
	sed 's/^/    /' "$F"
fi

# ---------------------------------------------------------------- T5

say "T5 mmap then delete the netns: mapping still readable, values keep the last content, fd close clean"

# T4 tore down the session; recreate one here and produce a non-zero timestamp as the "last content"
if nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" >"$WORK/up-c2.txt" 2>&1; then
	info "iwc session recreated"
	# SESSION_DOWN deleted iwan0, so the inner routes disappeared with the device => they must be restored,
	# otherwise the following inner packet is dropped by rp_filter.
	setup_inner_routes "$NS_C"
	setup_inner_routes "$NS_S"
else
	bad "T5 iwc re-SESSION_UP failed"; sed 's/^/    /' "$WORK/up-c2.txt"
fi
if inner_one t5; then
	sleep 0.2
else
	# Do not give up when the inner path is unusable: send a PT_PING_REQ directly (outer path only,
	# independent of inner routes); the kernel still refreshes this page's timestamp.
	info "T5a inner packet did not reach iwc; peer sends PT_PING_REQ to produce a timestamp instead"
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 "$ENC" "$SID" "$TOK" \
		"$OUTER_S" "$OUTER_C" "$PORT" >/dev/null 2>&1
	sleep 0.3
fi
# v1 always reads the real page value. Previously, when the inner packet was lost, v1 was forced
# to 0 as a placeholder, so T5d/T5f compared real values to a fake 0 and reported two bogus mismatches.
v1=$(num "$(sval <(nsx "$NS_C" "$SHM" dump 2>/dev/null) last_rx_ms)")
if [ "$v1" -gt 0 ]; then
	ok "T5a precondition holds: timestamp non-zero before deleting the netns ($v1)"
else
	bad "T5a timestamp was 0 before deleting the netns; cannot verify value retention"
fi

OOPS0=$(dmesg_oops_count)
R0=$(num "$(modrefcnt)")

# Key: inside iwc, open /dev/iwan + mmap, then move the process into the netns of PID 1.
# This makes "the original netns is deleted" really complete pernet exit (only the file's page ref
# remains), verifying the refcount: mapping still there => page still there.
nsx "$NS_C" "$SHM" watch --count 40 --interval 100 --leave-netns \
	>"$WORK/t5-watch.log" 2>&1 &
WP=$!
if wait_ready "$WORK/t5-watch.log" '^left_netns=1$'; then
	ok "T5b open + mmap + migrate out of the original netns succeeded (file holds the page)"
else
	bad "T5b watch did not print left_netns=1 (mmap or setns failed)"
	sed 's/^/    /' "$WORK/t5-watch.log"
	kill "$WP" 2>/dev/null
fi

R1=$(num "$(modrefcnt)")
if [ "$R1" -ge "$((R0 + 1))" ]; then
	ok "T5c the open file adds 1 to the module refcount ($R0->$R1): release is the only return point"
else
	bad "T5c module refcount did not increase by 1 ($R0->$R1): does the open file not hold a reference?"
fi

I_BEFORE=$(iter_last "$WORK/t5-watch.log")
V_BEFORE=$(iter_rx "$WORK/t5-watch.log")
if [ "${V_BEFORE:-0}" = "$v1" ]; then
	ok "T5d watch (mmap) and dump (another open) read the same value: $V_BEFORE"
else
	bad "T5d watch read ${V_BEFORE:-empty}, dump read $v1 (same open should agree)"
fi

# Delete iwc: the process is no longer in that netns now, so pernet exit really completes
if ip netns del "$NS_C" 2>/dev/null; then
	info "ip netns del $NS_C done (process migrated out; pernet exit will really complete)"
else
	bad "ip netns del $NS_C failed"
fi
sleep 0.5

# Wait for watch to print at least one more iteration: the page is still readable after deletion, no oops
I_AFTER=""
for _ in $(seq 1 60); do
	I_AFTER=$(iter_last "$WORK/t5-watch.log")
	[ -n "$I_AFTER" ] && [ "${I_BEFORE:-0}" != "" ] && [ "$I_AFTER" -gt "${I_BEFORE:-0}" ] && break
	sleep 0.1
done
V_AFTER=$(iter_rx "$WORK/t5-watch.log")
if [ -n "${I_AFTER:-}" ] && [ "${I_AFTER:-0}" -gt "${I_BEFORE:-0}" ]; then
	ok "T5e mapping still readable after deleting the netns (iter $I_BEFORE->$I_AFTER, page not freed early)"
else
	bad "T5e no new iteration after deleting the netns (iter=${I_AFTER:-empty}): mapping dead or process stuck?"
	tail -5 "$WORK/t5-watch.log" | sed 's/^/    /'
fi
if [ "${V_AFTER:-x}" = "$v1" ]; then
	ok "T5f value keeps the last content (last_rx_ms=$V_AFTER; deleting the netns does not change the page)"
else
	bad "T5f value changed after deleting the netns: $v1 -> ${V_AFTER:-empty}"
fi

# Let watch finish --count on its own (clean fd close, exits without oops)
wait_pid_timeout "$WP" 15
WRC=$?
if [ "$WRC" = 0 ]; then
	ok "T5g watch exited on its own (--count exhausted) with code 0: clean release"
else
	bad "T5g watch exited abnormally (rc=$WRC; 124 = timed out, possibly stuck in release)"
	tail -5 "$WORK/t5-watch.log" | sed 's/^/    /'
fi
WP=""

R2=$(num "$(modrefcnt)")
if [ "$R2" -lt "$R1" ]; then
	ok "T5h module refcount dropped after closing the fd ($R1->$R2)"
else
	bad "T5h module refcount did not drop after closing the fd ($R1->$R2): release not returning the ref?"
fi

if dmesg >/dev/null 2>&1; then
	OOPS1=$(dmesg_oops_count)
	if [ "${OOPS1:-0}" -le "${OOPS0:-0}" ]; then
		ok "T5i no new oops/BUG/use-after-free in dmesg throughout ($OOPS0->$OOPS1)"
	else
		bad "T5i new oops/BUG in dmesg ($OOPS0->$OOPS1): check dmesg | tail -40 first"
		dmesg | tail -20 | sed 's/^/    /'
	fi
else
	info "dmesg not readable (missing CAP_SYSLOG), skipping the oops check"
fi

# ---------------------------------------------------------------- results

say "Results (execution order T1 T2 T6 T3 T4 T5)"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$KEEP" = 1 ]; then
	echo "--keep: keep the scene $WORK (netns and module are kept too)"
fi

if [ "$FAIL" = 0 ]; then
	echo "All passed: /dev/iwan initial state, per-frame timestamp, netns isolation, PT_CLOSE zeroing,"
	echo "SESSION_DOWN zeroing, and the refcount for mmap-then-delete-netns all match CONTROL-PLANE.md section 11."
	exit 0
fi
echo "Some cases failed. Debug hints: dmesg | tail -30;"
echo "  1) T1 fails -> check whether /dev/iwan was created (misc_register/devtmpfs) and whether the page version changed;"
echo "  2) T2/T6 timestamp not advancing -> check whether the session is really established (GET_STATS sid/devname),"
echo "     whether the inner packet goes via iwan0 (ip route get), and whether the outer port/credentials match;"
echo "  3) T2d other side changes too -> check for other traffic (IPv6 RS/ICMP) hitting the peer (disable IPv6 first);"
echo "  4) T3 timestamp not 0 -> check whether PT_CLOSE sid/tok equal the session credentials (0x17 uses session creds);"
echo "  5) T5 fails -> check the watch log and dmesg, suspect netns teardown vs mmap refcount."
exit 1
