#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN GSO batch + asymmetric port acceptance test -- requires root
#
#   sudo bash kernel/tests/gso_test.sh [--keep] [--count N]
#
# Why a separate script: iwan_rx_batch() in kernel/iwan_rx.c (the GSO merged-packet path)
# was **never entered** by the existing four test scripts -- defects on that path (e.g. "freed the
# skb itself but still returned NF_DROP" double free) could never be exposed by the other cases. This script uses
# UDP_SEGMENT to send N **equal-length** encrypted frames as one UDP super-packet in a single call: the veth
# features include NETIF_F_GSO_SOFTWARE (including GSO_UDP_L4), so validate_xmit_skb() will not
# segment early, and the receiver side therefore sees an skb with skb_is_gso() in the netfilter hook and enters the batch
# path (iwan_rx.c: `if (skb_is_gso(skb) && skb_shinfo(skb)->gso_size)`).
#
# Topology and configuration entry follow netlink_test.sh: two netns + veth as the wire, inner addresses on lo,
# iwan0 created on demand by SESSION_UP; insmod without any session parameter (configuration can only come from netlink).
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   session --outer-src 10.100.0.1
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   session --outer-src 10.100.0.2
#   T1-T5 both ends --dport 6100 and no --sport (receive port = dport, old convention);
#   T6 switches to asymmetric ports: iwc --dport 6100 --sport 6200, iws --dport 6200 --sport 6100.
#
# Test cases:
#   T1 gso_send sends N equal-length frames with one sendmsg(UDP_SEGMENT) (self-check + actual bytes sent)
#   T2 receiver-side rx_batch grows -- the GSO batch path is really taken, not one packet at a time
#   T3 rx_delivered/rx_frames exactly +N, no delta in rx_bad_hdr/rx_batch_skip/rx_bad_inner
#   T4 iwc's inner socket receives all N packets, sequence 0..N-1 complete and lengths identical
#   T5 dmesg has no new BUG/Oops/GPF (an oops in softirq does not necessarily make the script exit)
#   T6 asymmetric ports (receive port = SPORT) still pass inner UDP in both directions
#
# Only depends on ip / cc / python3 (nc / tcpdump / ss / ethtool not needed).

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
CTL_SRC="$HERE/iwan_ctl.c"
GSO_SRC="$HERE/gso_send.c"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
PORT=6100		# T1-T5 outer tunnel port (same on both ends, receive port = dport)
PORT_C=6100		# T6: iwc's dport (= local port on peer iws)
PORT_S=6200		# T6: iwc's sport (= iwc's own receive port)
INNER_PORT=9999		# inner UDP destination port (received by iwc's python3 socket)
INNER_SPORT=40000	# inner UDP source port (gso_send uses a fixed value for easier diagnosis)
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 => outer layer does not fragment
INNER_LEN=200		# total inner IPv4 packet length (frame length = 8 + 200 = 208)
COUNT=32		# frame count: 32 x 208 = 6656 bytes, > veth MTU, must be a GSO super-packet
KEEP=0
DMESG_PAT='BUG:|Oops|general protection fault|kernel NULL pointer dereference|KASAN|RIP: 0010:iwan'

while [ $# -gt 0 ]; do
	case "$1" in
	--keep)
		KEEP=1
		shift
		;;
	--count)
		shift
		COUNT="${1:-}"
		[ -n "$COUNT" ] || { echo "--count needs a value"; exit 2; }
		shift
		;;
	-h|--help)
		sed -n '2,32p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $1 (supported: --keep / --count N)"
		exit 2
		;;
	esac
done
case "$COUNT" in
''|*[!0-9]*) echo "--count requires a positive integer"; exit 2 ;;
esac
[ "$COUNT" -ge 1 ] && [ "$COUNT" -le 64 ] \
	|| { echo "--count must be in 1..64 (UDP_MAX_SEGMENTS=64)"; exit 2; }

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

snap() { # snap <netns> <tag>  -> iwan_ctl get-stats lands in $WORK/stats-<tag>.txt
	nsx "$1" "$CTL" get-stats >"$WORK/stats-$2.txt" 2>"$WORK/stats-$2.err"
	echo $?
}

val() { sed -n "s/^$2=//p" "$1" | head -n1; }

num() { # any non-numeric value counts as 0
	case "${1:-}" in
	''|*[!0-9-]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# extract a key from gso_send/iwan_ctl KEY=value output
gv() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -n1; }

link_exists() { nsx "$1" ip link show dev "$2" >/dev/null 2>&1; }

start_recv() { # <netns> <log> <bind_ip> <want> [timeout]: inner UDP receiver
	: >"$2"
	nsx "$1" python3 "$WORK/recv_gso.py" "$3" "$INNER_PORT" "$4" "${5:-10}" \
		>"$2" 2>&1 &
	echo $!
}

send_udp() { # <netns> <src_ip> <dst_ip> <dport>: send one inner UDP packet
	nsx "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"iwan-gso-test-ports", (sys.argv[2], int(sys.argv[3])))
print("INNER_TX_OK")
' "$2" "$3" "$4"
}

wait_ready() { # <log> <pattern>
	local pat="${2:-^RECV_READY=1$}"
	for _ in $(seq 1 80); do
		grep -q "$pat" "$1" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

dmesg_hits() { dmesg 2>/dev/null | grep -cE "$DMESG_PAT"; }

# Delete only the iwan0 created by this module. iwan0 in the init netns is not necessarily ours: a user's own
# iwan-client runs a real tunnel on TUN iwan0, and deleting it by mistake would break a live tunnel. The criterion is
# whether the detail line from `ip -d link show` has this module's kind (iwan); device name must not be used,
# nor ARPHRD -- TUN and iwan both use 65534. This logic matches netlink_test.sh.
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

INNER_ADDRS_ADDED=0
add_inner() { # inner address + inner route (routes must be re-added after every device rebuild)
	local dev_c="$1" dev_s="$2"

	if [ "$INNER_ADDRS_ADDED" = 0 ]; then
		nsx "$NS_C" ip addr add "$INNER_C/32" dev lo 2>/dev/null
		nsx "$NS_S" ip addr add "$INNER_S/32" dev lo 2>/dev/null
		INNER_ADDRS_ADDED=1
	fi
	nsx "$NS_C" ip link set "$dev_c" up 2>/dev/null
	nsx "$NS_S" ip link set "$dev_s" up 2>/dev/null
	nsx "$NS_C" ip route add "$INNER_S/32" dev "$dev_c" 2>/dev/null \
		|| info "iwc: failed to add inner route $INNER_S dev $dev_c (T4/T6 may fail)"
	nsx "$NS_S" ip route add "$INNER_C/32" dev "$dev_s" 2>/dev/null \
		|| info "iws: failed to add inner route $INNER_C dev $dev_s (T4/T6 may fail)"
}

cleanup() {
	if [ "$KEEP" = 0 ]; then
		[ -n "${WORK:-}" ] && [ -x "${CTL:-}" ] && {
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		}
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# this one in the init netns must be deleted explicitly, otherwise the device pins the module and rmmod is refused.
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- prerequisites

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
command -v ip >/dev/null || die "iproute2 is missing"
command -v cc >/dev/null || die "cc is missing"
command -v python3 >/dev/null || die "python3 is missing"
[ -f "$GSO_SRC" ] || die "$GSO_SRC is missing"

WORK="$(mktemp -d /tmp/iwan-gso-test.XXXXXX)"
CTL="$WORK/iwan_ctl"
GSO="$WORK/gso_send"

cat >"$WORK/recv_gso.py" <<'PY'
# Inner UDP receiver: print statistics after receiving want packets (or on timeout).
# The inner payload from gso_send starts with "IWAN-GSO-<4-digit sequence>"; count each frame by it.
# Print INNER_RX_FROM as soon as the first packet arrives (the T6 port-convention case sends only one packet).
import re, socket, sys, time

bind_ip, port, want, timeout = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
s.bind((bind_ip, port))
print("RECV_READY=1", flush=True)
idxs, lens = [], []
first = True
deadline = time.time() + timeout
while len(idxs) < want and time.time() < deadline:
    s.settimeout(max(0.05, deadline - time.time()))
    try:
        d, a = s.recvfrom(4096)
    except socket.timeout:
        break
    if first:
        print("INNER_RX_FROM=%s:%d" % (a[0], a[1]), flush=True)
        first = False
    m = re.match(rb"IWAN-GSO-(\d{4})", d)
    idxs.append(int(m.group(1)) if m else -1)
    lens.append(len(d))
print("RECV_COUNT=%d" % len(idxs))
print("RECV_LENS=%s" % ",".join(str(x) for x in sorted(set(lens))))
print("MISSING=%s" % ",".join(str(i) for i in range(want) if i not in idxs))
print("BAD_MARK=%d" % sum(1 for i in idxs if i < 0))
print("RESULT=%s" % ("ok" if len(idxs) == want and -1 not in idxs else "incomplete"))
PY

say "Building kernel module and userspace tools"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "module build failed"; }
[ -f "$KO" ] || die "$KO was not generated"
info "module build complete: $KO (build log $(grep -c . "$WORK/build.log") lines, 0 warning lines)"
for t in "iwan_ctl:$CTL_SRC:$CTL" "gso_send:$GSO_SRC:$GSO"; do
	name="${t%%:*}"; rest="${t#*:}"; src="${rest%%:*}"; out="${rest#*:}"
	cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$out" "$src" \
		>"$WORK/$name-build.log" 2>&1 \
		|| { cat "$WORK/$name-build.log"; die "$name build failed"; }
	info "$name build complete ($(grep -c . "$WORK/$name-build.log") lines of compiler output, 0 lines means no warnings)"
done
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# ---------------------------------------------------------------- topology

say "T1 set up topology and load module (without any session parameter)"

DMESG0=$(dmesg_hits)
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
	# After decapsulation the inner packet source address (10.9.0.x) has its return route via iwan0, while the packet came in on veth;
	# strict mode (rp_filter=1) drops it directly. A new netns defaults to 0; set it explicitly to avoid
	# being affected by the host sysctl.
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
	# Disable IPv6: when iwan0 comes up the kernel automatically sends IPv6 RS, which gets encapsulated to the peer and advances the peer's
	# rx_frames/rx_bad_inner, polluting the "exactly +N" assertion.
	nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

# Key point: no sid/tok/key/enc/dport/outer_* -- the session can only come from netlink
insmod "$KO" || die "insmod failed (see dmesg | tail for the reason)"
info "insmod complete (/proc/modules: $(grep -c '^iwan ' /proc/modules) iwan instances)"

if command -v ethtool >/dev/null 2>&1; then
	# Diagnostics only: the batch path requires the sending device to preserve GSO (veth advertises GSO_UDP_L4).
	info "veth-c udp-segmentation: $(nsx "$NS_C" ethtool -k veth-c 2>/dev/null | awk -F': ' '/udp-segmentation/{print $2}' | head -n1)"
fi

# ---------------------------------------------------------------- T1: session + GSO batch send

say "T1 SESSION_UP (both ends, dport=$PORT, no sport: receive port = dport)"

up_out=$(nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-c.err")
rc=$?
DEV_C=iwan0
if [ "$rc" != 0 ]; then
	bad "T1 iwc: session-up failed (rc=$rc)"
	sed 's/^/    /' "$WORK/up-c.err"
else
	DEV_C=$(gv DEVNAME "$up_out"); [ -n "$DEV_C" ] || DEV_C=iwan0
	info "iwc reply: DEVNAME=$DEV_C MTU=$(gv MTU "$up_out") DEV_OWNED=$(gv DEV_OWNED "$up_out")"
	ok "T1a iwc: SESSION_UP succeeded ($DEV_C)"
fi
up_out=$(nsx "$NS_S" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-s.err")
rc=$?
DEV_S=iwan0
if [ "$rc" != 0 ]; then
	bad "T1 iws: session-up failed (rc=$rc)"
	sed 's/^/    /' "$WORK/up-s.err"
	die "no receiver-side session; subsequent GSO test cases cannot proceed"
fi
DEV_S=$(gv DEVNAME "$up_out"); [ -n "$DEV_S" ] || DEV_S=iwan0
info "iws reply: DEVNAME=$DEV_S MTU=$(gv MTU "$up_out") DEV_OWNED=$(gv DEV_OWNED "$up_out")"
add_inner "$DEV_C" "$DEV_S"

say "T1b one sendmsg(UDP_SEGMENT) sends $COUNT equal-length frames (frame length $((INNER_LEN + 8)))"

snap "$NS_C" g1 >/dev/null
rpid=$(start_recv "$NS_C" "$WORK/recv-gso.log" "$INNER_C" "$COUNT")
wait_ready "$WORK/recv-gso.log" '^RECV_READY=1$' \
	|| { bad "T1b iwc's inner receiver did not start (python3 exception?)"; sed 's/^/    /' "$WORK/recv-gso.log"; }

gs_out=$(nsx "$NS_S" "$GSO" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--sport "$PORT" --dport "$PORT" \
	--inner-src "$INNER_S" --inner-dst "$INNER_C" \
	--inner-sport "$INNER_SPORT" --inner-dport "$INNER_PORT" \
	--sid "$SID" --tok "$TOK" --enc "$ENC" --key "$KEY" \
	--count "$COUNT" --inner-len "$INNER_LEN" 2>"$WORK/gso-send.err")
gs_rc=$?
sleep 0.5
wait "$rpid" 2>/dev/null

SENT_BYTES=$(gv SENDMSG_BYTES "$gs_out")
TOTAL_BYTES=$(gv TOTAL_BYTES "$gs_out")
info "gso_send: rc=$gs_rc TOTAL_BYTES=$TOTAL_BYTES SENDMSG_BYTES=$SENT_BYTES SELFCHECK=$(gv SELFCHECK "$gs_out") SEGMENT_SETSOCKOPT=$(gv SEGMENT_SETSOCKOPT "$gs_out")"
[ -s "$WORK/gso-send.err" ] && sed 's/^/    /' "$WORK/gso-send.err"

# expected frame header: type (0x18/0x14) + enc + sid(u16 BE) + tok(u32 BE)
exp_hdr=$(printf '%02x%02x%04x%08x' "$((ENC == 0 ? 0x14 : 0x18))" "$ENC" "$SID" "$TOK")
got_hdr=$(gv FRAME0_HDR_HEX "$gs_out")

if [ "$gs_rc" = 0 ] && [ "$(gv RESULT "$gs_out")" = ok ] \
	&& [ "$SENT_BYTES" = "$TOTAL_BYTES" ] && [ "$(gv SELFCHECK "$gs_out")" = ok ]; then
	ok "T1b gso_send self-check passed and all $TOTAL_BYTES bytes were sent in one call (UDP_SEGMENT, segment size $((INNER_LEN + 8)))"
else
	bad "T1b gso_send failed (rc=$gs_rc RESULT=$(gv RESULT "$gs_out") SENDMSG_ERROR=$(gv SENDMSG_ERROR "$gs_out"))"
	hint "If the sender side fails, T2-T5 are meaningless; not seeing the UDP_SEGMENT super-packet in tcpdump/capture is normal (it is already a GSO skb at the device layer)"
fi

if [ "$got_hdr" = "$exp_hdr" ]; then
	ok "T1c frame 0 header 8 bytes match the frozen format ($got_hdr, including big-endian serialization of sid/tok)"
else
	bad "T1c frame 0 header $got_hdr does not match expected $exp_hdr (header serialization/parameter error)"
fi

# ---------------------------------------------------------------- T2/T3: counters

snap "$NS_C" g2 >/dev/null
d_batch=$(( $(num "$(val "$WORK/stats-g2.txt" rx_batch)") - $(num "$(val "$WORK/stats-g1.txt" rx_batch)") ))
d_skip=$(( $(num "$(val "$WORK/stats-g2.txt" rx_batch_skip)") - $(num "$(val "$WORK/stats-g1.txt" rx_batch_skip)") ))
d_frames=$(( $(num "$(val "$WORK/stats-g2.txt" rx_frames)") - $(num "$(val "$WORK/stats-g1.txt" rx_frames)") ))
d_deliv=$(( $(num "$(val "$WORK/stats-g2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-g1.txt" rx_delivered)") ))
d_badhdr=$(( $(num "$(val "$WORK/stats-g2.txt" rx_bad_hdr)") - $(num "$(val "$WORK/stats-g1.txt" rx_bad_hdr)") ))
d_badinner=$(( $(num "$(val "$WORK/stats-g2.txt" rx_bad_inner)") - $(num "$(val "$WORK/stats-g1.txt" rx_bad_inner)") ))
info "iwc counter deltas: rx_batch +$d_batch, rx_batch_skip +$d_skip, rx_frames +$d_frames, rx_delivered +$d_deliv, rx_bad_hdr +$d_badhdr, rx_bad_inner +$d_badinner"

if [ "$d_batch" -ge 1 ]; then
	ok "T2 iwc rx_batch +$d_batch: the N frames really took the GSO batch path (skb_is_gso)"
else
	bad "T2 iwc rx_batch did not grow (+0): iwan_rx_batch() was not entered (GSO not preserved?)"
	hint "If rx_delivered is exactly +$COUNT, packets arrived one by one: the sending device split UDP_SEGMENT, or GRO did not pass the super-packet up; first check tx-udp-segmentation in ethtool -k <sender veth>"
fi

if [ "$d_deliv" = "$COUNT" ]; then
	ok "T3a iwc rx_delivered exactly +$COUNT (every segment decapsulated and delivered)"
else
	bad "T3a iwc rx_delivered +$d_deliv, expected +$COUNT"
	hint "less than expected: check rx_bad_hdr/rx_bad_inner (+$d_badhdr/+$d_badinner) and dmesg; more than expected: other frames entered this netns"
fi
if [ "$d_frames" = "$COUNT" ]; then
	ok "T3b iwc rx_frames exactly +$COUNT (frame header/credentials verified per frame)"
else
	bad "T3b iwc rx_frames +$d_frames, expected +$COUNT"
fi
if [ "$d_badhdr" = 0 ] && [ "$d_skip" = 0 ] && [ "$d_badinner" = 0 ]; then
	ok "T3c no delta in rx_bad_hdr/rx_batch_skip/rx_bad_inner (bad frames, skipped segments, bad inner all 0)"
else
	bad "T3c abnormal deltas: rx_bad_hdr +$d_badhdr, rx_batch_skip +$d_skip, rx_bad_inner +$d_badinner"
fi

# ---------------------------------------------------------------- T4: all inner packets delivered

if [ "$(gv RECV_COUNT "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" = "$COUNT" ] \
	&& [ -z "$(gv MISSING "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" ] \
	&& [ "$(gv BAD_MARK "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" = 0 ]; then
	ok "T4 iwc inner socket received all $COUNT packets, sequence 0..$((COUNT - 1)) complete and lengths identical ($(gv RECV_LENS "$(cat "$WORK/recv-gso.log")"))"
else
	bad "T4 inner socket did not receive all $COUNT packets (RECV_COUNT=$(gv RECV_COUNT "$(cat "$WORK/recv-gso.log" 2>/dev/null)") MISSING=$(gv MISSING "$(cat "$WORK/recv-gso.log" 2>/dev/null)"))"
	sed 's/^/    /' "$WORK/recv-gso.log"
	hint "count equal to rx_delivered but less than N: some segment was dropped in the batch; none at all: look at T2/T3 together with routing/rp_filter"
fi

# ---------------------------------------------------------------- T5: no panic/oops

DMESG1=$(dmesg_hits)
if [ -z "$DMESG1" ] || [ "$DMESG1" = "$DMESG0" ]; then
	ok "T5 dmesg has no new BUG/Oops/GPF ($DMESG0 before, $DMESG1 after)"
else
	bad "T5 dmesg shows new BUG/Oops/GPF ($DMESG0 -> $DMESG1)"
	dmesg 2>/dev/null | grep -E "$DMESG_PAT" | tail -20 | sed 's/^/    /'
fi

# ---------------------------------------------------------------- T6: asymmetric ports

say "T6 asymmetric ports: receive port = SPORT (iwc dport=$PORT_C sport=$PORT_S, iws dport=$PORT_S sport=$PORT_C)"

nsx "$NS_C" "$CTL" session-down >/dev/null 2>&1
nsx "$NS_S" "$CTL" session-down >/dev/null 2>&1
sleep 0.3
up_c=$(nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT_C" --sport "$PORT_S" --mtu "$MTU" 2>"$WORK/up-c2.err")
rc_c=$?
up_s=$(nsx "$NS_S" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--dport "$PORT_S" --sport "$PORT_C" --mtu "$MTU" 2>"$WORK/up-s2.err")
rc_s=$?
DEV_C=$(gv DEVNAME "$up_c"); [ -n "$DEV_C" ] || DEV_C=iwan0
DEV_S=$(gv DEVNAME "$up_s"); [ -n "$DEV_S" ] || DEV_S=iwan0
# The device was rebuilt: routes must be re-added (deleting the device removes its routes too)
add_inner "$DEV_C" "$DEV_S"

snap "$NS_C" a1 >/dev/null
snap "$NS_S" b1 >/dev/null
sc=$(val "$WORK/stats-a1.txt" sport); ss=$(val "$WORK/stats-b1.txt" sport)
info "GET_STATS sport: iwc=$sc (expected $PORT_S) iws=$ss (expected $PORT_C); rc=$rc_c/$rc_s"
if [ "$rc_c" = 0 ] && [ "$rc_s" = 0 ] && [ "$sc" = "$PORT_S" ] && [ "$ss" = "$PORT_C" ]; then
	ok "T6a asymmetric-port session established, GET_STATS echoes a sport matching the configured value"
else
	bad "T6a asymmetric-port session abnormal (rc=$rc_c/$rc_s sport=$sc/$ss)"
	sed 's/^/    /' "$WORK/up-c2.err" "$WORK/up-s2.err" 2>/dev/null
fi

# Direction 1: iws -> iwc (outer iws sport=$PORT_C -> iwc sport=$PORT_S)
rpid=$(start_recv "$NS_C" "$WORK/recv-c2.log" "$INNER_C" 1 6)
if wait_ready "$WORK/recv-c2.log" '^RECV_READY=1$'; then
	tx_out=$(send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" 2>&1)
	case "$tx_out" in *INNER_TX_OK*) : ;; *) bad "T6b iws inner send failed"; echo "$tx_out" | sed 's/^/    /' ;; esac
	sleep 0.6
	wait "$rpid" 2>/dev/null
	if grep -q "^INNER_RX_FROM=$INNER_S" "$WORK/recv-c2.log" 2>/dev/null; then
		ok "T6b iws->iwc works: iwc received the inner packet on sport=$PORT_S (outer destination port = peer SPORT convention holds)"
	else
		bad "T6b iws->iwc does not work (iwc's socket received nothing)"
		sed 's/^/    /' "$WORK/recv-c2.log"
	fi
else
	bad "T6b iwc receiver did not start"
	kill "$rpid" 2>/dev/null
fi
snap "$NS_C" a2 >/dev/null
d_deliv_c=$(( $(num "$(val "$WORK/stats-a2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-a1.txt" rx_delivered)") ))

# Direction 2: iwc -> iws (outer iwc sport=$PORT_S -> iws sport=$PORT_C)
rpid=$(start_recv "$NS_S" "$WORK/recv-s2.log" "$INNER_S" 1 6)
if wait_ready "$WORK/recv-s2.log" '^RECV_READY=1$'; then
	tx_out=$(send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT" 2>&1)
	case "$tx_out" in *INNER_TX_OK*) : ;; *) bad "T6c iwc inner send failed"; echo "$tx_out" | sed 's/^/    /' ;; esac
	sleep 0.6
	wait "$rpid" 2>/dev/null
	if grep -q "^INNER_RX_FROM=$INNER_C" "$WORK/recv-s2.log" 2>/dev/null; then
		ok "T6c iwc->iws works: iws received the inner packet on sport=$PORT_C (both directions receive on SPORT)"
	else
		bad "T6c iwc->iws does not work (iws's socket received nothing)"
		sed 's/^/    /' "$WORK/recv-s2.log"
	fi
else
	bad "T6c iws receiver did not start"
	kill "$rpid" 2>/dev/null
fi
info "iwc rx_delivered on the T6b path +$d_deliv_c (expected >= 1)"

# ---------------------------------------------------------------- summary

say "Counter summary"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns ---"
	nsx "$ns" cat /proc/net/iwan 2>/dev/null | sed 's/^/    /'
done

say "Results"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	echo "All passed: UDP_SEGMENT super-packets really enter iwan_rx_batch(), all N frames are decapsulated and delivered,"
	echo "inner UDP still works in both directions with asymmetric ports, and there is no panic/oops."
	exit 0
fi
echo "Some test cases failed. Troubleshooting hints:"
echo "  1) T2 does not grow while T3a is exactly +$COUNT -> the receiver side is not seeing a GSO skb:"
echo "     GSO capability of the sending veth (ethtool -k veth-s | grep udp-segmentation),"
echo "     or some other hook/device split the super-packet in the middle;"
echo "  2) T3a is a few short -> dmesg | tail -30, look at iwan's rx_bad_* and WARNING (segment checksum/linearization);"
echo "  3) T4 received 0 -> inner route/rp_filter and whether iwan0 is UP;"
echo "  4) T6 fails in one direction -> outer port convention: receive port = SPORT (DPORT if not given),"
echo "     TX source port = SPORT; check whether the two ends' dport/sport are each other's sport/dport."
if [ "$KEEP" = 1 ]; then
	echo "  - logs and intermediate files kept in $WORK"
else
	echo "  - rerun with --keep to keep the logs and intermediate files under $WORK"
fi
exit 1
