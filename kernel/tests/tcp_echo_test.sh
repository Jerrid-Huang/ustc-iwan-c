#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN zero-userspace data path -- local end-to-end acceptance (needs root)
#
#   sudo bash kernel/tests/tcp_echo_test.sh [--keep] [--quick]
#
# Topology (two netns connected by veth as the cable, each with a kernel virtual NIC iwan0):
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#   iwc: ip route add 10.9.0.2/32 dev iwan0   (egress handed to iwan0 for encapsulation)
#   iws: ip route add 10.9.0.1/32 dev iwan0
#
# Egress: iwan0's ndo_start_xmit gets a finished IP packet that is "already segmented by the stack, checksum already computed" ->
#       XOR -> 8B frame header -> UDP -> outer IP -> ip_local_out via veth.
# Ingress: the module matches the outer 4-tuple at PRE_ROUTING(prio=-300) -> when needed the hook inlines
#       ip_defrag to reassemble the outer packet -> check sid/tok -> strip header -> XOR restore -> hand to kernel stack.
#
# Test cases:
#   T1 TCP small-packet echo (three-way handshake + short segment, non-GSO path)
#   T2 TCP 4 MiB echo (GSO segmentation + full MTU path)
#   T3 UDP 8x3000B echo (inner fragmentation: iwan0 mtu 1400 => 3 inner fragments)
#   T4 outer fragmentation: df=0 + veth mtu 1000 => both layers fragmented, verify the hook's inline reassembly
#   T5 negative: crafted frames verify the credential gate (wrong tok is rejected at the frame header, only correct tok reaches inner validation)
# Also watch Tcp InCsumErrors / RetransSegs and the module counters throughout.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
ECHO_PY="$HERE/echo_net.py"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
PORT=6100
SID=4660
TOK=3405691582
KEY=0011223344556677
MTU_INNER=1400          # iwan0 mtu: 1400 + 36 = 1436 < 1500 => no outer fragmentation
KEEP=0
QUICK=0

for a in "$@"; do
	case "$a" in
	--keep)  KEEP=1 ;;
	--quick) QUICK=1 ;;
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
die()  { printf '\033[31mfatal: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# A single counter in /proc/net/iwan (reads the view of that netns)
ctr() { nsx "$1" awk -v k="$2" '$1==k{print $2}' /proc/net/iwan 2>/dev/null; }
# Fields of the /proc/net/snmp Tcp: line ($13=RetransSegs, $16=InCsumErrors)
tcpsnmp() { nsx "$1" awk -v f="$2" '/^Tcp:/{v=$f} END{print v+0}' /proc/net/snmp; }

# Only delete the iwan0 created by this module. The iwan0 in the init netns is not necessarily ours: this project's
# iwan-client runs a real tunnel over TUN iwan0, so deleting it by mistake would break the live tunnel. The criterion is
# whether the detail line of `ip -d link show` shows the kind of this module (iwan); the device name does not tell,
# and neither does ARPHRD -- TUN and iwan are both 65534.
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

cleanup() {
	if [ "$KEEP" = 0 ]; then
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# The module creates iwan0 in every netns; the one in the init netns must be removed explicitly,
		# otherwise the device holds a reference to the module and the kernel refuses rmmod (Module iwan is in use).
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "needs root: sudo bash $0"
[ -f "$ECHO_PY" ] || die "missing $ECHO_PY"
command -v ip >/dev/null || die "missing iproute2"

WORK="$(mktemp -d /tmp/iwan-tcp-test.XXXXXX)"
say "build kernel module"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "module build failed"; }
[ -f "$KO" ] || die "$KO was not generated"
info "build done: $KO"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

say "load module and build topology"
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_S" outer_dst="$OUTER_C" \
	dport="$PORT" sid="$SID" tok="$TOK" key="$KEY" enc=1 batch=1 df=1 \
	|| die "insmod failed (see dmesg | tail for the reason)"
info "insmod done (any_dir=1: both directions on this host share one RX configuration)"

ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
ip netns add "$NS_C" || die "failed to create netns $NS_C"
ip netns add "$NS_S" || die "failed to create netns $NS_S"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "failed to create veth"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# Reverse path filtering: the return route for the decapsulated inner packet source (10.9.0.x) goes via iwan0,
	# while the packet came in from veth, so strict mode (rp_filter=1) would drop it outright.
	# The kernel default in a fresh netns is already 0; set it explicitly here so the host sysctl does not influence it.
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

# iwan0 is provided by rtnl_link_ops and must be created explicitly (no longer auto-created by pernet init)
for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: failed to create iwan0"
done
nsx "$NS_C" ip link set iwan0 mtu "$MTU_INNER" up
nsx "$NS_S" ip link set iwan0 mtu "$MTU_INNER" up

# Per-netns egress outer endpoint (one module instance serves all netns, so differing directions can only be configured per netns)
nsx "$NS_C" ip addr add "$INNER_C/32" dev lo
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S' > /proc/net/iwan" \
	|| die "$NS_C: failed to write /proc/net/iwan"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C' > /proc/net/iwan" \
	|| die "$NS_S: failed to write /proc/net/iwan"

nsx "$NS_C" ip route add "$INNER_S/32" dev iwan0 || die "$NS_C: failed to add inner route"
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "$NS_S: failed to add inner route"

info "topology ready: $NS_C $INNER_C <-> $NS_S $INNER_S (outer $OUTER_C/$OUTER_S port $PORT)"
nsx "$NS_C" head -4 /proc/net/iwan | sed 's/^/    /'

# ---------------------------------------------------------------- test framework

run_tcp() { # run_tcp <name> <bytes> [timeout]
	local name="$1" bytes="$2" to="${3:-25}"
	local slog="$WORK/server-$name.log" clog="$WORK/client-$name.log"
	nsx "$NS_S" python3 "$ECHO_PY" server --bind "$INNER_S" --port "$PORT" \
		--timeout "$((to + 5))" >"$slog" 2>&1 &
	local spid=$!
	for _ in $(seq 1 50); do grep -q SERVER_READY "$slog" 2>/dev/null && break; sleep 0.1; done
	nsx "$NS_C" python3 "$ECHO_PY" client --host "$INNER_S" --port "$PORT" \
		--bytes "$bytes" --timeout "$to" >"$clog" 2>&1
	local rc=$?
	wait $spid 2>/dev/null
	echo "    client: $(tr '\n' ' ' <"$clog")"
	echo "    server: $(tr '\n' ' ' <"$slog")"
	return $rc
}

run_udp() { # run_udp <name> <size> <count>
	local name="$1" size="$2" count="$3"
	local slog="$WORK/server-$name.log" clog="$WORK/client-$name.log"
	nsx "$NS_S" python3 "$ECHO_PY" server --udp --bind "$INNER_S" --port "$PORT" \
		--count "$count" --timeout 15 >"$slog" 2>&1 &
	local spid=$!
	for _ in $(seq 1 50); do grep -q SERVER_READY "$slog" 2>/dev/null && break; sleep 0.1; done
	nsx "$NS_C" python3 "$ECHO_PY" client --udp --host "$INNER_S" --port "$PORT" \
		--size "$size" --count "$count" --timeout 15 >"$clog" 2>&1
	local rc=$?
	wait $spid 2>/dev/null
	echo "    client: $(tr '\n' ' ' <"$clog")"
	echo "    server: $(tr '\n' ' ' <"$slog")"
	return $rc
}

# ---------------------------------------------------------------- T1/T2

say "T1 TCP small-packet echo (handshake + short segment)"
if run_tcp T1 65536; then
	ok "T1 TCP 64 KiB bidirectional echo matches"
else
	bad "T1 TCP 64 KiB echo failed"
fi

if [ "$QUICK" = 0 ]; then
	say "T2 TCP 4 MiB echo (GSO segmentation + full MTU)"
	rc_c=$(tcpsnmp "$NS_C" 16); rt_c=$(tcpsnmp "$NS_C" 13)
	if run_tcp T2 4194304; then
		ok "T2 TCP 4 MiB bidirectional echo matches"
	else
		bad "T2 TCP 4 MiB echo failed"
	fi
	dc=$(( $(tcpsnmp "$NS_C" 16) - rc_c )); dr=$(( $(tcpsnmp "$NS_C" 13) - rt_c ))
	info "client netns: Tcp InCsumErrors +$dc, RetransSegs +$dr"
	[ "$dc" -eq 0 ] && ok "T2 no TCP checksum errors (XOR did not break the checksum)" \
			 || bad "T2 saw $dc TCP checksum errors"
	[ "$dr" -le 20 ] && ok "T2 $dr retransmissions (normal range)" || bad "T2 too many retransmissions: $dr"
fi

# ---------------------------------------------------------------- T3

say "T3 UDP 8x3000B echo (inner fragmentation)"
d_before=$(ctr "$NS_S" rx_delivered)
if run_udp T3 3000 8; then
	ok "T3 eight 3000B datagrams echoed consistently (inner fragmentation + kernel reassembly)"
else
	bad "T3 UDP large-packet echo failed"
fi
d_after=$(ctr "$NS_S" rx_delivered)
info "server rx_delivered $d_before -> $d_after (>1 means the inner packet was indeed fragmented and reassembled)"
[ "$((d_after - d_before))" -gt 8 ] && ok "T3 inner fragmentation path covered (multiple fragments per packet)" \
				   || bad "T3 inner packet was not fragmented (mtu setting not in effect?)"

# ---------------------------------------------------------------- T4

say "T4 outer fragmentation: df=0 + veth mtu 1000 (both layers fragmented)"
echo 0 > /sys/module/iwan/parameters/df
nsx "$NS_C" ip link set veth-c mtu 1000
nsx "$NS_S" ip link set veth-s mtu 1000
r_before=$(ctr "$NS_S" rx_reasm)
if run_udp T4 3000 8; then
	ok "T4 echo matches under outer fragmentation (hook inline ip_defrag reassembly succeeded)"
else
	bad "T4 outer-fragmentation echo failed"
fi
r_after=$(ctr "$NS_S" rx_reasm)
info "server rx_reasm $r_before -> $r_after"
if [ "$((r_after - r_before))" -gt 0 ]; then
	ok "T4 outer reassembly happened in the hook (rx_reasm grew)"
elif lsmod | grep -q '^nf_conntrack\b'; then
	# the conntrack nf_defrag_ipv4 hook at prio=-400 reassembles the outer packet first and passes it down,
	# so the inline defrag of this module becomes redundant (harmless). In that case judge by functional correctness.
	info "nf_conntrack is loaded: the outer packet may already be reassembled by the -400 defrag hook (this module's inline reassembly is redundant but harmless)"
	ok "T4 functionally correct under outer fragmentation (reassembly done by the conntrack defrag hook)"
else
	bad "T4 the hook did not reassemble the outer packet and there is no conntrack to do it -- fragment path is broken"
fi
echo 1 > /sys/module/iwan/parameters/df
nsx "$NS_C" ip link set veth-c mtu 1500
nsx "$NS_S" ip link set veth-s mtu 1500
if run_tcp T4b 262144; then
	ok "T4b TCP still works after restoring df=1/mtu1500"
else
	bad "T4b TCP failed after the restore"
fi

# ---------------------------------------------------------------- T5

# The credentials sid/tok are module-wide global configuration: one module instance serves all netns, so changing
# /sys/module/iwan/parameters/tok changes both ends at once and cannot create a "mismatch".
# Therefore the negative cases craft frames and send them from the client netns, verifying the data-plane credential gate:
#   - frame with wrong tok      -> rejected by the frame-header check, only rx_bad_hdr grows
#   - correct tok, bad inner    -> passes the credential gate, rx_frames and rx_bad_inner grow
# Both must be observed together to prove that the credentials are what discriminates, not that all foreign packets are dropped.
say "T5 negative: crafted frames verify the credential gate (wrong tok always dropped, only correct tok reaches inner validation)"

cat >"$WORK/send_frame.py" <<'PYEOF'
import socket, struct, sys
# argv: <mode> <src_ip> <sid> <dst_ip> <port>
mode, src, sid, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, port))     # source port fixed to the outer port: packets sent by the module itself use sport=dport
if mode == "garbage":
    payload = bytes(60)                              # first byte 0 != 0x18, not an iWAN frame
else:
    payload = struct.pack("!BBHI", 0x18, 1, sid, int(mode)) + bytes(40)
s.sendto(payload, (dst, port))
PYEOF

h_before=$(ctr "$NS_S" rx_bad_hdr)
i_before=$(ctr "$NS_S" rx_bad_inner)
f_before=$(ctr "$NS_S" rx_frames)
p_before=$(ctr "$NS_S" rx_pkts)
o_before=$(ctr "$NS_S" rx_outer)

# Three frames, identical outer 5-tuple, differing only in the credentials inside the payload:
#   (1) garbage payload (not an iWAN frame) -> rejected at the frame header
#   (2) wrong tok                           -> rejected at the frame header
#   (3) correct tok, bad inner              -> passes the gate, stops at inner validation
nsx "$NS_C" python3 "$WORK/send_frame.py" garbage "$OUTER_C" "$SID" "$OUTER_S" "$PORT"
sleep 0.2
nsx "$NS_C" python3 "$WORK/send_frame.py" 999 "$OUTER_C" "$SID" "$OUTER_S" "$PORT"
sleep 0.2
nsx "$NS_C" python3 "$WORK/send_frame.py" "$TOK" "$OUTER_C" "$SID" "$OUTER_S" "$PORT"

for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ "$(ctr "$NS_S" rx_bad_inner)" -gt "$i_before" ] && break
	sleep 0.2
done

h_after=$(ctr "$NS_S" rx_bad_hdr)
i_after=$(ctr "$NS_S" rx_bad_inner)
f_after=$(ctr "$NS_S" rx_frames)
p_after=$(ctr "$NS_S" rx_pkts)
o_after=$(ctr "$NS_S" rx_outer)
info "server rx_pkts $p_before -> $p_after, rx_outer $o_before -> $o_after, rx_bad_hdr $h_before -> $h_after, rx_bad_inner $i_before -> $i_after, rx_frames $f_before -> $f_after"

[ "$((p_after - p_before))" -ge 3 ] \
	&& ok "T5 all three frames reached the server hook (rx_pkts +$((p_after - p_before)))" \
	|| bad "T5 crafted frames did not reach the hook (rx_pkts +$((p_after - p_before))): check the send-side route/port first, this is not a credential problem"
[ "$((h_after - h_before))" -ge 2 ] \
	&& ok "T5 garbage frame and wrong-tok frame both rejected at the frame header (rx_bad_hdr +$((h_after - h_before)))" \
	|| bad "T5 frame-header gate did not take effect (rx_bad_hdr +$((h_after - h_before)), expected +2)"
[ "$((i_after - i_before))" -ge 1 ] \
	&& ok "T5 frame with correct tok passed the credential gate and stopped at inner validation (rx_bad_inner +$((i_after - i_before)))" \
	|| bad "T5 frame with correct tok did not reach inner validation (did the gate reject the correct one too?)"
[ "$((f_after - f_before))" = 1 ] \
	&& ok "T5 only the frame with correct credentials was accepted as a data frame (rx_frames +1)" \
	|| bad "T5 rx_frames delta should be 1, actual $((f_after - f_before))"

# ---------------------------------------------------------------- summary

say "counter summary"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns ---"
	nsx "$ns" cat /proc/net/iwan | sed 's/^/    /'
done

say "results"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	echo "all passed: ingress decapsulation (inline reassembly, credential check) and egress encapsulation (checksum/segmentation correct) both work."
	exit 0
fi
echo "there are failing cases. Hints: dmesg | tail -30; rx_bad_* / tx_bad_* counters in /proc/net/iwan;"
echo "             growing Tcp InCsumErrors usually means XOR broke the checksum (egress path problem)."
exit 1
