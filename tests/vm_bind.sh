#!/bin/bash
# Underlay NIC binding test (raw only) -- explicit binding (/proc oif=) and "pinned after FIB resolution".
#
# Run inside the crash-lab guest: bash /bench/tests/vm_bind.sh [MTU]
#
# Topology (all inside the guest; no netlink session; uses module params + /proc fallback path):
#   cl netns: vethbp1 172.31.201.2/24 -- vethbp0 172.31.201.1/24(root netns)
#             vethb3  10.55.0.2/24     -- vethb2  10.55.0.1/24 (root netns, no outer route)
#   cl also has iwan0 (ip link add type iwan), route 10.9.9.9/32 dev iwan0
#
# All criteria are counters (guest has no dmesg command; pinning evidence is in the serial log -- each run's
# log has the "underlay NIC ... (pinned after FIB resolution/explicit binding) needed_headroom=52" line):
#   tx_pkts/tx_err/rx_delivered = cl's /proc/net/iwan;
#   vethbp0/vethb2 RX           = rx_packets of the peer NIC in root netns,
#                                 used to prove "which NIC the packets actually leave from".
# Peer counters also include ARP/IPv6 neighbor discovery, so the criteria are one-way:
#   expected peer >= sent count; unexpected peer <= 1 (noise tolerance). IPv6 is disabled in cl to reduce noise.
#
# Kernel semantics (confirmed by this test): after flowi4_oif is set, if FIB has no route
# through that device, ip_route_output_flow() synthesizes a scope-link route for **that UP device with an address**
# (SO_BINDTODEVICE semantics). Thus explicit binding to any UP NIC can send,
# and the egress device always equals the bound one -- exactly "ignore all other NICs". Case 4 uses this
# semantics as evidence: binding vethb3 sends packets via vethb3/vethb2, while vethbp1, which FIB itself would choose,
# shows zero growth. The module also self-checks (resolved ifindex must equal the bound value) to catch
# future kernel changes to this fallback behavior.
#
# Cases:
#   1. no oif: first packet is FIB-resolved and pinned => tx_pkts +5, tx_err +0, vethbp0 RX +5;
#      needed_headroom 36 -> 52 (veth LL_RESERVED_SPACE=16 => 36+16).
#   2. explicit bind vethbp1: same as above, and vethb2 side has zero growth.
#   3. explicit bind lo: all 5 packets leave via lo (both peer NICs show zero growth), and cl's own RX
#      hook extracts them on lo => rx_delivered +5 (inbound gate allows the bound NIC).
#   4. explicit bind vethb3 (FIB would not choose it): vethb2 RX +5, vethbp0 RX +0
#      => egress depends only on the bound NIC, ignoring all others.
#   5. bind by egress IP (/proc ip=, IWAN_A_IP in the session ABI):
#      5-1 ip=10.55.0.2 (vethb3 address) => egress via vethb3 (vethb2 RX +5,
#           vethbp0 RX +0); serial log shows "resolved by egress IP 10.55.0.2";
#      5-2 ip=172.31.201.2 (vethbp1 address) => switch back to vethbp1 side
#           (each ip= change clears the pin; the next packet resolves via the new address table -- this also verifies
#           the "lazy re-resolution by IP after pin is cleared" path);
#      5-3 ip=192.0.2.1 (belongs to no local interface) => write must fail
#           (-EADDRNOTAVAIL: binding a nonexistent address is meaningless; unlike oif=,
#           which "only validates format and allows configuring before the NIC is up");
#      5-4 oif=<vethbp1> + ip=10.55.0.2 (address is on vethb3) => write must fail
#           (-EINVAL: when two binding specs point to different interfaces, neither may be chosen), and after the failed assertion
#           tx_oif/tx_bind_ip must be **unchanged** (one /proc write is a config transaction;
#           commit only after all checks pass -- per-token application would leave "half a config");
#      5-6 tx_src=<outer address> + ip=10.55.0.2 (two tokens set the same field inconsistently)
#           => write must fail (order-independent, avoiding the implicit "last write wins" rule);
#      State assertions use the newly added tx_oif / tx_bind_ip / carrier read back from /proc,
#      no longer inferring "which NIC the kernel bound" only from counters and serial logs.
#      5-5 ip=0.0.0.0 tx_src=<outer address> => clear only "bind by IP"; outer source address
#           remains, and underlay NIC returns to FIB resolution (vethbp0 RX +5, vethb2 RX +0)
#           => proves what was cleared is the binding, not the source address.
set -u

MTU=${1:-2000}
NET=cl
KO=/bench/kernel/iwan.ko
OUTER_C=172.31.201.2	# cl outer address (local side)
OUTER_S=172.31.201.1	# peer (root netns side)
INNER=10.9.9.9
PORT=16002
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  PASS $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
note() { echo "  - $*"; }
die()  { echo "[bind] fatal: $*"; exit 2; }

# cl's /proc/net/iwan counters (view of that netns)
# Look up by **name**, not field position: readback has both line-start keys like "tx_pkts <n>" and
# mid-line keys like "tx_oif 2 tx_bind_ip <ip> carrier 4" ($1==k would yield empty).
ctr()  { ip netns exec "$NET" awk -v k="$1" \
	'{for(i=1;i<NF;i++) if($i==k){print $(i+1); exit}}' /proc/net/iwan; }
# RX packet count of the peer NIC in root netns (peer of vethbp1/vethb3)
prx()  { cat /sys/class/net/"$1"/statistics/rx_packets; }
# iwan0 needed_headroom in cl: this kernel's sysfs lacks the attribute; use the
# pinning line (needed_headroom=52) in the serial log and vm_profile.sh's pskb_expand_head hit count as evidence.

# Write fallback-path config; $1 = oif (empty = omit this item, let FIB resolve)
setconf() {
	local kv="tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1"
	[ -n "$1" ] && kv="$kv oif=$1"
	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" || die "failed to write /proc/net/iwan"
}
# Send 5 raw inner packets through the tunnel (one per bash /dev/udp write)
send5() { ip netns exec "$NET" bash -c "for i in 1 2 3 4 5; do echo x > /dev/udp/$INNER/$PORT; done"; }

# One measurement round: $1 name $2 oif $3 expected egress peer NIC (expect RX >= 5)
#   $4-5 expected (tx_pkts,tx_err) delta; $6 unexpected peer (expect RX <= 1)
round() {
	local name=$1 oif=$2 peer=$3 wp=$4 we=$5 other=$6
	local p0 e0 u0 o0 p1 e1 u1 o1 dused dother

	setconf "$oif"
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer"); o0=$(prx "$other")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer"); o1=$(prx "$other")
	dused=$((u1 - u0)); dother=$((o1 - o0))
	note "$name: tx_pkts +$((p1 - p0))/$wp tx_err +$((e1 - e0))/$we $peer RX +$dused(>=$wp)$other RX +$dother(<=1)"
	[ $((p1 - p0)) = "$wp" ] && [ $((e1 - e0)) = "$we" ] && \
	[ "$dused" -ge "$wp" ] && [ "$dother" -le 1 ] && ok "$name" || bad "$name"
}

# One measurement round for arbitrary kv: $1 name $2 kv string $3 expected egress peer $4-5 expected (tx_pkts,tx_err)
#   $6 unexpected peer (expect RX <= 1)
roundkv() {
	local name=$1 kv=$2 peer=$3 wp=$4 we=$5 other=$6
	local p0 e0 u0 o0 p1 e1 u1 o1 dused dother

	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" \
		|| die "failed to write /proc/net/iwan: $kv"
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer"); o0=$(prx "$other")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer"); o1=$(prx "$other")
	dused=$((u1 - u0)); dother=$((o1 - o0))
	note "$name: tx_pkts +$((p1 - p0))/$wp tx_err +$((e1 - e0))/$we $peer RX +$dused(>=$wp)$other RX +$dother(<=1)"
	[ $((p1 - p0)) = "$wp" ] && [ $((e1 - e0)) = "$we" ] && \
	[ "$dused" -ge "$wp" ] && [ "$dother" -le 1 ] && ok "$name" || bad "$name"
}

# /proc readback state assertion: $1 name $2 key $3 expected value
expect_state() {
	local name=$1 key=$2 want=$3 got

	got=$(ctr "$key")
	[ "$got" = "$want" ] && ok "$name($key=$got)" \
		|| bad "$name ($key=$got, expected $want)"
}

# Write must be rejected (kernel returns negative errno, echo exits nonzero), and no binding state may change
expect_write_fail() {
	local name=$1 kv=$2
	local o0 b0 c0 o1 b1 c1

	o0=$(ctr tx_oif); b0=$(ctr tx_bind_ip); c0=$(ctr carrier)
	if ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" 2>/dev/null; then
		bad "$name (write should have been rejected)"
		return
	fi
	o1=$(ctr tx_oif); b1=$(ctr tx_bind_ip); c1=$(ctr carrier)
	[ "$o0" = "$o1" ] && [ "$b0" = "$b1" ] && [ "$c0" = "$c1" ] \
		&& ok "$name" \
		|| bad "$name (write rejected but state changed: tx_oif $o0->$o1 tx_bind_ip $b0->$b1)"
}

[ -f "$KO" ] || die "missing $KO"
[ "$(id -u)" = 0 ] || die "root required (the crash-lab guest runs as root)"

echo "== vm_bind: create topology (cl netns + two veth pairs) =="
ip netns del $NET 2>/dev/null
ip link del vethbp0 2>/dev/null
ip link del vethb2 2>/dev/null
ip netns add $NET || die "failed to create netns"
ip link add vethbp0 type veth peer name vethbp1 || die "failed to create veth"
ip link set vethbp1 netns $NET
ip addr add $OUTER_S/24 dev vethbp0
ip link set vethbp0 up
ip -n $NET addr add $OUTER_C/24 dev vethbp1
ip -n $NET link set vethbp1 up
ip link add vethb2 type veth peer name vethb3 || die "failed to create second veth pair"
ip link set vethb3 netns $NET
ip addr add 10.55.0.1/24 dev vethb2
ip link set vethb2 up
ip -n $NET addr add 10.55.0.2/24 dev vethb3
ip -n $NET link set vethb3 up
ip -n $NET link set lo up

echo "== vm_bind: load module (fallback path: module params + /proc) =="
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_C" outer_dst="$OUTER_S" \
	dport="$PORT" sid=4660 tok=3405691582 key=0011223344556677 enc=1 \
	batch=1 df=1 max_mtu="$MTU" || die "insmod failed"

ip -n $NET link add iwan0 type iwan || die "failed to create iwan0"
ip -n $NET link set iwan0 up
ip -n $NET route add $INNER/32 dev iwan0 || die "failed to add inner route"
OIF_VETH=$(ip netns exec $NET cat /sys/class/net/vethbp1/ifindex) || die "failed to get vethbp1 ifindex"
OIF_B3=$(ip netns exec $NET cat /sys/class/net/vethb3/ifindex) || die "failed to get vethb3 ifindex"
note "cl: vethbp1 ifindex=$OIF_VETH, vethb3 ifindex=$OIF_B3, iwan0 ifindex=$(ip netns exec $NET cat /sys/class/net/iwan0/ifindex)"
# Disable IPv6 in cl: neighbor discovery/MLD frames hit peer NICs and pollute the "which NIC egresses" counter evidence
ip netns exec $NET sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null \
	&& note "cl: IPv6 disabled (avoid neighbor-discovery frames polluting peer counters)"

# Case 4 needs packets to really leave via vethb3: that link has no 172.31.201.1, so ARP gets no reply;
# so pin a static neighbor (pointing to vethb2's MAC) first, otherwise packets stall in the neighbor resolution queue.
if ip -n $NET neigh add $OUTER_S lladdr "$(cat /sys/class/net/vethb2/address)" dev vethb3 2>/dev/null; then
	note "cl: static neighbor pinned for $OUTER_S on vethb3 (so case 4 packets really egress)"
else
	note "cl: failed to add static neighbor (case 4 packets may stall in ARP queue)"
fi

echo "== vm_bind: cases =="
round "1. FIB-resolved pin" ""            vethbp0 5 0 vethb2
round "2. explicit bind vethbp1"  "$OIF_VETH"  vethbp0 5 0 vethb2

# 3. bind lo: do not assume whether it can egress; require "no silent loss" and that packets really leave via lo
p0=$(ctr tx_pkts); e0=$(ctr tx_err); d0=$(ctr rx_delivered); a0=$(prx vethbp0); b0=$(prx vethb2)
setconf 1; send5; sleep 1
p1=$(ctr tx_pkts); e1=$(ctr tx_err); d1=$(ctr rx_delivered); a1=$(prx vethbp0); b1=$(prx vethb2)
dp=$((p1 - p0)); de=$((e1 - e0)); dd=$((d1 - d0)); da=$((a1 - a0)); db=$((b1 - b0))
note "3. explicit bind lo: tx_pkts +$dp tx_err +$de (sum should be 5) vethbp0 RX +$da vethb2 RX +$db cl rx_delivered +$dd"
[ $((dp + de)) = 5 ] && ok "3. bind lo: all 5 packets accounted for (no silent drop)" \
	|| bad "3. bind lo: dp+de=$((dp + de)) should be 5"
[ "$da" -le 1 ] && [ "$db" -le 1 ] && ok "3. bind lo: neither peer NIC received (packets only on lo)" \
	|| bad "3. bind lo: vethbp0 +$da vethb2 +$db (no other NIC should egress)"
[ "$dd" -ge 5 ] && ok "3. bind lo: cl RX gate allows the bound lo (rx_delivered +$dd)" \
	|| bad "3. bind lo: rx_delivered only +$dd (inbound gate may reject the bound NIC)"

round "4. explicit bind vethb3 (FIB would not choose it)" "$OIF_B3" vethb2 5 0 vethbp0

echo "== vm_bind: case 5 (bind by egress IP) =="
# Pre-check: state assertions depend on binding fields in readback; with an old module, report clearly
# instead of flooding FAIL on a dozen empty $key= values.
if [ -z "$(ctr tx_oif)" ] || [ -z "$(ctr tx_bind_ip)" ] || [ -z "$(ctr carrier)" ]; then
	die "readback lacks tx_oif/tx_bind_ip/carrier (is $KO not a build with binding export?)"
fi
# Put oif=0 first in kv: /proc overwrites per token; without explicit clear it keeps the previous bound NIC,
# and ip= would be judged "conflicts with oif" (exactly what case 5-4 tests).
roundkv "5-1 ip=10.55.0.2(vethb3)" \
	"tx_dst=$OUTER_S enabled=1 oif=0 ip=10.55.0.2" vethb2 5 0 vethbp0
expect_state "5-1 binding state" tx_bind_ip 10.55.0.2
expect_state "5-1 actual underlay NIC" carrier "$OIF_B3"
roundkv "5-2 ip=172.31.201.2(vethbp1)" \
	"tx_dst=$OUTER_S enabled=1 oif=0 ip=$OUTER_C" vethbp0 5 0 vethb2
expect_state "5-2 binding state" tx_bind_ip "$OUTER_C"
expect_state "5-2 actual underlay NIC" carrier "$OIF_VETH"
expect_write_fail "5-3 ip belongs to no local interface => reject (-EADDRNOTAVAIL)" \
	"tx_dst=$OUTER_S enabled=1 ip=192.0.2.1"
expect_write_fail "5-4 ip is not on the specified NIC => reject (-EINVAL)" \
	"tx_dst=$OUTER_S enabled=1 oif=$OIF_VETH ip=10.55.0.2"
expect_write_fail "5-6 tx_src and ip inconsistent in one write => reject" \
	"tx_dst=$OUTER_S enabled=1 tx_src=$OUTER_C ip=10.55.0.2"
roundkv "5-5 ip=0.0.0.0 clears binding (source address kept)" \
	"tx_dst=$OUTER_S enabled=1 ip=0.0.0.0 tx_src=$OUTER_C" vethbp0 5 0 vethb2
expect_state "5-5 binding cleared" tx_bind_ip 0.0.0.0
expect_state "5-5 outer source address kept" tx_src "$OUTER_C"

echo "== vm_bind: result PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" = 0 ]
