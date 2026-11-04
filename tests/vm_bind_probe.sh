#!/bin/bash
# Bearer-NIC event semantics probe (raw only) -- empirical basis for "which events the control plane must watch".
#
# Run inside the crash-lab guest: bash /bench/tests/vm_bind_probe.sh [MTU]
#
# Topology is the same as tests/vm_bind.sh (cl netns + two veth pairs + iwan0, using module params and
# the /proc/net/iwan fallback path, without creating a netlink session).
#
# The probe changes bearer device state item by item and observes the two possible data-plane outcomes:
#   tx_pkts grows = the module accepted the packet and handed it to the outer stack (later link-layer drops are not reported back);
#   tx_err  grows = the module dropped it at outer route lookup (refused to send).
# Each item states a "hypothesis" and the "measured" result, to judge which events the control plane must react to.
set -u

MTU=${1:-2000}
NET=cl
KO=/bench/kernel/iwan.ko
OUTER_C=172.31.201.2
OUTER_S=172.31.201.1
INNER=10.9.9.9
PORT=16002
OK=0
MISS=0
NEIGH_MAC=

ok()   { OK=$((OK + 1)); echo "    [hypothesis holds] $*"; }
miss() { MISS=$((MISS + 1)); echo "    [hypothesis fails] $*"; }
note() { echo "  - $*"; }
die()  { echo "[probe] fatal: $*"; exit 2; }

# Look up a counter by name (same as vm_bind.sh): the readback has both line-leading and mid-line keys
ctr() { ip netns exec "$NET" awk -v k="$1" \
	'{for(i=1;i<NF;i++) if($i==k){print $(i+1); exit}}' /proc/net/iwan; }
prx() { cat /sys/class/net/"$1"/statistics/rx_packets; }
setconf() {
	local kv="tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1 oif=${1:-0}"
	# oif=0 must be written explicitly: writes to /proc override per item and keep old values for omitted keys -- otherwise the "auto pin"
	# group would keep using the explicit binding set by the previous group, and the measured path would not be FIB at all.
	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" || die "writing /proc/net/iwan failed"
}
send5() { ip netns exec "$NET" bash -c "for i in 1 2 3 4 5; do echo x > /dev/udp/$INNER/$PORT; done"; }
static_neigh() {	# vethb3 has no OUTER_S; a static neighbor is needed for next-hop resolution
	ip -n $NET neigh replace $OUTER_S lladdr "$NEIGH_MAC" dev vethb3 2>/dev/null
}

# Observe one round: $1 name $2 hypothesis $3 peer on the expected egress $4 expected(tx_pkts,tx_err)
probe() {
	local name=$1 hyp=$2 peer=$3 wp=$4 we=$5
	local p0 e0 u0 p1 e1 u1 dp de du
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer")
	dp=$((p1 - p0)); de=$((e1 - e0)); du=$((u1 - u0))
	note "$name"
	note "  hypothesis: $hyp"
	note "  measured: tx_pkts +$dp (expect $wp) tx_err +$de (expect $we) $peer RX +$du (expect >=$wp)"
	if [ "$dp" = "$wp" ] && [ "$de" = "$we" ] && [ "$du" -ge "$wp" ]; then ok "$name"; else miss "$name"; fi
}

[ -f "$KO" ] || die "missing $KO"
[ "$(id -u)" = 0 ] || die "root required (the crash-lab guest runs as root)"

echo "== vm_bind_probe: create topology =="
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
ip netns exec $NET sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null

rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_C" outer_dst="$OUTER_S" \
	dport="$PORT" sid=4660 tok=3405691582 key=0011223344556677 enc=1 \
	batch=1 df=1 max_mtu="$MTU" || die "insmod failed"
ip -n $NET link add iwan0 type iwan || die "failed to create iwan0"
ip -n $NET link set iwan0 up
ip -n $NET route add $INNER/32 dev iwan0 || die "failed to add inner route"

OIF_VETH=$(ip netns exec $NET cat /sys/class/net/vethbp1/ifindex)
OIF_B3=$(ip netns exec $NET cat /sys/class/net/vethb3/ifindex)
NEIGH_MAC=$(cat /sys/class/net/vethb2/address)
note "cl: vethbp1 ifindex=$OIF_VETH, vethb3 ifindex=$OIF_B3"
static_neigh

echo "== vm_bind_probe: (1) interface admin state (down/up, explicit binding) =="
setconf "$OIF_B3"
probe "1-0 baseline: explicitly bound to vethb3 (UP, has address)" "accept and send out" vethb2 5 0
ip -n $NET link set vethb3 down
probe "1-1 vethb3 down" "lookup fails => refuse to send" vethb2 0 5
ip -n $NET link set vethb3 up
static_neigh	# down clears the neighbor table
probe "1-2 vethb3 up (restored)" "egress restored" vethb2 5 0

echo "== vm_bind_probe: (2) interface address set (del/add address, explicit binding) =="
ip -n $NET addr del 10.55.0.2/24 dev vethb3
probe "2-1 delete vethb3's only IPv4 address" "synthetic route invalid => refuse to send" vethb2 0 5
ip -n $NET addr add 10.55.0.2/24 dev vethb3
probe "2-2 address restored" "egress restored" vethb2 5 0

echo "== vm_bind_probe: (3) FIB path (auto pin, down/up) =="
setconf ""
ip -n $NET route flush cache 2>/dev/null
probe "3-0 no oif written: FIB resolves to vethbp1" "accept and send out via vethbp1" vethbp0 5 0
ip -n $NET link set vethbp1 down
probe "3-1 vethbp1 down (no alternate outer path)" "lookup fails => refuse to send" vethbp0 0 5
ip -n $NET link set vethbp1 up
probe "3-2 vethbp1 up (auto path self-heals)" "re-resolve and restore egress" vethbp0 5 0

echo "== vm_bind_probe: (4) interface deletion (explicit binding) =="
setconf "$OIF_B3"
ip -n $NET link del vethb3
# After vethb3 disappears its root-netns peer vethb2 also disappears, so the peer counters can no longer be read;
# this item keeps only the sender-side evidence (tx_err growth).
probe "4-1 delete the explicitly bound vethb3" "lookup fails (-ENODEV) => refuse to send" vethbp0 0 5

echo "== vm_bind_probe: result hypotheses-hold=$OK hypotheses-fail=$MISS =="
exit 0
