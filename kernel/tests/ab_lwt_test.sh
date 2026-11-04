#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# A/B experiment: the same iWAN protocol semantics, egress respectively through
#   1. kernel module iwan0 (ndo_start_xmit, the product path in this repo)
#   2. eBPF program on LWT_XMIT (kernel/bpf/lwt_encap.bpf.c, the comparison path)
# Both sides use the kernel module to decapsulate inbound, only egress differs => any difference can only come from the egress path.
#
#   sudo bash kernel/tests/ab_lwt_test.sh [--keep]
#
# Three groups:
#   A  egress via iwan0, enc=1 (XOR)           -> TCP echo must pass (baseline)
#   B  egress via LWT eBPF, enc=1 (XOR)        -> must fail and server Tcp InCsumErrors must increase
#   B2 egress via LWT eBPF, enc=0 (no XOR)     -> must pass
#   B and B2 differ only in the XOR switch, so the failure cause is pinned to
#   "XOR happens before L4 checksum computation" (the module does XOR in ndo_start_xmit,
#   after the checksum is already computed, so it does not have this problem).
#
# Dependencies: kernel module build toolchain, clang (-target bpf), bpftool, iproute2.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
BPF_OBJ="$KDIR/bpf/lwt_encap.o"
LWT_CFG="$KDIR/bpf/lwt_cfg.py"
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
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

PASS=0
FAIL=0
declare -a RESULTS=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  - %s\n' "$*"; }
die()  { printf '\033[31mfatal: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }
tcpsnmp() { nsx "$1" awk -v f="$2" '/^Tcp:/{v=$f} END{print v+0}' /proc/net/snmp; }
set_enc() { echo "$1" > /sys/module/iwan/parameters/enc; }

cleanup() {
	[ "$KEEP" = 1 ] && return
	ip netns del "$NS_C" 2>/dev/null
	ip netns del "$NS_S" 2>/dev/null
	rmmod iwan 2>/dev/null
	[ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
for c in bpftool python3 ip; do
	command -v "$c" >/dev/null || die "missing $c (A/B experiment needs: bpftool, python3, iproute2)"
done
# clang is located by kernel/bpf/Makefile itself (falls back to /usr/lib/llvm-*/bin when absent from PATH)

WORK="$(mktemp -d /tmp/iwan-ab-lwt.XXXXXX)"

say "build"
make -C "$KDIR" >"$WORK/build-mod.log" 2>&1 || { tail -20 "$WORK/build-mod.log"; die "kernel module build failed"; }
make -C "$KDIR/bpf" >"$WORK/build-bpf.log" 2>&1 || { tail -20 "$WORK/build-bpf.log"; die "eBPF comparison program build failed"; }
[ -f "$KO" ] && [ -f "$BPF_OBJ" ] || die "build artifacts missing"
info "iwan.ko + lwt_encap.o ready"

say "load module, set up topology"
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_S" outer_dst="$OUTER_C" \
	dport="$PORT" sid="$SID" tok="$TOK" key="$KEY" enc=1 batch=1 df=1 \
	|| die "insmod failed"
ip netns del "$NS_C" 2>/dev/null; ip netns del "$NS_S" 2>/dev/null
ip netns add "$NS_C" || die "failed to create netns"
ip netns add "$NS_S" || die "failed to create netns"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "failed to create veth"
for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up
nsx "$NS_C" ip addr add "$INNER_C/32" dev lo
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo
for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: failed to create iwan0"
	nsx "$ns" ip link set iwan0 mtu 1400 up || die "$ns: failed to bring up iwan0"
done
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S' > /proc/net/iwan" || die "failed to write proc"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C' > /proc/net/iwan" || die "failed to write proc"
# The server return path always uses the module (only the client egress changes path)
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "failed to add server inner route"

# Run one TCP echo, return 0/1; use --expect-fail when a failure is expected
try_tcp() { # try_tcp <name> <expect:ok|fail>
	local name="$1" expect="$2" flag=""
	[ "$expect" = fail ] && flag="--expect-fail"
	nsx "$NS_S" python3 "$ECHO_PY" server --bind "$INNER_S" --port "$PORT" \
		--timeout 12 >"$WORK/s-$name.log" 2>&1 &
	local spid=$!
	for _ in $(seq 1 50); do grep -q SERVER_READY "$WORK/s-$name.log" && break; sleep 0.1; done
	nsx "$NS_C" python3 "$ECHO_PY" client --host "$INNER_S" --port "$PORT" \
		--bytes 65536 --timeout 6 $flag >"$WORK/c-$name.log" 2>&1
	local rc=$?
	wait $spid 2>/dev/null
	info "client[$name]: $(tr '\n' ' ' <"$WORK/c-$name.log")"
	return $rc
}

# ---------------------------------------------------------------- group A

say "group A: egress via iwan0 (kernel module, XOR)"
set_enc 1
nsx "$NS_C" ip route replace "$INNER_S/32" dev iwan0
if try_tcp A ok; then
	ok "group A TCP echo passed (baseline: module egress + XOR)"
else
	bad "group A failed -- baseline does not hold, check kernel/tests/tcp_echo_test.sh first"
fi

# ---------------------------------------------------------------- group B

say "group B: egress via LWT eBPF (XOR)"
# src must be explicit: the LWT route hangs off veth-c (the outer port); otherwise the kernel
# picks the source from the egress primary address, so the inner SYN becomes 10.100.0.1 instead of 10.9.0.1 -- the server can still decapsulate
# and deliver it (all counters rise), but the reply goes straight by the outer address, so the connection must time out. Group A has no such issue because
# iwan0 has no IPv4 address, so the source can only fall back to 10.9.0.1 on lo.
nsx "$NS_C" ip route replace "$INNER_S/32" dev veth-c src "$INNER_C" \
	encap bpf xmit obj "$BPF_OBJ" sec lwt_xmit || die "failed to attach LWT eBPF program"

# LWT_XMIT runs before validate_xmit_skb(); at this point the inner TCP checksum is still
# CHECKSUM_PARTIAL. If the egress device claims checksum offload support (veth's VETH_FEATURES has
# NETIF_F_HW_CSUM), software will never compute it, and the peer checking the raw field value necessarily sees InCsumErrors
# -- this is unrelated to XOR, enc=0 fails too. Disabling tx checksum offload on veth-c moves "checksum computation"
# past the LWT hook, so enc=0 should pass and enc=1 still fails, making XOR timing the only variable.
if command -v ethtool >/dev/null 2>&1; then
	nsx "$NS_C" ethtool -K veth-c tx off >/dev/null 2>&1 \
		&& info "veth-c tx checksum offload disabled" \
		|| info "failed to disable veth-c tx checksum offload (continuing, B2 may fail because the checksum is not computed)"
else
	info "ethtool not found, keeping the default offload settings"
fi
python3 "$LWT_CFG" set --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --sid "$SID" --tok "$TOK" --key "$KEY" --enc 1 \
	|| die "failed to write lwt_cfg_map"
info "map configured; reading the counter baseline first"
python3 "$LWT_CFG" counters | sed 's/^/    /'

ic_before=$(tcpsnmp "$NS_S" 16)
if try_tcp B fail; then
	ok "group B failed as expected: the checksum is computed by a later step after XOR, so the peer sees a checksum error"
else
	bad "group B unexpectedly passed -- this kernel completes the L4 checksum before LWT (not as expected, needs to be recorded)"
fi
ic_after=$(tcpsnmp "$NS_S" 16)
info "server Tcp InCsumErrors: $ic_before -> $ic_after (InErrs=$(( $(tcpsnmp "$NS_S" 14) )))"
if [ "$((ic_after - ic_before))" -gt 0 ]; then
	ok "group B failure cause confirmed: server TCP checksum errors increased by +$((ic_after - ic_before))"
else
	bad "group B failed but the server has no checksum errors -- the cause is not the checksum, look elsewhere"
fi
cnt5=$(python3 "$LWT_CFG" counters | awk -F'[= ]' '{for(i=1;i<=NF;i++) if($i=="c5") print $(i+1)}' | tail -1)
info "lwt_cnt encrypted sent c5=$cnt5"
[ "${cnt5:-0}" -gt 0 ] && ok "group B really did send encrypted packets from the LWT path (c5>0)" \
		       || bad "group B sent no encrypted packets on the LWT path (program not effective?)"

# ---------------------------------------------------------------- group B2

say "group B2: egress via LWT eBPF (no XOR) -- only one switch differs"
set_enc 0
# A B2 failure must be localized to a specific step of the hook: rx_pkts rises but rx_outer does not => the outer 5-tuple
# is not accepted; both rx_outer and rx_bad_hdr rise => frame type/credential gate rejects (with enc=0
# PT_DATA is expected); rx_frames/rx_delivered also rise => inbound is decapsulated and delivered, so only the return path is left.
# For the return path check two things: did the client hook receive and decapsulate the SYN-ACK, and did the server reply at all?
rxctr() { nsx "$1" awk -v k="$2" '$1==k{print $2+0}' /proc/net/iwan 2>/dev/null; }
snap() {
	for ns in "$NS_C" "$NS_S"; do
		info "[$ns] $(for k in rx_pkts rx_outer rx_bad_hdr rx_bad_inner rx_frames rx_delivered; do
			printf '%s=%s ' "$k" "$(rxctr "$ns" "$k")"
		done)InErrs=$(tcpsnmp "$ns" 14) InCsumErrors=$(tcpsnmp "$ns" 16) OutSegs=$(tcpsnmp "$ns" 11)"
	done
}
info "B2 pre-test snapshot"
snap
python3 "$LWT_CFG" set --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --sid "$SID" --tok "$TOK" --key "$KEY" --enc 0 \
	|| die "failed to write lwt_cfg_map"
if try_tcp B2 ok; then
	ok "group B2 passed: LWT encapsulation/reroute/decapsulation are all fine, the problem is only XOR"
else
	bad "group B2 failed too -- the LWT path has a problem beyond XOR"
fi
info "B2 post-test snapshot"
snap
set_enc 1

# ---------------------------------------------------------------- summary

say "results"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	cat <<'EOF'
Conclusion: module egress (ndo_start_xmit, XOR after the checksum is computed) is correct;
      eBPF egress on LWT_XMIT necessarily breaks the checksum as soon as XOR is enabled,
      disabling XOR restores normal operation immediately => the failure cause is the conflict between XOR and checksum computation timing,
      not that "eBPF cannot write a tunnel".
EOF
	exit 0
fi
echo "Some cases did not match the expected A/B conclusion; see the client/server logs and counters above."
exit 1
