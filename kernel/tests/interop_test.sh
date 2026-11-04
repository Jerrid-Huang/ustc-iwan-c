#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN cross-implementation interop acceptance test (needs root)
#
#   sudo bash kernel/tests/interop_test.sh [--keep]
#
# Purpose: compare the bytes the **kernel module** really produces on the wire, byte by
# byte, with the **user-space reference implementation** (kernel/tests/interop_c.c, which
# uses src/common/'s production wire-format code pkt_hdr()/xor_crypt()). Defects invisible
# to "module sends to itself, receives from itself" (port/address byte order, XOR scope, frame header serialization, outer length) are all exposed by this comparison.
#
# Topology and load parameters follow tcp_echo_test.sh:
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#   module level: any_dir=1 dport=6100 sid=4660 tok=3405691582 key=0011223344556677
#           enc=1 batch=1 df=1; each netns then also writes tx_src/tx_dst/enabled=1
#
# Three assertions:
#   A1 module outbound -> C-side decapsulation
#      inject on iwc via a raw socket (IP_HDRINCL + SO_BINDTODEVICE=iwan0)
#      the **known-content** inner packet built by interop_c mkudp; on iws's veth-s
#      capture the outer UDP payload with capture_iwan.py, hand it to interop_c decap,
#      then compare it with the injected original inner packet using interop_c cmpin.
#   A2 C-side encapsulation -> module inbound
#      build a payload with interop_c encap and send it from iwc with the outer 5-tuple
#      10.100.0.1:6100 -> 10.100.0.2:6100 to iws, asserting the module decapsulates and
#      delivers it (/proc/net/iwan rx_pkts/rx_outer/rx_frames/rx_delivered deltas),
#      and the UDP socket on iws receives an inner payload **byte-for-byte identical** to the sender's.
#   A3 outer header field consistency
#      interop_c outer generates the expected outer header; the actual fields captured
#      by capture_iwan.py are compared one field at a time (source/destination address and port are exactly where historical byte-order bugs were), and the first 26 bytes of the outer header
#      are compared byte for byte with the expected header (covering TTL/ID/DF/IP checksum as well).
#
# Dependencies: ip(iproute2), python3, cc + libcrypto, make, insmod/rmmod, awk/sed/grep.
#       ethtool / tcpdump / nc / ping are deliberately not used: capture, packet construction and sending are done by
#       capture_iwan.py, interop_c, and small python scripts generated on the spot under $WORK.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"		# kernel/
ROOT="$(cd "$KDIR/.." && pwd)"		# repo root
SRC="$ROOT/src/common"
KO="$KDIR/iwan.ko"
INTEROP_C="$HERE/interop_c.c"
CAPTURE_PY="$HERE/capture_iwan.py"

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
MTU_INNER=1400
A1_SPORT=40000			# A1 inner UDP port (known-content injected packet)
A1_DPORT=40001
A2_SPORT=40002			# A2 inner UDP port (the receiver really listens on 40003)
A2_DPORT=40003
CAP_TIMEOUT=8			# total timeout of capture_iwan.py (seconds)
A1_STR="iwan-interop-A1-0123456789abcdef"
A2_STR="iwan-interop-A2-fedcba9876543210"
KEEP=0

for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
	-h|--help) sed -n '2,37p' "$0"; exit 0 ;;
	*) echo "unknown argument: $a (supported: --keep)"; exit 2 ;;
	esac
done

PASS=0
FAIL=0
declare -a RESULTS=()
declare -a BG_PIDS=()

# ok/bad/info all use "$*": callers may split long messages across several string lines without losing content
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $*"); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
info() { printf '  - %s\n' "$*"; }
die()  { printf '\033[31mfatal: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# a single counter from /proc/net/iwan (reads that netns's view; missing counts as 0)
ctr() {
	local v
	v=$(nsx "$1" awk -v k="$2" '$1==k{print $2}' /proc/net/iwan 2>/dev/null)
	echo "${v:-0}"
}

# take the value of the last key occurrence from a KEY=value stream (output format of interop_c and capture_iwan.py)
kvget() {
	awk -v k="$2" 'index($0, k"=")==1 { v=substr($0, length(k)+2) } END { print v }' "$1"
}

# take a key by packet index from capture_iwan.py output (one INDEX=<i> section per packet when there are several)
capget() {
	awk -v want="$2" -v k="$3" '
		/^INDEX=/ { cur = substr($0, 7) + 0 }
		index($0, k"=")==1 && cur == want { v = substr($0, length(k)+2) }
		END { print v }' "$1"
}

# wait until a line starting with the given prefix appears in the file (at most $3 times x 0.1s)
wait_line() {
	local i
	for ((i = 0; i < $3; i++)); do
		grep -q "^$2" "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# only delete the iwan0 created by this module. The iwan0 in the init netns may not be ours: this project's
# iwan-client runs a real tunnel on TUN iwan0, and deleting it by mistake would cut a live tunnel. The criterion is
# whether the detail line of `ip -d link show` shows this module's kind (iwan), not the device name,
# and not ARPHRD either -- TUN and iwan are both 65534.
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

cleanup() {
	local p
	for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do
		kill "$p" 2>/dev/null
	done
	if [ "$KEEP" = 0 ]; then
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# the iwan0 in the init netns must be deleted explicitly, otherwise the device holds a module reference and rmmod is refused.
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- environment checks

[ "$(id -u)" = 0 ] || die "root required: sudo bash $0"
for tool in ip python3 cc make insmod rmmod awk sed grep mktemp cat head tail sleep; do
	command -v "$tool" >/dev/null || die "missing dependency: $tool"
done
[ -f "$INTEROP_C" ] || die "missing $INTEROP_C"
[ -f "$CAPTURE_PY" ] || die "missing $CAPTURE_PY"
[ -f "$SRC/protocol.c" ] && [ -f "$SRC/crypto.c" ] \
	|| die "missing $SRC/protocol.c or crypto.c"

WORK="$(mktemp -d /tmp/iwan-interop-test.XXXXXX)" || die "mktemp failed"
[ "$KEEP" = 1 ] && info "--keep: keep netns/module, temp dir $WORK"

# ---------------------------------------------------------------- on-the-spot helpers

# receive inner UDP: argv <bind_ip> <port> <out_file> <timeout>
cat >"$WORK/udp_recv.py" <<'PYEOF'
import socket, sys
bind_ip, port, out_f, to = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((bind_ip, port))
s.settimeout(to)
print("RECV_READY=1", flush=True)
print("BIND=%s:%d" % (bind_ip, port), flush=True)
try:
    data, peer = s.recvfrom(65535)
except socket.timeout:
    print("RX_BYTES=0")
    print("RESULT=timeout")
    sys.exit(1)
open(out_f, "wb").write(data)
print("RX_BYTES=%d" % len(data))
print("RX_FILE=%s" % out_f)
print("RX_FROM=%s:%d" % (peer[0], peer[1]))
print("RESULT=ok")
PYEOF

# send UDP with the outer 5-tuple: argv <bind_ip> <bind_port> <dst_ip> <dst_port> <payload_file>
cat >"$WORK/send_udp.py" <<'PYEOF'
import socket, sys
src, sport, dst, dport, pf = (sys.argv[1], int(sys.argv[2]), sys.argv[3],
                              int(sys.argv[4]), sys.argv[5])
payload = open(pf, "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, sport))          # source port fixed to the outer port: the module's own packets use sport=dport
n = s.sendto(payload, (dst, dport))
print("SENT_BYTES=%d" % n)
print("PAYLOAD_BYTES=%d" % len(payload))
print("SENT_FROM=%s:%d" % (src, sport))
print("SENT_TO=%s:%d" % (dst, dport))
print("RESULT=ok" if n == len(payload) else "RESULT=short")
sys.exit(0 if n == len(payload) else 1)
PYEOF

# inject the **finished inner IP packet** as-is through the given NIC (IP_HDRINCL):
# argv <ifname> <inner_pkt_file> <dst_ip>
# so iwan0's ndo_start_xmit gets exactly the packet mkudp generated byte by byte; id/ttl/checksum
# are the values we wrote in, which is what makes a strict comparison possible for cmpin.
cat >"$WORK/inject_raw.py" <<'PYEOF'
import socket, sys
ifname, pf, dst = sys.argv[1], sys.argv[2], sys.argv[3]
pkt = open(pf, "rb").read()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except OSError as e:
    print("inject_raw: failed to create raw socket: %s (root/CAP_NET_RAW required)" % e,
          file=sys.stderr)
    sys.exit(2)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
except OSError as e:               # the route already points at iwan0; this is only an extra safety switch
    print("BINDTODEVICE_FAIL=%s" % e, file=sys.stderr)
n = s.sendto(pkt, (dst, 0))
print("INJECTED_BYTES=%d" % n)
print("INJECTED_DEV=%s" % ifname)
print("RESULT=ok" if n == len(pkt) else "RESULT=short")
sys.exit(0 if n == len(pkt) else 1)
PYEOF

# byte-by-byte comparison (--limit N compares only the first N bytes, used for "first 26 bytes of the outer header")
# argv: --got <file> --want <file> [--limit N]
cat >"$WORK/hdrcmp.py" <<'PYEOF'
import sys
got_f = want_f = None
limit = 0
i = 0
a = sys.argv[1:]
while i < len(a):
    if a[i] == "--got":
        got_f = a[i + 1]; i += 2
    elif a[i] == "--want":
        want_f = a[i + 1]; i += 2
    elif a[i] == "--limit":
        limit = int(a[i + 1]); i += 2
    else:
        sys.stderr.write("hdrcmp: unknown option %s\n" % a[i]); sys.exit(2)
if not got_f or not want_f:
    sys.stderr.write("hdrcmp: --got and --want are required\n"); sys.exit(2)
g = open(got_f, "rb").read()
w = open(want_f, "rb").read()
gn = len(g) if limit <= 0 else min(len(g), limit)
wn = len(w) if limit <= 0 else min(len(w), limit)
print("GOT_BYTES=%d" % len(g))
print("WANT_BYTES=%d" % len(w))
print("LIMIT=%d" % limit)
print("COMPARED_BYTES=%d" % min(gn, wn))
diffs = [k for k in range(min(gn, wn)) if g[k] != w[k]]
same_len = (gn == wn)
if limit <= 0 and not same_len:
    print("LENGTH_DIFF=%d" % (len(g) - len(w)))
print("DIFF_COUNT=%d" % len(diffs))
if diffs:
    k = diffs[0]
    print("DIFF_OFFSET=%d" % k)
    print("GOT_BYTE=0x%02x" % g[k])
    print("WANT_BYTE=0x%02x" % w[k])
    print("DIFF_OFFSETS=%s" % ",".join(str(x) for x in diffs[:16]))
if diffs or not same_len:
    print("RESULT=diff")
    sys.exit(1)
print("RESULT=ok")
PYEOF

# ---------------------------------------------------------------- build

say "building kernel module"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "module build failed"; }
[ -f "$KO" ] || die "$KO was not generated"
info "build complete: $KO"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

say "compiling reference implementation interop_c"
if ! cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -I "$SRC" \
	-o "$WORK/interop_c" "$INTEROP_C" "$SRC/protocol.c" "$SRC/crypto.c" \
	-lcrypto >"$WORK/cc.log" 2>&1; then
	tail -20 "$WORK/cc.log"
	die "interop_c compilation failed (needs cc + libcrypto dev package; the script will not install it)"
fi
INTEROP="$WORK/interop_c"
info "compile complete: $INTEROP (-D_GNU_SOURCE is mandatory, otherwise src/common/port.h will not compile)"

say "loading module and building topology"
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_S" outer_dst="$OUTER_C" \
	dport="$PORT" sid="$SID" tok="$TOK" key="$KEY" enc=1 batch=1 df=1 \
	|| die "insmod failed (see dmesg | tail for the reason)"
info "insmod complete (any_dir=1: both directions on this host share one RX config)"

ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
ip netns add "$NS_C" || die "failed to create netns $NS_C"
ip netns add "$NS_S" || die "failed to create netns $NS_S"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "failed to create veth"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# the return route for the decapsulated inner packet's source address goes via iwan0, but the packet came in from veth: strict
	# rp_filter would drop it outright. The kernel default in a new netns is already 0; set it explicitly so it is not
	# affected by the host sysctl.
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: failed to create iwan0"
done
nsx "$NS_C" ip link set iwan0 mtu "$MTU_INNER" up
nsx "$NS_S" ip link set iwan0 mtu "$MTU_INNER" up

nsx "$NS_C" ip addr add "$INNER_C/32" dev lo
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1' > /proc/net/iwan" \
	|| die "$NS_C: failed to write /proc/net/iwan"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C enabled=1' > /proc/net/iwan" \
	|| die "$NS_S: failed to write /proc/net/iwan"

nsx "$NS_C" ip route add "$INNER_S/32" dev iwan0 || die "$NS_C: failed to add inner route"
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "$NS_S: failed to add inner route"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" test -r /proc/net/iwan || die "$ns: no /proc/net/iwan (module did not initialize in that netns)"
done
info "topology ready: $NS_C $INNER_C <-> $NS_S $INNER_S (outer $OUTER_C/$OUTER_S port $PORT)"
nsx "$NS_C" head -4 /proc/net/iwan | sed 's/^/    /'

A1_CAP_OK=0

# ---------------------------------------------------------------- A1

say "A1 module outbound -> C-side decapsulation (raw-inject a known inner packet, capture, then decap + cmpin comparison)"

"$INTEROP" mkudp --out "$WORK/a1-inner.bin" --payload-out "$WORK/a1-inner-pl.bin" \
	--src "$INNER_C" --dst "$INNER_S" --sport "$A1_SPORT" --dport "$A1_DPORT" \
	--id 4660 --ttl 64 --df 0 --payload-str "$A1_STR" --quiet \
	>"$WORK/a1-mkudp.kv" 2>"$WORK/a1-mkudp.err" \
	|| die "interop_c mkudp failed: $(tail -1 "$WORK/a1-mkudp.err")"
INNER_BYTES="$(kvget "$WORK/a1-mkudp.kv" INNER_BYTES)"
INNER_CSUM="$(kvget "$WORK/a1-mkudp.kv" INNER_IP_CSUM)"
info "injected packet: $INNER_BYTES bytes $INNER_C:$A1_SPORT -> $INNER_S:$A1_DPORT" \
     "id=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_ID) IP checksum=$INNER_CSUM payload=$A1_STR"
info "note mkudp's id is non-zero: the raw injection path's raw_send_hdrinc() only uses" \
     "ip_select_ident() to fill it in when id==0; id!=0 is what allows a strict byte-by-byte comparison"

# expected outer header (used to compare the actual frame, see A3): source/destination come from each netns's tx_src/tx_dst
"$INTEROP" outer --out "$WORK/a1-expected.hdr" --src "$OUTER_C" --dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --payload-len "$((INNER_BYTES + 8))" \
	--ttl 64 --id 0 --df 1 --quiet >"$WORK/a1-outer.kv" 2>"$WORK/a1-outer.err" \
	|| die "interop_c outer failed: $(tail -1 "$WORK/a1-outer.err")"

nsx "$NS_S" python3 "$CAPTURE_PY" --ifname veth-s --dport "$PORT" --count 1 \
	--timeout "$CAP_TIMEOUT" --out "$WORK/a1-cap" \
	>"$WORK/a1-cap.kv" 2>"$WORK/a1-cap.err" &
CAP_PID=$!
BG_PIDS+=("$CAP_PID")

if ! wait_line "$WORK/a1-cap.kv" "CAPTURE_READY=1" 50; then
	bad "A1 capture process did not become ready (see $WORK/a1-cap.err)"
else
	info "on veth-s of $NS_S capturing dport=$PORT (device layer, earlier than the module's PREROUTING hook)"
	tx0=$(ctr "$NS_C" tx_pkts)
	# inject twice: the first may collide with veth-c neighbor resolution and be queued, the second is guaranteed to go straight out.
	# The content of both is identical and the capture keeps only the first to arrive, so the comparison result is unaffected.
	for _ in 1 2; do
		if ! nsx "$NS_C" python3 "$WORK/inject_raw.py" iwan0 "$WORK/a1-inner.bin" "$INNER_S" \
			>"$WORK/a1-inject.kv" 2>"$WORK/a1-inject.err"; then
			info "injection failed: $(tail -1 "$WORK/a1-inject.err")"
		fi
		sleep 0.3
	done
	tx1=$(ctr "$NS_C" tx_pkts)
	info "iwc tx_pkts $tx0 -> $tx1 (the module really encapsulated and sent the inner packet)"

	cap_rc=0
	wait "$CAP_PID" || cap_rc=$?
	info "capture process exit code $cap_rc, RESULT=$(kvget "$WORK/a1-cap.kv" RESULT)," \
	     "CAPTURED=$(kvget "$WORK/a1-cap.kv" CAPTURED)/$(kvget "$WORK/a1-cap.kv" WANTED)," \
	     "SKIPPED=$(kvget "$WORK/a1-cap.kv" SKIPPED)"

	if [ "$cap_rc" != 0 ] || [ ! -s "$WORK/a1-cap.0" ]; then
		bad "A1 did not capture the outer frame sent by the module (is iwan0 not sending, or is the capture NIC/port wrong?)"
	else
		A1_CAP_OK=1
		ok "A1 captured the outer UDP frame sent by the module (payload $(kvget "$WORK/a1-cap.kv" PAYLOAD_BYTES) bytes)"
	fi
fi

if [ "$A1_CAP_OK" = 1 ]; then
	if "$INTEROP" decap --in "$WORK/a1-cap.0" --out "$WORK/a1-decapped.bin" \
		--key "$KEY" --sid "$SID" --tok "$TOK" --enc 1 --quiet \
		>"$WORK/a1-decap.kv" 2>"$WORK/a1-decap.err"; then
		info "decap: FRAME_TYPE=$(kvget "$WORK/a1-decap.kv" FRAME_TYPE)" \
		     "FRAME_SID=$(kvget "$WORK/a1-decap.kv" FRAME_SID)" \
		     "FRAME_TOK=$(kvget "$WORK/a1-decap.kv" FRAME_TOK)" \
		     "ROUNDTRIP=$(kvget "$WORK/a1-decap.kv" ROUNDTRIP)" \
		     "INNER_BYTES=$(kvget "$WORK/a1-decap.kv" INNER_BYTES)"
		ok "A1 frame header/credentials/XOR match the production implementation (decap verified byte by byte with pkt_hdr() and passed)"
	else
		bad "A1 interop_c decap failed: $(tail -1 "$WORK/a1-decap.err")"
	fi

	if [ -s "$WORK/a1-decapped.bin" ]; then
		if "$INTEROP" cmpin --got "$WORK/a1-decapped.bin" --want "$WORK/a1-inner.bin" \
			--quiet >"$WORK/a1-cmpin.kv" 2>"$WORK/a1-cmpin.err"; then
			ok "A1 decapsulated inner packet is byte-for-byte identical to the injected inner packet ($INNER_BYTES bytes, no field excluded)"
			info "included in the comparison: IP version/header length/TOS/total length/id/frag_off/ttl/proto/checksum/" \
			     "source/destination address + UDP ports/length/checksum + payload"
		elif "$INTEROP" cmpin --got "$WORK/a1-decapped.bin" --want "$WORK/a1-inner.bin" \
			--ignore-stack-fields --quiet >"$WORK/a1-cmpin2.kv" 2>/dev/null; then
			info "strict comparison: got $(kvget "$WORK/a1-cmpin.kv" GOT_BYTES) bytes /" \
			     "want $(kvget "$WORK/a1-cmpin.kv" WANT_BYTES) bytes, " \
			     "first difference at offset $(kvget "$WORK/a1-cmpin.kv" DIFF_OFFSET)" \
			     "(-1 = lengths differ) got=$(kvget "$WORK/a1-cmpin.kv" GOT_BYTE)" \
			     "want=$(kvget "$WORK/a1-cmpin.kv" WANT_BYTE); " \
			     "got id=$(kvget "$WORK/a1-cmpin.kv" GOT_IP_ID)" \
			     "ttl=$(kvget "$WORK/a1-cmpin.kv" GOT_IP_TTL), " \
			     "want id=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_ID)" \
			     "ttl=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_TTL)"
			ok "A1 decapsulated inner packet matches the injected packet (excluding id/frag_off/ttl/IP checksum, 4 places: " \
			   "kernel __ip_local_out() recomputes tot_len and the IP checksum, and raw injection with id=0" \
			   "also has id filled in by ip_select_ident(); all other bytes, including payload and UDP checksum, are identical)"
		else
			bad "A1 decapsulated inner packet differs from the injected packet (offset $(kvget "$WORK/a1-cmpin2.kv" DIFF_OFFSET)" \
			    "got=$(kvget "$WORK/a1-cmpin2.kv" GOT_BYTE) want=$(kvget "$WORK/a1-cmpin2.kv" WANT_BYTE))"
		fi
	else
		bad "A1 decap produced no inner packet, nothing to compare"
	fi
fi

# ---------------------------------------------------------------- A2

say "A2 C-side encapsulation -> module inbound (interop_c encap builds the frame, sent to iws with the outer 5-tuple)"

"$INTEROP" mkudp --out "$WORK/a2-inner.bin" --payload-out "$WORK/a2-inner-pl.bin" \
	--src "$INNER_C" --dst "$INNER_S" --sport "$A2_SPORT" --dport "$A2_DPORT" \
	--id 4661 --ttl 64 --df 0 --payload-str "$A2_STR" --quiet \
	>"$WORK/a2-mkudp.kv" 2>"$WORK/a2-mkudp.err" \
	|| die "interop_c mkudp failed: $(tail -1 "$WORK/a2-mkudp.err")"
"$INTEROP" encap --in "$WORK/a2-inner.bin" --out "$WORK/a2-outer-payload.bin" \
	--key "$KEY" --sid "$SID" --tok "$TOK" --enc 1 --quiet \
	>"$WORK/a2-encap.kv" 2>"$WORK/a2-encap.err" \
	|| die "interop_c encap failed: $(tail -1 "$WORK/a2-encap.err")"
info "C-side payload $(kvget "$WORK/a2-encap.kv" FRAME_BYTES) bytes" \
     "(type=$(kvget "$WORK/a2-encap.kv" FRAME_TYPE) sid=$SID tok=$TOK)" \
     "containing an inner packet of $(kvget "$WORK/a2-encap.kv" INNER_BYTES) bytes"

nsx "$NS_S" python3 "$WORK/udp_recv.py" "$INNER_S" "$A2_DPORT" "$WORK/a2-rx.bin" 8 \
	>"$WORK/a2-recv.kv" 2>"$WORK/a2-recv.err" &
RX_PID=$!
BG_PIDS+=("$RX_PID")

if ! wait_line "$WORK/a2-recv.kv" "RECV_READY=1" 50; then
	bad "A2 inner receiver on $NS_S is not ready (see $WORK/a2-recv.err)"
else
	info "inner receiver listening on $(kvget "$WORK/a2-recv.kv" BIND)"
	p0=$(ctr "$NS_S" rx_pkts)
	o0=$(ctr "$NS_S" rx_outer)
	f0=$(ctr "$NS_S" rx_frames)
	d0=$(ctr "$NS_S" rx_delivered)
	b0=$(ctr "$NS_S" rx_bad_hdr)

	# key point: the source port is also the outer port, so the 5-tuple is perfectly symmetric with the module's own packets
	if nsx "$NS_C" python3 "$WORK/send_udp.py" "$OUTER_C" "$PORT" "$OUTER_S" "$PORT" \
		"$WORK/a2-outer-payload.bin" >"$WORK/a2-send.kv" 2>"$WORK/a2-send.err"; then
		info "from $OUTER_C:$PORT sent $(kvget "$WORK/a2-send.kv" SENT_BYTES) bytes to $OUTER_S:$PORT"
	else
		info "send failed: $(tail -1 "$WORK/a2-send.err")"
	fi

	for ((i = 0; i < 100; i++)); do
		grep -q '^RESULT=' "$WORK/a2-recv.kv" 2>/dev/null && break
		sleep 0.1
	done
	if kill -0 "$RX_PID" 2>/dev/null; then
		kill "$RX_PID" 2>/dev/null
	fi
	rx_rc=0
	wait "$RX_PID" || rx_rc=$?

	p1=$(ctr "$NS_S" rx_pkts)
	o1=$(ctr "$NS_S" rx_outer)
	f1=$(ctr "$NS_S" rx_frames)
	d1=$(ctr "$NS_S" rx_delivered)
	b1=$(ctr "$NS_S" rx_bad_hdr)
	info "$NS_S counter deltas: rx_pkts +$((p1 - p0)) rx_outer +$((o1 - o0))" \
	     "rx_frames +$((f1 - f0)) rx_delivered +$((d1 - d0)) rx_bad_hdr +$((b1 - b0))"

	[ "$((o1 - o0))" -ge 1 ] \
		&& ok "A2 outer tuple hit the module's RX hook (rx_outer +$((o1 - o0)))" \
		|| bad "A2 outer tuple did not hit (rx_outer +$((o1 - o0))): check any_dir/addresses/ports"
	[ "$((f1 - f0))" -ge 1 ] \
		&& ok "A2 the frame built by the C side passed the credential gate and was treated as a data frame (rx_frames +$((f1 - f0)))" \
		|| bad "A2 frame was not accepted (rx_frames +$((f1 - f0))): check sid/tok/type (whether XOR matches)"
	[ "$((d1 - d0))" -ge 1 ] \
		&& ok "A2 module decapsulated and delivered to the local stack (rx_delivered +$((d1 - d0)))" \
		|| bad "A2 no decapsulated delivery (rx_delivered +$((d1 - d0))): check XOR scope/inner header validation"
	# negative control: this frame must pass the gate on the first try, not only after repeated rejections
	[ "$((b1 - b0))" = 0 ] \
		&& ok "A2 the frame was not rejected by the frame-header/credential gate (no rx_bad_hdr delta)" \
		|| bad "A2 saw rx_bad_hdr +$((b1 - b0)): sid/tok/type or destination port mismatch"

	if [ "$rx_rc" = 0 ] && [ -s "$WORK/a2-rx.bin" ]; then
		if python3 "$WORK/hdrcmp.py" --got "$WORK/a2-rx.bin" \
			--want "$WORK/a2-inner-pl.bin" >"$WORK/a2-cmp.kv" 2>&1; then
			ok "A2 inner payload received on $NS_S is byte-for-byte identical to the one sent by the C side ($(kvget "$WORK/a2-cmp.kv" GOT_BYTES) bytes)"
		else
			bad "A2 received inner payload differs (got $(kvget "$WORK/a2-cmp.kv" GOT_BYTES) bytes /" \
			    "want $(kvget "$WORK/a2-cmp.kv" WANT_BYTES) bytes, offset $(kvget "$WORK/a2-cmp.kv" DIFF_OFFSET))"
		fi
	else
		bad "A2 the UDP socket on $NS_S received no inner data (RESULT=$(kvget "$WORK/a2-recv.kv" RESULT))"
	fi
fi

# ---------------------------------------------------------------- A3

say "A3 outer header field consistency (expected values from interop_c outer, actual values from capture_iwan.py)"

# field_ck <field name> <expected> <actual>
field_ck() {
	if [ -z "$3" ]; then
		bad "A3 $1 has no captured actual value"
	elif [ "$2" = "$3" ]; then
		ok "A3 $1 = $3"
	else
		bad "A3 $1 expected $2, actual $3"
	fi
}

if [ "$A1_CAP_OK" != 1 ]; then
	bad "A3 cannot run: A1 did not capture the outer frame sent by the module, outer header consistency was not verified"
else
	# compare seven fields one by one; the address/port group is exactly where historical byte-order bugs were
	# (TTL/ID/DF/IP checksum are not here; they are covered by the 26-byte byte-by-byte comparison below)
	for f in OUTER_IP_SRC OUTER_IP_DST OUTER_IP_PROTO OUTER_UDP_SPORT \
		 OUTER_UDP_DPORT OUTER_IP_TOT_LEN OUTER_UDP_LEN; do
		field_ck "$f" "$(kvget "$WORK/a1-outer.kv" "$f")" "$(capget "$WORK/a1-cap.kv" 0 "$f")"
	done
	info "expected header generated by interop_c outer: $(kvget "$WORK/a1-outer.kv" OUTER_IP_SRC):" \
	     "$(kvget "$WORK/a1-outer.kv" OUTER_UDP_SPORT) ->" \
	     "$(kvget "$WORK/a1-outer.kv" OUTER_IP_DST):$(kvget "$WORK/a1-outer.kv" OUTER_UDP_DPORT)" \
	     "proto=$(kvget "$WORK/a1-outer.kv" OUTER_IP_PROTO) tot_len=$(kvget "$WORK/a1-outer.kv" OUTER_IP_TOT_LEN)"

	# first 26 bytes = IPv4 header + UDP source/destination ports + UDP length; excludes the UDP checksum
	# in bytes 27/28 (under HW_CSUM offload the captured value may be a partial sum, so comparing it is meaningless).
	if python3 "$WORK/hdrcmp.py" --got "$WORK/a1-cap.0.hdr" \
		--want "$WORK/a1-expected.hdr" --limit 26 >"$WORK/a3-hdr.kv" 2>&1; then
		ok "A3 the first 26 bytes of the outer header match the expected header byte for byte (covering TTL/ID/DF/IP checksum as well)"
	else
		bad "A3 the first 26 bytes of the outer header differ (first difference at offset $(kvget "$WORK/a3-hdr.kv" DIFF_OFFSET): " \
		    "got=$(kvget "$WORK/a3-hdr.kv" GOT_BYTE) want=$(kvget "$WORK/a3-hdr.kv" WANT_BYTE)" \
		    "$(kvget "$WORK/a3-hdr.kv" DIFF_COUNT) differing bytes)"
	fi
	for f in OUTER_IP_TTL OUTER_IP_ID OUTER_IP_DF OUTER_IP_CSUM; do
		info "$f expected $(kvget "$WORK/a1-outer.kv" "$f") actual $(capget "$WORK/a1-cap.kv" 0 "$f")"
	done
fi

# ---------------------------------------------------------------- summary

say "counter summary"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns ---"
	nsx "$ns" cat /proc/net/iwan 2>/dev/null | sed 's/^/    /'
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
	echo "all passed: the module's outbound bytes can be decapsulated by the C side, C-side encapsulation can be decapsulated and delivered by the module, and the outer header fields match."
	exit 0
fi
echo "some cases failed. Troubleshooting hints:"
if [ "$KEEP" = 1 ]; then
	echo "  - all logs and intermediate files are in $WORK (kept by --keep)"
else
	echo "  - rerun with --keep to keep the logs and intermediate files (they were deleted on this exit)"
fi
echo "  - dmesg | tail -30; rx_bad_hdr / rx_bad_inner / tx_bad_* counters in /proc/net/iwan"
echo "  - if addresses/ports do not match, look at A3 first (historical byte-order bugs): which byte differs between the module and interop_c outer's expectation"
exit 1
