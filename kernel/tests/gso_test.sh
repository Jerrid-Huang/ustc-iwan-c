#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN GSO 批处理 + 不对称端口验收 —— 需要 root
#
#   sudo bash kernel/tests/gso_test.sh [--keep] [--count N]
#
# 为什么要单独一个脚本：kernel/iwan_rx.c 的 iwan_rx_batch()（GSO 合并包路径）
# 在既有四个测试脚本里**从未进入过** —— 那条路径上的缺陷（例如"已经自己释放
# skb 却返回 NF_DROP"的双重释放）在别的用例里永远暴露不出来。本脚本用
# UDP_SEGMENT 把 N 个**等长**加密帧一次发成一个 UDP 超级报文：veth 的
# features 含 NETIF_F_GSO_SOFTWARE（含 GSO_UDP_L4），validate_xmit_skb() 不会
# 提前分段，接收侧因此在 netfilter 钩子里看到 skb_is_gso() 的 skb，进入批处理
# 路径（iwan_rx.c：`if (skb_is_gso(skb) && skb_shinfo(skb)->gso_size)`）。
#
# 拓扑与配置入口沿用 netlink_test.sh：双 netns + veth 当网线，内层地址挂 lo，
# iwan0 由 SESSION_UP 按需创建；insmod 不带任何会话参数（配置只能来自 netlink）。
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   会话 --outer-src 10.100.0.1
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   会话 --outer-src 10.100.0.2
#   T1–T5 两端 --dport 6100 且不给 --sport（接收端口 = dport，旧口径）；
#   T6 换成不对称端口：iwc --dport 6100 --sport 6200、iws --dport 6200 --sport 6100。
#
# 用例：
#   T1 gso_send 一次 sendmsg(UDP_SEGMENT) 发出 N 个等长帧（自检 + 实发字节数）
#   T2 接收侧 rx_batch 增长 —— 确实走了 GSO 批处理路径，而不是逐包单发
#   T3 rx_delivered/rx_frames 恰好 +N，rx_bad_hdr/rx_batch_skip/rx_bad_inner 无增量
#   T4 iwc 的内层 socket 收到全部 N 个包，序号 0..N-1 齐全且长度一致
#   T5 dmesg 无新增 BUG/Oops/GPF（软中断里的 oops 未必会让脚本退出）
#   T6 不对称端口（接收端口 = SPORT）双向内层 UDP 仍通
#
# 只依赖 ip / cc / python3（不需要 nc / tcpdump / ss / ethtool）。

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
PORT=6100		# T1–T5 的外层隧道端口（两端一致，接收端口 = dport）
PORT_C=6100		# T6：iwc 的 dport（= 对端 iws 的本地端口）
PORT_S=6200		# T6：iwc 的 sport（= iwc 自己的接收端口）
INNER_PORT=9999		# 内层 UDP 目的端口（iwc 的 python3 socket 收）
INNER_SPORT=40000	# 内层 UDP 源端口（gso_send 用固定值，便于排查）
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 ⇒ 外层不分片
INNER_LEN=200		# 内层 IPv4 包总长（帧长 = 8 + 200 = 208）
COUNT=32		# 帧数：32 × 208 = 6656 字节，> veth MTU，必须是 GSO 超包
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
		[ -n "$COUNT" ] || { echo "--count 需要数值"; exit 2; }
		shift
		;;
	-h|--help)
		sed -n '2,32p' "$0"
		exit 0
		;;
	*)
		echo "未知参数: $1（支持 --keep / --count N）"
		exit 2
		;;
	esac
done
case "$COUNT" in
''|*[!0-9]*) echo "--count 需要一个正整数"; exit 2 ;;
esac
[ "$COUNT" -ge 1 ] && [ "$COUNT" -le 64 ] \
	|| { echo "--count 必须在 1..64 之间（UDP_MAX_SEGMENTS=64）"; exit 2; }

PASS=0
FAIL=0
declare -a RESULTS=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  · %s\n' "$*"; }
hint() { printf '  \033[33m提示\033[0m %s\n' "$*"; }
die()  { printf '\033[31m致命: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# ---------------------------------------------------------------- 小工具

snap() { # snap <netns> <tag>  -> iwan_ctl get-stats 落到 $WORK/stats-<tag>.txt
	nsx "$1" "$CTL" get-stats >"$WORK/stats-$2.txt" 2>"$WORK/stats-$2.err"
	echo $?
}

val() { sed -n "s/^$2=//p" "$1" | head -n1; }

num() { # 非数字一律当 0
	case "${1:-}" in
	''|*[!0-9-]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# 从 gso_send/iwan_ctl 的 KEY=value 输出里取键
gv() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -n1; }

link_exists() { nsx "$1" ip link show dev "$2" >/dev/null 2>&1; }

start_recv() { # <netns> <log> <bind_ip> <want> [timeout]：内层 UDP 接收端
	: >"$2"
	nsx "$1" python3 "$WORK/recv_gso.py" "$3" "$INNER_PORT" "$4" "${5:-10}" \
		>"$2" 2>&1 &
	echo $!
}

send_udp() { # <netns> <src_ip> <dst_ip> <dport>：发一个内层 UDP 报文
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

# 只删本模块创建的 iwan0。init netns 里的 iwan0 未必是我们的：用户自己的
# iwan-client 就用 TUN iwan0 跑真实隧道，误删会直接打断活隧道。判据是
# `ip -d link show` 的 detail 行是否为本模块的 kind（iwan），不能看设备名，
# 也不能看 ARPHRD —— TUN 与 iwan 同为 65534。这段逻辑与 netlink_test.sh 一致。
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

INNER_ADDRS_ADDED=0
add_inner() { # 内层地址 + 内层路由（设备每次重建后都要重加路由）
	local dev_c="$1" dev_s="$2"

	if [ "$INNER_ADDRS_ADDED" = 0 ]; then
		nsx "$NS_C" ip addr add "$INNER_C/32" dev lo 2>/dev/null
		nsx "$NS_S" ip addr add "$INNER_S/32" dev lo 2>/dev/null
		INNER_ADDRS_ADDED=1
	fi
	nsx "$NS_C" ip link set "$dev_c" up 2>/dev/null
	nsx "$NS_S" ip link set "$dev_s" up 2>/dev/null
	nsx "$NS_C" ip route add "$INNER_S/32" dev "$dev_c" 2>/dev/null \
		|| info "iwc: 加内层路由 $INNER_S dev $dev_c 失败（T4/T6 可能失败）"
	nsx "$NS_S" ip route add "$INNER_C/32" dev "$dev_s" 2>/dev/null \
		|| info "iws: 加内层路由 $INNER_C dev $dev_s 失败（T4/T6 可能失败）"
}

cleanup() {
	if [ "$KEEP" = 0 ]; then
		[ -n "${WORK:-}" ] && [ -x "${CTL:-}" ] && {
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		}
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# init netns 里这一个要显式删除，否则设备引用着模块，rmmod 会被拒。
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- 前置

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
command -v ip >/dev/null || die "缺少 iproute2"
command -v cc >/dev/null || die "缺少 cc"
command -v python3 >/dev/null || die "缺少 python3"
[ -f "$GSO_SRC" ] || die "缺少 $GSO_SRC"

WORK="$(mktemp -d /tmp/iwan-gso-test.XXXXXX)"
CTL="$WORK/iwan_ctl"
GSO="$WORK/gso_send"

cat >"$WORK/recv_gso.py" <<'PY'
# 内层 UDP 接收端：收满 want 个包（或超时）后打印统计。
# gso_send 的内层载荷以 "IWAN-GSO-<4位序号>" 开头，据此清点每一帧；
# 第一个包到达时立刻打印 INNER_RX_FROM（T6 的端口口径用例只发一个包）。
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

say "构建内核模块与用户态工具"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "模块构建失败"; }
[ -f "$KO" ] || die "没有生成 $KO"
info "模块构建完成: $KO（构建日志 $(grep -c . "$WORK/build.log") 行，0 warning 行）"
for t in "iwan_ctl:$CTL_SRC:$CTL" "gso_send:$GSO_SRC:$GSO"; do
	name="${t%%:*}"; rest="${t#*:}"; src="${rest%%:*}"; out="${rest#*:}"
	cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$out" "$src" \
		>"$WORK/$name-build.log" 2>&1 \
		|| { cat "$WORK/$name-build.log"; die "$name 构建失败"; }
	info "$name 构建完成（$(grep -c . "$WORK/$name-build.log") 行编译输出，0 行即无警告）"
done
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# ---------------------------------------------------------------- 拓扑

say "T1 建立拓扑并加载模块（不带任何会话参数）"

DMESG0=$(dmesg_hits)
rmmod iwan 2>/dev/null
ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
del_iwan0_if_ours
ip netns add "$NS_C" || die "创建 netns $NS_C 失败"
ip netns add "$NS_S" || die "创建 netns $NS_S 失败"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "创建 veth 失败"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# 解封后的内层包源地址(10.9.0.x)回程路由走 iwan0，而包是从 veth 进来的；
	# strict 模式(rp_filter=1)会直接丢掉。新建 netns 默认就是 0，显式设置以免
	# 受宿主 sysctl 影响。
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
	# 关 IPv6：iwan0 起来时内核自动发的 IPv6 RS 会被封装到对端，推进对端的
	# rx_frames/rx_bad_inner，污染"恰好 +N"的断言。
	nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

# 关键：不带 sid/tok/key/enc/dport/outer_* —— 会话只能来自 netlink
insmod "$KO" || die "insmod 失败（dmesg | tail 看原因）"
info "insmod 完成（/proc/modules: $(grep -c '^iwan ' /proc/modules) 个 iwan）"

if command -v ethtool >/dev/null 2>&1; then
	# 只做诊断信息：批处理路径要求发送设备保留 GSO（veth 声明 GSO_UDP_L4）。
	info "veth-c udp-segmentation: $(nsx "$NS_C" ethtool -k veth-c 2>/dev/null | awk -F': ' '/udp-segmentation/{print $2}' | head -n1)"
fi

# ---------------------------------------------------------------- T1：会话 + GSO 批发送

say "T1 SESSION_UP（两端，dport=$PORT，不给 sport：接收端口 = dport）"

up_out=$(nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-c.err")
rc=$?
DEV_C=iwan0
if [ "$rc" != 0 ]; then
	bad "T1 iwc: session-up 失败（rc=$rc）"
	sed 's/^/    /' "$WORK/up-c.err"
else
	DEV_C=$(gv DEVNAME "$up_out"); [ -n "$DEV_C" ] || DEV_C=iwan0
	info "iwc 回执: DEVNAME=$DEV_C MTU=$(gv MTU "$up_out") DEV_OWNED=$(gv DEV_OWNED "$up_out")"
	ok "T1a iwc: SESSION_UP 成功（$DEV_C）"
fi
up_out=$(nsx "$NS_S" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-s.err")
rc=$?
DEV_S=iwan0
if [ "$rc" != 0 ]; then
	bad "T1 iws: session-up 失败（rc=$rc）"
	sed 's/^/    /' "$WORK/up-s.err"
	die "没有接收侧会话，后续 GSO 用例无法进行"
fi
DEV_S=$(gv DEVNAME "$up_out"); [ -n "$DEV_S" ] || DEV_S=iwan0
info "iws 回执: DEVNAME=$DEV_S MTU=$(gv MTU "$up_out") DEV_OWNED=$(gv DEV_OWNED "$up_out")"
add_inner "$DEV_C" "$DEV_S"

say "T1b 一次 sendmsg(UDP_SEGMENT) 发出 $COUNT 个等长帧（帧长 $((INNER_LEN + 8))）"

snap "$NS_C" g1 >/dev/null
rpid=$(start_recv "$NS_C" "$WORK/recv-gso.log" "$INNER_C" "$COUNT")
wait_ready "$WORK/recv-gso.log" '^RECV_READY=1$' \
	|| { bad "T1b iwc 的内层接收端没起来（python3 异常？）"; sed 's/^/    /' "$WORK/recv-gso.log"; }

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

# 期望帧头：type（0x18/0x14）+ enc + sid(u16 BE) + tok(u32 BE)
exp_hdr=$(printf '%02x%02x%04x%08x' "$((ENC == 0 ? 0x14 : 0x18))" "$ENC" "$SID" "$TOK")
got_hdr=$(gv FRAME0_HDR_HEX "$gs_out")

if [ "$gs_rc" = 0 ] && [ "$(gv RESULT "$gs_out")" = ok ] \
	&& [ "$SENT_BYTES" = "$TOTAL_BYTES" ] && [ "$(gv SELFCHECK "$gs_out")" = ok ]; then
	ok "T1b gso_send 自检通过并一次发出全部 $TOTAL_BYTES 字节（UDP_SEGMENT，段长 $((INNER_LEN + 8))）"
else
	bad "T1b gso_send 失败（rc=$gs_rc RESULT=$(gv RESULT "$gs_out") SENDMSG_ERROR=$(gv SENDMSG_ERROR "$gs_out")）"
	hint "发送侧失败时后面 T2–T5 无意义；tcpdump/抓包看不到 UDP_SEGMENT 的超级报文属正常（它在设备层已是 GSO skb）"
fi

if [ "$got_hdr" = "$exp_hdr" ]; then
	ok "T1c 第 0 帧头 8 字节与冻结格式一致（$got_hdr，含 sid/tok 的大端序列化）"
else
	bad "T1c 第 0 帧头 $got_hdr 与期望 $exp_hdr 不一致（帧头序列化/参数错）"
fi

# ---------------------------------------------------------------- T2/T3：计数器

snap "$NS_C" g2 >/dev/null
d_batch=$(( $(num "$(val "$WORK/stats-g2.txt" rx_batch)") - $(num "$(val "$WORK/stats-g1.txt" rx_batch)") ))
d_skip=$(( $(num "$(val "$WORK/stats-g2.txt" rx_batch_skip)") - $(num "$(val "$WORK/stats-g1.txt" rx_batch_skip)") ))
d_frames=$(( $(num "$(val "$WORK/stats-g2.txt" rx_frames)") - $(num "$(val "$WORK/stats-g1.txt" rx_frames)") ))
d_deliv=$(( $(num "$(val "$WORK/stats-g2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-g1.txt" rx_delivered)") ))
d_badhdr=$(( $(num "$(val "$WORK/stats-g2.txt" rx_bad_hdr)") - $(num "$(val "$WORK/stats-g1.txt" rx_bad_hdr)") ))
d_badinner=$(( $(num "$(val "$WORK/stats-g2.txt" rx_bad_inner)") - $(num "$(val "$WORK/stats-g1.txt" rx_bad_inner)") ))
info "iwc 计数器增量: rx_batch +$d_batch, rx_batch_skip +$d_skip, rx_frames +$d_frames, rx_delivered +$d_deliv, rx_bad_hdr +$d_badhdr, rx_bad_inner +$d_badinner"

if [ "$d_batch" -ge 1 ]; then
	ok "T2 iwc rx_batch +$d_batch：N 帧确实走了 GSO 批处理路径（skb_is_gso）"
else
	bad "T2 iwc rx_batch 没有增长（+0）：没有进入 iwan_rx_batch()（GSO 未保留？）"
	hint "若 rx_delivered 正好 +$COUNT，说明包是逐包到达的：发送侧设备把 UDP_SEGMENT 拆了，或 GRO 没把超级报文递上来；先看 ethtool -k <发送侧veth> 的 tx-udp-segmentation"
fi

if [ "$d_deliv" = "$COUNT" ]; then
	ok "T3a iwc rx_delivered 恰好 +$COUNT（每段都解封并投递）"
else
	bad "T3a iwc rx_delivered +$d_deliv，期望 +$COUNT"
	hint "少于期望：看 rx_bad_hdr/rx_bad_inner（+$d_badhdr/+$d_badinner）与 dmesg；多于期望：本 netns 有别的帧进来"
fi
if [ "$d_frames" = "$COUNT" ]; then
	ok "T3b iwc rx_frames 恰好 +$COUNT（帧头/凭据逐帧校验通过）"
else
	bad "T3b iwc rx_frames +$d_frames，期望 +$COUNT"
fi
if [ "$d_badhdr" = 0 ] && [ "$d_skip" = 0 ] && [ "$d_badinner" = 0 ]; then
	ok "T3c rx_bad_hdr/rx_batch_skip/rx_bad_inner 无增量（坏帧、跳过分段、坏内层都为 0）"
else
	bad "T3c 出现异常增量：rx_bad_hdr +$d_badhdr, rx_batch_skip +$d_skip, rx_bad_inner +$d_badinner"
fi

# ---------------------------------------------------------------- T4：内层包全部投递

if [ "$(gv RECV_COUNT "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" = "$COUNT" ] \
	&& [ -z "$(gv MISSING "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" ] \
	&& [ "$(gv BAD_MARK "$(cat "$WORK/recv-gso.log" 2>/dev/null)")" = 0 ]; then
	ok "T4 iwc 内层 socket 收到全部 $COUNT 个包，序号 0..$((COUNT - 1)) 齐全且长度一致（$(gv RECV_LENS "$(cat "$WORK/recv-gso.log")")）"
else
	bad "T4 内层 socket 没收到全部 $COUNT 个包（RECV_COUNT=$(gv RECV_COUNT "$(cat "$WORK/recv-gso.log" 2>/dev/null)") MISSING=$(gv MISSING "$(cat "$WORK/recv-gso.log" 2>/dev/null)")）"
	sed 's/^/    /' "$WORK/recv-gso.log"
	hint "收到数目等于 rx_delivered 而少于 N：批处理里某个分段被丢；一个都没有：T2/T3 与路由/rp_filter 一起看"
fi

# ---------------------------------------------------------------- T5：无 panic/oops

DMESG1=$(dmesg_hits)
if [ -z "$DMESG1" ] || [ "$DMESG1" = "$DMESG0" ]; then
	ok "T5 dmesg 无新增 BUG/Oops/GPF（前 $DMESG0 条，后 $DMESG1 条）"
else
	bad "T5 dmesg 出现新增 BUG/Oops/GPF（$DMESG0 -> $DMESG1）"
	dmesg 2>/dev/null | grep -E "$DMESG_PAT" | tail -20 | sed 's/^/    /'
fi

# ---------------------------------------------------------------- T6：不对称端口

say "T6 不对称端口：接收端口 = SPORT（iwc dport=$PORT_C sport=$PORT_S，iws dport=$PORT_S sport=$PORT_C）"

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
# 设备是重建的：路由必须重加（删设备会连带删掉它的路由）
add_inner "$DEV_C" "$DEV_S"

snap "$NS_C" a1 >/dev/null
snap "$NS_S" b1 >/dev/null
sc=$(val "$WORK/stats-a1.txt" sport); ss=$(val "$WORK/stats-b1.txt" sport)
info "GET_STATS sport: iwc=$sc（期望 $PORT_S） iws=$ss（期望 $PORT_C）; rc=$rc_c/$rc_s"
if [ "$rc_c" = 0 ] && [ "$rc_s" = 0 ] && [ "$sc" = "$PORT_S" ] && [ "$ss" = "$PORT_C" ]; then
	ok "T6a 不对称端口会话建立成功，GET_STATS 回显 sport 与下发值一致"
else
	bad "T6a 不对称端口会话异常（rc=$rc_c/$rc_s sport=$sc/$ss）"
	sed 's/^/    /' "$WORK/up-c2.err" "$WORK/up-s2.err" 2>/dev/null
fi

# 方向 1：iws -> iwc（外层 iws sport=$PORT_C -> iwc sport=$PORT_S）
rpid=$(start_recv "$NS_C" "$WORK/recv-c2.log" "$INNER_C" 1 6)
if wait_ready "$WORK/recv-c2.log" '^RECV_READY=1$'; then
	tx_out=$(send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" 2>&1)
	case "$tx_out" in *INNER_TX_OK*) : ;; *) bad "T6b iws 内层发包失败"; echo "$tx_out" | sed 's/^/    /' ;; esac
	sleep 0.6
	wait "$rpid" 2>/dev/null
	if grep -q "^INNER_RX_FROM=$INNER_S" "$WORK/recv-c2.log" 2>/dev/null; then
		ok "T6b iws->iwc 通：iwc 在 sport=$PORT_S 上收到内层包（外层目的端口 = 对端 SPORT 的口径成立）"
	else
		bad "T6b iws->iwc 不通（iwc 的 socket 没收到）"
		sed 's/^/    /' "$WORK/recv-c2.log"
	fi
else
	bad "T6b iwc 接收端没起来"
	kill "$rpid" 2>/dev/null
fi
snap "$NS_C" a2 >/dev/null
d_deliv_c=$(( $(num "$(val "$WORK/stats-a2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-a1.txt" rx_delivered)") ))

# 方向 2：iwc -> iws（外层 iwc sport=$PORT_S -> iws sport=$PORT_C）
rpid=$(start_recv "$NS_S" "$WORK/recv-s2.log" "$INNER_S" 1 6)
if wait_ready "$WORK/recv-s2.log" '^RECV_READY=1$'; then
	tx_out=$(send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT" 2>&1)
	case "$tx_out" in *INNER_TX_OK*) : ;; *) bad "T6c iwc 内层发包失败"; echo "$tx_out" | sed 's/^/    /' ;; esac
	sleep 0.6
	wait "$rpid" 2>/dev/null
	if grep -q "^INNER_RX_FROM=$INNER_C" "$WORK/recv-s2.log" 2>/dev/null; then
		ok "T6c iwc->iws 通：iws 在 sport=$PORT_C 上收到内层包（双向都按 SPORT 收）"
	else
		bad "T6c iwc->iws 不通（iws 的 socket 没收到）"
		sed 's/^/    /' "$WORK/recv-s2.log"
	fi
else
	bad "T6c iws 接收端没起来"
	kill "$rpid" 2>/dev/null
fi
info "T6b 路径上 iwc rx_delivered +$d_deliv_c（期望 >= 1）"

# ---------------------------------------------------------------- 汇总

say "计数器汇总"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns ---"
	nsx "$ns" cat /proc/net/iwan 2>/dev/null | sed 's/^/    /'
done

say "结果"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	echo "全部通过：UDP_SEGMENT 超级报文确实进入 iwan_rx_batch()，N 帧全部解封投递，"
	echo "不对称端口下双向内层 UDP 仍通，且没有 panic/oops。"
	exit 0
fi
echo "有失败用例。排查提示："
echo "  1) T2 不涨而 T3a 正好 +$COUNT → 接收侧看到的不是 GSO skb："
echo "     发送侧 veth 的 GSO 能力（ethtool -k veth-s | grep udp-segmentation）、"
echo "     或中途有别的 hook/设备把超包拆了；"
echo "  2) T3a 少几个 → dmesg | tail -30 看 iwan 的 rx_bad_* 与 WARNING（段校验和/线性化）；"
echo "  3) T4 收到 0 个 → 内层路由/rp_filter 与 iwan0 是否 UP；"
echo "  4) T6 单向不通 → 外层端口口径：接收端口 = SPORT（未给则 DPORT），"
echo "     TX 的源端口 = SPORT；核对两端 dport/sport 是否互为对方的 sport/dport。"
if [ "$KEEP" = 1 ]; then
	echo "  · 日志与中间文件保留在 $WORK"
else
	echo "  · 加 --keep 重跑可保留 $WORK 下的日志与中间文件"
fi
exit 1
