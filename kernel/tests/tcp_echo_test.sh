#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN 零用户态数据路径 —— 本机端到端验收（需要 root）
#
#   sudo bash kernel/tests/tcp_echo_test.sh [--keep] [--quick]
#
# 拓扑（两个 netns 用 veth 当网线，各自挂内核虚拟网卡 iwan0）：
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#   iwc: ip route add 10.9.0.2/32 dev iwan0   （出站交给 iwan0 封装）
#   iws: ip route add 10.9.0.1/32 dev iwan0
#
# 出站：iwan0 的 ndo_start_xmit 拿到"栈已分段、校验和已算完"的成品 IP 包 →
#       XOR → 8B 帧头 → UDP → 外层 IP → ip_local_out 走 veth。
# 入站：模块在 PRE_ROUTING(prio=-300) 匹配外层四元组 → 需要时钩子内联
#       ip_defrag 重组外层 → 校验 sid/tok → 剥头 → XOR 还原 → 交给内核栈。
#
# 用例：
#   T1 TCP 小包 echo（三次握手 + 短段，非 GSO 路径）
#   T2 TCP 4 MiB echo（GSO 分段 + 满 MTU 路径）
#   T3 UDP 8×3000B echo（内层分片：iwan0 mtu 1400 ⇒ 内层 3 片）
#   T4 外层分片：df=0 + veth mtu 1000 ⇒ 内外两层都分片，验证钩子内联重组
#   T5 负向：构造帧验证凭据闸门（tok 错则帧头即被拒，tok 对才进内层校验）
# 另外全程盯 Tcp InCsumErrors / RetransSegs 与模块计数器。

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
MTU_INNER=1400          # iwan0 mtu：1400 + 36 = 1436 < 1500 ⇒ 外层不分片
KEEP=0
QUICK=0

for a in "$@"; do
	case "$a" in
	--keep)  KEEP=1 ;;
	--quick) QUICK=1 ;;
	*) echo "未知参数: $a"; exit 2 ;;
	esac
done

PASS=0
FAIL=0
declare -a RESULTS=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  · %s\n' "$*"; }
die()  { printf '\033[31m致命: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# /proc/net/iwan 里的单个计数器（读的是该 netns 的视图）
ctr() { nsx "$1" awk -v k="$2" '$1==k{print $2}' /proc/net/iwan 2>/dev/null; }
# /proc/net/snmp Tcp: 行的字段（$13=RetransSegs, $16=InCsumErrors）
tcpsnmp() { nsx "$1" awk -v f="$2" '/^Tcp:/{v=$f} END{print v+0}' /proc/net/snmp; }

# 只删本模块创建的 iwan0。init netns 里的 iwan0 未必是我们的：本项目的
# iwan-client 就用 TUN iwan0 跑真实隧道，误删会直接打断活隧道。判据是
# `ip -d link show` 的 detail 行是否为本模块的 kind（iwan），不能看设备名，
# 也不能看 ARPHRD —— TUN 与 iwan 同为 65534。
del_iwan0_if_ours() {
	ip -d link show dev iwan0 2>/dev/null | grep -qE '^[[:space:]]+iwan[[:space:]]' || return 0
	ip link del iwan0 2>/dev/null
}

cleanup() {
	if [ "$KEEP" = 0 ]; then
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# 模块在每个 netns 都建了 iwan0；init netns 里那一个要显式删除，
		# 否则设备引用着模块，rmmod 会被内核拒绝（Module iwan is in use）。
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
[ -f "$ECHO_PY" ] || die "缺少 $ECHO_PY"
command -v ip >/dev/null || die "缺少 iproute2"

WORK="$(mktemp -d /tmp/iwan-tcp-test.XXXXXX)"
say "构建内核模块"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "模块构建失败"; }
[ -f "$KO" ] || die "没有生成 $KO"
info "构建完成: $KO"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

say "加载模块并建立拓扑"
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_S" outer_dst="$OUTER_C" \
	dport="$PORT" sid="$SID" tok="$TOK" key="$KEY" enc=1 batch=1 df=1 \
	|| die "insmod 失败（dmesg | tail 看原因）"
info "insmod 完成（any_dir=1：本机双向共用一份 RX 配置）"

ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
ip netns add "$NS_C" || die "创建 netns $NS_C 失败"
ip netns add "$NS_S" || die "创建 netns $NS_S 失败"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "创建 veth 失败"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link set lo up
	# 反向路径过滤：解封后的内层包源地址(10.9.0.x)的回程路由走 iwan0，
	# 而包是从 veth 进来的，strict 模式(rp_filter=1)会直接丢掉。
	# 新建 netns 的内核默认值本来就是 0，这里显式设置以免受宿主 sysctl 影响。
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

# iwan0 由 rtnl_link_ops 提供，需要显式创建（不再由 pernet init 自动建）
for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: 创建 iwan0 失败"
done
nsx "$NS_C" ip link set iwan0 mtu "$MTU_INNER" up
nsx "$NS_S" ip link set iwan0 mtu "$MTU_INNER" up

# 每 netns 的出站外层端点（一个模块实例服务所有 netns，方向不同只能按 netns 配）
nsx "$NS_C" ip addr add "$INNER_C/32" dev lo
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S' > /proc/net/iwan" \
	|| die "$NS_C: 写 /proc/net/iwan 失败"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C' > /proc/net/iwan" \
	|| die "$NS_S: 写 /proc/net/iwan 失败"

nsx "$NS_C" ip route add "$INNER_S/32" dev iwan0 || die "$NS_C: 加内层路由失败"
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "$NS_S: 加内层路由失败"

info "拓扑就绪：$NS_C $INNER_C <-> $NS_S $INNER_S（外层 $OUTER_C/$OUTER_S 端口 $PORT）"
nsx "$NS_C" head -4 /proc/net/iwan | sed 's/^/    /'

# ---------------------------------------------------------------- 用例框架

run_tcp() { # run_tcp <名称> <字节数> [超时]
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

run_udp() { # run_udp <名称> <size> <count>
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

say "T1 TCP 小包 echo（握手 + 短段）"
if run_tcp T1 65536; then
	ok "T1 TCP 64 KiB 双向回显一致"
else
	bad "T1 TCP 64 KiB 回显失败"
fi

if [ "$QUICK" = 0 ]; then
	say "T2 TCP 4 MiB echo（GSO 分段 + 满 MTU）"
	rc_c=$(tcpsnmp "$NS_C" 16); rt_c=$(tcpsnmp "$NS_C" 13)
	if run_tcp T2 4194304; then
		ok "T2 TCP 4 MiB 双向回显一致"
	else
		bad "T2 TCP 4 MiB 回显失败"
	fi
	dc=$(( $(tcpsnmp "$NS_C" 16) - rc_c )); dr=$(( $(tcpsnmp "$NS_C" 13) - rt_c ))
	info "客户端 netns: Tcp InCsumErrors +$dc, RetransSegs +$dr"
	[ "$dc" -eq 0 ] && ok "T2 无 TCP 校验和错误（XOR 未破坏校验和）" \
			 || bad "T2 出现 $dc 个 TCP 校验和错误"
	[ "$dr" -le 20 ] && ok "T2 重传 $dr 个（正常范围）" || bad "T2 重传过多: $dr"
fi

# ---------------------------------------------------------------- T3

say "T3 UDP 8×3000B echo（内层分片）"
d_before=$(ctr "$NS_S" rx_delivered)
if run_udp T3 3000 8; then
	ok "T3 8 个 3000B 数据报回显一致（内层分片 + 内核重组）"
else
	bad "T3 UDP 大包回显失败"
fi
d_after=$(ctr "$NS_S" rx_delivered)
info "服务端 rx_delivered $d_before -> $d_after（>1 说明内层确实被分片又重组）"
[ "$((d_after - d_before))" -gt 8 ] && ok "T3 内层分片路径已覆盖（每包多片）" \
				   || bad "T3 内层包没有分片（mtu 设置没生效？）"

# ---------------------------------------------------------------- T4

say "T4 外层分片：df=0 + veth mtu 1000（内外两层都分片）"
echo 0 > /sys/module/iwan/parameters/df
nsx "$NS_C" ip link set veth-c mtu 1000
nsx "$NS_S" ip link set veth-s mtu 1000
r_before=$(ctr "$NS_S" rx_reasm)
if run_udp T4 3000 8; then
	ok "T4 外层分片下回显一致（钩子内联 ip_defrag 重组成功）"
else
	bad "T4 外层分片回显失败"
fi
r_after=$(ctr "$NS_S" rx_reasm)
info "服务端 rx_reasm $r_before -> $r_after"
if [ "$((r_after - r_before))" -gt 0 ]; then
	ok "T4 外层重组发生在钩子里（rx_reasm 增长）"
elif lsmod | grep -q '^nf_conntrack\b'; then
	# conntrack 在 prio=-400 的 nf_defrag_ipv4 钩子会先把外层拼好再送下来，
	# 本模块的内联 defrag 就成了冗余（无害）。此时靠功能正确性判定。
	info "nf_conntrack 已加载：外层可能已被 -400 的 defrag 钩子重组（本模块内联重组冗余但无害）"
	ok "T4 外层分片下功能正确（重组由 conntrack 的 defrag 钩子完成）"
else
	bad "T4 钩子没有做外层重组，且没有 conntrack 可代劳 —— 分片路径有缺陷"
fi
echo 1 > /sys/module/iwan/parameters/df
nsx "$NS_C" ip link set veth-c mtu 1500
nsx "$NS_S" ip link set veth-s mtu 1500
if run_tcp T4b 262144; then
	ok "T4b 恢复 df=1/mtu1500 后 TCP 仍正常"
else
	bad "T4b 恢复后 TCP 失败"
fi

# ---------------------------------------------------------------- T5

# 凭据 sid/tok 是模块级全局配置：一个模块实例服务所有 netns，改
# /sys/module/iwan/parameters/tok 等于把两端一起改掉，构不成"不匹配"。
# 所以负向用例直接构造帧从客户端 netns 发出，验证数据面的凭据闸门：
#   · tok 错的帧       → 帧头校验就被拒，只涨 rx_bad_hdr
#   · tok 对但内层非法 → 已过凭据闸门，涨 rx_frames 与 rx_bad_inner
# 两条一起看才能证明"是凭据在区分"，而不是把外来包统统丢掉。
say "T5 负向：构造帧验证凭据闸门（错 tok 必丢，对 tok 才进内层校验）"

cat >"$WORK/send_frame.py" <<'PYEOF'
import socket, struct, sys
# argv: <mode> <src_ip> <sid> <dst_ip> <port>
mode, src, sid, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, port))     # 源端口固定为外层端口：模块自己发的包就是 sport=dport
if mode == "garbage":
    payload = bytes(60)                              # 首字节 0 != 0x18，非 iWAN 帧
else:
    payload = struct.pack("!BBHI", 0x18, 1, sid, int(mode)) + bytes(40)
s.sendto(payload, (dst, port))
PYEOF

h_before=$(ctr "$NS_S" rx_bad_hdr)
i_before=$(ctr "$NS_S" rx_bad_inner)
f_before=$(ctr "$NS_S" rx_frames)
p_before=$(ctr "$NS_S" rx_pkts)
o_before=$(ctr "$NS_S" rx_outer)

# 三帧，外层五元组完全相同，只有载荷里的凭据不同：
#   ① 垃圾载荷（非 iWAN 帧）     → 帧头被拒
#   ② tok 错                     → 帧头被拒
#   ③ tok 对、内层非法           → 过闸门，止于内层校验
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
	&& ok "T5 三帧都到达服务端钩子（rx_pkts +$((p_after - p_before))）" \
	|| bad "T5 构造帧没到达钩子（rx_pkts +$((p_after - p_before))）：先查发送侧路由/端口，不是凭据问题"
[ "$((h_after - h_before))" -ge 2 ] \
	&& ok "T5 垃圾帧与错 tok 帧都在帧头被拒（rx_bad_hdr +$((h_after - h_before))）" \
	|| bad "T5 帧头闸门没生效（rx_bad_hdr +$((h_after - h_before))，期望 +2）"
[ "$((i_after - i_before))" -ge 1 ] \
	&& ok "T5 对 tok 的帧通过凭据闸门、止于内层校验（rx_bad_inner +$((i_after - i_before))）" \
	|| bad "T5 对 tok 的帧没走到内层校验（闸门把对的也拒了？）"
[ "$((f_after - f_before))" = 1 ] \
	&& ok "T5 只有凭据正确那一帧被当数据帧接收（rx_frames +1）" \
	|| bad "T5 rx_frames 增量应为 1，实际 $((f_after - f_before))"

# ---------------------------------------------------------------- 汇总

say "计数器汇总"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns ---"
	nsx "$ns" cat /proc/net/iwan | sed 's/^/    /'
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
	echo "全部通过：入站解封（含内联重组、凭据校验）与出站封装（校验和/分段正确）都工作。"
	exit 0
fi
echo "有失败用例。排查提示：dmesg | tail -30；/proc/net/iwan 的 rx_bad_* / tx_bad_* 计数；"
echo "             Tcp InCsumErrors 增长通常意味着 XOR 破坏了校验和（出站路径问题）。"
exit 1
