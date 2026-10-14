#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# 对照实验：同一份 iWAN 协议语义，出站分别走
#   ① 内核模块 iwan0（ndo_start_xmit，本仓库的产品路径）
#   ② LWT_XMIT 上的 eBPF 程序（kernel/bpf/lwt_encap.bpf.c，对照路径）
# 入站两边都用内核模块解封，只有出站不同 ⇒ 差异只能来自出站路径。
#
#   sudo bash kernel/tests/ab_lwt_test.sh [--keep]
#
# 三组：
#   A  出站走 iwan0，enc=1（XOR）           → TCP echo 必须通过（基线）
#   B  出站走 LWT eBPF，enc=1（XOR）        → 必须失败，且服务端 Tcp InCsumErrors 增长
#   B2 出站走 LWT eBPF，enc=0（不 XOR）     → 必须通过
#   B 与 B2 只差一个 XOR 开关，于是失败原因被锁定在
#   「XOR 发生在 L4 校验和计算之前」这一点上（模块把 XOR 放在 ndo_start_xmit，
#   那时校验和已算完，所以没有这个问题）。
#
# 依赖：内核模块构建工具链、clang（-target bpf）、bpftool、iproute2。

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
info() { printf '  · %s\n' "$*"; }
die()  { printf '\033[31m致命: %s\033[0m\n' "$*"; exit 2; }

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

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
for c in bpftool python3 ip; do
	command -v "$c" >/dev/null || die "缺少 $c（对照实验需要：bpftool、python3、iproute2）"
done
# clang 由 kernel/bpf/Makefile 自己找（PATH 里没有时会退回 /usr/lib/llvm-*/bin）

WORK="$(mktemp -d /tmp/iwan-ab-lwt.XXXXXX)"

say "构建"
make -C "$KDIR" >"$WORK/build-mod.log" 2>&1 || { tail -20 "$WORK/build-mod.log"; die "内核模块构建失败"; }
make -C "$KDIR/bpf" >"$WORK/build-bpf.log" 2>&1 || { tail -20 "$WORK/build-bpf.log"; die "eBPF 对照程序构建失败"; }
[ -f "$KO" ] && [ -f "$BPF_OBJ" ] || die "构建产物缺失"
info "iwan.ko + lwt_encap.o 就绪"

say "加载模块、建拓扑"
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_S" outer_dst="$OUTER_C" \
	dport="$PORT" sid="$SID" tok="$TOK" key="$KEY" enc=1 batch=1 df=1 \
	|| die "insmod 失败"
ip netns del "$NS_C" 2>/dev/null; ip netns del "$NS_S" 2>/dev/null
ip netns add "$NS_C" || die "创建 netns 失败"
ip netns add "$NS_S" || die "创建 netns 失败"
ip link add veth-c netns "$NS_C" type veth peer name veth-s netns "$NS_S" \
	|| die "创建 veth 失败"
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
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: 创建 iwan0 失败"
	nsx "$ns" ip link set iwan0 mtu 1400 up || die "$ns: iwan0 起不来"
done
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S' > /proc/net/iwan" || die "写 proc 失败"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C' > /proc/net/iwan" || die "写 proc 失败"
# 服务端回程始终走模块（只有客户端出站换路径）
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "服务端内层路由失败"

# 跑一次 TCP echo，返回 0/1；期望失败时用 --expect-fail
try_tcp() { # try_tcp <名字> <expect:ok|fail>
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

# ---------------------------------------------------------------- A 组

say "A 组：出站走 iwan0（内核模块，XOR）"
set_enc 1
nsx "$NS_C" ip route replace "$INNER_S/32" dev iwan0
if try_tcp A ok; then
	ok "A 组 TCP echo 通过（基线：模块出站 + XOR）"
else
	bad "A 组失败 —— 基线不成立，先查 kernel/tests/tcp_echo_test.sh"
fi

# ---------------------------------------------------------------- B 组

say "B 组：出站走 LWT eBPF（XOR）"
# src 必须显式写：LWT 路由挂在 veth-c（外层口）上，不指定时内核按出口设备
# 主地址选源，内层 SYN 会变成 10.100.0.1 而不是 10.9.0.1 —— 服务端照样能解封
# 投递（计数全涨），但回程按外层地址直发，连接必然超时。A 组没这问题是因为
# iwan0 上没有任何 IPv4 地址，源地址只能落回 lo 上的 10.9.0.1。
nsx "$NS_C" ip route replace "$INNER_S/32" dev veth-c src "$INNER_C" \
	encap bpf xmit obj "$BPF_OBJ" sec lwt_xmit || die "挂 LWT eBPF 程序失败"

# LWT_XMIT 跑在 validate_xmit_skb() 之前，此刻内层 TCP 校验和还是
# CHECKSUM_PARTIAL。若出口设备声称支持校验和卸载（veth 的 VETH_FEATURES 含
# NETIF_F_HW_CSUM），软件就永远不会去算它，对端按字段原值校验必然 InCsumErrors
# —— 这与 XOR 无关，enc=0 也会失败。关掉 veth-c 的 tx 校验和卸载，就把"算校验和"
# 推到了 LWT 钩子之后，于是 enc=0 应当通过、enc=1 仍然失败，XOR 时机成为唯一变量。
if command -v ethtool >/dev/null 2>&1; then
	nsx "$NS_C" ethtool -K veth-c tx off >/dev/null 2>&1 \
		&& info "已关闭 veth-c 的 tx 校验和卸载" \
		|| info "关闭 veth-c tx 校验和卸载失败（继续，B2 可能因校验和未计算而失败）"
else
	info "未找到 ethtool，保持默认卸载设置"
fi
python3 "$LWT_CFG" set --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --sid "$SID" --tok "$TOK" --key "$KEY" --enc 1 \
	|| die "写 lwt_cfg_map 失败"
info "map 已配置；先看计数器基线"
python3 "$LWT_CFG" counters | sed 's/^/    /'

ic_before=$(tcpsnmp "$NS_S" 16)
if try_tcp B fail; then
	ok "B 组如预期失败：XOR 之后校验和由后面的步骤算，对端认为校验和错误"
else
	bad "B 组竟然通过了 —— 说明该内核在 LWT 之前就已完成 L4 校验和（与预期不符，需要记录）"
fi
ic_after=$(tcpsnmp "$NS_S" 16)
info "服务端 Tcp InCsumErrors: $ic_before -> $ic_after（InErrs=$(( $(tcpsnmp "$NS_S" 14) ))）"
if [ "$((ic_after - ic_before))" -gt 0 ]; then
	ok "B 组失败原因确认：服务端 TCP 校验和错误增长 +$((ic_after - ic_before))"
else
	bad "B 组失败但服务端没有校验和错误 —— 失败原因不是校验和，需要另找"
fi
cnt5=$(python3 "$LWT_CFG" counters | awk -F'[= ]' '{for(i=1;i<=NF;i++) if($i=="c5") print $(i+1)}' | tail -1)
info "lwt_cnt 加密发出 c5=$cnt5"
[ "${cnt5:-0}" -gt 0 ] && ok "B 组确有加密报文从 LWT 路径发出（c5>0）" \
		       || bad "B 组 LWT 路径没有发出加密报文（程序没生效？）"

# ---------------------------------------------------------------- B2 组

say "B2 组：出站走 LWT eBPF（不 XOR）—— 只差一个开关"
set_enc 0
# B2 的失败必须定位到钩子的具体一步：rx_pkts 涨而 rx_outer 不涨 ⇒ 外层五元组
# 不被接受；rx_outer 与 rx_bad_hdr 都涨 ⇒ 帧类型/凭据闸门拒收（enc=0 时期望
# PT_DATA）；rx_frames/rx_delivered 也涨 ⇒ 入站已解封投递，剩下的只能是回程。
# 回程要看两件事：客户端钩子有没有收到并解封 SYN-ACK，服务端到底有没有应答。
rxctr() { nsx "$1" awk -v k="$2" '$1==k{print $2+0}' /proc/net/iwan 2>/dev/null; }
snap() {
	for ns in "$NS_C" "$NS_S"; do
		info "[$ns] $(for k in rx_pkts rx_outer rx_bad_hdr rx_bad_inner rx_frames rx_delivered; do
			printf '%s=%s ' "$k" "$(rxctr "$ns" "$k")"
		done)InErrs=$(tcpsnmp "$ns" 14) InCsumErrors=$(tcpsnmp "$ns" 16) OutSegs=$(tcpsnmp "$ns" 11)"
	done
}
info "B2 前置快照"
snap
python3 "$LWT_CFG" set --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --sid "$SID" --tok "$TOK" --key "$KEY" --enc 0 \
	|| die "写 lwt_cfg_map 失败"
if try_tcp B2 ok; then
	ok "B2 组通过：LWT 的封装/重路由/解封都没问题，问题只在 XOR"
else
	bad "B2 组也失败 —— 说明 LWT 路径还有 XOR 之外的问题"
fi
info "B2 后置快照"
snap
set_enc 1

# ---------------------------------------------------------------- 汇总

say "结果"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	cat <<'EOF'
结论：内核模块出站（ndo_start_xmit，校验和算完之后再 XOR）正确；
      LWT_XMIT 的 eBPF 出站只要打开 XOR 就必然破坏校验和，
      关掉 XOR 立刻恢复正常 ⇒ 失效原因就是 XOR 与校验和计算时机的冲突，
      而不是"eBPF 写不了隧道"。
EOF
	exit 0
fi
echo "有对照结论不符预期的用例，请看上面的 client/server 日志与计数器。"
exit 1
