#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN 控制面（genetlink）验收 —— 需要 root
#
#   sudo bash kernel/tests/netlink_test.sh [--keep] [--any-dir] [--extra]
#
# 与 tcp_echo_test.sh 的分工：那份用模块参数 + /proc 配数据面，这份只走 netlink
# （insmod 不带任何会话参数，验证 netlink 是唯一配置来源），按 CONTROL-PLANE.md
# 的冻结 ABI 验收：
#
#   SESSION_UP -> 内层数据 -> 控制帧事件 -> GET_STATS -> SESSION_DOWN
#
# 拓扑（外层用 veth 当网线，内层地址挂 lo，iwan0 由 SESSION_UP 按需创建）：
#
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#
# 会话（IWAN_A_OUTER_SRC = 本端外层地址，IWAN_A_OUTER_DST = 对端外层地址）：
#   iwc: --outer-src 10.100.0.1 --outer-dst 10.100.0.2 --dport 6100
#   iws: --outer-src 10.100.0.2 --outer-dst 10.100.0.1 --dport 6100
#
# 方向说明：事件按 netns 投递（CONTROL-PLANE.md 第 9 节），所以"要在 iwc 里
# 观测到事件/keepalive"就必须由 iwc 收到帧 —— 控制帧从 iws 发往 iwc:6100，
# events/get-stats 都在 iwc 跑；内层数据两个方向各验一次（T4）。
#
# 用例：
#   T1 insmod 不带会话参数：配置前两端都没有 iwan0，/proc 凭据为 0
#   T2 SESSION_UP：两端按需建 iwan0、状态 UP、MTU 与回执一致
#   T3 GET_STATS 配置快照与下发值一致（sid/tok/enc/outer-src/outer-dst/dport）
#   T4 内层 UDP 双向：iws->iwc 断言 iwc 的 rx_* 增长且 iwc 用户态 socket 收到；
#      再 iwc->iws 断言 iws 的 rx_* 增长
#   T5 控制帧 PT_PING_REQ -> IWAN_EV_CTRL_FRAME（打印帧类型与 hex）
#   T6 收到 PING 后 last_keepalive_ms 非零
#   T7 PT_CLOSE -> IWAN_EV_CTRL_FRAME + IWAN_EV_PEER_CLOSE
#   T8 SESSION_DOWN：iwan0 被删除、再次 GET_STATS 凭据清零/会话不存在
#   T9/T10（--extra，可选）SET_PEER 漂移、SET_ENABLED 停/启数据面
#
# 只依赖 ip / cc / python3（不需要 ethtool / tcpdump / ss / nc）。

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
SRC="$HERE/iwan_ctl.c"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
OUTER_S2=10.100.0.9	# --extra: SET_PEER 对端漂移用的第二个外层地址
PORT=6100		# 外层隧道端口
INNER_PORT=9999		# 内层 UDP 目的端口（T4 用 iwc 的 python3 socket 收）
INNER_PORT2=9998	# T4 反方向用（不监听，只看计数）
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 ⇒ 外层不分片
KEEP=0
ANY_DIR=0
EXTRA=0

for a in "$@"; do
	case "$a" in
	--keep)    KEEP=1 ;;
	--any-dir) ANY_DIR=1 ;;
	--extra)   EXTRA=1 ;;
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
hint() { printf '  \033[33m提示\033[0m %s\n' "$*"; }
die()  { printf '\033[31m致命: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# ---------------------------------------------------------------- 小工具

# get-stats 快照：stdout 落到 KEY=value 文件，便于反复 grep
snap() { # snap <netns> <tag>  -> 回显 iwan_ctl 的退出码
	nsx "$1" "$CTL" get-stats >"$WORK/stats-$2.txt" 2>"$WORK/stats-$2.err"
	echo $?
}

val() { # val <快照文件> <key>
	sed -n "s/^$2=//p" "$1" | head -n1
}

num() { # num <值>：非数字一律当 0
	case "${1:-}" in
	''|*[!0-9]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# dport 之类被字节反转时的提示（be16 vs 主机序的经典错误）
revport() { echo $(( (($1 >> 8) | (($1 & 0xff) << 8)) & 0xffff )); }

link_exists() { nsx "$1" ip link show dev "$2" >/dev/null 2>&1; }

link_flags() { # <netns> <dev> -> 尖括号里的标志串
	nsx "$1" ip -o link show dev "$2" 2>/dev/null \
		| sed -n 's/^[0-9]*: [^:]*: <\([^>]*\)>.*/\1/p' | head -n1
}

link_mtu() { # <netns> <dev>
	nsx "$1" ip -o link show dev "$2" 2>/dev/null \
		| awk '{for (i = 1; i <= NF; i++) if ($i == "mtu") print $(i + 1)}' \
		| head -n1
}

is_up() { # <netns> <dev>
	case ",$(link_flags "$1" "$2")," in
	*,UP,*) return 0 ;;
	*) return 1 ;;
	esac
}

# 在 netns 里起一个内层 UDP 接收端；先打印 RECV_READY=1 再 recvfrom，避免竞态
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

# 从 netns 里发一个内层 UDP 报文（源地址显式绑定，保证走 iwan0 的路由）
send_udp() { # <netns> <src_ip> <dst_ip> <dport>
	nsx "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(b"iwan-netlink-test", (sys.argv[2], int(sys.argv[3])))
print("INNER_TX_OK")
' "$2" "$3" "$4"
}

# events 后台监听：READY=1 之后脚本才发帧，避免"还没入组就发"的竞态
start_events() { # <netns> <log> <count> <timeout>
	: >"$2"
	nsx "$1" "$CTL" events --count "$3" --timeout "$4" >"$2" 2>&1 &
	echo $!
}

# 等待后台进程打出就绪行。两种就绪标记不同，别用一个模式去等另一个：
#   UDP 接收端 → RECV_READY=1      iwan_ctl events → READY=1
# 这里写错过一次：等接收端日志却匹配 ^READY=1$，永远超时，于是报"接收端没起来"，
# 而真正的后果是发包那一步在 if 分支里被整个跳过，看起来像"模块不发包"。
wait_ready() { # <log> [pattern]
	local pat="${2:-^READY=1$}"
	for _ in $(seq 1 60); do
		grep -q "$pat" "$1" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

# ---------------------------------------------------------------- 清理

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
		# 先让模块自己拆会话（顺便验证幂等：设备可能已经不在了）
		[ -n "${WORK:-}" ] && [ -x "${CTL:-}" ] && {
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		}
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# 模块在每个 netns 都可能建过 iwan0；init netns 里这一个要显式删除，
		# 否则设备引用着模块，rmmod 会被内核拒绝（Module iwan is in use）。
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
command -v python3 >/dev/null || die "缺少 python3（构造控制帧/收发内层 UDP 用）"
[ -f "$SRC" ] || die "缺少 $SRC"

WORK="$(mktemp -d /tmp/iwan-netlink-test.XXXXXX)"
CTL="$WORK/iwan_ctl"

say "构建内核模块与用户态工具"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "模块构建失败"; }
[ -f "$KO" ] || die "没有生成 $KO"
info "模块构建完成: $KO"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$CTL" "$SRC" \
	>"$WORK/ctl-build.log" 2>&1 \
	|| { cat "$WORK/ctl-build.log"; die "iwan_ctl 构建失败"; }
info "工具构建完成: $CTL（$(grep -c . "$WORK/ctl-build.log") 行编译输出，0 行即无警告）"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# ---------------------------------------------------------------- 拓扑

say "T1 建立拓扑并加载模块（不带任何会话参数）"

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
	# strict 模式(rp_filter=1)会直接丢掉。新建 netns 默认就是 0，这里显式设置
	# 以免受宿主 sysctl 影响。
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

INSMOD_ARGS=()
[ "$ANY_DIR" = 1 ] && INSMOD_ARGS+=(any_dir=1)
# 关键：不带 sid/tok/key/enc/dport/outer_* —— 会话只能来自 netlink
insmod "$KO" ${INSMOD_ARGS[@]+"${INSMOD_ARGS[@]}"} \
	|| die "insmod 失败（dmesg | tail 看原因）"
if grep -q '^iwan ' /proc/modules; then
	info "insmod 完成${INSMOD_ARGS[0]+（${INSMOD_ARGS[*]}）}：iwan 已加载"
else
	info "insmod 完成${INSMOD_ARGS[0]+（${INSMOD_ARGS[*]}）}（/proc/modules 里没看到 iwan？）"
fi

if link_exists "$NS_C" iwan0 || link_exists "$NS_S" iwan0; then
	bad "T1 未下发会话却已存在 iwan0（模块参数/自动建卡没关掉？）"
else
	ok "T1 insmod 后未下发会话：两端都没有 iwan0（配置只能来自 netlink）"
fi
pc_sid=$(nsx "$NS_C" awk '$1=="sid"{print $2}' /proc/net/iwan 2>/dev/null)
pc_tok=$(nsx "$NS_C" awk '$1=="tok"{print $2}' /proc/net/iwan 2>/dev/null)
info "iwc /proc/net/iwan sid=${pc_sid:-不可读} tok=${pc_tok:-不可读}（未下发会话时应为 0）"

# ---------------------------------------------------------------- T1b（设备类型闸门）

# 同名但**不是**本模块建的设备必须拒绝复用（kernel/iwan_netlink.c 的
# iwan_dev_ensure 闸门）。这是安全底线而不是洁癖：本项目的 iwan-client 就用
# TUN 建了一张 iwan0 跑真实隧道，而 TUN 与 iwan 的 ARPHRD 同为 65534，只看
# 名字与链路类型根本分不出来；老实现只 pr_warn 然后**继续复用**，还会顺手改
# 它的 MTU —— 那会直接打断用户正在跑的隧道。
say "T1b 设备类型闸门：预置一张非 iwan 的 iwan0，SESSION_UP 必须失败且不动它"

GATE_ERR="$(sed -n 's/.*: //p' "$WORK/gate-add.err" 2>/dev/null | head -n1)"
if link_exists "$NS_C" iwan0; then
	bad "T1b 预置条件不成立：iwc 里已经有 iwan0（前面哪一步建的？）"
elif nsx "$NS_C" ip link add iwan0 type veth peer name iwan0x \
		2>"$WORK/gate-add.err"; then
	# 故意把它设成 DOWN + 非默认 MTU：会话若"接管"了这张设备，MTU 会被改成
	# 请求值、flag 里会多出 UP，这两点都能观测到。
	nsx "$NS_C" ip link set iwan0 mtu 1300 2>/dev/null
	gate_mtu0=$(link_mtu "$NS_C" iwan0)
	gate_flags0=$(link_flags "$NS_C" iwan0)
	nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
		--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
		--dport "$PORT" --mtu "$MTU" >"$WORK/gate-up.out" 2>"$WORK/gate-up.err"
	rc=$?
	if [ "$rc" != 0 ]; then
		ok "T1b 非 iwan 的 iwan0 存在时 SESSION_UP 被拒绝（rc=$rc，期望 -EBUSY=16）"
	else
		bad "T1b 非 iwan 的 iwan0 被复用了（SESSION_UP 竟然成功：收到了 $(val "$WORK/gate-up.out" DEVNAME)）"
	fi
	gate_detail=$(nsx "$NS_C" ip -d link show dev iwan0 2>/dev/null)
	if printf '%s\n' "$gate_detail" | grep -qE '^[[:space:]]+iwan[[:space:]]'; then
		bad "T1b 预置的 veth 被改成了 iwan 类型设备（不该发生）"
	elif printf '%s\n' "$gate_detail" | grep -qE '^[[:space:]]+veth[[:space:]]'; then
		ok "T1b 预置设备仍是 veth（没有被本模块接管）"
	else
		bad "T1b 找不到预置 veth 的 detail 行（断言依据不足）"
	fi
	if [ "$(link_mtu "$NS_C" iwan0)" = "$gate_mtu0" ] &&
	   [ "$(link_flags "$NS_C" iwan0)" = "$gate_flags0" ]; then
		ok "T1b 预置设备的 MTU/状态未被改动（$gate_mtu0 / $gate_flags0：既没改 MTU 也没被置 UP）"
	else
		bad "T1b 预置设备被动过：MTU $(link_mtu "$NS_C" iwan0)←$gate_mtu0，flags $(link_flags "$NS_C" iwan0)←$gate_flags0"
	fi
	# 清掉，让 T2 走正常路径（这张 veth 是我们自己建的，删它不会碰到别人的设备）
	nsx "$NS_C" ip link del iwan0 2>/dev/null
	nsx "$NS_C" ip link del iwan0x 2>/dev/null
else
	info "跳过 T1b：iwc 里建不出 veth 预置设备（${GATE_ERR:-原因未知}）—— 闸门未被验证"
fi

# ---------------------------------------------------------------- T2

say "T2 SESSION_UP（两端，命令一律在各自 netns 内执行）"

up_out=$(nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-c.err")
rc=$?
DEV_C=iwan0
MTU_C="$MTU"
if [ "$rc" != 0 ]; then
	bad "T2 iwc: iwan_ctl session-up 失败（rc=$rc）"
	sed 's/^/    /' "$WORK/up-c.err"
else
	DEV_C=$(printf '%s\n' "$up_out" | sed -n 's/^DEVNAME=//p' | head -n1)
	MTU_C=$(printf '%s\n' "$up_out" | sed -n 's/^MTU=//p' | head -n1)
	MTU_FROM_REPLY=$(printf '%s\n' "$up_out" | sed -n 's/^MTU_FROM_REPLY=//p' | head -n1)
	DEV_OWNED=$(printf '%s\n' "$up_out" | sed -n 's/^DEV_OWNED=//p' | head -n1)
	[ -n "$DEV_C" ] || DEV_C=iwan0
	[ -n "$MTU_C" ] || MTU_C="$MTU"
	info "iwc 回执: DEVNAME=$DEV_C MTU=$MTU_C MTU_FROM_REPLY=${MTU_FROM_REPLY:-0} DEV_OWNED=${DEV_OWNED:-未回传}"
	if link_exists "$NS_C" "$DEV_C"; then
		ok "T2a iwc: SESSION_UP 后 $DEV_C 已按需创建"
	else
		bad "T2a iwc: SESSION_UP 后没有 $DEV_C"
	fi
	# 新增属性 IWAN_A_DEV_OWNED：1 = 这张 iwan0 是模块建/认领的
	# （SESSION_DOWN 负责删），0 = 不是我们建的。这里查的是正常路径：
	# netns 是刚建的、T1b 预置的 veth 已清掉，设备只可能来自本次
	# SESSION_UP，所以必须是 1。
	if [ "$DEV_OWNED" = 1 ]; then
		ok "T2e iwc: 回执 DEV_OWNED=1（设备由模块创建，SESSION_DOWN 会负责删除）"
	else
		bad "T2e iwc: 回执 DEV_OWNED=${DEV_OWNED:-缺失}，期望 1（新属性没回传，或归属判定错了）"
	fi
	if is_up "$NS_C" "$DEV_C"; then
		ok "T2b iwc: $DEV_C 状态 UP"
	else
		bad "T2b iwc: $DEV_C 不是 UP（flags=$(link_flags "$NS_C" "$DEV_C")）"
		nsx "$NS_C" ip link set "$DEV_C" up 2>/dev/null \
			&& info "已手动置 UP 以便继续（T2b 仍记 FAIL）"
	fi
	real_mtu=$(link_mtu "$NS_C" "$DEV_C")
	if [ "$real_mtu" = "$MTU_C" ]; then
		ok "T2c iwc: 设备 MTU=$real_mtu 与回执一致"
	else
		bad "T2c iwc: 设备 MTU=$real_mtu 与回执 MTU=$MTU_C 不一致"
	fi
fi

up_out=$(nsx "$NS_S" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_S" --outer-dst "$OUTER_C" \
	--dport "$PORT" --mtu "$MTU" 2>"$WORK/up-s.err")
rc=$?
DEV_S=iwan0
if [ "$rc" != 0 ]; then
	bad "T2d iws: iwan_ctl session-up 失败（rc=$rc）"
	sed 's/^/    /' "$WORK/up-s.err"
else
	DEV_S=$(printf '%s\n' "$up_out" | sed -n 's/^DEVNAME=//p' | head -n1)
	[ -n "$DEV_S" ] || DEV_S=iwan0
	if link_exists "$NS_S" "$DEV_S" && is_up "$NS_S" "$DEV_S"; then
		ok "T2d iws: $DEV_S 已创建且 UP（对端会话就绪，T4/T5 才有接收侧）"
	else
		bad "T2d iws: $DEV_S 不存在或不是 UP（flags=$(link_flags "$NS_S" "$DEV_S")）"
		nsx "$NS_S" ip link set "$DEV_S" up 2>/dev/null
	fi
fi

# 内层地址与路由：设备要存在才能加路由，所以放在 SESSION_UP 之后
nsx "$NS_C" ip addr add "$INNER_C/32" dev lo 2>/dev/null
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo 2>/dev/null
nsx "$NS_C" ip link set "$DEV_C" up 2>/dev/null
nsx "$NS_S" ip link set "$DEV_S" up 2>/dev/null
nsx "$NS_C" ip route add "$INNER_S/32" dev "$DEV_C" 2>/dev/null \
	|| info "iwc: 加内层路由 $INNER_S dev $DEV_C 失败（后续 T4 可能失败）"
nsx "$NS_S" ip route add "$INNER_C/32" dev "$DEV_S" 2>/dev/null \
	|| info "iws: 加内层路由 $INNER_C dev $DEV_S 失败（后续 T4 可能失败）"
info "拓扑就绪：$NS_C $INNER_C <-> $NS_S $INNER_S（外层 $OUTER_C/$OUTER_S 端口 $PORT）"

# ---------------------------------------------------------------- T3

say "T3 GET_STATS 配置快照与下发值一致（iwc）"
snap "$NS_C" snap1 >/dev/null
for k in sid tok enc key outer_src outer_dst sport dport mtu devname enabled \
	last_keepalive_ms peer_state; do
	info "$k=$(val "$WORK/stats-snap1.txt" "$k")"
done

mism=""
for kv in "sid=$SID" "tok=$TOK" "enc=$ENC" "outer_src=$OUTER_C" \
	  "outer_dst=$OUTER_S" "dport=$PORT"; do
	k=${kv%%=*}
	e=${kv#*=}
	g=$(val "$WORK/stats-snap1.txt" "$k")
	[ "$g" = "$e" ] || mism="$mism $k(得到\"$g\"期望\"$e\")"
done
if [ -z "$mism" ]; then
	ok "T3 配置快照与下发值一致（sid/tok/enc/outer-src/outer-dst/dport）"
else
	bad "T3 配置快照不一致:$mism"
	sed 's/^/    /' "$WORK/stats-snap1.err"
	gd=$(val "$WORK/stats-snap1.txt" dport)
	if [ -n "$gd" ] && [ "$gd" = "$(revport "$PORT")" ]; then
		hint "dport 回显 $gd 正好是 $PORT 的字节反转：检查 IWAN_A_DPORT 是否按 be16 解码（iwan_genl.h 注释是 be16）"
	fi
	gi=$(val "$WORK/stats-snap1.txt" outer_src)
	if [ "$gi" = "$(echo "$OUTER_C" | awk -F. '{print $4"."$3"."$2"."$1}')" ]; then
		hint "outer_src 回显 $gi 是 $OUTER_C 的字节反转：检查 IWAN_A_OUTER_SRC/DST 是否按 be32 解码"
	fi
fi

# ---------------------------------------------------------------- T4

say "T4 内层 UDP 双向（先 iws->iwc，再 iwc->iws）"

snap "$NS_C" c1 >/dev/null
snap "$NS_S" s1 >/dev/null
rpid=$(start_udp_recv "$NS_C" "$INNER_C" "$INNER_PORT" "$WORK/recv-c.log")
if wait_ready "$WORK/recv-c.log" '^RECV_READY=1$'; then
	# 发包独立判成败：发送端自己失败时不能记成"接收端没起来"
	tx_out=$(send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" 2>&1)
	case "$tx_out" in
	*INNER_TX_OK*) : ;;
	*) bad "T4a iws 的内层发包失败（python3 异常？）"
	   echo "$tx_out" | sed 's/^/    /' ;;
	esac
	sleep 0.5
	wait "$rpid" 2>/dev/null
else
	bad "T4a iwc 的内层 UDP 接收端没起来（python3 异常？）"
	sed 's/^/    /' "$WORK/recv-c.log"
	kill "$rpid" 2>/dev/null
fi
snap "$NS_C" c2 >/dev/null
snap "$NS_S" s2 >/dev/null

d_pkts=$(( $(num "$(val "$WORK/stats-c2.txt" rx_pkts)") - $(num "$(val "$WORK/stats-c1.txt" rx_pkts)") ))
d_frames=$(( $(num "$(val "$WORK/stats-c2.txt" rx_frames)") - $(num "$(val "$WORK/stats-c1.txt" rx_frames)") ))
d_deliv=$(( $(num "$(val "$WORK/stats-c2.txt" rx_delivered)") - $(num "$(val "$WORK/stats-c1.txt" rx_delivered)") ))
d_outer=$(( $(num "$(val "$WORK/stats-c2.txt" rx_outer)") - $(num "$(val "$WORK/stats-c1.txt" rx_outer)") ))
d_tx_s=$(( $(num "$(val "$WORK/stats-s2.txt" tx_pkts)") - $(num "$(val "$WORK/stats-s1.txt" tx_pkts)") ))
info "iws->iwc: iwc rx_pkts $(val "$WORK/stats-c1.txt" rx_pkts) -> $(val "$WORK/stats-c2.txt" rx_pkts) (+$d_pkts), rx_outer +$d_outer, rx_frames +$d_frames, rx_delivered +$d_deliv"
info "iws tx_pkts $(val "$WORK/stats-s1.txt" tx_pkts) -> $(val "$WORK/stats-s2.txt" tx_pkts) (+$d_tx_s)"

if [ "$d_pkts" -gt 0 ] || [ "$d_frames" -gt 0 ] || [ "$d_deliv" -gt 0 ]; then
	ok "T4a iws->iwc: iwc 的 rx_pkts/rx_frames/rx_delivered 至少一项增长（+$d_pkts/+$d_frames/+$d_deliv）"
else
	bad "T4a iws->iwc: iwc 三个计数都没涨（发包侧或入站钩子没工作）"
	hint "查 iws tx_pkts（+$d_tx_s）、iwc 的外层地址方向（IWAN_A_OUTER_SRC=本端/OUTER_DST=对端）与 dport 字节序"
fi
if grep -q "^INNER_RX_FROM=$INNER_S" "$WORK/recv-c.log" 2>/dev/null; then
	ok "T4b iws->iwc: iwc 用户态 socket 收到内层数据报（解封后确实投递到协议栈）"
else
	bad "T4b iws->iwc: iwc 用户态 socket 没收到内层数据报"
	sed 's/^/    /' "$WORK/recv-c.log" 2>/dev/null
fi

snap "$NS_S" s3 >/dev/null
send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
sleep 0.5
snap "$NS_S" s4 >/dev/null
e_pkts=$(( $(num "$(val "$WORK/stats-s4.txt" rx_pkts)") - $(num "$(val "$WORK/stats-s3.txt" rx_pkts)") ))
e_frames=$(( $(num "$(val "$WORK/stats-s4.txt" rx_frames)") - $(num "$(val "$WORK/stats-s3.txt" rx_frames)") ))
e_deliv=$(( $(num "$(val "$WORK/stats-s4.txt" rx_delivered)") - $(num "$(val "$WORK/stats-s3.txt" rx_delivered)") ))
info "iwc->iws: iws rx_pkts $(val "$WORK/stats-s3.txt" rx_pkts) -> $(val "$WORK/stats-s4.txt" rx_pkts) (+$e_pkts), rx_frames +$e_frames, rx_delivered +$e_deliv"
if [ "$e_pkts" -gt 0 ] || [ "$e_frames" -gt 0 ] || [ "$e_deliv" -gt 0 ]; then
	ok "T4c iwc->iws: iws 的 rx_pkts/rx_frames/rx_delivered 至少一项增长（+$e_pkts/+$e_frames/+$e_deliv）"
else
	bad "T4c iwc->iws: iws 三个计数都没涨"
fi

# ---------------------------------------------------------------- 控制帧

# 24B 控制帧：8B 帧头(type,enc,sid BE,tok BE) + 16B MD5(头||"mw") 签名
cat >"$WORK/send_ctrl.py" <<'PYEOF'
import hashlib, socket, struct, sys
# argv: <type> <enc> <sid> <tok> <src_ip> <dst_ip> <port>
typ, enc, sid, tok = (int(x, 0) for x in sys.argv[1:5])
src, dst, port = sys.argv[5], sys.argv[6], int(sys.argv[7])
hdr = struct.pack("!BBHI", typ, enc, sid, tok)
frame = hdr + hashlib.md5(hdr + b"mw").digest()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, port))		# 源端口也用隧道端口（模块自己发的包就是 sport=dport）
s.sendto(frame, (dst, port))
print("CTRL_TX type=0x%02x len=%d %s:%d -> %s:%d" % (typ, len(frame), src, port, dst, port))
PYEOF

snap "$NS_C" ctrl1 >/dev/null

say "T5 控制帧事件：PT_PING_REQ（0x29）"
# --count 给 2（只发一帧）是为了容错：多出来的事件（如 KEEPALIVE）不会让我们
# 在期望的事件到达前就因为 --count 满足而停掉
ep=$(start_events "$NS_C" "$WORK/ev-ping.log" 2 3)
if wait_ready "$WORK/ev-ping.log"; then
	grep -E '家族|多播组' "$WORK/ev-ping.log" | sed 's/^/    /'
	# PING 用的是协议固定凭据 IWAN_PING_SID/TOK = 0xFFFF/0xFFFFFFFF（不是会话
	# 凭据，见 kernel/iwan.h 的 iwan_ctrl_cred_ok 注释），enc=0 与真实客户端一致
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 0 65535 4294967295 "$OUTER_S" "$OUTER_C" "$PORT"
	sleep 0.3
	wait "$ep" 2>/dev/null
	if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-ping.log" \
	   && grep -q '^FRAME_TYPE_NAME=PT_PING_REQ$' "$WORK/ev-ping.log"; then
		ok "T5 events 收到 IWAN_EV_CTRL_FRAME（PT_PING_REQ，帧字节已 hex 打印）"
		grep -E '^(EVENT|SID|OUTER_SRC|OUTER_DST|SPORT|DPORT|FRAME_LEN|FRAME_TYPE|FRAME_TYPE_NAME|FRAME_HEX)=' \
			"$WORK/ev-ping.log" | sed 's/^/    /'
	else
		bad "T5 没收到 PT_PING_REQ 的 IWAN_EV_CTRL_FRAME"
		sed 's/^/    /' "$WORK/ev-ping.log"
	fi
else
	bad "T5 events 没打印 READY=1（加入多播组失败）"
	sed 's/^/    /' "$WORK/ev-ping.log"
	kill "$ep" 2>/dev/null
fi
snap "$NS_C" ctrl2 >/dev/null
info "iwc rx_ctrl_frame $(val "$WORK/stats-ctrl1.txt" rx_ctrl_frame) -> $(val "$WORK/stats-ctrl2.txt" rx_ctrl_frame)"

# ---------------------------------------------------------------- T6

say "T6 keepalive：收到 PING 后 last_keepalive_ms 非零（iwc）"
snap "$NS_C" ka >/dev/null
ka=$(num "$(val "$WORK/stats-ka.txt" last_keepalive_ms)")
pstate=$(val "$WORK/stats-ka.txt" peer_state_name)
info "last_keepalive_ms=$ka peer_state=${pstate:-未知}（peer_state=1 表示 IWAN_PEER_UP）"
if [ "$ka" -gt 0 ]; then
	ok "T6 last_keepalive_ms=$ka（PT_PING_REQ 更新了 keepalive 时间戳）"
else
	bad "T6 last_keepalive_ms 仍为 0：内核收到 PING 但没更新时间戳"
fi

# ---------------------------------------------------------------- T7

say "T7 控制帧事件：PT_CLOSE（0x17）→ CTRL_FRAME + PEER_CLOSE"
ep=$(start_events "$NS_C" "$WORK/ev-close.log" 3 3)
if wait_ready "$WORK/ev-close.log"; then
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x17 "$ENC" "$SID" "$TOK" "$OUTER_S" "$OUTER_C" "$PORT"
	sleep 0.3
	wait "$ep" 2>/dev/null
	if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-close.log" \
	   && grep -q '^FRAME_TYPE_NAME=PT_CLOSE$' "$WORK/ev-close.log"; then
		ok "T7a events 收到 PT_CLOSE 的 IWAN_EV_CTRL_FRAME"
	else
		bad "T7a 没收到 PT_CLOSE 的 IWAN_EV_CTRL_FRAME"
	fi
	if grep -q '^EVENT=IWAN_EV_PEER_CLOSE$' "$WORK/ev-close.log"; then
		ok "T7b events 收到 IWAN_EV_PEER_CLOSE"
	else
		bad "T7b 没收到 IWAN_EV_PEER_CLOSE"
	fi
	grep -E '^(EVENT|SID|FRAME_TYPE|FRAME_TYPE_NAME|FRAME_HEX)=' "$WORK/ev-close.log" | sed 's/^/    /'
else
	bad "T7 events 没打印 READY=1（加入多播组失败）"
	sed 's/^/    /' "$WORK/ev-close.log"
	kill "$ep" 2>/dev/null
fi

# ---------------------------------------------------------------- 汇总前快照

say "计数器与配置汇总（SESSION_DOWN 前）"
for ns in "$NS_C" "$NS_S"; do
	echo "  --- $ns get-stats ---"
	nsx "$ns" "$CTL" get-stats 2>/dev/null | sed 's/^/    /'
done

# ---------------------------------------------------------------- --extra

if [ "$EXTRA" = 1 ]; then
	say "T9 SET_PEER：对端外层地址漂移（--extra）"
	nsx "$NS_S" ip addr add "$OUTER_S2/24" dev veth-s 2>/dev/null
	nsx "$NS_C" "$CTL" set-peer --outer-dst "$OUTER_S2" >"$WORK/setpeer.log" 2>&1
	rc=$?
	snap "$NS_C" peer >/dev/null
	got=$(val "$WORK/stats-peer.txt" outer_dst)
	if [ "$rc" = 0 ] && [ "$got" = "$OUTER_S2" ]; then
		ok "T9a SET_PEER 后配置快照 outer_dst=$got（rc=0）"
	else
		bad "T9a SET_PEER 失败或快照没更新（rc=$rc outer_dst=$got 期望 $OUTER_S2）"
		sed 's/^/    /' "$WORK/setpeer.log"
	fi
	ep=$(start_events "$NS_C" "$WORK/ev-peer.log" 3 3)
	if wait_ready "$WORK/ev-peer.log"; then
		nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 0 65535 4294967295 "$OUTER_S2" "$OUTER_C" "$PORT"
		sleep 0.3
		wait "$ep" 2>/dev/null
		if grep -q '^EVENT=IWAN_EV_CTRL_FRAME$' "$WORK/ev-peer.log"; then
			ok "T9b 从新对端地址 $OUTER_S2 发的控制帧仍被接收（漂移生效）"
		else
			bad "T9b 从新对端地址 $OUTER_S2 发的控制帧没被接收"
			sed 's/^/    /' "$WORK/ev-peer.log"
		fi
	else
		bad "T9b events 没打印 READY=1"
		kill "$ep" 2>/dev/null
	fi
	nsx "$NS_C" "$CTL" set-peer --outer-dst "$OUTER_S" >/dev/null 2>&1
	nsx "$NS_S" ip addr del "$OUTER_S2/24" dev veth-s 2>/dev/null

	say "T10 SET_ENABLED：停数据面再启用（--extra）"
	snap "$NS_S" en1 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en2 >/dev/null
	g1=$(( $(num "$(val "$WORK/stats-en2.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en1.txt" rx_pkts)") ))
	nsx "$NS_C" "$CTL" set-enabled 0 >"$WORK/dis.log" 2>&1 || bad "T10 set-enabled 0 失败"
	nsx "$NS_S" "$CTL" set-enabled 0 >/dev/null 2>&1
	snap "$NS_S" en3 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en4 >/dev/null
	d1=$(( $(num "$(val "$WORK/stats-en4.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en3.txt" rx_pkts)") ))
	nsx "$NS_C" "$CTL" set-enabled 1 >/dev/null 2>&1
	nsx "$NS_S" "$CTL" set-enabled 1 >"$WORK/en.log" 2>&1 || bad "T10 set-enabled 1 失败"
	snap "$NS_S" en5 >/dev/null
	send_udp "$NS_C" "$INNER_C" "$INNER_S" "$INNER_PORT2" >/dev/null
	sleep 0.4
	snap "$NS_S" en6 >/dev/null
	g2=$(( $(num "$(val "$WORK/stats-en6.txt" rx_pkts)") - $(num "$(val "$WORK/stats-en5.txt" rx_pkts)") ))
	info "iws rx_pkts 增量：启用时 +$g1，set-enabled 0 期间 +$d1，重新启用后 +$g2"
	if [ "$g2" -gt 0 ]; then
		ok "T10 set-enabled 1 后数据面恢复（rx_pkts +$g2）"
	else
		bad "T10 set-enabled 1 后数据面没恢复（rx_pkts +$g2）"
	fi
fi

# ---------------------------------------------------------------- T8

say "T8 SESSION_DOWN：删设备、清凭据（iwc）"
nsx "$NS_C" "$CTL" session-down >"$WORK/down-c.log" 2>&1
rc=$?
if [ "$rc" = 0 ]; then
	ok "T8a iwan_ctl session-down 返回 0"
else
	bad "T8a iwan_ctl session-down 失败（rc=$rc）"
	sed 's/^/    /' "$WORK/down-c.log"
fi
if link_exists "$NS_C" "$DEV_C"; then
	bad "T8b SESSION_DOWN 后 $DEV_C 仍然存在"
else
	ok "T8b SESSION_DOWN 后 $DEV_C 已被删除"
fi
rc=$(snap "$NS_C" down)
d_sid=$(val "$WORK/stats-down.txt" sid)
d_tok=$(val "$WORK/stats-down.txt" tok)
d_err=$(val "$WORK/stats-down.txt" error)
d_ka=$(num "$(val "$WORK/stats-down.txt" last_keepalive_ms)")
info "down 后 get-stats: rc=$rc sid=${d_sid:-空} tok=${d_tok:-空} error=${d_err:-无} last_keepalive_ms=$d_ka"
if { [ -z "$d_sid" ] || [ "$d_sid" = 0 ]; } && { [ -z "$d_tok" ] || [ "$d_tok" = 0 ]; }; then
	ok "T8c 再次 GET_STATS：凭据已清零（sid=${d_sid:-空} tok=${d_tok:-空}）"
elif [ -n "$d_err" ]; then
	ok "T8c 再次 GET_STATS：会话不存在（内核回执 error=$d_err）"
else
	bad "T8c 再次 GET_STATS 仍能读到凭据（sid=$d_sid tok=$d_tok）"
fi
nsx "$NS_S" "$CTL" session-down >/dev/null 2>&1
if link_exists "$NS_S" "$DEV_S"; then
	info "iws: $DEV_S 仍在（该 netns 的 SESSION_DOWN 可能失败，清理时随 netns 一起消失）"
else
	info "iws: SESSION_DOWN 后 $DEV_S 也已删除"
fi

# ---------------------------------------------------------------- 结果

say "结果"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$FAIL" = 0 ]; then
	echo "全部通过：netlink 会话建立/配置快照/数据面双向/控制帧事件/keepalive/拆会话都符合冻结 ABI。"
	exit 0
fi
echo "有失败用例。排查提示：dmesg | tail -30；"
echo "  1) 家族/多播组解析信息看 iwan_ctl 的 stderr（家族 \"iwan\" id / 多播组 \"events\" id）；"
echo "  2) 配置快照不一致 → 先看是否 sid/tok 顺序或 dport/地址字节序（be16/be32）解错；"
echo "  3) T4 不涨 → 是否为每个 netns 各自建立了会话（本脚本在两端各跑一次 SESSION_UP），"
echo "     以及 IWAN_A_OUTER_SRC=本端 / OUTER_DST=对端 与 RX 五元组方向的映射；"
echo "  4) T5/T7 无事件 → 事件是否投递到收包 socket 所在 netns（本脚本 events 在 iwc 里跑）。"
exit 1
