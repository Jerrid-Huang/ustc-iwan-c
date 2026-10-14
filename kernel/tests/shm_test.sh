#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN /dev/iwan 共享内存页验收 —— 需要 root
#
#   sudo bash kernel/tests/shm_test.sh [--keep]
#
# 验收对象：每 netns 一页的只读共享内存（kernel/iwan_shm.{h,c}，ABI 见
# CONTROL-PLANE.md §11）。内核每收到一个通过凭据闸门的帧（数据帧或控制帧）就把
# 当前单调毫秒写进这一页；PT_CLOSE(0x17) 把它置 0；用户态 mmap 只读轮询，
# 超时即判定断线。本脚本只通过 /dev/iwan 观测，不依赖 netlink 读取时间戳。
#
# 用例（编号按题目给的语义，执行顺序见下）：
#   T1 insmod 后 /dev/iwan 存在；未下发会话时 version=1、enabled=0、last_rx_ms=0
#   T2 两个 netns 各建会话 + 一个内层 UDP 包：收包侧时间戳推进，另一侧不受影响
#   T3 从对端发 PT_CLOSE：时间戳变 0、peer_state=CLOSED，全程不调用 netlink
#   T4 SESSION_DOWN：整页清零（保留 version）、enabled=0
#   T5 先 mmap 再删 netns：映射仍可读、值保持最后一次内容、关 fd 干净
#   T6 连续两个内层包之间时间戳单调不减
#
# 执行顺序 = T1 T2 T6 T3 T4 T5：T6 需要"活会话 + 非零时间戳"，必须在 T3（CLOSE
# 置 0）与 T4（拆会话）之前；T5 会销毁 iwc 的 netns，只能放最后。
#
# 拓扑（与 netlink_test.sh 相同：外层 veth 当网线，内层地址挂 lo，iwan0 由
# SESSION_UP 按需创建）：
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   会话 --outer-src 10.100.0.1
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   会话 --outer-src 10.100.0.2
# 两端 --dport 6100 且不给 --sport（接收端口 = dport，与旧口径一致）。
# 两个 netns 都关掉 IPv6：iwan0 起来时内核自动发的 IPv6 RS 会被封装发给对端，
# 那会在"另一侧不受影响"的断言里制造噪声。
#
# 只依赖 ip / cc / python3（不需要 nc / tcpdump / ss）。

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"
KO="$KDIR/iwan.ko"
CTL_SRC="$HERE/iwan_ctl.c"
SHM_SRC="$HERE/iwan_shm.c"
NS_C=iwc
NS_S=iws
INNER_C=10.9.0.1
INNER_S=10.9.0.2
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
PORT=6100		# 外层隧道端口（两端一致，接收端口 = dport）
INNER_PORT=9999		# 内层 UDP 目的端口（iwc 的 python3 socket 收）
SID=4660
TOK=3405691582
KEY=0011223344556677
ENC=1
MTU=1400		# 1400 + 36 = 1436 < 1500 ⇒ 外层不分片
KEEP=0

for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
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

SHM=""			# 用户态工具路径（构建后填）
CTL=""
WORK=""
WP=""			# T5 的 watch 进程（cleanup 要收掉）

# 共享内存快照：<netns> <tag> → $WORK/shm-<tag>.txt（KEY=value），
# 返回值 = iwan_shm 的退出码（0 才说明打开+读成功）
shm_snap() {
	nsx "$1" "$SHM" dump >"$WORK/shm-$2.txt" 2>"$WORK/shm-$2.err"
}

sval() { sed -n "s/^$2=//p" "$1" | head -n1; }		# 从快照文件取一个字段

# 比较两次快照的字段（不含 dev/method/map_len/page_size/ready 这些运行信息）
shm_fields() { grep -v -E '^(dev|method|map_len|page_size|ready)=' "$1"; }

num() { # 非数字一律当 0
	case "${1:-}" in
	''|*[!0-9]*) echo 0 ;;
	*) echo "$1" ;;
	esac
}

# 内层 UDP 接收端：先打印 RECV_READY=1 再 recvfrom，避免竞态
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
s.sendto(b"iwan-shm-test", (sys.argv[2], int(sys.argv[3])))
print("INNER_TX_OK")
' "$2" "$3" "$4"
}

# 等日志里出现就绪行。两种标记不同，不要用一个模式去等另一个：
#   UDP 接收端 → RECV_READY=1     iwan_shm watch → left_netns=1
wait_ready() { # <log> <pattern>
	local pat="${2:-^READY=1$}"
	for _ in $(seq 1 80); do
		grep -q "$pat" "$1" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

# 发一个内层 UDP 包，并确认它真的到了 iwc 的 socket（避免 ICMP 回程噪声，
# 也避免"其实没发出去"被误判成"时间戳没推进"）。
inner_one() { # <tag>
	local rlog="$WORK/recv-$1.log" rp
	rp=$(start_udp_recv "$NS_C" "$INNER_C" "$INNER_PORT" "$rlog")
	if ! wait_ready "$rlog" '^RECV_READY=1$'; then
		info "iwc 的内层接收端没起来"
		kill "$rp" 2>/dev/null
		return 1
	fi
	send_udp "$NS_S" "$INNER_S" "$INNER_C" "$INNER_PORT" >/dev/null 2>&1
	for _ in $(seq 1 60); do
		grep -q '^INNER_RX_FROM=' "$rlog" && break
		sleep 0.05
	done
	wait "$rp" 2>/dev/null
	grep -q '^INNER_RX_FROM=' "$rlog"
}

# 内层地址/路由：各自只挂自己的内层地址到 lo，去对端内层地址的路由指向 iwan0。
# 必须**可重复调用**：SESSION_DOWN 会把 iwan0 删掉，挂在它上面的路由随之消失；
# 重建会话后不补回来，内层包就会因为没有回程路由被 rp_filter 丢掉 —— 表现为
# "内层包没到 socket"，而此时共享内存的时间戳其实已经被更新了（很容易被误判
# 成内核缺陷）。
setup_inner_routes() { # <netns>
	local ns="$1" own peer
	if [ "$ns" = "$NS_C" ]; then own="$INNER_C"; peer="$INNER_S"
	else own="$INNER_S"; peer="$INNER_C"; fi
	nsx "$ns" ip addr add "$own/32" dev lo 2>/dev/null
	nsx "$ns" ip route replace "$peer/32" dev iwan0 2>/dev/null
}

# watch 日志解析
iter_last() { sed -n 's/^iter=\([0-9]*\) .*/\1/p' "$1" | tail -n1; }
iter_rx()   { sed -n 's/^iter=[0-9]* t_ms=[0-9]* last_rx_ms=\([0-9]*\) .*/\1/p' "$1" | tail -n1; }

modrefcnt() { awk '$1 == "iwan" { print $3 }' /proc/modules 2>/dev/null | head -n1; }

dmesg_oops_count() {
	dmesg 2>/dev/null | grep -c -E 'BUG:|Oops|general protection fault|use-after-free|KASAN' || true
}

# 等子进程退出，超时（0.1s 粒度）返回 124
wait_pid_timeout() { # <pid> <秒>
	local pid="$1" secs="$2" i
	for ((i = 0; i < secs * 10; i++)); do
		if ! kill -0 "$pid" 2>/dev/null; then
			wait "$pid"
			return $?
		fi
		sleep 0.1
	done
	kill -9 "$pid" 2>/dev/null
	return 124
}

# ---------------------------------------------------------------- 清理

cleanup() {
	[ -n "$WP" ] && kill "$WP" 2>/dev/null
	if [ "$KEEP" = 0 ]; then
		if [ -n "$WORK" ] && [ -x "$CTL" ]; then
			# 先让模块自己拆会话（顺便验证幂等：设备/netns 可能已经不在了）
			ip netns exec "$NS_C" "$CTL" session-down >/dev/null 2>&1
			ip netns exec "$NS_S" "$CTL" session-down >/dev/null 2>&1
		fi
		ip netns del "$NS_C" 2>/dev/null
		ip netns del "$NS_S" 2>/dev/null
		# 模块在每个 netns 都可能建过 iwan0；init netns 里这一个要显式删除，
		# 否则设备引用着模块，rmmod 会被内核拒绝（Module iwan is in use）。
		ip link del iwan0 2>/dev/null
		rmmod iwan 2>/dev/null
		[ -n "$WORK" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- 前置

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
command -v ip >/dev/null || die "缺少 iproute2"
command -v cc >/dev/null || die "缺少 cc"
command -v python3 >/dev/null || die "缺少 python3（构造控制帧/收发内层 UDP 用）"
[ -f "$CTL_SRC" ] || die "缺少 $CTL_SRC"
[ -f "$SHM_SRC" ] || die "缺少 $SHM_SRC"

WORK="$(mktemp -d /tmp/iwan-shm-test.XXXXXX)"
CTL="$WORK/iwan_ctl"
SHM="$WORK/iwan_shm"

say "构建内核模块与用户态工具"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "模块构建失败"; }
[ -f "$KO" ] || die "没有生成 $KO"
WARN=$(grep -c -i 'warning' "$WORK/build.log" \
	| head -n1)
info "模块构建完成: $KO（构建日志 warning 行数 $WARN，来自内核构建系统的编译器提示）"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$CTL" "$CTL_SRC" \
	>"$WORK/ctl-build.log" 2>&1 \
	|| { cat "$WORK/ctl-build.log"; die "iwan_ctl 构建失败"; }
info "iwan_ctl 构建完成（$(grep -c . "$WORK/ctl-build.log") 行编译输出，0 行即无警告）"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$SHM" "$SHM_SRC" \
	>"$WORK/shm-build.log" 2>&1 \
	|| { cat "$WORK/shm-build.log"; die "iwan_shm 构建失败" ; }
info "iwan_shm 构建完成（$(grep -c . "$WORK/shm-build.log") 行编译输出，0 行即无警告）"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

# 控制帧构造（与 netlink_test.sh 同一份：8B 帧头 + MD5(头||"mw") 的 16B 签名）
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

# ---------------------------------------------------------------- 拓扑 + insmod

say "拓扑与加载（insmod 不带任何会话参数）"
rmmod iwan 2>/dev/null
ip netns del "$NS_C" 2>/dev/null
ip netns del "$NS_S" 2>/dev/null
ip link del iwan0 2>/dev/null
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
	# 关 IPv6：iwan0 起来时内核会自动发 IPv6 RS，它会被封装后到达对端并推进
	# 对端的时间戳，污染"另一侧不受影响"的断言。
	nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up
insmod "$KO" || die "insmod 失败（dmesg | tail 看原因）"
info "insmod 完成：$(grep -c '^iwan ' /proc/modules) 个 iwan 模块实例"

# ---------------------------------------------------------------- T1

say "T1 /dev/iwan 存在；未下发会话时 version=1、enabled=0、last_rx_ms=0"

if [ -c /dev/iwan ]; then
	ok "T1a /dev/iwan 存在（misc_register + devtmpfs 自动建节点）"
	ls -l /dev/iwan | sed 's/^/    /'
else
	bad "T1a /dev/iwan 不存在（misc_register 失败？看 dmesg）"
fi

if shm_snap "$NS_C" t1 >/dev/null; then
	F="$WORK/shm-t1.txt"
	v=$(num "$(sval "$F" version)")
	lr=$(num "$(sval "$F" last_rx_ms)")
	en=$(num "$(sval "$F" enabled)")
	ps=$(num "$(sval "$F" peer_state)")
	rf=$(num "$(sval "$F" rx_frames)")
	rc=$(num "$(sval "$F" rx_ctrl_frame)")
	info "iwc 未下发会话: version=$v last_rx_ms=$lr enabled=$en peer_state=$ps rx_frames=$rf rx_ctrl_frame=$rc"
	if [ "$v" = 1 ] && [ "$lr" = 0 ] && [ "$en" = 0 ] && [ "$ps" = 0 ] \
	   && [ "$rf" = 0 ] && [ "$rc" = 0 ]; then
		ok "T1b 初始页面正确：version=1、enabled=0、last_rx_ms=0、peer_state=0、两个计数为 0"
	else
		bad "T1b 初始页面字段不符（期望 version=1 enabled=0 last_rx_ms=0 peer_state=0 计数=0）"
		sed 's/^/    /' "$F"
	fi
else
	bad "T1b iwc 里执行 iwan_shm dump 失败"
	sed 's/^/    /' "$WORK/shm-t1.err"
fi

# mmap 与 pread 两条读路径必须给出同一份数据
if nsx "$NS_C" "$SHM" dump --pread >"$WORK/shm-t1-pread.txt" 2>&1; then
	if diff -u <(shm_fields "$WORK/shm-t1.txt") \
		   <(shm_fields "$WORK/shm-t1-pread.txt") >"$WORK/shm-t1-diff.txt"; then
		ok "T1c mmap 视图与 pread 视图逐字段一致（节点支持两条只读路径）"
	else
		bad "T1c mmap 与 pread 视图不一致"
		sed 's/^/    /' "$WORK/shm-t1-diff.txt"
	fi
else
	bad "T1c iwan_shm dump --pread 失败"
	sed 's/^/    /' "$WORK/shm-t1-pread.txt"
fi

# ---------------------------------------------------------------- T2

say "T2 两端 SESSION_UP + 一个内层 UDP 包（收包侧推进、另一侧不受影响）"

up_ok=1
for spec in "$NS_C:$OUTER_C:$OUTER_S" "$NS_S:$OUTER_S:$OUTER_C"; do
	ns="${spec%%:*}"; rest="${spec#*:}"; osrc="${rest%%:*}"; odst="${rest##*:}"
	if nsx "$ns" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
		--key "$KEY" --outer-src "$osrc" --outer-dst "$odst" \
		--dport "$PORT" --mtu "$MTU" >"$WORK/up-$ns.txt" 2>&1; then
		info "$ns SESSION_UP: $(sed -n 's/^DEVNAME=/dev=/p;s/^MTU=/mtu=/p' "$WORK/up-$ns.txt" | tr '\n' ' ')"
	else
		bad "T2 $ns SESSION_UP 失败"; sed 's/^/    /' "$WORK/up-$ns.txt"; up_ok=0
	fi
	# 内层地址/路由：曾经两个 netns 都挂两个地址，于是对端地址在本地也成了
	# "本机地址"，内层包被本地投递短路、根本不出 iwan0（T2c/T6/T3/T5a 全失败
	# 的根因，内核侧其实是好的）。现在统一走这个 helper。
	setup_inner_routes "$ns"
done

if [ "$up_ok" = 1 ]; then
	ok "T2a 两端 SESSION_UP 成功（iwan0 由会话按需创建）"
	# 会话刚建立：时间戳从 0 开始，enabled=1
	shm_snap "$NS_C" t2a >/dev/null; shm_snap "$NS_S" t2b >/dev/null
	base_c=$(num "$(sval "$WORK/shm-t2a.txt" last_rx_ms)")
	base_s=$(num "$(sval "$WORK/shm-t2b.txt" last_rx_ms)")
	en_c=$(num "$(sval "$WORK/shm-t2a.txt" enabled)")
	en_s=$(num "$(sval "$WORK/shm-t2b.txt" enabled)")
	fr_c0=$(num "$(sval "$WORK/shm-t2a.txt" rx_frames)")
	info "基线（发内层包之前）: iwc last_rx_ms=$base_c enabled=$en_c rx_frames=$fr_c0；iws last_rx_ms=$base_s enabled=$en_s"
	if [ "$base_c" = 0 ] && [ "$base_s" = 0 ] && [ "$en_c" = 1 ] && [ "$en_s" = 1 ]; then
		ok "T2b SESSION_UP 后：两端 enabled=1、last_rx_ms=0（新会话从零开始）"
	else
		bad "T2b SESSION_UP 后的初始页面不符（期望 enabled=1 且 last_rx_ms=0）"
	fi

	if inner_one t2; then
		sleep 0.2
		shm_snap "$NS_C" t2c >/dev/null; shm_snap "$NS_S" t2d >/dev/null
		new_c=$(num "$(sval "$WORK/shm-t2c.txt" last_rx_ms)")
		new_s=$(num "$(sval "$WORK/shm-t2d.txt" last_rx_ms)")
		fr_c1=$(num "$(sval "$WORK/shm-t2c.txt" rx_frames)")
		info "iws→iwc 一个内层包后: iwc last_rx_ms=$base_c→$new_c（rx_frames $fr_c0→$fr_c1）；iws last_rx_ms=$base_s→$new_s"
		if [ "$new_c" -gt "$base_c" ] && [ "$new_c" -gt 0 ]; then
			ok "T2c 收包侧 iwc 时间戳推进（$base_c→$new_c，单调毫秒）"
		else
			bad "T2c 收包侧 iwc 时间戳没有推进（$base_c→$new_c）"
		fi
		if [ "$new_s" = "$base_s" ]; then
			ok "T2d 另一侧 iws 不受影响（last_rx_ms 仍为 $new_s）：页面按 netns 隔离"
		else
			bad "T2d 另一侧 iws 的时间戳也变了（$base_s→$new_s）：不是按 netns 隔离！"
		fi
		if [ "$fr_c1" -gt "$fr_c0" ]; then
			ok "T2e 页面的 rx_frames 同步增长（+$((fr_c1 - fr_c0))，与 /proc、GET_STATS 同源）"
		else
			bad "T2e 页面的 rx_frames 没增长（$fr_c0→$fr_c1）"
		fi
	else
		bad "T2c 内层包没有到达 iwc 的 socket（测试环境问题，后面的断言不可信）"
	fi
else
	bad "T2 会话没建起来，跳过后续断言"
fi

# ---------------------------------------------------------------- T6

say "T6 连续两个内层包之间时间戳单调不减（在 T3/T4 之前跑：需要活会话）"

if inner_one t6a; then
	sleep 0.25
	t1=$(num "$(nsx "$NS_C" "$SHM" dump 2>/dev/null | sed -n 's/^last_rx_ms=//p')")
	if inner_one t6b; then
		sleep 0.25
		t2=$(num "$(nsx "$NS_C" "$SHM" dump 2>/dev/null | sed -n 's/^last_rx_ms=//p')")
		info "两个内层包: t1=$t1 t2=$t2（差 $((t2 - t1)) ms）"
		if [ "$t1" -gt 0 ] && [ "$t2" -ge "$t1" ]; then
			ok "T6 时间戳单调不减（t1=$t1 > 0，t2=$t2 >= t1）"
		else
			bad "T6 时间戳不满足单调不减（t1=$t1 t2=$t2）"
		fi
	else
		bad "T6 第二个内层包没到 iwc"
	fi
else
	bad "T6 第一个内层包没到 iwc"
fi

# ---------------------------------------------------------------- T3

say "T3 对端发 PT_CLOSE(0x17)：时间戳变 0、peer_state=CLOSED（只用 mmap 观测）"

shm_snap "$NS_C" t3a >/dev/null
pre_rx=$(num "$(sval "$WORK/shm-t3a.txt" last_rx_ms)")
pre_ctrl=$(num "$(sval "$WORK/shm-t3a.txt" rx_ctrl_frame)")
pre_state=$(num "$(sval "$WORK/shm-t3a.txt" peer_state)")
info "CLOSE 之前: last_rx_ms=$pre_rx peer_state=$pre_state rx_ctrl_frame=$pre_ctrl"
if [ "$pre_rx" -gt 0 ]; then
	ok "T3a 前置条件成立：CLOSE 之前时间戳非零（$pre_rx）"
	# 注意：从这里到读结果之间，脚本只调用 iwan_shm（/dev/iwan mmap），
	# 不调用 iwan_ctl 的任何 netlink 命令 —— 事件到达是内核直接写共享内存。
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x17 "$ENC" "$SID" "$TOK" \
		"$OUTER_S" "$OUTER_C" "$PORT" | sed 's/^/    /'
	sleep 0.3
	shm_snap "$NS_C" t3b >/dev/null
	post_rx=$(num "$(sval "$WORK/shm-t3b.txt" last_rx_ms)")
	post_state=$(num "$(sval "$WORK/shm-t3b.txt" peer_state)")
	post_ctrl=$(num "$(sval "$WORK/shm-t3b.txt" rx_ctrl_frame)")
	post_name=$(sval "$WORK/shm-t3b.txt" peer_state_name)
	info "CLOSE 之后: last_rx_ms=$post_rx peer_state=$post_state($post_name) rx_ctrl_frame=$pre_ctrl→$post_ctrl"
	if [ "$post_rx" = 0 ]; then
		ok "T3b 收到 PT_CLOSE 后时间戳置 0（用户态据此判定断线）"
	else
		bad "T3b 收到 PT_CLOSE 后时间戳仍为 $post_rx（应置 0）"
	fi
	if [ "$post_state" = 3 ]; then
		ok "T3c peer_state=CLOSED($post_state)"
	else
		bad "T3c peer_state=$post_state（期望 3=CLOSED）"
	fi
	if [ "$post_ctrl" -gt "$pre_ctrl" ]; then
		ok "T3d 页面的 rx_ctrl_frame 增长（$pre_ctrl→$post_ctrl）：内核确实收到了这一帧"
	else
		bad "T3d 页面的 rx_ctrl_frame 没增长（$pre_ctrl→$post_ctrl）"
	fi
	info "本用例只跑了 iwan_shm dump/watch（/dev/iwan mmap），没有任何 get-stats/events 调用"
else
	bad "T3a 前置条件不成立：CLOSE 之前时间戳就是 0（T2/T6 的包没被记上）"
fi

# ---------------------------------------------------------------- T4

say "T4 SESSION_DOWN：整页清零（保留 version）、enabled=0"

if nsx "$NS_C" "$CTL" session-down >"$WORK/down-c.txt" 2>&1; then
	ok "T4a iwc SESSION_DOWN 成功（netlink 只用来拆会话，时间戳仍从共享内存读）"
else
	bad "T4a iwc SESSION_DOWN 失败"
	sed 's/^/    /' "$WORK/down-c.txt"
fi
shm_snap "$NS_C" t4 >/dev/null
F="$WORK/shm-t4.txt"
v=$(num "$(sval "$F" version)"); lr=$(num "$(sval "$F" last_rx_ms)")
en=$(num "$(sval "$F" enabled)"); ps=$(num "$(sval "$F" peer_state)")
rf=$(num "$(sval "$F" rx_frames)"); rc=$(num "$(sval "$F" rx_ctrl_frame)")
info "SESSION_DOWN 后: version=$v last_rx_ms=$lr enabled=$en peer_state=$ps rx_frames=$rf rx_ctrl_frame=$rc"
if [ "$v" = 1 ] && [ "$lr" = 0 ] && [ "$en" = 0 ] && [ "$ps" = 0 ] \
   && [ "$rf" = 0 ] && [ "$rc" = 0 ]; then
	ok "T4b 整页清零且保留 version=1（enabled=0、时间戳/状态/计数全 0）"
else
	bad "T4b SESSION_DOWN 后页面字段不符（期望 version=1，其余 0）"
	sed 's/^/    /' "$F"
fi

# ---------------------------------------------------------------- T5

say "T5 先 mmap 再删 netns：映射仍可读、值保持最后一次内容、关 fd 干净"

# T4 拆过会话，这里重新建一个，并制造一个非零时间戳作为"最后一次内容"
if nsx "$NS_C" "$CTL" session-up --sid "$SID" --tok "$TOK" --enc "$ENC" \
	--key "$KEY" --outer-src "$OUTER_C" --outer-dst "$OUTER_S" \
	--dport "$PORT" --mtu "$MTU" >"$WORK/up-c2.txt" 2>&1; then
	info "iwc 会话已重建"
	# SESSION_DOWN 删掉了 iwan0，内层路由也随设备消失 ⇒ 必须补回来，
	# 否则下面的内层包会被 rp_filter 丢掉。
	setup_inner_routes "$NS_C"
	setup_inner_routes "$NS_S"
else
	bad "T5 iwc 重新 SESSION_UP 失败"; sed 's/^/    /' "$WORK/up-c2.txt"
fi
if inner_one t5; then
	sleep 0.2
else
	# 内层通路不可用时不要放弃：直接发一个 PT_PING_REQ（只走外层，与内层
	# 路由无关），内核照样会刷新这一页的时间戳。
	info "T5a 内层包没到 iwc，改用对端发 PT_PING_REQ 制造时间戳"
	nsx "$NS_S" python3 "$WORK/send_ctrl.py" 0x29 "$ENC" "$SID" "$TOK" \
		"$OUTER_S" "$OUTER_C" "$PORT" >/dev/null 2>&1
	sleep 0.3
fi
# v1 一律读页面真实值。以前这里在内层包没到时把 v1 强制置 0 当占位符，
# 于是 T5d/T5f 拿真实页面值去跟假想的 0 比，报出两个并不存在的"值不一致"。
v1=$(num "$(sval <(nsx "$NS_C" "$SHM" dump 2>/dev/null) last_rx_ms)")
if [ "$v1" -gt 0 ]; then
	ok "T5a 前置条件成立：删 netns 之前时间戳非零（$v1）"
else
	bad "T5a 删 netns 之前时间戳为 0，无法验证值保持"
fi

OOPS0=$(dmesg_oops_count)
R0=$(num "$(modrefcnt)")

# 关键：在 iwc 里打开 /dev/iwan + mmap，然后把自己挪到 PID 1 所在 netns。
# 这样"原 netns 被删除"才会真正走完 pernet exit（页面引用只剩 file 的那一个），
# 从而验证引用计数：映射还在 ⇒ 页面还在。
nsx "$NS_C" "$SHM" watch --count 40 --interval 100 --leave-netns \
	>"$WORK/t5-watch.log" 2>&1 &
WP=$!
if wait_ready "$WORK/t5-watch.log" '^left_netns=1$'; then
	ok "T5b 打开 + mmap + 迁移出原 netns 成功（页面已由打开的 file 持有）"
else
	bad "T5b watch 没打印 left_netns=1（mmap 或 setns 失败）"
	sed 's/^/    /' "$WORK/t5-watch.log"
	kill "$WP" 2>/dev/null
fi

R1=$(num "$(modrefcnt)")
if [ "$R1" -ge "$((R0 + 1))" ]; then
	ok "T5c 打开的 file 让模块引用计数 +1（$R0→$R1）：release 是唯一归还点"
else
	bad "T5c 模块引用计数没有 +1（$R0→$R1）：打开的 file 没有持引用？"
fi

I_BEFORE=$(iter_last "$WORK/t5-watch.log")
V_BEFORE=$(iter_rx "$WORK/t5-watch.log")
if [ "${V_BEFORE:-0}" = "$v1" ]; then
	ok "T5d watch（mmap）与 dump（另一次打开）读到同一个值：$V_BEFORE"
else
	bad "T5d watch 读到 ${V_BEFORE:-空}，dump 读到 $v1（同一次打开应一致）"
fi

# 删掉 iwc：此刻进程已不在该 netns 里，pernet exit 会真正跑完
if ip netns del "$NS_C" 2>/dev/null; then
	info "ip netns del $NS_C 已执行（进程已迁出，pernet exit 会真正走完）"
else
	bad "ip netns del $NS_C 失败"
fi
sleep 0.5

# 等 watch 至少再打印一次新迭代：删除之后仍然能读这一页且不 oops
I_AFTER=""
for _ in $(seq 1 60); do
	I_AFTER=$(iter_last "$WORK/t5-watch.log")
	[ -n "$I_AFTER" ] && [ "${I_BEFORE:-0}" != "" ] && [ "$I_AFTER" -gt "${I_BEFORE:-0}" ] && break
	sleep 0.1
done
V_AFTER=$(iter_rx "$WORK/t5-watch.log")
if [ -n "${I_AFTER:-}" ] && [ "${I_AFTER:-0}" -gt "${I_BEFORE:-0}" ]; then
	ok "T5e 删除 netns 之后映射仍可读（iter $I_BEFORE→$I_AFTER，页面没有被提前回收）"
else
	bad "T5e 删除 netns 之后没有新的迭代（iter=${I_AFTER:-空}）：映射是否已失效或进程卡死？"
	tail -5 "$WORK/t5-watch.log" | sed 's/^/    /'
fi
if [ "${V_AFTER:-x}" = "$v1" ]; then
	ok "T5f 值保持最后一次内容（last_rx_ms=$V_AFTER，删 netns 不改变页面内容）"
else
	bad "T5f 删除 netns 后值变了：$v1 → ${V_AFTER:-空}"
fi

# 让 watch 自己跑完 --count（关 fd 干净、不带 oops 地退出）
wait_pid_timeout "$WP" 15
WRC=$?
if [ "$WRC" = 0 ]; then
	ok "T5g watch 自行退出（--count 用尽）且退出码 0：release 干净"
else
	bad "T5g watch 退出异常（rc=$WRC；124 = 超时未退出，可能卡在 release）"
	tail -5 "$WORK/t5-watch.log" | sed 's/^/    /'
fi
WP=""

R2=$(num "$(modrefcnt)")
if [ "$R2" -lt "$R1" ]; then
	ok "T5h 关闭 fd 之后模块引用计数回落（$R1→$R2）"
else
	bad "T5h 关闭 fd 之后模块引用计数没有回落（$R1→$R2）：release 没有归还引用？"
fi

if dmesg >/dev/null 2>&1; then
	OOPS1=$(dmesg_oops_count)
	if [ "${OOPS1:-0}" -le "${OOPS0:-0}" ]; then
		ok "T5i 整个过程 dmesg 没有新增 oops/BUG/use-after-free（$OOPS0→$OOPS1）"
	else
		bad "T5i dmesg 出现新的 oops/BUG（$OOPS0→$OOPS1）：先看 dmesg | tail -40"
		dmesg | tail -20 | sed 's/^/    /'
	fi
else
	info "dmesg 不可读（缺少 CAP_SYSLOG），跳过 oops 检查"
fi

# ---------------------------------------------------------------- 结果

say "结果（执行顺序 T1 T2 T6 T3 T4 T5）"
for r in "${RESULTS[@]}"; do
	case "$r" in
	PASS*) printf '  \033[32m%s\033[0m\n' "$r" ;;
	*)     printf '  \033[31m%s\033[0m\n' "$r" ;;
	esac
done
printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"

if [ "$KEEP" = 1 ]; then
	echo "--keep：保留现场 $WORK（netns 与模块也保留）"
fi

if [ "$FAIL" = 0 ]; then
	echo "全部通过：/dev/iwan 的初始状态、每帧时间戳、netns 隔离、PT_CLOSE 置 0、"
	echo "SESSION_DOWN 清零、mmap 后删 netns 的引用计数都符合 CONTROL-PLANE.md §11。"
	exit 0
fi
echo "有失败用例。排查提示：dmesg | tail -30；"
echo "  1) T1 失败 → /dev/iwan 是否建出来（misc_register/devtmpfs）、页面 version 是否被改；"
echo "  2) T2/T6 时间戳不推进 → 会话是否真的建立（GET_STATS 的 sid/devname）、"
echo "     内层包是否走 iwan0（ip route get）、外层端口/凭据是否一致；"
echo "  3) T2d 另一侧也变 → 是否有别的流量（IPv6 RS/ICMP）打进对端，先关 IPv6 再看；"
echo "  4) T3 时间戳不为 0 → PT_CLOSE 的 sid/tok 是否等于会话凭据（0x17 走会话凭据）；"
echo "  5) T5 失败 → 先看 watch 日志与 dmesg，重点怀疑 netns 销毁与 mmap 的引用计数。"
exit 1
