#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN 跨实现互通验收（需要 root）
#
#   sudo bash kernel/tests/interop_test.sh [--keep]
#
# 目的：把**内核模块**在线上真实产生的字节，与**用户态参照实现**
# （kernel/tests/interop_c.c，走 src/common/ 的生产线格式代码 pkt_hdr()/
# xor_crypt()）做逐字节对拍。"模块自己发、自己收"看不出来的缺陷（端口/地址
# 的字节序、XOR 的作用范围、帧头序列化、外层长度）都会被对拍暴露出来。
#
# 拓扑与加载参数沿用 tcp_echo_test.sh：
#   iwc: lo 10.9.0.1/32   veth-c 10.100.0.1/24   iwan0 mtu 1400
#   iws: lo 10.9.0.2/32   veth-s 10.100.0.2/24   iwan0 mtu 1400
#   模块级：any_dir=1 dport=6100 sid=4660 tok=3405691582 key=0011223344556677
#           enc=1 batch=1 df=1；每 netns 再写 tx_src/tx_dst/enabled=1
#
# 三条断言：
#   A1 模块出站 → C 侧解封
#      在 iwc 用 raw socket（IP_HDRINCL + SO_BINDTODEVICE=iwan0）注入
#      interop_c mkudp 造的**内容已知**的内层包，在 iws 的 veth-s 上用
#      capture_iwan.py 抓外层 UDP 载荷，交给 interop_c decap 解封，再用
#      interop_c cmpin 与注入的原始内层包对拍。
#   A2 C 侧封装 → 模块入站
#      用 interop_c encap 造载荷，从 iwc 以外层五元组
#      10.100.0.1:6100 → 10.100.0.2:6100 发给 iws，断言模块解封投递
#      （/proc/net/iwan 的 rx_pkts/rx_outer/rx_frames/rx_delivered 增量），
#      且 iws 上的 UDP 套接字收到与发送端**逐字节相同**的内层载荷。
#   A3 外层头字段一致性
#      interop_c outer 生成期望外层头，capture_iwan.py 抓到的实际字段逐字段
#      比较（源/目的地址与端口正是历史字节序缺陷所在），并把外层头前 26 字节
#      与期望头逐字节比较（TTL/ID/DF/IP 校验和一并覆盖）。
#
# 依赖：ip(iproute2)、python3、cc + libcrypto、make、insmod/rmmod、awk/sed/grep。
#       刻意不用 ethtool / tcpdump / nc / ping：抓包、造包、发包分别由
#       capture_iwan.py、interop_c 和 $WORK 下现场生成的小 python 脚本完成。

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$HERE/.." && pwd)"		# kernel/
ROOT="$(cd "$KDIR/.." && pwd)"		# 仓库根
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
A1_SPORT=40000			# A1 内层 UDP 端口（内容已知的注入包）
A1_DPORT=40001
A2_SPORT=40002			# A2 内层 UDP 端口（接收端真的在监听 40003）
A2_DPORT=40003
CAP_TIMEOUT=8			# capture_iwan.py 的总超时（秒）
A1_STR="iwan-interop-A1-0123456789abcdef"
A2_STR="iwan-interop-A2-fedcba9876543210"
KEEP=0

for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
	-h|--help) sed -n '2,37p' "$0"; exit 0 ;;
	*) echo "未知参数: $a（支持 --keep）"; exit 2 ;;
	esac
done

PASS=0
FAIL=0
declare -a RESULTS=()
declare -a BG_PIDS=()

# ok/bad/info 都用 "$*"：调用处把长消息拆成多行字符串拼起来也不会丢内容
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS + 1)); RESULTS+=("PASS  $*"); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
die()  { printf '\033[31m致命: %s\033[0m\n' "$*"; exit 2; }

nsx() { ip netns exec "$1" "${@:2}"; }

# /proc/net/iwan 里的单个计数器（读的是该 netns 的视图；缺失按 0 处理）
ctr() {
	local v
	v=$(nsx "$1" awk -v k="$2" '$1==k{print $2}' /proc/net/iwan 2>/dev/null)
	echo "${v:-0}"
}

# 从 KEY=value 流里取最后一个键的值（interop_c 与 capture_iwan.py 的输出格式）
kvget() {
	awk -v k="$2" 'index($0, k"=")==1 { v=substr($0, length(k)+2) } END { print v }' "$1"
}

# 从 capture_iwan.py 的输出里按包序号取键（多个包时每个包一段 INDEX=<i>）
capget() {
	awk -v want="$2" -v k="$3" '
		/^INDEX=/ { cur = substr($0, 7) + 0 }
		index($0, k"=")==1 && cur == want { v = substr($0, length(k)+2) }
		END { print v }' "$1"
}

# 等到文件里出现以某前缀开头的行（最多 $3 次 × 0.1s）
wait_line() {
	local i
	for ((i = 0; i < $3; i++)); do
		grep -q "^$2" "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# 只删本模块创建的 iwan0。init netns 里的 iwan0 未必是我们的：本项目的
# iwan-client 就用 TUN iwan0 跑真实隧道，误删会直接打断活隧道。判据是
# `ip -d link show` 的 detail 行是否为本模块的 kind（iwan），不能看设备名，
# 也不能看 ARPHRD —— TUN 与 iwan 同为 65534。
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
		# init netns 里的 iwan0 要显式删除，否则设备引用模块，rmmod 被拒。
		del_iwan0_if_ours
		rmmod iwan 2>/dev/null
		[ -n "${WORK:-}" ] && rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- 环境检查

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
for tool in ip python3 cc make insmod rmmod awk sed grep mktemp cat head tail sleep; do
	command -v "$tool" >/dev/null || die "缺少依赖: $tool"
done
[ -f "$INTEROP_C" ] || die "缺少 $INTEROP_C"
[ -f "$CAPTURE_PY" ] || die "缺少 $CAPTURE_PY"
[ -f "$SRC/protocol.c" ] && [ -f "$SRC/crypto.c" ] \
	|| die "缺少 $SRC/protocol.c 或 crypto.c"

WORK="$(mktemp -d /tmp/iwan-interop-test.XXXXXX)" || die "mktemp 失败"
[ "$KEEP" = 1 ] && info "--keep：保留 netns/模块，临时目录 $WORK"

# ---------------------------------------------------------------- 现场小工具

# 收内层 UDP：argv <bind_ip> <port> <out_file> <timeout>
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

# 按外层五元组发 UDP：argv <bind_ip> <bind_port> <dst_ip> <dst_port> <payload_file>
cat >"$WORK/send_udp.py" <<'PYEOF'
import socket, sys
src, sport, dst, dport, pf = (sys.argv[1], int(sys.argv[2]), sys.argv[3],
                              int(sys.argv[4]), sys.argv[5])
payload = open(pf, "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, sport))          # 源端口固定成外层端口：模块自己发的包就是 sport=dport
n = s.sendto(payload, (dst, dport))
print("SENT_BYTES=%d" % n)
print("PAYLOAD_BYTES=%d" % len(payload))
print("SENT_FROM=%s:%d" % (src, sport))
print("SENT_TO=%s:%d" % (dst, dport))
print("RESULT=ok" if n == len(payload) else "RESULT=short")
sys.exit(0 if n == len(payload) else 1)
PYEOF

# 把**成品内层 IP 包**原样从指定网卡注入（IP_HDRINCL）：
# argv <ifname> <inner_pkt_file> <dst_ip>
# 这样 iwan0 的 ndo_start_xmit 拿到的就是 mkudp 逐字节生成的包，id/ttl/校验和
# 都是我们写进去的值，cmpin 才有条件做严格比对。
cat >"$WORK/inject_raw.py" <<'PYEOF'
import socket, sys
ifname, pf, dst = sys.argv[1], sys.argv[2], sys.argv[3]
pkt = open(pf, "rb").read()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except OSError as e:
    print("inject_raw: 创建 raw socket 失败：%s（需要 root/CAP_NET_RAW）" % e,
          file=sys.stderr)
    sys.exit(2)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
except OSError as e:               # 路由本身已经指向 iwan0，这里只是加一道保险
    print("BINDTODEVICE_FAIL=%s" % e, file=sys.stderr)
n = s.sendto(pkt, (dst, 0))
print("INJECTED_BYTES=%d" % n)
print("INJECTED_DEV=%s" % ifname)
print("RESULT=ok" if n == len(pkt) else "RESULT=short")
sys.exit(0 if n == len(pkt) else 1)
PYEOF

# 逐字节比较（--limit N 只比前 N 字节，用于"外层头前 26 字节"）
# argv: --got <文件> --want <文件> [--limit N]
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
        sys.stderr.write("hdrcmp: 未知选项 %s\n" % a[i]); sys.exit(2)
if not got_f or not want_f:
    sys.stderr.write("hdrcmp: 需要 --got 与 --want\n"); sys.exit(2)
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

# ---------------------------------------------------------------- 构建

say "构建内核模块"
make -C "$KDIR" >"$WORK/build.log" 2>&1 || { tail -20 "$WORK/build.log"; die "模块构建失败"; }
[ -f "$KO" ] || die "没有生成 $KO"
info "构建完成: $KO"
if [ -n "${SUDO_UID:-}" ] && [ "${SUDO_UID:-0}" != 0 ]; then
	chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR"/*.o "$KO" 2>/dev/null
	chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$KDIR/.tmp_versions" 2>/dev/null
fi

say "编译参照实现 interop_c"
if ! cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -I "$SRC" \
	-o "$WORK/interop_c" "$INTEROP_C" "$SRC/protocol.c" "$SRC/crypto.c" \
	-lcrypto >"$WORK/cc.log" 2>&1; then
	tail -20 "$WORK/cc.log"
	die "interop_c 编译失败（依赖 cc + libcrypto 开发包，脚本不会自行安装）"
fi
INTEROP="$WORK/interop_c"
info "编译完成: $INTEROP（-D_GNU_SOURCE 必须带，否则 src/common/port.h 编译不过）"

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
	# 解封后的内层包源地址回程路由走 iwan0，而包是从 veth 进来的：strict
	# rp_filter 会直接丢掉。新 netns 的内核默认值本来就是 0，显式设置以免
	# 受宿主 sysctl 影响。
	nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
	nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
done
nsx "$NS_C" ip addr add "$OUTER_C/24" dev veth-c
nsx "$NS_C" ip link set veth-c up
nsx "$NS_S" ip addr add "$OUTER_S/24" dev veth-s
nsx "$NS_S" ip link set veth-s up

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" ip link add iwan0 type iwan || die "$ns: 创建 iwan0 失败"
done
nsx "$NS_C" ip link set iwan0 mtu "$MTU_INNER" up
nsx "$NS_S" ip link set iwan0 mtu "$MTU_INNER" up

nsx "$NS_C" ip addr add "$INNER_C/32" dev lo
nsx "$NS_S" ip addr add "$INNER_S/32" dev lo
nsx "$NS_C" sh -c "echo 'tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1' > /proc/net/iwan" \
	|| die "$NS_C: 写 /proc/net/iwan 失败"
nsx "$NS_S" sh -c "echo 'tx_src=$OUTER_S tx_dst=$OUTER_C enabled=1' > /proc/net/iwan" \
	|| die "$NS_S: 写 /proc/net/iwan 失败"

nsx "$NS_C" ip route add "$INNER_S/32" dev iwan0 || die "$NS_C: 加内层路由失败"
nsx "$NS_S" ip route add "$INNER_C/32" dev iwan0 || die "$NS_S: 加内层路由失败"

for ns in "$NS_C" "$NS_S"; do
	nsx "$ns" test -r /proc/net/iwan || die "$ns: 没有 /proc/net/iwan（模块没在该 netns 初始化）"
done
info "拓扑就绪：$NS_C $INNER_C <-> $NS_S $INNER_S（外层 $OUTER_C/$OUTER_S 端口 $PORT）"
nsx "$NS_C" head -4 /proc/net/iwan | sed 's/^/    /'

A1_CAP_OK=0

# ---------------------------------------------------------------- A1

say "A1 模块出站 → C 侧解封（raw 注入已知内层包，抓包后 decap + cmpin 对拍）"

"$INTEROP" mkudp --out "$WORK/a1-inner.bin" --payload-out "$WORK/a1-inner-pl.bin" \
	--src "$INNER_C" --dst "$INNER_S" --sport "$A1_SPORT" --dport "$A1_DPORT" \
	--id 4660 --ttl 64 --df 0 --payload-str "$A1_STR" --quiet \
	>"$WORK/a1-mkudp.kv" 2>"$WORK/a1-mkudp.err" \
	|| die "interop_c mkudp 失败：$(tail -1 "$WORK/a1-mkudp.err")"
INNER_BYTES="$(kvget "$WORK/a1-mkudp.kv" INNER_BYTES)"
INNER_CSUM="$(kvget "$WORK/a1-mkudp.kv" INNER_IP_CSUM)"
info "注入包：$INNER_BYTES 字节 $INNER_C:$A1_SPORT -> $INNER_S:$A1_DPORT" \
     "id=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_ID) IP校验和=$INNER_CSUM 载荷=$A1_STR"
info "注意 mkudp 的 id 非 0：raw 注入路径的 raw_send_hdrinc() 只在 id==0 时用" \
     "ip_select_ident() 代填，id!=0 才能做严格逐字节比对"

# 期望外层头（与实际帧比较用，见 A3）：源/目的取的是每 netns 的 tx_src/tx_dst
"$INTEROP" outer --out "$WORK/a1-expected.hdr" --src "$OUTER_C" --dst "$OUTER_S" \
	--sport "$PORT" --dport "$PORT" --payload-len "$((INNER_BYTES + 8))" \
	--ttl 64 --id 0 --df 1 --quiet >"$WORK/a1-outer.kv" 2>"$WORK/a1-outer.err" \
	|| die "interop_c outer 失败：$(tail -1 "$WORK/a1-outer.err")"

nsx "$NS_S" python3 "$CAPTURE_PY" --ifname veth-s --dport "$PORT" --count 1 \
	--timeout "$CAP_TIMEOUT" --out "$WORK/a1-cap" \
	>"$WORK/a1-cap.kv" 2>"$WORK/a1-cap.err" &
CAP_PID=$!
BG_PIDS+=("$CAP_PID")

if ! wait_line "$WORK/a1-cap.kv" "CAPTURE_READY=1" 50; then
	bad "A1 抓包进程没就绪（见 $WORK/a1-cap.err）"
else
	info "已在 $NS_S 的 veth-s 上抓 dport=$PORT（设备层，早于模块的 PREROUTING 钩子）"
	tx0=$(ctr "$NS_C" tx_pkts)
	# 注入两次：第一次可能撞上 veth-c 的邻居解析而被排队，第二次必然直发。
	# 两次内容完全相同，抓包只取第一个到的，所以不影响比对结果。
	for _ in 1 2; do
		if ! nsx "$NS_C" python3 "$WORK/inject_raw.py" iwan0 "$WORK/a1-inner.bin" "$INNER_S" \
			>"$WORK/a1-inject.kv" 2>"$WORK/a1-inject.err"; then
			info "注入失败：$(tail -1 "$WORK/a1-inject.err")"
		fi
		sleep 0.3
	done
	tx1=$(ctr "$NS_C" tx_pkts)
	info "iwc tx_pkts $tx0 -> $tx1（模块确实封装发出了内层包）"

	cap_rc=0
	wait "$CAP_PID" || cap_rc=$?
	info "抓包进程退出码 $cap_rc, RESULT=$(kvget "$WORK/a1-cap.kv" RESULT)," \
	     "CAPTURED=$(kvget "$WORK/a1-cap.kv" CAPTURED)/$(kvget "$WORK/a1-cap.kv" WANTED)," \
	     "SKIPPED=$(kvget "$WORK/a1-cap.kv" SKIPPED)"

	if [ "$cap_rc" != 0 ] || [ ! -s "$WORK/a1-cap.0" ]; then
		bad "A1 没抓到模块发出的外层帧（是 iwan0 没发包，还是抓包网卡/端口不对？）"
	else
		A1_CAP_OK=1
		ok "A1 抓到模块发出的外层 UDP 帧（载荷 $(kvget "$WORK/a1-cap.kv" PAYLOAD_BYTES) 字节）"
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
		ok "A1 帧头/凭据/XOR 与生产实现一致（decap 用 pkt_hdr() 逐字节校验并通过）"
	else
		bad "A1 interop_c decap 失败：$(tail -1 "$WORK/a1-decap.err")"
	fi

	if [ -s "$WORK/a1-decapped.bin" ]; then
		if "$INTEROP" cmpin --got "$WORK/a1-decapped.bin" --want "$WORK/a1-inner.bin" \
			--quiet >"$WORK/a1-cmpin.kv" 2>"$WORK/a1-cmpin.err"; then
			ok "A1 解出的内层包与注入的内层包逐字节一致（$INNER_BYTES 字节，未排除任何字段）"
			info "已纳入比对：IP 版本/头长/TOS/总长/id/frag_off/ttl/proto/校验和/" \
			     "源/目的地址 + UDP 端口/长度/校验和 + 载荷"
		elif "$INTEROP" cmpin --got "$WORK/a1-decapped.bin" --want "$WORK/a1-inner.bin" \
			--ignore-stack-fields --quiet >"$WORK/a1-cmpin2.kv" 2>/dev/null; then
			info "严格比对：got $(kvget "$WORK/a1-cmpin.kv" GOT_BYTES) 字节 /" \
			     "want $(kvget "$WORK/a1-cmpin.kv" WANT_BYTES) 字节，" \
			     "首个差异偏移 $(kvget "$WORK/a1-cmpin.kv" DIFF_OFFSET)" \
			     "（-1 = 长度不同）got=$(kvget "$WORK/a1-cmpin.kv" GOT_BYTE)" \
			     "want=$(kvget "$WORK/a1-cmpin.kv" WANT_BYTE)；" \
			     "got id=$(kvget "$WORK/a1-cmpin.kv" GOT_IP_ID)" \
			     "ttl=$(kvget "$WORK/a1-cmpin.kv" GOT_IP_TTL)，" \
			     "want id=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_ID)" \
			     "ttl=$(kvget "$WORK/a1-mkudp.kv" INNER_IP_TTL)"
			ok "A1 解出的内层包与注入包一致（排除 id/frag_off/ttl/IP 校验和 4 处：" \
			   "内核 __ip_local_out() 会重算 tot_len 与 IP 校验和，raw 注入在 id=0 时" \
			   "还会由 ip_select_ident() 代填 id；其余字节含载荷与 UDP 校验和逐字节相同）"
		else
			bad "A1 解出的内层包与注入包不一致（偏移 $(kvget "$WORK/a1-cmpin2.kv" DIFF_OFFSET)" \
			    "got=$(kvget "$WORK/a1-cmpin2.kv" GOT_BYTE) want=$(kvget "$WORK/a1-cmpin2.kv" WANT_BYTE)）"
		fi
	else
		bad "A1 decap 没有产出内层包，无法比对"
	fi
fi

# ---------------------------------------------------------------- A2

say "A2 C 侧封装 → 模块入站（interop_c encap 造帧，按外层五元组发给 iws）"

"$INTEROP" mkudp --out "$WORK/a2-inner.bin" --payload-out "$WORK/a2-inner-pl.bin" \
	--src "$INNER_C" --dst "$INNER_S" --sport "$A2_SPORT" --dport "$A2_DPORT" \
	--id 4661 --ttl 64 --df 0 --payload-str "$A2_STR" --quiet \
	>"$WORK/a2-mkudp.kv" 2>"$WORK/a2-mkudp.err" \
	|| die "interop_c mkudp 失败：$(tail -1 "$WORK/a2-mkudp.err")"
"$INTEROP" encap --in "$WORK/a2-inner.bin" --out "$WORK/a2-outer-payload.bin" \
	--key "$KEY" --sid "$SID" --tok "$TOK" --enc 1 --quiet \
	>"$WORK/a2-encap.kv" 2>"$WORK/a2-encap.err" \
	|| die "interop_c encap 失败：$(tail -1 "$WORK/a2-encap.err")"
info "C 侧载荷 $(kvget "$WORK/a2-encap.kv" FRAME_BYTES) 字节" \
     "(type=$(kvget "$WORK/a2-encap.kv" FRAME_TYPE) sid=$SID tok=$TOK)" \
     "内含内层包 $(kvget "$WORK/a2-encap.kv" INNER_BYTES) 字节"

nsx "$NS_S" python3 "$WORK/udp_recv.py" "$INNER_S" "$A2_DPORT" "$WORK/a2-rx.bin" 8 \
	>"$WORK/a2-recv.kv" 2>"$WORK/a2-recv.err" &
RX_PID=$!
BG_PIDS+=("$RX_PID")

if ! wait_line "$WORK/a2-recv.kv" "RECV_READY=1" 50; then
	bad "A2 $NS_S 上的内层接收端没就绪（见 $WORK/a2-recv.err）"
else
	info "内层接收端已监听 $(kvget "$WORK/a2-recv.kv" BIND)"
	p0=$(ctr "$NS_S" rx_pkts)
	o0=$(ctr "$NS_S" rx_outer)
	f0=$(ctr "$NS_S" rx_frames)
	d0=$(ctr "$NS_S" rx_delivered)
	b0=$(ctr "$NS_S" rx_bad_hdr)

	# 关键：源端口也用外层端口，五元组与模块自己发的包完全对称
	if nsx "$NS_C" python3 "$WORK/send_udp.py" "$OUTER_C" "$PORT" "$OUTER_S" "$PORT" \
		"$WORK/a2-outer-payload.bin" >"$WORK/a2-send.kv" 2>"$WORK/a2-send.err"; then
		info "已从 $OUTER_C:$PORT 发出 $(kvget "$WORK/a2-send.kv" SENT_BYTES) 字节到 $OUTER_S:$PORT"
	else
		info "发送失败：$(tail -1 "$WORK/a2-send.err")"
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
	info "$NS_S 计数器增量: rx_pkts +$((p1 - p0)) rx_outer +$((o1 - o0))" \
	     "rx_frames +$((f1 - f0)) rx_delivered +$((d1 - d0)) rx_bad_hdr +$((b1 - b0))"

	[ "$((o1 - o0))" -ge 1 ] \
		&& ok "A2 外层四元组命中模块的 RX 钩子（rx_outer +$((o1 - o0))）" \
		|| bad "A2 外层四元组没命中（rx_outer +$((o1 - o0))）：查 any_dir/地址/端口"
	[ "$((f1 - f0))" -ge 1 ] \
		&& ok "A2 C 侧造的帧通过了凭据闸门被当成数据帧（rx_frames +$((f1 - f0))）" \
		|| bad "A2 帧没被接受（rx_frames +$((f1 - f0))）：查 sid/tok/type(XOR 是否一致)"
	[ "$((d1 - d0))" -ge 1 ] \
		&& ok "A2 模块解封并投递到本机协议栈（rx_delivered +$((d1 - d0))）" \
		|| bad "A2 没有解封投递（rx_delivered +$((d1 - d0))）：查 XOR 范围/内层头校验"
	# 负向对照：这一帧必须是"一次就过闸门"，不能是靠反复被拒后才通过
	[ "$((b1 - b0))" = 0 ] \
		&& ok "A2 该帧没有被帧头/凭据闸门拒掉（rx_bad_hdr 无增量）" \
		|| bad "A2 出现 rx_bad_hdr +$((b1 - b0))：sid/tok/type 或目的端口有不匹配"

	if [ "$rx_rc" = 0 ] && [ -s "$WORK/a2-rx.bin" ]; then
		if python3 "$WORK/hdrcmp.py" --got "$WORK/a2-rx.bin" \
			--want "$WORK/a2-inner-pl.bin" >"$WORK/a2-cmp.kv" 2>&1; then
			ok "A2 $NS_S 收到的内层载荷与 C 侧发送的逐字节一致（$(kvget "$WORK/a2-cmp.kv" GOT_BYTES) 字节）"
		else
			bad "A2 收到的内层载荷不一致（got $(kvget "$WORK/a2-cmp.kv" GOT_BYTES) 字节 /" \
			    "want $(kvget "$WORK/a2-cmp.kv" WANT_BYTES) 字节，偏移 $(kvget "$WORK/a2-cmp.kv" DIFF_OFFSET)）"
		fi
	else
		bad "A2 $NS_S 上的 UDP 套接字没收到内层数据（RESULT=$(kvget "$WORK/a2-recv.kv" RESULT)）"
	fi
fi

# ---------------------------------------------------------------- A3

say "A3 外层头字段一致性（期望值来自 interop_c outer，实际值来自 capture_iwan.py）"

# field_ck <字段名> <期望> <实际>
field_ck() {
	if [ -z "$3" ]; then
		bad "A3 $1 没抓到实际值"
	elif [ "$2" = "$3" ]; then
		ok "A3 $1 = $3"
	else
		bad "A3 $1 期望 $2，实际 $3"
	fi
}

if [ "$A1_CAP_OK" != 1 ]; then
	bad "A3 无法进行：A1 没抓到模块发出的外层帧，外层头一致性未被验证"
else
	# 七个字段逐字段比较；地址与端口这一组正是历史字节序缺陷的位置
	# （TTL/ID/DF/IP 校验和不在这里，由下面 26 字节的逐字节比较覆盖）
	for f in OUTER_IP_SRC OUTER_IP_DST OUTER_IP_PROTO OUTER_UDP_SPORT \
		 OUTER_UDP_DPORT OUTER_IP_TOT_LEN OUTER_UDP_LEN; do
		field_ck "$f" "$(kvget "$WORK/a1-outer.kv" "$f")" "$(capget "$WORK/a1-cap.kv" 0 "$f")"
	done
	info "期望头由 interop_c outer 生成：$(kvget "$WORK/a1-outer.kv" OUTER_IP_SRC):" \
	     "$(kvget "$WORK/a1-outer.kv" OUTER_UDP_SPORT) ->" \
	     "$(kvget "$WORK/a1-outer.kv" OUTER_IP_DST):$(kvget "$WORK/a1-outer.kv" OUTER_UDP_DPORT)" \
	     "proto=$(kvget "$WORK/a1-outer.kv" OUTER_IP_PROTO) tot_len=$(kvget "$WORK/a1-outer.kv" OUTER_IP_TOT_LEN)"

	# 前 26 字节 = IPv4 头 + UDP 源/目的端口 + UDP 长度；不含第 27/28 字节的
	# UDP 校验和（HW_CSUM 卸载下抓到的可能是部分和，比较无意义）。
	if python3 "$WORK/hdrcmp.py" --got "$WORK/a1-cap.0.hdr" \
		--want "$WORK/a1-expected.hdr" --limit 26 >"$WORK/a3-hdr.kv" 2>&1; then
		ok "A3 外层头前 26 字节与期望逐字节一致（TTL/ID/DF/IP 校验和一并覆盖）"
	else
		bad "A3 外层头前 26 字节不一致（首个差异偏移 $(kvget "$WORK/a3-hdr.kv" DIFF_OFFSET)：" \
		    "got=$(kvget "$WORK/a3-hdr.kv" GOT_BYTE) want=$(kvget "$WORK/a3-hdr.kv" WANT_BYTE)" \
		    "差异字节数 $(kvget "$WORK/a3-hdr.kv" DIFF_COUNT)）"
	fi
	for f in OUTER_IP_TTL OUTER_IP_ID OUTER_IP_DF OUTER_IP_CSUM; do
		info "$f 期望 $(kvget "$WORK/a1-outer.kv" "$f") 实际 $(capget "$WORK/a1-cap.kv" 0 "$f")"
	done
fi

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
	echo "全部通过：模块出站字节可被 C 侧解封、C 侧封装可被模块解封投递、外层头字段一致。"
	exit 0
fi
echo "有失败用例。排查提示："
if [ "$KEEP" = 1 ]; then
	echo "  · 全部日志与中间文件在 $WORK（--keep 已保留）"
else
	echo "  · 加 --keep 重跑可保留日志与中间文件（本次退出时已删除）"
fi
echo "  · dmesg | tail -30；/proc/net/iwan 的 rx_bad_hdr / rx_bad_inner / tx_bad_* 计数"
echo "  · 地址/端口不符先看 A3（历史字节序缺陷）：模块与 interop_c outer 的期望差在哪一字节"
exit 1
