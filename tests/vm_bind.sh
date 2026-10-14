#!/bin/bash
# 承载网卡绑定验证（只测 raw）——显式绑定（/proc oif=）与"由 FIB 解析后钉住"。
#
# 在崩溃靶场 guest 里跑：bash /bench/tests/vm_bind.sh [MTU]
#
# 拓扑（全部在 guest 内，不建 netlink 会话，走模块参数 + /proc 回落路径）：
#   cl netns: vethbp1 172.31.201.2/24 ── vethbp0 172.31.201.1/24（root netns）
#             vethb3  10.55.0.2/24     ── vethb2  10.55.0.1/24（root netns，无外层路由）
#   cl 内另有 iwan0（ip link add type iwan），路由 10.9.9.9/32 dev iwan0
#
# 判据全部是计数器（guest 里没有 dmesg 命令，钉住日志看串口日志 —— 每次运行的
# 日志里都有"承载网卡 …（FIB 解析后钉住/显式绑定）needed_headroom=52"那一行）：
#   tx_pkts/tx_err/rx_delivered = cl 的 /proc/net/iwan；
#   vethbp0/vethb2 RX           = root netns 侧对端网卡的 rx_packets，
#                                 用来证明"包到底从哪张卡出去"。
# 对端计数混着 ARP/IPv6 邻居发现，所以判据是单向的：
#   该出线的对端 ≥ 发送数；不该出线的对端 ≤ 1（噪声容差）。cl 里关掉 IPv6 以减少噪声。
#
# 内核语义（本次实测确认）：设了 flowi4_oif 之后，若 FIB 里没有经该设备的
# 路由，ip_route_output_flow() 会为**这张 UP 且有地址的设备**合成一条 scope
# link 路由（SO_BINDTODEVICE 语义）。所以显式绑定到任何一张 UP 的卡都能出站，
# 出站设备恒等于绑定的那张 —— 这正是"完全不管其他网卡"。用例 ④ 就是拿这条
# 语义做证据：绑 vethb3 时包从 vethb3/vethb2 出去，FIB 自己会选的 vethbp1
# 侧零增长。模块另有一道自查（解析出的 ifindex 必须等于绑定值），用来兜住
# 内核将来改变这套回落行为的情况。
#
# 用例：
#   ① 不写 oif：首包由 FIB 解析并钉住 ⇒ tx_pkts +5、tx_err +0、vethbp0 RX +5；
#      needed_headroom 36 → 52（veth 的 LL_RESERVED_SPACE=16 ⇒ 36+16）。
#   ② 显式绑 vethbp1：同上，且 vethb2 侧零增长。
#   ③ 显式绑 lo：5 个报文都从 lo 出去（对端两张卡都零增长），cl 自己的 RX
#      钩子在 lo 上把它们解出来 ⇒ rx_delivered +5（入站门限放行绑定的卡）。
#   ④ 显式绑 vethb3（FIB 自己不会选它）：vethb2 RX +5、vethbp0 RX +0
#      ⇒ 出站只看绑定卡，完全不管其他网卡。
#   ⑤ 按出口 IP 绑定（/proc 的 ip=，会话 ABI 里是 IWAN_A_IP）：
#      ⑤-1 ip=10.55.0.2（vethb3 的地址）⇒ 出站走 vethb3（vethb2 RX +5、
#           vethbp0 RX +0），串口日志出现"按出口 IP 10.55.0.2 解析"；
#      ⑤-2 ip=172.31.201.2（vethbp1 的地址）⇒ 换回 vethbp1 侧
#           （每次改 ip= 都清钉住，下一包按新地址表解析——这条同时验证
#           "钉住被清后按 IP 惰性重解析"的路径）；
#      ⑤-3 ip=192.0.2.1（不属于任何本机接口）⇒ 写入必须失败
#           （-EADDRNOTAVAIL：绑一个不存在的地址没有意义，与 oif= 的
#           "只校验格式、先配后起卡"刻意不同）；
#      ⑤-4 oif=<vethbp1> + ip=10.55.0.2（地址在 vethb3 上）⇒ 写入必须失败
#           （-EINVAL：两个绑定规格指向不同接口时不能取其一），且断言失败
#           后 tx_oif/tx_bind_ip **未变**（/proc 一次写入是一个配置事务，
#           全部校验通过才提交——逐令牌生效会留下"半个配置"）；
#      ⑤-6 tx_src=<外层地址> + ip=10.55.0.2（两个令牌设同一字段却不一致）
#           ⇒ 写入必须失败（与顺序无关，避免"谁写在后面谁赢"的隐式规则）；
#      状态断言用 /proc 读回新增的 tx_oif / tx_bind_ip / carrier 三项，
#      不再只靠计数器与串口日志推断"内核到底绑了哪张卡"。
#      ⑤-5 ip=0.0.0.0 tx_src=<外层地址> ⇒ 只清除"按 IP 绑定"，外层源地址
#           仍在，承载网卡回到 FIB 解析（vethbp0 RX +5、vethb2 RX +0）
#           ⇒ 证明被清除的是绑定，不是源地址。
set -u

MTU=${1:-2000}
NET=cl
KO=/bench/kernel/iwan.ko
OUTER_C=172.31.201.2	# cl 的外层地址（本端）
OUTER_S=172.31.201.1	# 对端（root netns 侧）
INNER=10.9.9.9
PORT=16002
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "  PASS $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
note() { echo "  · $*"; }
die()  { echo "[bind] 致命: $*"; exit 2; }

# cl 的 /proc/net/iwan 计数器（该 netns 的视图）
# 按**名字**取值，不依赖字段位置：读回里既有 "tx_pkts <n>" 这种行首键，也有
# "tx_oif 2 tx_bind_ip <ip> carrier 4" 这种行中键（用 $1==k 会取到空值）。
ctr()  { ip netns exec "$NET" awk -v k="$1" \
	'{for(i=1;i<NF;i++) if($i==k){print $(i+1); exit}}' /proc/net/iwan; }
# root netns 侧对端网卡的收包数（对端 = vethbp1/vethb3 的 peer）
prx()  { cat /sys/class/net/"$1"/statistics/rx_packets; }
# cl 里 iwan0 的 needed_headroom：本内核 sysfs 没有这个属性，留给串口日志里的
# 钉住行（needed_headroom=52）和 vm_profile.sh 的 pskb_expand_head 命中数做证据。

# 写回落路径配置；$1 = oif（空 = 不写这一项，交给 FIB 解析）
setconf() {
	local kv="tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1"
	[ -n "$1" ] && kv="$kv oif=$1"
	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" || die "写 /proc/net/iwan 失败"
}
# 经隧道发 5 个 raw 内层报文（bash 的 /dev/udp 每次一条）
send5() { ip netns exec "$NET" bash -c "for i in 1 2 3 4 5; do echo x > /dev/udp/$INNER/$PORT; done"; }

# 一轮测量：$1 名称 $2 oif $3 该出线的对端网卡（期望 RX ≥ 5）
#   $4-5 期望(tx_pkts,tx_err)Δ，$6 不该出线的对端（期望 RX ≤ 1）
round() {
	local name=$1 oif=$2 peer=$3 wp=$4 we=$5 other=$6
	local p0 e0 u0 o0 p1 e1 u1 o1 dused dother

	setconf "$oif"
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer"); o0=$(prx "$other")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer"); o1=$(prx "$other")
	dused=$((u1 - u0)); dother=$((o1 - o0))
	note "$name: tx_pkts +$((p1 - p0))/$wp tx_err +$((e1 - e0))/$we $peer RX +$dused（≥$wp）$other RX +$dother（≤1）"
	[ $((p1 - p0)) = "$wp" ] && [ $((e1 - e0)) = "$we" ] && \
	[ "$dused" -ge "$wp" ] && [ "$dother" -le 1 ] && ok "$name" || bad "$name"
}

# 任意 kv 的一轮测量：$1 名称 $2 kv 串 $3 该出线的对端 $4-5 期望(tx_pkts,tx_err)
#   $6 不该出线的对端（期望 RX ≤ 1）
roundkv() {
	local name=$1 kv=$2 peer=$3 wp=$4 we=$5 other=$6
	local p0 e0 u0 o0 p1 e1 u1 o1 dused dother

	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" \
		|| die "写 /proc/net/iwan 失败: $kv"
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer"); o0=$(prx "$other")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer"); o1=$(prx "$other")
	dused=$((u1 - u0)); dother=$((o1 - o0))
	note "$name: tx_pkts +$((p1 - p0))/$wp tx_err +$((e1 - e0))/$we $peer RX +$dused（≥$wp）$other RX +$dother（≤1）"
	[ $((p1 - p0)) = "$wp" ] && [ $((e1 - e0)) = "$we" ] && \
	[ "$dused" -ge "$wp" ] && [ "$dother" -le 1 ] && ok "$name" || bad "$name"
}

# /proc 读回的状态断言：$1 名称 $2 键 $3 期望值
expect_state() {
	local name=$1 key=$2 want=$3 got

	got=$(ctr "$key")
	[ "$got" = "$want" ] && ok "$name（$key=$got）" \
		|| bad "$name（$key=$got，期望 $want）"
}

# 写入必须被拒绝（内核返回负 errno，echo 非零退出），且绑定状态一项都不许变
expect_write_fail() {
	local name=$1 kv=$2
	local o0 b0 c0 o1 b1 c1

	o0=$(ctr tx_oif); b0=$(ctr tx_bind_ip); c0=$(ctr carrier)
	if ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" 2>/dev/null; then
		bad "$name（写入本应被拒绝）"
		return
	fi
	o1=$(ctr tx_oif); b1=$(ctr tx_bind_ip); c1=$(ctr carrier)
	[ "$o0" = "$o1" ] && [ "$b0" = "$b1" ] && [ "$c0" = "$c1" ] \
		&& ok "$name" \
		|| bad "$name（写入被拒，但状态被改了：tx_oif $o0→$o1 tx_bind_ip $b0→$b1）"
}

[ -f "$KO" ] || die "缺少 $KO"
[ "$(id -u)" = 0 ] || die "需要 root（靶场 guest 内就是 root）"

echo "== vm_bind: 建拓扑（cl netns + 两对 veth）=="
ip netns del $NET 2>/dev/null
ip link del vethbp0 2>/dev/null
ip link del vethb2 2>/dev/null
ip netns add $NET || die "建 netns 失败"
ip link add vethbp0 type veth peer name vethbp1 || die "建 veth 失败"
ip link set vethbp1 netns $NET
ip addr add $OUTER_S/24 dev vethbp0
ip link set vethbp0 up
ip -n $NET addr add $OUTER_C/24 dev vethbp1
ip -n $NET link set vethbp1 up
ip link add vethb2 type veth peer name vethb3 || die "建第二对 veth 失败"
ip link set vethb3 netns $NET
ip addr add 10.55.0.1/24 dev vethb2
ip link set vethb2 up
ip -n $NET addr add 10.55.0.2/24 dev vethb3
ip -n $NET link set vethb3 up
ip -n $NET link set lo up

echo "== vm_bind: 加载模块（回落路径：模块参数 + /proc）=="
rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_C" outer_dst="$OUTER_S" \
	dport="$PORT" sid=4660 tok=3405691582 key=0011223344556677 enc=1 \
	batch=1 df=1 max_mtu="$MTU" || die "insmod 失败"

ip -n $NET link add iwan0 type iwan || die "建 iwan0 失败"
ip -n $NET link set iwan0 up
ip -n $NET route add $INNER/32 dev iwan0 || die "加内层路由失败"
OIF_VETH=$(ip netns exec $NET cat /sys/class/net/vethbp1/ifindex) || die "取 vethbp1 ifindex 失败"
OIF_B3=$(ip netns exec $NET cat /sys/class/net/vethb3/ifindex) || die "取 vethb3 ifindex 失败"
note "cl: vethbp1 ifindex=$OIF_VETH, vethb3 ifindex=$OIF_B3, iwan0 ifindex=$(ip netns exec $NET cat /sys/class/net/iwan0/ifindex)"
# 关掉 cl 的 IPv6：邻居发现/MLD 的帧会打到对端网卡上，干扰"哪张卡出站"的计数证据
ip netns exec $NET sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null \
	&& note "cl: 已关闭 IPv6（避免邻居发现帧污染对端计数）"

# 用例 ④ 需要包真的从 vethb3 出去：该 link 上没有 172.31.201.1，ARP 不会有人答，
# 所以先钉一条静态邻居（指向 vethb2 的 MAC），否则包会停在邻居解析队列里。
if ip -n $NET neigh add $OUTER_S lladdr "$(cat /sys/class/net/vethb2/address)" dev vethb3 2>/dev/null; then
	note "cl: 已为 $OUTER_S 在 vethb3 上钉静态邻居（让 ④ 的包真能出线）"
else
	note "cl: 静态邻居添加失败（④ 的包可能停在 ARP 队列）"
fi

echo "== vm_bind: 用例 =="
round "① FIB 解析后钉住" ""            vethbp0 5 0 vethb2
round "② 显式绑 vethbp1"  "$OIF_VETH"  vethbp0 5 0 vethb2

# ③ 绑 lo：不预设它到底能不能出站，只要求"没有静默丢失"且确实从 lo 出去
p0=$(ctr tx_pkts); e0=$(ctr tx_err); d0=$(ctr rx_delivered); a0=$(prx vethbp0); b0=$(prx vethb2)
setconf 1; send5; sleep 1
p1=$(ctr tx_pkts); e1=$(ctr tx_err); d1=$(ctr rx_delivered); a1=$(prx vethbp0); b1=$(prx vethb2)
dp=$((p1 - p0)); de=$((e1 - e0)); dd=$((d1 - d0)); da=$((a1 - a0)); db=$((b1 - b0))
note "③ 显式绑 lo: tx_pkts +$dp tx_err +$de（两者之和应为 5）vethbp0 RX +$da vethb2 RX +$db cl rx_delivered +$dd"
[ $((dp + de)) = 5 ] && ok "③ 绑 lo：5 个报文都有归宿（无静默丢弃）" \
	|| bad "③ 绑 lo：dp+de=$((dp + de)) 应为 5"
[ "$da" -le 1 ] && [ "$db" -le 1 ] && ok "③ 绑 lo：对端两张卡都没收到（包只走 lo）" \
	|| bad "③ 绑 lo：vethbp0 +$da vethb2 +$db（本不该有其他卡出站）"
[ "$dd" -ge 5 ] && ok "③ 绑 lo：cl 的 RX 门限在绑定的 lo 上放行（rx_delivered +$dd）" \
	|| bad "③ 绑 lo：rx_delivered 只 +$dd（入站门限可能误伤绑定的卡）"

round "④ 显式绑 vethb3（FIB 不会选它）" "$OIF_B3" vethb2 5 0 vethbp0

echo "== vm_bind: 用例 ⑤（按出口 IP 绑定）=="
# 前置自检：状态断言依赖读回里的绑定字段；打包了旧模块时直接报清楚，
# 而不是在十几个 $key= 空值上刷 FAIL。
if [ -z "$(ctr tx_oif)" ] || [ -z "$(ctr tx_bind_ip)" ] || [ -z "$(ctr carrier)" ]; then
	die "读回里没有 tx_oif/tx_bind_ip/carrier（$KO 不是带绑定导出的版本？）"
fi
# kv 里先写 oif=0：/proc 是按令牌覆盖的，不显式清零会沿用上一轮的绑定网卡，
# 那样 ip= 会被判成"与 oif 冲突"（这正是 ⑤-4 要测的行为）。
roundkv "⑤-1 ip=10.55.0.2（vethb3）" \
	"tx_dst=$OUTER_S enabled=1 oif=0 ip=10.55.0.2" vethb2 5 0 vethbp0
expect_state "⑤-1 绑定状态" tx_bind_ip 10.55.0.2
expect_state "⑤-1 实际承载网卡" carrier "$OIF_B3"
roundkv "⑤-2 ip=172.31.201.2（vethbp1）" \
	"tx_dst=$OUTER_S enabled=1 oif=0 ip=$OUTER_C" vethbp0 5 0 vethb2
expect_state "⑤-2 绑定状态" tx_bind_ip "$OUTER_C"
expect_state "⑤-2 实际承载网卡" carrier "$OIF_VETH"
expect_write_fail "⑤-3 ip 不属于任何本机接口 ⇒ 拒绝（-EADDRNOTAVAIL）" \
	"tx_dst=$OUTER_S enabled=1 ip=192.0.2.1"
expect_write_fail "⑤-4 ip 不在指定的网卡上 ⇒ 拒绝（-EINVAL）" \
	"tx_dst=$OUTER_S enabled=1 oif=$OIF_VETH ip=10.55.0.2"
expect_write_fail "⑤-6 tx_src 与 ip 在同一写入里不一致 ⇒ 拒绝" \
	"tx_dst=$OUTER_S enabled=1 tx_src=$OUTER_C ip=10.55.0.2"
roundkv "⑤-5 ip=0.0.0.0 清除绑定（源地址保留）" \
	"tx_dst=$OUTER_S enabled=1 ip=0.0.0.0 tx_src=$OUTER_C" vethbp0 5 0 vethb2
expect_state "⑤-5 绑定已清除" tx_bind_ip 0.0.0.0
expect_state "⑤-5 外层源地址保留" tx_src "$OUTER_C"

echo "== vm_bind: 结果 PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" = 0 ]
