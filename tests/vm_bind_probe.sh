#!/bin/bash
# 承载网卡事件语义探针（只测 raw）——为"控制面该监听哪些事件"提供实测依据。
#
# 在崩溃靶场 guest 里跑：bash /bench/tests/vm_bind_probe.sh [MTU]
#
# 拓扑与 tests/vm_bind.sh 相同（cl netns + 两对 veth + iwan0，走模块参数与
# /proc/net/iwan 回落路径，不建 netlink 会话）。
#
# 探针逐项改变承载设备的状态，观察数据面的两类归宿：
#   tx_pkts 增长 = 模块接受了报文并交给了外层栈（链路层再丢不再回传错误）；
#   tx_err  增长 = 模块在外层路由查找阶段就丢弃（拒绝发送）。
# 每项给出"假设"与"实测"，供判断控制面必须对哪些事件做出反应。
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

ok()   { OK=$((OK + 1)); echo "    [符合假设] $*"; }
miss() { MISS=$((MISS + 1)); echo "    [不符假设] $*"; }
note() { echo "  · $*"; }
die()  { echo "[probe] 致命: $*"; exit 2; }

# 按名字取值（同 vm_bind.sh）：读回里既有行首键也有行中键
ctr() { ip netns exec "$NET" awk -v k="$1" \
	'{for(i=1;i<NF;i++) if($i==k){print $(i+1); exit}}' /proc/net/iwan; }
prx() { cat /sys/class/net/"$1"/statistics/rx_packets; }
setconf() {
	local kv="tx_src=$OUTER_C tx_dst=$OUTER_S enabled=1 oif=${1:-0}"
	# 必须显式写 oif=0：/proc 写入是按项覆盖，缺项保留旧值 —— 否则"自动固定"
	# 那一组会继续沿用上一组设的显式绑定，测出来的根本不是 FIB 路径。
	ip netns exec "$NET" sh -c "echo '$kv' > /proc/net/iwan" || die "写 /proc/net/iwan 失败"
}
send5() { ip netns exec "$NET" bash -c "for i in 1 2 3 4 5; do echo x > /dev/udp/$INNER/$PORT; done"; }
static_neigh() {	# vethb3 上没有 OUTER_S，需要静态邻居才能完成下一跳解析
	ip -n $NET neigh replace $OUTER_S lladdr "$NEIGH_MAC" dev vethb3 2>/dev/null
}

# 观测一轮：$1 名称 $2 假设 $3 该出线的对端 $4 期望(tx_pkts,tx_err)
probe() {
	local name=$1 hyp=$2 peer=$3 wp=$4 we=$5
	local p0 e0 u0 p1 e1 u1 dp de du
	p0=$(ctr tx_pkts); e0=$(ctr tx_err); u0=$(prx "$peer")
	send5
	sleep 1
	p1=$(ctr tx_pkts); e1=$(ctr tx_err); u1=$(prx "$peer")
	dp=$((p1 - p0)); de=$((e1 - e0)); du=$((u1 - u0))
	note "$name"
	note "  假设：$hyp"
	note "  实测：tx_pkts +$dp（期望 $wp）tx_err +$de（期望 $we）$peer RX +$du（期望 ≥$wp）"
	if [ "$dp" = "$wp" ] && [ "$de" = "$we" ] && [ "$du" -ge "$wp" ]; then ok "$name"; else miss "$name"; fi
}

[ -f "$KO" ] || die "缺少 $KO"
[ "$(id -u)" = 0 ] || die "需要 root（靶场 guest 内就是 root）"

echo "== vm_bind_probe: 建拓扑 =="
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
ip netns exec $NET sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null

rmmod iwan 2>/dev/null
insmod "$KO" enabled=1 any_dir=1 outer_src="$OUTER_C" outer_dst="$OUTER_S" \
	dport="$PORT" sid=4660 tok=3405691582 key=0011223344556677 enc=1 \
	batch=1 df=1 max_mtu="$MTU" || die "insmod 失败"
ip -n $NET link add iwan0 type iwan || die "建 iwan0 失败"
ip -n $NET link set iwan0 up
ip -n $NET route add $INNER/32 dev iwan0 || die "加内层路由失败"

OIF_VETH=$(ip netns exec $NET cat /sys/class/net/vethbp1/ifindex)
OIF_B3=$(ip netns exec $NET cat /sys/class/net/vethb3/ifindex)
NEIGH_MAC=$(cat /sys/class/net/vethb2/address)
note "cl: vethbp1 ifindex=$OIF_VETH, vethb3 ifindex=$OIF_B3"
static_neigh

echo "== vm_bind_probe: ① 接口管理状态（down/up，显式绑定）=="
setconf "$OIF_B3"
probe "①-0 基线：显式绑 vethb3（UP、有地址）" "接受并出线" vethb2 5 0
ip -n $NET link set vethb3 down
probe "①-1 vethb3 down" "查找失败 ⇒ 拒绝发送" vethb2 0 5
ip -n $NET link set vethb3 up
static_neigh	# down 会清掉邻居表
probe "①-2 vethb3 up（恢复）" "恢复出线" vethb2 5 0

echo "== vm_bind_probe: ② 接口地址集合（删地址/加地址，显式绑定）=="
ip -n $NET addr del 10.55.0.2/24 dev vethb3
probe "②-1 删除 vethb3 的唯一 IPv4 地址" "合成路由失效 ⇒ 拒绝发送" vethb2 0 5
ip -n $NET addr add 10.55.0.2/24 dev vethb3
probe "②-2 地址恢复" "恢复出线" vethb2 5 0

echo "== vm_bind_probe: ③ FIB 路径（自动固定，down/up）=="
setconf ""
ip -n $NET route flush cache 2>/dev/null
probe "③-0 不写 oif：FIB 解析到 vethbp1" "接受并从 vethbp1 出线" vethbp0 5 0
ip -n $NET link set vethbp1 down
probe "③-1 vethbp1 down（无备选外层路径）" "查找失败 ⇒ 拒绝发送" vethbp0 0 5
ip -n $NET link set vethbp1 up
probe "③-2 vethbp1 up（自动路径自愈）" "重新解析并恢复出线" vethbp0 5 0

echo "== vm_bind_probe: ④ 接口删除（显式绑定）=="
setconf "$OIF_B3"
ip -n $NET link del vethb3
# vethb3 消失后 root netns 侧的 vethb2 也随之消失，无法再读对端计数，
# 这一项只保留发送侧证据（tx_err 增长）。
probe "④-1 删除被显式绑定的 vethb3" "查找失败（-ENODEV）⇒ 拒绝发送" vethbp0 0 5

echo "== vm_bind_probe: 结果 符合假设=$OK 不符假设=$MISS =="
exit 0
