#!/usr/bin/env bash
# vm_profile.sh —— 崩溃靶场 guest 内的数据面耗时剖析驱动。
#
# 用法（guest 内，root）：bash /bench/tests/vm_profile.sh tx|rx|open <MTU>
#   tx：SINK=1 + KERNEL_ONLY=1，只跑 raw c2s —— 量模块**发送**路径
#       （含外层承载、计量端接收侧；对应 host 上的 SINK=1 阶梯口径）
#   rx：SINK=0 + KERNEL_ONLY=1，只跑 raw s2c —— 量模块**接收**路径
#       （服务端用户态 TUN 注入 → 外层承载 → 钩子解密 → 内层交付）
#   open：与 tx 同拓扑，但在宿主侧对 vethbp0 入向 DROP。外层包在 netfilter
#       INPUT 即被丢弃 ⇒ 计量端 socket 队列与发送侧 sk_wmem_alloc 反压都消失，
#       量到的是**开环**发送能力（发送 syscall + 模块 + 承载 + 宿主入向处理）。
#
# 原理：用 ftrace 的函数统计器（function_profile_enabled + set_ftrace_filter）
# 只对数据面相关函数计数与计时，避免全函数插桩把机器压垮。统计器给的是
# **含子调用的时间**（inclusive），因此报告里同时给出命中数：单次调用 =
# 该函数自身 + 其下游的总耗时，按调用树逐层相减即得各段独占时间。
# 输出经串口回传，故只打印聚合结果，不落原始 trace。
set -u

MODE=${1:-tx}
MTU=${2:-65499}
# 第三个参数可选：覆盖 raw 行的报文字节数（默认 = MTU）。用途：同一会话下
# 用 1200B 跑一遍，从混合平均里减去小包分量，得到大包每包成本的干净值。
SIZE_RAW=${3:-$MTU}
# 第四个参数可选：探针 UDP 行的内层尺寸（默认 1200）。把它也设成大包，可以让
# 统计窗口里只剩一种报文尺寸，平均值即该尺寸的每包成本，不必再做跨运行相减。
SIZE_UDP=${4:-1200}
# 第五个参数可选：只跑哪一种协议行（raw|udp|tcp）。paged 模式默认 udp，其余默认 raw。
PROTO=${5:-}
TR=/sys/kernel/debug/tracing
BIN=/bench/bin

say() { echo "[profile] $*"; }

mount -t debugfs none /sys/kernel/debug 2>/dev/null
if [ ! -d "$TR" ]; then
	echo "[profile] 无 $TR：内核未启用 debugfs/ftrace，无法剖析" >&2
	exit 2
fi
say "可用 tracer：$(cat "$TR/available_tracers" 2>/dev/null)"
if [ ! -e "$TR/function_profile_enabled" ]; then
	echo "[profile] 无 function_profile_enabled（CONFIG_FUNCTION_PROFILER 未启用）" >&2
	exit 3
fi

# ---- 待观测函数集：按模式区分 -------------------------------------------
# 说明：只列数据面路径上的关键节点，父子关系即调用树的边。
FUNCS_COMMON="iwan_xmit iwan_xor_skb iwan_xor_paged iwan_xor \
skb_cow_head pskb_expand_head udp_set_csum ip_send_check \
ip_local_out ip_finish_output __dev_queue_xmit validate_xmit_skb skb_checksum_help \
dst_cache_get_ip4 ip_route_output_flow veth_xmit netif_rx \
udp_rcv __udp4_lib_rcv udp_queue_rcv_skb udp_recvmsg \
skb_copy_datagram_iter skb_release_data kfree_skb_reason consume_skb"

FUNCS_TX="raw_sendmsg ip_append_data __ip_append_data sock_alloc_send_skb"
FUNCS_RX="tun_chr_write_iter tun_get_user ip_rcv ip_rcv_core ip_local_deliver \
nf_hook_slow nf_hook_slow_list iwan_rx_hook iwan_decap_one raw_rcv skb_gso_segment"

case "$MODE" in
tx)    FUNCS="$FUNCS_COMMON $FUNCS_TX"; SINKV=1; DIRV=c2s ;;
rx)    FUNCS="$FUNCS_COMMON $FUNCS_RX"; SINKV=0; DIRV=s2c ;;
open)  FUNCS="$FUNCS_COMMON $FUNCS_TX"; SINKV=1; DIRV=c2s ;;
# paged：SINK=0 且只跑 udp c2s。SINK=0 时协议行完全由 PROTO_LIST 驱动（SINK=1
# 分支固定带一行 raw c2s），而 TUN 档的报文不经过模块的 ndo_start_xmit，于是
# iwan_* 的样本全部来自**套接字发送方（分页 skb）**，是模块 TX 开销的干净值。
paged) FUNCS="$FUNCS_COMMON $FUNCS_TX"; SINKV=0; DIRV=c2s ;;
*)     echo "[profile] 未知模式 $MODE（可选 tx/rx/open/paged）" >&2; exit 2 ;;
esac
: "${PROTO:=raw}"
if [ "$MODE" = paged ] && [ -z "${5:-}" ]; then PROTO=udp; fi

echo 0 > "$TR/tracing_on" 2>/dev/null

# 次序是硬约束：**先加载模块，再写过滤器**。模块函数在 insmod 之后才进
# kallsyms/ftrace 哈希；反过来的话 set_ftrace_filter 认不出这些名字，模块
# 自身函数（iwan_xmit / iwan_xor_skb / iwan_xor_paged …）一个都不会被计数。
insmod /bench/kernel/iwan.ko max_mtu="$MTU" || exit 4

: > "$TR/set_ftrace_filter" 2>/dev/null
for f in $FUNCS; do
	echo "$f" >> "$TR/set_ftrace_filter" 2>/dev/null
done
say "接受插桩的函数：$(grep -c . "$TR/set_ftrace_filter" 2>/dev/null) 个"
say "$(tr '\n' ' ' < "$TR/set_ftrace_filter" 2>/dev/null)"

# 开环模式：外层包在宿主 INPUT 即丢弃
if [ "$MODE" = open ]; then
	iptables -I INPUT 1 -i vethbp0 -j DROP && say "已对 vethbp0 入向 DROP（开环）"
fi

# ---- 打流（统计器全程开着，只有上面这些函数会被计数）--------------------
echo 1 > "$TR/function_profile_enabled" 2>/dev/null
ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK="$SINKV" KERNEL_ONLY=1 SKIP_BASELINE=1 \
BIN=$BIN CLI_MTU="$MTU" VETH_MTU=65535 SIZE_RAW="$SIZE_RAW" SIZE_UDP="$SIZE_UDP" \
PROTO_LIST="$PROTO" DIR_LIST="$DIRV" bash /bench/tests/bench_proto.sh
echo 0 > "$TR/function_profile_enabled" 2>/dev/null
if [ "$MODE" = open ]; then
	iptables -D INPUT 1 2>/dev/null
fi

# ---- 汇总（逐 CPU 相加；busybox awk 足够）-------------------------------
say "== 原始样例行（确认单位）=="
head -3 "$TR/trace_stat/function0" 2>/dev/null
say "== 汇总：time(us) hits avg(us) 函数（含子调用）=="
awk 'NF >= 4 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]/ {
	h[$1] += $2; t[$1] += $3
}
END { for (f in t) printf "%12d %10d %8.2f %s\n", t[f], h[f], t[f]/h[f], f }' \
	"$TR"/trace_stat/function* 2>/dev/null | sort -k1 -nr | head -40

echo 0 > "$TR/function_profile_enabled" 2>/dev/null
rmmod iwan 2>/dev/null
echo "[profile] 完成（mode=$MODE mtu=$MTU size_raw=$SIZE_RAW size_udp=$SIZE_UDP proto=$PROTO）"
