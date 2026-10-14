#!/usr/bin/env bash
# iWAN 同机单向容量基准 —— 内层 tcp / udp / 裸 IP（IP 协议号 253）
#
# 三种协议 × 两个方向 × 最多三个场景（基线 6 行 / TUN 档 6 行 / 内核档 6 行）：
#   · 基线：不经隧道，两个 bench_proto 进程直接在 127.0.0.1 上对打（lo）。
#     它的作用有两个：给出隧道开销的参照，同时**标定发生器自己的上限**
#     （隧道数字要是逼近基线，那量到的就是尺子不是隧道）。
#   · 隧道：真 iwan-server（用户态 TUN，宿主）+ netns 里的真 TUN 客户端，
#     外层是 veth —— **不是 lo**，lo 只用在基线那一档。c2s = netns 里发、宿主收；
#     s2c = 宿主发、netns 里收。
#   · 内核：KERNEL=1 时追加，同一拓扑把客户端换成 --data-plane kernel（模块建
#     iwan0、零 TUN，服务端仍是 TUN）。前置：sudo insmod kernel/iwan.ko。
#   · 计量：SINK=1 时服务端带 IWAN_SRV_SINK=1 起（仅计量接收端点：不建 TUN、
#     不解封装、不注入、不回送）。只有 c2s 的 udp/raw 两档成立（TCP 要三次
#     握手、s2c 要服务端回送数据），接收侧证据换成服务端日志里的 SINK 计量行
#     （口径是外层 UDP 净荷，含 8B 定长首部）加客户端 TUN 的出口计数。
#
# 每个非基线数字都带**独立证据**：采样两端隧道设备（TUN 档是客户端 TUN，内核档
# 是模块建的 iwan0）的 rx/tx 字节数（sysfs），
# 要求"确实过线的方向"增量不小于接收侧统计到的 payload。只看 bench_proto
# 自己的计数会漏掉最危险的一类错误 —— 路由没生效、流量从 veth 直穿过去，
# 报出来的是同机链路的几十 Gbps（bench.sh 里就踩过这个坑）。
#
# 用法：
#   sudo bash tests/bench_proto.sh [时长秒]         # 默认 5 秒
#   THREADS=8 sudo bash tests/bench_proto.sh 10     # 加并发
#   SKIP_BASELINE=1 sudo bash tests/bench_proto.sh  # 只测隧道
#   sudo insmod kernel/iwan.ko                      # 内核档前置（无参数即可）
#   sudo env KERNEL=1 bash tests/bench_proto.sh     # 追加内核数据面对照档
#   sudo env SINK=1 bash tests/bench_proto.sh       # 服务端仅计量（不建 TUN）：
#                                                   # 只量客户端 c2s 的 udp/raw
#   SKIP_TUNNEL=1 sudo bash tests/bench_proto.sh    # 只跑裸基线（无 /dev/net/tun 的机器）
#   sudo env KERNEL=1 KERNEL_ONLY=1 PROTO_LIST=tcp DIR_LIST=c2s bash tests/bench_proto.sh
#          （KERNEL_ONLY=1 只是"在 KERNEL=1 时不跑 TUN 档"，本身仍要求 KERNEL=1）
#                                                   # 行过滤 + 只跑内核档（panic 定位用）
#
# 环境变量：THREADS(4) SIZE_UDP(1200) SIZE_RAW(1220，含 20 字节 IP 头)
#           SIZE_TCP(65536) SKIP_BASELINE(0) SINK(0)
#           PROTO_LIST(tcp udp raw) DIR_LIST(c2s s2c) KERNEL_ONLY(0)
set -uo pipefail

cd "$(dirname "$0")/.."

DURATION=${1:-5}
THREADS=${THREADS:-4}
SIZE_UDP=${SIZE_UDP:-1200}
SIZE_RAW=${SIZE_RAW:-1220}
SIZE_TCP=${SIZE_TCP:-65536}
SKIP_BASELINE=${SKIP_BASELINE:-0}
SINK=${SINK:-0}              # 1 = 服务端仅计量（IWAN_SRV_SINK=1，不建 TUN）
[[ "$DURATION" =~ ^[0-9]+$ ]] || { echo "error: 时长要正整数秒: $DURATION" >&2; exit 2; }

# 与 tests/bench.sh 完全错开的名字与端口：两个脚本可以同时开着跑
PORT=16002
NS=iwabp
VETH_H=172.31.201.1          # 宿主侧 veth
VETH_N=172.31.201.2          # netns 侧 veth
VETH_H_DEV=vethbp0
VETH_N_DEV=vethbp1
TUN=iwabp0                   # 服务端 TUN（宿主）
TUN_CLI=iwabp-tun0           # 客户端 TUN（netns 内）
KERNEL=${KERNEL:-0}          # 1 = 追加内核数据面对照档（要求 iwan 模块已加载）
# SINK=1 与 KERNEL=1 可以同时成立：模块的钩子注册在**客户端自己的 netns** 里，
# 而 SINK 的服务端没有 TUN、也没有钩子，两者不会抢同一条外层四元组。该组合量的是
# "客户端内核发送路径单独能把多少 raw 包推出去"，主指标是 pps。
# （TUN 数据面 + SINK 是另一回事，见下面的模块门禁：那种组合必须先把模块卸掉。）
# 内核档 + 超过模块上限的内层 MTU 会 panic（2026-10-07 实测，见 docs/perf-plan.md）。
# 上限现在是模块参数 max_mtu（默认 1500）：模块已加载就直接读它来判，这样
# "insmod max_mtu=1600 + CLI_MTU=1600" 这类同值的复现阶梯不会被误拦。
# 模块没加载时按默认 1500 判。要硬闯（明知会 panic 的尺寸）设 ALLOW_JUMBO_KERNEL=1。
KMOD_MTU_MAX=1500
if [ "$KERNEL" = 1 ] && [ -r /sys/module/iwan/parameters/max_mtu ]; then
    KMOD_MTU_MAX=$(cat /sys/module/iwan/parameters/max_mtu 2>/dev/null || echo 1500)
fi
if [ "$KERNEL" = 1 ] && [ -n "${CLI_MTU:-}" ] && [ "${CLI_MTU:-0}" -gt "$KMOD_MTU_MAX" ] \
        && [ "${ALLOW_JUMBO_KERNEL:-0}" != 1 ]; then
    echo "警告：CLI_MTU=$CLI_MTU > 模块上限 max_mtu=$KMOD_MTU_MAX 且 KERNEL=1 —— 该组合会 kernel panic；"
    echo "      本轮跳过内核场景（先 sudo rmmod iwan; sudo insmod kernel/iwan.ko max_mtu=$CLI_MTU）"
    echo "      要硬闯设 ALLOW_JUMBO_KERNEL=1，并先准备好抓 trace"
    KERNEL=0
fi
SKIP_TUNNEL=${SKIP_TUNNEL:-0} # 1 = 只跑裸 lo 基线（没有 /dev/net/tun 的机器也能标定尺子）
# 行过滤：定位 panic / 定向复核时只跑子集（默认全跑）。单行写法——别把命令拆行。
PROTO_LIST=${PROTO_LIST:-tcp udp raw}   # 只跑列出的协议
DIR_LIST=${DIR_LIST:-c2s s2c}           # 只跑列出的方向
KERNEL_ONLY=${KERNEL_ONLY:-0}           # 1 = KERNEL=1 时跳过 TUN 档直接进内核档
if [ "$KERNEL_ONLY" = 1 ] && [ "$KERNEL" != 1 ]; then
    echo "error: KERNEL_ONLY=1 需要 KERNEL=1（跳过 TUN 档只对内核档有意义）" >&2
    exit 2
fi
# 方向过滤判定：DIR_LIST 按空格分词，前后补空格做整词匹配
want_dir() { case " $DIR_LIST " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
BIN=${BIN:-./bin}           # 二进制目录；度量档可用 build-jumbo/bin 而不动 build/
die() { echo "error: $*" >&2; exit 1; }

# 只在真正的脚本文件里做 pkill -f：脚本自身的命令行只有脚本路径，不会像
# 交互式 bash -c 那样把模式串也带进去（本轮就因此把自己的 shell 杀了一次）。
cleanup() {
    set +e
    # 内核档下 SIGKILL 会把会话留给 netns 销毁去回收；先给一次优雅退出，
    # 让模块收到 SESSION_DOWN 自己清掉会话与 iwan0
    if [ -n "$CLI_PID" ] && kill -0 "$CLI_PID" 2>/dev/null; then
        kill -INT "$CLI_PID" 2>/dev/null
        for _ in $(seq 1 20); do kill -0 "$CLI_PID" 2>/dev/null || break; sleep 0.1; done
    fi
    [ -n "$CLI_PID" ] && kill -9 "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && wait "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && wait "$SRV_PID" 2>/dev/null
    pkill -9 -x bench_proto 2>/dev/null
    pkill -9 -f "bin/iwan-client proxy .*--port $PORT" 2>/dev/null
    pkill -9 -f "bin/iwan-server .*--port $PORT" 2>/dev/null
    [ "$RULE_VETH" = 1 ] && iptables -D INPUT -i "$VETH_H_DEV" -j ACCEPT 2>/dev/null
    [ "$RULE_TUN" = 1 ] && iptables -D INPUT -i "$TUN" -j ACCEPT 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$VETH_H_DEV" 2>/dev/null
    # 失败时先把工作日志留一份再删目录：否则事后只剩"哪一行错了"，没有现场
    # （前两轮真机失败时 server/client 日志就是这样丢掉的）
    if [ "${FAILS:-0}" != 0 ] && [ -d "$WORK" ]; then
        KEEP="/tmp/iwan-benchproto-logs.$$"
        mkdir -p "$KEEP" 2>/dev/null && cp "$WORK"/*.log "$KEEP"/ 2>/dev/null && \
            echo "现场日志已保留：$KEEP/（server.log / client.log / client-kernel.log）" >&2
    fi
    rm -rf "$WORK"
}

# 内层 MTU 的两条硬约束：① 上限 65499（外层 IPv4 总长 65535 - 36B 封装开销）；
# ② 承载链路的**三层 MTU** 必须装下外层报文 = 内层分组 + 36B（20B IP + 8B UDP
# + 8B 定长首部），否则外层会被分片。注意其余 14B 是以太网首部，只出现在字节
# 计数器里，不计入 MTU。泵已按协商 MTU 动态定尺。
if [ -n "${CLI_MTU:-}" ]; then
    if [ "$CLI_MTU" -gt 65499 ]; then
        die "CLI_MTU=$CLI_MTU 超过规范上限 65499（外层 IPv4 总长 65535 - 36B 封装开销）"
    fi
    if [ "$VETH_MTU" -lt "$((CLI_MTU + 36))" ]; then
        die "VETH_MTU=$VETH_MTU < CLI_MTU+36=$((CLI_MTU + 36))：外层报文装不下，会被分片，请提高 VETH_MTU"
    fi
fi
VETH_MTU=${VETH_MTU:-1500}   # 外层 veth 的 MTU；度量档配 IWAN_JUMBO_MTU 时设 65535
CLI_MTU=${CLI_MTU:-}         # 隧道内层 MTU（传 --mtu，取 min(服务端回执, 此值)）；
                             # 空 = 用编译期默认（正常构建 1400，度量档 = IWAN_JUMBO_MTU）
MTU_ARG=()                   # 空数组：不传 --mtu
[ -n "$CLI_MTU" ] && MTU_ARG=(--mtu "$CLI_MTU")
# SINK=1：给服务端加 IWAN_SRV_SINK=1（空数组 = 默认档命令行一个字节都不变）。
# 用 env 前缀而不是把 "A=B" 放进数组：展开出来的赋值词不会被当成赋值。
SRV_ENV=()
[ "$SINK" = 1 ] && SRV_ENV=(env IWAN_SRV_SINK=1)
KERNEL_DEV=iwan0             # 模块固定设备名（kernel/iwan.h: IWAN_DEV_NAME）
CLI_DEV=""                   # 当前档位客户端侧的隧道设备（证据从它的 sysfs 采）
# s2c 时客户端侧的**证据设备**可以换一个（默认同 CLI_DEV）。内核档必须换：
# 模块入站是 netif_rx/netif_receive_skb 直接注入协议栈，不经 netdev 的驱动 RX
# 路径，内核也不会替驱动累加 dev->stats.rx_* —— iwan0 的 rx_bytes 恒为 0，
# 拿它当证据会把"通了"误判成"没走隧道"。改用客户端 netns 外层 veth 的到达计数
# （外层 = 36B 帧头 + 内层包，字节数天然 ≥ payload）。
CLI_DEV_S2C="" 
SRV_IP=100.64.0.1
SUBNET=100.64.0.0/16
P_TCP=17020
P_UDP=17021
P_RAW=17022
WORK=$(mktemp -d)
LOGR=/tmp/iwan-benchproto-recv.$$.log
LOGS=/tmp/iwan-benchproto-send.$$.log

SRV_PID=""; CLI_PID=""
RULE_VETH=0; RULE_TUN=0
FAILS=0
declare -A BASE_MAX=()      # 每个协议基线的接收侧最优值（= 发生器上限估计）

# ---------------------------------------------------------------- 基础工具

trap cleanup EXIT

# 进程存活检查：netns/veth 清不干净会让下一轮 ip link add 失败
module_loaded() { grep -q "^iwan " /proc/modules 2>/dev/null; }

# TUN 设备字节数（sysfs，netns 内也成立）：输出 "rx tx"
# 打印"尺子"自己的状态。本机实测轮间基线能差 35%+（负载 37/24 核、97°C、
# 累计降频事件 10 万+），不记下来的话速率类数字根本没法判可信度。
machine_state() {
    local load tmax=0 th=0 v f tops
    load=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)
    for f in /sys/class/thermal/thermal_zone*/temp; do
        [ -r "$f" ] || continue
        v=$(cat "$f" 2>/dev/null) || continue
        [ -n "$v" ] && [ "$v" -gt "$tmax" ] 2>/dev/null && tmax=$v
    done
    for f in /sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count; do
        [ -r "$f" ] && th=$((th + $(cat "$f" 2>/dev/null || echo 0)))
    done
    tops=$(ps -eo pcpu=,comm= --sort=-pcpu 2>/dev/null | head -3 | \
           awk '{printf " %s(%s%%)", $2, $1}')
    printf '  [机器状态] load=%s / %s 核；最热 %s°C；累计降频 %s 次；CPU 前三:%s\n' \
        "${load:-?}" "$(nproc)" "$((tmax / 1000))" "$th" "${tops:- 无}"
}

tun_bytes() {   # $1=netns(空=宿主) $2=设备
    local -a pre=()
    [ -n "$1" ] && pre=(ip netns exec "$1")
    local rx tx
    rx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/rx_bytes" 2>/dev/null)
    tx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/tx_bytes" 2>/dev/null)
    echo "${rx:-0} ${tx:-0}"
}

tun_pkts() {    # $1=netns(空=宿主) $2=设备；tx_packets = 内核交给该设备的包数
    local -a pre=()
    [ -n "$1" ] && pre=(ip netns exec "$1")
    local rx tx
    rx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/rx_packets" 2>/dev/null)
    tx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/tx_packets" 2>/dev/null)
    echo "${rx:-0} ${tx:-0}"
}

# 从 bench_proto 的输出里取字段
field() { sed -n "s/.*$2=\([0-9.]*\).*/\1/p" "$1" | head -1; }

# 字节数 → "xx.x"（MB）；只用于打印证据，不参与判据
mb() { awk -v v="${1:-0}" 'BEGIN{ printf "%.1f", v / 1e6 }'; }

# SINK=1 的证据来源：服务端每 5 秒一行 "SINK pkts=.. bytes=.. pps=.. gbps=.."
# （pkts/bytes 是累计值，pps/gbps 是这一轮的区间速率）。取最新一行，输出
# "<pkts> <bytes> <pps> <gbps>"；还没有计量行就输出空串 —— 调用方打 n/a，
# 拿不到证据既不报错也不伪造。
sink_last() {
    local re='s/^SINK pkts=\([0-9]*\) bytes=\([0-9]*\)'
    re="$re pps=\([0-9.]*\) gbps=\([0-9.]*\).*/\1 \2 \3 \4/p"
    sed -n "$re" "$WORK/server.log" 2>/dev/null | tail -1
}

# 已有计量行数：区分"这一轮没有新行"与"新行的计数没涨"（后者才可疑）。
sink_lines() {
    grep -c '^SINK pkts=' "$WORK/server.log" 2>/dev/null || true
}

# 等对端 READY（bind/listen 完成才开打，否则前若干包打在空气里，
# 还会因为 ICMP 端口不可达把 errs 顶起来）
wait_ready() {  # $1=日志 $2=秒
    local i
    for i in $(seq 1 $(( $2 * 20 ))); do
        grep -q '^READY' "$1" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# 跑一对收发。参数：proto rns bip sns tip port size label dir [时长秒]
# rns/sns 为空表示在宿主；否则是 netns 名。
measure() {
    local proto=$1 rns=$2 bip=$3 sns=$4 tip=$5 port=$6 size=$7 label=$8 dir=$9
    local dur=${10:-$DURATION}
    local -a rcmd=("$BIN"/bench_proto recv --proto "$proto" --bind "$bip"
                   --port "$port" --duration "$dur" --threads "$THREADS"
                   --size "$size")
    local -a scmd=("$BIN"/bench_proto send --proto "$proto" --target "$tip"
                   --port "$port" --duration "$dur" --threads "$THREADS"
                   --size "$size")
    [ -n "$rns" ] && rcmd=(ip netns exec "$rns" "${rcmd[@]}")
    [ -n "$sns" ] && scmd=(ip netns exec "$sns" "${scmd[@]}")

    rm -f "$LOGR" "$LOGS"
    # timeout 兜底：发生器内部已经全部改成有界等待，但 root 下万一卡住，
    # 整个基准不该陪它一起挂死（kill 之后日志里没有 RESULT，会被判失败）
    timeout $((dur + 25)) "${rcmd[@]}" >"$LOGR" 2>&1 &
    local rpid=$!
    if ! wait_ready "$LOGR" 5; then
        echo "  **接收侧没起来**：$(head -2 "$LOGR" | tr '\n' ' ')"
        kill "$rpid" 2>/dev/null; wait "$rpid" 2>/dev/null
        FAILS=$((FAILS + 1)); return 1
    fi

    # 隧道场景的独立证据：两端隧道设备计数器快照。客户端侧按方向选设备 ——
    # 内核档 s2c 必须换外层网卡，原因见 CLI_DEV_S2C 定义处。
    local cdev=$CLI_DEV
    [ "$dir" = "s2c" ] && cdev=${CLI_DEV_S2C:-$CLI_DEV}
    local ct0="" ct1="" st0="" st1="" co0="" co1="" ho0="" ho1=""
    if [ "$label" != "基线" ]; then
        ct0=$(tun_bytes "$NS" "$cdev"); st0=$(tun_bytes "" "$TUN")
        co0=$(tun_bytes "$NS" "$VETH_N_DEV"); ho0=$(tun_bytes "" "$VETH_H_DEV")
    fi

    timeout $((dur + 25)) "${scmd[@]}" >"$LOGS" 2>&1
    local src=$?
    wait "$rpid"; local rrc=$?
    sleep 0.3        # 等在途尾部包落地，再采"之后"的快照

    if [ "$label" != "基线" ]; then
        ct1=$(tun_bytes "$NS" "$cdev"); st1=$(tun_bytes "" "$TUN")
        co1=$(tun_bytes "$NS" "$VETH_N_DEV"); ho1=$(tun_bytes "" "$VETH_H_DEV")
    fi

    local tx rx txg rxg loss rpps errs bad
    tx=$(field "$LOGS" bytes); rx=$(field "$LOGR" bytes)
    tx=${tx:-0}; rx=${rx:-0}
    txg=$(field "$LOGS" gbps); rxg=$(field "$LOGR" gbps)
    rpps=$(field "$LOGR" pps); errs=$(field "$LOGS" errs); bad=$(field "$LOGR" bad)
    loss=$(awk -v a="$tx" -v b="$rx" 'BEGIN{ if(a>0) printf "%.2f", (a-b)*100.0/a; else print "100.00" }')
    local note="-"
    if [ "$label" != "基线" ]; then
        # tun_bytes 打印 "rx_bytes tx_bytes"，两个字段的含义必须分清：
        #   TUN 的 tx_bytes = 内核把包交给设备（= 隧道 app 读走）
        #   TUN 的 rx_bytes = 设备把包交给内核（= 隧道 app 注入进来）
        # 上一轮我把这两个变量名接反了，探针因此误报"流量可能没走隧道"——
        # 而真机数据恰好是对的（c2s：客户端 tx=287MB + 服务端 rx=219MB）。
        local c_tx c_rx s_tx s_rx chk
        c_rx=$(( ${ct1%% *} - ${ct0%% *} )); c_tx=$(( ${ct1##* } - ${ct0##* } ))
        s_rx=$(( ${st1%% *} - ${st0%% *} )); s_tx=$(( ${st1##* } - ${st0##* } ))
        note=$(awk -v a="$c_tx" -v b="$c_rx" -v c="$s_tx" -v d="$s_rx" \
            -v cd="$cdev" -v sd="$TUN" \
            'BEGIN{ printf "客户端[%s]tx=%.1fMB rx=%.1fMB 服务端[%s]tx=%.1fMB rx=%.1fMB", cd, a/1e6, b/1e6, sd, c/1e6, d/1e6 }')
        # c2s：客户端内核把内层包交给客户端 TUN（客户端 tx），服务端隧道再把包
        # 注入自己的 TUN（服务端 rx）；s2c 方向对调。两个计数器都必须至少覆盖
        # 接收侧收到的 payload —— 这是"真的从 TUN 过线"的硬证据。
        if [ "$dir" = "c2s" ]; then
            chk=$(awk -v a="$c_tx" -v b="$s_rx" -v rx="$rx" 'BEGIN{ print (a>=rx && b>=rx) ? "ok" : "bad" }')
        else
            chk=$(awk -v a="$s_tx" -v b="$c_rx" -v rx="$rx" 'BEGIN{ print (a>=rx && b>=rx) ? "ok" : "bad" }')
        fi
        if [ "$chk" != "ok" ]; then
            note="$note  **${cdev} 计数不覆盖接收量，流量可能没走隧道**"
            FAILS=$((FAILS + 1))
        fi
        # 外层到达计数：把"外层根本没到"和"到了但隧道那一段没跟上"分开。
        #   c2s：宿主侧 $VETH_H_DEV 的 rx = 客户端上行外层帧到达量
        #   s2c：客户端 netns 里 $VETH_N_DEV 的 rx = 服务端下行外层帧到达量
        # 内核档 s2c 的证据设备本来就是客户端外层 veth，不重复打印。
        local ho_rx co_rx
        ho_rx=$(awk -v a="${ho1:-0 0}" -v b="${ho0:-0 0}" \
            'BEGIN{ split(a,x," "); split(b,y," "); printf "%d", x[1]-y[1] }')
        co_rx=$(awk -v a="${co1:-0 0}" -v b="${co0:-0 0}" \
            'BEGIN{ split(a,x," "); split(b,y," "); printf "%d", x[1]-y[1] }')
        if [ "$dir" = "c2s" ]; then
            note="$note 外层到达[宿主${VETH_H_DEV}]rx=$(awk -v v="$ho_rx" 'BEGIN{printf "%.1f", v/1e6}')MB"
        elif [ "$cdev" != "$VETH_N_DEV" ]; then
            note="$note 外层到达[客户端${VETH_N_DEV}]rx=$(awk -v v="$co_rx" 'BEGIN{printf "%.1f", v/1e6}')MB"
        fi
        # 收到的远端地址：内层流量若从 veth 直穿，这里会写成 172.31.201.x
        # 而不是隧道地址，比只看字节数更直接
        local rem
        rem=$(field "$LOGR" remote)
        [ -n "$rem" ] && note="$note 对端=$rem"
    fi

    printf '%-8s %-4s %-4s %8.2f %8.2f %7s%% %10s  %s\n' \
        "$label" "$proto" "$dir" "${txg:-0}" "${rxg:-0}" "$loss" "${rpps:-0}" "$note"
    if [ "$rrc" != 0 ] || [ "$src" != 0 ]; then
        echo "  **收发进程退出码异常** send=$src recv=$rrc errs=${errs:-?} bad=${bad:-?}"
        FAILS=$((FAILS + 1))
    fi
    # EAGAIN 在发生器里已经被跳过、不计入 errs，所以 errs>0 都是真错误；
    # bad>0 说明收到的包里混了不是我们发的（魔术/协议号不对），数据不干净。
    if [ "${errs:-0}" != 0 ] || [ "${bad:-0}" != 0 ]; then
        echo "  **errs=$errs bad=$bad：这一行数据不可信（不是拥塞，是真错误/脏包）**"
        FAILS=$((FAILS + 1))
    fi
    # 接收侧一个包都没收到 = 根本没通，和"丢包"是两回事，单独报错
    if [ "$rx" = 0 ] && [ "$tx" != 0 ]; then
        echo "  **接收侧一个包都没收到**（发送侧已发 $tx 字节，这不是丢包而是根本没到）"
        FAILS=$((FAILS + 1))
    fi
    if [ "$label" = "基线" ] && [ "$rx" != 0 ]; then
        awk -v a="${BASE_MAX[$proto]:-0}" -v b="${rxg:-0}" 'BEGIN{ exit (b > a) ? 0 : 1 }' && \
            BASE_MAX[$proto]=${rxg:-0}
        awk -v l="$loss" 'BEGIN{ exit (l > 1.0) ? 0 : 1 }' && \
            echo "  **基线丢包 ${loss}%：发生器自己到顶了（接收侧跟不上），这行是尺子的上限不是链路的上限**"
    fi
}

# SINK=1 专用：只跑发送侧。服务端是仅计量端点（不解封装、不注入、不回送），
# 宿主侧没有内层接收方，接收列只能打 n/a —— 量到的是**客户端单侧**能把多少
# 内层流量推进隧道。独立证据两条：
#   · 客户端 TUN 的 tx 增量（内核确实把内层包交给了隧道，不是从 veth 直穿）；
#   · 服务端日志里的 SINK 计量行（这些帧到了对端且过了会话/令牌校验），
#     口径是外层 UDP 净荷（含 8B 定长首部），不是内层字节数。
# 参数：proto sns tip port size label dir [时长秒]
measure_sink() {
    local proto=$1 sns=$2 tip=$3 port=$4 size=$5 label=$6 dir=$7
    local dur=${8:-$DURATION}
    local -a scmd=("$BIN"/bench_proto send --proto "$proto" --target "$tip"
                   --port "$port" --duration "$dur" --threads "$THREADS"
                   --size "$size")
    [ -n "$sns" ] && scmd=(ip netns exec "$sns" "${scmd[@]}")

    rm -f "$LOGS"
    # 证据快照：客户端 TUN 出口计数取增量，服务端取最新计量行 + 行数
    local cdev=$CLI_DEV ct0 ct1 cp0 cp1 s0 s1 n0 n1
    ct0=$(tun_bytes "$NS" "$cdev")
    cp0=$(tun_pkts "$NS" "$cdev")
    s0=$(sink_last); n0=$(sink_lines)

    timeout $((dur + 25)) "${scmd[@]}" >"$LOGS" 2>&1
    local src=$?
    sleep 0.3        # 等在途尾部包落进服务端计量
    ct1=$(tun_bytes "$NS" "$cdev")
    cp1=$(tun_pkts "$NS" "$cdev")
    s1=$(sink_last); n1=$(sink_lines)

    local tx txg errs c_tx
    tx=$(field "$LOGS" bytes); tx=${tx:-0}
    txg=$(field "$LOGS" gbps); errs=$(field "$LOGS" errs)
    c_tx=$(( ${ct1##* } - ${ct0##* } ))   # 第二列是 tx_bytes（见 tun_bytes）
    # 客户端自己出站的内层包数/包率：TUN 档 = 用户态中继从 TUN 抽走的速率，
    # 内核档 = 模块 ndo_start_xmit 的包率。它与计量端点的接收能力无关，
    # 因此是"客户端单侧每包处理能力"的权威数字。
    local c_pkts c_pps c_gbps
    c_pkts=$(( ${cp1##* } - ${cp0##* } ))
    c_pps=$(awk -v n="$c_pkts" -v d="$dur" 'BEGIN{ printf "%.0f", (d>0)? n/d : 0 }')
    c_gbps=$(awk -v b="$c_tx" -v d="$dur" 'BEGIN{ printf "%.2f", (d>0)? b*8/d/1e9 : 0 }')

    local note rcv_pps="" loss=n/a
    note=$(awk -v d="$cdev" -v v="$tx" -v w="$c_tx" 'BEGIN{ printf \
        "发送=%.1fMB(负载) 客户端[%s]tx=%.1fMB(内层)", v/1e6, d, w/1e6 }')
    if [ -z "$s1" ]; then
        note="$note 服务端SINK=n/a（还没有计量行）"
    else
        local sp sb spps sgbps op ob
        read -r sp sb spps sgbps <<<"$s1"
        rcv_pps=$spps
        note="$note 服务端SINK最新行 pkts=$sp bytes=$(mb "$sb")MB"
        note="$note pps=$spps gbps=$sgbps"
        if [ -n "$s0" ] && [ "$n1" -gt "$n0" ]; then
            read -r op ob _ _ <<<"$s0"
            note="$note 本轮Δpkts=$((sp - op)) Δbytes=$(mb "$((sb - ob))")MB"
            # 有新行却一字节没涨：上行帧可能没到对端/没过校验。只提示不判失败
            # —— 5 秒一行的节奏下，行尾的包本来就可能还没进最新一行。
            if [ "$sb" = "$ob" ] && [ "$tx" != 0 ]; then
                echo "  注意：服务端计量行本轮没有增长，本行上行帧可能没被计到"
            fi
        else
            note="$note 本轮Δ=n/a（窗口内没有新的计量行）"
        fi
    fi
    # 计量/出站包比：<1 说明客户端发出去的包没有全部被计量端点收到 —— 要么在
    # 宿主接收路径上被丢，要么计量端点自己就是瓶颈。它决定"限速项在客户端还是
    # 在测量链路上"，是这轮内核档最需要看的旁证。
    if [ -n "$rcv_pps" ] && [ "${c_pps:-0}" != 0 ]; then
        note="$note 计量/出站包比=$(awk -v a="$rcv_pps" -v b="$c_pps" 'BEGIN{ printf "%.3f", a/b }')"
    fi
    note="$note 客户端出站=$c_pkts 包(内层) pps=$c_pps 口径=外层UDP净荷含8B首部"

    # SINK 行的接收列就是计量端点的实测值：接收Gbps/收pps 取自它的 5 秒窗口行，
    # 丢包列是"发出 vs 计到"的过载比（隧道不向应用传播背压 ⇒ 差额在端点队列被丢）。
    if [ "${txg:-0}" != 0 ]; then
        loss=$(awk -v s="$txg" -v r="$c_gbps" 'BEGIN{ printf "%.2f%%", (s-r)/s*100 }')
    fi
    # SINK 行一律按客户端单侧口径报：接收Gbps/收pps = 客户端隧道设备自己的出口
    # 计数增量（内层），丢包 = 发出 vs 进隧道 的过载比；计量端点的数字放在证据列
    # 做旁证（它自己也可能成为瓶颈，不能当主指标）。
    printf '%-8s %-4s %-4s %8.2f %8s %8s %10s  %s\n' \
        "$label" "$proto" "$dir" "${txg:-0}" "$c_gbps" "$loss" "${c_pps:-0}" "$note"
    if [ "$src" != 0 ]; then
        echo "  **发送进程退出码异常** send=$src errs=${errs:-?}"
        FAILS=$((FAILS + 1))
    fi
    if [ "${errs:-0}" != 0 ]; then
        echo "  **errs=$errs：这一行数据不可信（不是拥塞，是真错误/脏包）**"
        FAILS=$((FAILS + 1))
    fi
    if [ "$tx" = 0 ]; then
        echo "  **发送侧一个包都没发出去**（路由没生效，或时长内全在等缓冲）"
        FAILS=$((FAILS + 1))
    fi
}

# ---------------------------------------------------------------- 前置检查

[ "$(id -u)" = 0 ] || die "需要 root（TUN 设备、netns、raw socket），用 sudo 跑"

echo "== 构建 =="
if [ "$BIN" = "./bin" ]; then
    cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON >/dev/null || die "cmake 配置失败"
    cmake --build build -j"$(nproc)" >/dev/null || die "构建失败"
else
    echo "  跳过构建（BIN=$BIN：用外部构建目录的产物）"
fi
# 显式确认产物：CMake 的"成功"不等于目标真的建出来了（本仓库 CMakeLists
# 里就记着 cmake --install 静默成功的坑），必须有这一道
for b in bench_proto iwan-client iwan-server; do
    [ -x "$BIN/$b" ] || die "$BIN/$b 不存在 —— -DBUILD_TESTING=ON 没生效？删掉 build/ 重来"
done

# 模块加载状态与档位的关系：
#   · 默认档（TUN 数据面）在模块已加载时拒绝运行：iwan_outer_match 只比外层
#     地址，而内核钩子与 TUN 客户端走的是同一条外层四元组，钩子会把 TUN 客户端
#     的下行帧截走，量出来的"容量"是假的。
#   · KERNEL=1 档要求模块已加载且有 /dev/iwan。钩子是 nf_register_net_hook(
#     客户端所在 netns) 注册的，只在本脚本自己建的 netns 里生效 —— 碰不到
#     别的 netns 里正在使用的隧道。
if module_loaded; then
    if [ "$SINK" = 1 ] && [ "$KERNEL" != 1 ]; then
        # SINK=1 的客户端是 TUN 数据面：钩子会截走服务端的控制面回包
        # （OPEN_ACK/keepalive），会话根本起不来，量不出东西。
        # KERNEL=1 时相反 —— 客户端就是内核数据面，模块必须已加载。
        echo "error: iwan 内核模块已加载：SINK=1 用的还是 TUN 客户端，钩子会抢同一条外层四元组" >&2
        echo "       先 sudo rmmod iwan，再：sudo env SINK=1 bash $0" >&2
        exit 1
    fi
    if [ "$KERNEL" != 1 ]; then
        echo "error: iwan 内核模块已加载（dport/sport/sid/tok = $(cat /sys/module/iwan/parameters/dport 2>/dev/null)/$(cat /sys/module/iwan/parameters/sport 2>/dev/null)/$(cat /sys/module/iwan/parameters/sid 2>/dev/null)/$(cat /sys/module/iwan/parameters/tok 2>/dev/null)）" >&2
        echo "       默认档走 TUN 数据面，与内核钩子共用同一条外层四元组，会互相抢包。" >&2
        echo "       要跑内核数据面对照：sudo env KERNEL=1 bash tests/bench_proto.sh" >&2
        echo "       只跑 TUN 档：先 sudo rmmod iwan（模块没加载时 rmmod 会失败，别用 && 串），再：" >&2
        echo "         sudo env BIN=$BIN VETH_MTU=$VETH_MTU CLI_MTU=${CLI_MTU:-} bash $0" >&2
        exit 1
    fi
    [ -c /dev/iwan ] || { echo "error: 模块已加载但没有 /dev/iwan（模块与客户端不是同批构建？）" >&2; exit 1; }
else
    [ "$KERNEL" = 1 ] && {
        echo "error: KERNEL=1 需要 iwan 模块已加载：sudo insmod kernel/iwan.ko" >&2
        echo "       模块无参数加载即可（默认 enabled=true，会话由客户端 SESSION_UP 建立）" >&2
        exit 1
    }
fi

echo "== 预清理上一轮残留 =="
pkill -9 -x bench_proto 2>/dev/null
pkill -9 -f "bin/iwan-client proxy .*--port $PORT" 2>/dev/null
pkill -9 -f "bin/iwan-server .*--port $PORT" 2>/dev/null
sleep 0.3
ip netns del "$NS" 2>/dev/null
ip link del "$VETH_H_DEV" 2>/dev/null

printf 'test:s3cret\n' > "$WORK/users.txt"
chmod 600 "$WORK/users.txt"

DISC="内层 ${SIZE_UDP}B UDP / ${SIZE_RAW}B 裸 IP（负载 $((SIZE_RAW - 20))B）/ TCP 写块 ${SIZE_TCP}B；${THREADS} 线程；每档 ${DURATION}s 单向饱和打流"
echo "== 口径：$DISC =="
# 回程路由是可选特性（--reply-via-tunnel），本脚本一律不用 ⇒ 取数里既不装
# CONNMARK 规则、也没有 fwmark 策略路由表，conntrack 与策略路由的开销为 0。
echo "口径（固定）：回程路由/conntrack = 关（未使用 --reply-via-tunnel；不装 CONNMARK 规则与 fwmark 策略路由）"
if [ "$SINK" = 1 ]; then
    echo "口径（SINK=1）：只量客户端单侧承载能力；服务端不解封装、不注入、不回送" \
         "⇒ 无 TCP、无 s2c"
    if [ "$KERNEL" = 1 ]; then
        echo "口径（SINK=1 + KERNEL=1）：客户端走内核数据面 $KERNEL_DEV，只跑 raw 的 c2s；" \
             "主指标 = 服务端计量行的 pps（每包处理成本与报文字节数无关）；" \
             "内层字节数由 $KERNEL_DEV 的 tx_bytes 增量给出"
    fi
fi
machine_state
printf '%-8s %-4s %-4s %8s %8s %8s %10s  %s\n' 场景 协议 方向 发送Gbps 接收Gbps 丢包 收pps 证据
printf '%s\n' "----------------------------------------------------------------------------------------------------"

# ---------------------------------------------------------------- 场景 1：基线

if [ "$SKIP_BASELINE" != 1 ]; then
    for proto in $PROTO_LIST; do
        case $proto in
            tcp) size=$SIZE_TCP; port=$P_TCP ;;
            udp) size=$SIZE_UDP; port=$P_UDP ;;
            raw) size=$SIZE_RAW; port=$P_RAW ;;
        esac
        if [ "$SINK" = 1 ]; then
            # SINK=1 的输出里不留 tcp/s2c 行：基线也只跑 udp/raw 的 c2s，
            # 留作"发生器上限"的尺子（基线走 lo，与服务端无关）
            [ "$proto" = tcp ] && continue
            [ "$KERNEL" = 1 ] && [ "$proto" != raw ] && continue
            want_dir c2s && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" 基线 c2s
        else
            # 同机基线两个方向在物理上是对称的，仍分 c2s/s2c 报，方便与隧道行对齐
            want_dir c2s && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" 基线 c2s
            want_dir s2c && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" 基线 s2c
        fi
    done
    if [ "$SINK" = 1 ]; then
        echo "  发生器上限（udp/raw 基线接收侧最优值）：udp ${BASE_MAX[udp]:-?}" \
             "/ raw ${BASE_MAX[raw]:-?} Gbps"
        echo "  注意口径：udp/raw 两档是**发生器**先到顶（单机收包循环）" \
             "—— SINK=1 只跟同日同参数的这两行比。"
    else
        echo "  发生器上限（各协议基线接收侧最优值）：tcp ${BASE_MAX[tcp]:-?} / udp ${BASE_MAX[udp]:-?} / raw ${BASE_MAX[raw]:-?} Gbps"
        echo "  注意口径：udp/raw 这两档是**发生器**先到顶（单机收包循环），lo 本身容量远高于此（看 tcp 行）；"
        echo "          所以隧道行只能跟**同日同参数**的基线行比，不能拿 udp 隧道数字去比 tcp 基线。"
    fi
fi

if [ "$SKIP_TUNNEL" = 1 ]; then
    echo "  已跳过隧道与内核档（SKIP_TUNNEL=1）"
    if [ "$FAILS" = 0 ]; then echo "BENCH DONE（只跑基线）"; else echo "BENCH FAILED：$FAILS 处异常" >&2; fi
    exit $(( FAILS > 0 ? 1 : 0 ))
fi

# ---------------------------------------------------------------- 场景 2：隧道

machine_state
if [ "$SINK" = 1 ]; then
    echo "== 启动 iwan-server（仅计量接收端点 IWAN_SRV_SINK=1，不建 TUN）=="
else
    echo "== 启动 iwan-server（用户态 TUN）=="
fi
"${SRV_ENV[@]}" stdbuf -oL -eL "$BIN"/iwan-server --users "$WORK/users.txt" \
    --port "$PORT" --tun "$TUN" --server-ip "$SRV_IP" --subnet "$SUBNET" \
    --dns 114.114.114.114 --nat-if lo >"$WORK/server.log" 2>&1 &
SRV_PID=$!
if [ "$SINK" = 1 ]; then
    # 计量端点不建 TUN：就绪判据换成它自己打印的模式行（iwan_server.c 的
    # "sink mode: metering only ..."）；服务端 TUN 的地址与 INPUT 规则都不存在
    for _ in $(seq 1 40); do
        kill -0 "$SRV_PID" 2>/dev/null || { echo "error: iwan-server 退出："; tail -5 "$WORK/server.log"; exit 1; }
        grep -q '^sink mode: metering only' "$WORK/server.log" && break
        sleep 0.25
    done
    grep -q '^sink mode: metering only' "$WORK/server.log" || \
        die "服务端没进 sink 模式（日志：$WORK/server.log）"
else
    for _ in $(seq 1 40); do
        grep -q "$SRV_IP" <(ip -4 -o addr show dev "$TUN" 2>/dev/null) && break
        kill -0 "$SRV_PID" 2>/dev/null || { echo "error: iwan-server 退出："; tail -5 "$WORK/server.log"; exit 1; }
        sleep 0.25
    done
    ip -4 -o addr show dev "$TUN" 2>/dev/null | grep -q "$SRV_IP" || die "服务端 TUN 没起来"
    iptables -C INPUT -i "$TUN" -j ACCEPT 2>/dev/null || { iptables -I INPUT -i "$TUN" -j ACCEPT 2>/dev/null && RULE_TUN=1; }
fi

echo "== 建 netns + veth，起 TUN 客户端 =="
# 上一轮被 Ctrl-C / panic / 脚本中途退出打断时，/run/netns/$NS 会残留
# （`ip netns list` 里显示为 (id: 0)），此时 ip netns add 以 "File exists"
# 失败 —— 2026-10-11 实测踩到过。先按名字删一次；名字删不动就当成挂载残留
# 卸载并删除那个具体文件（只碰 $NS 这一个路径），仍失败才报错。
if ! ip netns add "$NS" 2>/dev/null; then
    echo "警告: ip netns add $NS 失败（残留？）—— 先 ip netns del 再试" >&2
    ip netns del "$NS" 2>/dev/null
    if [ -e "/run/netns/$NS" ]; then
        umount "/run/netns/$NS" 2>/dev/null
        rm -f "/run/netns/$NS" 2>/dev/null
    fi
    ip netns add "$NS" || die "ip netns add 失败"
fi
ip link add "$VETH_H_DEV" type veth peer name "$VETH_N_DEV" || die "建 veth 失败"
ip link set "$VETH_H_DEV" mtu "$VETH_MTU" || die "设 $VETH_H_DEV MTU 失败"
ip link set "$VETH_N_DEV" mtu "$VETH_MTU" || die "设 $VETH_N_DEV MTU 失败"
ip link set "$VETH_N_DEV" netns "$NS"
ip addr add "$VETH_H/24" dev "$VETH_H_DEV"
ip link set "$VETH_H_DEV" up
ip netns exec "$NS" ip addr add "$VETH_N/24" dev "$VETH_N_DEV"
ip netns exec "$NS" ip link set "$VETH_N_DEV" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$VETH_H"
echo "  口径：外层 ${VETH_H_DEV}/${VETH_N_DEV} MTU=${VETH_MTU}；隧道内层 MTU=${CLI_MTU:-编译期默认}"
iptables -C INPUT -i "$VETH_H_DEV" -j ACCEPT 2>/dev/null || { iptables -I INPUT -i "$VETH_H_DEV" -j ACCEPT 2>/dev/null && RULE_VETH=1; }

# KERNEL_ONLY=1：netns/veth/服务端/iptables 规则保留（内核档直接复用），
# 跳过 TUN 客户端启动、拓扑探针与 TUN 档全部行。CLI_PID 先置空（set -u）。
CLI_PID=""
if [ "$KERNEL_ONLY" != 1 ]; then
ip netns exec "$NS" stdbuf -oL -eL "$BIN"/iwan-client proxy \
    --server "$VETH_H" --port "$PORT" --user test --pass s3cret \
    --tun "$TUN_CLI" --proxy-cidr "$SUBNET" "${MTU_ARG[@]}" >"$WORK/client.log" 2>&1 &
CLI_PID=$!
# 等隧道路由：路由没出来就开打，流量会从 veth 直穿，报出同机链路的几十 Gbps
for _ in $(seq 1 40); do
    kill -0 "$CLI_PID" 2>/dev/null || { echo "error: 客户端退出："; tail -5 "$WORK/client.log"; exit 1; }
    ip netns exec "$NS" ip route show 2>/dev/null | grep -q "$SUBNET" && break
    sleep 0.25
done
ip netns exec "$NS" ip route show 2>/dev/null | grep -q "$SUBNET" || die "隧道路由没建立"
CLI_IP=$(ip netns exec "$NS" ip -4 -o addr show dev "$TUN_CLI" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "$CLI_IP" ] || die "拿不到客户端隧道地址"
CLI_DEV=$TUN_CLI
if [ "$SINK" = 1 ]; then
    # 宿主到客户端隧道地址的路由由服务端 TUN 提供，SINK=1 没有 TUN：这条
    # 检查不成立（也不该因此 die），宿主侧到 $CLI_IP 的可达性打 n/a
    echo "  隧道路由就绪：客户端隧道地址 $CLI_IP（宿主经 $TUN 可达 n/a" \
         "—— SINK=1 无服务端 TUN；证据设备 $CLI_DEV）"
else
    # s2c 方向要宿主自己把包送进服务端 TUN：没有这条路由，包会走默认路由出去，
    # 表现为"两边计数都是 0"，很难第一眼看懂
    ip route get "$CLI_IP" 2>/dev/null | grep -q "dev $TUN" || \
        die "宿主没有经 $TUN 到 $CLI_IP 的路由：$(ip route get "$CLI_IP" 2>&1 | head -1)"
    echo "  隧道路由就绪：客户端隧道地址 $CLI_IP（宿主经 $TUN 可达，证据设备 $CLI_DEV）"
fi

if [ "$SINK" = 1 ]; then
    echo "== 探针：c2s 1 秒（服务端只回控制面，靠客户端 TUN 与 SINK 计量行确认上行）=="
else
    echo "== 探针：两个方向各 1 秒，先确认拓扑真的通 =="
fi
FAILS_BEFORE=$FAILS
if [ "$SINK" = 1 ]; then
    measure_sink udp "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" 探针 c2s 1
else
    measure udp "" "$SRV_IP" "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" 探针 c2s 1
    measure udp "$NS" "$CLI_IP" "" "$CLI_IP" "$P_UDP" "$SIZE_UDP" 探针 s2c 1
fi
# 只看探针自己新增的失败：基线段的失败（例如没 root 时的 raw 档）与拓扑无关
if [ "$FAILS" != "$FAILS_BEFORE" ]; then
    if [ "$SINK" = 1 ]; then
        echo "error: 探针就失败了，先修拓扑再看全量数字（完整日志：$LOGS）" >&2
    else
        echo "error: 探针就失败了，先修拓扑再看全量数字（完整日志：$LOGR / $LOGS）" >&2
    fi
    exit 1
fi

for proto in $PROTO_LIST; do
    case $proto in
        tcp) size=$SIZE_TCP; port=$P_TCP ;;
        udp) size=$SIZE_UDP; port=$P_UDP ;;
        raw) size=$SIZE_RAW; port=$P_RAW ;;
    esac
    if [ "$SINK" = 1 ]; then
        # 计数端点不回 ACK、不注入、不回送：只有 c2s 的 udp/raw 两档成立
        [ "$proto" = tcp ] && continue
        measure_sink "$proto" "$NS" "$SRV_IP" "$port" "$size" SINK c2s
    else
        # c2s：netns 里发 → 宿主上的服务端 TUN 入口收
        want_dir c2s && \
        measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" 隧道 c2s
        # s2c：宿主发 → netns 里收（目标地址由服务端分配）
        want_dir s2c && \
        measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" 隧道 s2c
    fi
done
fi   # KERNEL_ONLY=1：上面整段（TUN 客户端 + 拓扑探针 + TUN 档行）跳过

# ---------------------------------------------------------------- 场景 3：内核数据面

if [ "$KERNEL" = 1 ]; then
    echo
    machine_state
    echo "== 切换到内核数据面（客户端 --data-plane kernel，设备 $KERNEL_DEV）=="
    # 必须先把 TUN 客户端停干净：两者的外层四元组完全相同，而 iwan_outer_match
    # 只比外层地址 —— 同时存在时内核钩子会把 TUN 客户端的下行帧截走，数字必假。
    # SIGINT 让它优雅退出，模块收到 SESSION_DOWN 才回收会话与 iwan0。
    if [ -n "$CLI_PID" ]; then
        kill -INT "$CLI_PID" 2>/dev/null
        for _ in $(seq 1 30); do kill -0 "$CLI_PID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$CLI_PID" 2>/dev/null
        wait "$CLI_PID" 2>/dev/null
        CLI_PID=""
    fi
    sleep 0.5

    ip netns exec "$NS" stdbuf -oL -eL "$BIN"/iwan-client proxy \
        --server "$VETH_H" --port "$PORT" --user test --pass s3cret \
        --data-plane kernel --tun "$KERNEL_DEV" \
        --proxy-cidr "$SUBNET" "${MTU_ARG[@]}" >"$WORK/client-kernel.log" 2>&1 &
    CLI_PID=$!
    # 内核档不建 TUN：iwan0 由模块在 SESSION_UP 时按需创建，地址由客户端按
    # 回执里的 DEVNAME 配置（与 route_setup 同一套代码）。
    for _ in $(seq 1 60); do
        kill -0 "$CLI_PID" 2>/dev/null || { echo "error: 内核档客户端退出："; tail -5 "$WORK/client-kernel.log"; exit 1; }
        ip netns exec "$NS" ip -4 -o addr show dev "$KERNEL_DEV" 2>/dev/null | grep -q "inet " && break
        sleep 0.25
    done
    CLI_IP=$(ip netns exec "$NS" ip -4 -o addr show dev "$KERNEL_DEV" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$CLI_IP" ] || die "内核档 $KERNEL_DEV 没拿到地址：$(tail -3 "$WORK/client-kernel.log")"
    # s2c 同样要求宿主经服务端 TUN 可达新地址（服务端可能分配了另一个地址）
    if [ "$SINK" = 1 ]; then
        # 这条检查只为 s2c 服务：宿主得经服务端 TUN 把包送回客户端。SINK 模式
        # 没有服务端 TUN，s2c 物理上也不成立（服务端不回送）。
        echo "  宿主到 $CLI_IP 的路由：n/a（SINK=1 无服务端 TUN）"
    else
        ip route get "$CLI_IP" 2>/dev/null | grep -q "dev $TUN" || \
            die "宿主没有经 $TUN 到 $CLI_IP 的路由：$(ip route get "$CLI_IP" 2>&1 | head -1)"
    fi
    # 证据设备换成 iwan0，sysfs 语义与 TUN 相同：出站（内核在 ndo_start_xmit 里
    # 交给模块）计 tx_bytes，入站（模块解封后注入协议栈）计 rx_bytes。
    CLI_DEV=$KERNEL_DEV
    # 出站走 netdev（模块在 ndo_start_xmit 里累加 dev->stats.tx_bytes）→ 可用；
    # 入站不经 netdev → iwan0 的 rx_bytes 恒为 0，s2c 证据换外层 veth 到达计数
    CLI_DEV_S2C=$VETH_N_DEV
    # 不用 ip -d 的 kind：iproute2 对模块建的设备会把 kind 打成 link/ipip 之类
    # （e2e 脚本里踩过），mtu/state 才是可靠且真正要看的（mtu 决定内层能多大）
    echo "  内核档就绪：$KERNEL_DEV 地址 $CLI_IP，$(ip netns exec "$NS" ip -o link show dev "$KERNEL_DEV" 2>/dev/null | sed -n 's/.*<\([^>]*\)>.*mtu \([0-9]*\).*/flags=\1 mtu=\2/p' | head -1)"

    echo "  模块参数：$(for _p in reinject batch hooknum hookprio max_mtu; do printf '%s=%s ' "$_p" "$(cat "/sys/module/iwan/parameters/$_p" 2>/dev/null || echo '?')"; done)"

    if [ "$SINK" = 1 ]; then
        echo "== 内核档探针：c2s 1 秒（SINK=1 无 s2c：服务端不注入、不回送）=="
        FAILS_BEFORE=$FAILS
        measure_sink udp "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" 内核 c2s 1
        if [ "$FAILS" != "$FAILS_BEFORE" ]; then
            echo "error: 内核档探针就失败了，先修拓扑（完整日志：$LOGS）" >&2
            exit 1
        fi
        # 只测 raw 的 c2s：内核发送路径的 pps 是主指标
        measure_sink raw "$NS" "$SRV_IP" "$P_RAW" "$SIZE_RAW" 内核 c2s
    else
        echo "== 内核档探针：两个方向各 1 秒 =="
        FAILS_BEFORE=$FAILS
        measure udp "" "$SRV_IP" "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" 内核 c2s 1
        measure udp "$NS" "$CLI_IP" "" "$CLI_IP" "$P_UDP" "$SIZE_UDP" 内核 s2c 1
        if [ "$FAILS" != "$FAILS_BEFORE" ]; then
            echo "error: 内核档探针就失败了，先修拓扑（完整日志：$LOGR / $LOGS）" >&2
            exit 1
        fi

        for proto in $PROTO_LIST; do
            case $proto in
                tcp) size=$SIZE_TCP; port=$P_TCP ;;
                udp) size=$SIZE_UDP; port=$P_UDP ;;
                raw) size=$SIZE_RAW; port=$P_RAW ;;
            esac
            want_dir c2s && \
            measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" 内核 c2s
            want_dir s2c && \
            measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" 内核 s2c
        done

        # REINJECT_SWEEP="0 1"：**同一轮内**重跑内核档，只切模块参数 reinject。
        # 为什么必须在同一轮：发生器上限本身在漂（同日实测 udp 8.12 -> 10.90 Gbps），
        # 分两轮跑出来的差会被这个漂移淹没。场景列写 内核rj<值>，直接对比。
        if [ -n "${REINJECT_SWEEP:-}" ]; then
            RJ_PATH=/sys/module/iwan/parameters/reinject
            if [ ! -w "$RJ_PATH" ]; then
                echo "警告: $RJ_PATH 不可写（模块没加载？）—— 跳过 REINJECT_SWEEP" >&2
            else
                RJ_ORIG=$(cat "$RJ_PATH" 2>/dev/null)
                for rj in $REINJECT_SWEEP; do
                    if ! echo "$rj" > "$RJ_PATH" 2>/dev/null; then
                        echo "警告: 写 reinject=$rj 失败，跳过" >&2
                        continue
                    fi
                    echo "== 内核档复测：reinject=$rj（拓扑/服务端/发生器全不变）=="
                    for proto in $PROTO_LIST; do
                        case $proto in
                            tcp) size=$SIZE_TCP; port=$P_TCP ;;
                            udp) size=$SIZE_UDP; port=$P_UDP ;;
                            raw) size=$SIZE_RAW; port=$P_RAW ;;
                        esac
                        want_dir c2s && \
                        measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" "内核rj$rj" c2s
                        want_dir s2c && \
                        measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" "内核rj$rj" s2c
                    done
                done
                echo "$RJ_ORIG" > "$RJ_PATH" 2>/dev/null
                echo "  已把 reinject 还原为 ${RJ_ORIG:-?}"
            fi
        fi
    fi
fi

echo "----------------------------------------------------------------------------------------------------"
if [ "$FAILS" = 0 ]; then
    if [ "$SINK" = 1 ] && [ "$KERNEL" = 1 ]; then
        echo "BENCH DONE（SINK=1 + KERNEL=1：只量客户端内核数据面单侧 raw c2s；" \
             "主指标=服务端计量行 pps；证据=$KERNEL_DEV 的 tx_bytes 增量 + 计量行）"
    elif [ "$SINK" = 1 ]; then
        echo "BENCH DONE（SINK=1：只量客户端单侧 c2s；证据=客户端 TUN 出口计数 + 服务端计量行）"
    elif [ "$KERNEL" = 1 ]; then
        echo "BENCH DONE（全部档位收发正常；TUN 档与内核档的设备计数证据都成立）"
    else
        echo "BENCH DONE（全部档位收发正常，非基线档位的设备计数证据成立）"
    fi
else
    echo "BENCH FAILED：$FAILS 处异常，见上面带 ** 的行" >&2
fi
exit $(( FAILS > 0 ? 1 : 0 ))
