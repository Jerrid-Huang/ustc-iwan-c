#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# iWAN 客户端内核数据面（--data-plane kernel）端到端验收 —— 需要 root
#
#   sudo bash docs/kernel-data-plane-e2e.sh [--keep] [--extra] [--bind] [--life]
#
# --bind 追加 B 组：承载网卡绑定的三模式走**真网卡**（genetlink SESSION_UP 带
#   IWAN_A_OIF / IWAN_A_IP），验证点与 tests/vm_bind.sh（/proc 回落路径）互补
#   —— 这里跑的是客户端实际使用的控制面入口：
#   B1 --bind-ip <本端外层地址>   ⇒ 会话建立时由地址表解析并钉住 veth-c，
#      内层 TCP echo 仍往返一致（绑定的卡上真的能过流量）；
#   B2 --bind-dev <本端网卡>      ⇒ oif 与 carrier 都是它；
#   B3 --bind-ip <非本机地址>     ⇒ 启动即拒绝（用户态先拦住）；
#   B4 --bind-dev lo --bind-ip <本端地址> ⇒ 拒绝（地址不在指定网卡上）；
#   B5 --bind-* 与 TUN 数据面同用 ⇒ 拒绝（不给"静默忽略"的选项）。
#
# --life 追加 L 组：**有真服务器时**的失效与恢复（前面各组只覆盖"建立 → 跑稳
#   → 正常收尾"；这一组才是 1 秒节拍与重连循环的实测）：
#   L1 --bind-dev：把绑定的网卡 down ⇒ 客户端在节拍内报"绑定失效"并关闭内核
#      部分（SESSION_DOWN：sid 归零、iwan0 被删 ⇒ 经 iwan0 的路由随之失效，
#       内层流量交路由表下一条）；网卡 up ⇒ 等绑定恢复后**重新握手**，
#       内层 TCP 恢复；
#   L2 --bind-ip：删掉绑定的出口 IP ⇒ 同上停用；地址配回来 ⇒ 重新握手、
#       内层 TCP 恢复；
#   L3 外层链路断（不涉及绑定）⇒ 判死只能来自"无人应答"预算（keepalive
#       发送每次都失败）⇒ 链路回来 ⇒ 重新握手、内层 TCP 恢复；
#   L4 服务端端口黑洞（只收不回：send 全部成功、没有任何回帧）⇒ 失败预算
#       涨不起来，判死只能来自 IWAN_RX_STALE_MS 看门狗（用例设 30s）⇒ 断言
#       "看门狗判死"且"没有 keepalive 失败" ⇒ 两条机制被分开测；
#   L5 TUN 数据面（显式 --data-plane tun）同样场景（服务端消失）⇒ 判死来自接收侧
#       硬错误计数的同一条预算，服务端回来 ⇒ 重连、内层 TCP 恢复。
#
#   两条判死机制的口径（2026-10-10 实测后修正，见 src/common/proxy.h）：预算
#   统计"无人应答的失败"，**只有收到过门限的有效帧才清零**（成功的 send 不算
#   —— 连通 UDP 套接字把 ICMP 错误隔次上报，中间那次 send 会成功）；看门狗
#   是外层兜底，负责"收得下但一个都不回"的黑洞情形。
#
# 与 kernel/tests/netlink_test.sh 的分工：那份只验模块自己的控制面；这份验
# **真客户端**（iwan-client --data-plane kernel）和**真服务端**（iwan-server，
# 用户态 TUN 转发）在内核数据面上互通 —— 客户端 netns 里由 iwan-client 自己
# SESSION_UP，模块建 iwan0 并把下行帧交给它；服务端 netns 里**没有** netlink
# 会话，模块走"无会话回落"（等于引入控制面之前的行为），所以 iwan-server 的
# 用户态 UDP socket 正常收发。
#
# 拓扑（外层用 veth 当网线，绝不在 init netns 里下发真实外层五元组）：
#
#   iwc: veth-c 10.100.0.1/24   iwan0 = 模块按需创建，mtu 1400，
#                               地址 = OPEN_ACK 回执里的 tun ip（198.18.0.x/24）
#   iws: veth-s 10.100.0.2/24   iwan-srv = iwan-server 自己的 TUN（198.18.0.1/16）
#
#   iwc 内层 TCP 198.18.0.x -> 198.18.0.1:19099（iws 里的 python3 echo）
#   外层     10.100.0.1:<随机> -> 10.100.0.2:16200
#
# 用例与**预期输出**（全部打印 PASS/FAIL，退出码 = FAIL 数）：
#
#   C1  模块加载后 /dev/iwan 存在；两端都没有 iwan0（配置只能来自 netlink）
#   C2  iwan-server 起来：日志出现 "server ready."，iwan-srv 是 tun 设备
#   C3  客户端起来：日志出现 "内核数据面: 会话已建立 dev=iwan0 mtu=1400"，
#       随后 "kernel data plane running (dev iwan0)"
#   C4  iwc 的 iwan0：kind=iwan、state UP、mtu=1400、地址 == 服务端回执的 ip
#   C5  iws 没有 iwan0（服务端没有内核会话，只有自己的 iwan-srv）
#   C6  内层 TCP echo（iwc -> iws 的 198.18.0.1:19099）回显一致
#   C7  /dev/iwan dump：version=1、enabled=1、last_rx_ms 非 0（收到过对端帧）
#   C8  iwan_ctl get-stats：sid/tok 与客户端日志一致，rx_frames 增长（内层包
#       真的从内核数据面走）
#   C9  Ctrl-C 退出：客户端 rc=0，且打印 "kernel data plane stopped (user stop)"
#   C10 退出后 iwan0 已删除、get-stats 会话清零（sid=0 tok=0）、默认路由与
#       iwc 路由表没有残留（没有 --proxy-cidr，不该动默认路由）；
#       C10e：服务端日志出现 "[peer] session 0x…. closed" —— PT_CLOSE 真的过了线
#
#   --extra（可选，单列，便于排查）：
#   E1  iwan0 被别的设备占用（dummy）：客户端必须报
#       "已存在，但不是 iwan 内核模块创建的设备" 并以非零码退出，dummy 不动
#   E2  SIGKILL 残留（已知回归）：设备/会话仍在；用 iwan_ctl session-down 清理
#   E3  外部删除 iwan0：客户端 2s 内报"设备 iwan0 被外部删除"并重建
#
#   --plane（可选）：默认数据面 + 回退 + "本 netns 已有活会话"的握手前拒绝
#   P1  不给 --data-plane（默认 auto）：日志"数据面: 默认 kernel"，真走内核面，
#       iwan0 由模块建出，内层 echo 通
#   P2  内核面不可用（iwan0 被 dummy 占）⇒ 自动回退 TUN（--tun iwan9）：内核面
#       原因已报出、回退日志出现、TUN 面起来、内层 echo 仍通
#   P3  两个面都不可用（iwan0 被 dummy 占且不给替代设备名）⇒ 非零退出，日志同时
#       有"自动回退到 TUN 数据面"与 TUN 的名字被拒文本（不再是误导性的
#       "must be root"），最后"TUN 数据面也不可用，退出"
#   P4  本 netns 已有活会话时，第二条客户端（不指定数据面）在**握手之前**被拒：
#       日志有"本 netns 已有一条活会话"，且没有"会话已建立"（证明没握手），
#       并明确"不回退 TUN"；第一条会话 sid 不变、echo 仍通
#   P6  外层 IPv6（切片 2）：客户端按 --server 的**字面量地址族**自动选外层，
#       服务端同一端口同时监听 v4/v6：
#       P6a 内核面用 --server [v6] 建会话；P6b 日志声明外层 v6 端点；
#       P6c 服务端日志有 v6 监听行；P6d 内核里确有会话；
#       P6e 内层 v4 经外层 v6 真往返（跨版本 -> netif_rx 重新入栈）；
#       P6f/P6g 内层 v6 经外层 v6 真往返（同版本 -> 原地投递）；
#       P6h/P6i 内层 MTU + v6 封装超过承载 MTU 被拒（外层 v6 不分片）；
#       P6j v4/v6 两对地址同时给被拒；P6k 绑定的出口 v6 IP 不在本机被拒；
#       P6l 三个被拒用例无残留。宿主机没有可用 IPv6 时整组明确"跳过"。
#       （地址/前缀在 C0 就位，与 P5 的 --proxy-cidr6 和派生 ULA 都不重叠）
#   P5  内层 IPv6（--proxy-cidr6）在两个数据面上都真的通（切片 1 起内核模块也
#       按版本解封内层 v6；v6 in v4 走 netif_rx 重新入栈）：
#       P5a/P5b auto + --proxy-cidr6 仍是内核面（默认选面不再被 v6 需求改掉）；
#       P5c 内核面装上 --proxy-cidr6 的 IPv6 路由；P5d iwan0 上有会话派生 ULA
#       （fd00::/96 + 内层 IPv4，protocol.h 的 ip6_derive_ula）；P5e 内层 IPv6
#       TCP echo 经内核面**往返一致**（本轮核心断言，不是"路由装上了"）；
#       P5f 同一会话内层 IPv4 仍通（双栈共存）；P5g 退出后 v6 路由回滚；
#       P5h/P5h2/P5i 显式 --data-plane kernel + v6 正常建会话且 v6 echo 通
#       （切片 0 的用法错误拒绝已翻转）；P5j/P5j2/P5k 绑网卡（强制内核面）
#       与 v6 并存且 v6 echo 通（切片 0 的互斥已翻转）；P5l/P5l2/P5l3 TUN 面
#       照旧装/卸 IPv6 路由（回归）。保留的 FLAGS bit1 置位必被模块拒绝 ——
#       同参数不带它能建会话（P5m/P5m2）、带它必失败且无残留（P5n/P5o），
#       差别只有那一位
#
# 注意：脚本起/停的进程都按 "--port $PORT" 锚定（本脚本专用端口与 netns 名），
# 开头与退出清理各做一次 pkill 兜底；用户自己的隧道在别的端口上，不会被波及。
# 需要 root：模块 + netns + veth + TUN。非 root 运行会直接退出 1。

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
KO="$ROOT/kernel/iwan.ko"
BIN="$ROOT/bin"
NS_C=iwc-kdp
NS_S=iws-kdp
# 回程路由组（R1/R2）用的第三只 netns 与"非承载网卡"。必须放顶层：
# cleanup() 是 EXIT trap 且脚本是 set -u，没跑该组时 NS_L 也得是已绑定的。
NS_L=iwl-kdp
VETH_LC=veth-rr-c
VETH_LL=veth-rr-l
RR_CIDR=203.0.113.0/24
RR_SERVED=203.0.113.1
RR_PEER=203.0.113.9
RR_PORT=19101
RR_PORT2=19102
RR_INNER=198.18.0.2
RR_MARK=0x1
RR_TABLE=100
VETH_C=veth-kdp-c
VETH_S=veth-kdp-s
OUTER_C=10.100.0.1
OUTER_S=10.100.0.2
# 外层 IPv6（切片 2）：同一对 veth 上加的 v6 地址。前缀刻意与 P5 用的
# --proxy-cidr6（2001:db8:beef::/48）以及派生 ULA（fd00::/96）都不重叠 ——
# 外层路由绝不能被隧道自己劫持的路由覆盖。
OUTER6_C=2001:db8:1ce::1
OUTER6_S=2001:db8:1ce::2
PORT="${PORT:-16200}"
ECHO_PORT=19099
USERS=/tmp/iwan-kdp-e2e-users.txt
LOG_C=/tmp/iwan-kdp-e2e-client.log
LOG_S=/tmp/iwan-kdp-e2e-server.log
WORK=""

KEEP=0
EXTRA=0
BIND=0
LIFE=0
PLANE=0
for a in "$@"; do
    case "$a" in
    --keep)  KEEP=1 ;;
    --extra) EXTRA=1 ;;
    --bind)  BIND=1 ;;
    --life)  LIFE=1 ;;
    --plane) PLANE=1 ;;
    *) echo "未知参数: $a"; exit 2 ;;
    esac
done

PASS=0
FAIL=0
CLI=""
SRV=""
ECHO=""
# 回程路由组的两个 python 监听（NS_C 上被服务地址 / 会话内层地址）
RRLAN=""
RRTUN=""
# 内层 v6 回显监听（P5/P6 用）的 PID：必须在 cleanup 之前就有定义，否则脚本
# 在**起来之前**失败（例如 iwan_ctl 编译不过）时 cleanup 会在 set -u 下报
# "ECHO6: unbound variable"，把真正的失败原因淹没在后面。
ECHO6=""
LOADED_MODULE=0

say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
die()  { printf '致命: %s\n' "$*" >&2; exit 1; }

# 有界地停掉一个后台进程：先 SIGINT，最多等 $2 秒；不退就 SIGKILL。返回最终退出码，
# 超时强杀返回 124。**清理路径绝不能无限等** —— 现场教训：客户端收到 SIGINT 后不退出
# （原因待查），脚本的 `wait` 与 EXIT trap 于是双双挂死，机器上留下一整套残留。
# 判"已退出"要看 /proc 状态而不是 kill -0：进程退出后到被回收前，kill -0 仍然成功。
# 先 SIGINT、后限时 SIGKILL。两个已知细节：
#   · SIGINT 若发在目标"装 handler 之前"会被直接丢弃（继承来的 SIG_IGN），表现为
#     白等满 t 秒后 rc=124。实测：启动后立刻发 = 124，延迟 0.3s 发 = 0。C9 在客户端
#     跑了几秒之后才发信号，因此在窗口之外。
#   · 目标可能是 resolve_pid 兜底解析出的孙进程（被 shell 包装的情形），对它 wait
#     会返回 127（not a child）—— 那不是异常退出码，按 0 记（见下）。
stop_pid() {
    local p="$1" t="${2:-10}" i=0 st

    [ -n "$p" ] || return 0
    kill -INT "$p" 2>/dev/null
    while [ "$i" -lt $((t * 10)) ]; do
        st="$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$p/stat" 2>/dev/null)"
        if [ -z "$st" ] || [ "$st" = "Z" ]; then
            # 只有自己的子进程才 wait 得到退出码。resolve_pid 兜底解析出来的可能是孙
            # 进程（被 shell 包装的情形），对它 wait 会返回 127（not a child），
            # 那不是"退出码异常" —— 进程确实已按 SIGINT 自行退出，记 0。
            local wrc
            wait "$p" 2>/dev/null
            wrc=$?
            [ "$wrc" = "127" ] && return 0
            return "$wrc"
        fi
        sleep 0.1
        i=$((i + 1))
    done
    kill -9 "$p" 2>/dev/null
    wait "$p" 2>/dev/null
    return 124
}

cleanup() {
    set +e
    stop_pid "$CLI" 10
    if [ -n "$ECHO" ]; then
        kill -9 "$ECHO" 2>/dev/null
        wait "$ECHO" 2>/dev/null   # 回收掉，免得 bash 在终端上打一行 "Killed"
    fi
    if [ -n "$ECHO6" ]; then
        kill -9 "$ECHO6" 2>/dev/null
        wait "$ECHO6" 2>/dev/null
    fi
    # 回程路由组自己起的两个监听：不回收会在莫名其妙的地方留下 python
    for _rrp in "${RRLAN:-}" "${RRTUN:-}"; do
        [ -n "$_rrp" ] || continue
        kill -9 "$_rrp" 2>/dev/null
        wait "$_rrp" 2>/dev/null
    done
    stop_pid "$SRV" 10
    ip netns del "$NS_C" 2>/dev/null
    ip netns del "$NS_S" 2>/dev/null
    ip netns del "$NS_L" 2>/dev/null
    # 兜底：本脚本自己的进程一律按"--port $PORT"锚定清掉（TUN 泵之外不会有
    # 别的进程用这个端口；用户自己的隧道在别的端口上，不会被波及）。
    pkill -9 -f "iwan-client proxy .*--port $PORT" 2>/dev/null || true
    pkill -9 -f "iwan-server .*--port $PORT" 2>/dev/null || true
    # 只卸**我们自己 insmod** 的那个（脚本开头写明：模块本来就加载着时不动它）。
    # 卸载失败不静默 —— 残留的会话/网卡会让下一轮 insmod 报 EEXIST。
    if [ "$KEEP" = 1 ]; then
        printf '  KEEP=1：模块 iwan 保留未卸载\n'
    elif [ "$LOADED_MODULE" = 1 ]; then
        rmmod iwan 2>/dev/null \
            || printf '  警告: rmmod iwan 失败（仍有会话/网卡占用？先 sudo iwan_ctl session-down）\n'
    else
        printf '  模块 iwan 是脚本启动前就加载的：按约定不卸载\n'
    fi
    [ -n "$WORK" ] && [ "$KEEP" = 0 ] && rm -rf "$WORK"
    set -e
}
trap cleanup EXIT

# 等日志出现某个子串（最多 $3 秒）
wait_log() {
    local f="$1" pat="$2" t="${3:-20}" i=0

    while [ "$i" -lt $((t * 10)) ]; do
        grep -q -- "$pat" "$f" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# 等日志里某个子串出现第 $3 次（默认第 2 次，最多 $4 秒）。恢复类用例的文本
# 与建立时相同（"会话已建立"），只看"出现过"会把恢复前的旧行当成本次证据。
wait_log_n() {
    local f="$1" pat="$2" n="${3:-2}" t="${4:-20}" i=0

    while [ "$i" -lt $((t * 10)) ]; do
        [ "$(grep -c -- "$pat" "$f" 2>/dev/null)" -ge "$n" ] && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

nsx() { ip netns exec "$1" "${@:2}"; }

# 有界地停掉一个客户端：重连循环里的客户端可能正卡在一次握手超时上，直接
# wait 会把用例挂住（首轮实测过两分钟的静默）。
stop_cli() {
    local p="$1" i=0

    kill -INT "$p" 2>/dev/null
    while [ "$i" -lt 40 ]; do
        kill -0 "$p" 2>/dev/null || break
        sleep 0.25
        i=$((i + 1))
    done
    kill -9 "$p" 2>/dev/null
    wait "$p" 2>/dev/null
}

# 模块是否已加载：直接读 /proc/modules（不依赖 lsmod 在 root 的 PATH 里）。
module_loaded() { grep -q '^iwan ' /proc/modules 2>/dev/null; }

# 解析后台任务的**真实目标进程** PID。两类时间差都必须容忍：
#   · exec 时间差：`ip netns exec` / `env` 都是原地 exec，PID 不变，但 /proc/PID/comm
#     要过一会儿才变成目标名 —— 断言太早会误报"被包装了"（踩过一次，纯误报）；
#   · shell 包装：对 shell 函数用 `&` 会 fork 出子 shell，而子 shell 按 POSIX 规定把
#     SIGINT/SIGQUIT 置为忽略 ⇒ 信号发给它等于没发，`wait` 还会一直等它的子进程。
#     这时目标进程是它的**子进程**，直接采用之。
# 现场教训：C9 曾因信号发给包装子 shell 而假死 20 分钟，一度被误判成客户端缺陷。
resolve_pid() {
    local p="$1" want="$2" i=0 got kid

    while [ "$i" -lt 40 ]; do
        got="$(cat "/proc/$p/comm" 2>/dev/null)"
        [ "$got" = "$want" ] && { printf '%s' "$p"; return 0; }
        kid="$(pgrep -P "$p" -x "$want" 2>/dev/null | head -n1)"
        [ -n "$kid" ] && { printf '%s' "$kid"; return 0; }
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

# 用法：<后台命令> & bg_resolve <变量名> <目标进程名>
# 自己在函数里读 $!，调用点不出现 $! —— 少一个"能忘、忘了还静默"的步骤。
# 踩过一次：改脚本时替换文本顺手把 ECHO=$! / CLI=$! 一起删掉，resolve_pid 收到空串，
# 转满 40 圈才报"解析 PID 失败"，白跑一整轮。
bg_resolve() {
    local __var="$1" __want="$2" __job __real

    __job="$!"
    [ -n "$__job" ] || die "bg_resolve $__var：没有可取的后台任务（\$! 为空）"
    if [ ! -e "/proc/$__job" ]; then
        # 秒退：最常见的原因是重定向打不开（日志文件属 root/无权限）。别只说"解析失败"。
        die "后台 $__want 进程 $__job 已退出（重定向或启动就失败了？看它的日志）"
    fi
    __real="$(resolve_pid "$__job" "$__want")" \
        || die "解析 $__want 进程 PID 失败（job=$__job comm=$(cat "/proc/$__job/comm" 2>/dev/null)）"
    printf -v "$__var" '%s' "$__real"
}

# 设备 kind：`ip -d link show dev X` 里**第一个不以 link/ 开头的详情行**的行首 token。
# 不要取第二行：那是 ARPHRD 渲染（link/ipip、link/none、link/ether），不是 kind；
# kind 有自己的详情行（`iwan addrgenmode …`、`tun type tap …`、`veth addrgenmode …`）。
# 设备不存在时输出空。取错行的后果是假 FAIL：模块建的 iwan0 会被读成 "link/ipip"，
# TUN 会被读成 "link/none"。
dev_kind() {
    nsx "$1" ip -d link show dev "$2" 2>/dev/null \
        | sed -n '2,$s/^[ \t]*\([^ \t]*\)[ \t].*/\1/p' \
        | grep -v '^link/' | head -n1
}

# 设备 flags（第一行 <> 里的内容）：DOWN 的设备不含 UP
dev_flags() {
    nsx "$1" ip -d link show dev "$2" 2>/dev/null | sed -n '1{s/.*<\([^>]*\)>.*/\1/p;q}'
}

dev_mtu() {
    nsx "$1" ip -o link show dev "$2" 2>/dev/null | sed -n 's/.* mtu \([0-9]*\).*/\1/p;q'
}

dev_ip4() {
    nsx "$1" ip -o -4 addr show dev "$2" 2>/dev/null | awk '{print $4; exit}'
}

# 首个"可用"的 v6 地址：排除 fe80::（每个网卡都有，不是内层地址）与
# tentative（DAD 未完成，不能当源地址）
dev_ip6() {
    nsx "$1" ip -o -6 addr show dev "$2" 2>/dev/null \
        | awk '$4 !~ /^fe80:/ && $0 !~ /tentative/ {print $4; exit}'
}

# 派生 ULA：与 protocol.h 的 ip6_derive_ula() 同一算法（fd00::/96 + 内层
# IPv4 的低 32 位）。内层 v6 的地址就是这么来的 —— 客户端与服务端各自把
# 自己分到的内层 IPv4 映射成 ULA，两侧的准入过滤也按它校验。
ula_of() {
    python3 -c "
import ipaddress, sys
print(ipaddress.IPv6Address(b'\xfd' + b'\x00' * 11 +
      ipaddress.IPv4Address(sys.argv[1]).packed))
" "$1"
}

# get-stats 的 KEY=value（没有该 key 时为空）
# 内层回显探针（与 C6 同一条路径）：经 iwan0 的 TCP 往返是否通
echo_probe() {
    nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'bind-probe')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
}

# 内层 IPv6 回显探针：目标地址是**服务端的派生 ULA**（内层 v6 的两个端点
# 就是两侧各自的 ULA；客户端侧由 route_iface_up 的 v6 侧自动配好，见 P5d）
echo_probe6() {
    nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('$ULA_S6', $ECHO_PORT), 5)
s.sendall(b'v6-probe')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
}

# DAD 期间（约 1s）刚加的 ULA 是 tentative，不能当源地址：等它可用再探。
# 内核面/ TUN 面都跑 DAD，且 DAD 的 NS 源是未指定地址、会被对端的 ULA 准入
# 过滤丢掉（等不到回应 → 超时后转 preferred），所以这里必须等。
wait_ula_ready() {
    for _ in $(seq 1 40); do
        [ -n "$(dev_ip6 "$NS_C" iwan0)" ] && return 0
        sleep 0.25
    done
    return 1
}

stat_of() {
    nsx "$1" "$WORK/iwan_ctl" get-stats 2>/dev/null | sed -n "s/^$2=//p" | head -1
}

# 内层 v6 回显失败时的现场：模块计数器（tx_bad_inner/rx_bad_inner 直指"模块
# 把内层 v6 判成坏包"，rx_delivered/tx_pkts 直指"没收到/没发出"）+ 两端日志
# 尾部。没有它，"echo 失败" 只会留下一个让人从头查的谜面。
v6_fail_hint() {
    printf '    模块计数器(客户端 netns): %s\n' \
        "$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>/dev/null | tr '\n' ' ' | cut -c1-240)"
    printf '    客户端日志尾部:\n'
    tail -n 3 "$1" 2>/dev/null | sed 's/^/      /'
    printf '    服务端日志尾部:\n'
    tail -n 3 "$LOG_S" 2>/dev/null | sed 's/^/      /'
}

# ---------------------------------------------------------------- 前置

[ "$(id -u)" = 0 ] || die "需要 root：sudo bash $0"
command -v ip >/dev/null   || die "缺少 iproute2"
command -v cc >/dev/null   || die "缺少 cc（编译 kernel/tests 的两个只读工具）"
[ -f "$KO" ]               || die "缺少 $KO：先 make -C kernel"
[ -x "$BIN/iwan-client" ]  || die "缺少 $BIN/iwan-client：先 cmake -B build -DIWAN_WERROR=ON -DIWAN_STRICT=ON && cmake --build build"
[ -x "$BIN/iwan-server" ]  || die "缺少 $BIN/iwan-server：同上"
# 构建档位前置：内核模块的 max_mtu 默认 1500，而度量档构建（cmake -DIWAN_JUMBO_MTU=N）
# 会把客户端的**默认**内层 MTU 抬到上限（例如 65499）—— 那种客户端不带 --mtu 时
# 必被模块以 -EINVAL 拒绝（日志 "SESSION_UP 参数非法 ... mtu=65499"）。默认数据面
# 就是"不带 --mtu"的路径，所以这里必须先挡住，别让档位错配伪装成选面失败。
CLI_MTU_DEFAULT="$("$BIN/iwan-client" proxy --help 2>/dev/null \
                   | sed -n 's/.*--mtu <MTU> *\[default: \([0-9]*\)\].*/\1/p' | head -1)"
[ "$CLI_MTU_DEFAULT" = "1400" ] \
    || die "客户端的默认内层 MTU 是 ${CLI_MTU_DEFAULT:-未知}（应为 1400）：这是度量档构建（IWAN_JUMBO_MTU），内核模块装不下。请用普通构建：cmake -B build -DIWAN_WERROR=ON -DIWAN_STRICT=ON && cmake --build build"

WORK="$(mktemp -d /tmp/iwan-kdp-e2e.XXXXXX)"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$WORK/iwan_ctl"  "$ROOT/kernel/tests/iwan_ctl.c"  || die "编译 iwan_ctl 失败"
cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -o "$WORK/iwan_shm"  "$ROOT/kernel/tests/iwan_shm.c"  || die "编译 iwan_shm 失败"

# 每个用例一个账号：服务端对同一账号的并发/异址会话会回 OPEN_REJECT
# （"session active elsewhere"），分账号可以避免用例之间互相干扰
printf 'alice:s3cret-pass\nbob:s3cret-pass\ncarol:s3cret-pass\ndave:s3cret-pass\n' > "$USERS"
chmod 600 "$USERS"

# 幂等前置：上一轮若挂过（例如强杀了包装子 shell 而真正的客户端成了孤儿），会留下
# netns + 会话 + iwan0，下一轮 insmod 直接 "File exists"、脚本根本起不来。这里只清
# **本脚本自己**的残留：netns 名与端口都是本脚本专有的，碰不到用户自己的隧道。
pkill -9 -f "iwan-client proxy .*--port $PORT" 2>/dev/null || true
pkill -9 -f "iwan-server .*--port $PORT" 2>/dev/null || true
sleep 0.3
ip netns del "$NS_C" 2>/dev/null || true
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_L" 2>/dev/null || true

if module_loaded; then
    say "模块 iwan 已加载（要求它当初是无会话参数加载的；退出时也不 rmmod）"
    sid0="$(awk '$1=="sid"{print $2}' /proc/net/iwan 2>/dev/null)"
    [ -z "$sid0" ] || [ "$sid0" = "0" ] \
        || die "init netns 已有内核会话（sid=$sid0）：先 sudo iwan_ctl session-down 或 sudo rmmod iwan 再跑"
    # 已加载的模块必须是**这份源码的构建**：模块侧的断言（例如 P5n 的保留
    # FLAGS 位、C4 的 MTU 语义）在旧模块上会静默验成旧行为，让人以为改动没
    # 生效。/sys/module/<名> 的 mtime 就是加载时刻，拿它和磁盘上的 .ko 比。
    if [ "$KO" -nt /sys/module/iwan ]; then
        die "已加载的 iwan 比 $KO 旧（磁盘构建：$(date -r "$KO" '+%F %T')，模块加载：$(date -r /sys/module/iwan '+%F %T')）：先 sudo rmmod iwan && sudo insmod $KO 再跑，否则模块侧断言验的是旧代码"
    fi
else
    say "加载模块（不带任何会话参数）"
    # 上一轮的 rmmod 与本次 insmod 会抢跑：卸载中的模块已从 /proc/modules 消失，但
    # init_module 仍可能拿到 EEXIST。重试几次再判死，别让一次竞态废掉整轮验收。
    loaded=""
    for _ in 1 2 3 4 5 6; do
        if insmod "$KO" 2>"$WORK/insmod.err"; then
            loaded=ours
            break
        fi
        if module_loaded; then
            loaded=theirs
            break
        fi
        sleep 0.3
    done
    case "$loaded" in
        ours)   LOADED_MODULE=1 ;;
        theirs) say "insmod 报已存在，但 iwan 已加载且无会话 —— 继续用已加载的模块" ;;
        *)      die "insmod 重试 6 次仍失败：$(cat "$WORK/insmod.err" 2>/dev/null)（dmesg | tail 看原因）" ;;
    esac
fi

say "C1 模块与初始状态"
[ -e /dev/iwan ] && ok "C1a /dev/iwan 存在" || bad "C1a /dev/iwan 不存在"

# 上一轮被打断时 /run/netns/<名字> 会残留，此时 ip netns add 以 "File exists"
# 失败（2026-10-11 在 bench 上实测踩到）。按名字先删；删不动就当挂载残留卸载
# 并删掉那一个文件（只碰这两个具体路径），仍失败才报错。
mk_netns() {
    local n="$1"

    ip netns add "$n" 2>/dev/null && return 0
    echo "警告: ip netns add $n 失败（残留？）—— 先删再试" >&2
    ip netns del "$n" 2>/dev/null
    if [ -e "/run/netns/$n" ]; then
        umount "/run/netns/$n" 2>/dev/null
        rm -f "/run/netns/$n" 2>/dev/null
    fi
    ip netns add "$n"
}
mk_netns "$NS_C" || die "ip netns add $NS_C 失败"
mk_netns "$NS_S" || die "ip netns add $NS_S 失败"
ip link add "$VETH_C" type veth peer name "$VETH_S" || die "建 veth 失败"
ip link set "$VETH_C" netns "$NS_C"
ip link set "$VETH_S" netns "$NS_S"
nsx "$NS_C" ip addr add "$OUTER_C/24" dev "$VETH_C"
nsx "$NS_S" ip addr add "$OUTER_S/24" dev "$VETH_S"
# 外层 v6：nodad 跳过 DAD 等待（否则地址在 ~1s 内是 tentative，不能当外层
# 源地址）。宿主机若整体关了 IPv6 这里会失败 —— 记 V6_OK=0，P6 组整体跳过
# 并明说"跳过"，不伪装成通过。
V6_OK=1
nsx "$NS_C" ip -6 addr add "$OUTER6_C/64" dev "$VETH_C" nodad 2>/dev/null || V6_OK=0
nsx "$NS_S" ip -6 addr add "$OUTER6_S/64" dev "$VETH_S" nodad 2>/dev/null || V6_OK=0
nsx "$NS_C" ip -6 addr show dev "$VETH_C" 2>/dev/null | grep -q "$OUTER6_C" || V6_OK=0
[ "$V6_OK" = 1 ] && say "C0 外层 v6 地址已就位（$OUTER6_C / $OUTER6_S）" \
                 || say "C0 外层 v6 不可用：P6 组将跳过"
nsx "$NS_C" ip link set lo up
nsx "$NS_S" ip link set lo up
nsx "$NS_C" ip link set "$VETH_C" up
nsx "$NS_S" ip link set "$VETH_S" up
nsx "$NS_C" ping -c1 -W1 "$OUTER_S" >/dev/null 2>&1 \
    && ok "C1b veth 互通（$OUTER_C -> $OUTER_S）" \
    || bad "C1b veth 不通"
[ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "C1c iwc 里还没有 iwan0（配置只能来自 netlink）" \
                                   || bad "C1c iwc 里已经有 iwan0"
[ "$(stat_of "$NS_C" sid)" = "0" ] && [ "$(stat_of "$NS_C" tok)" = "0" ] \
    && ok "C1d iwc get-stats: 无会话（sid=0 tok=0）" \
    || bad "C1d iwc 初始会话不是空的"

# ---------------------------------------------------------------- 服务端（iws）

say "C2 服务端（用户态 TUN 转发，无内核会话）"
ip netns exec "$NS_S" "$BIN/iwan-server" --port "$PORT" --tun iwan-srv \
    --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --nat-if "$VETH_S" \
    --dns 198.18.0.1 --users "$USERS" >"$LOG_S" 2>&1 &
bg_resolve SRV iwan-server
wait_log "$LOG_S" "server ready." 15 && ok "C2a server ready" \
    || { bad "C2a 服务端没起来"; tail -5 "$LOG_S"; }
[ "$(dev_kind "$NS_S" iwan-srv)" = "tun" ] && ok "C2b iws 的 iwan-srv 是 tun 设备" \
                                          || bad "C2b iws 的 iwan-srv 不是 tun"
[ -z "$(dev_kind "$NS_S" iwan0)" ] && ok "C2c iws 没有 iwan0（服务端不走内核数据面）" \
                                   || bad "C2c iws 出现了 iwan0"

# iws 里的内层 echo（客户端 TCP 的目标）
ip netns exec "$NS_S" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('198.18.0.1', $ECHO_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
bg_resolve ECHO python3

# 内层 IPv6 的同一端口监听：绑服务端的派生 ULA（iws 启动时由它自己配到
# iwan-srv 上）。内核面的内层 v6 断言（P5e/P5i/P5k）靠它回显；必须
# IPV6_V6ONLY，否则 :: 会和上面那个 v4 socket 抢同一个端口。
ULA_S6="$(ula_of 198.18.0.1)"
ip netns exec "$NS_S" python3 -c "
import socket
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(('$ULA_S6', $ECHO_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
bg_resolve ECHO6 python3

# ---------------------------------------------------------------- 客户端（iwc）

say "C3 客户端（--data-plane kernel）"
ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
    --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
    --data-plane kernel --mtu 1400 >"$LOG_C" 2>&1 &
bg_resolve CLI iwan-client
if wait_log "$LOG_C" "kernel data plane running" 25; then
    ok "C3a 客户端进入内核数据面运行态"
else
    bad "C3a 客户端没进运行态"; tail -12 "$LOG_C"
fi
grep -q "内核数据面: 会话已建立 dev=iwan0 mtu=1400" "$LOG_C" \
    && ok "C3b 日志: 会话已建立 dev=iwan0 mtu=1400" \
    || bad "C3b 会话建立日志不符（见 $LOG_C）"

SRV_TUN_IP="$(sed -n 's/.*OPEN_ACK -> alice .* ip=\([0-9.]*\).*/\1/p' "$LOG_S" | head -1)"
[ -n "$SRV_TUN_IP" ] && ok "C3c 服务端回执分配的 tun ip = $SRV_TUN_IP" \
                     || bad "C3c 服务端日志里没有 OPEN_ACK 的 tun ip"

say "C4 iwc 的 iwan0 由模块创建并配好"
[ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "C4a kind=iwan（模块创建的卡）" \
                                        || bad "C4a kind=$(dev_kind "$NS_C" iwan0)"
case "$(dev_flags "$NS_C" iwan0)" in
*UP*) ok "C4b flags 含 UP（$(dev_flags "$NS_C" iwan0)）" ;;
*)    bad "C4b 设备没 UP（flags=$(dev_flags "$NS_C" iwan0)）" ;;
esac
[ "$(dev_mtu "$NS_C" iwan0)" = "1400" ]  && ok "C4c mtu=1400" || bad "C4c mtu=$(dev_mtu "$NS_C" iwan0)"
[ "$(dev_ip4 "$NS_C" iwan0)" = "$SRV_TUN_IP/24" ] \
    && ok "C4d 地址 = $SRV_TUN_IP/24（与回执一致）" \
    || bad "C4d 地址 = $(dev_ip4 "$NS_C" iwan0)，期望 $SRV_TUN_IP/24"

say "C5 iws 侧没有内核会话"
[ -z "$(dev_kind "$NS_S" iwan0)" ] && ok "C5a iws 仍然没有 iwan0" || bad "C5a iws 有 iwan0"

say "C6 内层 TCP 走内核数据面（iwc -> iws 198.18.0.1:$ECHO_PORT）"
OUT="$(nsx "$NS_C" python3 -c "
import socket, sys
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'hello-kernel-data-plane')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1)"
[ "$OUT" = "hello-kernel-data-plane" ] && ok "C6a TCP echo 回显一致: $OUT" \
                                       || bad "C6a TCP echo 失败/不一致: $OUT"

say "C7 /dev/iwan 共享内存（只读 mmap）"
SHM="$(nsx "$NS_C" "$WORK/iwan_shm" dump 2>&1)"
printf '%s\n' "$SHM" | sed 's/^/    /'
printf '%s\n' "$SHM" | grep -q '^version=1$'  && ok "C7a version=1"  || bad "C7a version != 1"
printf '%s\n' "$SHM" | grep -q '^enabled=1$'  && ok "C7b enabled=1"  || bad "C7b enabled != 1"
LRX="$(printf '%s\n' "$SHM" | sed -n 's/^last_rx_ms=//p' | head -1)"
[ -n "$LRX" ] && [ "$LRX" != "0" ] && ok "C7c last_rx_ms=$LRX（收到过对端帧）" \
                                   || bad "C7c last_rx_ms=$LRX，期望非 0"

say "C8 内核计数器（iwan_ctl get-stats，iwc）"
GS1="$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>&1)"
printf '%s\n' "$GS1" | sed 's/^/    /'
CLI_SID_HEX="$(sed -n 's/.*会话已建立 .*sid=\(0x[0-9a-f]*\).*/\1/p' "$LOG_C" | head -1)"
CLI_SID_DEC=$((CLI_SID_HEX))
GS_SID="$(printf '%s\n' "$GS1" | sed -n 's/^sid=//p' | head -1)"
[ -n "$CLI_SID_HEX" ] && [ "$GS_SID" = "$CLI_SID_DEC" ] \
    && ok "C8a sid 一致（日志 $CLI_SID_HEX = 内核 $GS_SID）" \
    || bad "C8a sid: 客户端 $CLI_SID_HEX（$CLI_SID_DEC）vs 内核 $GS_SID"
RX1="$(printf '%s\n' "$GS1" | sed -n 's/^rx_frames=//p' | head -1)"
nsx "$NS_C" python3 -c "
import socket
s = socket.create_connection(('198.18.0.1', $ECHO_PORT), 5)
s.sendall(b'x' * 32)
s.recv(64)
s.close()
" >/dev/null 2>&1
sleep 1
GS2="$(nsx "$NS_C" "$WORK/iwan_ctl" get-stats 2>&1)"
RX2="$(printf '%s\n' "$GS2" | sed -n 's/^rx_frames=//p' | head -1)"
[ -n "$RX1" ] && [ -n "$RX2" ] && [ "$RX2" -gt "$RX1" ] \
    && ok "C8b rx_frames 增长: $RX1 -> $RX2" \
    || bad "C8b rx_frames 没增长: $RX1 -> $RX2"

say "C9 Ctrl-C 退出（三态返回码 0 = 用户停止）"
DEFAULT_BEFORE="$(nsx "$NS_C" ip route show default)"
# 有界等待 + 现场采集：客户端不退时不要把脚本挂死在这里（`wait` 无限等过一次，
# 连带 EXIT trap 一起挂死）。超时就先把进程状态/信号掩码/日志尾部打出来再强杀，
# 这样"失败"本身带着定位信息。
kill -INT "$CLI" 2>/dev/null || true
i=0
RC=""
while [ "$i" -lt 100 ]; do
    st="$(sed -n 's/^[^)]*) \([A-Z]\).*/\1/p' "/proc/$CLI/stat" 2>/dev/null || true)"
    if [ -z "$st" ] || [ "$st" = "Z" ]; then
        wait "$CLI" 2>/dev/null || true
        RC=$?
        break
    fi
    sleep 0.1
    i=$((i + 1))
done
if [ -z "$RC" ]; then
    bad "C9a 客户端 SIGINT 后 10s 未退出（现场如下，随后强杀）"
    ps -o pid=,stat=,etime=,time=,args= -p "$CLI" 2>/dev/null \
        | cut -c1-150 | sed 's/^/    进程: /' || true
    grep -E '^State|^Sig(Blk|Ign|Cgt)|^Threads' "/proc/$CLI/status" 2>/dev/null \
        | sed 's/^/    /' || true
    printf '    客户端日志尾部:\n'
    tail -n 4 "$LOG_C" 2>/dev/null | sed 's/^/      /' || true
    kill -9 "$CLI" 2>/dev/null || true
    wait "$CLI" 2>/dev/null || true
    RC=124
else
    [ "$RC" = 0 ] && ok "C9a 客户端退出码 0" || bad "C9a 客户端退出码 $RC"
fi
CLI=""
grep -q "kernel data plane stopped (user stop)" "$LOG_C" \
    && ok "C9b 日志: kernel data plane stopped (user stop)" \
    || bad "C9b 日志里没有 stopped (user stop)"

say "C10 退出清理"
[ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "C10a iwan0 已删除" \
                                   || bad "C10a iwan0 仍在: kind=$(dev_kind "$NS_C" iwan0)"
[ "$(stat_of "$NS_C" sid)" = "0" ] && [ "$(stat_of "$NS_C" tok)" = "0" ] \
    && ok "C10b 会话清零（sid=0 tok=0）" \
    || bad "C10b 会话残留: sid=$(stat_of "$NS_C" sid) tok=$(stat_of "$NS_C" tok)"
grep -q "CLOSE sent" "$LOG_C" && ok "C10c 客户端发过 PT_CLOSE（告别帧）" \
                              || bad "C10c 客户端日志里没有 CLOSE sent"
# 客户端日志只能证明"发了"；"对端真收到并拆了会话"必须看服务端 —— server.c 的 PT_CLOSE
# 分支在 token 正确时无条件 srv_log("[peer] session 0x…. (ip …) closed")（stdout+fflush，
# 不受 debug 开关影响）。服务端日志在本脚本里开局清空，这一行只可能来自 C9 的告别帧。
if wait_log "$LOG_S" " closed" 3; then
    ok "C10e 服务端确认会话已关闭: $(grep -m1 -- " closed" "$LOG_S")"
else
    bad "C10e 服务端没有会话关闭记录（PT_CLOSE 没送达？看 $LOG_S）"
fi
[ "$(nsx "$NS_C" ip route show default)" = "$DEFAULT_BEFORE" ] \
    && ok "C10d 默认路由没被动过（无 --proxy-cidr）" \
    || bad "C10d 默认路由变了: $DEFAULT_BEFORE -> $(nsx "$NS_C" ip route show default)"

# ---------------------------------------------------------------- --extra

if [ "$EXTRA" = 1 ]; then
    say "E1 iwan0 被别的设备占用（dummy）"
    nsx "$NS_C" ip link add iwan0 type dummy || bad "E1a 建 dummy 失败"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user bob --pass s3cret-pass --data-plane kernel >"$LOG_C.e1" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "E1b 客户端非零退出（$RC）" || bad "E1b 客户端居然成功"
    grep -q "已存在，但不是 iwan 内核模块创建的设备" "$LOG_C.e1" \
        && ok "E1c 中文归属报错" || bad "E1c 报错文本不符（见 $LOG_C.e1）"
    [ "$(dev_kind "$NS_C" iwan0)" = "dummy" ] && ok "E1d dummy 未被删除/接管" \
                                             || bad "E1d dummy 被动了"
    nsx "$NS_C" ip link del iwan0

    say "E2 SIGKILL 残留（已知回归）与其清理"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user carol --pass s3cret-pass \
        --data-plane kernel >"$LOG_C.e2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.e2" "kernel data plane running" 25 || bad "E2a 客户端没起来"
    kill -9 "$CLI" 2>/dev/null
    wait "$CLI" 2>/dev/null
    CLI=""
    sleep 0.5
    [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] \
        && ok "E2b SIGKILL 后 iwan0 仍在（回归：TUN 模式不会有残留）" \
        || bad "E2b SIGKILL 后 iwan0 竟然没了"
    [ "$(stat_of "$NS_C" sid)" != "0" ] && ok "E2c 会话仍在内核里（钩子继续吞包）" \
                                       || bad "E2c 会话没了"
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    sleep 0.5
    [ -z "$(dev_kind "$NS_C" iwan0)" ] && ok "E2d session-down 清掉会话与设备" \
                                       || bad "E2d session-down 之后 iwan0 还在"

    say "E3 外部删除 iwan0 -> 客户端重建"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane kernel >"$LOG_C.e3" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.e3" "kernel data plane running" 25 || bad "E3a 客户端没起来"
    nsx "$NS_C" ip link del iwan0 2>/dev/null
    if wait_log "$LOG_C.e3" "已重建" 6; then
        ok "E3b 日志: iwan0 被外部删除后已重建"
        [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "E3c 设备真的回来了" \
                                                 || bad "E3c 设备没回来"
    else
        bad "E3b 没看到重建（见 $LOG_C.e3）"
    fi
    kill -INT "$CLI" 2>/dev/null
    wait "$CLI" 2>/dev/null
    CLI=""
fi

# ------------------------------------------------- 选面、回退与握手前拒绝（--plane）

if [ "$PLANE" = 1 ]; then
    say "P1 默认数据面（不给 --data-plane）= 内核面"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        >"$LOG_C.p1" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p1" "kernel data plane running" 25; then
        ok "P1a 默认选面走到了内核面"
    else
        bad "P1a 默认没走内核面（见 $LOG_C.p1）"
    fi
    grep -q "数据面: 默认 kernel" "$LOG_C.p1" && ok "P1b 日志声明默认选面" \
        || bad "P1b 缺默认选面日志（见 $LOG_C.p1）"
    [ "$(dev_kind "$NS_C" iwan0)" = "iwan" ] && ok "P1c iwan0 由模块建出" \
        || bad "P1c iwan0 kind=$(dev_kind "$NS_C" iwan0)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P1d 内层 TCP echo 往返一致" \
        || bad "P1d 内层 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""
    # 等内核里的会话与设备真的没了，再让 P2 用 dummy 占住 iwan0
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    say "P2 内核面不可用（iwan0 被 dummy 占）⇒ 自动回退 TUN"
    if nsx "$NS_C" ip link add iwan0 type dummy; then
        ok "P2 前置: dummy 占住 iwan0"
    else
        bad "P2 前置: dummy 建不出来（iwan0 还有残留？）"
    fi
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --tun iwan9 >"$LOG_C.p2" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p2" "TUN proxy running" 25; then
        ok "P2a 回退后 TUN 面起来了"
    else
        bad "P2a 回退失败（见 $LOG_C.p2）"
    fi
    grep -q "已存在，但不是 iwan 内核模块创建的设备" "$LOG_C.p2" \
        && ok "P2b 内核面不可用的原因已报出" || bad "P2b 缺内核面原因（见 $LOG_C.p2）"
    grep -q "自动回退到 TUN 数据面" "$LOG_C.p2" && ok "P2c 回退日志出现" \
        || bad "P2c 缺回退日志（见 $LOG_C.p2）"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P2d 回退后内层 TCP echo 往返一致" \
        || bad "P2d 回退后 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""
    nsx "$NS_C" ip link del iwan0

    say "P3 两个数据面都不可用 ⇒ 非零退出（TUN 报错文本不再说 must be root）"
    nsx "$NS_C" ip link add iwan0 type dummy
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass >"$LOG_C.p3" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P3a 非零退出（$RC）" || bad "P3a 居然成功了"
    grep -q "自动回退到 TUN 数据面" "$LOG_C.p3" && ok "P3b 确实尝试了回退" \
        || bad "P3b 没尝试回退（见 $LOG_C.p3）"
    grep -q "内核拒绝了这个名字" "$LOG_C.p3" \
        && ok "P3c TUN 报错文本指出名字被内核拒绝" \
        || bad "P3c TUN 报错文本不符（见 $LOG_C.p3）"
    grep -q "TUN 数据面也不可用，退出" "$LOG_C.p3" && ok "P3d 明确报告两边都不可用" \
        || bad "P3d 缺"两边都不可用"的结论（见 $LOG_C.p3）"
    grep -q "must be root" "$LOG_C.p3" && bad "P3e 仍在用误导性的 must be root" \
        || ok "P3e 不再出现 must be root"
    nsx "$NS_C" ip link del iwan0

    say "P4 本 netns 已有活会话 ⇒ 第二条客户端在握手前被拒"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        >"$LOG_C.p4a" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p4a" "kernel data plane running" 25; then
        ok "P4a 第一条客户端进入内核数据面运行态"
    else
        bad "P4a 第一条没起来（见 $LOG_C.p4a）"
    fi
    # 判活的输入是共享内存里的 last_rx_ms：刚建立的会话它还是 0（第一次
    # keepalive 要到 10s 才发出）。先打一发内层 echo 让内核收到过闸帧，
    # last_rx_ms 就"新鲜"了（< 2×keepalive 的判活窗口内）。
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P4a2 内层 echo 通（制造最近的收帧）" \
        || bad "P4a2 内层 echo 失败: $OUT"
    SHM4="$(nsx "$NS_C" "$WORK/iwan_shm" dump 2>&1)"
    printf '%s\n' "$SHM4" | grep -q '^enabled=1$' \
        && ok "P4a3 共享内存 enabled=1（判活输入就绪）" \
        || bad "P4a3 enabled != 1: $(printf '%s\n' "$SHM4" | grep '^enabled' )"
    SID_A="$(stat_of "$NS_C" sid)"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass >"$LOG_C.p4b" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P4b 第二条非零退出（$RC）" || bad "P4b 第二条居然成功"
    grep -q "本 netns 已有一条活会话" "$LOG_C.p4b" \
        && ok "P4c 报错文本：本 netns 已有活会话" \
        || bad "P4c 报错文本不符（见 $LOG_C.p4b）"
    grep -q "不回退 TUN" "$LOG_C.p4b" && ok "P4d 明确不回退 TUN" \
        || bad "P4d 缺"不回退"的说明（见 $LOG_C.p4b）"
    # 光有说明不够：busy 这一类必须**连试都不试** TUN 面 —— P3 已经证明
    # TUN 被占时报的是"打开 TUN 设备…"，这里没有那行就说明没走到 TUN。
    grep -q "打开 TUN 设备\|TUN proxy running" "$LOG_C.p4b" \
        && bad "P4d2 居然去试了 TUN 面（见 $LOG_C.p4b）" \
        || ok "P4d2 全程没有碰 TUN 面"
    grep -q "会话已建立\|SESSION_UP 与已有会话冲突" "$LOG_C.p4b" \
        && bad "P4e 第二条还是握了手（判活没在握手之前）" \
        || ok "P4e 没有握手、没有 SESSION_UP（判活在握手之前）"
    [ "$(stat_of "$NS_C" sid)" = "$SID_A" ] && ok "P4f 第一条会话未被顶掉（sid 不变）" \
        || bad "P4f sid 变了: $SID_A -> $(stat_of "$NS_C" sid)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P4g 第一条仍在正常转发" \
        || bad "P4g 第一条 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""

    say "P5 内层 IPv6（--proxy-cidr6）在两个数据面上都真的通"
    # 背景（切片 1）：内核模块与用户态泵一样按版本解封内层分组 —— v4/v6 都收。
    #   · 出站：TX 用一份共用判据校验内层头自洽（v4 看 tot_len、v6 看
    #     payload_len + 扩展头链）；
    #   · 入站：RX 同判据。内层版本 ≠ 外层版本（v6 in v4）时，"让当前协议栈
    #     路径继续走"（NF_ACCEPT）必然被按外层版本误解析，所以那种帧改走
    #     netif_rx 重新入栈，由 skb->protocol 按内层版本重选处理器。
    # 断言口径：不看"路由装上了"，而是做**真往返** —— 内层 v6 的两个端点就是
    # 两侧各自的派生 ULA（fd00::/96 + 内层 IPv4 低 32 位，protocol.h 的
    # ip6_derive_ula）。静默黑洞的特征正是"路由装上但不通"。
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --proxy-cidr6 2001:db8:beef::/48 >"$LOG_C.p5a" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5a" "kernel data plane running" 25; then
        ok "P5a auto + --proxy-cidr6 仍是内核面（默认选面没被 v6 需求改掉）"
    else
        bad "P5a 没起来（见 $LOG_C.p5a）"
    fi
    grep -q "数据面: 默认 kernel" "$LOG_C.p5a" \
        && ok "P5b 日志声明默认选面（不再提改选 TUN）" \
        || bad "P5b 缺默认选面日志（见 $LOG_C.p5a）"
    V6_RT=""
    for _ in $(seq 1 20); do
        V6_RT="$(nsx "$NS_C" ip -6 route show 2>/dev/null \
                 | grep "2001:db8:beef::/48")"
        [ -n "$V6_RT" ] && break
        sleep 0.25
    done
    [ -n "$V6_RT" ] && ok "P5c 内核面装上了 --proxy-cidr6 的 IPv6 路由" \
        || bad "P5c 内核面没装 IPv6 路由"
    if wait_ula_ready; then
        TUN_IP_C="$(dev_ip4 "$NS_C" iwan0)"
        WANT_ULA="$(ula_of "${TUN_IP_C%%/*}")/96"
        [ "$(dev_ip6 "$NS_C" iwan0)" = "$WANT_ULA" ] \
            && ok "P5d 内核面也配好了派生 ULA $WANT_ULA（route_iface_up 的 v6 侧）" \
            || bad "P5d iwan0 的 v6 地址是 $(dev_ip6 "$NS_C" iwan0)，期望 $WANT_ULA"
    else
        bad "P5d iwan0 上一直没有可用的派生 ULA（DAD 没过或地址没配）"
    fi
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] \
        && ok "P5e 内层 IPv6 TCP echo 经内核数据面往返一致（本轮新能力）" \
        || { bad "P5e 内层 IPv6 echo 失败: $OUT"; v6_fail_hint "$LOG_C.p5a"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "P5f 同一会话内层 IPv4 仍通（双栈共存）" \
        || bad "P5f 内层 IPv4 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 20); do
        nsx "$NS_C" ip -6 route show 2>/dev/null \
            | grep -q "2001:db8:beef::/48" || break
        sleep 0.25
    done
    nsx "$NS_C" ip -6 route show 2>/dev/null | grep -q "2001:db8:beef::/48" \
        && bad "P5g 退出后 IPv6 路由还在（没回滚）" \
        || ok "P5g 退出后 IPv6 路由已回滚"

    say "P5h 显式 --data-plane kernel + --proxy-cidr6（切片 0 的拒绝已翻转）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user bob --pass s3cret-pass \
        --data-plane kernel --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p5h" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5h" "kernel data plane running" 25; then
        ok "P5h 显式内核面 + --proxy-cidr6 正常建立会话（不再按用法错误拒绝）"
    else
        bad "P5h 显式内核面 + v6 没起来（见 $LOG_C.p5h）"
    fi
    grep -q "只在 TUN 数据面下有效\|静默黑洞" "$LOG_C.p5h" \
        && bad "P5h2 还在报「v6 只在 TUN 面有效」（切片 0 的守卫没拆干净）" \
        || ok "P5h2 不再出现「内核面不支持内层 v6」的拒绝文本"
    wait_ula_ready || true
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] && ok "P5i 显式内核面下内层 IPv6 echo 也通" \
        || { bad "P5i 内层 IPv6 echo 失败: $OUT"; v6_fail_hint "$LOG_C.p5h"; }
    stop_cli "$CLI"; CLI=""

    say "P5j 绑网卡 + --proxy-cidr6（切片 0 的互斥已翻转）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user carol --pass s3cret-pass \
        --bind-dev "$VETH_C" --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p5j" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5j" "kernel data plane running" 25; then
        ok "P5j 绑网卡（强制内核面）与 --proxy-cidr6 不再冲突"
    else
        bad "P5j 绑定 + v6 没起来（见 $LOG_C.p5j）"
    fi
    grep -q "绑定方式=绑网卡 $VETH_C" "$LOG_C.p5j" \
        && ok "P5j2 绑定确实生效" \
        || bad "P5j2 绑定日志不符: $(grep 绑定方式 "$LOG_C.p5j" | head -1)"
    wait_ula_ready || true
    OUT="$(echo_probe6)"
    [ "$OUT" = "v6-probe" ] && ok "P5k 绑定会话里内层 IPv6 echo 往返一致" \
        || { bad "P5k 内层 IPv6 echo 失败: $OUT"; v6_fail_hint "$LOG_C.p5j"; }
    stop_cli "$CLI"; CLI=""

    say "P5l TUN 面 + --proxy-cidr6 仍照旧装 IPv6 路由（回归）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane tun --proxy-cidr6 2001:db8:beef::/48 --tun iwan9 \
        >"$LOG_C.p5l" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p5l" "TUN proxy running" 25; then
        ok "P5l TUN 面起来了"
    else
        bad "P5l TUN 面没起来（见 $LOG_C.p5l）"
    fi
    V6_RT=""
    for _ in $(seq 1 20); do
        V6_RT="$(nsx "$NS_C" ip -6 route show 2>/dev/null \
                 | grep "2001:db8:beef::/48")"
        [ -n "$V6_RT" ] && break
        sleep 0.25
    done
    [ -n "$V6_RT" ] && ok "P5l2 TUN 面照旧装上 IPv6 路由（能力没被改坏）" \
        || bad "P5l2 TUN 面没装 IPv6 路由"
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 20); do
        nsx "$NS_C" ip -6 route show 2>/dev/null \
            | grep -q "2001:db8:beef::/48" || break
        sleep 0.25
    done
    nsx "$NS_C" ip -6 route show 2>/dev/null | grep -q "2001:db8:beef::/48" \
        && bad "P5l3 TUN 面退出后 IPv6 路由还在" \
        || ok "P5l3 TUN 面退出后 IPv6 路由已回滚"

    # 保留的 FLAGS 位（bit1 = 曾计划的"内核代答 PT_PING_REQ"）必须被拒：
    # ABI 只定义了 CREATE_DEV，宁可拒绝也不假装支持。同一组参数不带保留
    # 位能成功、带保留位必失败 —— 差别只有那一位，因此这个判据不依赖文本。
    # --no-create-dev 让这组用例既不建 iwan0 也不碰 veth。
    nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
        --key 0000000000000000 --outer-src 127.0.0.1 --outer-dst 127.0.0.2 \
        --dport 1234 --no-create-dev >"$LOG_C.p5m" 2>&1 \
        && ok "P5m 对照组：不带保留位能建立会话" \
        || bad "P5m 对照组就失败了（见 $LOG_C.p5m）"
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    [ "$(stat_of "$NS_C" sid)" = "0" ] \
        && [ -z "$(dev_kind "$NS_C" iwan0)" ] \
        && ok "P5m2 对照组收干净（无会话、无 iwan0）" \
        || bad "P5m2 对照组有残留：sid=$(stat_of "$NS_C" sid) kind=$(dev_kind "$NS_C" iwan0)"
    nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
        --key 0000000000000000 --outer-src 127.0.0.1 --outer-dst 127.0.0.2 \
        --dport 1234 --no-create-dev --reserved-flag-bit1 \
        >"$LOG_C.p5n" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "P5n 保留位置位被拒（rc=$RC）" \
        || bad "P5n 保留位居然被接受"
    [ "$(stat_of "$NS_C" sid)" = "0" ] && ok "P5o 被拒后没有会话残留" \
        || bad "P5o sid 非 0：$(stat_of "$NS_C" sid)"

    # ------------------------------------------------- P6 外层 IPv6（切片 2）
    #
    # 服务端同时监听 v4/v6（同一端口），客户端按 --server 的**字面量地址族**
    # 自动选外层：这次会话的外层头就是 IPv6，内核模块的 v6 钩子/解析/发出
    # 全链都在真往返里过一遍。两组数据面用例分别覆盖两条投递路：
    #   · 内层 v4 经外层 v6 = 版本不同 -> netif_rx 重新入栈；
    #   · 内层 v6 经外层 v6 = 版本相同 -> v6 钩子上 NF_ACCEPT 原地继续。
    say "P6 外层 IPv6：按 --server 的字面量地址族自动选外层"
    if [ "$V6_OK" != 1 ]; then
        say "P6 跳过：本机没有可用的外层 IPv6（见 C0）"
    else
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "[$OUTER6_S]" --port "$PORT" --user carol --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.p6" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p6" "kernel data plane running" 25; then
        ok "P6a 外层 v6 会话建立（--server [v6] 自动选外层 v6）"
    else
        bad "P6a 外层 v6 会话没起来（见 $LOG_C.p6）"
        tail -8 "$LOG_C.p6"
    fi
    grep -q "外层v6" "$LOG_C.p6" && ok "P6b 客户端日志声明外层 v6 端点" \
        || bad "P6b 缺外层 v6 声明（见 $LOG_C.p6）"
    grep -q "\[::\]:$PORT" "$LOG_S" && ok "P6c 服务端 v6 监听已打开" \
        || bad "P6c 服务端没有 v6 监听行（见 $LOG_S）"
    [ "$(stat_of "$NS_C" sid)" != "0" ] && ok "P6d 内核里确有会话（sid 非 0）" \
        || bad "P6d 内核里没有会话"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] \
        && ok "P6e 内层 v4 经外层 v6 往返一致（跨版本 -> netif_rx 重新入栈）" \
        || { bad "P6e 内层 v4 经外层 v6 失败: $OUT"; v6_fail_hint "$LOG_C.p6"; }
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "[$OUTER6_S]" --port "$PORT" --user dave --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr6 2001:db8:beef::/48 \
        >"$LOG_C.p6b" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.p6b" "kernel data plane running" 25; then
        ok "P6f 外层 v6 会话 + --proxy-cidr6 建立"
    else
        bad "P6f 没起来（见 $LOG_C.p6b）"
        tail -8 "$LOG_C.p6b"
    fi
    if wait_ula_ready; then
        OUT="$(echo_probe6)"
        [ "$OUT" = "v6-probe" ] \
            && ok "P6g 内层 v6 经外层 v6 往返一致（同版本 -> 原地投递）" \
            || { bad "P6g 内层 v6 经外层 v6 失败: $OUT"; v6_fail_hint "$LOG_C.p6b"; }
    else
        bad "P6g 客户端 iwan0 上没有派生的 v6 地址（ULA）"
        v6_fail_hint "$LOG_C.p6b"
    fi
    stop_cli "$CLI"; CLI=""
    for _ in $(seq 1 40); do
        [ -z "$(dev_kind "$NS_C" iwan0)" ] && break
        sleep 0.25
    done

    # ABI 判据（都不建卡；先把上一段的会话清干净，让 P6l 只反映本段三个用例）
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    for _ in $(seq 1 20); do
        [ "$(stat_of "$NS_C" sid)" = "0" ] && break
        sleep 0.25
    done
    # 外层 v6 可达性前置。为什么必须有这条：无绑定 IP 时内核**有意容忍**外层
    # 路由解析失败（那是给"设备先建、路由后到"留的口子），一旦解析不到，
    # iwan_carrier_resolve6 会在 MTU 判据之前就返回，于是 P6h 变成"没走到判据"
    # 而不是"判据被推翻"。把地址与解析现场钉进日志，别让用例变成谜面。
    nsx "$NS_C" ip -6 addr show dev "$VETH_C" >"$LOG_C.p6rt" 2>&1
    nsx "$NS_C" ip -6 route get "$OUTER6_S" >>"$LOG_C.p6rt" 2>&1
    if grep -q "$OUTER6_C" "$LOG_C.p6rt" && grep -q "dev $VETH_C" "$LOG_C.p6rt"; then
        ok "P6m 前置：外层 v6 地址与解析路由仍在（$OUTER6_C 经 $VETH_C）"
    else
        bad "P6m 前置失败：外层 v6 地址/路由不见了（见 $LOG_C.p6rt）"
    fi
    VETH_MTU="$(nsx "$NS_C" cat "/sys/class/net/$VETH_C/mtu" 2>/dev/null)"
    VETH_C_OIF="$(nsx "$NS_C" cat "/sys/class/net/$VETH_C/ifindex" 2>/dev/null)"
    # 外层 v6 的封装开销 = IWAN_OVERHEAD_V6 = 8B 帧头 + 8B UDP + 40B IPv6 = 56
    #（kernel/iwan.h；既不是 v4 的 36，也不是早期文档里写错的 72）。
    OW6=56
    GOOD_MTU=$(( ${VETH_MTU:-1500} - OW6 ))
    BAD_MTU=$(( GOOD_MTU + 1 ))
    # 边界用例：恰好装得下必须能建立 —— 判据过严同样是错的，只测"多 1 被拒"
    # 无法区分"判据正确"与"判据把一切都拒了"。
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --mtu "$GOOD_MTU" \
            --no-create-dev >"$LOG_C.p6c0" 2>&1; then
        ok "P6h0 边界：内层 MTU $GOOD_MTU + 封装 $OW6 = 承载 MTU $VETH_MTU，恰好装得下 → 建立"
    else
        bad "P6h0 边界：内层 MTU $GOOD_MTU + 封装 $OW6 = $VETH_MTU 却被拒（判据过严）"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --mtu "$BAD_MTU" \
            --no-create-dev >"$LOG_C.p6c" 2>&1; then
        P6H_RC=0
    else
        P6H_RC=$?
    fi
    # 内核侧现场：建立与拒绝都要抓 —— 拒绝时正是要知道为什么拒
    dmesg 2>/dev/null | grep "外层 v6" | tail -6 >"$LOG_C.p6dmesg" 2>&1 || true
    if [ "$P6H_RC" = 0 ]; then
        bad "P6h 内层 MTU $BAD_MTU + 封装 $OW6 超过承载 MTU $VETH_MTU 却被接受"
        printf '    回执里的 carrier=（非空=解析成功、走到了 MTU 判据）：%s\n' \
            "$(grep -o 'carrier=[0-9]*' "$LOG_C.p6c" 2>/dev/null | head -1)"
        printf '    内核侧外层 v6 解析记录：%s\n' \
            "$(tr '\n' '|' <"$LOG_C.p6dmesg" 2>/dev/null | cut -c1-300)"
        printf '    外层 v6 解析现场：%s\n' \
            "$(tr '\n' '|' <"$LOG_C.p6rt" 2>/dev/null | cut -c1-200)"
        printf '    iwan_ctl 回执：%s\n' \
            "$(tr '\n' ' ' <"$LOG_C.p6c" 2>/dev/null | cut -c1-200)"
    else
        ok "P6h 内层 MTU + v6 封装超过承载网卡 MTU 被拒（外层 v6 不分片）"
    fi
    # 判据的"人话"有两条出口：EXTACK（iwan_ctl 只印 errno 文本，客户端会印
    # 内核给的说明）与内核日志（iwan_carrier_resolve6 的拒绝行）。命中其一
    # 即算说明到位。
    if grep -q "装不下\|超过承载网卡" "$LOG_C.p6c" ||
       grep -q "超过承载网卡" "$LOG_C.p6dmesg"; then
        ok "P6i 拒绝原因指向 MTU/封装开销（EXTACK 或内核日志）"
    else
        bad "P6i 拒绝原因不含 MTU 说明（见 $LOG_C.p6c 与 $LOG_C.p6dmesg）"
    fi
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src "$OUTER_C" \
            --outer-dst "$OUTER_S" --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --no-create-dev \
            >"$LOG_C.p6d" 2>&1; then
        bad "P6j v4/v6 两对地址同时给却被接受"
    else
        ok "P6j 外层地址两族同时给被拒（族必须唯一）"
    fi
    # 同一判据的"绑了承载网卡"版本：绑定路径不容忍解析错误，所以这条不依赖
    # "解析当时能不能成"。两条一起看才知道是判据没求值还是判据被推翻。
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --oif "$VETH_C_OIF" \
            --dport 1234 --mtu "$BAD_MTU" --no-create-dev \
            >"$LOG_C.p6c2" 2>&1; then
        bad "P6h2 绑了承载网卡 $VETH_C（MTU $VETH_MTU）仍接受内层 MTU $BAD_MTU"
    else
        ok "P6h2 绑承载网卡版本也被拒（绑定路径不容忍解析错误）"
    fi
    # 被拒的请求不应留下会话（P6h/P6h2 两条都算）；先断言再清场，
    # 否则最后的 P6l 会被我们自己清掉而失去意义。
    if [ "$(stat_of "$NS_C" sid)" = "0" ]; then
        ok "P6h3 被拒的 v6 外层请求没有留下会话"
    else
        bad "P6h3 被拒后仍有残留：sid=$(stat_of "$NS_C" sid)"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    # v6 会话省略 --mtu 时的默认值必须按 **v6** 开销算：1500 - 56 = 1444。
    # 按 v4 的 36 算会得到 1464，而 1464 + 56 > 1500 —— 默认配置自己就违规，
    # 会被 MTU 判据拒。所以"能建立且回执 MTU=1444"就是这个修复的回归测试。
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --dport 1234 --no-create-dev \
            >"$LOG_C.p6n" 2>&1 && grep -q "MTU=1444" "$LOG_C.p6n"; then
        ok "P6n v6 会话省略 --mtu 的默认值按 v6 开销算（1444 = 1500 - 56）"
    else
        bad "P6n v6 默认 MTU 不是 1444：$(tr '\n' ' ' <"$LOG_C.p6n" 2>/dev/null | cut -c1-160)"
    fi
    nsx "$NS_C" "$WORK/iwan_ctl" session-down >/dev/null 2>&1
    if nsx "$NS_C" "$WORK/iwan_ctl" session-up --sid 1 --tok 1 --enc 1 \
            --key 0000000000000000 --outer-src6 "$OUTER6_C" \
            --outer-dst6 "$OUTER6_S" --ip6 2001:db8:1ce::9 --dport 1234 \
            --no-create-dev >"$LOG_C.p6e" 2>&1; then
        bad "P6k 绑定的出口 v6 IP 不属于本机却被接受"
    else
        ok "P6k 绑定的出口 v6 IP 不在本机地址表里被拒"
    fi
    [ "$(stat_of "$NS_C" sid)" = "0" ] && ok "P6l 三个被拒用例都没有残留会话" \
        || bad "P6l 有残留：sid=$(stat_of "$NS_C" sid)"
    fi

    # ======================================================== 回程路由（R1）
    # 场景：被服务前缀 203.0.113.0/24 里有台机器**不在**隧道另一侧，而是
    # 直连在本机另一张网卡上（/32 直连路由比 --proxy-cidr 的 /24 更具体）。
    # 它发来的连接：目的地址在被服务集合内、但从非承载网卡进入 —— 必须
    # 如期绕过 iwan（不打 conntrack 标记、回包不塞进隧道）。
    say "R1 回程路由（conntrack）：被服务前缀里、从非承载网卡来的连接绕过 iwan"

    mk_netns "$NS_L" || die "ip netns add $NS_L 失败"
    ip link add "$VETH_LC" type veth peer name "$VETH_LL" || die "建 LAN veth 失败"
    ip link set "$VETH_LC" netns "$NS_C"
    ip link set "$VETH_LL" netns "$NS_L"
    nsx "$NS_C" ip link set lo up
    nsx "$NS_L" ip link set lo up
    nsx "$NS_C" ip addr add "$RR_SERVED/32" dev "$VETH_LC"
    nsx "$NS_C" ip link set "$VETH_LC" up
    nsx "$NS_C" ip route add "$RR_PEER/32" dev "$VETH_LC"
    nsx "$NS_L" ip addr add "$RR_PEER/32" dev "$VETH_LL"
    nsx "$NS_L" ip link set "$VETH_LL" up
    nsx "$NS_L" ip route add "$RR_SERVED/32" dev "$VETH_LL"
    if nsx "$NS_L" ping -c 1 -W 3 "$RR_SERVED" >/dev/null 2>&1; then
        ok "R1a LAN 侧 /32 点对点直连可用（$RR_PEER -> $RR_SERVED）"
    else
        bad "R1a LAN 侧 /32 直连不通"
    fi

    # 被服务地址上的监听：回包的去向就是这条用例的全部内容
    ip netns exec "$NS_C" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$RR_SERVED', $RR_PORT))
s.listen(4)
while True:
    c, _ = s.accept()
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
    bg_resolve RRLAN python3

    # 客户端给了 v4 --proxy-cidr* 就进入"接管默认路由"模型：起步先 capture_default()
    # 记下原默认（退出时好还原），没有默认路由就直接拒绝启动（kdp.c）。
    # 本 netns 建的时候没有默认路由（C10d 因此说"没被动过"），这里补一条。
    # 注意它会被客户端接管成"默认走 iwan0"——见下面 R2a2 的说明，R 组收尾会删掉。
    nsx "$NS_C" ip route add default via "$OUTER_S" dev "$VETH_C" 2>/dev/null || true
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --reply-via-tunnel >"$LOG_C.rr" 2>&1 &
    bg_resolve RRCLI iwan-client
    RR_UP=0
    if wait_log "$LOG_C.rr" "kernel data plane running" 25; then
        RR_UP=1
        ok "R1b --reply-via-tunnel + --proxy-cidr 下进入运行态"
    else
        bad "R1b 客户端没起来（见 $LOG_C.rr）"; tail -14 "$LOG_C.rr"
    fi
    # 规则安装发生在 SESSION_UP 之后，与"运行态"日志的先后不保证：等一小会儿
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        grep -q "回程路由" "$LOG_C.rr" && break
        sleep 0.3
    done
    grep -q "回程路由: 已开" "$LOG_C.rr" \
        && ok "R1c 回程路由规则已装（客户端日志有交代）" \
        || bad "R1c 日志里没有回程路由的交代（见 $LOG_C.rr）"

    RR_RT="$(nsx "$NS_C" ip route get "$RR_PEER" from "$RR_SERVED" 2>&1)"
    if [ "$RR_UP" = 1 ] && printf '%s' "$RR_RT" | grep -q "dev $VETH_LC"; then
        ok "R1d 反例路由：$RR_SERVED -> $RR_PEER 走 $VETH_LC（没被代理前缀带进隧道）"
    else
        bad "R1d 反例路由走了别处：$RR_RT"
    fi

    RR_ECHO="$(nsx "$NS_L" python3 -c "
import socket, sys
s = socket.create_connection(('$RR_SERVED', $RR_PORT), 5)
s.sendall(b'reply-bypass')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1)"
    [ "$RR_UP" = 1 ] && [ "$RR_ECHO" = "reply-bypass" ] \
        && ok "R1e 反例连接真通（回包真到了对端，不是被塞进隧道）" \
        || bad "R1e 反例连接失败：$RR_ECHO"

    # /proc/net/nf_conntrack 的 mark= 是**十进制**（ip rule 那边才是 0x1），
    # 而且要先把这条流找出来 —— 只查"没有 mark="会空转通过。
    # "如期绕过"的判据是规则口径：标记只认承载网卡那一半。不要拿
    # /proc/net/nf_conntrack 当判据 —— 没触发过 ct 求值的 netns 里它可能
    # 根本不存在，"读不到"既不能算通过也不该算失败。
    RR_RULES="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null || true)"
    [ -n "$RR_RULES" ] || RR_RULES="$(nsx "$NS_C" iptables -t mangle -S 2>/dev/null || true)"
    if [ "$RR_UP" = 1 ] && printf '%s' "$RR_RULES" | grep -q "$VETH_C" &&
       ! printf '%s' "$RR_RULES" | grep -q "$VETH_LC"; then
        ok "R1f 规则只认承载网卡 $VETH_C、不认 LAN 网卡 $VETH_LC（这就是绕过的来源）"
    else
        bad "R1f 规则口径不对：$(printf '%s' "$RR_RULES" | tr '\n' '|' | cut -c1-200)"
    fi
    # 附加（只在 proc 文件存在时做）：这条流确实没有标记
    if [ "$RR_UP" = 1 ] && nsx "$NS_C" test -r /proc/net/nf_conntrack; then
        RR_CT="$(nsx "$NS_C" sh -c "grep '$RR_PEER' /proc/net/nf_conntrack 2>/dev/null" || true)"
        if [ -n "$RR_CT" ] && printf '%s' "$RR_CT" | grep -q "mark=1\b"; then
            bad "R1f2 被服务前缀里的直连连接被打上了标记"
        else
            ok "R1f2 conntrack 里这条流没有标记（附加确认）"
        fi
    fi

    stop_cli "$RRCLI"
    RR_RULE_L="$(nsx "$NS_C" ip rule show 2>/dev/null | grep -c "fwmark $RR_MARK" || true)"
    RR_TBL_L="$(nsx "$NS_C" ip route show table "$RR_TABLE" 2>/dev/null | grep -c . || true)"
    RR_NFT_L="$(nsx "$NS_C" nft list tables 2>/dev/null | grep -c iwan_reply || true)"
    [ "$RR_UP" = 1 ] && [ "${RR_RULE_L:-1}" = "0" ] && [ "${RR_TBL_L:-1}" = "0" ] && [ "${RR_NFT_L:-1}" = "0" ] \
        && ok "R1g 退出后 rule/表/nft 全部回滚（rule=$RR_RULE_L 表=$RR_TBL_L nft=$RR_NFT_L）" \
        || bad "R1g 有残留：rule=$RR_RULE_L 表=$RR_TBL_L nft=$RR_NFT_L"

    # ---- (d) 先决检查：内核面钩子必须早于 conntrack（或 reinject=1）
    # 改的是**参数值本身**，判据读的就是它；已注册的钩子不会因此移动，所以
    # 只影响这条判据、不影响正在跑的流量。跑完立刻恢复原值。
    RR_P_HOOK="$(cat /sys/module/iwan/parameters/hooknum 2>/dev/null)"
    RR_P_REIN="$(cat /sys/module/iwan/parameters/reinject 2>/dev/null)"
    if [ -n "$RR_P_HOOK" ] && [ -n "$RR_P_REIN" ]; then
        echo 1 >/sys/module/iwan/parameters/hooknum 2>/dev/null || true
        echo 0 >/sys/module/iwan/parameters/reinject 2>/dev/null || true
        RR_REF="$(timeout 20 ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
            --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
            --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
            --reply-via-tunnel 2>&1 </dev/null | head -40 || true)"
        echo "$RR_P_HOOK" >/sys/module/iwan/parameters/hooknum 2>/dev/null || true
        echo "$RR_P_REIN" >/sys/module/iwan/parameters/reinject 2>/dev/null || true
        printf '%s' "$RR_REF" | grep -q "钩子不在 conntrack 之前" \
            && ok "R1h 钩子晚于 conntrack 时拒绝启动并说明理由" \
            || bad "R1h 没有拒绝或没说理由：$(printf '%s' "$RR_REF" | tr '\n' '|' | cut -c1-200)"
        sleep 1
        [ "$(stat_of "$NS_C" sid)" = "0" ] && [ -z "$(dev_kind "$NS_C" iwan0)" ] \
            && ok "R1h2 被拒后没有留下会话或 iwan0" \
            || bad "R1h2 被拒后有残留：sid=$(stat_of "$NS_C" sid) iwan0=$(dev_kind "$NS_C" iwan0)"
    else
        bad "R1h 读不到 /sys/module/iwan/parameters/{hooknum,reinject}"
    fi

    # ---- (b) 从隧道进来的连接：回包必须按来路回去，而且**没有它就真发不回去**
    say "R2 回程路由：从隧道进来的连接按来路回去（标记必需，不是锦上添花）"
    # 对端在隧道另一侧，源地址取内层 /16 里**不在 iwan0 那条 /24 上**的地址：
    # 主表对 198.18.7.7 没有任何路由（既不在 198.18.0.0/24 直连里，也没有
    # --proxy-cidr 覆盖），回包只能落到默认路由——也就是物理网卡。于是
    # "回程路由不生效"= 真的发不回去，而不是"恰好也通"。
    # 连接终结在**会话自己的内层地址** 198.18.0.2 上，而不是被服务的
    # 203.0.113.1：回包的源地址就是连接的本端地址，而服务端对隧道内层包有
    # 源地址准入，源若不是本会话分配的地址会被当伪造丢掉。所以被服务集合里
    # 额外加上 198.18.0.2/32（-d 这一半照样成立），对端仍从 198.18.7.7 发起。
    nsx "$NS_S" ip addr add 198.18.7.7/32 dev iwan-srv 2>/dev/null || true

    # 对端探针：绑 198.18.7.7 发起连接（失败返回 FAIL:<异常名>，不当成崩溃）
    rr_peer_probe() {
        # 每次探测前重读**本次**会话的内层地址：同一账号重连拿到的内层 IP
        # 不同（run5 现场：R2a 是 .14，R2b 换了一个），沿用上一轮的地址会打到
        # "这个地址不属于任何会话"上，被服务端按无人认领丢掉 —— 现象就是
        # 监听一次都没 accept、探针超时。
        RR_INNER="$(nsx "$NS_C" ip -4 -o addr show dev iwan0 2>/dev/null |
            awk '{print $4}' | cut -d/ -f1 | head -1)"
        nsx "$NS_S" python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(6)
s.bind(('198.18.7.7', 0))
try:
    s.connect(('$RR_INNER', $RR_PORT2))
except Exception as e:
    sys.stdout.write('FAIL:' + type(e).__name__)
    raise SystemExit(0)
s.sendall(b'reply-via-tunnel')
d = s.recv(64)
s.close()
sys.stdout.write(d.decode())
" 2>&1
    }

    # R2a 反证：不开 --reply-via-tunnel 时必须发不回去
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --proxy-cidr 198.18.0.0/24 >"$LOG_C.rr2a" 2>&1 &
    bg_resolve RRCLI2A iwan-client
    RR2A_UP=0
    if wait_log "$LOG_C.rr2a" "kernel data plane running" 25; then
        RR2A_UP=1
    else
        bad "R2 前置：不开回程的客户端没起来"; tail -8 "$LOG_C.rr2a"
    fi
    sleep 1
    RR_INNER_RT="$(nsx "$NS_C" ip -4 -o addr show dev iwan0 2>/dev/null |
        awk '{print $4}' | cut -d/ -f1 | head -1)"
    if [ -n "$RR_INNER_RT" ]; then
        RR_INNER="$RR_INNER_RT"
        ok "R2 前置：本次会话的内层地址 = $RR_INNER"
    else
        bad "R2 前置：读不到 iwan0 的内层地址，回退 $RR_INNER"
    fi
    ip netns exec "$NS_C" python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $RR_PORT2))
s.listen(8)
while True:
    c, a = s.accept()
    open('$LOG_C.rrtun.accept', 'a').write('accept from %s -> %s\n' % (a, c.getsockname()))
    d = c.recv(64)
    c.sendall(d)
    c.close()
" >/dev/null 2>&1 &
    bg_resolve RRTUN python3
    sleep 0.3
    # 说明（原先这里断言"不带标记时不走 iwan0"，在本环境不成立也不该成立）：
    # 客户端给了 v4 --proxy-cidr 就会接管默认路由 ⇒ 主表默认已经指向 iwan0，
    # 于是对 198.18.7.7 这种"没有更具体路由"的地址，不带标记也走隧道。
    # 这不是缺陷：全局走隧道时回程规则本就是冗余的（见 docs/reply-routing.md
    # 的"已定项"）。真正需要回程规则的场景是"只代理若干前缀、默认路由还给
    # 物理网卡"，那需要一份 v6 版本的用例（v6 的 --proxy-cidr6 不触发接管），
    # 列为后续项。这里只记录观察，不作断言。
    RR_NOMARK_RT="$(nsx "$NS_C" ip route get 198.18.7.7 from "$RR_INNER" 2>&1)"
    printf '    R2a2 观察：不带标记时主表查路由 => %s\n' \
        "$(printf '%s' "$RR_NOMARK_RT" | head -1 | cut -c1-120)"
    RR_NOFLAG="$(rr_peer_probe)"
    # 这里**不**断言"必须连不上"：本 e2e 里客户端的物理网卡与服务端是同一条
    # veth，漏出去（未封装）的回包会落到服务端主机上，而服务端的 iwan-srv 正好
    # 持有 198.18.7.7 —— 于是"漏出去"也能侥幸到达。真实网络里物理网卡通向
    # 别处，漏出去就是发不回去。判据只取确定性的两条（R2a2 不带标记的路由、
    # R2a3 不带标记就没有 conntrack 标记），下面只记录观察结果。
    case "$RR_NOFLAG" in
        FAIL:*) printf '    R2a 观察：不开开关时对端连不上（%s）\n' "$RR_NOFLAG" ;;
        *) printf '    R2a 观察：不开开关时对端仍连上了（%s）—— 拓扑局限，见注释\n' "$RR_NOFLAG" ;;
    esac
    # 不要用"读 /proc/net/nf_conntrack 没读到标记"当判据：本机内核没开
    # 那个 compat procfs，文件根本不存在，"读不到"会永远通过（空转）。
    # 直接查规则：不开开关时**不该有任何**回程路由规则/表。
    RR_RULES_A="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null || true)"
    [ -n "$RR_RULES_A" ] || RR_RULES_A="$(nsx "$NS_C" iptables -t mangle -S 2>/dev/null | grep -i connmark || true)"
    if [ "$RR2A_UP" = 1 ] && [ -z "$RR_RULES_A" ]; then
        ok "R2a3 不开开关时没有任何回程路由规则（规则确实没装）"
    else
        bad "R2a3 不开开关却装了规则：$(printf '%s' "$RR_RULES_A" | tr '\n' '|' | cut -c1-160)"
    fi
    stop_cli "$RRCLI2A"

    # R2b/R2c/R2d 正证
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --proxy-cidr "$RR_CIDR" \
        --proxy-cidr 198.18.0.0/24 --reply-via-tunnel >"$LOG_C.rr2b" 2>&1 &
    bg_resolve RRCLI2B iwan-client
    RR2B_UP=0
    if wait_log "$LOG_C.rr2b" "kernel data plane running" 25; then
        RR2B_UP=1
    else
        bad "R2 前置：开回程的客户端没起来"; tail -8 "$LOG_C.rr2b"
    fi
    sleep 1
    # 直接取证标记：本机没有 /proc/net/nf_conntrack（compat procfs 未开），
    # 也没有 conntrack 工具。于是往客户端自己的 nft 表末尾追加一条
    # "数已标记包"的规则 —— 它排在打标记的规则之后，命中数 > 0 即证明标记
    # 真的打上了。整张表在客户端退出时由它自己删掉，不用额外清理。
    RR_CNT_OK=0
    nsx "$NS_C" nft add rule inet iwan_reply pre ct mark 0x1 counter \
        >/dev/null 2>&1 && RR_CNT_OK=1
    RR_FLAG="$(rr_peer_probe)"
    [ "$RR2B_UP" = 1 ] && [ "$RR_FLAG" = "reply-via-tunnel" ] \
        && ok "R2b 从隧道进来的连接按来路回去了（回包经 iwan0 到达对端）" \
        || bad "R2b 开了回程路由仍然不通：$RR_FLAG"
    printf '    R2 现场 rule：%s\n' \
        "$(nsx "$NS_C" ip rule show 2>&1 | tr '\n' '|' | cut -c1-200)"
    printf '    R2 现场 表 %s：%s\n' "$RR_TABLE" \
        "$(nsx "$NS_C" ip route show table "$RR_TABLE" 2>&1 | tr '\n' '|' | cut -c1-200)"
    printf '    R2 现场 监听收到的连接：%s\n' \
        "$(tr '\n' '|' <"$LOG_C.rrtun.accept" 2>/dev/null | cut -c1-200)"
    # nft 把标记规范化成 0x00000001 打印（不是 0x1），别拿 "ct mark 0x1"
    # 去匹配；用"同时含 ct mark 与 counter 的行"取计数。
    RR_CNT="$(nsx "$NS_C" nft list table inet iwan_reply 2>/dev/null |
        grep "ct mark" | grep "counter" | grep -o "packets [0-9]*" |
        head -1 | awk '{print $2}')"
    printf '    R2c 取证：计数规则装上了=%s，已标记包数=%s\n' "$RR_CNT_OK" "${RR_CNT:-无}"
    printf '    R2c 取证：表内容=%s\n' \
        "$(nsx "$NS_C" nft list table inet iwan_reply 2>&1 | tr '\n' '|' | tr -s ' ' | cut -c1-400)"
    if [ "$RR2B_UP" = 1 ] && [ "$RR_CNT_OK" = 1 ] && [ -n "$RR_CNT" ] && [ "$RR_CNT" -gt 0 ]; then
        ok "R2c 标记确实打上了（nft 计数规则数到 $RR_CNT 个已标记包）"
    elif [ "$RR_CNT_OK" != 1 ]; then
        # 没有 nft（走了 iptables 回退）时无法这样取证：退回到规则口径断言
        if printf '%s' "$RR_RULES" | grep -q "$VETH_C"; then
            ok "R2c 无 nft 无法直接计数，退回规则口径：规则认的是承载网卡 $VETH_C"
        else
            bad "R2c 无法取证标记，且规则口径也不对"
        fi
    else
        bad "R2c 计数规则在，但没有数到任何已标记包（标记没打上）"
    fi
    RR_RT2="$(nsx "$NS_C" ip route get 198.18.7.7 mark 1 2>&1)"
    [ "$RR2B_UP" = 1 ] && printf '%s' "$RR_RT2" | grep -q "dev iwan0" \
        && ok "R2d 带标记查路由走 iwan0（回程规则真的接上了）" \
        || bad "R2d 带标记仍不走 iwan0：$RR_RT2（rule/表见上）"
    stop_cli "$RRCLI2B"
    # R 组收尾：把为 v4 接管模型补的那条默认路由删掉，后面的组看到原样
    nsx "$NS_C" ip route del default 2>/dev/null || true
    [ -z "$(nsx "$NS_C" ip route show default 2>/dev/null)" ] \
        && ok "R2e R 组收尾：默认路由已还原（后续组看到原样）" \
        || bad "R2e 默认路由有残留：$(nsx "$NS_C" ip route show default 2>&1)"
fi

# ---------------------------------------------------------------- 绑定的三模式（--bind）

if [ "$BIND" = 1 ]; then
    OIF_C="$(nsx "$NS_C" cat /sys/class/net/$VETH_C/ifindex)"

    say "B1 绑出口 IP（--bind-ip $OUTER_C，genetlink IWAN_A_IP）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-ip "$OUTER_C" \
        >"$LOG_C.b1" 2>&1 &
    bg_resolve CLI iwan-client
    if wait_log "$LOG_C.b1" "kernel data plane running" 25; then
        ok "B1a 进入内核数据面运行态"
    else
        bad "B1a 没进运行态"; tail -8 "$LOG_C.b1"
    fi
    grep -q "绑定方式=绑出口 IP $OUTER_C" "$LOG_C.b1" \
        && ok "B1b 客户端日志: 绑定方式=绑出口 IP $OUTER_C" \
        || bad "B1b 绑定日志不符: $(grep 绑定方式 "$LOG_C.b1" | head -1)"
    [ "$(stat_of "$NS_C" bind_ip)" = "$OUTER_C" ] \
        && ok "B1c 内核快照 bind_ip=$OUTER_C" \
        || bad "B1c bind_ip=$(stat_of "$NS_C" bind_ip)，期望 $OUTER_C"
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "B1d 实际承载网卡=$VETH_C($OIF_C)：会话建立时由地址表解析并钉住" \
        || bad "B1d carrier=$(stat_of "$NS_C" carrier)，期望 $OIF_C"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "B1e 内层 TCP echo 经绑定的承载网卡往返一致" \
                              || bad "B1e 内层 echo 失败: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""
    [ "$(stat_of "$NS_C" carrier)" = "0" ] \
        && ok "B1f 会话结束后承载网卡回到未钉住（carrier=0）" \
        || bad "B1f carrier=$(stat_of "$NS_C" carrier)，期望 0"

    say "B2 绑网卡（--bind-dev $VETH_C，genetlink IWAN_A_OIF）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-dev "$VETH_C" \
        >"$LOG_C.b2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.b2" "kernel data plane running" 25 && ok "B2a 进入内核数据面运行态" \
        || { bad "B2a 没进运行态"; tail -8 "$LOG_C.b2"; }
    [ "$(stat_of "$NS_C" oif)" = "$OIF_C" ] && [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "B2b 请求 oif=$OIF_C 且实际承载网卡=$OIF_C" \
        || bad "B2b oif=$(stat_of "$NS_C" oif) carrier=$(stat_of "$NS_C" carrier)，期望 $OIF_C"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "B2c 内层 TCP echo 往返一致" || bad "B2c 内层 echo 失败: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    say "B3 负例：绑一个不属于本机的地址 ⇒ 启动即拒绝"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane kernel \
        --bind-ip 192.0.2.1 >"$LOG_C.b3" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B3a 非零退出（$RC）" || bad "B3a 居然成功了"
    grep -q "已不在本机地址表里" "$LOG_C.b3" && ok "B3b 报错文本: 地址不在本机地址表" \
        || bad "B3b 报错文本不符: $(tail -1 "$LOG_C.b3")"

    say "B4 负例：地址与网卡不是同一张 ⇒ 拒绝"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane kernel \
        --bind-dev lo --bind-ip "$OUTER_C" >"$LOG_C.b4" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B4a 非零退出（$RC）" || bad "B4a 居然成功了"
    grep -q "不在承载网卡" "$LOG_C.b4" && ok "B4b 报错文本: 地址不在指定的网卡上" \
        || bad "B4b 报错文本不符: $(tail -1 "$LOG_C.b4")"

    say "B5 负例：TUN 数据面 + 绑定 ⇒ 拒绝（不静默忽略）"
    nsx "$NS_C" "$BIN/iwan-client" proxy --server "$OUTER_S" --port "$PORT" \
        --user alice --pass s3cret-pass --data-plane tun \
        --bind-dev "$VETH_C" >"$LOG_C.b5" 2>&1
    RC=$?
    [ "$RC" != 0 ] && ok "B5a 非零退出（$RC）" || bad "B5a 居然成功了"
    grep -q "只在 --data-plane kernel 下有效" "$LOG_C.b5" && ok "B5b 报错文本: 仅内核数据面" \
        || bad "B5b 报错文本不符: $(tail -1 "$LOG_C.b5")"
fi

# ---------------------------------------------------------------- 失效与恢复（--life）

if [ "$LIFE" = 1 ]; then
    OIF_C="$(nsx "$NS_C" cat /sys/class/net/$VETH_C/ifindex)"
    SID0=""

    # 等内核里的会话真的没了（客户端先 log 再 SESSION_DOWN，两者有时序）
    wait_sid0() {
        local i=0

        while [ "$i" -lt 40 ]; do
            [ "$(stat_of "$NS_C" sid)" = "0" ] && return 0
            sleep 0.25
            i=$((i + 1))
        done
        return 1
    }

    # 有界地停服务端（优雅退出有窗口，别让 wait 挂住）
    stop_srv() {
        local i=0

        [ -n "$SRV" ] || return 0
        kill -INT "$SRV" 2>/dev/null
        while [ "$i" -lt 20 ]; do
            kill -0 "$SRV" 2>/dev/null || break
            sleep 0.25
            i=$((i + 1))
        done
        kill -9 "$SRV" 2>/dev/null
        wait "$SRV" 2>/dev/null
        SRV=""
    }

    # 重启服务端并等**下一次**"server ready."（日志是追加的，只看"出现过"
    # 会把上次启动那行当证据）。上一实例的 TUN 设备正常随进程消失，万一残留
    # 先删掉，免得重启报占用。
    SRV_READY_N=1
    srv_start() {
        nsx "$NS_S" ip link del iwan-srv 2>/dev/null || true
        ip netns exec "$NS_S" "$BIN/iwan-server" --port "$PORT" --tun iwan-srv \
            --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --nat-if "$VETH_S" \
            --dns 198.18.0.1 --users "$USERS" >>"$LOG_S" 2>&1 &
        bg_resolve SRV iwan-server
        SRV_READY_N=$((SRV_READY_N + 1))
        wait_log_n "$LOG_S" "server ready." "$SRV_READY_N" 20
    }

    say "L1 绑网卡失效与恢复（--bind-dev $VETH_C）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-dev "$VETH_C" >"$LOG_C.l1" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l1" "kernel data plane running" 25 && ok "L1a 绑定态下进入运行态" \
        || { bad "L1a 没进运行态"; tail -8 "$LOG_C.l1"; }
    SID0="$(stat_of "$NS_C" sid)"
    [ -n "$SID0" ] && [ "$SID0" != "0" ] && ok "L1b 会话已建立（sid=$SID0）" \
                                      || bad "L1b sid=$SID0"

    nsx "$NS_C" ip link set "$VETH_C" down
    if wait_log "$LOG_C.l1" "绑定失效" 8; then
        ok "L1c 1 秒节拍内发现绑定失效: $(grep 绑定失效 "$LOG_C.l1" | head -1)"
    else
        bad "L1c 没看到绑定失效（见 $LOG_C.l1）"
    fi
    wait_sid0 && ok "L1d 内核部分已关闭（sid=0）" || bad "L1d sid=$(stat_of "$NS_C" sid) 仍非 0"
    [ -z "$(dev_kind "$NS_C" iwan0)" ] \
        && ok "L1e iwan0 已删除（经它的路由随之失效，内层流量交路由表下一条）" \
        || bad "L1e iwan0 还在: $(dev_kind "$NS_C" iwan0)"

    nsx "$NS_C" ip link set "$VETH_C" up
    if wait_log_n "$LOG_C.l1" "内核数据面: 会话已建立" 2 30; then
        ok "L1f 绑定恢复后重新握手成功"
    else
        bad "L1f 没等到重新握手（见 $LOG_C.l1）"
    fi
    SID1="$(stat_of "$NS_C" sid)"
    [ -n "$SID1" ] && [ "$SID1" != "0" ] && ok "L1g 新会话 sid=$SID1（旧 $SID0）" \
                                      || bad "L1g sid=$SID1"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L1h 内层 TCP 经恢复后的会话往返一致" \
                              || bad "L1h 内层 echo 失败: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    say "L2 绑出口 IP 失效与恢复（--bind-ip $OUTER_C）"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 --bind-ip "$OUTER_C" >"$LOG_C.l2" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l2" "kernel data plane running" 25 && ok "L2a 绑定态下进入运行态" \
        || { bad "L2a 没进运行态"; tail -8 "$LOG_C.l2"; }
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "L2b 承载网卡已按出口 IP 钉住（carrier=$OIF_C）" \
        || bad "L2b carrier=$(stat_of "$NS_C" carrier)"

    nsx "$NS_C" ip addr del "$OUTER_C/24" dev "$VETH_C"
    if wait_log "$LOG_C.l2" "绑定失效" 8; then
        ok "L2c 出口 IP 被删后判定绑定失效: $(grep 绑定失效 "$LOG_C.l2" | head -1)"
    else
        bad "L2c 没看到绑定失效（见 $LOG_C.l2）"
    fi
    wait_sid0 && ok "L2d 内核部分已关闭（sid=0）" || bad "L2d sid=$(stat_of "$NS_C" sid) 仍非 0"

    nsx "$NS_C" ip addr add "$OUTER_C/24" dev "$VETH_C"
    if wait_log_n "$LOG_C.l2" "内核数据面: 会话已建立" 2 30; then
        ok "L2e 地址回来后重新握手成功"
    else
        bad "L2e 没等到重新握手（见 $LOG_C.l2）"
    fi
    [ "$(stat_of "$NS_C" carrier)" = "$OIF_C" ] \
        && ok "L2f 重新握手后承载网卡再次钉住（carrier=$OIF_C）" \
        || bad "L2f carrier=$(stat_of "$NS_C" carrier)"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L2g 内层 TCP 经恢复后的会话往返一致" \
                              || bad "L2g 内层 echo 失败: $OUT"
    kill -INT "$CLI" 2>/dev/null; wait "$CLI" 2>/dev/null; CLI=""

    # ---- L3 外层链路断：判死只能来自"无人应答"预算（不涉及绑定）----
    say "L3 外层链路断（无绑定）⇒ 判死来自 keepalive 失败预算"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.l3" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l3" "kernel data plane running" 25 && ok "L3a 进入运行态" \
        || { bad "L3a 没进运行态"; tail -8 "$LOG_C.l3"; }

    # 链路 down ⇒ 每次 send 都 ENETUNREACH（不是隔次上报的 ICMP），三条预算
    # 按 10s 节拍 ⇒ 约 30s 判死；看门狗 120s，所以这里必定是预算赢
    nsx "$NS_C" ip link set "$VETH_C" down
    if wait_log "$LOG_C.l3" "keepalive 失败累计" 45; then
        ok "L3b 判死来自失败预算: $(grep 失败累计 "$LOG_C.l3" | head -1)"
    else
        bad "L3b 预算没判死（见 $LOG_C.l3）"
    fi
    grep -q "IWAN_RX_STALE_MS" "$LOG_C.l3" \
        && bad "L3c 预算先判死，不该再出现看门狗" \
        || ok "L3c 全程没触发看门狗（预算先判死）"
    wait_sid0 && ok "L3d 内核会话已清（sid=0）" || bad "L3d sid=$(stat_of "$NS_C" sid) 仍非 0"

    nsx "$NS_C" ip link set "$VETH_C" up
    wait_log_n "$LOG_C.l3" "内核数据面: 会话已建立" 2 30 \
        && ok "L3e 链路回来后重新握手成功" || bad "L3e 没重新握手（见 $LOG_C.l3）"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L3f 重连后内层 TCP 往返一致" \
                              || bad "L3f 内层 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""

    # ---- L4 服务端端口黑洞：send 全部成功、一个回帧都没有 ⇒ 只剩看门狗 ----
    say "L4 服务端端口黑洞（只收不回）⇒ 判死来自 IWAN_RX_STALE_MS 看门狗"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 IWAN_RX_STALE_MS=30000 \
        "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane kernel --mtu 1400 >"$LOG_C.l4" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l4" "kernel data plane running" 25 && ok "L4a 进入运行态" \
        || { bad "L4a 没进运行态"; tail -8 "$LOG_C.l4"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L4b 服务端在时的内层 TCP 往返一致" \
                              || bad "L4b 内层 echo 失败: $OUT"

    stop_srv
    ip netns exec "$NS_S" python3 -c "
# IWAN_SINK_MARKER
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', $PORT))
while True:
    s.recvfrom(65535)
" >/dev/null 2>&1 &
    SINK_JOB=$!
    sleep 1
    if wait_log "$LOG_C.l4" "IWAN_RX_STALE_MS=30000" 45; then
        ok "L4c 判死来自看门狗: $(grep IWAN_RX_STALE_MS "$LOG_C.l4" | head -1)"
    else
        bad "L4c 看门狗没判死（见 $LOG_C.l4）"
    fi
    grep -q "keepalive 失败累计" "$LOG_C.l4" \
        && bad "L4d send 全成功却出现失败预算（口径不对）" \
        || ok "L4d 全程没有失败预算（说明 send 确实全部成功）"
    wait_sid0 && ok "L4e 内核会话已清（sid=0）" || bad "L4e sid=$(stat_of "$NS_C" sid) 仍非 0"
    stop_cli "$CLI"; CLI=""
    pkill -9 -f "IWAN_SINK_MARKER" 2>/dev/null || true
    wait "$SINK_JOB" 2>/dev/null   # 回收，免得 bash 打一行 "Killed"

    # ---- L5 TUN 数据面：同一条预算，失败事件由接收侧硬错误提供 ----
    say "L5 TUN 数据面：服务端消失 ⇒ 判死来自接收侧硬错误计数"
    srv_start && ok "L5a 服务端已重启" || bad "L5a 服务端没起来"
    ip netns exec "$NS_C" env IWAN_DEBUG=1 "$BIN/iwan-client" proxy \
        --server "$OUTER_S" --port "$PORT" --user alice --pass s3cret-pass \
        --data-plane tun --mtu 1400 >"$LOG_C.l5" 2>&1 &
    bg_resolve CLI iwan-client
    wait_log "$LOG_C.l5" "TUN proxy running" 25 && ok "L5b TUN 会话建立（泵已运行）" \
        || { bad "L5b 没建立（见 $LOG_C.l5）"; tail -8 "$LOG_C.l5"; }
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L5c TUN 数据面内层 TCP 往返一致" \
                              || bad "L5c 内层 echo 失败: $OUT"

    stop_srv
    # 只等 "peer not answering" 会停在第一次计数（1/3）而误判通过；必须等预算
    # 耗尽的那行 "N unanswered transport failures ... session lost"。
    if wait_log "$LOG_C.l5" "unanswered transport failures" 60; then
        ok "L5d 判死: $(grep 'unanswered transport failures' "$LOG_C.l5" | tail -1)"
    else
        bad "L5d 没判死（见 $LOG_C.l5）"
    fi
    grep -q "IWAN_RX_STALE_MS" "$LOG_C.l5" \
        && bad "L5e 预算先判死，不该再出现看门狗" \
        || ok "L5e 全程没触发看门狗（预算先判死）"

    srv_start && ok "L5f 服务端再次重启" || bad "L5f 服务端没起来"
    wait_log_n "$LOG_C.l5" "TUN proxy running" 2 40 \
        && ok "L5g TUN 客户端重连成功（泵第 2 次运行）" \
        || bad "L5g 没重连（见 $LOG_C.l5）"
    OUT="$(echo_probe)"
    [ "$OUT" = "bind-probe" ] && ok "L5h 重连后内层 TCP 往返一致" \
                              || bad "L5h 内层 echo 失败: $OUT"
    stop_cli "$CLI"; CLI=""
fi

# ---------------------------------------------------------------- 汇总

printf '\n== 汇总: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$KEEP" = 1 ]; then
    printf '   --keep: 保留 %s 与两个 netns（%s / %s）、模块不卸载\n' "$WORK" "$NS_C" "$NS_S"
fi
[ "$FAIL" = 0 ] || exit "$FAIL"
