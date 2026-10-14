#!/usr/bin/env bash
# 内核数据面 MTU 阶梯：逐步抬高模块参数 max_mtu，每步只跑 raw 的 c2s（客户端走内核
# 数据面 iwan0，服务端是仅计量端点 IWAN_SRV_SINK=1），跑完立刻检查这一步新增的
# dmesg，一旦出现 oops/BUG/WARNING 就停下并保留现场。
#
# 背景：内层 MTU 曾抬到 60000 时炸过一次 kernel panic，trace 丢了（pstore 无条目、
# journald 没落盘）。现在上限是模块参数（kernel/iwan.h 的 IWAN_MAX_MTU 只是默认值），
# 所以复现阶梯不需要重编译。规范硬上限 65499 = 65535 - 36B 封装开销。
#
# 用法（需要 root）：
#   sudo bash tests/mtu_ladder.sh
#   sudo MTS="2048 4096 9000" bash tests/mtu_ladder.sh       # 从某一档续走
#   sudo DURATION=10 STEP_TIMEOUT=1800 bash tests/mtu_ladder.sh
# 自检（不需要 root，不碰内核）：
#   bash tests/mtu_ladder.sh --selftest
#
# 为什么每步都要 SIZE_RAW=<MTU>：内层报文必须与 MTU 同量级，否则只是"在大 MTU 上传小包"，
# 根本碰不到要复现的那条路径。pps 在 1220B 时就已到单机发生器上限（~1Mpps），所以阶梯
# 看的是**字节/是否 panic**，不是包率。
set -u

# 内核异常关键字。必须写成**同一行**的单引号串：如果拆成多行，$() 里的换行会变成命令
# 分隔符，前半段就成了不带文件参数的 grep —— 它会转去读 stdin，把整条阶梯挂死在原地。
BAD_RE='BUG:|Oops|WARNING:|Call Trace|general protection|NULL pointer|soft lockup|watchdog:|refcount_t|list_del|kernel BUG'

cd "$(dirname "$0")/.." || exit 1

# ---------------------------------------------------------------- 自检（不需要 root）
# 只验证两件容易悄悄坏掉的事：表头列序变了导致 awk 取错列；异常关键字判定失效。
if [ "${1:-}" = --selftest ]; then
    t=$(mktemp -d) || exit 1
    cat >"$t/bench.log" <<'EOF'
基线   raw  c2s     15.38    10.47   31.95%     948035  -
内核   raw  c2s     16.78    16.94   -0.96%    1034202  发送=10486.8MB(负载) 客户端[iwan0]tx=10590.2MB(内层)
EOF
    cat >"$t/clean.new" <<'EOF'
[79432.929033] iwan: netns 4026533312: SESSION_UP sid=3 enc=1 dport=16002 sport=59267 dev=iwan0 ifindex=3 mtu=2048 owned=1
[79440.074649] iwan: netns 4026533312: SESSION_DOWN（dev=iwan0 ifindex=3 已删，行为回到模块参数默认值）
EOF
    cat >"$t/dirty.new" <<'EOF'
[79450.000000] BUG: kernel NULL pointer dereference, address: 0000000000000018
[79450.000001] Call Trace:
EOF
    fail=0
    krow=$(grep -E '^内核[[:space:]]+raw[[:space:]]+c2s' "$t/bench.log" | tail -1)
    brow=$(grep -E '^基线[[:space:]]+raw[[:space:]]+c2s' "$t/bench.log" | tail -1)
    kg=$(echo "$krow" | awk '{print $5}')
    kp=$(echo "$krow" | awk '{print $7}')
    bg=$(echo "$brow" | awk '{print $5}')
    bp=$(echo "$brow" | awk '{print $7}')
    clean=$(grep -nE "$BAD_RE" "$t/clean.new" </dev/null | head -5)
    dirty=$(grep -nE "$BAD_RE" "$t/dirty.new" </dev/null | head -5)
    echo "取列：内核 raw -> 内层Gbps=$kg 出站pps=$kp ；基线 raw -> Gbps=$bg pps=$bp"
    echo "判定：干净 dmesg -> ${clean:-（空 = 正常）} ；含 BUG -> ${dirty:+命中}"
    [ "$kg" = 16.94 ]    || { echo "FAIL: 内核行第 5 列应为 16.94，实得 '$kg'"; fail=1; }
    [ "$kp" = 1034202 ]  || { echo "FAIL: 内核行第 7 列应为 1034202，实得 '$kp'"; fail=1; }
    [ "$bg" = 10.47 ]    || { echo "FAIL: 基线行第 5 列应为 10.47，实得 '$bg'"; fail=1; }
    [ "$bp" = 948035 ]   || { echo "FAIL: 基线行第 7 列应为 948035，实得 '$bp'"; fail=1; }
    [ -z "$clean" ]      || { echo "FAIL: 干净 dmesg 被误判为异常"; fail=1; }
    [ -n "$dirty" ]      || { echo "FAIL: 含 BUG 的 dmesg 没被判定为异常"; fail=1; }
    case "$t" in /tmp/tmp.*) rm -rf "$t" ;; esac   # 只删 mktemp 自己造的目录
    [ "$fail" = 0 ] && echo "自检通过（6 项）"
    exit "$fail"
fi

MTS=${MTS:-"1600 2048 4096 9000 20000 40000 65499"}
BIN=${BIN:-$PWD/build-jumbo2/bin}
SINK=${SINK:-1}          # 1=服务端只计量（只覆盖模块发送路径，快）；0=完整收发
                         # （s2c 会走模块接收路径：外层解封 + 注入 iwan0）
VETH_MTU=${VETH_MTU:-65535}
OUT=${OUT:-/tmp/iwan-mtu-ladder.$$}

# ---- 过期产物门禁 -----------------------------------------------------------
# 按**文件 mtime** 判，不按提交时间：本仓库的习惯是先改代码、跑通、再提交，提交
# 时间能比产物晚一小时，按提交时间判会把最新产物误判成过期。
# 2026-10-08 踩过一次真过期：build-jumbo2/bin/bench_proto 是 19:12 构建的，而
# tests/bench_proto.c 的收包缓冲区修复在 22:26 —— 于是所有 SIZE_RAW>1400 的基线
# 行都被 recvfrom 静默截断在 1400B（每包只算 1380B），"接收Gbps"与"丢包"全是
# 假的（包数有效），差一点写进结论。
stale_reason() {   # $1=产物 $2=源目录；其后是 find -name 模式（缺省全部）；过期则打印原因
    local bin=$1 dir=$2 newer p
    shift 2
    local -a expr=()
    if [ $# -eq 0 ]; then
        expr=(-name '*')
    else
        for p in "$@"; do expr+=(-o -name "$p"); done
        expr=("(" "${expr[@]:1}" ")")     # 去掉首个 -o 并加括号，保证 -newer 作用于整体
    fi
    [ -e "$bin" ] || { echo "$bin 不存在"; return 0; }
    newer=$(find "$dir" -type f "${expr[@]}" -newer "$bin" -print -quit 2>/dev/null)
    [ -n "$newer" ] && echo "$bin 早于 $newer"
    return 0
}
STALE=""
note_stale() {   # 追加一条过期原因
    local r
    r=$(stale_reason "$@")
    [ -z "$r" ] || STALE="$STALE
  · $r"
}
note_stale "$BIN/bench_proto" tests 'bench_proto.c'
note_stale "$BIN/iwan-client" src '*.c' '*.h'
note_stale "$BIN/iwan-server" src '*.c' '*.h'
note_stale kernel/iwan.ko kernel '*.c' '*.h'   # 只比源码：kbuild 的 .cmd/.o 不算
if [ -n "$STALE" ]; then
    if [ "${ALLOW_STALE_BIN:-0}" != 1 ]; then
        echo "error: 产物落后于源码，先重建再量（否则量的是旧代码）：$STALE"
        echo "  cmake --build build-jumbo2 -j 12      # 用户态产物"
        echo "  make -C kernel                        # 模块 kernel/iwan.ko"
        echo "  确实要用旧产物：ALLOW_STALE_BIN=1"
        exit 1
    fi
    echo "警告：允许了过期产物$STALE"
fi

[ "$(id -u)" = 0 ] || { echo "error: 需要 root（insmod/rmmod/netns）" >&2; exit 1; }
mkdir -p "$OUT" || exit 1
# /tmp 是 tmpfs：panic 重启会把整套日志抹掉，而那正是最需要它的时候
# （2026-10-08 15:08 真丢过一轮）。检测到就警告。
if findmnt -n -o FSTYPE --target "$OUT" 2>/dev/null | grep -q '^tmpfs$'; then
    echo "警告：日志目录 $OUT 在 tmpfs 上 —— 一旦 panic 重启，全套日志消失。"
    echo "      要复盘请设 OUT=\$HOME/iwan-logs/mtu-ladder，并把 tee 也指到持久路径"
fi

echo "内核数据面 MTU 阶梯：$MTS"
echo "BIN=$BIN  veth MTU=$VETH_MTU  SINK=$SINK  每步日志：$OUT/"
echo "判定用 dmesg 增量（不清空 dmesg，只按行数取新增部分）"
if [ "$SINK" = 1 ]; then
    echo "口径：SINK=1，每档只跑 raw 的 c2s —— 主指标是客户端设备计数（模块发送路径）"
else
    echo "口径：SINK=0，每档 udp/raw/tcp 两个方向全跑 —— s2c 时模块走接收路径"
    echo "  边界：服务端仍是用户态 TUN，不会产生 GSO 超包 ⇒ iwan_rx 的批量/重组分支仍未覆盖"
fi
if [ "$SINK" = 1 ]; then
    printf '%-7s %10s %10s %10s %10s  %s\n' MTU 内层Gbps 出站pps 基线Gbps 基线pps 判定
else
    printf '%-7s %10s %10s %10s %10s  %s\n' MTU 接收Gbps 收pps 基线Gbps 基线pps 判定
fi
printf '%s\n' "--------------------------------------------------------------------------------"

for m in $MTS; do
    step="$OUT/mtu-$m"
    mkdir -p "$step"

    # 先声明"正在跑哪一档"：万一这一步直接 panic 重启，屏幕上最后一行就能定位档位，
    # 不用猜是这一档还是下一档
    echo "== 开始 MTU=$m =="

    # 每步都用对应的 max_mtu 重新加载：模块参数是加载期读的
    rmmod iwan 2>/dev/null || true
    if lsmod 2>/dev/null | grep -q '^iwan[[:space:]]'; then
        echo "$m: 旧模块仍在内核里（仍有引用），已停"
        break
    fi
    if ! insmod kernel/iwan.ko max_mtu="$m" 2>"$step/insmod.err"; then
        echo "$m: insmod 失败 —— $(cat "$step/insmod.err")"
        break
    fi
    got=$(cat /sys/module/iwan/parameters/max_mtu 2>/dev/null)
    [ "$got" = "$m" ] || echo "$m: 注意 max_mtu 读回 '$got'，与请求不符"
    n0=$(dmesg </dev/null 2>/dev/null | wc -l)

    # tee：一边存日志一边实时打到终端 —— 只重定向的话，整档跑完前屏幕上什么都没有
    # timeout：万一某档真的挂住，整条阶梯不会陪着一起卡死
    BIN="$BIN" KERNEL=1 SINK="$SINK" CLI_MTU="$m" VETH_MTU="$VETH_MTU" SIZE_RAW="$m" \
        timeout "${STEP_TIMEOUT:-900}" bash tests/bench_proto.sh 2>&1 | tee "$step/bench.log"
    rc=${PIPESTATUS[0]}
    dmesg </dev/null 2>/dev/null | tail -n +$((n0 + 1)) >"$step/dmesg.new"

    # 取内核 raw c2s 行与基线 raw 行（列序见 bench_proto.sh 的表头）
    krow=$(grep -E '^内核[[:space:]]+raw[[:space:]]+c2s' "$step/bench.log" | tail -1)
    brow=$(grep -E '^基线[[:space:]]+raw[[:space:]]+c2s' "$step/bench.log" | tail -1)
    kg=$(echo "$krow" | awk '{print $5}')
    kp=$(echo "$krow" | awk '{print $7}')
    bg=$(echo "$brow" | awk '{print $5}')
    bp=$(echo "$brow" | awk '{print $7}')

    # 只看这一步新增的 dmesg：内核异常的关键字（用户态 TUN 那条 TX queue 警告不算）
    bad=$(grep -nE "$BAD_RE" "$step/dmesg.new" </dev/null | head -5)

    verdict=正常
    [ "$rc" = 124 ] && verdict="** 超时 ${STEP_TIMEOUT:-900}s，已停 **"
    [ "$rc" != 0 ] && [ "$rc" != 124 ] && verdict="bench 退出码 $rc"
    [ -n "$bad" ] && verdict="** dmesg 异常，已停 **"

    printf '%-7s %10s %10s %10s %10s  %s\n' \
        "$m" "${kg:-?}" "${kp:-?}" "${bg:-?}" "${bp:-?}" "$verdict"

    if [ -n "$bad" ]; then
        echo
        echo "本步 dmesg 新增内容（完整：$step/dmesg.new）："
        cat "$step/dmesg.new"
        echo
        echo "已停在 MTU=$m。请把以下内容发我："
        echo "  · $step/bench.log 里该档的最后几行"
        echo "  · $step/dmesg.new（已保留）"
        exit 1
    fi
    [ "$rc" != 0 ] && { echo "bench 非零退出，已停（日志 $step/bench.log）"; exit 1; }
done

echo
echo "阶梯走完，未发现内核异常。逐步日志：$OUT/"
