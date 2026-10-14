#!/usr/bin/env bash
# vm_crashlab.sh —— iwan 崩溃靶场：把 bench 塞进一个极小化 Linux 虚拟机里跑。
#
# 为什么：2026-10-08 实测 "内核档 + MTU=20000 + TCP" 会让宿主机 panic，而 panic
# 时屏幕花屏、journald 来不及落盘、efi_pstore 也没抓到 —— 主机上每次复现都是
# 一次无 trace 的硬重启。VM 里炸则无所谓，且串口控制台把 panic 前的**每一条**
# 内核 printk 原样写进宿主机文件，屏幕花不花屏都无所谓。
#
# 原理：
#   guest 内核 = 宿主机正在跑的同一个 /boot/vmlinuz-$(uname -r)。iwan.ko 的
#   vermagic 与它完全一致，模块原样可加载；veth 是模块（打包时解出 .ko.zst），
#   tun 已内建（CONFIG_TUN=y）。
#   根文件系统 = 一个 initramfs（busybox + 真实 iproute2/iptables/stdbuf +
#   build-jumbo2 产物 + kernel/iwan.ko），无盘、无 systemd，/init 挂好
#   proc/sys/dev 后直接跑 bench_proto.sh。
#   guest 内核参数 oops=panic panic=10 + qemu -no-reboot：任何 oops/软锁死/
#   hung task 都先打完整 trace，然后自动"重启"，qemu 随即退出，宿主机脚本
#   接着打印日志里的异常行和尾部。
#
# 用法（两步；第二步不需要 root，因为用户在 kvm 组里）：
#   sudo bash tests/vm_crashlab.sh pack [内层MTU]   # 打包 initramfs（默认 20000）
#   bash tests/vm_crashlab.sh run                   # KVM 启动一次，盯串口日志
# 自定义 guest 内命令（在 /bench 下以 root 执行；记得带 BIN=/bench/bin 跳过构建）：
#   sudo env VM_CMD='insmod /bench/kernel/iwan.ko max_mtu=20000
#     ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK=0 KERNEL_ONLY=1 SKIP_BASELINE=1 BIN=/bench/bin
#     CLI_MTU=20000 VETH_MTU=65535 SIZE_RAW=20000 PROTO_LIST=tcp DIR_LIST=c2s s2c
#     bash /bench/tests/bench_proto.sh' bash tests/vm_crashlab.sh pack
#
# 注意：VM 里的吞吐数字与宿主机**不可比**（vCPU 数、调度、时钟都变了）——
# 它只是崩溃靶场，用来拿 trace 和做 方向/协议/尺寸 的二分；容量结论仍以
# 宿主机为准。每次 run 会占用 VM_SMP(8) 个 vCPU 约 1-3 分钟。
#
# 日志：~/iwan-logs/vm-crashlab/vm-<时间戳>.log（持久路径，不放 /tmp）。

set -uo pipefail

UNAME=$(uname -r)
SRC=$(cd "$(dirname "$0")/.." && pwd)
# OUT 必须对 pack（root）与 run（普通用户）解析成同一路径：sudo 下 $HOME 是
# /root，直接用会让 run 找不到 pack 的产物 —— 按 SUDO_USER 的真实家目录取。
LAB_HOME=$HOME
if [ -n "${SUDO_USER:-}" ]; then
    LAB_HOME=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [ -n "$LAB_HOME" ] || LAB_HOME=$HOME
fi
OUT=${OUT:-$LAB_HOME/iwan-logs/vm-crashlab}
VM="$OUT/vm"
BIN_DIR=${BIN_DIR:-$SRC/build-jumbo2/bin}
STAGE=""

usage() {
    sed -n '2,34p' "$0" | grep -E '^#' | sed 's/^# \{0,1\}//'
}

# copy_bin <命令名>：把宿主机的真实二进制及其 ldd 闭包拷进 staging 的 /usr/bin
# 与 /lib。busybox 提供其余 applet（cat/grep/awk/seq/insmod/...），PATH 里
# /usr/bin 在前，真实工具优先于 busybox 的同名弱化版。
copy_bin() {
    local p deps so
    p=$(command -v "$1" 2>/dev/null)
    if [ -z "$p" ]; then
        for p in "/usr/sbin/$1" "/sbin/$1" "/usr/bin/$1" "/bin/$1"; do
            [ -x "$p" ] && break
            p=""
        done
    fi
    [ -n "$p" ] || { echo "  （宿主机没有 $1，跳过）"; return 0; }
    p=$(readlink -f "$p")
    mkdir -p "$STAGE/usr/bin"
    # 先删再拷：目的位可能是 busybox applet 的符号链接，cp 会顺着链接写穿
    rm -f "$STAGE/usr/bin/$1"
    cp -L "$p" "$STAGE/usr/bin/$1"
    chmod 0755 "$STAGE/usr/bin/$1"
    deps=$(ldd "$p" 2>/dev/null | awk '{ if ($2 == "=>") print $3; else if ($1 ~ /^\//) print $1 }')
    for so in $deps; do
        [ -f "$so" ] || continue
        mkdir -p "$STAGE$(dirname "$so")"
        cp -L "$so" "$STAGE$so"
    done
}

# copy_mod <模块名>：从 /lib/modules 解出（.ko.zst → .ko）放进 staging/mods
copy_mod() {
    local name=$1 f
    f=$(find "/lib/modules/$UNAME" -name "$name.ko*" 2>/dev/null | head -1)
    [ -n "$f" ] || { echo "  （内核里没有 $name.ko，跳过）"; return 0; }
    case "$f" in
        *.zst) zstd -d -q -f -o "$STAGE/mods/$name.ko" "$f" ;;
        *) cp "$f" "$STAGE/mods/$name.ko" ;;
    esac
    echo "  mods/$name.ko ← $f"
}

do_pack() {
    local mtu=${1:-20000}
    local cmd

    # root 只在读 /boot/vmlinuz 时才需要；VM/vmlinuz 已存在则普通用户可重打包
    if [ ! -r "/boot/vmlinuz-$UNAME" ] && [ ! -f "$VM/vmlinuz" ]; then
        echo "error: 读不到 /boot/vmlinuz-$UNAME 且 $VM/vmlinuz 不存在：第一次请用 sudo 跑 pack" >&2
        exit 1
    fi
    for f in bench_proto iwan-client iwan-server; do
        [ -f "$BIN_DIR/$f" ] || { echo "error: $BIN_DIR/$f 不存在（先构建）" >&2; exit 1; }
    done
    [ -f "$SRC/kernel/iwan.ko" ] || { echo "error: 缺 kernel/iwan.ko（先构建模块）" >&2; exit 1; }
    command -v zstd >/dev/null || { echo "error: 需要 zstd 解 veth.ko.zst（本脚本不装包）" >&2; exit 1; }

    echo "== crashlab: 打包 initramfs（内层 MTU=$mtu）=="
    STAGE=$(mktemp -d /tmp/vm-crashlab.XXXXXX)
    mkdir -p "$STAGE"/bin "$STAGE"/usr/bin "$STAGE"/sbin "$STAGE"/proc "$STAGE"/sys \
             "$STAGE"/dev/net "$STAGE"/run/netns "$STAGE"/tmp "$STAGE"/var \
             "$STAGE"/bench/bin "$STAGE"/bench/kernel "$STAGE"/bench/tests "$STAGE"/mods
    ln -sfn /run "$STAGE/var/run"

    # ① busybox + 真实工具 + 共享库闭包
    if [ -f /usr/lib/initramfs-tools/bin/busybox ]; then
        cp /usr/lib/initramfs-tools/bin/busybox "$STAGE/bin/busybox"
    elif [ -f /bin/busybox ]; then
        cp /bin/busybox "$STAGE/bin/busybox"
    else
        echo "error: 找不到 busybox（initramfs-tools 的那个）" >&2; exit 1
    fi
    chmod 0755 "$STAGE/bin/busybox"
    # initramfs-tools 的 busybox 不带 --install 安装器（guest 里静默失败 ⇒
    # insmod/bash 全部 not found，2026-10-08 probe 实测），在宿主机这边把
    # applet 链接直接建进 staging（与 mkinitramfs 同一做法）。真二进制随
    # 后拷进 /usr/bin，PATH=/usr/bin:/bin 让它们盖过同名弱化 applet。
    "$STAGE/bin/busybox" --list 2>/dev/null | while read -r a; do
        [ "$a" = "busybox" ] && continue
        ln -sf /bin/busybox "$STAGE/bin/$a"
    done
    copy_bin ip
    copy_bin iptables
    copy_bin stdbuf
    # uutils stdbuf 需要 LD_PRELOAD 的伴生库（probe5 实测：找不到即启动失败）
    if [ -f /usr/libexec/rust-coreutils/libstdbuf.so ]; then
        mkdir -p "$STAGE/usr/libexec/rust-coreutils"
        cp /usr/libexec/rust-coreutils/libstdbuf.so "$STAGE/usr/libexec/rust-coreutils/"
    fi
    copy_bin bash      # bench_proto.sh 用数组与 =~，busybox sh 跑不了
    copy_bin env
    copy_bin insmod    # 这套 busybox 没有 insmod/rmmod/head/pkill/nproc
    copy_bin rmmod
    copy_bin head
    copy_bin nproc
    copy_bin pkill
    copy_bin pgrep
    copy_bin ps
    copy_bin timeout  # measure() 用 timeout 包住接收侧（probe7 实测缺失）
    # bench 主体还要的 coreutils（busybox applet 缺就补真的，齐了也无妨）
    copy_bin id        # root 检查（probe3 实测：id 缺失 ⇒ die）
    copy_bin dirname   # cd "$(dirname "$0")/.."
    copy_bin sleep
    copy_bin wc
    copy_bin cut
    copy_bin sort
    copy_bin tr
    copy_bin stat
    copy_bin ls
    copy_bin mkdir
    copy_bin rm
    copy_bin ln
    copy_bin du
    copy_bin date
    copy_bin uniq
    copy_bin find
    # busybox 自己是动态链接的，libc/ld.so 由这一步补齐（copy_bin 的闭包含 libc）
    { ldd "$STAGE/bin/busybox" 2>/dev/null \
        | awk '{ if ($2 == "=>") print $3; else if ($1 ~ /^\//) print $1 }' ; } | while read -r so; do
        [ -f "$so" ] || continue
        mkdir -p "$STAGE$(dirname "$so")"
        cp -L "$so" "$STAGE$so"
    done

    # ② 内核模块：veth（模块）+ iptables-nft 的内核侧依赖（尽力而为：
    #    guest 没有防火墙，装不上也不影响 bench，宿主端 iptables 行只是兼容性动作）
    copy_mod veth
    local d ds
    ds=$(modinfo -F depends "$STAGE/mods/veth.ko" 2>/dev/null | tr ',' ' ')
    for d in $ds; do copy_mod "$d"; done
    for d in nfnetlink nf_tables; do copy_mod "$d" 2>/dev/null; done

    # ③ 本仓库产物
    cp "$BIN_DIR/bench_proto" "$BIN_DIR/iwan-client" "$BIN_DIR/iwan-server" "$STAGE/bench/bin/"
    cp "$SRC/kernel/iwan.ko" "$STAGE/bench/kernel/iwan.ko"
    cp "$SRC/tests"/*.sh "$STAGE/bench/tests/"
    chmod 0755 "$STAGE"/bench/bin/* "$STAGE/bench/tests/"*.sh

    # ⑦ 最小 /etc：iwan-server 预开队列后要降权到 'nobody'（probe6 实测：
    #    没有 /etc/passwd 就 "cannot resolve user 'nobody'"）
    mkdir -p "$STAGE/etc"
    cat > "$STAGE/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
EOF
    cat > "$STAGE/etc/group" <<'EOF'
root:x:0:
nogroup:x:65534:
EOF

    # ④ guest 内执行的 bench 命令（默认：宿主机上 exact 复现 panic 的那个组合）
    cmd=${VM_CMD:-}
    if [ -z "$cmd" ]; then
        cmd="insmod /bench/kernel/iwan.ko max_mtu=$mtu
ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK=0 KERNEL_ONLY=1 SKIP_BASELINE=1 BIN=/bench/bin \
CLI_MTU=$mtu VETH_MTU=65535 SIZE_RAW=$mtu PROTO_LIST=tcp DIR_LIST=c2s \
bash /bench/tests/bench_proto.sh"
    fi
    { echo '#!/bin/busybox sh'; echo 'cd /bench'; printf '%s\n' "$cmd"; } > "$STAGE/run/cmd.sh"
    chmod 0755 "$STAGE/run/cmd.sh"

    # ⑤ /init：挂文件系统 → 打开全部 panic 捕获开关 → 跑 cmd.sh → 关机
    cat > "$STAGE/init" <<'INIT'
#!/bin/busybox sh
# 先用显式 /bin/busybox 前缀挂 proc：applet 链接在打包时已在宿主机建好
# （这个 busybox 没有 --install，2026-10-08 probe 实测静默失败）。
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
# bash 的进程替换 <(...) 走 /dev/fd/63：devtmpfs 不自带这些符号链接
ln -sf /proc/self/fd /dev/fd
ln -sf /proc/self/fd/0 /dev/stdin
ln -sf /proc/self/fd/1 /dev/stdout
ln -sf /proc/self/fd/2 /dev/stderr
echo 8 > /proc/sys/kernel/printk
echo 1 > /proc/sys/kernel/panic_on_oops
echo 10 > /proc/sys/kernel/panic
echo 1 > /proc/sys/kernel/softlockup_panic
echo 30 > /proc/sys/kernel/hung_task_timeout_secs
echo 1 > /proc/sys/kernel/hung_task_panic
export PATH=/usr/bin:/bin HOME=/root TMPDIR=/tmp
for m in /mods/*.ko; do insmod "$m" 2>/dev/null; done
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "== crashlab: guest 就绪，模块：$(grep -c '^iwan' /proc/modules) 个 iwan 已加载 =="
echo "== crashlab: 开始跑 /run/cmd.sh =="
sh /run/cmd.sh 2>&1
rc=$?
echo "== crashlab: guest 命令结束 rc=$rc =="
sleep 2
/bin/busybox poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger 2>/dev/null
# 兜底：init 绝不能退出（init 退出 = "Attempted to kill init" panic）
while :; do /bin/busybox sleep 3600; done
INIT
    chmod 0755 "$STAGE/init"

    # ⑥ cpio + gzip → initramfs；拷内核镜像（读不到就复用上次的）
    mkdir -p "$VM"
    (cd "$STAGE" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9) > "$VM/initramfs.cpio.gz"
    if [ -r "/boot/vmlinuz-$UNAME" ]; then
        cp "/boot/vmlinuz-$UNAME" "$VM/vmlinuz"
    else
        echo "  （/boot/vmlinuz 不可读，复用已有 $VM/vmlinuz）"
    fi
    chmod 0644 "$VM/vmlinuz" "$VM/initramfs.cpio.gz" 2>/dev/null || true

    rm -rf "$STAGE"
    STAGE=""
    if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
        chown -R "$SUDO_UID:$SUDO_GID" "$OUT"
    fi

    echo "== crashlab: 打包完成 =="
    echo "  $VM/vmlinuz            （$UNAME，与宿主机同内核）"
    echo "  $VM/initramfs.cpio.gz  （$(du -h "$VM/initramfs.cpio.gz" | cut -f1)）"
    echo "  guest 内命令："
    printf '%s\n' "$cmd" | sed 's/^/    /'
    echo "下一步（不需要 root）："
    echo "  bash tests/vm_crashlab.sh run"
}

do_run() {
    local log rc
    [ -f "$VM/vmlinuz" ] && [ -f "$VM/initramfs.cpio.gz" ] \
        || { echo "error: 还没打包：先 sudo bash tests/vm_crashlab.sh pack" >&2; exit 1; }
    mkdir -p "$OUT"
    log="$OUT/vm-$(date +%Y%m%d-%H%M%S).log"

    local kvmargs="-enable-kvm -cpu host"
    [ -w /dev/kvm ] || { echo "（/dev/kvm 不可写：退化 TCG 软件模拟，慢约 20 倍，但足够触发问题）"; kvmargs=""; }

    echo "== crashlab: 启动 VM（串口 → $log）=="
    echo "== crashlab: 实时观看：另开终端 tail -f \"$log\" =="
    echo "== crashlab: panic 会打完整 trace 后自动退出；最长 ${VM_TIMEOUT:-900}s =="
    # 三条纪律（2026-10-08 21:11 实测翻车来的）：
    #   ① 串口用 -serial file: 直接写文件，qemu 全程不碰 tty —— timeout 默认把
    #      子进程放进新进程组，-serial stdio 摸终端会被作业控制 SIGTTOU 停住，
    #      整条管线冻死、日志 0 字节；
    #   ② stdin 接 /dev/null：guest 控制台不需要输入，也杜绝 tty 交互；
    #   ③ 不用 tee 管道（同①：管道 + tty = 冻结风险）。
    timeout --foreground -k 30 "${VM_TIMEOUT:-900}s" \
    qemu-system-x86_64 $kvmargs -smp "${VM_SMP:-8}" -m "${VM_MEM_MB:-6144}" \
        -kernel "$VM/vmlinuz" -initrd "$VM/initramfs.cpio.gz" \
        -append "console=ttyS0,115200 earlyprintk=serial nokaslr oops=panic panic=10 softlockup_panic=1 hung_task_panic=1 hung_task_timeout_secs=30" \
        -display none -monitor none -no-reboot -nic none \
        -serial "file:$log" \
        </dev/null >/dev/null 2>&1
    rc=$?
    echo
    echo "== crashlab: VM 退出 rc=$rc（0=正常关机/重启退出，124=超时被杀），日志：$log =="
    echo "== crashlab: 内核异常行 =="
    grep -n -E "BUG:|Oops|Kernel panic|RIP:|Call Trace|general protection|soft lockup|watchdog:" "$log" | tail -30
    echo "== crashlab: 日志尾部 40 行 =="
    tail -40 "$log"
}

case "${1:-}" in
    pack) shift; do_pack "$@" ;;
    run)  do_run ;;
    *)    usage; exit 2 ;;
esac
