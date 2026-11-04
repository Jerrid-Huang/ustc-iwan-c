#!/usr/bin/env bash
# vm_crashlab.sh -- iwan crash lab: run the bench inside a minimal Linux VM.
#
# Why: on 2026-10-08, "kernel mode + MTU=20000 + TCP" was measured to panic the host, and during a panic
# the screen garbles, journald cannot persist in time, and efi_pstore catches nothing -- every host reproduction is
# a hard reboot without a trace. Crashing in the VM is harmless, and the serial console writes **every**
# kernel printk before the panic verbatim to a host file; screen garbling does not matter.
#
# How it works:
#   guest kernel = the same /boot/vmlinuz-$(uname -r) the host is running. iwan.ko's
#   vermagic matches exactly, so the module loads as-is; veth is a module (.ko.zst extracted while packing),
#   tun is built in (CONFIG_TUN=y).
#   root filesystem = an initramfs (busybox + real iproute2/iptables/stdbuf +
#   build-jumbo2 artifacts + kernel/iwan.ko), diskless, no systemd; /init mounts
#   proc/sys/dev and then runs bench_proto.sh directly.
#   guest kernel args oops=panic panic=10 + qemu -no-reboot: any oops/soft lockup/
#   hung task first prints a full trace, then auto "reboots"; qemu exits immediately and the host script
#   then prints fault lines and the log tail.
#
# Usage (two steps; the second needs no root because the user is in the kvm group):
#   sudo bash tests/vm_crashlab.sh pack [inner MTU]   # pack initramfs (default 20000)
#   bash tests/vm_crashlab.sh run                   # boot KVM once, watch the serial log
# Customize the in-guest command (runs as root under /bench; include BIN=/bench/bin to skip the build):
#   sudo env VM_CMD='insmod /bench/kernel/iwan.ko max_mtu=20000
#     ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK=0 KERNEL_ONLY=1 SKIP_BASELINE=1 BIN=/bench/bin
#     CLI_MTU=20000 VETH_MTU=65535 SIZE_RAW=20000 PROTO_LIST=tcp DIR_LIST=c2s s2c
#     bash /bench/tests/bench_proto.sh' bash tests/vm_crashlab.sh pack
#
# Note: VM throughput numbers are **not comparable** to the host (vCPU count, scheduling, clocks all differ) --
# it is only a crash lab, for getting traces and bisecting direction/protocol/size; capacity conclusions still come from
# the host. Each run uses VM_SMP(8) vCPUs for about 1-3 minutes.
#
# Logs: ~/iwan-logs/vm-crashlab/vm-<timestamp>.log (persistent path, not /tmp).

set -uo pipefail

UNAME=$(uname -r)
SRC=$(cd "$(dirname "$0")/.." && pwd)
# OUT must resolve to the same path for pack (root) and run (normal user): under sudo $HOME is
# /root, so using it directly makes run miss pack's artifacts -- use SUDO_USER's real home directory.
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

# copy_bin <command name>: copy the host's real binary and its ldd closure into staging /usr/bin
# and /lib. busybox provides the remaining applets (cat/grep/awk/seq/insmod/...); in PATH,
# /usr/bin comes first, so real tools win over busybox's stripped-down namesakes.
copy_bin() {
    local p deps so
    p=$(command -v "$1" 2>/dev/null)
    if [ -z "$p" ]; then
        for p in "/usr/sbin/$1" "/sbin/$1" "/usr/bin/$1" "/bin/$1"; do
            [ -x "$p" ] && break
            p=""
        done
    fi
    [ -n "$p" ] || { echo "  (host has no $1, skipping)"; return 0; }
    p=$(readlink -f "$p")
    mkdir -p "$STAGE/usr/bin"
    # Remove first, then copy: the destination may be a busybox applet symlink, and cp would write through it
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

# copy_mod <module name>: extract from /lib/modules (.ko.zst -> .ko) into staging/mods
copy_mod() {
    local name=$1 f
    f=$(find "/lib/modules/$UNAME" -name "$name.ko*" 2>/dev/null | head -1)
    [ -n "$f" ] || { echo "  (kernel has no $name.ko, skipping)"; return 0; }
    case "$f" in
        *.zst) zstd -d -q -f -o "$STAGE/mods/$name.ko" "$f" ;;
        *) cp "$f" "$STAGE/mods/$name.ko" ;;
    esac
    echo "  mods/$name.ko <- $f"
}

do_pack() {
    local mtu=${1:-20000}
    local cmd

    # root is needed only to read /boot/vmlinuz; if VM/vmlinuz exists, a normal user can repack
    if [ ! -r "/boot/vmlinuz-$UNAME" ] && [ ! -f "$VM/vmlinuz" ]; then
        echo "error: cannot read /boot/vmlinuz-$UNAME and $VM/vmlinuz does not exist: first pack with sudo" >&2
        exit 1
    fi
    for f in bench_proto iwan-client iwan-server; do
        [ -f "$BIN_DIR/$f" ] || { echo "error: $BIN_DIR/$f does not exist (build first)" >&2; exit 1; }
    done
    [ -f "$SRC/kernel/iwan.ko" ] || { echo "error: missing kernel/iwan.ko (build the module first)" >&2; exit 1; }
    command -v zstd >/dev/null || { echo "error: zstd required to extract veth.ko.zst (this script installs nothing)" >&2; exit 1; }

    echo "== crashlab: packing initramfs (inner MTU=$mtu) =="
    STAGE=$(mktemp -d /tmp/vm-crashlab.XXXXXX)
    mkdir -p "$STAGE"/bin "$STAGE"/usr/bin "$STAGE"/sbin "$STAGE"/proc "$STAGE"/sys \
             "$STAGE"/dev/net "$STAGE"/run/netns "$STAGE"/tmp "$STAGE"/var \
             "$STAGE"/bench/bin "$STAGE"/bench/kernel "$STAGE"/bench/tests "$STAGE"/mods
    ln -sfn /run "$STAGE/var/run"

    # 1. busybox + real tools + shared-library closure
    if [ -f /usr/lib/initramfs-tools/bin/busybox ]; then
        cp /usr/lib/initramfs-tools/bin/busybox "$STAGE/bin/busybox"
    elif [ -f /bin/busybox ]; then
        cp /bin/busybox "$STAGE/bin/busybox"
    else
        echo "error: cannot find busybox (the initramfs-tools one)" >&2; exit 1
    fi
    chmod 0755 "$STAGE/bin/busybox"
    # initramfs-tools' busybox lacks the --install installer (silently fails in the guest =>
    # insmod/bash all not found; measured by the 2026-10-08 probe), so on the host side create
    # applet links directly in staging (same approach as mkinitramfs). Real binaries are then
    # copied into /usr/bin; PATH=/usr/bin:/bin lets them override stripped-down applets with the same name.
    "$STAGE/bin/busybox" --list 2>/dev/null | while read -r a; do
        [ "$a" = "busybox" ] && continue
        ln -sf /bin/busybox "$STAGE/bin/$a"
    done
    copy_bin ip
    copy_bin iptables
    copy_bin stdbuf
    # uutils stdbuf needs its LD_PRELOAD companion library (probe5: startup fails if not found)
    if [ -f /usr/libexec/rust-coreutils/libstdbuf.so ]; then
        mkdir -p "$STAGE/usr/libexec/rust-coreutils"
        cp /usr/libexec/rust-coreutils/libstdbuf.so "$STAGE/usr/libexec/rust-coreutils/"
    fi
    copy_bin bash      # bench_proto.sh uses arrays and =~; busybox sh cannot run it
    copy_bin env
    copy_bin insmod    # this busybox lacks insmod/rmmod/head/pkill/nproc
    copy_bin rmmod
    copy_bin head
    copy_bin nproc
    copy_bin pkill
    copy_bin pgrep
    copy_bin ps
    copy_bin timeout  # measure() wraps the receiver in timeout (probe7 found it missing)
    # coreutils also needed by the bench body (copy real ones if the busybox applet is missing; harmless if present)
    copy_bin id        # root check (probe3: missing id => die)
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
    # busybox itself is dynamically linked; this step adds libc/ld.so (copy_bin's closure includes libc)
    { ldd "$STAGE/bin/busybox" 2>/dev/null \
        | awk '{ if ($2 == "=>") print $3; else if ($1 ~ /^\//) print $1 }' ; } | while read -r so; do
        [ -f "$so" ] || continue
        mkdir -p "$STAGE$(dirname "$so")"
        cp -L "$so" "$STAGE$so"
    done

    # 2. kernel modules: veth (module) + iptables-nft kernel-side deps (best effort:
    #    the guest has no firewall; load failures do not affect the bench, host-side iptables lines are compatibility only)
    copy_mod veth
    local d ds
    ds=$(modinfo -F depends "$STAGE/mods/veth.ko" 2>/dev/null | tr ',' ' ')
    for d in $ds; do copy_mod "$d"; done
    for d in nfnetlink nf_tables; do copy_mod "$d" 2>/dev/null; done

    # 3. this repo's artifacts
    cp "$BIN_DIR/bench_proto" "$BIN_DIR/iwan-client" "$BIN_DIR/iwan-server" "$STAGE/bench/bin/"
    cp "$SRC/kernel/iwan.ko" "$STAGE/bench/kernel/iwan.ko"
    cp "$SRC/tests"/*.sh "$STAGE/bench/tests/"
    chmod 0755 "$STAGE"/bench/bin/* "$STAGE/bench/tests/"*.sh

    # 7. minimal /etc: iwan-server drops privileges to 'nobody' after pre-opening queues (probe6:
    #    without /etc/passwd it says "cannot resolve user 'nobody'")
    mkdir -p "$STAGE/etc"
    cat > "$STAGE/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
EOF
    cat > "$STAGE/etc/group" <<'EOF'
root:x:0:
nogroup:x:65534:
EOF

    # 4. bench command executed in the guest (default: the exact combination that panicked the host)
    cmd=${VM_CMD:-}
    if [ -z "$cmd" ]; then
        cmd="insmod /bench/kernel/iwan.ko max_mtu=$mtu
ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK=0 KERNEL_ONLY=1 SKIP_BASELINE=1 BIN=/bench/bin \
CLI_MTU=$mtu VETH_MTU=65535 SIZE_RAW=$mtu PROTO_LIST=tcp DIR_LIST=c2s \
bash /bench/tests/bench_proto.sh"
    fi
    { echo '#!/bin/busybox sh'; echo 'cd /bench'; printf '%s\n' "$cmd"; } > "$STAGE/run/cmd.sh"
    chmod 0755 "$STAGE/run/cmd.sh"

    # 5. /init: mount filesystems -> enable all panic capture switches -> run cmd.sh -> power off
    cat > "$STAGE/init" <<'INIT'
#!/bin/busybox sh
# Mount proc with an explicit /bin/busybox prefix first: applet links were created on the host while packing
# (this busybox has no --install; the 2026-10-08 probe saw it fail silently).
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
# bash process substitution <(...) uses /dev/fd/63: devtmpfs does not provide these symlinks
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
echo "== crashlab: guest ready, modules: $(grep -c '^iwan' /proc/modules) iwan loaded =="
echo "== crashlab: starting /run/cmd.sh =="
sh /run/cmd.sh 2>&1
rc=$?
echo "== crashlab: guest command finished rc=$rc =="
sleep 2
/bin/busybox poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger 2>/dev/null
# Fallback: init must never exit (init exit = "Attempted to kill init" panic)
while :; do /bin/busybox sleep 3600; done
INIT
    chmod 0755 "$STAGE/init"

    # 6. cpio + gzip -> initramfs; copy the kernel image (reuse the previous one if unreadable)
    mkdir -p "$VM"
    (cd "$STAGE" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9) > "$VM/initramfs.cpio.gz"
    if [ -r "/boot/vmlinuz-$UNAME" ]; then
        cp "/boot/vmlinuz-$UNAME" "$VM/vmlinuz"
    else
        echo "  (/boot/vmlinuz unreadable, reusing existing $VM/vmlinuz)"
    fi
    chmod 0644 "$VM/vmlinuz" "$VM/initramfs.cpio.gz" 2>/dev/null || true

    rm -rf "$STAGE"
    STAGE=""
    if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
        chown -R "$SUDO_UID:$SUDO_GID" "$OUT"
    fi

    echo "== crashlab: packing complete =="
    echo "  $VM/vmlinuz            ($UNAME, same kernel as host)"
    echo "  $VM/initramfs.cpio.gz  ($(du -h "$VM/initramfs.cpio.gz" | cut -f1))"
    echo "  in-guest command:"
    printf '%s\n' "$cmd" | sed 's/^/    /'
    echo "next step (no root needed):"
    echo "  bash tests/vm_crashlab.sh run"
}

do_run() {
    local log rc
    [ -f "$VM/vmlinuz" ] && [ -f "$VM/initramfs.cpio.gz" ] \
        || { echo "error: not packed yet: first run sudo bash tests/vm_crashlab.sh pack" >&2; exit 1; }
    mkdir -p "$OUT"
    log="$OUT/vm-$(date +%Y%m%d-%H%M%S).log"

    local kvmargs="-enable-kvm -cpu host"
    [ -w /dev/kvm ] || { echo "(/dev/kvm not writable: falling back to TCG software emulation, about 20x slower but enough to trigger the bug)"; kvmargs=""; }

    echo "== crashlab: starting VM (serial -> $log) =="
    echo "== crashlab: live view: in another terminal, tail -f \"$log\" =="
    echo "== crashlab: a panic prints a full trace then exits automatically; max ${VM_TIMEOUT:-900}s =="
    # Three rules (learned from a 2026-10-08 21:11 field failure):
    #   1. Serial uses -serial file: to write directly to a file; qemu never touches a tty -- timeout by default puts
    #      the child in a new process group, and -serial stdio touching the terminal gets stopped by job-control SIGTTOU,
    #      freezing the whole pipeline and leaving a 0-byte log;
    #   2. stdin from /dev/null: the guest console needs no input, and tty interaction is eliminated;
    #   3. no tee pipe (same as 1: pipe + tty = freeze risk).
    timeout --foreground -k 30 "${VM_TIMEOUT:-900}s" \
    qemu-system-x86_64 $kvmargs -smp "${VM_SMP:-8}" -m "${VM_MEM_MB:-6144}" \
        -kernel "$VM/vmlinuz" -initrd "$VM/initramfs.cpio.gz" \
        -append "console=ttyS0,115200 earlyprintk=serial nokaslr oops=panic panic=10 softlockup_panic=1 hung_task_panic=1 hung_task_timeout_secs=30" \
        -display none -monitor none -no-reboot -nic none \
        -serial "file:$log" \
        </dev/null >/dev/null 2>&1
    rc=$?
    echo
    echo "== crashlab: VM exited rc=$rc (0=normal shutdown/reboot exit, 124=killed by timeout), log: $log =="
    echo "== crashlab: kernel fault lines =="
    grep -n -E "BUG:|Oops|Kernel panic|RIP:|Call Trace|general protection|soft lockup|watchdog:" "$log" | tail -30
    echo "== crashlab: last 40 log lines =="
    tail -40 "$log"
}

case "${1:-}" in
    pack) shift; do_pack "$@" ;;
    run)  do_run ;;
    *)    usage; exit 2 ;;
esac
