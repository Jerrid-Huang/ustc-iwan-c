#!/usr/bin/env bash
# Kernel data-plane MTU ladder: raise module parameter max_mtu step by step; each step runs only raw c2s (client through kernel
# data plane iwan0, server is a metering-only endpoint IWAN_SRV_SINK=1); right after each run check newly added
# dmesg lines; stop and preserve the scene on oops/BUG/WARNING.
#
# Background: raising inner MTU to 60000 once caused a kernel panic and the trace was lost (no pstore entry,
# journald did not persist it). The limit is now a module parameter (IWAN_MAX_MTU in kernel/iwan.h is only the default),
# so reproducing the ladder needs no rebuild. Spec hard limit 65499 = 65535 - 36B encapsulation overhead.
#
# Usage (requires root):
#   sudo bash tests/mtu_ladder.sh
#   sudo MTS="2048 4096 9000" bash tests/mtu_ladder.sh       # continue from a given step
#   sudo DURATION=10 STEP_TIMEOUT=1800 bash tests/mtu_ladder.sh
# Self-test (no root, does not touch the kernel):
#   bash tests/mtu_ladder.sh --selftest
#
# Why SIZE_RAW=<MTU> at each step: inner packets must be on the order of the MTU, otherwise it is just "small packets over a large MTU"
# and never hits the path being reproduced. At 1220B, pps already reaches the single-host generator ceiling (~1Mpps), so the ladder
# measures **bytes / whether it panics**, not packet rate.
set -u

# Kernel fault keywords. Must be a **single-line** single-quoted string: if split across lines, the newline inside $() becomes a command
# separator and the first part becomes a grep without file arguments -- it reads stdin and hangs the whole ladder.
BAD_RE='BUG:|Oops|WARNING:|Call Trace|general protection|NULL pointer|soft lockup|watchdog:|refcount_t|list_del|kernel BUG'

cd "$(dirname "$0")/.." || exit 1

# ---------------------------------------------------------------- self-test (no root needed)
# Verify only the two things that break silently: a header column-order change making awk pick wrong columns; fault-keyword detection failing.
if [ "${1:-}" = --selftest ]; then
    t=$(mktemp -d) || exit 1
    cat >"$t/bench.log" <<'EOF'
baseline raw  c2s     15.38    10.47   31.95%     948035  -
kernel   raw  c2s     16.78    16.94   -0.96%    1034202  sent=10486.8MB(payload) client[iwan0]tx=10590.2MB(inner)
EOF
    cat >"$t/clean.new" <<'EOF'
[79432.929033] iwan: netns 4026533312: SESSION_UP sid=3 enc=1 dport=16002 sport=59267 dev=iwan0 ifindex=3 mtu=2048 owned=1
[79440.074649] iwan: netns 4026533312: SESSION_DOWN (dev=iwan0 ifindex=3 deleted, behavior back to module parameter default)
EOF
    cat >"$t/dirty.new" <<'EOF'
[79450.000000] BUG: kernel NULL pointer dereference, address: 0000000000000018
[79450.000001] Call Trace:
EOF
    fail=0
    krow=$(grep -E '^kernel[[:space:]]+raw[[:space:]]+c2s' "$t/bench.log" | tail -1)
    brow=$(grep -E '^baseline[[:space:]]+raw[[:space:]]+c2s' "$t/bench.log" | tail -1)
    kg=$(echo "$krow" | awk '{print $5}')
    kp=$(echo "$krow" | awk '{print $7}')
    bg=$(echo "$brow" | awk '{print $5}')
    bp=$(echo "$brow" | awk '{print $7}')
    clean=$(grep -nE "$BAD_RE" "$t/clean.new" </dev/null | head -5)
    dirty=$(grep -nE "$BAD_RE" "$t/dirty.new" </dev/null | head -5)
    echo "extract: kernel raw -> inner Gbps=$kg tx pps=$kp ; baseline raw -> Gbps=$bg pps=$bp"
    echo "verdict: clean dmesg -> ${clean:-empty-normal} ; contains BUG -> ${dirty:+hit}"
    [ "$kg" = 16.94 ]    || { echo "FAIL: kernel row column 5 should be 16.94, got '$kg'"; fail=1; }
    [ "$kp" = 1034202 ]  || { echo "FAIL: kernel row column 7 should be 1034202, got '$kp'"; fail=1; }
    [ "$bg" = 10.47 ]    || { echo "FAIL: baseline row column 5 should be 10.47, got '$bg'"; fail=1; }
    [ "$bp" = 948035 ]   || { echo "FAIL: baseline row column 7 should be 948035, got '$bp'"; fail=1; }
    [ -z "$clean" ]      || { echo "FAIL: clean dmesg was misjudged as faulty"; fail=1; }
    [ -n "$dirty" ]      || { echo "FAIL: dmesg containing BUG was not judged faulty"; fail=1; }
    case "$t" in /tmp/tmp.*) rm -rf "$t" ;; esac   # remove only the directory created by mktemp
    [ "$fail" = 0 ] && echo "self-test passed (6 checks)"
    exit "$fail"
fi

MTS=${MTS:-"1600 2048 4096 9000 20000 40000 65499"}
BIN=${BIN:-$PWD/build-jumbo2/bin}
SINK=${SINK:-1}          # 1=server meters only (covers module TX path only, fast); 0=full send/receive
                         # (s2c goes through module RX path: outer decap + inject into iwan0)
VETH_MTU=${VETH_MTU:-65535}
OUT=${OUT:-/tmp/iwan-mtu-ladder.$$}

# ---- stale-artifact gate -----------------------------------------------------
# Judge by **file mtime**, not commit time: this repo edits, tests, then commits, so commit
# time can be an hour after the artifact; judging by commit time would flag the newest artifact as stale.
# 2026-10-08 hit a real stale case: build-jumbo2/bin/bench_proto was built at 19:12 while
# the tests/bench_proto.c RX buffer fix landed at 22:26 -- so every baseline row with SIZE_RAW>1400
# was silently truncated by recvfrom at 1400B (only 1380B counted per packet), making "rxGbps" and "loss" entirely
# fake (packet counts were valid); it nearly went into the conclusion.
stale_reason() {   # $1=artifact $2=source dir; followed by find -name patterns (default all); print reason if stale
    local bin=$1 dir=$2 newer p
    shift 2
    local -a expr=()
    if [ $# -eq 0 ]; then
        expr=(-name '*')
    else
        for p in "$@"; do expr+=(-o -name "$p"); done
        expr=("(" "${expr[@]:1}" ")")     # drop the first -o and add parens so -newer applies to the whole set
    fi
    [ -e "$bin" ] || { echo "$bin does not exist"; return 0; }
    newer=$(find "$dir" -type f "${expr[@]}" -newer "$bin" -print -quit 2>/dev/null)
    [ -n "$newer" ] && echo "$bin is older than $newer"
    return 0
}
STALE=""
note_stale() {   # append one stale reason
    local r
    r=$(stale_reason "$@")
    [ -z "$r" ] || STALE="$STALE
  - $r"
}
note_stale "$BIN/bench_proto" tests 'bench_proto.c'
note_stale "$BIN/iwan-client" src '*.c' '*.h'
note_stale "$BIN/iwan-server" src '*.c' '*.h'
note_stale kernel/iwan.ko kernel '*.c' '*.h'   # source only: kbuild .cmd/.o do not count
if [ -n "$STALE" ]; then
    if [ "${ALLOW_STALE_BIN:-0}" != 1 ]; then
        echo "error: artifact is older than source; rebuild before measuring (otherwise you measure old code): $STALE"
        echo "  cmake --build build-jumbo2 -j 12      # userspace artifacts"
        echo "  make -C kernel                        # module kernel/iwan.ko"
        echo "  really want the old artifacts: ALLOW_STALE_BIN=1"
        exit 1
    fi
    echo "warning: stale artifacts allowed$STALE"
fi

[ "$(id -u)" = 0 ] || { echo "error: root required (insmod/rmmod/netns)" >&2; exit 1; }
mkdir -p "$OUT" || exit 1
# /tmp is tmpfs: a panic reboot wipes the whole log set, exactly when it is needed most
# (lost a full round at 2026-10-08 15:08). Warn if detected.
if findmnt -n -o FSTYPE --target "$OUT" 2>/dev/null | grep -q '^tmpfs$'; then
    echo "warning: log dir $OUT is on tmpfs -- a panic reboot makes the whole log set disappear."
    echo "      for postmortem set OUT=\$HOME/iwan-logs/mtu-ladder and point tee at a persistent path too"
fi

echo "kernel data-plane MTU ladder: $MTS"
echo "BIN=$BIN  veth MTU=$VETH_MTU  SINK=$SINK  per-step logs: $OUT/"
echo "verdict uses dmesg delta (does not clear dmesg; takes only newly added lines by line count)"
if [ "$SINK" = 1 ]; then
    echo "scope: SINK=1, each level runs only raw c2s -- main metric is client device counters (module TX path)"
else
    echo "scope: SINK=0, each level runs udp/raw/tcp in both directions -- s2c uses the module RX path"
    echo "  boundary: server is still a userspace TUN and produces no GSO super-packets => iwan_rx batching/reassembly branches remain uncovered"
fi
if [ "$SINK" = 1 ]; then
    printf '%-7s %10s %10s %10s %10s  %s\n' MTU innerGbps txpps baselineGbps baselinepps verdict
else
    printf '%-7s %10s %10s %10s %10s  %s\n' MTU rxGbps rxpps baselineGbps baselinepps verdict
fi
printf '%s\n' "--------------------------------------------------------------------------------"

for m in $MTS; do
    step="$OUT/mtu-$m"
    mkdir -p "$step"

    # Announce the current level first: if this step panics and reboots, the last screen line identifies the level,
    # no need to guess whether it was this level or the next
    echo "== start MTU=$m =="

    # Reload with the matching max_mtu each step: module params are read at load time
    rmmod iwan 2>/dev/null || true
    if lsmod 2>/dev/null | grep -q '^iwan[[:space:]]'; then
        echo "$m: old module still in kernel (still referenced), stopped"
        break
    fi
    if ! insmod kernel/iwan.ko max_mtu="$m" 2>"$step/insmod.err"; then
        echo "$m: insmod failed -- $(cat "$step/insmod.err")"
        break
    fi
    got=$(cat /sys/module/iwan/parameters/max_mtu 2>/dev/null)
    [ "$got" = "$m" ] || echo "$m: note max_mtu read back '$got', does not match request"
    n0=$(dmesg </dev/null 2>/dev/null | wc -l)

    # tee: save log and print live -- with redirection only, the screen stays empty until the whole level finishes
    # timeout: if a level really hangs, the whole ladder does not hang with it
    BIN="$BIN" KERNEL=1 SINK="$SINK" CLI_MTU="$m" VETH_MTU="$VETH_MTU" SIZE_RAW="$m" \
        timeout "${STEP_TIMEOUT:-900}" bash tests/bench_proto.sh 2>&1 | tee "$step/bench.log"
    rc=${PIPESTATUS[0]}
    dmesg </dev/null 2>/dev/null | tail -n +$((n0 + 1)) >"$step/dmesg.new"

    # Extract the kernel raw c2s row and baseline raw row (column order: see bench_proto.sh header)
    krow=$(grep -E '^kernel[[:space:]]+raw[[:space:]]+c2s' "$step/bench.log" | tail -1)
    brow=$(grep -E '^baseline[[:space:]]+raw[[:space:]]+c2s' "$step/bench.log" | tail -1)
    kg=$(echo "$krow" | awk '{print $5}')
    kp=$(echo "$krow" | awk '{print $7}')
    bg=$(echo "$brow" | awk '{print $5}')
    bp=$(echo "$brow" | awk '{print $7}')

    # Only newly added dmesg for this step: kernel fault keywords (the userspace TUN TX queue warning does not count)
    bad=$(grep -nE "$BAD_RE" "$step/dmesg.new" </dev/null | head -5)

    verdict=OK
    [ "$rc" = 124 ] && verdict="** timeout ${STEP_TIMEOUT:-900}s, stopped **"
    [ "$rc" != 0 ] && [ "$rc" != 124 ] && verdict="bench exit code $rc"
    [ -n "$bad" ] && verdict="** dmesg fault, stopped **"

    printf '%-7s %10s %10s %10s %10s  %s\n' \
        "$m" "${kg:-?}" "${kp:-?}" "${bg:-?}" "${bp:-?}" "$verdict"

    if [ -n "$bad" ]; then
        echo
        echo "dmesg lines added in this step (full: $step/dmesg.new):"
        cat "$step/dmesg.new"
        echo
        echo "stopped at MTU=$m. Please send me the following:"
        echo "  - last lines of that level in $step/bench.log"
        echo "  - $step/dmesg.new (preserved)"
        exit 1
    fi
    [ "$rc" != 0 ] && { echo "bench exited non-zero, stopped (log $step/bench.log)"; exit 1; }
done

echo
echo "ladder complete, no kernel fault found. Per-step logs: $OUT/"
