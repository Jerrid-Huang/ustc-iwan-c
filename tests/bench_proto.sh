#!/usr/bin/env bash
# iWAN same-host unidirectional capacity benchmark -- inner tcp / udp / raw IP (IP protocol 253)
#
# Three protocols x two directions x up to three scenarios (baseline 6 rows / TUN 6 rows / kernel 6 rows):
#   - baseline: no tunnel; two bench_proto processes talk directly over 127.0.0.1 (lo).
#     It serves two purposes: a reference for tunnel overhead, and **calibrating the generator's own ceiling**
#     (if tunnel numbers approach the baseline, you measured the ruler, not the tunnel).
#   - tunnel: real iwan-server (userspace TUN, host) + real TUN client in a netns,
#     outer link is veth -- **not lo**; lo is used only for the baseline. c2s = send in netns, receive on host;
#     s2c = send on host, receive in netns.
#   - kernel: appended when KERNEL=1; same topology but the client uses --data-plane kernel (module creates
#     iwan0, zero TUN; server still TUN). Prerequisite: sudo insmod kernel/iwan.ko.
#   - metering: with SINK=1 the server starts with IWAN_SRV_SINK=1 (metering receive endpoint only: no TUN,
#     no decapsulation, no injection, no reply). Only udp/raw c2s apply (TCP needs a three-way
#     handshake, s2c needs server replies); receive-side evidence becomes the SINK metering lines in the server log
#     (outer UDP payload, including the 8B fixed header) plus the client TUN egress counters.
#
# Every non-baseline number carries **independent evidence**: sample rx/tx bytes (sysfs) of the tunnel device at both ends
# (TUN mode: client TUN; kernel mode: module-created iwan0),
# requiring the increment in the direction that actually crosses the link to be at least the payload counted by the receiver. Looking only at bench_proto's
# own counters misses the most dangerous error class -- route not effective, traffic crosses the veth directly,
# reporting tens of Gbps of same-host link (a pitfall already hit in bench.sh).
#
# Usage:
#   sudo bash tests/bench_proto.sh [duration seconds]         # default 5 seconds
#   THREADS=8 sudo bash tests/bench_proto.sh 10     # add concurrency
#   SKIP_BASELINE=1 sudo bash tests/bench_proto.sh  # tunnel only
#   sudo insmod kernel/iwan.ko                      # kernel-mode prerequisite (no args)
#   sudo env KERNEL=1 bash tests/bench_proto.sh     # append kernel data-plane reference rows
#   sudo env SINK=1 bash tests/bench_proto.sh       # server metering only (no TUN):
#                                                   # measure client c2s udp/raw only
#   SKIP_TUNNEL=1 sudo bash tests/bench_proto.sh    # raw baseline only (machines without /dev/net/tun)
#   sudo env KERNEL=1 KERNEL_ONLY=1 PROTO_LIST=tcp DIR_LIST=c2s bash tests/bench_proto.sh
#          (KERNEL_ONLY=1 only means "skip TUN rows when KERNEL=1"; KERNEL=1 is still required)
#                                                   # row filter + kernel rows only (panic localization)
#
# Environment: THREADS(4) SIZE_UDP(1200) SIZE_RAW(1220, incl. 20-byte IP header)
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
SINK=${SINK:-0}              # 1 = server metering only (IWAN_SRV_SINK=1, no TUN)
[[ "$DURATION" =~ ^[0-9]+$ ]] || { echo "error: duration must be a positive integer number of seconds: $DURATION" >&2; exit 2; }

# Names and ports fully distinct from tests/bench.sh: both scripts can run at the same time
PORT=16002
NS=iwabp
VETH_H=172.31.201.1          # host-side veth
VETH_N=172.31.201.2          # netns-side veth
VETH_H_DEV=vethbp0
VETH_N_DEV=vethbp1
TUN=iwabp0                   # server TUN (host)
TUN_CLI=iwabp-tun0           # client TUN (inside netns)
KERNEL=${KERNEL:-0}          # 1 = append kernel data-plane reference rows (iwan module must be loaded)
# SINK=1 and KERNEL=1 can coexist: the module hooks are registered in **the client's own netns**,
# while the SINK server has no TUN and no hooks, so they do not compete for the same outer 4-tuple. This combination measures
# "how many raw packets the client kernel TX path alone can push out"; the main metric is pps.
# (TUN data plane + SINK is different; see the module gate below: that combination must unload the module first.)
# Kernel mode + inner MTU above the module limit panics (measured 2026-10-07, see docs/perf-plan.md).
# The limit is now the module parameter max_mtu (default 1500): if the module is loaded, read it to decide, so
# reproduction ladders like "insmod max_mtu=1600 + CLI_MTU=1600" with equal values are not falsely blocked.
# If the module is not loaded, assume the default 1500. To force through (a size known to panic), set ALLOW_JUMBO_KERNEL=1.
KMOD_MTU_MAX=1500
if [ "$KERNEL" = 1 ] && [ -r /sys/module/iwan/parameters/max_mtu ]; then
    KMOD_MTU_MAX=$(cat /sys/module/iwan/parameters/max_mtu 2>/dev/null || echo 1500)
fi
if [ "$KERNEL" = 1 ] && [ -n "${CLI_MTU:-}" ] && [ "${CLI_MTU:-0}" -gt "$KMOD_MTU_MAX" ] \
        && [ "${ALLOW_JUMBO_KERNEL:-0}" != 1 ]; then
    echo "warning: CLI_MTU=$CLI_MTU > module limit max_mtu=$KMOD_MTU_MAX and KERNEL=1 -- this combination causes a kernel panic;"
    echo "      skipping kernel scenarios this round (first sudo rmmod iwan; sudo insmod kernel/iwan.ko max_mtu=$CLI_MTU)"
    echo "      to force through set ALLOW_JUMBO_KERNEL=1, and prepare trace capture first"
    KERNEL=0
fi
SKIP_TUNNEL=${SKIP_TUNNEL:-0} # 1 = raw lo baseline only (the ruler can be calibrated on machines without /dev/net/tun)
# Row filter: run only a subset when localizing a panic / targeted recheck (default all). Single-line form -- do not split commands.
PROTO_LIST=${PROTO_LIST:-tcp udp raw}   # only listed protocols
DIR_LIST=${DIR_LIST:-c2s s2c}           # only listed directions
KERNEL_ONLY=${KERNEL_ONLY:-0}           # 1 = with KERNEL=1 skip TUN rows and go straight to kernel rows
if [ "$KERNEL_ONLY" = 1 ] && [ "$KERNEL" != 1 ]; then
    echo "error: KERNEL_ONLY=1 requires KERNEL=1 (skipping TUN rows only makes sense for kernel rows)" >&2
    exit 2
fi
# Direction filter: DIR_LIST is word-split; pad both sides with spaces for whole-word matching
want_dir() { case " $DIR_LIST " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
BIN=${BIN:-./bin}           # binary directory; measurement builds may use build-jumbo/bin without touching build/
die() { echo "error: $*" >&2; exit 1; }

# pkill -f only on the actual script file: the script's own command line contains only its path, unlike
# interactive bash -c which also carries the pattern string (this round killed its own shell because of that).
cleanup() {
    set +e
    # Under kernel mode SIGKILL leaves the session to netns destruction; give one graceful exit first,
    # so the module receives SESSION_DOWN and cleans up the session and iwan0 itself
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
    # On failure keep a copy of the work log before deleting the directory: otherwise only "which line failed" remains, no scene
    # (this is how server/client logs were lost in the first two real-machine failures)
    if [ "${FAILS:-0}" != 0 ] && [ -d "$WORK" ]; then
        KEEP="/tmp/iwan-benchproto-logs.$$"
        mkdir -p "$KEEP" 2>/dev/null && cp "$WORK"/*.log "$KEEP"/ 2>/dev/null && \
            echo "scene logs kept: $KEEP/ (server.log / client.log / client-kernel.log)" >&2
    fi
    rm -rf "$WORK"
}

# Two hard inner MTU constraints: (1) max 65499 (outer IPv4 total 65535 - 36B encapsulation overhead);
# (2) the carrier link's **layer-3 MTU** must hold the outer packet = inner packet + 36B (20B IP + 8B UDP
# + 8B fixed header), otherwise the outer packet is fragmented. Note the other 14B is the Ethernet header, present only in byte
# counters, not in MTU. The pump already sizes itself dynamically from the negotiated MTU.
if [ -n "${CLI_MTU:-}" ]; then
    if [ "$CLI_MTU" -gt 65499 ]; then
        die "CLI_MTU=$CLI_MTU exceeds the spec limit 65499 (outer IPv4 total 65535 - 36B encapsulation overhead)"
    fi
    if [ "$VETH_MTU" -lt "$((CLI_MTU + 36))" ]; then
        die "VETH_MTU=$VETH_MTU < CLI_MTU+36=$((CLI_MTU + 36)): outer packet does not fit and will be fragmented; raise VETH_MTU"
    fi
fi
VETH_MTU=${VETH_MTU:-1500}   # outer veth MTU; set 65535 for measurement builds with IWAN_JUMBO_MTU
CLI_MTU=${CLI_MTU:-}         # tunnel inner MTU (passed as --mtu, min(server reply, this value));
                             # empty = compile-time default (1400 for normal builds, IWAN_JUMBO_MTU for measurement builds)
MTU_ARG=()                   # empty array: do not pass --mtu
[ -n "$CLI_MTU" ] && MTU_ARG=(--mtu "$CLI_MTU")
# SINK=1: add IWAN_SRV_SINK=1 for the server (empty array = default command line unchanged byte for byte).
# Use an env prefix rather than putting "A=B" in the array: expanded assignment words are not treated as assignments.
SRV_ENV=()
[ "$SINK" = 1 ] && SRV_ENV=(env IWAN_SRV_SINK=1)
KERNEL_DEV=iwan0             # fixed module device name (kernel/iwan.h: IWAN_DEV_NAME)
CLI_DEV=""                   # client-side tunnel device for the current mode (evidence sampled from its sysfs)
# For s2c the client-side **evidence device** may differ (default same as CLI_DEV). Kernel mode must differ:
# module ingress injects via netif_rx/netif_receive_skb directly into the stack, bypassing the netdev driver RX
# path, and the kernel does not add dev->stats.rx_* for the driver -- iwan0's rx_bytes is always 0,
# so using it as evidence misjudges "working" as "did not use the tunnel". Use the client netns outer veth arrival counter
# (outer = 36B frame header + inner packet; byte count is naturally >= payload).
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
declare -A BASE_MAX=()      # best receive-side value per protocol baseline (= generator ceiling estimate)

# ---------------------------------------------------------------- basic tools

trap cleanup EXIT

# Process liveness check: leftover netns/veth makes the next ip link add fail
module_loaded() { grep -q "^iwan " /proc/modules 2>/dev/null; }

# TUN device byte counts (sysfs, also valid inside netns): prints "rx tx"
# Print the "ruler's" own state. On this machine the baseline varies 35%+ between runs (load 37/24 cores, 97C,
# 100k+ cumulative throttle events); without recording it, rate numbers cannot be judged for credibility.
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
    printf '  [machine state] load=%s / %s cores; hottest %sC; cumulative throttles %s; top-3 CPU:%s\n' \
        "${load:-?}" "$(nproc)" "$((tmax / 1000))" "$th" "${tops:- none}"
}

tun_bytes() {   # $1=netns(empty=host) $2=device
    local -a pre=()
    [ -n "$1" ] && pre=(ip netns exec "$1")
    local rx tx
    rx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/rx_bytes" 2>/dev/null)
    tx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/tx_bytes" 2>/dev/null)
    echo "${rx:-0} ${tx:-0}"
}

tun_pkts() {    # $1=netns(empty=host) $2=device; tx_packets = packets the kernel handed to this device
    local -a pre=()
    [ -n "$1" ] && pre=(ip netns exec "$1")
    local rx tx
    rx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/rx_packets" 2>/dev/null)
    tx=$("${pre[@]}" cat "/sys/class/net/$2/statistics/tx_packets" 2>/dev/null)
    echo "${rx:-0} ${tx:-0}"
}

# Extract a field from bench_proto output
field() { sed -n "s/.*$2=\([0-9.]*\).*/\1/p" "$1" | head -1; }

# bytes -> "xx.x" (MB); printing evidence only, not used in decisions
mb() { awk -v v="${1:-0}" 'BEGIN{ printf "%.1f", v / 1e6 }'; }

# SINK=1 evidence source: server prints "SINK pkts=.. bytes=.. pps=.. gbps=.." every 5 seconds
# (pkts/bytes are cumulative, pps/gbps are interval rates for this round). Take the newest line, output
# "<pkts> <bytes> <pps> <gbps>"; if no metering line yet output empty string -- caller prints n/a,
# missing evidence is neither an error nor fabricated.
sink_last() {
    local re='s/^SINK pkts=\([0-9]*\) bytes=\([0-9]*\)'
    re="$re pps=\([0-9.]*\) gbps=\([0-9.]*\).*/\1 \2 \3 \4/p"
    sed -n "$re" "$WORK/server.log" 2>/dev/null | tail -1
}

# Metering line count: distinguish "no new line this round" from "new line but counters did not grow" (the latter is suspicious).
sink_lines() {
    grep -c '^SINK pkts=' "$WORK/server.log" 2>/dev/null || true
}

# Wait for peer READY (start only after bind/listen; otherwise early packets hit nothing,
# and ICMP port unreachable raises errs)
wait_ready() {  # $1=log $2=seconds
    local i
    for i in $(seq 1 $(( $2 * 20 ))); do
        grep -q '^READY' "$1" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# Run one send/receive pair. Args: proto rns bip sns tip port size label dir [duration seconds]
# rns/sns empty means host; otherwise a netns name.
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
    # timeout fallback: all waits inside the generator are bounded now, but under root a hang must not
    # take the whole benchmark with it (after kill there is no RESULT in the log, judged failed)
    timeout $((dur + 25)) "${rcmd[@]}" >"$LOGR" 2>&1 &
    local rpid=$!
    if ! wait_ready "$LOGR" 5; then
        echo "  **receiver did not start**: $(head -2 "$LOGR" | tr '\n' ' ')"
        kill "$rpid" 2>/dev/null; wait "$rpid" 2>/dev/null
        FAILS=$((FAILS + 1)); return 1
    fi

    # Independent evidence for tunnel scenarios: counter snapshots of both tunnel devices. Client side picks the device by direction --
    # kernel-mode s2c must switch to the outer NIC; see the CLI_DEV_S2C definition.
    local cdev=$CLI_DEV
    [ "$dir" = "s2c" ] && cdev=${CLI_DEV_S2C:-$CLI_DEV}
    local ct0="" ct1="" st0="" st1="" co0="" co1="" ho0="" ho1=""
    if [ "$label" != "baseline" ]; then
        ct0=$(tun_bytes "$NS" "$cdev"); st0=$(tun_bytes "" "$TUN")
        co0=$(tun_bytes "$NS" "$VETH_N_DEV"); ho0=$(tun_bytes "" "$VETH_H_DEV")
    fi

    timeout $((dur + 25)) "${scmd[@]}" >"$LOGS" 2>&1
    local src=$?
    wait "$rpid"; local rrc=$?
    sleep 0.3        # wait for in-flight tail packets to land, then take the "after" snapshot

    if [ "$label" != "baseline" ]; then
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
    if [ "$label" != "baseline" ]; then
        # tun_bytes prints "rx_bytes tx_bytes"; the two fields' meanings must be kept straight:
        #   TUN tx_bytes = kernel handed the packet to the device (= tunnel app read it)
        #   TUN rx_bytes = device handed the packet to the kernel (= tunnel app injected it)
        # Last round I swapped these two variable names, so the probe falsely reported "traffic may not use the tunnel" --
        # while the real-machine data was actually correct (c2s: client tx=287MB + server rx=219MB).
        local c_tx c_rx s_tx s_rx chk
        c_rx=$(( ${ct1%% *} - ${ct0%% *} )); c_tx=$(( ${ct1##* } - ${ct0##* } ))
        s_rx=$(( ${st1%% *} - ${st0%% *} )); s_tx=$(( ${st1##* } - ${st0##* } ))
        note=$(awk -v a="$c_tx" -v b="$c_rx" -v c="$s_tx" -v d="$s_rx" \
            -v cd="$cdev" -v sd="$TUN" \
            'BEGIN{ printf "client[%s]tx=%.1fMB rx=%.1fMB server[%s]tx=%.1fMB rx=%.1fMB", cd, a/1e6, b/1e6, sd, c/1e6, d/1e6 }')
        # c2s: client kernel hands inner packets to the client TUN (client tx), then the server tunnel injects them
        # into its own TUN (server rx); s2c swaps directions. Both counters must cover at least the
        # receiver's payload -- this is hard evidence that traffic really crossed the TUN.
        if [ "$dir" = "c2s" ]; then
            chk=$(awk -v a="$c_tx" -v b="$s_rx" -v rx="$rx" 'BEGIN{ print (a>=rx && b>=rx) ? "ok" : "bad" }')
        else
            chk=$(awk -v a="$s_tx" -v b="$c_rx" -v rx="$rx" 'BEGIN{ print (a>=rx && b>=rx) ? "ok" : "bad" }')
        fi
        if [ "$chk" != "ok" ]; then
            note="$note  **${cdev} counter does not cover received bytes; traffic may not use the tunnel**"
            FAILS=$((FAILS + 1))
        fi
        # Outer arrival counter: separate "outer never arrived" from "arrived but the tunnel stage lagged".
        #   c2s: host-side $VETH_H_DEV rx = client uplink outer frames arrived
        #   s2c: client netns $VETH_N_DEV rx = server downlink outer frames arrived
        # Kernel-mode s2c already uses the client outer veth as evidence device; do not print twice.
        local ho_rx co_rx
        ho_rx=$(awk -v a="${ho1:-0 0}" -v b="${ho0:-0 0}" \
            'BEGIN{ split(a,x," "); split(b,y," "); printf "%d", x[1]-y[1] }')
        co_rx=$(awk -v a="${co1:-0 0}" -v b="${co0:-0 0}" \
            'BEGIN{ split(a,x," "); split(b,y," "); printf "%d", x[1]-y[1] }')
        if [ "$dir" = "c2s" ]; then
            note="$note outer-arrival[host ${VETH_H_DEV}]rx=$(awk -v v="$ho_rx" 'BEGIN{printf "%.1f", v/1e6}')MB"
        elif [ "$cdev" != "$VETH_N_DEV" ]; then
            note="$note outer-arrival[client ${VETH_N_DEV}]rx=$(awk -v v="$co_rx" 'BEGIN{printf "%.1f", v/1e6}')MB"
        fi
        # Remote address received: if inner traffic crosses the veth directly, this is 172.31.201.x
        # instead of the tunnel address, more direct than bytes alone
        local rem
        rem=$(field "$LOGR" remote)
        [ -n "$rem" ] && note="$note peer=$rem"
    fi

    printf '%-8s %-4s %-4s %8.2f %8.2f %7s%% %10s  %s\n' \
        "$label" "$proto" "$dir" "${txg:-0}" "${rxg:-0}" "$loss" "${rpps:-0}" "$note"
    if [ "$rrc" != 0 ] || [ "$src" != 0 ]; then
        echo "  **send/receive process exit code abnormal** send=$src recv=$rrc errs=${errs:-?} bad=${bad:-?}"
        FAILS=$((FAILS + 1))
    fi
    # EAGAIN is skipped in the generator and not counted in errs, so errs>0 is a real error;
    # bad>0 means received packets include traffic not sent by us (wrong magic/protocol); data is dirty.
    if [ "${errs:-0}" != 0 ] || [ "${bad:-0}" != 0 ]; then
        echo "  **errs=$errs bad=$bad: this row is untrustworthy (not congestion, but real errors/dirty packets)**"
        FAILS=$((FAILS + 1))
    fi
    # Zero packets on the receiver = nothing got through at all, distinct from "loss"; report separately
    if [ "$rx" = 0 ] && [ "$tx" != 0 ]; then
        echo "  **receiver got zero packets** (sender sent $tx bytes; this is not loss, nothing arrived)"
        FAILS=$((FAILS + 1))
    fi
    if [ "$label" = "baseline" ] && [ "$rx" != 0 ]; then
        awk -v a="${BASE_MAX[$proto]:-0}" -v b="${rxg:-0}" 'BEGIN{ exit (b > a) ? 0 : 1 }' && \
            BASE_MAX[$proto]=${rxg:-0}
        awk -v l="$loss" 'BEGIN{ exit (l > 1.0) ? 0 : 1 }' && \
            echo "  **baseline loss ${loss}%: the generator itself saturated (receiver cannot keep up); this row is the ruler's ceiling, not the link's**"
    fi
}

# SINK=1 only: run sender side only. The server is a metering-only endpoint (no decap, no injection, no reply),
# so the host has no inner receiver and the receive column prints n/a -- this measures how much **client-side** inner
# traffic can be pushed into the tunnel. Two independent evidence sources:
#   - client TUN tx increment (kernel really handed inner packets to the tunnel, not bypassed via veth);
#   - SINK metering lines in the server log (frames reached the peer and passed session/token checks),
#     in outer UDP payload (including 8B fixed header), not inner byte count.
# Args: proto sns tip port size label dir [duration seconds]
measure_sink() {
    local proto=$1 sns=$2 tip=$3 port=$4 size=$5 label=$6 dir=$7
    local dur=${8:-$DURATION}
    local -a scmd=("$BIN"/bench_proto send --proto "$proto" --target "$tip"
                   --port "$port" --duration "$dur" --threads "$THREADS"
                   --size "$size")
    [ -n "$sns" ] && scmd=(ip netns exec "$sns" "${scmd[@]}")

    rm -f "$LOGS"
    # Evidence snapshot: client TUN egress counter delta, server newest metering line + line count
    local cdev=$CLI_DEV ct0 ct1 cp0 cp1 s0 s1 n0 n1
    ct0=$(tun_bytes "$NS" "$cdev")
    cp0=$(tun_pkts "$NS" "$cdev")
    s0=$(sink_last); n0=$(sink_lines)

    timeout $((dur + 25)) "${scmd[@]}" >"$LOGS" 2>&1
    local src=$?
    sleep 0.3        # wait for in-flight tail packets to enter server metering
    ct1=$(tun_bytes "$NS" "$cdev")
    cp1=$(tun_pkts "$NS" "$cdev")
    s1=$(sink_last); n1=$(sink_lines)

    local tx txg errs c_tx
    tx=$(field "$LOGS" bytes); tx=${tx:-0}
    txg=$(field "$LOGS" gbps); errs=$(field "$LOGS" errs)
    c_tx=$(( ${ct1##* } - ${ct0##* } ))   # second field is tx_bytes (see tun_bytes)
    # Client's own egress inner packet count/rate: TUN mode = rate the userspace relay drains from TUN,
    # kernel mode = module ndo_start_xmit packet rate. It is independent of the metering endpoint's receive capability,
    # so it is the authoritative number for "client-side per-packet processing capacity".
    local c_pkts c_pps c_gbps
    c_pkts=$(( ${cp1##* } - ${cp0##* } ))
    c_pps=$(awk -v n="$c_pkts" -v d="$dur" 'BEGIN{ printf "%.0f", (d>0)? n/d : 0 }')
    c_gbps=$(awk -v b="$c_tx" -v d="$dur" 'BEGIN{ printf "%.2f", (d>0)? b*8/d/1e9 : 0 }')

    local note rcv_pps="" loss=n/a
    note=$(awk -v d="$cdev" -v v="$tx" -v w="$c_tx" 'BEGIN{ printf \
        "sent=%.1fMB(payload) client[%s]tx=%.1fMB(inner)", v/1e6, d, w/1e6 }')
    if [ -z "$s1" ]; then
        note="$note server SINK=n/a (no metering line yet)"
    else
        local sp sb spps sgbps op ob
        read -r sp sb spps sgbps <<<"$s1"
        rcv_pps=$spps
        note="$note server SINK newest line pkts=$sp bytes=$(mb "$sb")MB"
        note="$note pps=$spps gbps=$sgbps"
        if [ -n "$s0" ] && [ "$n1" -gt "$n0" ]; then
            read -r op ob _ _ <<<"$s0"
            note="$note this round delta-pkts=$((sp - op)) delta-bytes=$(mb "$((sb - ob))")MB"
            # New line but zero byte growth: uplink frames may not have reached the peer/passed checks. Hint only, not failure
            # -- at a 5-second cadence, tail packets may legitimately not be in the newest line yet.
            if [ "$sb" = "$ob" ] && [ "$tx" != 0 ]; then
                echo "  note: server metering line did not grow this round; uplink frames in this row may not have been counted"
            fi
        else
            note="$note this round delta=n/a (no new metering line in window)"
        fi
    fi
    # Metered/egress packet ratio: <1 means not all client-sent packets reached the metering endpoint -- either dropped on
    # the host receive path, or the metering endpoint is the bottleneck. It decides "is the limiter on the client or
    # on the measurement path", the key side evidence for kernel mode this round.
    if [ -n "$rcv_pps" ] && [ "${c_pps:-0}" != 0 ]; then
        note="$note metered/egress-pkt-ratio=$(awk -v a="$rcv_pps" -v b="$c_pps" 'BEGIN{ printf "%.3f", a/b }')"
    fi
    note="$note client egress=$c_pkts pkts(inner) pps=$c_pps convention=outer UDP payload incl. 8B header"

    # SINK row receive column is the metering endpoint's measured value: rxGbps/rxpps come from its 5-second window line,
    # loss column is the overload ratio "sent vs metered" (tunnel does not propagate backpressure to the app => the difference is dropped in the endpoint queue).
    if [ "${txg:-0}" != 0 ]; then
        loss=$(awk -v s="$txg" -v r="$c_gbps" 'BEGIN{ printf "%.2f%%", (s-r)/s*100 }')
    fi
    # SINK rows always report client-side convention: rxGbps/rxpps = client tunnel device's own egress
    # counter delta (inner); loss = overload ratio sent vs entered-tunnel; metering endpoint numbers go in evidence column
    # as supporting evidence (it may itself be the bottleneck, so it cannot be the primary metric).
    printf '%-8s %-4s %-4s %8.2f %8s %8s %10s  %s\n' \
        "$label" "$proto" "$dir" "${txg:-0}" "$c_gbps" "$loss" "${c_pps:-0}" "$note"
    if [ "$src" != 0 ]; then
        echo "  **sender process exit code abnormal** send=$src errs=${errs:-?}"
        FAILS=$((FAILS + 1))
    fi
    if [ "${errs:-0}" != 0 ]; then
        echo "  **errs=$errs: this row is untrustworthy (not congestion, but real errors/dirty packets)**"
        FAILS=$((FAILS + 1))
    fi
    if [ "$tx" = 0 ]; then
        echo "  **sender sent zero packets** (route not effective, or waited on buffers the whole time)"
        FAILS=$((FAILS + 1))
    fi
}

# ---------------------------------------------------------------- preflight checks

[ "$(id -u)" = 0 ] || die "requires root (TUN device, netns, raw socket); run with sudo"

echo "== build =="
if [ "$BIN" = "./bin" ]; then
    cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON >/dev/null || die "cmake configure failed"
    cmake --build build -j"$(nproc)" >/dev/null || die "build failed"
else
    echo "  skipping build (BIN=$BIN: using artifacts from an external build directory)"
fi
# Explicitly verify artifacts: CMake "success" does not mean the target was actually built (this repo's CMakeLists
# already records a cmake --install silently succeeding pitfall), so this check is mandatory
for b in bench_proto iwan-client iwan-server; do
    [ -x "$BIN/$b" ] || die "$BIN/$b missing -- did -DBUILD_TESTING=ON take effect? Delete build/ and retry"
done

# Relationship between module load state and modes:
#   - default mode (TUN data plane) refuses to run when the module is loaded: iwan_outer_match compares only outer
#     addresses, and kernel hooks use the same outer 4-tuple as the TUN client; hooks would intercept the TUN client's
#     downlink frames, making the measured "capacity" fake.
#   - KERNEL=1 mode requires the module loaded and /dev/iwan present. Hooks are registered by nf_register_net_hook(
#     the client's netns) and only take effect in this script's own netns -- they cannot touch tunnels in other netns.
#     tunnels in use in other netns.
if module_loaded; then
    if [ "$SINK" = 1 ] && [ "$KERNEL" != 1 ]; then
        # SINK=1's client is the TUN data plane: hooks would intercept the server's control-plane replies
        # (OPEN_ACK/keepalive), the session would never come up, and nothing could be measured.
        # With KERNEL=1 it is the opposite -- the client is the kernel data plane, so the module must be loaded.
        echo "error: iwan kernel module is loaded: SINK=1 still uses a TUN client, hooks would grab the same outer 4-tuple" >&2
        echo "       first sudo rmmod iwan, then: sudo env SINK=1 bash $0" >&2
        exit 1
    fi
    if [ "$KERNEL" != 1 ]; then
        echo "error: iwan kernel module is loaded (dport/sport/sid/tok = $(cat /sys/module/iwan/parameters/dport 2>/dev/null)/$(cat /sys/module/iwan/parameters/sport 2>/dev/null)/$(cat /sys/module/iwan/parameters/sid 2>/dev/null)/$(cat /sys/module/iwan/parameters/tok 2>/dev/null))" >&2
        echo "       default mode uses the TUN data plane and shares the same outer 4-tuple with kernel hooks; they steal packets from each other." >&2
        echo "       to run the kernel data-plane reference: sudo env KERNEL=1 bash tests/bench_proto.sh" >&2
        echo "       TUN rows only: first sudo rmmod iwan (rmmod fails when the module is not loaded; do not chain with &&), then:" >&2
        echo "         sudo env BIN=$BIN VETH_MTU=$VETH_MTU CLI_MTU=${CLI_MTU:-} bash $0" >&2
        exit 1
    fi
    [ -c /dev/iwan ] || { echo "error: module loaded but /dev/iwan missing (module and client built from different batches?)" >&2; exit 1; }
else
    [ "$KERNEL" = 1 ] && {
        echo "error: KERNEL=1 requires the iwan module loaded: sudo insmod kernel/iwan.ko" >&2
        echo "       loading without parameters is fine (default enabled=true; sessions are created by client SESSION_UP)" >&2
        exit 1
    }
fi

echo "== pre-clean leftovers from previous round =="
pkill -9 -x bench_proto 2>/dev/null
pkill -9 -f "bin/iwan-client proxy .*--port $PORT" 2>/dev/null
pkill -9 -f "bin/iwan-server .*--port $PORT" 2>/dev/null
sleep 0.3
ip netns del "$NS" 2>/dev/null
ip link del "$VETH_H_DEV" 2>/dev/null

printf 'test:s3cret\n' > "$WORK/users.txt"
chmod 600 "$WORK/users.txt"

DISC="inner ${SIZE_UDP}B UDP / ${SIZE_RAW}B raw IP (payload $((SIZE_RAW - 20))B) / TCP write block ${SIZE_TCP}B; ${THREADS} threads; ${DURATION}s unidirectional saturation per mode"
echo "== convention: $DISC =="
# Reply route is an optional feature (--reply-via-tunnel); this script never uses it => no
# CONNMARK rules installed and no fwmark policy-routing table; conntrack and policy-routing overhead is 0.
echo "convention (fixed): reply route/conntrack = off (no --reply-via-tunnel; no CONNMARK rules or fwmark policy routing)"
if [ "$SINK" = 1 ]; then
    echo "convention (SINK=1): measure client-side carrying capacity only; server does not decapsulate, inject, or reply" \
         "=> no TCP, no s2c"
    if [ "$KERNEL" = 1 ]; then
        echo "convention (SINK=1 + KERNEL=1): client uses kernel data plane $KERNEL_DEV, only raw c2s;" \
             "primary metric = pps of server metering line (per-packet cost is independent of packet byte count);" \
             "inner byte count from the $KERNEL_DEV tx_bytes delta"
    fi
fi
machine_state
printf '%-8s %-4s %-4s %8s %8s %8s %10s  %s\n' scenario proto dir txGbps rxGbps loss rxpps evidence
printf '%s\n' "----------------------------------------------------------------------------------------------------"

# ---------------------------------------------------------------- scenario 1: baseline

if [ "$SKIP_BASELINE" != 1 ]; then
    for proto in $PROTO_LIST; do
        case $proto in
            tcp) size=$SIZE_TCP; port=$P_TCP ;;
            udp) size=$SIZE_UDP; port=$P_UDP ;;
            raw) size=$SIZE_RAW; port=$P_RAW ;;
        esac
        if [ "$SINK" = 1 ]; then
            # Do not leave tcp/s2c rows in SINK=1 output: baseline also runs only udp/raw c2s,
            # kept as the "generator ceiling" ruler (baseline uses lo, independent of the server)
            [ "$proto" = tcp ] && continue
            [ "$KERNEL" = 1 ] && [ "$proto" != raw ] && continue
            want_dir c2s && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" baseline c2s
        else
            # Same-host baseline directions are physically symmetric, but still report c2s/s2c separately to align with tunnel rows
            want_dir c2s && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" baseline c2s
            want_dir s2c && \
            measure "$proto" "" 127.0.0.1 "" 127.0.0.1 "$port" "$size" baseline s2c
        fi
    done
    if [ "$SINK" = 1 ]; then
        echo "  generator ceiling (best udp/raw baseline receive-side values): udp ${BASE_MAX[udp]:-?}" \
             "/ raw ${BASE_MAX[raw]:-?} Gbps"
        echo "  note: udp/raw modes hit the **generator** ceiling first (same-host receive loop)" \
             "-- SINK=1 compares only with these two rows from the same day and parameters."
    else
        echo "  generator ceiling (best baseline receive-side value per protocol): tcp ${BASE_MAX[tcp]:-?} / udp ${BASE_MAX[udp]:-?} / raw ${BASE_MAX[raw]:-?} Gbps"
        echo "  note: udp/raw modes hit the **generator** ceiling first (same-host receive loop); lo itself has much higher capacity (see tcp row);"
        echo "          so tunnel rows can only be compared with **same-day, same-parameter** baseline rows; do not compare a udp tunnel number with a tcp baseline."
    fi
fi

if [ "$SKIP_TUNNEL" = 1 ]; then
    echo "  skipped tunnel and kernel modes (SKIP_TUNNEL=1)"
    if [ "$FAILS" = 0 ]; then echo "BENCH DONE (baseline only)"; else echo "BENCH FAILED: $FAILS anomalies" >&2; fi
    exit $(( FAILS > 0 ? 1 : 0 ))
fi

# ---------------------------------------------------------------- scenario 2: tunnel

machine_state
if [ "$SINK" = 1 ]; then
    echo "== start iwan-server (metering-only receive endpoint IWAN_SRV_SINK=1, no TUN) =="
else
    echo "== start iwan-server (userspace TUN) =="
fi
"${SRV_ENV[@]}" stdbuf -oL -eL "$BIN"/iwan-server --users "$WORK/users.txt" \
    --port "$PORT" --tun "$TUN" --server-ip "$SRV_IP" --subnet "$SUBNET" \
    --dns 114.114.114.114 --nat-if lo >"$WORK/server.log" 2>&1 &
SRV_PID=$!
if [ "$SINK" = 1 ]; then
    # Metering endpoint creates no TUN: readiness uses its own printed mode line (iwan_server.c's
    # "sink mode: metering only ..."); the server TUN address and INPUT rules do not exist
    for _ in $(seq 1 40); do
        kill -0 "$SRV_PID" 2>/dev/null || { echo "error: iwan-server exited: "; tail -5 "$WORK/server.log"; exit 1; }
        grep -q '^sink mode: metering only' "$WORK/server.log" && break
        sleep 0.25
    done
    grep -q '^sink mode: metering only' "$WORK/server.log" || \
        die "server did not enter sink mode (log: $WORK/server.log)"
else
    for _ in $(seq 1 40); do
        grep -q "$SRV_IP" <(ip -4 -o addr show dev "$TUN" 2>/dev/null) && break
        kill -0 "$SRV_PID" 2>/dev/null || { echo "error: iwan-server exited: "; tail -5 "$WORK/server.log"; exit 1; }
        sleep 0.25
    done
    ip -4 -o addr show dev "$TUN" 2>/dev/null | grep -q "$SRV_IP" || die "server TUN did not come up"
    iptables -C INPUT -i "$TUN" -j ACCEPT 2>/dev/null || { iptables -I INPUT -i "$TUN" -j ACCEPT 2>/dev/null && RULE_TUN=1; }
fi

echo "== create netns + veth, start TUN client =="
# When the previous round was interrupted by Ctrl-C / panic / script exit, /run/netns/$NS may remain
# (shows as (id: 0) in `ip netns list`), and ip netns add then fails with "File exists"
# -- hit on 2026-10-11. Delete by name once; if the name cannot be deleted, treat it as a mount leftover,
# unmount and delete that specific file (touch only $NS), and report an error only if that also fails.
if ! ip netns add "$NS" 2>/dev/null; then
    echo "warning: ip netns add $NS failed (leftover?) -- try ip netns del first" >&2
    ip netns del "$NS" 2>/dev/null
    if [ -e "/run/netns/$NS" ]; then
        umount "/run/netns/$NS" 2>/dev/null
        rm -f "/run/netns/$NS" 2>/dev/null
    fi
    ip netns add "$NS" || die "ip netns add failed"
fi
ip link add "$VETH_H_DEV" type veth peer name "$VETH_N_DEV" || die "veth create failed"
ip link set "$VETH_H_DEV" mtu "$VETH_MTU" || die "failed to set MTU on $VETH_H_DEV"
ip link set "$VETH_N_DEV" mtu "$VETH_MTU" || die "failed to set MTU on $VETH_N_DEV"
ip link set "$VETH_N_DEV" netns "$NS"
ip addr add "$VETH_H/24" dev "$VETH_H_DEV"
ip link set "$VETH_H_DEV" up
ip netns exec "$NS" ip addr add "$VETH_N/24" dev "$VETH_N_DEV"
ip netns exec "$NS" ip link set "$VETH_N_DEV" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$VETH_H"
echo "  convention: outer ${VETH_H_DEV}/${VETH_N_DEV} MTU=${VETH_MTU}; tunnel inner MTU=${CLI_MTU:-compile-time default}"
iptables -C INPUT -i "$VETH_H_DEV" -j ACCEPT 2>/dev/null || { iptables -I INPUT -i "$VETH_H_DEV" -j ACCEPT 2>/dev/null && RULE_VETH=1; }

# KERNEL_ONLY=1: keep netns/veth/server/iptables rules (kernel mode reuses them),
# skip TUN client startup, topology probe, and all TUN rows. Clear CLI_PID first (set -u).
CLI_PID=""
if [ "$KERNEL_ONLY" != 1 ]; then
ip netns exec "$NS" stdbuf -oL -eL "$BIN"/iwan-client proxy \
    --server "$VETH_H" --port "$PORT" --user test --pass s3cret \
    --tun "$TUN_CLI" --proxy-cidr "$SUBNET" "${MTU_ARG[@]}" >"$WORK/client.log" 2>&1 &
CLI_PID=$!
# Wait for the tunnel route: starting before it appears lets traffic cross the veth directly, reporting tens of Gbps on the same host
for _ in $(seq 1 40); do
    kill -0 "$CLI_PID" 2>/dev/null || { echo "error: client exited: "; tail -5 "$WORK/client.log"; exit 1; }
    ip netns exec "$NS" ip route show 2>/dev/null | grep -q "$SUBNET" && break
    sleep 0.25
done
ip netns exec "$NS" ip route show 2>/dev/null | grep -q "$SUBNET" || die "tunnel route not established"
CLI_IP=$(ip netns exec "$NS" ip -4 -o addr show dev "$TUN_CLI" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "$CLI_IP" ] || die "cannot get client tunnel address"
CLI_DEV=$TUN_CLI
if [ "$SINK" = 1 ]; then
    # Host route to the client tunnel address is provided by the server TUN; SINK=1 has no TUN, so this
    # check does not hold (and must not die); host reachability to $CLI_IP prints n/a
    echo "  tunnel route ready: client tunnel address $CLI_IP (host reachable via $TUN n/a"
         "-- SINK=1 has no server TUN; evidence device $CLI_DEV)"
else
    # s2c requires the host itself to send packets into the server TUN: without this route packets take the default route,
    # producing "both counters are 0", hard to understand at first glance
    ip route get "$CLI_IP" 2>/dev/null | grep -q "dev $TUN" || \
        die "host has no route to $CLI_IP via $TUN: $(ip route get "$CLI_IP" 2>&1 | head -1)"
    echo "  tunnel route ready: client tunnel address $CLI_IP (host reachable via $TUN, evidence device $CLI_DEV)"
fi

if [ "$SINK" = 1 ]; then
    echo "== probe: c2s 1 second (server replies control-plane only; confirm uplink via client TUN and SINK metering line) =="
else
    echo "== probe: 1 second each direction, first confirm the topology really works =="
fi
FAILS_BEFORE=$FAILS
if [ "$SINK" = 1 ]; then
    measure_sink udp "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" probe c2s 1
else
    measure udp "" "$SRV_IP" "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" probe c2s 1
    measure udp "$NS" "$CLI_IP" "" "$CLI_IP" "$P_UDP" "$SIZE_UDP" probe s2c 1
fi
# Look only at new probe failures: baseline failures (e.g. raw mode without root) are unrelated to topology
if [ "$FAILS" != "$FAILS_BEFORE" ]; then
    if [ "$SINK" = 1 ]; then
        echo "error: probe already failed; fix the topology before looking at full numbers (full log: $LOGS)" >&2
    else
        echo "error: probe already failed; fix the topology before looking at full numbers (full log: $LOGR / $LOGS)" >&2
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
        # Metering endpoint does not ACK, inject, or reply: only udp/raw c2s modes apply
        [ "$proto" = tcp ] && continue
        measure_sink "$proto" "$NS" "$SRV_IP" "$port" "$size" SINK c2s
    else
        # c2s: send in netns -> receive at server TUN ingress on host
        want_dir c2s && \
        measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" tunnel c2s
        # s2c: send on host -> receive in netns (destination assigned by server)
        want_dir s2c && \
        measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" tunnel s2c
    fi
done
fi   # KERNEL_ONLY=1: the whole block above (TUN client + topology probe + TUN rows) is skipped

# ---------------------------------------------------------------- scenario 3: kernel data plane

if [ "$KERNEL" = 1 ]; then
    echo
    machine_state
    echo "== switch to kernel data plane (client --data-plane kernel, device $KERNEL_DEV) =="
    # Stop the TUN client cleanly first: both use exactly the same outer 4-tuple, and iwan_outer_match
    # compares only outer addresses -- if both exist, kernel hooks intercept the TUN client's downlink frames and numbers are necessarily fake.
    # SIGINT lets it exit gracefully; the module receives SESSION_DOWN before reclaiming the session and iwan0.
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
    # Kernel mode creates no TUN: iwan0 is created on demand by the module at SESSION_UP, address assigned by the client from
    # the reply's DEVNAME (same code as route_setup).
    for _ in $(seq 1 60); do
        kill -0 "$CLI_PID" 2>/dev/null || { echo "error: kernel-mode client exited: "; tail -5 "$WORK/client-kernel.log"; exit 1; }
        ip netns exec "$NS" ip -4 -o addr show dev "$KERNEL_DEV" 2>/dev/null | grep -q "inet " && break
        sleep 0.25
    done
    CLI_IP=$(ip netns exec "$NS" ip -4 -o addr show dev "$KERNEL_DEV" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$CLI_IP" ] || die "kernel-mode $KERNEL_DEV got no address: $(tail -3 "$WORK/client-kernel.log")"
    # s2c also requires host reachability to the new address via the server TUN (server may assign a different address)
    if [ "$SINK" = 1 ]; then
        # This check serves s2c only: the host must send packets back to the client via the server TUN. SINK mode
        # has no server TUN and s2c is physically impossible (server does not reply).
        echo "  host route to $CLI_IP: n/a (SINK=1 has no server TUN)"
    else
        ip route get "$CLI_IP" 2>/dev/null | grep -q "dev $TUN" || \
            die "host has no route to $CLI_IP via $TUN: $(ip route get "$CLI_IP" 2>&1 | head -1)"
    fi
    # Evidence device switches to iwan0; sysfs semantics match TUN: egress (kernel hands packets to module in ndo_start_xmit)
    # counts tx_bytes; ingress (module decapsulates and injects into the stack) counts rx_bytes.
    CLI_DEV=$KERNEL_DEV
    # Egress goes through netdev (module adds dev->stats.tx_bytes in ndo_start_xmit) -> usable;
    # ingress bypasses netdev -> iwan0 rx_bytes is always 0; s2c evidence switches to the outer veth arrival counter
    CLI_DEV_S2C=$VETH_N_DEV
    # Do not use ip -d kind: iproute2 may label module-created devices as link/ipip or similar
    # (hit in the e2e script); mtu/state are reliable and what really matters (mtu determines max inner size)
    echo "  kernel mode ready: $KERNEL_DEV address $CLI_IP, $(ip netns exec "$NS" ip -o link show dev "$KERNEL_DEV" 2>/dev/null | sed -n 's/.*<\([^>]*\)>.*mtu \([0-9]*\).*/flags=\1 mtu=\2/p' | head -1)"

    echo "  module parameters: $(for _p in reinject batch hooknum hookprio max_mtu; do printf '%s=%s ' "$_p" "$(cat "/sys/module/iwan/parameters/$_p" 2>/dev/null || echo '?')"; done)"

    if [ "$SINK" = 1 ]; then
        echo "== kernel-mode probe: c2s 1 second (SINK=1 has no s2c: server does not inject or reply) =="
        FAILS_BEFORE=$FAILS
        measure_sink udp "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" kernel c2s 1
        if [ "$FAILS" != "$FAILS_BEFORE" ]; then
            echo "error: kernel-mode probe already failed; fix the topology first (full log: $LOGS)" >&2
            exit 1
        fi
        # Only raw c2s: pps of the kernel TX path is the primary metric
        measure_sink raw "$NS" "$SRV_IP" "$P_RAW" "$SIZE_RAW" kernel c2s
    else
        echo "== kernel-mode probe: 1 second each direction =="
        FAILS_BEFORE=$FAILS
        measure udp "" "$SRV_IP" "$NS" "$SRV_IP" "$P_UDP" "$SIZE_UDP" kernel c2s 1
        measure udp "$NS" "$CLI_IP" "" "$CLI_IP" "$P_UDP" "$SIZE_UDP" kernel s2c 1
        if [ "$FAILS" != "$FAILS_BEFORE" ]; then
            echo "error: kernel-mode probe already failed; fix the topology first (full log: $LOGR / $LOGS)" >&2
            exit 1
        fi

        for proto in $PROTO_LIST; do
            case $proto in
                tcp) size=$SIZE_TCP; port=$P_TCP ;;
                udp) size=$SIZE_UDP; port=$P_UDP ;;
                raw) size=$SIZE_RAW; port=$P_RAW ;;
            esac
            want_dir c2s && \
            measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" kernel c2s
            want_dir s2c && \
            measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" kernel s2c
        done

        # REINJECT_SWEEP="0 1": rerun kernel mode **within the same round**, only switching module parameter reinject.
        # Why same round: the generator ceiling itself drifts (same-day measured udp 8.12 -> 10.90 Gbps),
        # a difference from two rounds is drowned by this drift. Scenario column writes kernel-rj<value> for direct comparison.
        if [ -n "${REINJECT_SWEEP:-}" ]; then
            RJ_PATH=/sys/module/iwan/parameters/reinject
            if [ ! -w "$RJ_PATH" ]; then
                echo "warning: $RJ_PATH not writable (module not loaded?) -- skipping REINJECT_SWEEP" >&2
            else
                RJ_ORIG=$(cat "$RJ_PATH" 2>/dev/null)
                for rj in $REINJECT_SWEEP; do
                    if ! echo "$rj" > "$RJ_PATH" 2>/dev/null; then
                        echo "warning: failed to write reinject=$rj; skipping" >&2
                        continue
                    fi
                    echo "== kernel-mode rerun: reinject=$rj (topology/server/generator all unchanged) =="
                    for proto in $PROTO_LIST; do
                        case $proto in
                            tcp) size=$SIZE_TCP; port=$P_TCP ;;
                            udp) size=$SIZE_UDP; port=$P_UDP ;;
                            raw) size=$SIZE_RAW; port=$P_RAW ;;
                        esac
                        want_dir c2s && \
                        measure "$proto" "" "$SRV_IP" "$NS" "$SRV_IP" "$port" "$size" "kernel-rj$rj" c2s
                        want_dir s2c && \
                        measure "$proto" "$NS" "$CLI_IP" "" "$CLI_IP" "$port" "$size" "kernel-rj$rj" s2c
                    done
                done
                echo "$RJ_ORIG" > "$RJ_PATH" 2>/dev/null
                echo "  restored reinject to ${RJ_ORIG:-?}"
            fi
        fi
    fi
fi

echo "----------------------------------------------------------------------------------------------------"
if [ "$FAILS" = 0 ]; then
    if [ "$SINK" = 1 ] && [ "$KERNEL" = 1 ]; then
        echo "BENCH DONE (SINK=1 + KERNEL=1: client kernel data-plane raw c2s only;" \
             "primary metric = server metering line pps; evidence = $KERNEL_DEV tx_bytes delta + metering lines)"
    elif [ "$SINK" = 1 ]; then
        echo "BENCH DONE (SINK=1: client-side c2s only; evidence = client TUN egress counters + server metering lines)"
    elif [ "$KERNEL" = 1 ]; then
        echo "BENCH DONE (all modes sent/received normally; device-counter evidence holds for TUN and kernel modes)"
    else
        echo "BENCH DONE (all modes sent/received normally; device-counter evidence holds for non-baseline modes)"
    fi
else
    echo "BENCH FAILED: $FAILS anomalies; see lines marked with ** above" >&2
fi
exit $(( FAILS > 0 ? 1 : 0 ))
