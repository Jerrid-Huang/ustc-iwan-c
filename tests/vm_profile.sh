#!/usr/bin/env bash
# vm_profile.sh -- data-plane latency profiling driver inside the crash-lab guest.
#
# Usage (inside the guest, as root): bash /bench/tests/vm_profile.sh tx|rx|open <MTU>
#   tx: SINK=1 + KERNEL_ONLY=1, run raw c2s only -- measure the module's **transmit** path
#       (including outer bearer and receiver-side accounting; matches the host's SINK=1 ladder)
#   rx: SINK=0 + KERNEL_ONLY=1, run raw s2c only -- measure the module's **receive** path
#       (server userspace TUN injection -> outer bearer -> hook decrypt -> inner delivery)
#   open: same topology as tx, but DROP inbound to vethbp0 on the host. Outer packets are
#       dropped at netfilter INPUT => the receiver socket queue and the sender's sk_wmem_alloc backpressure disappear,
#       so this measures **open-loop** transmit capacity (send syscall + module + bearer + host ingress processing).
#
# Principle: use the ftrace function profiler (function_profile_enabled + set_ftrace_filter)
# to count and time only data-plane functions, avoiding whole-kernel instrumentation that would crush the machine. The profiler reports
# **inclusive time**, so the report also gives hit counts: one call =
# the function itself plus all downstream time; subtract layer by layer along the call tree to obtain exclusive time per segment.
# Output travels over the serial console, so only aggregate results are printed; no raw trace is kept.
set -u

MODE=${1:-tx}
MTU=${2:-65499}
# Optional third argument: override the raw line's packet size in bytes (default = MTU). Use: in the same session
# run once with 1200B too; subtract the small-packet component from the blended average to get a clean large-packet cost.
SIZE_RAW=${3:-$MTU}
# Optional fourth argument: inner size of the probe UDP line (default 1200). Setting it to the large size as well leaves
# only one packet size in the accounting window, so the average is the per-packet cost of that size without cross-run subtraction.
SIZE_UDP=${4:-1200}
# Optional fifth argument: run only one protocol line (raw|udp|tcp). paged defaults to udp, others default to raw.
PROTO=${5:-}
TR=/sys/kernel/debug/tracing
BIN=/bench/bin

say() { echo "[profile] $*"; }

mount -t debugfs none /sys/kernel/debug 2>/dev/null
if [ ! -d "$TR" ]; then
	echo "[profile] no $TR: kernel lacks debugfs/ftrace, cannot profile" >&2
	exit 2
fi
say "available tracers: $(cat "$TR/available_tracers" 2>/dev/null)"
if [ ! -e "$TR/function_profile_enabled" ]; then
	echo "[profile] no function_profile_enabled (CONFIG_FUNCTION_PROFILER not enabled)" >&2
	exit 3
fi

# ---- Functions to observe: selected per mode -------------------------------------------
# Note: only key data-plane path nodes are listed; parent/child edges are the call-tree edges.
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
# paged: SINK=0 and only udp c2s. With SINK=0 the protocol lines are fully driven by PROTO_LIST (SINK=1
# hardcodes one raw c2s line), and TUN packets do not pass through the module's ndo_start_xmit, so
# all iwan_* samples come from the **socket sender (paged skb)** -- a clean measure of module TX cost.
paged) FUNCS="$FUNCS_COMMON $FUNCS_TX"; SINKV=0; DIRV=c2s ;;
*)     echo "[profile] unknown mode $MODE (choose tx/rx/open/paged)" >&2; exit 2 ;;
esac
: "${PROTO:=raw}"
if [ "$MODE" = paged ] && [ -z "${5:-}" ]; then PROTO=udp; fi

echo 0 > "$TR/tracing_on" 2>/dev/null

# Order is a hard constraint: **load the module first, then write the filter**. Module functions enter
# kallsyms/ftrace only after insmod; otherwise set_ftrace_filter cannot resolve these names and
# none of the module's own functions (iwan_xmit / iwan_xor_skb / iwan_xor_paged ...) get counted.
insmod /bench/kernel/iwan.ko max_mtu="$MTU" || exit 4

: > "$TR/set_ftrace_filter" 2>/dev/null
for f in $FUNCS; do
	echo "$f" >> "$TR/set_ftrace_filter" 2>/dev/null
done
say "functions accepted for instrumentation: $(grep -c . "$TR/set_ftrace_filter" 2>/dev/null)"
say "$(tr '\n' ' ' < "$TR/set_ftrace_filter" 2>/dev/null)"

# Open-loop mode: outer packets are dropped at the host's INPUT
if [ "$MODE" = open ]; then
	iptables -I INPUT 1 -i vethbp0 -j DROP && say "inbound DROP installed on vethbp0 (open loop)"
fi

# ---- Traffic generation (profiler stays on the whole time; only the functions above are counted) ---------
echo 1 > "$TR/function_profile_enabled" 2>/dev/null
ALLOW_JUMBO_KERNEL=1 KERNEL=1 SINK="$SINKV" KERNEL_ONLY=1 SKIP_BASELINE=1 \
BIN=$BIN CLI_MTU="$MTU" VETH_MTU=65535 SIZE_RAW="$SIZE_RAW" SIZE_UDP="$SIZE_UDP" \
PROTO_LIST="$PROTO" DIR_LIST="$DIRV" bash /bench/tests/bench_proto.sh
echo 0 > "$TR/function_profile_enabled" 2>/dev/null
if [ "$MODE" = open ]; then
	iptables -D INPUT 1 2>/dev/null
fi

# ---- Summary (sum per CPU; busybox awk is enough) ---------------------------------------
say "== raw sample rows (verify units) =="
head -3 "$TR/trace_stat/function0" 2>/dev/null
say "== summary: time(us) hits avg(us) function (inclusive) =="
awk 'NF >= 4 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]/ {
	h[$1] += $2; t[$1] += $3
}
END { for (f in t) printf "%12d %10d %8.2f %s\n", t[f], h[f], t[f]/h[f], f }' \
	"$TR"/trace_stat/function* 2>/dev/null | sort -k1 -nr | head -40

echo 0 > "$TR/function_profile_enabled" 2>/dev/null
rmmod iwan 2>/dev/null
echo "[profile] done (mode=$MODE mtu=$MTU size_raw=$SIZE_RAW size_udp=$SIZE_UDP proto=$PROTO)"
