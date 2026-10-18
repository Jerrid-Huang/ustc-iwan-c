#!/bin/bash
# iwanmp 端到端一轮：宿主先起外层计数端，再让客体跑 vm-mp-ab.ps1，最后打印两侧计数。
#
# 用法：mp-ab.sh [秒] [载荷] [线程] [pps]      （默认 10 1200 1 20000）
#      mp-ab.sh prepare                        （只做客体侧准备：改名/停 KM-TEST/设地址与 MTU）
set -u
cd /home/uker/my/software/ustc-iwan-c || exit 1
mkdir -p /tmp/mp

if [ "${1:-}" = "prepare" ]; then
    ssh -o ConnectTimeout=10 nano11 \
        'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-ab.ps1 -PrepareOnly' 2>&1 | tail -40
    exit $?
fi

secs="${1:-10}"; bytes="${2:-1200}"; thr="${3:-1}"; pps="${4:-20000}"
sink_log="/tmp/mp/sink-mp-$secs-$bytes-$thr-$pps.log"
python3 tests/win_blast.py sink 45678 $((secs + 80)) >"$sink_log" 2>&1 &
sink_pid=$!
sleep 1
echo "=== 客体（secs=$secs bytes=$bytes threads=$thr pps=$pps）"
timeout $((secs + 200)) ssh -o ConnectTimeout=10 nano11 \
  "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\\\iwan\\\\vm-mp-ab.ps1 -Seconds $secs -Bytes $bytes -Threads $thr -Pps $pps" 2>&1 | tail -80
echo "=== 宿主计数端（sink 45678）"
wait "$sink_pid" 2>/dev/null
cat "$sink_log"
