#!/bin/bash
# iwanmp end-to-end round: host starts the outer sink first, then the guest runs vm-mp-ab.ps1, and finally both counts are printed.
#
# Usage: mp-ab.sh [seconds] [bytes] [threads] [pps]      (default 10 1200 1 20000)
#      mp-ab.sh prepare                        (guest-side preparation only: rename / stop KM-TEST / set address and MTU)
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
echo "=== guest (secs=$secs bytes=$bytes threads=$thr pps=$pps)"
timeout $((secs + 200)) ssh -o ConnectTimeout=10 nano11 \
  "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\\\iwan\\\\vm-mp-ab.ps1 -Seconds $secs -Bytes $bytes -Threads $thr -Pps $pps" 2>&1 | tail -80
echo "=== host sink (sink 45678)"
wait "$sink_pid" 2>/dev/null
cat "$sink_log"
