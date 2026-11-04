#!/bin/bash
# Windows data-plane wire test (inbound: intercept after reassembly -> decapsulate -> inject before reassembly), one-shot repro.
#
# Usage: tests/win_vm_wire.sh [iwan.sys path] [peer window seconds] [peer IP]
#   Default peer IP = 10.0.2.2 (QEMU slirp gateway, see the topology notes below)
#   Default iwan.sys = /home/uker/iwan-sys/win-driver-x64/build/x64/Release/iwan.sys
#   Fetch: gh run list --workflow win-driver.yml --branch ci/win-driver-build --limit 1
#         gh run download <id> -D /home/uker/iwan-sys
#         (put it on a persistent path, not /tmp -- a host reboot wipes it)
#   Default window 160 s (must exceed the guest script's total session + ping + wire-hold time)
#
# Topology (peer uses the slirp gateway, no dependency on a host LAN address):
#   host 0.0.0.0:45678 (tests/win_wire_peer.py) <- 10.0.2.2 <- QEMU slirp
#        <- guest Ethernet 10.0.2.15; inside the guest iWAN (KM-TEST loopback) 10.99.0.1/24, 10.99.0.2/24
#
#   UDP the guest sends to 10.0.2.2:45678 is delivered by slirp straight to the host socket (verified working),
#   so the host reply still looks like source 10.0.2.2 to the guest -- which is why the session outer_dst must
#   also be 10.0.2.2 for the driver's 5-tuple gate to match. Do **NOT** use the host LAN address again: once the host
#   reboots, the wired NIC address is gone (enp8s0 DOWN, falls back to WiFi) and the whole wire test silently breaks
#   -- the symptom is peer hellos=0 (this script now hard-fails instead of warning).
#
#   The guest opens one iWAN session: outer 10.0.2.15:40660 <-> 10.0.2.2:45678,
#   sid 0x1234, tok 0x12345678, key 0102030405060708, enc=1, inner 10.99.0.2/32.
#   Guest userland sends "IWAN-WIRE-HELLO" to the peer (not through the driver, so the peer knows whom to reply to);
#   upon receipt the host peer tests/win_wire_peer.py replays crafted outer frames:
#     - normal frames x3/round -- must be intercepted by the driver, decapsulated, and the inner packet re-injected into the network stack;
#     - bad-credential frames x2 -- must be rejected by the driver's credential check.
#
# Criteria (the STATS lines in guest-side rx-out.txt, all values from IOCTL_IWAN_SESSION_GET):
#   rx_outer     = outer datagrams matching the 5-tuple (source port = session dport, dest port = session sport)
#   rx_frames    = of those, data frames passing header validation (type/enc/credentials)
#   rx_delivered = number of inner packets successfully injected into the network stack
#   rx_bad_hdr   = bad-credential/bad-structure sample count -- must exactly equal the number of bad samples the peer sent (2)
#   Pass criteria: rx_frames >= 10 and rx_delivered == rx_frames and rx_bad_hdr == 2,
#             and ssh is still up after the wire test (historically a "terminating filter written as CONTINUE"
#             took the whole machine offline on session setup; see the verdict comment in win-driver/iwan_win_wfp.c).
#
# Pitfalls already hit (all handled explicitly in this script):
#   - -Inject -Wire must be given together: the entire wire test hangs off if ($Inject), so -Wire alone does not run it;
#   - nested ssh -> powershell swallows -File script arguments, so the guest side uses
#     a wrapper script such as C:\iwan\vm-wire-run.ps1 with hardcoded arguments;
#   - $-Args is a PowerShell automatic variable; the wrapper renames it to $ScriptArgs;
#   - the guest C: once had 0 bytes free and both Add-Type and scp failed silently -- check fsutil first;
#   - serial log lines arrive in bursts; do not order events by host-side tail timestamps;
#   - counter names must match the function they live in: rx_batch_skip was once inserted into the outbound v6 classification
#     function, so the conclusion "inbound was never called" was false and cost a wasted round;
#   - injected inner packets look like "out-of-nowhere inbound UDP" to the guest firewall: without an allow
#     rule they are silently dropped while the inject API still returns success (rx_delivered still climbs).
#     Production injects the **replies** to tunneled traffic, which a stateful firewall allows; in this wire test the peer sends
#     crafted packets, so this script temporarily adds an inbound UDP 9999 allow rule and deletes it after the run.
set -u

SYS_PATH="${1:-/home/uker/iwan-sys/win-driver-x64/build/x64/Release/iwan.sys}"
WINDOW="${2:-160}"
PEER_IP="${3:-10.0.2.2}"
PEER_PORT=45678
# The guest is reached over an explicit host:port -- there is no "nano11" ssh-config alias any more.
GUEST_USER="${GUEST_USER:-Administrator}"
GUEST_HOST="${GUEST_HOST:-127.0.0.1}"
GUEST_PORT="${GUEST_PORT:-2222}"
GUEST="$GUEST_USER@$GUEST_HOST"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/win_vm_wire
mkdir -p "$OUT"

say() { echo "[wire] $*"; }
die() { echo "[wire] FAIL: $*" >&2; exit 1; }

[ -f "$SYS_PATH" ] || die "driver not found: $SYS_PATH (run gh run download first)"
timeout 15 ssh -p "$GUEST_PORT" -o ConnectTimeout=8 -o BatchMode=yes "$GUEST" 'echo ok' >/dev/null 2>&1 \
    || die "guest $GUEST:$GUEST_PORT unreachable"

# The guest-side scripts are half of this verification and would be lost with the environment if left on the guest: archive them to tests/win_vm/ while at it
if [ ! -d "$HERE/win_vm" ]; then
    mkdir -p "$HERE/win_vm"
    timeout 120 scp -q -P "$GUEST_PORT" "$GUEST:C:/iwan/*.ps1" "$HERE/win_vm/" 2>/dev/null \
        && say "archived guest scripts to tests/win_vm/ ($(ls -1 "$HERE/win_vm" | wc -l) files)"
fi

say "Swapping driver: $SYS_PATH ($(stat -c%s "$SYS_PATH") bytes)"
timeout 60 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" 'sc.exe stop iwan' >/dev/null 2>&1
sleep 3
timeout 150 scp -q -P "$GUEST_PORT" "$SYS_PATH" "$GUEST:C:/iwan/iwan.sys" || die "driver copy failed (guest disk full?)"
timeout 200 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" \
    'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-load.ps1 -SysPath C:\iwan\iwan.sys' \
    2>&1 | tr -d '\r' 2>/dev/null | grep -q "State    : Running" || die "driver did not start (State is not Running)"
say "driver State: Running"

# Guest-side prep: C: free space (a full disk makes Add-Type/scp fail silently) + inbound allow for inner packets.
# This guest disk is always tight (16 GB disk, ~230 MB free before a test run); see
# C:\iwan\vm-clean.ps1 for cleanup; if that is still not enough you must touch C:\Windows\LiveKernelReports (~685 MB
# of kernel dumps, evidence left by earlier hangs -- ask the user before deleting).
# Only trust the real free-space line: fsutil also prints total capacity, quota free, and pool usage (some zeros),
# so picking max/min by numeric value goes wrong (once treated 16 GB total capacity as free space).
FREE=$(timeout 60 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" 'fsutil volume diskfree C:' 2>/dev/null \
       | tr -d '\r' | grep -iE $'^(Total free bytes|\xe6\x80\xbb\xe5\x8f\xaf\xe7\x94\xa8\xe5\xad\x97\xe8\x8a\x82\xe6\x95\xb0)' \
       | grep -oE '[0-9][0-9,]{5,}' | tr -d ',' | head -1)
if [ -n "$FREE" ] && [ "$FREE" -lt 209715200 ]; then
    die "guest C: insufficient free space (${FREE} bytes) -- clean C:\\Windows\\Temp etc. first"
fi
say "guest C: ${FREE:-unknown} bytes free"
timeout 60 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" \
    'netsh advfirewall firewall add rule name="iwan-wire-in" dir=in action=allow protocol=UDP localport=9999' \
    >/dev/null 2>&1 && say "added inbound UDP 9999 allow rule (removed after the run)"

# Anti-"empty run": delete the guest output file first; it must reappear after the run -- once the script
# never ran at all (driver not loaded, script exited silently) and we read the previous rx-out.txt, taking stale numbers
# as a new conclusion.
timeout 60 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" \
    'powershell -NoProfile -Command "Remove-Item C:\\iwan\\rx-out.txt -Force -ErrorAction SilentlyContinue"' \
    >/dev/null 2>&1

# The guest wrapper script is generated by this script and uploaded: nested ssh -> powershell eats -File script
# arguments, so the arguments must live in a guest-side file; what lands there is decided here, so the guest does not keep
# the previous peer IP (a changed address becomes a silent hellos=0 empty run).
# Set console output to UTF-8: otherwise Chinese in the host-captured log is all '?' (numbers and ASCII payloads
# are unaffected, but evidence readability is much worse).
printf '\xef\xbb\xbf[Console]::OutputEncoding=[Text.Encoding]::UTF8\r\n& C:\\iwan\\vm-rx.ps1 -Inject -Wire -PeerIp %s -PeerPort %s -PingCount 0 -HoldSeconds 20\r\n' \
    "$PEER_IP" "$PEER_PORT" > "$OUT/vm-wire-run.ps1"
timeout 90 scp -q -P "$GUEST_PORT" "$OUT/vm-wire-run.ps1" "$GUEST:C:/iwan/vm-wire-run.ps1" \
    || die "failed to upload the guest wrapper script"
say "guest wrapper script: peer ${PEER_IP}:${PEER_PORT}"

say "starting host peer (window ${WINDOW}s)"
python3 "$HERE/win_wire_peer.py" "$WINDOW" > "$OUT/peer.log" 2>&1 &
PEER=$!
sleep 3

say "running guest wire test (-Inject -Wire, wrapper script at $OUT/vm-wire-run.ps1)"
timeout $((WINDOW + 60)) ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" \
    'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-wire-run.ps1' \
    > "$OUT/guest.log" 2>&1

wait $PEER 2>/dev/null
PEERLINE=$(grep -a "^PEER done" "$OUT/peer.log" || true)
if [ -z "$PEERLINE" ]; then
    die "peer printed no summary line (the guest script probably never started; see $OUT/guest.log)"
fi
say "$PEERLINE"
HELLOS=$(echo "$PEERLINE" | grep -oE 'hellos=[0-9]+' | cut -d= -f2)
[ "${HELLOS:-0}" -gt 0 ] || die "peer received no HELLO at all: the guest side sent no traffic, or the peer address is wrong (current ${PEER_IP}:${PEER_PORT}; guest log at $OUT/guest.log)"

# Prefer the evidence dumped by the guest to rx-out.txt; without it fall back to the console log (same content: STATS lines and
# ASCII payloads are both there; Chinese is lost to console encoding, which does not affect the criteria).
EVID="$OUT/rx-out.txt"
timeout 120 scp -q -P "$GUEST_PORT" "$GUEST:C:/iwan/rx-out.txt" "$EVID" 2>/dev/null || {
    EVID="$OUT/guest.log"
    say "guest has no rx-out.txt; taking evidence from the console log instead ($EVID)"
}

python3 - "$EVID" <<'PY' || exit 1
import re, sys
raw = open(sys.argv[1], 'rb').read()
try:
    txt = raw.decode('utf-8')
except UnicodeDecodeError:
    txt = raw.decode('gbk', 'replace')
txt = txt.replace('\r', '')
stats = {}
for m in re.finditer(r'STATS (\w+) ((?:\w+=\S+ ?)+)', txt):
    tag, body = m.group(1), m.group(2)
    stats[tag] = dict(kv.split('=') for kv in body.split())
final = stats.get('final') or (list(stats.values())[-1] if stats else None)
if not final:
    print('[wire] FAIL: no STATS line in rx-out.txt'); sys.exit(1)
g = lambda k: int(final.get(k, 0))
print('[wire] final counters: ' + ' '.join('%s=%s' % (k, final[k]) for k in
      ('rx_outer', 'rx_frames', 'rx_delivered', 'rx_batch', 'rx_batch_skip',
       'rx_bad_hdr', 'rx_bad_inner', 'ev_dropped') if k in final))
ok = True
if g('rx_frames') < 10:
    print('[wire] FAIL: rx_frames=%d, outer frames were not intercepted' % g('rx_frames')); ok = False
if g('rx_delivered') != g('rx_frames'):
    print('[wire] FAIL: rx_delivered=%d != rx_frames=%d, some frames were not injected successfully'
          % (g('rx_delivered'), g('rx_frames'))); ok = False
if g('rx_batch') != 0:
    print('[wire] FAIL: rx_batch=%d, some injections were bounced by WFP in the completion callback '
          '(rx_reasm sums the failure status codes; divide by rx_batch to get the original value; '
          '0xC000000D=STATUS_INVALID_PARAMETER is mostly a wrong NIC index/isolation compartment)' % g('rx_batch'))
    ok = False
if g('rx_bad_hdr') != 2:
    print('[wire] FAIL: rx_bad_hdr=%d, bad-credential sample count is wrong (expected 2)' % g('rx_bad_hdr')); ok = False
if 'IWAN-INNER-OK' in txt:
    print('[wire] extra evidence: guest userland received the inner payload IWAN-INNER-OK')
else:
    print('[wire] note: guest userland received no inner packet. First check rx_batch/rx_batch_skip/rx_reasm '
          '(injection completion status diagnostics: one counter each for success/failure; on failure rx_reasm sums the raw status codes); '
          'if completion is successful, rule out the guest firewall (this script already added the UDP 9999 allow rule).')
sys.exit(0 if ok else 1)
PY
RC=$?

timeout 60 ssh -p "$GUEST_PORT" -o ConnectTimeout=12 "$GUEST" \
    'netsh advfirewall firewall delete rule name="iwan-wire-in"' >/dev/null 2>&1

timeout 15 ssh -p "$GUEST_PORT" -o ConnectTimeout=8 -o BatchMode=yes "$GUEST" 'echo ok' >/dev/null 2>&1 \
    && say "network after wire test: up" || { say "network after wire test: down"; RC=1; }

[ $RC -eq 0 ] && say "PASS (evidence in $OUT/)" || say "FAIL (evidence in $OUT/)"
exit $RC
