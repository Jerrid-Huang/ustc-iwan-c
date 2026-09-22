#!/usr/bin/env python3
"""Reproduction: idle SOCKS5 flows permanently pin all 64 netstack slots.

Claim under test
----------------
`iwan-client socks` owns a fixed netstack connection table
(NS_MAX_CONN = 64, src/common/lwip_bridge.h). A SOCKS flow holds one slot
for as long as its `ns_idx >= 0`. The only reaper that could free an idle
flow is `reap_flows` (src/common/socks_flow.c), and its no-progress
watchdog requires either

    state == ST_CLOSING
      OR
    state == ST_ESTABLISHED && inner conn state == NS_CLOSE_WAIT/NS_CLOSED

So an ESTABLISHED flow whose inner connection is still NS_ESTABLISHED with
zero bytes moving is never reaped. Against the `--no-tun` echo-mirror
server the peer only echoes what the client sends, so an idle client
socket produces zero progress; lwIP keepalive probes (120s idle / 30s
interval / 3 probes) are themselves echoed, so the connection is not
aborted either. The slots stay pinned. Once the table is full,
`conn_slot_alloc` refuses, `ns_connect` returns -1, and the CONNECT is
answered with a SOCKS error (REP=1, "general SOCKS server failure",
src/common/socks_flow.c `open_tcp_conn_af`) instead of being served.

What this script does
---------------------
Phase 1: open idle connections ONE AT A TIME. For each attempt: connect to
the SOCKS listener, do the SOCKS5 no-auth greeting (`05 01 00` ->
`05 00`), send a CONNECT for the target, read the reply. `reply[1]` is the
REP code. On success the socket is KEPT OPEN and NOTHING is ever sent on
it again (that is what makes the flow idle). Stop when --idle-count
successes are held, or when --fail-streak consecutive attempts fail, or
when the bounded attempt budget runs out.

Phase 2 (only when Phase 1 stopped because attempts started failing):
report how many idle connections were held at the moment the first
failure appeared, print the failing REP codes, then hold for --timeout
seconds while re-probing once per second. New connections keep failing
while the idle sockets remain open -> the table is exhausted.

Output: a final machine-readable summary line

    IDLE_HELD=<n> FIRST_FAILURE_AT=<n> NEW_CONN_FAILS=<n> VERDICT=<...>

Usage:
    python3 tests/repro_idle_slot_exhaustion.py \
        --socks 127.0.0.1:18088 --target 10.9.9.9:1234 \
        --idle-count 80 --timeout 15

Exit status: 0 = EXHAUSTED (reproduced), 1 = NOT_REPRODUCED, 2 = usage/
environment error before any measurement could be taken.

Daemon-free: every socket is closed in a finally block; the process exits
on its own.
"""

import argparse
import socket
import struct
import sys
import time

# SOCKS5 constants
VER = 5
METHOD_NO_AUTH = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00

REP_NAMES = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def parse_hostport(text, what):
    """Parse HOST:PORT (IPv6 in brackets) into (host, port)."""
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise argparse.ArgumentTypeError("%s: bad IPv6 literal %r" % (what, text))
        host = text[1:end]
        rest = text[end + 1:]
        if not rest.startswith(":"):
            raise argparse.ArgumentTypeError("%s: missing port in %r" % (what, text))
        port_s = rest[1:]
    else:
        if ":" not in text:
            raise argparse.ArgumentTypeError("%s: expected HOST:PORT, got %r" % (what, text))
        host, port_s = text.rsplit(":", 1)
    try:
        port = int(port_s, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("%s: bad port %r" % (what, port_s))
    if not host or not (0 < port < 65536):
        raise argparse.ArgumentTypeError("%s: bad HOST:PORT %r" % (what, text))
    return host, port


def recv_exact(sock, n):
    """Read exactly n bytes or raise (EOF/timeout)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def socks_connect(host, port, target, io_timeout):
    """Open one SOCKS5 connection and CONNECT to target.

    Returns (sock, rep, detail). On success rep is 0 and sock is a live
    socket the caller owns. On a SOCKS-level failure rep is the REP byte
    from the 10-byte reply and sock is already closed. On a transport
    failure rep is None and detail carries the error text.
    """
    sock = socket.create_connection((host, port), timeout=io_timeout)
    try:
        sock.settimeout(io_timeout)
        # greeting: VER, NMETHODS=1, METHOD=no-auth
        sock.sendall(bytes([VER, 1, METHOD_NO_AUTH]))
        sel = recv_exact(sock, 2)
        if sel[0] != VER:
            raise ConnectionError("bad greeting version 0x%02x" % sel[0])
        if sel[1] != METHOD_NO_AUTH:
            raise ConnectionError("proxy chose method 0x%02x, not no-auth" % sel[1])
        # CONNECT request (IPv4 target)
        req = bytes([VER, CMD_CONNECT, 0x00, ATYP_IPV4]) + target[0] + struct.pack("!H", target[1])
        sock.sendall(req)
        # reply: VER REP RSV ATYP BND.ADDR BND.PORT
        head = recv_exact(sock, 4)
        if head[0] != VER:
            raise ConnectionError("bad reply version 0x%02x" % head[0])
        rep = head[1]
        atyp = head[3]
        if atyp == ATYP_IPV4:
            rest = recv_exact(sock, 4 + 2)
        elif atyp == ATYP_IPV6:
            rest = recv_exact(sock, 16 + 2)
        else:
            raise ConnectionError("bad reply ATYP 0x%02x" % atyp)
        if rep != REP_SUCCESS:
            sock.close()
            return None, rep, REP_NAMES.get(rep, "unknown")
        # Deliberately never write to this socket again: the flow must stay
        # idle (zero progress) for the mechanism under test.
        return sock, rep, "ok"
    except Exception as exc:  # noqa: BLE001 - reported as a probe failure
        try:
            sock.close()
        except OSError:
            pass
        return None, None, "%s: %s" % (type(exc).__name__, exc)


def main():
    ap = argparse.ArgumentParser(
        description="Reproduce idle SOCKS flow netstack-slot exhaustion.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--socks", required=True,
                    help="SOCKS5 listener HOST:PORT (e.g. 127.0.0.1:18088)")
    ap.add_argument("--target", required=True,
                    help="CONNECT target IP:PORT (any address with the --no-tun mirror)")
    ap.add_argument("--idle-count", type=int, default=80,
                    help="stop Phase 1 after this many successful idle connections")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="Phase 2 hold/re-probe duration in seconds")
    ap.add_argument("--fail-streak", type=int, default=3,
                    help="stop Phase 1 after this many consecutive failed attempts")
    ap.add_argument("--io-timeout", type=float, default=5.0,
                    help="per-socket connect/read timeout in seconds")
    args = ap.parse_args()

    if args.idle_count < 1 or args.fail_streak < 1:
        ap.error("--idle-count and --fail-streak must be >= 1")

    socks_host, socks_port = parse_hostport(args.socks, "--socks")
    tgt_host, tgt_port = parse_hostport(args.target, "--target")
    try:
        target = (socket.inet_aton(tgt_host), tgt_port)
    except OSError:
        ap.error("--target must be a numeric IPv4 address, got %r" % tgt_host)

    held = []            # live idle sockets (never written to)
    fail_reps = []       # REP code per failed Phase 1 attempt (or None)
    first_failure_at = None
    idle_at_first_failure = None
    stop_reason = None
    attempt = 0
    consecutive_fails = 0
    max_attempts = args.idle_count + max(20, args.idle_count)

    print("repro_idle_slot_exhaustion: socks=%s:%d target=%d.%d.%d.%d:%d "
          "idle-count=%d timeout=%.0fs fail-streak=%d"
          % (socks_host, socks_port, target[0][0], target[0][1], target[0][2],
             target[0][3], tgt_port, args.idle_count, args.timeout, args.fail_streak),
          flush=True)

    new_conn_total = 0
    new_conn_fails = 0

    try:
        # ---------------- Phase 1: pile up idle flows ----------------
        while True:
            if len(held) >= args.idle_count:
                stop_reason = "idle-count"
                break
            if consecutive_fails >= args.fail_streak:
                stop_reason = "failing"
                break
            if attempt >= max_attempts:
                stop_reason = "attempt-budget"
                break

            attempt += 1
            sock, rep, detail = socks_connect(socks_host, socks_port, target,
                                              args.io_timeout)
            if sock is not None:
                held.append(sock)
                consecutive_fails = 0
                print("  [%3d] OK   rep=0    idle_held=%d" % (attempt, len(held)),
                      flush=True)
            else:
                consecutive_fails += 1
                fail_reps.append(rep)
                if first_failure_at is None:
                    first_failure_at = attempt
                    idle_at_first_failure = len(held)
                    print("  [%3d] FAIL first failure: rep=%s (%s) idle_held=%d"
                          % (attempt,
                             "none" if rep is None else "0x%02x" % rep,
                             detail, len(held)),
                          flush=True)
                else:
                    print("  [%3d] FAIL rep=%s (%s) idle_held=%d streak=%d"
                          % (attempt,
                             "none" if rep is None else "0x%02x" % rep,
                             detail, len(held), consecutive_fails),
                          flush=True)

        print("phase1: stop_reason=%s attempts=%d idle_held=%d first_failure_at=%s"
              % (stop_reason, attempt, len(held),
                 "none" if first_failure_at is None else first_failure_at),
              flush=True)

        # ---------------- Phase 2: keep failing while idle stays open ----
        if stop_reason == "failing" and first_failure_at is not None:
            print("phase2: holding %d idle connections for %.0fs, re-probing "
                  "once per second" % (len(held), args.timeout), flush=True)
            deadline = time.monotonic() + max(0.0, args.timeout)
            probe = 0
            while time.monotonic() < deadline:
                probe += 1
                sock, rep, detail = socks_connect(socks_host, socks_port,
                                                  target, args.io_timeout)
                new_conn_total += 1
                if sock is not None:
                    # A new connection unexpectedly succeeded; keep it open
                    # too (it is not what pins the table) and report it.
                    held.append(sock)
                    print("  [probe %2d] OK   rep=0    (idle_held=%d)"
                          % (probe, len(held)), flush=True)
                else:
                    new_conn_fails += 1
                    print("  [probe %2d] FAIL rep=%s (%s) idle_held=%d"
                          % (probe,
                             "none" if rep is None else "0x%02x" % rep,
                             detail, len(held)), flush=True)
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(1.0, remaining))
        else:
            print("phase2: skipped (no failures seen in phase 1)", flush=True)

    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        held_count = len(held)

    # ---------------- Summary ----------------
    fail_reps_txt = ",".join("none" if r is None else "0x%02x" % r for r in fail_reps)
    if not fail_reps_txt:
        fail_reps_txt = "-"
    if first_failure_at is None:
        verdict = "NOT_REPRODUCED"
    elif new_conn_total > 0 and new_conn_fails == new_conn_total:
        verdict = "EXHAUSTED"
    else:
        verdict = "NOT_REPRODUCED"

    print("phase1_failing_reps=%s" % fail_reps_txt, flush=True)
    print("IDLE_HELD=%s FIRST_FAILURE_AT=%s NEW_CONN_FAILS=%d/%d VERDICT=%s"
          % (idle_at_first_failure if idle_at_first_failure is not None else held_count,
             "none" if first_failure_at is None else first_failure_at,
             new_conn_fails, new_conn_total, verdict), flush=True)
    if verdict != "EXHAUSTED":
        print("note: not reproduced; %d idle connection(s) were held%s"
              % (held_count,
                 "" if first_failure_at is None
                 else " and failures were not sustained"), flush=True)
    return 0 if verdict == "EXHAUSTED" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
