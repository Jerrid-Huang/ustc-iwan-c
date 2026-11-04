#!/usr/bin/env python3
"""Host-side throughput sender / sink (companion for Windows client throughput measurement).

Accounting matches the Linux baseline (tests/bench_proto.sh): **only payload that crosses the wire**,
pps from payload packet count, bps from payload bytes, plus a separate "sender call count" to distinguish it from payload
(a successful sendto does not mean the peer received it; slirp drops too).

Three roles:
  send   host sends -> guest receives (calibrate the slirp channel's uplink capacity)
  sink   host receives <- guest sends (calibrate downlink, or measure the tunnel's outbound outer rate)
  loop   self-loop (use the process's own limit as a reference so the "ruler" itself is not measured)

Usage:
  win_blast.py send <IP> <PORT> <SECONDS> [PAYLOAD]
  win_blast.py sink <PORT> <SECONDS> [PAYLOAD]
  win_blast.py loop <SECONDS> [PAYLOAD]

Output one parseable summary line:
  BLAST role=send pkts=N bytes=N elapsed=SEC rate_pps=N rate_mbps=N
"""
import socket
import sys
import time

PAYLOAD = 1200


def report(role, pkts, nbytes, elapsed):
    pps = pkts / elapsed if elapsed > 0 else 0.0
    mbps = nbytes * 8 / elapsed / 1e6 if elapsed > 0 else 0.0
    print("BLAST role=%s pkts=%d bytes=%d elapsed=%.3f rate_pps=%.0f rate_mbps=%.1f"
          % (role, pkts, nbytes, elapsed, pps, mbps), flush=True)


def do_send(ip, port, seconds, size):
    """Send as fast as possible: preallocate the buffer, only sendto in the loop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    sock.connect((ip, port))          # use send after connect to avoid resolving the address every time
    buf = bytes(size)
    pkts = nbytes = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        for _ in range(64):           # small inner batch, fewer clock reads
            try:
                sock.send(buf)
            except OSError:
                break
            pkts += 1
            nbytes += size
    elapsed = time.perf_counter() - t0
    sock.close()
    report("send", pkts, nbytes, elapsed)


def do_sink(port, seconds, expect):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(0.5)
    pkts = nbytes = 0
    other = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if expect and len(data) != expect:
            other += 1
            continue
        pkts += 1
        nbytes += len(data)
    elapsed = time.perf_counter() - t0
    sock.close()
    report("sink", pkts, nbytes, elapsed)
    if other:
        print("BLAST sink_other=%d (payload length did not match, not counted)" % other, flush=True)


def do_loop(seconds, size):
    """Self-loop: same process sends and receives, giving the ruler limit of this machine/process."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    sock.bind(("127.0.0.1", 0))
    addr = sock.getsockname()
    buf = bytes(size)
    pkts = nbytes = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        for _ in range(64):
            try:
                sock.sendto(buf, addr)
            except OSError:
                break
            pkts += 1
            nbytes += size
        sock.settimeout(0.001)
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                nbytes += 0
                del data
        except socket.timeout:
            pass
    elapsed = time.perf_counter() - t0
    sock.close()
    report("loop", pkts, nbytes, elapsed)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    role = sys.argv[1]
    if role == "send":
        do_send(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]),
                int(sys.argv[5]) if len(sys.argv) > 5 else PAYLOAD)
    elif role == "sink":
        do_sink(int(sys.argv[2]), float(sys.argv[3]),
                int(sys.argv[4]) if len(sys.argv) > 4 else 0)
    elif role == "loop":
        do_loop(float(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else PAYLOAD)
    else:
        print("unknown role %s" % role)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
