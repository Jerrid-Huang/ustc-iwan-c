#!/usr/bin/env python3
"""Concurrent TCP echo test client for the iWAN integration test.

Usage: echo_client.py --target HOST:PORT [--conns N] [--socks HOST:PORT]
                      [--rounds R] [--payload P]

Opens N concurrent TCP connections (optionally through a SOCKS5 proxy
with no-auth handshake), sends R rounds of P-byte pseudo-random payloads
per connection plus one 64KiB burst, and verifies the echoed bytes
byte-for-byte. Prints one line per connection and an aggregate line;
exits 0 only if every connection echoed everything correctly.
"""
import argparse
import os
import random
import socket
import struct
import threading
import time

SOCKS5_OK = b"\x05\x00"
SOCKS5_CONNECT_OK = b"\x05\x00\x00\x01"


def socks5_connect(proxy, target_host, target_port):
    ph, pp = proxy
    s = socket.create_connection((ph, pp), timeout=10)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != SOCKS5_OK:
        s.close()
        raise RuntimeError("SOCKS5 no-auth not accepted")
    ip = socket.inet_aton(target_host)
    s.sendall(b"\x05\x01\x00\x01" + ip + struct.pack(">H", target_port))
    rep = s.recv(10)
    if len(rep) < 10 or rep[:4] != SOCKS5_CONNECT_OK:
        s.close()
        raise RuntimeError(f"SOCKS5 connect failed: {rep.hex()}")
    return s


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def run_bulk(s, total_bytes):
    """Streaming throughput phase: keep the pipe full — write
    continuously while a reader thread drains the echoed bytes. The
    echo rounds already verified byte-exactness; here only the byte
    count matters (the echo server mirrors verbatim). Returns
    (bytes_sent, seconds)."""
    recv = [0]
    stop = [False]

    def reader():
        while not stop[0]:
            d = s.recv(1 << 20)
            if not d:
                break
            recv[0] += len(d)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    chunk = b"x" * (1 << 16)
    sent = 0
    t0 = time.monotonic()
    while sent < total_bytes:
        n = min(len(chunk), total_bytes - sent)
        s.sendall(chunk[:n])
        sent += n
    while recv[0] < sent and time.monotonic() - t0 < 120:
        time.sleep(0.01)
    dt = time.monotonic() - t0   # measure BEFORE reaping the reader:
    if recv[0] != sent:          # it is blocked in recv() and would add
        s.close()                # its full join timeout to the timing
        raise RuntimeError(f"bulk echo mismatch: {recv[0]} != {sent}")
    s.close()                    # unblocks the reader thread
    t.join(timeout=2)
    return sent, dt


def run_conn(idx, target, proxy, rounds, payload, bulk_bytes):
    rng = random.Random(0xC0FFEE + idx)
    t0 = time.monotonic()
    th, tp = target
    s = socks5_connect(proxy, th, tp) if proxy else socket.create_connection(
        (th, tp), timeout=15)
    s.settimeout(15)
    total = 0
    try:
        for r in range(rounds):
            data = bytes(rng.randrange(256) for _ in range(payload))
            s.sendall(data)
            got = recv_exact(s, len(data))
            if got != data:
                raise RuntimeError(f"round {r}: echo mismatch "
                                   f"({len(got)} != {len(data)})")
            total += len(data)
        burst = os.urandom(65536)
        s.sendall(burst)
        if recv_exact(s, len(burst)) != burst:
            raise RuntimeError("burst: echo mismatch")
        total += len(burst)
        if bulk_bytes > 0:
            bsent, bdt = run_bulk(s, bulk_bytes)
            brate = bsent * 8 / bdt / 1e6
            print(f"conn {idx}: bulk {bsent / 1e6:.0f} MB in {bdt:.2f}s "
                  f"({brate:.0f} Mbit/s)", flush=True)
            total += bsent
            return True
    finally:
        try:
            s.close()
        except OSError:
            pass
    dt = time.monotonic() - t0
    rate = total * 8 / dt / 1e6
    print(f"conn {idx}: OK  {total} bytes in {dt:.2f}s "
          f"({rate:.0f} Mbit/s)", flush=True)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--conns", type=int, default=4)
    ap.add_argument("--socks", default=None)
    ap.add_argument("--rounds", type=int, default=32)
    ap.add_argument("--payload", type=int, default=2048)
    ap.add_argument("--bulk-mb", type=int, default=0,
                    help="streaming throughput phase, MiB per connection")
    args = ap.parse_args()

    th, tp = args.target.rsplit(":", 1)
    target = (th, int(tp))
    proxy = None
    if args.socks:
        ph, pp = args.socks.rsplit(":", 1)
        proxy = (ph, int(pp))
    bulk = args.bulk_mb * (1 << 20)

    threads = []
    results = [False] * args.conns
    for i in range(args.conns):
        t = threading.Thread(target=lambda i=i: results.__setitem__(
            i, run_conn(i, target, proxy, args.rounds, args.payload, bulk)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    ok = all(results)
    print(f"RESULT: {sum(results)}/{args.conns} connections echoed "
          f"correctly", flush=True)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
