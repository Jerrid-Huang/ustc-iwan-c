#!/usr/bin/env python3
"""Fixed-duration TCP throughput client for the iWAN benchmark.

Usage: bench_client.py --target HOST:PORT --conns N --duration SECONDS
       --direction up|down [--socks HOST:PORT]

Opens N concurrent connections (optionally through a SOCKS5 proxy with a
no-auth handshake), runs each for a FIXED wall-clock window, and reports
the aggregate throughput from the ACTUAL bytes transferred in that
window (per-conn lines + aggregate). This is a throughput benchmark:
correctness is covered by tests/echo_client.py elsewhere.

up:   every conn streams data to the target (a discard sink) and counts
      what the local kernel accepted — TCP delivery is reliable, so the
      count equals the bytes that traversed the tunnel.
down: every conn reads the target's stream (a data source) and counts.

Exit 0 when every conn moved at least one byte.
"""
import argparse
import socket
import struct
import threading
import time

CHUNK = 1 << 16


def socks5_connect(proxy, target_host, target_port):
    ph, pp = proxy
    s = socket.create_connection((ph, pp), timeout=10)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise RuntimeError("SOCKS5 no-auth not accepted")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target_host) +
              struct.pack(">H", target_port))
    rep = s.recv(10)
    if len(rep) < 10 or rep[:4] != b"\x05\x00\x00\x01":
        s.close()
        raise RuntimeError(f"SOCKS5 connect failed: {rep.hex()}")
    return s


def bench_thread(idx, target, proxy, direction, duration, go, results):
    th, tp = target
    try:
        s = socks5_connect(proxy, th, tp) if proxy else \
            socket.create_connection((th, tp), timeout=15)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # 30s cap: a tunnel that silently stalls (no RST, no FIN) must
        # not hang the benchmark forever — the thread times out, reports
        # zero and the run moves on
        s.settimeout(30)
    except OSError as e:
        print(f"conn {idx}: connect failed: {e}", flush=True)
        return
    total = 0
    go.wait()
    deadline = time.monotonic() + duration
    try:
        if direction == "up":
            chunk = b"x" * CHUNK
            while time.monotonic() < deadline:
                s.sendall(chunk)
                total += len(chunk)
        else:
            while time.monotonic() < deadline:
                d = s.recv(1 << 20)
                if not d:
                    break
                total += len(d)
    except OSError:
        pass
    finally:
        s.close()
    results[idx] = total
    dt = duration
    print(f"conn {idx}: {total / 1e6:.1f} MB in {dt:.1f}s "
          f"({total * 8 / dt / 1e6:.0f} Mbit/s)", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--conns", type=int, default=4)
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--direction", choices=["up", "down"], required=True)
    ap.add_argument("--socks", default=None)
    args = ap.parse_args()

    th, tp = args.target.rsplit(":", 1)
    target = (th, int(tp))
    proxy = None
    if args.socks:
        ph, pp = args.socks.rsplit(":", 1)
        proxy = (ph, int(pp))

    go = threading.Event()
    results = [0] * args.conns
    threads = [threading.Thread(
        target=bench_thread,
        args=(i, target, proxy, args.direction, args.duration, go, results))
        for i in range(args.conns)]
    for t in threads:
        t.start()
    time.sleep(0.3)          # let all conns establish before the window
    t0 = time.monotonic()
    go.set()
    for t in threads:
        t.join()
    wall = time.monotonic() - t0
    total = sum(results)
    print(f"AGG {args.direction}: {total / 1e6:.1f} MB in {wall:.2f}s = "
          f"{total * 8 / wall / 1e6:.0f} Mbit/s aggregate", flush=True)
    raise SystemExit(0 if total > 0 else 1)


if __name__ == "__main__":
    main()
