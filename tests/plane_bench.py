#!/usr/bin/env python3
"""Simulate "opening test.ustc.edu.cn in a browser": multi-connection HTTP(S) download throughput.

No browser is started; it only does what a browser does: open N HTTP connections to the speed-test site
and fetch the same URL concurrently (or a large file split by Range), reporting per-second and overall goodput.

Usage (through the tunnel):
  ./bin/iwan-client socks --server 202.38.64.106 --port 6001 --user ... \\
      --pass-file /tmp/pw.txt --listen 127.0.0.1:11101
  python3 tests/plane_bench.py --proxy 127.0.0.1:11101 \\
      --url http://test.ustc.edu.cn/speedtest/upload/10mb.bin --conns 4 --seconds 8

Direct (no proxy) is also supported, as a link baseline:
  python3 tests/plane_bench.py --url http://... --conns 4 --seconds 8

Output: per-second sample lines + final JSON (--json prints a machine-readable summary).

Note: only HTTP response-body bytes are counted (headers are skipped); chunked-encoding
framing headers are included (at most 1% error), which is enough for A/B comparison.
"""
import argparse
import json
import socket
import ssl
import struct
import sys
import threading
import time

STOP = threading.Event()
LOCK = threading.Lock()
BYTES = 0
CONN_BYTES = []
ERRORS = []


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("socks: peer closed")
        buf += part
    return buf


def socks5_connect(proxy, dst_host, dst_port, timeout):
    host, port = proxy
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    v, m = recv_exact(s, 2)
    if v != 5 or m != 0:
        raise ConnectionError(f"socks: bad greeting {v}/{m}")
    h = dst_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dst_port))
    v, rep, _, atyp = recv_exact(s, 4)
    if rep != 0:
        raise ConnectionError(f"socks: connect failed rep={rep}")
    if atyp == 1:
        recv_exact(s, 4 + 2)
    elif atyp == 3:
        n = recv_exact(s, 1)[0]
        recv_exact(s, n + 2)
    elif atyp == 4:
        recv_exact(s, 16 + 2)
    else:
        raise ConnectionError(f"socks: bad atyp {atyp}")
    return s


def parse_url(url):
    if url.startswith("https://"):
        rest, tls, port = url[8:], True, 443
    elif url.startswith("http://"):
        rest, tls, port = url[7:], False, 80
    else:
        raise SystemExit("url must start with http:// or https://")
    slash = rest.find("/")
    if slash < 0:
        hostport, path = rest, "/"
    else:
        hostport, path = rest[:slash], rest[slash:] or "/"
    if ":" in hostport:
        host, p = hostport.rsplit(":", 1)
        port = int(p)
    else:
        host = hostport
    return host, port, path, tls


def worker(idx, host, port, path, tls, proxy, timeout, deadline):
    total = 0
    while not STOP.is_set() and time.time() < deadline:
        try:
            if proxy:
                s = socks5_connect(proxy, host, port, timeout)
            else:
                s = socket.create_connection((host, port), timeout)
                s.settimeout(timeout)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: iwan-plane-bench/1\r\nAccept: */*\r\n"
                   f"Connection: close\r\n\r\n")
            s.sendall(req.encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                part = s.recv(65536)
                if not part:
                    break
                buf += part
            body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
            global BYTES
            if body:
                with LOCK:
                    BYTES += len(body)
                total += len(body)
            while not STOP.is_set() and time.time() < deadline:
                part = s.recv(262144)
                if not part:
                    break
                with LOCK:
                    BYTES += len(part)
                total += len(part)
            s.close()
        except Exception as e:                      # noqa: BLE001
            with LOCK:
                ERRORS.append(f"{type(e).__name__}: {e}")
            if STOP.is_set() or time.time() >= deadline:
                break
            time.sleep(0.2)
    with LOCK:
        CONN_BYTES[idx] = total


def sampler(seconds, deadline):
    global BYTES
    last, last_t = 0, time.time()
    while not STOP.is_set() and time.time() < deadline:
        time.sleep(1.0)
        now = time.time()
        with LOCK:
            cur = BYTES
        dt = now - last_t
        mbps = (cur - last) * 8 / dt / 1e6 if dt > 0 else 0
        print(f"t={now - (deadline - seconds):5.1f}s  {mbps:8.2f} Mbps  "
              f"({(cur - last) / dt / 1e6:6.2f} MB/s)", flush=True)
        last, last_t = cur, now


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://test.ustc.edu.cn/")
    ap.add_argument("--proxy", default="", help="SOCKS5 host:port (empty=direct)")
    ap.add_argument("--conns", type=int, default=4)
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--connect-timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    host, port, path, tls = parse_url(a.url)
    proxy = None
    if a.proxy:
        ph, _, pp = a.proxy.rpartition(":")
        proxy = (ph or "127.0.0.1", int(pp))

    CONN_BYTES.extend([0] * a.conns)
    deadline = time.time() + a.seconds + 1.0
    t0 = time.time()

    ths = [threading.Thread(target=worker, daemon=True,
                            args=(i, host, port, path, tls, proxy,
                                  a.connect_timeout, deadline))
           for i in range(a.conns)]
    for t in ths:
        t.start()
    sampler(a.seconds, deadline)
    STOP.set()
    for t in ths:
        t.join(timeout=2)
    elapsed = time.time() - t0
    with LOCK:
        total = BYTES
    mbps = total * 8 / elapsed / 1e6 if elapsed else 0
    out = {
        "url": a.url,
        "proxy": a.proxy or None,
        "conns": a.conns,
        "seconds": round(elapsed, 2),
        "bytes": total,
        "mbps": round(mbps, 2),
        "per_conn_mbps": [round(b * 8 / elapsed / 1e6, 2) for b in CONN_BYTES],
        "errors": ERRORS[:5],
    }
    if a.json:
        print(json.dumps(out, ensure_ascii=False))
    else:
        print(f"\nRESULT  {mbps:.2f} Mbps  ({total / elapsed / 1e6:.2f} MB/s)  "
              f"conns={a.conns} elapsed={elapsed:.2f}s  "
              f"per-conn={out['per_conn_mbps']}")
        if ERRORS:
            print(f"errors: {len(ERRORS)} (first: {ERRORS[0]})")


if __name__ == "__main__":
    sys.exit(main())
