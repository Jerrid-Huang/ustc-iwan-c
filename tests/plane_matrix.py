#!/usr/bin/env python3
"""Two link types x two transmit planes: performance matrix.

Topology (all in userspace on this host, no root required):

    probe --SOCKS5--> iwan-client --link A(UDP)--> iwan-server --link B--> echo target

  link A = client<->server (bearer network). Use tests/link_sim.py to relay the tunnel's
           UDP flow: one-way rate cap, one-way delay, jitter, loss, queue limit.
  link B = server<->target. Use iwan-server --no-tun's echo mirror as the target,
           delay/jitter/loss/rate emulated by the server's env vars (IWAN_LEGB_*).

Each cell measures four quantities:
  latency  = median round-trip of a small echo packet (ms)
  jitter   = p95 - p50 of the same sample group (ms)
  upload   = byte rate written by the probe (Mbit/s)
  download = byte rate read back by the probe (Mbit/s)

Two transmit planes:
  tun    : default (UDP_SEGMENT batching + EAGAIN backpressure retry), equivalent to this
           repo's userspace data plane (TUN plane) transmit behavior
  kernel : IWAN_TX_NO_GSO=1 IWAN_TX_DROP_EBUSY=1, equivalent to the kernel plane's
           "one packet per submit, no bearer-queue congestion visibility, drop on congestion" semantics

Usage:
  python3 tests/plane_matrix.py                     # 4x4 two modes, about 4 minutes
  python3 tests/plane_matrix.py --cells 2 --json out.json
"""
import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "bin", "iwan-client")
SERVER = os.path.join(ROOT, "bin", "iwan-server")
LINKSIM = os.path.join(ROOT, "tests", "link_sim.py")

# Link conditions: name, one-way delay ms, jitter ms, loss rate, one-way rate cap Mbit/s (0=unlimited)
LEGA = [
    ("good(local)", 0.0, 0.0, 0.0, 0.0),
    ("broadband", 8.0, 2.0, 0.001, 200.0),
    ("wireless", 25.0, 10.0, 0.01, 100.0),
    ("long-distance 4G", 80.0, 25.0, 0.02, 30.0),
]
# link B delay is the server<->target round trip, so it is specified as RTT
LEGB = [
    ("same datacenter", 0.0, 0.0, 0.0, 0.0),
    ("metro", 10.0, 2.0, 0.0, 0.0),
    ("cross-province", 40.0, 8.0, 0.001, 0.0),
    ("cross-ocean", 120.0, 20.0, 0.01, 0.0),
]

MODES = [
    ("tun", {}),
    ("kernel", {"IWAN_TX_NO_GSO": "1", "IWAN_TX_DROP_EBUSY": "1"}),
]


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=5.0, kind=socket.SOCK_STREAM):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, kind)
            s.settimeout(0.2)
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def socks_connect(socks_port, dst, dport, timeout=8.0):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks greeting failed")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst) +
              struct.pack("!H", dport))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError("socks connect failed: %r" % (rep,))
    return s


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        part = s.recv(n - len(buf))
        if not part:
            raise RuntimeError("peer closed")
        buf += part
    return buf


def measure_cell(socks_port, seconds=3.0, samples=15):
    """Return dict(lat_ms, jitter_ms, up_mbps, down_mbps)."""
    lat = []
    s = socks_connect(socks_port, "10.99.0.2", 80)
    for i in range(samples):
        t0 = time.perf_counter()
        s.sendall(b"P%015d" % i)
        recv_exact(s, 16)
        lat.append((time.perf_counter() - t0) * 1000.0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    time.sleep(0.5)

    lat_sorted = sorted(lat)
    med = lat_sorted[len(lat_sorted) // 2]
    p95 = lat_sorted[min(len(lat_sorted) - 1, int(0.95 * len(lat_sorted)))]
    jitter = p95 - med

    # Bulk: single stream, 2 MB in-flight window (write only what was read), to avoid
    # treating the local socket buffer as link capacity. With the echo target both directions must carry equal bytes.
    WIN = 256 << 10
    CHUNK = 16 << 10
    sent = recvd = 0
    try:
        s = socks_connect(socks_port, "10.99.0.2", 80, timeout=6.0)
    except (OSError, RuntimeError):
        s = None
    if s is not None:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        s.setblocking(False)
        buf = bytearray(CHUNK)
        view = memoryview(buf)
        inflight = 0
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < seconds + 1.0:
            while inflight < WIN:
                try:
                    n = s.send(view)
                except BlockingIOError:
                    break
                except OSError:
                    inflight = WIN
                    break
                sent += n
                inflight += n
            try:
                n = s.recv_into(buf)
            except BlockingIOError:
                if time.perf_counter() - t0 >= seconds:
                    break
                time.sleep(0.0002)
                continue
            except OSError:
                break
            if n == 0:
                break
            recvd += n
            inflight -= n
        elapsed = max(time.perf_counter() - t0, 0.1)
        s.close()
    up = sent * 8.0 / max(elapsed, 0.1) / 1e6
    down = recvd * 8.0 / max(elapsed, 0.1) / 1e6

    return {"lat_ms": med, "jitter_ms": jitter, "up_mbps": up,
            "down_mbps": down}


def run_cell(mode_env, lega, legb, seconds, samples, users_file, log_dir):
    la_name, la_delay, la_jit, la_loss, la_rate = lega
    lb_name, lb_rtt, lb_jit, lb_loss, lb_rate = legb

    srv_port = free_port(socket.SOCK_DGRAM)
    socks_port = free_port()

    srv_env = dict(os.environ)
    srv_env.update({
        "IWAN_LEGB_RTT_MS": "%.3f" % lb_rtt,
        "IWAN_LEGB_JITTER_MS": "%.3f" % lb_jit,
        "IWAN_LEGB_LOSS_PCT": "%.3f" % (lb_loss * 100.0),
        "IWAN_LEGB_RATE_MBIT": "%.3f" % lb_rate,
    })
    srv_log = open(os.path.join(log_dir, "server.log"), "w")
    srv = subprocess.Popen([SERVER, "--no-tun", "--port", str(srv_port),
                            "--users", users_file],
                           stdout=srv_log, stderr=subprocess.STDOUT,
                           env=srv_env)

    # link_sim needs its own listening port and cannot share the server's: take another
    link_port = free_port(socket.SOCK_DGRAM)
    sim_args = [sys.executable, LINKSIM,
                "--listen", "127.0.0.1:%d" % link_port,
                "--upstream", "127.0.0.1:%d" % srv_port,
                "--delay-ms", "%.3f" % la_delay,
                 "--jitter-ms", "%.3f" % la_jit,
                 "--loss", "%.5f" % la_loss]
    if la_rate:
        sim_args += ["--rate-mbit", "%.3f" % la_rate]
    sim_log = open(os.path.join(log_dir, "linksim.log"), "w")
    sim = subprocess.Popen(sim_args, stdout=sim_log, stderr=subprocess.STDOUT)

    time.sleep(0.5)
    cli_env = dict(os.environ)
    cli_env.update(mode_env)
    cli_log = open(os.path.join(log_dir, "client.log"), "w")
    cli = subprocess.Popen([CLIENT, "socks", "--server", "127.0.0.1",
                            "--port", str(link_port), "--user", "revtest",
                            "--pass", "revpass",
                            "--listen", "127.0.0.1:%d" % socks_port],
                           stdout=cli_log, stderr=subprocess.STDOUT,
                           env=cli_env)
    try:
        if not wait_port(socks_port, timeout=8.0):
            raise RuntimeError("client socks listener did not come up")
        time.sleep(0.3)
        res = measure_cell(socks_port, seconds, samples)
    finally:
        for p in (cli, sim, srv):
            try:
                p.send_signal(signal.SIGTERM)
            except OSError:
                pass
        for p in (cli, sim, srv):
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in (cli_log, sim_log, srv_log):
            f.close()
    res["lega"] = la_name
    res["legb"] = lb_name
    return res


def fmt(v):
    return ("%.1f" % v).rstrip("0").rstrip(".") if v < 100 else "%.0f" % v


def table(rows, cells):
    names_b = [c[0] for c in cells]
    out = []
    head = "| link A \\ link B | " + " | ".join(names_b) + " |"
    out.append(head)
    out.append("|" + "---|" * (len(names_b) + 1))
    for r in rows:
        line = "| %s | " % r
        for c in cells:
            d = None
            for res in results:
                if res["lega"] == r and res["legb"] == c[0]:
                    d = res
                    break
            if d is None:
                line += "-- | "
            else:
                line += ("%s ms / %s ms / up %s / down %s Mbps | "
                         % (fmt(d["lat_ms"]), fmt(d["jitter_ms"]),
                            fmt(d["up_mbps"]), fmt(d["down_mbps"])))
        out.append(line)
    return "\n".join(out)


results = []


def main():
    global results
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=3.0)
    ap.add_argument("--samples", type=int, default=15)
    ap.add_argument("--cells", type=int, default=4,
                    help="take the first N levels of each link type (default 4)")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    lega = LEGA[:args.cells]
    legb = LEGB[:args.cells]

    users = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    users.write("revtest:revpass\n")
    users.close()
    os.chmod(users.name, 0o600)

    tables = {}
    for mode_name, mode_env in MODES:
        print("=== mode %s ===" % mode_name, file=sys.stderr)
        results = []
        for a in lega:
            for b in legb:
                log_dir = tempfile.mkdtemp(prefix="pm_")
                try:
                    r = run_cell(mode_env, a, b, args.seconds, args.samples,
                                 users.name, log_dir)
                except Exception as e:            # noqa: BLE001
                    print("  %s x %s: FAILED %s" % (a[0], b[0], e),
                          file=sys.stderr)
                    r = {"lega": a[0], "legb": b[0], "lat_ms": float("nan"),
                         "jitter_ms": float("nan"), "up_mbps": float("nan"),
                         "down_mbps": float("nan")}
                results.append(r)
                print("  A=%-8s B=%-6s lat=%6.1f jit=%6.1f up=%7.1f down=%7.1f"
                      % (r["lega"], r["legb"], r["lat_ms"], r["jitter_ms"],
                         r["up_mbps"], r["down_mbps"]), file=sys.stderr)
        tables[mode_name] = table([a[0] for a in lega], legb)

    os.unlink(users.name)

    for mode_name, _ in MODES:
        print("\n### %s" % mode_name)
        print(tables[mode_name])
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"cells": [a[0] for a in lega],
                       "legb": [b[0] for b in legb],
                       "tables": tables}, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
