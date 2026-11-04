#!/usr/bin/env python3
"""iwan end-to-end echo tool (TCP / UDP), used by kernel/tests/tcp_echo_test.sh.

Usage:
  server: echo_net.py server --bind 10.9.0.2 --port 9000 [--udp] [--timeout 20]
  client: echo_net.py client --host 10.9.0.2 --port 9000 --bytes 4194304 [--timeout 20]
          echo_net.py client --host 10.9.0.2 --port 9000 --udp --size 3000 --count 8
          echo_net.py client ... --expect-fail     # negative case: the echo must not arrive

TCP: the client sends deterministic data and the server echoes it verbatim. The client uses a separate reader thread to send and receive at the same time,
     avoiding the classic deadlock where "both sides are writing and nobody is reading"; the echoed content is verified byte by byte.
UDP: the client sends count datagrams of size bytes (crossing the inner MTU triggers inner IP fragmentation),
     the server echoes each one; the client matches by the 4-byte sequence number and verifies content and count.

Output is in KEY=value form so shell scripts can assert on it; exit code 0 = pass.
"""
import argparse
import hashlib
import socket
import sys
import threading
import time

PAT = bytes((i * 7 + 3) & 0xFF for i in range(256))


def pattern(n: int) -> bytes:
    """Deterministic payload so both ends can compute the expected value independently."""
    if n <= 0:
        return b""
    return (PAT * (n // len(PAT) + 1))[:n]


def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def emit(**kw):
    print(" ".join(f"{k}={v}" for k, v in kw.items()), flush=True)


# ---------------------------------------------------------------- TCP

def tcp_server(args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(4)
    srv.settimeout(args.timeout)
    print(f"SERVER_READY tcp {args.bind}:{args.port}", flush=True)
    try:
        conn, peer = srv.accept()
    except socket.timeout:
        emit(SERVER_TIMEOUT=1)
        return 2
    conn.settimeout(args.timeout)
    total = 0
    h = hashlib.md5()
    try:
        while True:
            chunk = conn.recv(1 << 16)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
            conn.sendall(chunk)          # echo verbatim
    except socket.timeout:
        emit(SERVER_TIMEOUT=1)
        conn.close()
        return 2
    try:
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    conn.close()
    srv.close()
    emit(SERVER_OK=1, proto="tcp", bytes=total, md5=h.hexdigest())
    return 0


def tcp_client(args):
    n = args.bytes
    want = pattern(n)
    got = bytearray()
    err = []

    def reader(sock):
        while len(got) < n:
            try:
                chunk = sock.recv(1 << 16)
            except socket.timeout:
                err.append(f"recv timeout (already received {len(got)}/{n})")
                return
            except OSError as e:
                err.append(f"recv failed: {e}")
                return
            if not chunk:
                return
            got.extend(chunk)

    t0 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.host, args.port))
    except OSError as e:
        if args.expect_fail:
            emit(CLIENT_OK=1, expected_fail=1, reason=f"connect failed: {e}")
            return 0
        emit(CLIENT_FAIL=1, reason=f"connect failed: {e}")
        return 1

    if args.expect_fail:
        # being able to connect (the SYN got through) is also abnormal: it means the server is not decrypting, check the counters
        emit(CLIENT_FAIL=1, reason="negative case but the connection succeeded")
        sock.close()
        return 1

    th = threading.Thread(target=reader, args=(sock,), daemon=True)
    th.start()
    sent = 0
    try:
        view = memoryview(want)
        while sent < n:
            sent += sock.send(view[sent:sent + (1 << 16)])
    except OSError as e:
        emit(CLIENT_FAIL=1, reason=f"send failed: {e}")
        sock.close()
        return 1
    sock.shutdown(socket.SHUT_WR)
    th.join(timeout=args.timeout + 5)
    elapsed = time.time() - t0
    sock.close()

    if err:
        emit(CLIENT_FAIL=1, reason=err[0])
        return 1
    if bytes(got) != want:
        want_h, got_h = md5(want), md5(bytes(got))
        emit(CLIENT_FAIL=1, reason="echo content mismatch",
             sent_md5=want_h, recv_md5=got_h, recv_bytes=len(got))
        return 1
    emit(CLIENT_OK=1, proto="tcp", sent=sent, recv=len(got), md5=md5(bytes(got)),
         seconds=f"{elapsed:.3f}", mbps=f"{n * 8 / elapsed / 1e6:.1f}")
    return 0


# ---------------------------------------------------------------- UDP

def udp_server(args):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.settimeout(args.timeout)
    print(f"SERVER_READY udp {args.bind}:{args.port}", flush=True)
    count = 0
    h = hashlib.md5()
    try:
        while True:
            data, peer = srv.recvfrom(1 << 16)
            h.update(data)
            count += 1
            srv.sendto(data, peer)
            if args.count and count >= args.count:
                break
    except socket.timeout:
        emit(SERVER_TIMEOUT=1, received=count)
        srv.close()
        return 2
    srv.close()
    emit(SERVER_OK=1, proto="udp", datagrams=count, md5=h.hexdigest())
    return 0


def udp_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.connect((args.host, args.port))
    payloads = {}
    for seq in range(args.count):
        body = seq.to_bytes(4, "big") + pattern(args.size - 4)
        payloads[seq] = body
        sock.send(body)
    seen = {}
    try:
        for _ in range(args.count):
            data = sock.recv(1 << 16)
            if len(data) < 4:
                emit(CLIENT_FAIL=1, reason=f"echo too short: {len(data)}")
                return 1
            seq = int.from_bytes(data[:4], "big")
            seen[seq] = seen.get(seq, 0) + 1
            if data != payloads.get(seq):
                emit(CLIENT_FAIL=1, reason=f"datagram {seq} content mismatch",
                     got_len=len(data), want_len=len(payloads.get(seq, b"")))
                return 1
    except socket.timeout:
        emit(CLIENT_FAIL=1, reason=f"only received {sum(seen.values())}/{args.count} echoes")
        return 1
    if len(seen) != args.count or any(v != 1 for v in seen.values()):
        emit(CLIENT_FAIL=1, reason=f"bad echo sequence numbers: {sorted(seen.items())}")
        return 1
    total = sum(len(p) for p in payloads.values())
    emit(CLIENT_OK=1, proto="udp", datagrams=args.count, size=args.size, bytes=total)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    for name in ("server", "client"):
        p = sub.add_parser(name)
        p.add_argument("--udp", action="store_true")
        p.add_argument("--port", type=int, default=9000)
        p.add_argument("--timeout", type=float, default=20.0)
        if name == "server":
            p.add_argument("--bind", default="0.0.0.0")
            p.add_argument("--count", type=int, default=0,
                           help="UDP: exit after receiving this many datagrams (0 = wait forever)")
        else:
            p.add_argument("--host", required=True)
            p.add_argument("--bytes", type=int, default=65536, help="TCP bytes to send")
            p.add_argument("--size", type=int, default=3000, help="UDP bytes per datagram")
            p.add_argument("--count", type=int, default=8, help="UDP datagram count")
            p.add_argument("--expect-fail", action="store_true",
                           help="negative case: passes only if the echo is not received")
    args = ap.parse_args()
    if args.role == "server":
        return udp_server(args) if args.udp else tcp_server(args)
    return udp_client(args) if args.udp else tcp_client(args)


if __name__ == "__main__":
    sys.exit(main())
