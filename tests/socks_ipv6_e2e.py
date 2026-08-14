#!/usr/bin/env python3
"""Root-free IPv6 SOCKS5 end-to-end test.

Requires (started by the caller, e.g. the CI step):
  - iwan-server --no-tun (TCP echo mirror) on a known port, and
  - iwan-client socks --socks-ipv6 listening on a known port
    (without --socks-ipv6 the server is assumed IPv4-only and ATYP=4
    CONNECTs are rejected rep=8).

The client opens a SOCKS5 connection with an ATYP=4 (IPv6) CONNECT to
the unreachable-off-link target 2001:db8::1; the server's echo mirror
answers it (the inner v6 SYN is mirrored, so the connection
establishes). The test asserts:
  - the greeting reply {5,0},
  - a 22-byte success reply (ver=5 rep=0 rsv=0 atyp=4) whose BND.ADDR
    is the client's derived ULA (fd00::/96 + inner IPv4, protocol.h),
  - a byte-exact echo round-trip of a payload through the tunnel.

Usage: python3 tests/socks_ipv6_e2e.py [--listen HOST:PORT]
"""

import argparse
import socket

DEFAULT_LISTEN = "127.0.0.1:11081"
TARGET = b"\x20\x01\x0d\xb8" + b"\x00" * 12   # 2001:db8::1
PAYLOAD = b"ipv6-e2e-payload" * 100           # 1600 bytes


def recv_exact(sock, n, timeout):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError("connection closed mid-read: %d/%d bytes"
                                 % (len(buf), n))
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default=DEFAULT_LISTEN)
    args = ap.parse_args()
    host, _, port = args.listen.rpartition(":")
    port = int(port)

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(b"\x05\x01\x00")
    assert recv_exact(s, 2, 15) == b"\x05\x00", "greeting"
    s.sendall(b"\x05\x01\x00\x04" + TARGET + b"\x00\x50")
    r = recv_exact(s, 22, 15)
    assert r[0] == 5 and r[1] == 0 and r[3] == 4, \
        "v6 success reply: %r" % r
    assert r[4] == 0xfd, "BND.ADDR must be the derived ULA: %r" % r
    s.sendall(PAYLOAD)
    got = b""
    s.settimeout(15)
    while len(got) < len(PAYLOAD):
        x = s.recv(4096)
        if not x:
            break
        got += x
    assert got == PAYLOAD, "echo mismatch: %d/%d bytes" % (len(got),
                                                           len(PAYLOAD))
    s.close()
    print("IPv6 SOCKS e2e: PASS")


if __name__ == "__main__":
    main()
