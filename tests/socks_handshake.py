#!/usr/bin/env python3
"""Root-free SOCKS5 handshake test suite.

Usage:
    python3 tests/socks_handshake.py [--harness PATH] [--token STR]
                                     [--fail-max N] [--window-ms N]
                                     [--connect-timeout-ms N]

The default harness path is <repo>/bin/socks_handshake_harness, where
<repo> is the parent of this script's directory (tests/..); the .exe
suffix is appended on Windows.

The suite drives the REAL production SOCKS5 code paths (accept, RFC1929
handshake, CONNECT, userspace netstack) through a loopback TCP listener.
Each case opens a FRESH TCP connection and asserts exact wire bytes. The
harness is run twice sequentially — once with no auth token (no-token
cases) and once with --token (token cases) — unless --token is omitted,
in which case only the no-token run happens. The rate-limit and
connect-timeout knobs are passed through the environment
(IWAN_AUTH_FAIL_MAX, IWAN_AUTH_FAIL_WINDOW_MS,
IWAN_NS_CONNECT_TIMEOUT_MS); the harness reads them itself.

Exits 0 iff all cases pass. Prints one PASS/FAIL line per case; a FAIL
prints the reason and the suite stops at the first failure.
"""

import argparse
import os
import socket
import subprocess
import sys
import threading
import time

DEFAULT_READ_TIMEOUT = 5.0
STALL_TIMEOUT = 0.5
LISTEN_TIMEOUT = 30.0
WRONGPASS = b"wrongpass"


def harness_path():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    exe = "socks_handshake_harness"
    if sys.platform.startswith("win"):
        exe += ".exe"
    return os.path.join(repo, "bin", exe)


def read_listen_line(proc):
    """Read the harness banner without hanging if it dies or stalls."""
    result = []

    def reader():
        result.append(proc.stdout.readline())

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(LISTEN_TIMEOUT)
    if t.is_alive():
        proc.kill()
        proc.wait()
        raise AssertionError("harness printed no LISTEN line within %.0fs"
                             % LISTEN_TIMEOUT)
    if not result or not result[0]:
        raise AssertionError("harness exited (code %s) before printing LISTEN"
                             % proc.returncode)
    return result[0]


def start_harness(path, token, fail_max, window_ms, connect_timeout_ms):
    env = dict(os.environ)
    env["IWAN_AUTH_FAIL_MAX"] = str(fail_max)
    env["IWAN_AUTH_FAIL_WINDOW_MS"] = str(window_ms)
    env["IWAN_NS_CONNECT_TIMEOUT_MS"] = str(connect_timeout_ms)
    args = [path]
    if token is not None:
        args += ["--token", token]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, env=env)
    line = read_listen_line(proc)
    prefix = b"LISTEN 127.0.0.1:"
    if not line.startswith(prefix):
        proc.terminate()
        proc.wait()
        raise AssertionError("bad harness banner: %r" % line)
    port = int(line[len(prefix):].strip())
    return proc, port


def stop_harness(proc):
    proc.terminate()
    proc.wait()


def connect_socket(port):
    return socket.create_connection(("127.0.0.1", port),
                                    timeout=DEFAULT_READ_TIMEOUT)


def with_conn(port, fn):
    s = connect_socket(port)
    try:
        fn(s)
    finally:
        s.close()


def recv_exact(sock, n, timeout):
    """Read exactly n bytes; short read / timeout / EOF raise."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise AssertionError("timed out reading %d bytes, got %r"
                                 % (n, buf))
        if not chunk:
            raise AssertionError("connection closed mid-read: %d/%d bytes"
                                 % (len(buf), n))
        buf += chunk
    return buf


def expect_prefix(sock, prefix, timeout):
    """Read until the buffer starts with prefix; timeout/EOF raise."""
    sock.settimeout(timeout)
    buf = b""
    while not buf.startswith(prefix):
        try:
            chunk = sock.recv(64)
        except socket.timeout:
            raise AssertionError("timed out waiting for %r, got %r"
                                 % (prefix, buf))
        if not chunk:
            raise AssertionError("connection closed waiting for %r, got %r"
                                 % (prefix, buf))
        buf += chunk
    return buf


def expect_silence(sock, timeout, what):
    """No reply bytes within timeout; EOF/reset/timeout all pass."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(64)
    except socket.timeout:
        return
    except ConnectionResetError:
        return   # server closed with unread data: reset, still no reply
    if data:
        raise AssertionError("%s: got unexpected reply %r" % (what, data))


def send_expect(port, data, prefix, timeout=DEFAULT_READ_TIMEOUT):
    with_conn(port, lambda s: (s.sendall(data),
                               expect_prefix(s, prefix, timeout)))


def greeting_then(data2, prefix2, port, data1=b"\x05\x01\x00",
                  prefix1=b"\x05\x00", timeout=DEFAULT_READ_TIMEOUT):
    def body(s):
        s.sendall(data1)
        expect_prefix(s, prefix1, timeout)
        s.sendall(data2)
        expect_prefix(s, prefix2, timeout)
    with_conn(port, body)


def run_no_token(port, connect_timeout_ms):
    ct_wait = max(6.0, connect_timeout_ms / 1000.0 + 4.0)

    def greeting_ok():
        # offer no-auth method -> {5,0}
        send_expect(port, b"\x05\x01\x00", b"\x05\x00")

    def greeting_badver():
        # VER!=5 -> {5,0xff}
        send_expect(port, b"\x04\x01\x00", b"\x05\xff")

    def greeting_half_frame():
        # version byte alone gets no reply, then the rest -> {5,0}
        def body(s):
            s.sendall(b"\x05")
            time.sleep(0.2)
            s.sendall(b"\x01\x00")
            expect_prefix(s, b"\x05\x00", DEFAULT_READ_TIMEOUT)
        with_conn(port, body)

    def greeting_pipelined_connect():
        # greeting + CONNECT in one write -> {5,0} then rep=4
        def body(s):
            s.sendall(b"\x05\x01\x00" b"\x05\x01\x00\x01"
                      b"\x0a\xff\xff\x01" b"\x00\x50")
            expect_prefix(s, b"\x05\x00", DEFAULT_READ_TIMEOUT)
            expect_prefix(s, b"\x05\x04", ct_wait)
        with_conn(port, body)

    def cmd_bind():
        # CMD!=1 -> rep=7 (greeting first, then the BIND request)
        greeting_then(b"\x05\x02\x00\x01" b"\x0a\xff\xff\x01" b"\x00\x50",
                      b"\x05\x07", port)

    def rsv_nonzero():
        # RSV!=0 -> rep=7
        greeting_then(b"\x05\x01\x01\x01" b"\x0a\xff\xff\x01" b"\x00\x50",
                      b"\x05\x07", port)

    def domain_len0():
        # ATYP=3 with dlen=0 (full 7-byte frame) -> rep=8
        greeting_then(b"\x05\x01\x00\x03\x00" b"\x00\x50", b"\x05\x08",
                      port)

    def atyp_ipv6():
        # ATYP=4 -> rep=8
        greeting_then(b"\x05\x01\x00\x04" + b"\x00" * 16 + b"\x00\x50",
                      b"\x05\x08", port)

    def stall_big_nmethods():
        # lying nmethods=0xff must produce NO reply
        def body(s):
            s.sendall(b"\x05\xff" + b"A" * 64)
            expect_silence(s, STALL_TIMEOUT, "stall_big_nmethods")
        with_conn(port, body)

    cases = [
        ("greeting_ok", greeting_ok),
        ("greeting_badver", greeting_badver),
        ("greeting_half_frame", greeting_half_frame),
        ("greeting_pipelined_connect", greeting_pipelined_connect),
        ("cmd_bind", cmd_bind),
        ("rsv_nonzero", rsv_nonzero),
        ("domain_len0", domain_len0),
        ("atyp_ipv6", atyp_ipv6),
        ("stall_big_nmethods", stall_big_nmethods),
    ]
    run_cases(cases)


def run_token(port, token, fail_max, window_ms, connect_timeout_ms):
    ct_wait = max(6.0, connect_timeout_ms / 1000.0 + 4.0)
    tb = token.encode("utf-8")

    def auth_frame(password):
        return (b"\x01" + bytes([4]) + b"user"
                + bytes([len(password)]) + password)

    cases = []

    # 1. greeting_offer2: offer method 2 -> {5,2}
    cases.append(("greeting_offer2", lambda: send_expect(
        port, b"\x05\x01\x02", b"\x05\x02")))

    # 2. auth_ok: RFC1929 with the right password -> {1,0}
    cases.append(("auth_ok", lambda: greeting_then(
        auth_frame(tb), b"\x01\x00", port,
        data1=b"\x05\x01\x02", prefix1=b"\x05\x02")))

    # 3. greeting_offer0_only: no-auth method not offered -> {5,0xff}
    cases.append(("greeting_offer0_only", lambda: send_expect(
        port, b"\x05\x01\x00", b"\x05\xff")))

    # 4. auth_ulen0: ulen=0 -> {1,1} (not a lockout-counted failure)
    cases.append(("auth_ulen0", lambda: greeting_then(
        b"\x01\x00", b"\x01\x01", port,
        data1=b"\x05\x01\x02", prefix1=b"\x05\x02")))

    # 5. auth_plen0: plen=0 -> {1,1} (not counted)
    cases.append(("auth_plen0", lambda: greeting_then(
        b"\x01\x03abc\x00", b"\x01\x01", port,
        data1=b"\x05\x01\x02", prefix1=b"\x05\x02")))

    # 6. auth_badver: auth VER!=1 -> {1,1} (not counted)
    cases.append(("auth_badver", lambda: greeting_then(
        b"\x02" + bytes([3]) + b"abc" + bytes([len(tb)]) + tb, b"\x01\x01",
        port, data1=b"\x05\x01\x02", prefix1=b"\x05\x02")))

    # 7. wrongpass_xN: fail_max well-formed wrong passwords on FRESH
    #    connections; each gets {1,1} and counts toward the lockout
    def wrongpass_xN():
        for _ in range(fail_max):
            greeting_then(auth_frame(WRONGPASS), b"\x01\x01", port,
                          data1=b"\x05\x01\x02", prefix1=b"\x05\x02")
    cases.append(("wrongpass_xN", wrongpass_xN))

    # 8. blocked_after_lockout: after fail_max failures the source is
    #    dropped at accept — NO reply bytes (EOF/reset/timeout all pass)
    def blocked_after_lockout():
        def body(s):
            try:
                s.sendall(b"\x05\x01\x02")
            except OSError:
                pass   # server dropped the connection: that is the point
            expect_silence(s, 1.0, "blocked_after_lockout")
        with_conn(port, body)
    cases.append(("blocked_after_lockout", blocked_after_lockout))

    # 9. recovery_after_window: after the window passes, auth works again
    #    and the authenticated CONNECT path times out with rep=4
    def recovery_after_window():
        time.sleep(window_ms / 1000.0 + 0.5)
        def body(s):
            s.sendall(b"\x05\x01\x02")
            expect_prefix(s, b"\x05\x02", DEFAULT_READ_TIMEOUT)
            s.sendall(auth_frame(tb))
            expect_prefix(s, b"\x01\x00", DEFAULT_READ_TIMEOUT)
            s.sendall(b"\x05\x01\x00\x01" b"\x0a\xff\xff\x01" b"\x00\x50")
            expect_prefix(s, b"\x05\x04", ct_wait)
        with_conn(port, body)
    cases.append(("recovery_after_window", recovery_after_window))

    # 10. stall_lying_ulen: lying ulen=0xff must produce NO reply
    def stall_lying_ulen():
        def body(s):
            s.sendall(b"\x05\x01\x02")
            expect_prefix(s, b"\x05\x02", DEFAULT_READ_TIMEOUT)
            s.sendall(b"\x01\xff" + b"A" * 64)
            expect_silence(s, STALL_TIMEOUT, "stall_lying_ulen")
        with_conn(port, body)
    cases.append(("stall_lying_ulen", stall_lying_ulen))

    run_cases(cases)


def run_cases(cases):
    for name, fn in cases:
        try:
            fn()
        except AssertionError as e:
            print("FAIL %s: %s" % (name, e))
            sys.exit(1)
        except Exception as e:
            print("FAIL %s: %s: %s" % (name, type(e).__name__, e))
            sys.exit(1)
        print("PASS %s" % name)


def main():
    ap = argparse.ArgumentParser(
        description="Root-free SOCKS5 handshake test suite.")
    ap.add_argument("--harness", default=harness_path(),
                    help="path to the harness binary (default: "
                         "<repo>/bin/socks_handshake_harness)")
    ap.add_argument("--token", default=None,
                    help="auth token to test with; omitted -> only the "
                         "no-token run")
    ap.add_argument("--fail-max", type=int, default=3,
                    help="IWAN_AUTH_FAIL_MAX (default: 3)")
    ap.add_argument("--window-ms", type=int, default=4000,
                    help="IWAN_AUTH_FAIL_WINDOW_MS (default: 4000)")
    ap.add_argument("--connect-timeout-ms", type=int, default=1500,
                    help="IWAN_NS_CONNECT_TIMEOUT_MS (default: 1500)")
    args = ap.parse_args()

    if args.fail_max < 1 or args.fail_max > 100:
        print("FAIL: --fail-max must be in 1..100 (harness range)")
        return 1
    if args.window_ms < 1000:
        print("FAIL: --window-ms must be >= 1000 (must outlive the "
              "wrongpass run)")
        return 1
    if args.connect_timeout_ms < 1000:
        print("FAIL: --connect-timeout-ms must be >= 1000 (netstack "
              "accepts 1000..300000)")
        return 1
    if not os.path.isfile(args.harness):
        print("FAIL: harness not found: %s" % args.harness)
        return 1

    # run 1: no token -> no-token cases
    try:
        proc, port = start_harness(args.harness, None, args.fail_max,
                                   args.window_ms, args.connect_timeout_ms)
    except AssertionError as e:
        print("FAIL: %s" % e)
        return 1
    try:
        run_no_token(port, args.connect_timeout_ms)
    finally:
        stop_harness(proc)

    # run 2: with token -> token cases (skipped when --token is absent)
    if args.token is not None:
        try:
            proc, port = start_harness(args.harness, args.token,
                                       args.fail_max, args.window_ms,
                                       args.connect_timeout_ms)
        except AssertionError as e:
            print("FAIL: %s" % e)
            return 1
        try:
            run_token(port, args.token, args.fail_max, args.window_ms,
                      args.connect_timeout_ms)
        finally:
            stop_harness(proc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
