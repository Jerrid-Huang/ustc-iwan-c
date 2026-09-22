#!/usr/bin/env python3
"""Stress & Chaos test client for ustc-iwan-c SOCKS mode.

Usage:
    python3 tests/stress_chaos_socks.py --socks 127.0.0.1:18083 \\
                                        --target 127.0.0.1:17010 \\
                                        --duration 600 \\
                                        --workers 30

Mixed traffic profiles:
    - Profile 1 (Bulk stream): full SOCKS5 handshake to echo target,
      stream data in 16KB chunks.
    - Profile 2 (TCP RST storm): complete SOCKS5 greeting, send 1-100 bytes,
      then immediately close with SO_LINGER (1, 0) forcing RST to peer.
    - Profile 3 (Half-close / FIN): send greeting and CONNECT, send 500 bytes,
      shutdown(SHUT_WR), read response, close.
    - Profile 4 (Slowloris / Hang): connect, send greeting, sleep 1-5 seconds,
      send partial connect, abort.
    - Profile 5 (Malformed): send bad version '\\x04\\x01', truncated bytes, etc.
    - Profile 6 (Domain / DNS): CONNECT with ATYP=3 domain names (localhost,
      non-existent .invalid, campus mirror, long label), with variants that
      wait for the reply, RST mid-resolution, or pipeline extra data.
    - Profile 7 (Burst connect): rapid connect/abort churn, empty connects
      closed immediately, ~half of them forced RST.

Statistics logged every second.
Exits 0 if runs to duration without unhandled script crashes.
"""

import argparse
import os
import random
import socket
import struct
import sys
import threading
import time

SOCKS5_OK = b"\x05\x00"
SOCKS5_CONNECT_OK_PREFIX = b"\x05\x00"


def recv_exact(s: socket.socket, n: int, timeout: float = 10.0) -> bytes:
    """Read exactly n bytes from socket s or raise RuntimeError."""
    s.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"EOF after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def socks5_connect(s: socket.socket, target_ip_bytes: bytes, target_port: int,
                   timeout: float = 10.0) -> None:
    """Perform standard SOCKS5 handshake and CONNECT."""
    s.settimeout(timeout)
    # Greeting (no auth)
    s.sendall(b"\x05\x01\x00")
    greet_reply = recv_exact(s, 2, timeout=timeout)
    if greet_reply != SOCKS5_OK:
        raise RuntimeError(f"SOCKS5 greeting rejected: {greet_reply.hex()}")

    # CONNECT request
    req = b"\x05\x01\x00\x01" + target_ip_bytes + struct.pack(">H", target_port)
    s.sendall(req)

    # Response header: VER, REP, RSV, ATYP
    hdr = recv_exact(s, 4, timeout=timeout)
    if hdr[0] != 5 or hdr[1] != 0:
        raise RuntimeError(f"SOCKS5 connect failed: {hdr.hex()}")

    atyp = hdr[3]
    if atyp == 1:
        # IPv4: 4 bytes + 2 bytes port
        recv_exact(s, 6, timeout=timeout)
    elif atyp == 4:
        # IPv6: 16 bytes + 2 bytes port
        recv_exact(s, 18, timeout=timeout)
    elif atyp == 3:
        # Domain name
        dlen = recv_exact(s, 1, timeout=timeout)[0]
        recv_exact(s, dlen + 2, timeout=timeout)
    else:
        raise RuntimeError(f"SOCKS5 unknown ATYP: {atyp}")


class ChaosStats:
    """Thread-safe statistics counter."""
    def __init__(self):
        self._lock = threading.Lock()
        self.active_conns = 0
        self.total_completed = 0
        self.rst_count = 0
        self.error_count = 0

    def inc_active(self):
        with self._lock:
            self.active_conns += 1

    def dec_active(self):
        with self._lock:
            self.active_conns -= 1

    def inc_completed(self):
        with self._lock:
            self.total_completed += 1

    def inc_rst(self):
        with self._lock:
            self.rst_count += 1

    def inc_error(self):
        with self._lock:
            self.error_count += 1

    def snapshot(self):
        with self._lock:
            return (self.active_conns, self.total_completed,
                    self.rst_count, self.error_count)


class ChaosWorker(threading.Thread):
    def __init__(self, worker_id: int, socks_addr: tuple, target_addr: tuple,
                 stats: ChaosStats, stop_event: threading.Event):
        super().__init__(name=f"worker-{worker_id}", daemon=True)
        self.worker_id = worker_id
        self.socks_host, self.socks_port = socks_addr
        self.target_host, self.target_port = target_addr
        self.target_ip_bytes = socket.inet_aton(self.target_host)
        self.stats = stats
        self.stop_event = stop_event

    def run(self):
        rng = random.Random(0xDEADBEEF + self.worker_id * 10007)
        # Profiles 1 to 7 weights:
        # 1: Bulk stream (15%)
        # 2: TCP RST storm (25%)
        # 3: Half-close / FIN (15%)
        # 4: Slowloris / Hang (10%)
        # 5: Malformed (10%)
        # 6: Domain / DNS (15%)
        # 7: Burst connect (10%)
        profiles = [1, 2, 3, 4, 5, 6, 7]
        weights = [15, 25, 15, 10, 10, 15, 10]

        while not self.stop_event.is_set():
            profile = rng.choices(profiles, weights=weights, k=1)[0]
            try:
                if profile == 1:
                    self.profile_bulk(rng)
                elif profile == 2:
                    self.profile_rst(rng)
                elif profile == 3:
                    self.profile_half_close(rng)
                elif profile == 4:
                    self.profile_slowloris(rng)
                elif profile == 5:
                    self.profile_malformed(rng)
                elif profile == 6:
                    self.profile_domain_dns(rng)
                elif profile == 7:
                    self.profile_burst_connect(rng)
                self.stats.inc_completed()
            except Exception:
                self.stats.inc_error()

            # Brief jitter between iterations to prevent synchronization lockstep
            time.sleep(rng.uniform(0.005, 0.05))

    def _open_socks_raw(self, timeout=5.0) -> socket.socket:
        s = socket.create_connection((self.socks_host, self.socks_port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def profile_bulk(self, rng: random.Random):
        """Profile 1 (Bulk stream): full SOCKS5 handshake to echo target, stream data in 16KB chunks."""
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=10.0)
            socks5_connect(s, self.target_ip_bytes, self.target_port, timeout=10.0)

            chunk_size = 16 * 1024
            num_chunks = rng.randint(4, 16)
            data_chunk = os.urandom(chunk_size)

            s.settimeout(10.0)
            for _ in range(num_chunks):
                if self.stop_event.is_set():
                    break
                s.sendall(data_chunk)
                got = recv_exact(s, chunk_size, timeout=10.0)
                if got != data_chunk:
                    raise RuntimeError("Echoed chunk mismatch in bulk stream")
        finally:
            self.stats.dec_active()
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def profile_rst(self, rng: random.Random):
        """Profile 2 (TCP RST storm): complete SOCKS5 greeting, send 1-100 bytes,

        then immediately close with SO_LINGER(1, 0) forcing immediate RST to peer.
        """
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=5.0)
            # SOCKS5 greeting
            s.sendall(b"\x05\x01\x00")
            recv_exact(s, 2, timeout=5.0)

            # Send 1-100 bytes (e.g. partial CONNECT or arbitrary noise)
            noise_len = rng.randint(1, 100)
            s.sendall(os.urandom(noise_len))
        finally:
            self.stats.dec_active()
            if s:
                try:
                    # Force immediate RST to peer
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    s.close()
                    self.stats.inc_rst()
                except OSError:
                    pass

    def profile_half_close(self, rng: random.Random):
        """Profile 3 (Half-close / FIN): send greeting and CONNECT, send 500 bytes,

        s.shutdown(socket.SHUT_WR), read response, close.
        """
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=10.0)
            socks5_connect(s, self.target_ip_bytes, self.target_port, timeout=10.0)

            payload = os.urandom(500)
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)

            # Read echoed payload until EOF
            s.settimeout(5.0)
            recvd = bytearray()
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                recvd.extend(chunk)

            if recvd != payload:
                raise RuntimeError(f"Half-close echo mismatch: got {len(recvd)} bytes, expected {len(payload)}")
        finally:
            self.stats.dec_active()
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def profile_slowloris(self, rng: random.Random):
        """Profile 4 (Slowloris / Hang): connect, send greeting, sleep 1-5 seconds,

        send partial connect, abort.
        """
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=10.0)
            s.sendall(b"\x05\x01\x00")
            recv_exact(s, 2, timeout=10.0)

            # Sleep 1-5 seconds (interruptible by stop_event)
            sleep_time = rng.uniform(1.0, 5.0)
            t_end = time.monotonic() + sleep_time
            while time.monotonic() < t_end and not self.stop_event.is_set():
                time.sleep(0.1)

            if not self.stop_event.is_set():
                # Partial CONNECT request (header without address/port, or partial bytes)
                partial = b"\x05\x01\x00\x01" + self.target_ip_bytes[: rng.randint(1, 3)]
                s.sendall(partial)
                time.sleep(0.05)
        finally:
            self.stats.dec_active()
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def profile_malformed(self, rng: random.Random):
        """Profile 5 (Malformed): send bad version \\x04\\x01, truncated bytes, etc."""
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=5.0)
            choice = rng.randint(1, 6)
            if choice == 1:
                # SOCKS4 request
                s.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
            elif choice == 2:
                # Bad SOCKS version
                s.sendall(b"\x04\x01")
            elif choice == 3:
                # Truncated greeting (only 1 byte)
                s.sendall(b"\x05")
            elif choice == 4:
                # Unsupported method count or empty methods
                s.sendall(b"\x05\x00")
            elif choice == 5:
                # CONNECT with invalid reserved byte or invalid atyp
                s.sendall(b"\x05\x01\x00")
                recv_exact(s, 2, timeout=3.0)
                s.sendall(b"\x05\x01\xFF\x01\x7f\x00\x00\x01\x00\x50")
            else:
                # Zero-length domain CONNECT (atyp 3 with len 0)
                s.sendall(b"\x05\x01\x00")
                recv_exact(s, 2, timeout=3.0)
                s.sendall(b"\x05\x01\x00\x03\x00\x00\x50")

            # Try to read whatever response the server returns or close on EOF/timeout
            s.settimeout(1.0)
            try:
                s.recv(64)
            except OSError:
                pass
        finally:
            self.stats.dec_active()
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def profile_domain_dns(self, rng: random.Random):
        """Profile 6 (Domain / DNS): CONNECT with ATYP=3 domain names.

        Exercises the tunnel's name-resolution path with a mix of resolvable,
        non-existent and over-long names, then RSTs, waits or pipelines data
        depending on the sub-behaviour chosen.
        """
        self.stats.inc_active()
        s = None
        try:
            s = self._open_socks_raw(timeout=5.0)
            s.sendall(b"\x05\x01\x00")
            recv_exact(s, 2, timeout=5.0)

            domains = [
                "localhost",
                f"no-such-host-{rng.randint(0, 0xFFFFFF):06x}.invalid",
                "mirrors.ustc.edu.cn",
                "a" * 60 + ".example.com",
            ]
            domain = rng.choice(domains).encode()

            # CONNECT with ATYP=3: 1-byte length + domain bytes + 2-byte port
            req = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack(">H", 80)
            s.sendall(req)

            sub = rng.randint(1, 3)
            if sub == 1:
                # Wait up to ~2s for the CONNECT reply, then close normally
                s.settimeout(2.0)
                try:
                    s.recv(10)
                except OSError:
                    pass
            elif sub == 2:
                # Force immediate RST: client gave up mid-resolution
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
                s = None
                self.stats.inc_rst()
            else:
                # Pipelined payload lands while the flow is still resolving
                s.sendall(os.urandom(200))
        finally:
            self.stats.dec_active()
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def profile_burst_connect(self, rng: random.Random):
        """Profile 7 (Burst connect): rapid connect/abort churn.

        Open 5-12 raw SOCKS5 connections in a row and drop each one instantly
        without sending a single byte; roughly half are aborted with
        SO_LINGER(1, 0) so the peer sees an RST instead of a clean FIN.
        """
        for _ in range(rng.randint(5, 12)):
            if self.stop_event.is_set():
                break

            self.stats.inc_active()
            s = None
            forced_rst = False
            try:
                # Short timeout keeps this profile from ever stalling
                s = self._open_socks_raw(timeout=1.0)
                if rng.random() < 0.5:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    forced_rst = True
            finally:
                self.stats.dec_active()
                if s:
                    try:
                        s.close()
                        if forced_rst:
                            self.stats.inc_rst()
                    except OSError:
                        pass


def parse_host_port(addr_str: str) -> tuple:
    if ":" not in addr_str:
        raise argparse.ArgumentTypeError(f"Invalid address format '{addr_str}', expected HOST:PORT")
    host, _, port_str = addr_str.rpartition(":")
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid port '{port_str}' in '{addr_str}'")
    return host, port


def main():
    parser = argparse.ArgumentParser(
        description="SOCKS mode stress & chaos test client"
    )
    parser.add_argument("--socks", required=True, help="SOCKS5 server address (HOST:PORT)")
    parser.add_argument("--target", required=True, help="Target echo server address (HOST:PORT)")
    parser.add_argument("--duration", type=int, default=600, help="Test duration in seconds (default: 600)")
    parser.add_argument("--workers", type=int, default=30, help="Number of concurrent worker threads (default: 30)")
    args = parser.parse_args()

    socks_addr = parse_host_port(args.socks)
    target_addr = parse_host_port(args.target)

    stats = ChaosStats()
    stop_event = threading.Event()

    workers = []
    for i in range(args.workers):
        w = ChaosWorker(i, socks_addr, target_addr, stats, stop_event)
        workers.append(w)
        w.start()

    print(f"Started {args.workers} chaos workers against SOCKS={args.socks}, TARGET={args.target} for {args.duration}s", flush=True)

    start_time = time.monotonic()
    last_print = start_time

    try:
        while True:
            now = time.monotonic()
            elapsed = now - start_time
            if elapsed >= args.duration:
                break

            time.sleep(1.0)
            active, completed, rst, errors = stats.snapshot()
            curr_elapsed = int(time.monotonic() - start_time)
            print(f"[{curr_elapsed:4d}s] active={active:<3d} completed={completed:<6d} rst={rst:<6d} errors={errors:<6d}", flush=True)

    except KeyboardInterrupt:
        print("\nStopping workers on KeyboardInterrupt...", flush=True)
    finally:
        stop_event.set()
        for w in workers:
            w.join(timeout=2.0)

    total_active, total_completed, total_rst, total_errors = stats.snapshot()
    total_elapsed = time.monotonic() - start_time
    print(f"\nFinal Statistics ({total_elapsed:.1f}s): active={total_active} completed={total_completed} rst={total_rst} errors={total_errors}", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
