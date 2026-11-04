#!/usr/bin/env python3
"""Host-side peer for the Windows data-plane wire test (one-way inbound proof).

Usage: win_wire_peer.py [WINDOW_SECONDS] [ALT_INNER_SRC]   (default 160)

This peer binds 0.0.0.0:PEER_PORT and is meant to be reached from a QEMU slirp
guest at 10.0.2.2:PEER_PORT (the slirp gateway forwards to host sockets; the
host's own LAN address is NOT usable as a stable target -- a host reboot can
take the wired NIC down and silently turn the whole run into a no-op).

ALT_INNER_SRC switches on a diagnostic mode: successive good frames alternate
their INNER SOURCE between the default (a guest-local address) and ALT_INNER_SRC
(a remote-looking one), and the payload says which variant it was. Windows
receive injection answers a local-source inner packet with
STATUS_INVALID_PARAMETER (0xC000000D) in the completion callback, so this mode
separates "local source is rejected" from "receive injection never works".

The guest (Windows, QEMU slirp) opens an iWAN session and its driver filters the
outbound/inbound paths. This peer plays the far end of the tunnel:

  * it listens on PEER_PORT and answers every "IWAN-HELLO" datagram the
    guest sends with GOOD tunnel frames, i.e. frames the guest driver must
    intercept at INBOUND_TRANSPORT_V4 (post-reassembly), decapsulate and inject
    at the network layer (pre-reassembly);
  * it also sends BAD frames (correct ports and length, wrong token) that the
    driver must reject: those are the negative control for the credential check.

Frame layout (byte-identical with the Linux kernel module, see
win-driver/iwan_win_frame.h):

    [outer IPv4][outer UDP sport=PEER_PORT dport=GUEST_PORT][8-byte frame][inner IP]

    frame[0]    type  0x18 = PT_DATA_ENC
    frame[1]    enc   1 (payload XORed with KEY, inner checksum plaintext)
    frame[2:4]  sid   big-endian
    frame[4:8]  tok   big-endian
    body            inner IP packet XORed from offset 0 with key[(off+i)&7]

The port pair is what gates the driver: it only takes a datagram whose source
port equals the session's dport and whose destination port equals the session's
sport. slirp restores the guest's own source port on the way back, so the peer
must simply reply to the address/port the HELLO came from.

Exit 0 after the window; prints one parseable summary line:
    PEER done: hellos=N bad=N good=N
"""

import socket
import struct
import sys
import time

KEY = bytes([1, 2, 3, 4, 5, 6, 7, 8])
SID = 0x1234
TOK = 0x12345678

PEER_PORT = 45678      # host side  = session dport
GUEST_PORT = 40660     # guest side = session sport
# The guest script (C:\iwan\vm-rx.ps1:389) actually sends b"IWAN-HELLO". We match by
# prefix and accept both spellings, **trusting the guest script**: earlier we only
# accepted our own b"IWAN-WIRE-HELLO", so the guest's hello was silently dropped
# (hellos=0) and the golden-vector test missed it -- peer and golden share one origin, so self-consistency hides this mismatch.
HELLO_PREFIXES = (b"IWAN-HELLO", b"IWAN-WIRE-HELLO")
GOOD_PER_HELLO = 3     # frames per round trip
INNER = ("10.99.0.1", 40001, "10.0.2.15", 9999, b"IWAN-INNER-OK")


def csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_inner(src=None, payload=None):
    s0, sp, dst, dp, p0 = INNER
    src = s0 if src is None else src
    payload = p0 if payload is None else payload
    total = 20 + 8 + len(payload)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", total)
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    ip[10:12] = struct.pack("!H", csum(bytes(ip)))
    udp = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
    return bytes(ip) + udp


def build_frame(tok, src=None, payload=None):
    inner = build_inner(src, payload)
    body = bytes(b ^ KEY[i % 8] for i, b in enumerate(inner))
    frame = struct.pack("!BBH", 0x18, 1, SID) + struct.pack("!I", tok) + body
    return struct.pack("!HHHH", PEER_PORT, GUEST_PORT, 8 + len(frame), 0) + frame


def describe(data):
    """Describe unrecognized datagrams in human terms as far as possible.

    The peer only recognizes the hello packets it sends by default; other packets used to print just the first 24 bytes as hex --
    so clues like "received 13 unknown 584-byte packets" could not identify the sender or the payload. Here
    we parse as a tunnel frame: 8-byte plaintext header, frame body (when enc=1) XOR-decrypted with the default key, then the inner
    IPv4 header. If it cannot be parsed, report PLAIN truthfully.
    """
    if len(data) >= 8 and data[0] in (0x14, 0x18):
        ftype = data[0]
        enc = data[1]
        sid = struct.unpack("!H", data[2:4])[0]
        tok = struct.unpack("!I", data[4:8])[0]
        body = data[8:]
        if enc:
            body = bytes(b ^ KEY[i % 8] for i, b in enumerate(body))
        inner = ""
        if len(body) >= 20 and (body[0] >> 4) == 4:
            tot = struct.unpack("!H", body[2:4])[0]
            proto = body[9]
            # Decode ICMP one level deeper: type/code immediately distinguishes echo (8/0),
            # port unreachable (3/3), redirect (5/x) -- attribution depends on these bytes.
            extra = ""
            if proto == 1 and len(body) >= 22:
                extra = " icmp:type=%d code=%d" % (body[20], body[21])
            tail = body[28:36].hex() if len(body) >= 36 else ""
            inner = " inner:tot=%d proto=%d %s->%s%s pay=%s" % (
                tot, proto, socket.inet_ntoa(body[12:16]),
                socket.inet_ntoa(body[16:20]), extra, tail)
        return "FRAME type=0x%02x enc=%d sid=0x%04x tok=0x%08x bodylen=%d%s" % (
            ftype, enc, sid, tok, len(body), inner)
    return "PLAIN"


def main():
    window = int(sys.argv[1]) if len(sys.argv) > 1 else 160
    alt_src = sys.argv[2] if len(sys.argv) > 2 else None
    # 4th argument: blast seconds. When >0, flood frames right after the first hello
    # instead of replying round by round -- used to measure inbound tunnel capacity (before deframe/reassembly injection).
    blast = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
    # Optional INNER_SIZE=<bytes>: inner payload length, used for throughput (default 13 B,
    # same as frame-structure validation). It is key=value so the positional arguments
    # stay unchanged -- alt_src must remain None to disable the "alternate inner source" diagnostic mode.
    inner_size = 13
    for arg in sys.argv[1:]:
        if arg.startswith("INNER_SIZE="):
            inner_size = int(arg.split("=", 1)[1])
    if inner_size < 1 or inner_size > 1400:
        raise SystemExit("INNER_SIZE must be in 1..1400 (outer total length must not exceed 1500)")
    payload = b"\xa5" * inner_size
    # Optional BLAST_PPS=<packets/s>: flood rate limit. 0 = unlimited. With unlimited flooding
    # the guest's rx_outer stays at 0 -- 446k pps overwhelms slirp's main loop and the socket
    # receive queue together, so packets vanish in the bearer and it looks like "the driver did not block".
    pps = 0
    for arg in sys.argv[1:]:
        if arg.startswith("BLAST_PPS="):
            pps = int(arg.split("=", 1)[1])
    def good_of(i):
        """i-th good frame: with ALT_INNER_SRC, alternate source addresses and mark the payload"""
        if alt_src is None:
            return good
        if i % 2 == 0:
            return build_frame(TOK)
        return build_frame(TOK, alt_src, b"IWAN-REMOTE-OK")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PEER_PORT))
    sock.settimeout(1.0)
    print("PEER ready on %d, window %ds" % (PEER_PORT, window), flush=True)

    good = build_frame(TOK, None, payload)
    bad = build_frame(TOK + 1, None, payload)
    inner = build_inner(None, payload)
    hellos = nbad = ngood = 0
    nunknown = 0
    nframes = 0
    deadline = time.time() + window

    while time.time() < deadline:
        try:
            data, peer = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if blast > 0:
            # Start as soon as the guest's first datagram arrives: with -SkipSelfTest the guest sends no
            # IWAN-HELLO, only outer frames of ping, so waiting for a hello turns the whole run into
            # idle spinning (all counters zero, looking like "the driver did not block").
            print("BLAST start: %ds continuous flooding -> %s:%d inner %d B"
                  % (blast, peer[0], peer[1], len(inner)), flush=True)
            sock.settimeout(0.0)
            t0 = time.time()
            tend = t0 + blast
            nqueued = 0
            while time.time() < tend:
                for _ in range(64):     # small inner batch, fewer clock reads
                    try:
                        sock.sendto(good, peer)
                    except OSError:
                        break
                    ngood += 1
                nqueued += 64
                if pps > 0:
                    # Coarse rate limiting: align by "batches sent x batch interval"; actual rate is measured
                    due = t0 + nqueued / float(pps)
                    now = time.time()
                    if due > now:
                        time.sleep(due - now)
                try:                    # the guest is still sending; drain opportunistically so the buffer does not fill
                    while True:
                        sock.recvfrom(2048)
                except (BlockingIOError, socket.timeout):
                    pass
            el = time.time() - t0
            # Report inner payload rate (excluding IP/UDP headers), consistent with the outbound measurement
            print("BLAST done: good=%d elapsed=%.3f rate_pps=%.0f rate_mbps=%.1f pps_target=%d"
                  % (ngood, el, ngood / el,
                     ngood * inner_size * 8.0 / el / 1e6, pps), flush=True)
            break
        if data.startswith(HELLO_PREFIXES):
            hellos += 1
            # Each round sends one bad-credential sample first, then good frames: the driver's rx_bad_hdr should
            # grow by exactly the bad samples, everything else goes through deframe/injection.
            if hellos == 1 or hellos == 4:
                sock.sendto(bad, peer)
                nbad += 1
            for k in range(GOOD_PER_HELLO):
                sock.sendto(good_of(ngood + k), peer)
                ngood += 1
            if hellos <= 3:
                print("HELLO#%d -> %d good frames to %s:%d (inner %d B)"
                      % (hellos, GOOD_PER_HELLO, peer[0], peer[1], len(inner)),
                      flush=True)
        else:
            # Record every unknown datagram: silently ignoring it disguises "wire test not connected at all"
            # as "the driver did not block", at the cost of several debugging rounds.
            nunknown += 1
            kind = describe(data)
            if kind.startswith("FRAME"):
                nframes += 1
            if nunknown <= 200:
                print("UNKNOWN %d B from %s:%d %s\n         hex=%s"
                      % (len(data), peer[0], peer[1], kind, data[:40].hex()),
                      flush=True)
    print("PEER done: hellos=%d bad=%d good=%d unknown=%d frames=%d"
          % (hellos, nbad, ngood, nunknown, nframes), flush=True)


if __name__ == "__main__":
    main()
