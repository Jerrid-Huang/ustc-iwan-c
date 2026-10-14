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
# 客体脚本（C:\iwan\vm-rx.ps1:389）发的其实是 b"IWAN-HELLO"。这里按前缀
# 匹配、两种写法都认，**以客体脚本为准**：曾经只认自己新写的
# b"IWAN-WIRE-HELLO"，客体发来的握手包被静默丢掉（hellos=0），而金标向量
# 测试照不出来 —— 对端与金标同源，自证循环看不见这种错位。
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
    """把不认识的数据报尽量解释成人话。

    对端默认只认自己会发的握手包，别的包以前只打前 24 字节十六进制 —— 结果是
    "收到 13 个 584 字节的未知包"这种线索没法定位是谁发的、装的是什么。这里
    按隧道帧解析：帧头 8 字节明文，帧体（enc=1 时）用默认密钥解 XOR，再解内层
    IPv4 头。解不出来就如实说 PLAIN。
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
            # ICMP 再往下解一层：type/code 一眼就能区分 echo（8/0）、
            # 端口不可达（3/3）、重定向（5/x）—— 归因全靠这几个字节。
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
    # 第 4 个参数：打流秒数。>0 时收到第一个握手包后就连续灌帧，不再按
    # 握手逐轮应答 —— 用来量"入向隧道"的容量（解封 + 重组前注入）。
    blast = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
    # 可选参数 INNER_SIZE=<字节>：内层载荷长度，用来量吞吐（默认 13 B，
    # 与帧结构验证时一致）。写成 key=value 是为了不动前面的位置参数 ——
    # alt_src 必须保持 None 才能关掉"备选内层源地址"诊断模式。
    inner_size = 13
    for arg in sys.argv[1:]:
        if arg.startswith("INNER_SIZE="):
            inner_size = int(arg.split("=", 1)[1])
    if inner_size < 1 or inner_size > 1400:
        raise SystemExit("INNER_SIZE 必须在 1..1400（外层总长不得超 1500）")
    payload = b"\xa5" * inner_size
    # 可选参数 BLAST_PPS=<包/秒>：灌帧限速。0 = 不限速。灌帧不限速时
    # 客体的 rx_outer 恒为 0 —— 446k pps 会把 slirp 的主循环与套接字接收
    # 队列一起压垮，包在承载通道里就没了，看着像"驱动没拦住"。
    pps = 0
    for arg in sys.argv[1:]:
        if arg.startswith("BLAST_PPS="):
            pps = int(arg.split("=", 1)[1])
    def good_of(i):
        """第 i 个正常帧：给了 ALT_INNER_SRC 就交替源地址并改载荷做标记"""
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
            # 收到客体的第一个数据报就开闸：-SkipSelfTest 下客体不发
            # IWAN-HELLO，只发 ping 的外层帧，等握手会把整轮测量变成空转
            # （计数器全零，看起来像"驱动没拦住"）。
            print("BLAST start: %ds 连续灌帧 -> %s:%d inner %d B"
                  % (blast, peer[0], peer[1], len(inner)), flush=True)
            sock.settimeout(0.0)
            t0 = time.time()
            tend = t0 + blast
            nqueued = 0
            while time.time() < tend:
                for _ in range(64):     # 小批内循环，少读两次时钟
                    try:
                        sock.sendto(good, peer)
                    except OSError:
                        break
                    ngood += 1
                nqueued += 64
                if pps > 0:
                    # 粗粒度限速：按"已发批数 × 批间隔"对齐，实际速率以实测为准
                    due = t0 + nqueued / float(pps)
                    now = time.time()
                    if due > now:
                        time.sleep(due - now)
                try:                    # 客体还在发包，随手排空，别让缓冲堵死
                    while True:
                        sock.recvfrom(2048)
                except (BlockingIOError, socket.timeout):
                    pass
            el = time.time() - t0
            # 报的是内层载荷速率（不含 IP/UDP 首部），与出向测量的口径一致
            print("BLAST done: good=%d elapsed=%.3f rate_pps=%.0f rate_mbps=%.1f pps_target=%d"
                  % (ngood, el, ngood / el,
                     ngood * inner_size * 8.0 / el / 1e6, pps), flush=True)
            break
        if data.startswith(HELLO_PREFIXES):
            hellos += 1
            # 每一轮先来一个坏凭据样本，再发正常帧：驱动的 rx_bad_hdr 应当
            # 只增长坏样本那么多，其余全部走到解封/注入。
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
            # 不认识的数据报一律留痕：静默忽略等于把"线测根本没接通"伪装成
            # "驱动没拦住"，代价是几轮排查。
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
