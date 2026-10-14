#!/usr/bin/env python3
"""宿主侧吞吐打流器 / 收流器（Windows 客户端吞吐测量配套）。

计量口径跟 Linux 基准（tests/bench_proto.sh）保持一致：**只算过线的净荷**，
pps 按净荷包数、bps 按净荷字节数，另外单独报"发包侧调用次数"以便和净荷区分
（sendto 成功不等于对端收到，slirp 也会丢）。

三种角色：
  send   宿主发 -> 客体收（标定 slirp 通道的上行容量）
  sink   宿主收 <- 客体发（标定下行容量，或量隧道出向的外层流速）
  loop   自环（拿进程自己的上限当参照，避免"量到的是尺子"）

用法：
  win_blast.py send <IP> <PORT> <SECONDS> [PAYLOAD]
  win_blast.py sink <PORT> <SECONDS> [PAYLOAD]
  win_blast.py loop <SECONDS> [PAYLOAD]

输出一行可解析的汇总：
  BLAST role=send pkts=N bytes=N elapsed=SEC rate_pps=N rate_mbps=N
"""
import socket
import sys
import time

PAYLOAD = 1200


def report(role, pkts, nbytes, elapsed):
    pps = pkts / elapsed if elapsed > 0 else 0.0
    mbps = nbytes * 8 / elapsed / 1e6 if elapsed > 0 else 0.0
    print("BLAST role=%s pkts=%d bytes=%d elapsed=%.3f rate_pps=%.0f rate_mbps=%.1f"
          % (role, pkts, nbytes, elapsed, pps, mbps), flush=True)


def do_send(ip, port, seconds, size):
    """尽量快地发：缓冲区提前建好，循环里只做 sendto。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    sock.connect((ip, port))          # connect 之后用 send，省去每次解析地址
    buf = bytes(size)
    pkts = nbytes = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        for _ in range(64):           # 小批内循环，少读两次时钟
            try:
                sock.send(buf)
            except OSError:
                break
            pkts += 1
            nbytes += size
    elapsed = time.perf_counter() - t0
    sock.close()
    report("send", pkts, nbytes, elapsed)


def do_sink(port, seconds, expect):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(0.5)
    pkts = nbytes = 0
    other = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if expect and len(data) != expect:
            other += 1
            continue
        pkts += 1
        nbytes += len(data)
    elapsed = time.perf_counter() - t0
    sock.close()
    report("sink", pkts, nbytes, elapsed)
    if other:
        print("BLAST sink_other=%d（净荷长度与期望不符，未计入）" % other, flush=True)


def do_loop(seconds, size):
    """自环：同一进程发自己收，得到这台机器/这个进程的尺子上限。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    sock.bind(("127.0.0.1", 0))
    addr = sock.getsockname()
    buf = bytes(size)
    pkts = nbytes = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        for _ in range(64):
            try:
                sock.sendto(buf, addr)
            except OSError:
                break
            pkts += 1
            nbytes += size
        sock.settimeout(0.001)
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                nbytes += 0
                del data
        except socket.timeout:
            pass
    elapsed = time.perf_counter() - t0
    sock.close()
    report("loop", pkts, nbytes, elapsed)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    role = sys.argv[1]
    if role == "send":
        do_send(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]),
                int(sys.argv[5]) if len(sys.argv) > 5 else PAYLOAD)
    elif role == "sink":
        do_sink(int(sys.argv[2]), float(sys.argv[3]),
                int(sys.argv[4]) if len(sys.argv) > 4 else 0)
    elif role == "loop":
        do_loop(float(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else PAYLOAD)
    else:
        print("未知角色 %s" % role)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
