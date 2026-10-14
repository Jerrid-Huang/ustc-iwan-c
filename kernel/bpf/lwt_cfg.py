#!/usr/bin/env python3
"""读写 LWT 对照程序（kernel/bpf/lwt_encap.bpf.c）的配置 map 与计数 map。

  # 配置（两端语义要一致：enc=1 时内核模块也要 enc=1）
  lwt_cfg.py set --outer-src 10.100.0.1 --outer-dst 10.100.0.2 \
                 --sport 6100 --dport 6100 --sid 4660 --tok 3405691582 \
                 --key 0011223344556677 --enc 1

  # 读计数：1=已XOR 2=明文 3=无配置 4=push_encap失败 5=加密发出 6=明文发出
  lwt_cfg.py counters

map 结构（见 lwt_encap.bpf.c 的 struct lwt_cfg）：外层地址按网络序字节存，
端口/sid/tok 按主机序（小端）存，其后是 8 字节密钥、enc、3 字节填充。
"""
import argparse
import re
import socket
import struct
import subprocess
import sys

CFG_MAP = "lwt_cfg_map"
CNT_MAP = "lwt_cnt"


def bpftool(*args, check=True):
    try:
        p = subprocess.run(["bpftool", *args], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("找不到 bpftool（对照实验需要它写/读 map）")
    if check and p.returncode != 0:
        sys.exit(f"bpftool {' '.join(args)} 失败: {p.stderr.strip()}")
    return p.stdout


def cfg_bytes(a):
    key = bytes.fromhex(a.key)
    if len(key) != 8:
        sys.exit(f"--key 需要 16 个十六进制字符，得到 {a.key!r}")
    b = socket.inet_aton(a.outer_src) + socket.inet_aton(a.outer_dst)
    # 端口与 sid/tok 在 map 里必须放**主机序**：BPF 程序是按主机序解释这些
    # 字段的（端口走 bpf_htons()，sid/tok 走移位），由它负责序列化成大端。
    # 这里若用 ">" 打包，程序会再交换一次，线上端口就变成字节交换后的值。
    b += struct.pack("<HHH", a.sport, a.dport, a.sid)
    # struct lwt_cfg 里 tok 是 __be32，前面有 2 字节对齐填充；漏掉它 map 的
    # value 就只有 30 字节，bpftool 会报 "value expected 32 bytes got 30"。
    b += b"\x00\x00"
    b += struct.pack("<I", a.tok)
    b += key
    b += bytes([a.enc & 0xFF, 0, 0, 0])
    return b


def do_set(a):
    val = cfg_bytes(a)
    # bpftool 的字节参数默认按十进制解析，必须带 0x 前缀，否则 "0a" 会报
    # error parsing byte: 0a。
    hexbytes = [f"0x{x:02x}" for x in val]
    out = bpftool("map", "update", "name", CFG_MAP, "key", "0", "0", "0", "0",
                  "value", *hexbytes)
    if out.strip():
        print(out.strip())
    print(f"设置完成: {len(val)} 字节 enc={a.enc} -> {CFG_MAP}")


def parse_dump(text):
    """把 `key: 01 00 00 00  value: 0a 00 ...` 解析成 {key: value}。"""
    out = {}
    rx = re.compile(r"key:\s*([0-9a-f ]+?)\s+value:\s*([0-9a-f ]+)")
    for m in rx.finditer(text):
        kb = bytes(int(x, 16) for x in m.group(1).split())
        vb = bytes(int(x, 16) for x in m.group(2).split())
        out[int.from_bytes(kb, "little")] = int.from_bytes(vb, "little")
    return out


def do_counters(_a):
    text = bpftool("map", "dump", "name", CNT_MAP, check=False)
    vals = parse_dump(text)
    if not vals:
        text = bpftool("map", "dump", "-j", "name", CNT_MAP, check=False)
        # JSON 形式：{"key":["0x01",...],"value":["0x0a",...]}
        for m in re.finditer(r'"key":\s*\[([^\]]*)\].*?"value":\s*\[([^\]]*)\]',
                             text, re.S):
            kb = bytes(int(x.strip().strip('"'), 16)
                       for x in m.group(1).split(",") if x.strip())
            vb = bytes(int(x.strip().strip('"'), 16)
                       for x in m.group(2).split(",") if x.strip())
            vals[int.from_bytes(kb, "little")] = int.from_bytes(vb, "little")
    if not vals:
        sys.exit(f"读不到 {CNT_MAP}：对照程序还没挂上？（stderr: {text.strip()[:200]}）")
    names = {1: "已XOR", 2: "明文", 3: "无配置", 4: "push失败", 5: "加密发出",
             6: "明文发出"}
    for k in sorted(vals):
        print(f"lwt_cnt[{k}]={vals[k]}" + (f"   # {names[k]}" if k in names else ""))
    # 机器可读一行，便于 shell 断言
    print(" ".join(f"c{k}={vals.get(k, 0)}" for k in range(8)))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set")
    s.add_argument("--outer-src", required=True)
    s.add_argument("--outer-dst", required=True)
    s.add_argument("--sport", type=int, default=6100)
    s.add_argument("--dport", type=int, default=6100)
    s.add_argument("--sid", type=int, default=0)
    s.add_argument("--tok", type=int, default=0)
    s.add_argument("--key", default="0000000000000000")
    s.add_argument("--enc", type=int, choices=(0, 1), default=0)
    s.set_defaults(func=do_set)
    c = sub.add_parser("counters")
    c.set_defaults(func=do_counters)
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
