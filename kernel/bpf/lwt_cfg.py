#!/usr/bin/env python3
"""Read and write the config map and counter map of the LWT comparison program (kernel/bpf/lwt_encap.bpf.c).

  # config (both ends must agree: with enc=1 the kernel module must also use enc=1)
  lwt_cfg.py set --outer-src 10.100.0.1 --outer-dst 10.100.0.2 \
                 --sport 6100 --dport 6100 --sid 4660 --tok 3405691582 \
                 --key 0011223344556677 --enc 1

  # read counters: 1=XOR done 2=plain 3=no config 4=push_encap failed 5=encrypted sent 6=plain sent
  lwt_cfg.py counters

map layout (see struct lwt_cfg in lwt_encap.bpf.c): outer addresses are stored as network byte order bytes,
ports/sid/tok are stored in host byte order (little-endian), followed by the 8-byte key, enc, and 3 padding bytes.
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
        sys.exit("bpftool not found (the comparison experiment needs it to write/read maps)")
    if check and p.returncode != 0:
        sys.exit(f"bpftool {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def cfg_bytes(a):
    key = bytes.fromhex(a.key)
    if len(key) != 8:
        sys.exit(f"--key needs 16 hex characters, got {a.key!r}")
    b = socket.inet_aton(a.outer_src) + socket.inet_aton(a.outer_dst)
    # Ports and sid/tok must be stored in **host byte order** in the map: the BPF program interprets these
    # fields in host order (ports via bpf_htons(), sid/tok via shifts); it is responsible for serializing to big-endian.
    # Packing with ">" here would make the program swap again, so the on-wire port becomes the byte-swapped value.
    b += struct.pack("<HHH", a.sport, a.dport, a.sid)
    # In struct lwt_cfg, tok is __be32 with 2 bytes of alignment padding before it; omit that and the map
    # value is only 30 bytes, and bpftool reports "value expected 32 bytes got 30".
    b += b"\x00\x00"
    b += struct.pack("<I", a.tok)
    b += key
    b += bytes([a.enc & 0xFF, 0, 0, 0])
    return b


def do_set(a):
    val = cfg_bytes(a)
    # bpftool parses byte arguments as decimal by default, so the 0x prefix is required; otherwise "0a" reports
    # error parsing byte: 0a.
    hexbytes = [f"0x{x:02x}" for x in val]
    out = bpftool("map", "update", "name", CFG_MAP, "key", "0", "0", "0", "0",
                  "value", *hexbytes)
    if out.strip():
        print(out.strip())
    print(f"set done: {len(val)} bytes enc={a.enc} -> {CFG_MAP}")


def parse_dump(text):
    """Parse `key: 01 00 00 00  value: 0a 00 ...` into {key: value}."""
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
        # JSON form: {"key":["0x01",...],"value":["0x0a",...]}
        for m in re.finditer(r'"key":\s*\[([^\]]*)\].*?"value":\s*\[([^\]]*)\]',
                             text, re.S):
            kb = bytes(int(x.strip().strip('"'), 16)
                       for x in m.group(1).split(",") if x.strip())
            vb = bytes(int(x.strip().strip('"'), 16)
                       for x in m.group(2).split(",") if x.strip())
            vals[int.from_bytes(kb, "little")] = int.from_bytes(vb, "little")
    if not vals:
        sys.exit(f"cannot read {CNT_MAP}: comparison program not attached yet? (stderr: {text.strip()[:200]})")
    names = {1: "XOR done", 2: "plain", 3: "no config", 4: "push failed", 5: "encrypted sent",
             6: "plain sent"}
    for k in sorted(vals):
        print(f"lwt_cnt[{k}]={vals[k]}" + (f"   # {names[k]}" if k in names else ""))
    # Machine-readable single line, convenient for shell assertions
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
