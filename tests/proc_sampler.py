#!/usr/bin/env python3
"""Per-process resource sampler for long-running stress tests.

Usage:
    python3 tests/proc_sampler.py --pid 123 [--pid 456] \
        --interval 10 --output metrics.csv

Appends one CSV row per process per interval:
    elapsed_s,pid,comm,cpu_pct,rss_kb,fds,threads

cpu_pct is the process-wide CPU utilisation over the previous interval
(derived from /proc/<pid>/stat utime+stime deltas vs. CLK_TCK). RSS comes
from /proc/<pid>/status VmRSS; fds is the entry count of
/proc/<pid>/fd. A process that disappears is reported once with empty
metrics and then dropped.
"""
import argparse
import os
import sys
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")


def read_stat(pid):
    """Return (comm, utime+stime seconds) or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read().decode("ascii", "replace")
    except OSError:
        return None
    # comm may contain spaces/parens: split around the LAST ')'
    close = data.rfind(")")
    if close < 0:
        return None
    comm = data[data.find("(") + 1:close]
    fields = data[close + 2:].split()
    # after comm: state is fields[0], so utime=fields[11], stime=fields[12]
    try:
        ticks = int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None
    return comm, ticks / CLK_TCK


def read_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def read_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def read_threads(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, action="append", required=True)
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    pids = list(dict.fromkeys(args.pid))          # dedupe, keep order
    prev = {}                                     # pid -> (wall, cpu_seconds)
    alive = set(pids)
    t0 = time.monotonic()

    new_file = not os.path.exists(args.output)
    with open(args.output, "a", buffering=1) as out:
        if new_file:
            out.write("elapsed_s,pid,comm,cpu_pct,rss_kb,fds,threads\n")
        while alive:
            now = time.monotonic()
            for pid in list(alive):
                st = read_stat(pid)
                if st is None:
                    out.write("%.1f,%d,GONE,,,,\n" % (now - t0, pid))
                    alive.discard(pid)
                    prev.pop(pid, None)
                    continue
                comm, cpu_sec = st
                p = prev.get(pid)
                if p is None:
                    cpu_pct = 0.0
                else:
                    dw = now - p[0]
                    cpu_pct = ((cpu_sec - p[1]) / dw * 100.0) if dw > 0 else 0.0
                prev[pid] = (now, cpu_sec)
                out.write("%.1f,%d,%s,%.1f,%d,%d,%d\n" % (
                    now - t0, pid, comm, cpu_pct,
                    read_rss_kb(pid), read_fds(pid), read_threads(pid)))
            if not alive:
                break
            time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
