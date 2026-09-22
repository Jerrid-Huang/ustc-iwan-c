#!/usr/bin/env python3
"""CPU Busy-spin Watchdog for process diagnostics.

Usage:
    python3 tests/cpu_watchdog.py --pid <CLIENT_PID> \\
                                  --timeout 600 \\
                                  --threshold 85.0 \\
                                  --duration-threshold 5 \\
                                  --output spin_dump.txt

Monitors CPU usage of <CLIENT_PID> every 0.5s by reading /proc/<pid>/stat.
If CPU% > threshold for consecutive seconds >= duration-threshold:
    - Runs: gdb -p <pid> -batch -ex "thread apply all bt" -ex "info threads" > <output>
    - Captures: ls -la /proc/<pid>/fd/ >> <output>
    - Prints: "WATCHDOG ALERT: CPU busy-spin detected at PID <pid>! Dump saved to <output>"
    - Exits with returncode 2.

If process exits normally or timeout reached, exits 0.
"""

import argparse
import os
import subprocess
import sys
import time


def get_clk_tck() -> int:
    try:
        return os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    except (AttributeError, KeyError, ValueError):
        return 100


def read_proc_stat(pid: int):
    """Read /proc/<pid>/stat and return (ticks, state).

    Returns None if the process does not exist or cannot be read.
    """
    stat_path = f"/proc/{pid}/stat"
    try:
        with open(stat_path, "r") as f:
            data = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None

    # The executable name in field 2 can contain spaces and parentheses: e.g. (cat)
    # The last ')' marks the end of field 2.
    rparen = data.rfind(")")
    if rparen < 0:
        return None

    fields = data[rparen + 2:].split()
    # In 1-based indexing from man proc:
    # field 1: pid
    # field 2: comm
    # field 3: state (index 0 in fields)
    # field 14: utime (index 11 in fields)
    # field 15: stime (index 12 in fields)
    try:
        state = fields[0]
        utime = int(fields[11])
        stime = int(fields[12])
        return (utime + stime, state)
    except (IndexError, ValueError):
        return None


def capture_diagnostics(pid: int, output_file: str) -> None:
    """Capture gdb stack traces and open file descriptors to output_file."""
    cmd_gdb = [
        "gdb",
        "-p", str(pid),
        "-batch",
        "-ex", "thread apply all bt",
        "-ex", "info threads",
    ]
    with open(output_file, "w") as out_f:
        out_f.write(f"=== CPU BUSY-SPIN WATCHDOG REPORT FOR PID {pid} ===\n")
        out_f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        out_f.write(f"=== GDB THREAD BACKTRACES: {' '.join(cmd_gdb)} ===\n")
        out_f.flush()

        try:
            subprocess.run(
                cmd_gdb,
                stdout=out_f,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
        except Exception as e:
            out_f.write(f"\n[Failed to run gdb: {e}]\n")

        out_f.write(f"\n=== OPEN FILE DESCRIPTORS: ls -la /proc/{pid}/fd/ ===\n")
        out_f.flush()

        try:
            subprocess.run(
                ["ls", "-la", f"/proc/{pid}/fd/"],
                stdout=out_f,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )
        except Exception as e:
            out_f.write(f"\n[Failed to list /proc/{pid}/fd: {e}]\n")


def main():
    parser = argparse.ArgumentParser(
        description="CPU Busy-spin Watchdog for process diagnostics"
    )
    parser.add_argument("--pid", type=int, required=True, help="Target process PID to monitor")
    parser.add_argument("--timeout", type=float, default=600.0, help="Total monitoring timeout in seconds (default: 600)")
    parser.add_argument("--threshold", type=float, default=85.0, help="CPU percentage threshold (default: 85.0)")
    parser.add_argument("--duration-threshold", type=float, default=5.0, help="Consecutive seconds exceeding threshold (default: 5.0)")
    parser.add_argument("--output", default="spin_dump.txt", help="Output file for diagnostics dump (default: spin_dump.txt)")
    args = parser.parse_args()

    pid = args.pid
    clk_tck = get_clk_tck()

    stat_res = read_proc_stat(pid)
    if stat_res is None or stat_res[1] in ("Z", "X"):
        print(f"Process PID {pid} not found or not active.", file=sys.stderr)
        sys.exit(0)

    prev_ticks, _ = stat_res
    prev_time = time.monotonic()
    consecutive_high_sec = 0.0
    start_time = prev_time

    while True:
        time.sleep(0.5)
        now = time.monotonic()
        curr_stat = read_proc_stat(pid)

        # Process exited normally or became zombie
        if curr_stat is None or curr_stat[1] in ("Z", "X"):
            print(f"Process PID {pid} has terminated. Watchdog exiting cleanly.")
            sys.exit(0)

        curr_ticks, _ = curr_stat

        dt = now - prev_time
        if dt <= 0:
            continue

        delta_ticks = curr_ticks - prev_ticks
        cpu_sec = delta_ticks / clk_tck
        cpu_pct = (cpu_sec / dt) * 100.0

        if cpu_pct > args.threshold:
            consecutive_high_sec += dt
        else:
            consecutive_high_sec = 0.0

        prev_ticks = curr_ticks
        prev_time = now

        if consecutive_high_sec >= args.duration_threshold:
            capture_diagnostics(pid, args.output)
            print(f"WATCHDOG ALERT: CPU busy-spin detected at PID {pid}! Dump saved to {args.output}")
            sys.exit(2)

        if now - start_time >= args.timeout:
            print(f"Watchdog timeout of {args.timeout}s reached. Exiting cleanly.")
            sys.exit(0)


if __name__ == "__main__":
    main()
