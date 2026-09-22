# SOCKS stress / chaos suite

Root-free (no TUN, no root) stress tooling for the `iwan-client socks`
datapath. Developed while investigating the field report *"in SOCKS-only mode
the client eventually freezes and pegs a CPU core"*; the notes below record
what each piece is for and what it did or did not reproduce.

## Pieces

| File | Role |
|---|---|
| `stress_socks.sh` | Main run: ASan+UBSan `iwan-server --no-tun` + `iwan-client socks`, the 7-profile chaos generator, the CPU watchdog and the resource sampler. `DURATION`/`WORKERS` configurable (default 3 h / 40). |
| `stress_socks_flap.sh` | Session-loss stress: kills the server for `DOWN` seconds every `UP` seconds while chaos traffic is in flight, forcing tunnel reconnect + re-auth. |
| `stress_socks_control.sh` | Control for leak attribution: builds an isolated **non-sanitized** Release copy of HEAD in `stress-out/control-*/tree` and runs the same workload, so ASan allocator warm-up can be told apart from a real leak. |
| `stress_chaos_socks.py` | The workload generator: 7 weighted profiles — (1) bulk streams, (2) RST storms, (3) half-close/FIN, (4) slowloris, (5) malformed frames, (6) domain/DNS (`ATYP=3`, including mid-resolution RST), (7) burst connect/abort. |
| `cpu_watchdog.py` | Polls `/proc/<pid>/stat`; if CPU stays above a threshold it dumps `gdb -p <pid> -batch -ex "thread apply all bt"` plus the fd table. This is the *only* way to catch a busy-spin: sanitizers cannot see one. |
| `proc_sampler.py` | Appends `elapsed,pid,comm,cpu%,rss,fds,threads` to CSV so leaks/growth are visible as trends rather than snapshots. |
| `repro_idle_slot_exhaustion.py` | Targeted repro for netstack-slot starvation: establish N SOCKS connections, hold them idle, then show that further CONNECTs are refused (`rep=0x01`) once the 64-slot conn table is pinned. |
| `probes/r55_skspin_harness.c` | Dynamic probe that drives the **real** `wait_events()` with injected flows against real loopback sockets: asserts an RST'd `events=0` slot does not spin, a clean FIN does not wake, and a half-open client still receives queued output. The third assertion guards the R56-001 truncation trade-off. |
| `probes/pollmap.c` | Small helper used to map which `revents` bits a platform reports for a given socket state. |

## Running

```bash
# sanitizer build first (bin/ is the fixed runtime output dir)
cmake -B build-sanitize -DBUILD_TESTING=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitize -j"$(nproc)"

DURATION=600 WORKERS=40 ./tests/stress_socks.sh      # output under stress-out/
```

Each script pre-flights its own ports and **never signals another process** —
a previous version `pkill`ed by binary path, which killed a concurrently
running harness that shared `bin/`. Run them one at a time; a port collision
aborts loudly instead.

## What the suite found

* **No memory / fd / thread leak** in the SOCKS client: the ASan build's RSS
  climbs to ~130 MB and then plateaus, while the non-sanitized control stays
  flat (20600 → 20820 KB over 420 s at 40 workers, ~0.02 KB/connection).
* **No Linux `events=0` × `POLLERR|POLLHUP` spin**: every path that skips a
  POLLIN-registered read also sets `rx_paused`/`ST_CLOSING` in the same round,
  so the convergence arm always fires, and `err_rounds` has no reset path.
* **A full 3 h ASan+UBSan run** (157,092 connections, 150,127 RSTs, 50,578
  malformed frames) completed with zero sanitizer reports and no spin.
* **Real defect found and fixed** (see `repro_idle_slot_exhaustion.py`):
  `NS_MAX_CONN` is only 64 with no eviction, so 64 idle-but-alive flows pin
  every slot permanently and all later CONNECTs are refused — fixed by
  pressure-driven LRU eviction of the stalest idle flow.
* **Not reproduced on Linux**: the reported freeze. The remaining unverified
  candidate is platform-specific — the non-Linux `wait_events` branch ignores
  `POLLERR|POLLHUP` entirely, so a platform that reports those bits on an
  `events=0` slot would spin until the 30 s reap. It cannot be reproduced here
  (Wine's `WSAPoll` inherits Linux semantics); it needs a real Windows/macOS
  host.
