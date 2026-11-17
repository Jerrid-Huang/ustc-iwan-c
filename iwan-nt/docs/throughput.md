# iWAN NT throughput: method and measured numbers

All numbers below were taken on the shared Windows VM (`ssh -p 2222
Administrator@127.0.0.1`), guest to host over QEMU's user-mode network (slirp), with
the host running the userspace server in sink mode:

    nohup env IWAN_SRV_SINK=1 ./bin/iwan-server -p 46001 -T \
        -u /tmp/iwusers.txt --user uker > /tmp/srv.log 2>&1 &

`/tmp/iwusers.txt` holds one `user:password` line and must be mode 600.

## What the path includes

Every pps/Mbps figure counts inner payload that reached the host sink, so it includes
the whole loop: guest TCP/IP -> miniport send -> frame seal -> staged queue -> one
`WskSendMessages` per batch -> slirp -> host UDP -> server sink. Keepalives share the
same UDP flow; they are 60-byte control frames sent every 2 s and are invisible at
these rates.

## Rules learned the hard way

- Inner payload must be **<= 1372 bytes**. The adapter MTU is 1400 and the frame adds
  28 bytes of outer headers, so a 1400-byte payload is fragmented by the IP stack and
  the driver's `accepted` counter ends up at twice the generator's packet count.
- Bind the generator to the address the **server assigned**, read with
  `iwannt-ctl.exe lease <ifindex>`. The server hands out addresses in session order,
  so `.2`, `.3`, `.4` all show up across runs; binding anything else fails with
  `GEN thread 0 setup error -2`.
- The adapter's interface index changes on every boot. Read it with
  `(Get-NetAdapter | WhereObject InterfaceDescription -like '*iWAN NT*').ifIndex`
  before calling `lease`.
- Measure for **10 s, not 5 s**: the first seconds are ramp-up, and a 5 s window
  reports 20-40% lower than the steady state.
- The VM is shared with another agent session. Run native and tunnel back to back,
  and report the ratio; absolute pps moves by a factor of two between quiet and busy
  periods.

## MTU and in-bound filtering (added 2026-11-17)

`stats` now reports three MTU numbers and two filter numbers:

    mtu: carrier=1500 effective=1464 peer=1400 dropped=0
    prefixes: 1 allowed, 0 in refused, 0 out refused

- `carrier` comes from `Parameters\CarrierMtu` (default 1500); `effective` is
  `min(carrier - 36, 1500)` for IPv4, so a 1500-byte carrier gives a 1464-byte
  adapter MTU. `peer` is the MTU the server advertised in its ACK; the send limit is
  `min(effective, peer)`, which is 1400 here, hence the <= 1372-byte payload rule.
  Frames larger than the limit are counted in `dropped` instead of being fragmented.
- `lease <ifindex> <prefix>...` installs the addresses, pushes the allowed-prefix
  table into the driver (`SET_PREFIXES`) and adds one route per prefix. With a
  non-empty table the receive path drops any inner packet whose source address is
  outside every prefix and counts it in `in refused`, and the send path drops any
  packet whose destination is outside every prefix and counts it in `out refused`;
  an empty table disables both checks.

One measured point with filtering enabled (1372 B payload, 2 threads, 10 s, host
load ~2.3): tunnel 31,533 pps / 346.1 Mbps inner, `tx accepted` delta exactly equal
to the generator's packet count, host sink 315,418 packets for 315,363 sent
(100.0%). Same-window native baseline: 61,454 pps / 674.5 Mbps, i.e. the tunnel
carried 51% of native pps.

The refuse path is covered by `tests/prefix_test.c` (28 checks: v4/v6, /0,
non-byte-aligned sources, host bits set, malformed entries, truncated headers) but
has **not** been exercised end to end: the only host-side counterpart available is
the sink server, which never originates inner traffic. A second sender is needed to
watch `inner packets refused` move.

## Reproduce

    # adapter index, then lease
    iwannt-ctl.exe connect 10.0.2.2 46001 testuser testpass 1400 1800   (start detached)
    iwannt-ctl.exe lease <ifindex>

    # tunnel: 1200-byte payloads, 2 threads, 10 s
    win_gen.exe -B <lease ip> -d 198.18.0.250 -p 9999 -b 1200 -t 2 -S 10

    # native control: same generator, no tunnel
    win_gen.exe -B 10.0.2.15 -d 10.0.2.2 -p 9999 -b 1200 -t 2 -S 10

`iwannt-ctl.exe stats` gives the driver's own counters. `tx accepted` must equal the
generator's packet count and the sink's packet count; any gap is a real drop.

## Numbers (1200-byte inner, 2 threads, 10 s runs)

| build | tunnel pps | tunnel Mbps | native pps same window | tunnel / native |
|---|---|---|---|---|
| 1.0.8.0 submit per packet, NBL held until send completed | 15,036 | 144 | 71,825 | 21% |
| 1.1.0.0 staged queue, NBL completed immediately | 30,045 | 288 | (same window) | 42% |
| 1.1.1.0 + drain thread polling every 1 ms | 19,808 | 190 | - | worse: the wait is pure latency |
| 1.1.2.0 + inline submit at 8 staged frames | 48,410-64,677 | 465-621 | 37,709-44,469 | 117-166% |

Final build, 4 threads, 1372-byte payload, 10 s: 61,389 pps / 673.8 Mbps, and
`tx accepted` delta == generator packets == sink delta == 614,032, i.e. the tunnel
delivered 100.0% of what the stack handed it.

The conclusion to carry forward: a single `WskSendMessages` per packet was the
bottleneck, not the copy. Staging the sealed frame and returning the NBL to NDIS
immediately removed it; after that the tunnel is no longer slower than the untunneled
path is on this emulated link, so further work has to look at the host side (slirp
and the sink) or at larger batches only when a real NIC is behind it.

## Round-trip measurement

`iwannt-ctl.exe stats` prints `peer: rtt cur/min/max`. The echo tick and the sample
must both come from `KeQuerySystemTimePrecise`: `KeQueryInterruptTime` is tracked per
CPU, so a request built on one processor and answered on another can look like it
came from the future and every sample is dropped. On this link the round trip reads
0.245-0.711 ms.