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

Two measured points with filtering enabled (1372 B payload, 2 threads, 10 s, host
load ~2.3-3.0):

| build | tunnel pps | tunnel Mbps | accepted delta | host sink | native pps |
| --- | --- | --- | --- | --- | --- |
| 1.3.2.0 (ingress only) | 31,533 | 346.1 | 315,363 = generator | 315,418 | 61,454 |
| 1.4.0.0 (ingress + egress) | 30,920 | 339.4 | 309,244 = generator | 309,244 | - |

In both runs `tx accepted` moved by exactly the generator's packet count and the
host sink received the same number, so the prefix checks cost nothing measurable
and drop nothing that belongs in the tunnel. `out refused` sits at a few dozen
packets per session: broadcast and multicast traffic the stack hands to a
connected interface before the lease address exists.

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
## Both directions, and the receive path bug that hid it (2026-11-17, 2.0.0.0)

The downlink had never delivered a single datagram. `win_sink` counted zero while the
adapter reported `rx indicated` climbing by more than a million, and the UDP counters
in `netstat -s` rose by exactly the number of frames the driver indicated, which made
the loss look like a socket problem. It was not: `pktmon` on the tunnel adapter showed
every frame dropped by the first receive component.

```
DropReason Unsupported EtherType, DropLocation 0xE0001007
ip: 198.18.0.250.9999 > 198.18.0.2.9999: UDP, length 1172
```

The packet was well formed and the net buffer list carried no frame type. NDIS wants
`NetBufferListFrameType` even on a raw IP miniport, in host order (the on-wire
EtherType byte swapped), and it has to be set per net buffer list rather than per
indication, because one chain may mix IPv4 and IPv6 and
`NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE` would then state a falsehood. The uplink never
noticed - the stack originates those packets - so the bug only existed on the side that
had no measurement until the injector was written.

With the fix, `receive:` reports 100% zero copy: the frame is decrypted in place in
the provider's MDL and indicated without a copy.

### Downlink (server injects, no uplink traffic)

`win_vsrv.exe -b 127.0.0.1 -p 46001 -r <pps> -z 1200 -j <threads>` in the guest, the
client connected to it, `win_sink.exe -B <lease> -p 9999 -S 10` as the receiver.

| offered (pps x threads) | sink | Mbps | zero copy |
|---|---|---|---|
| 50k x 2 | 69,015 pps | 647.1 | 100% |
| 50k x 4 | 74,623 pps | 699.7 | 100% |
| 60k x 4 | 60,377 pps | 566.1 | 100% |
| 60k x 6 | 57,738 pps | 541.4 | 100% |

The receive path saturates at 69-75k pps / 650-700 Mbps of inner traffic, and pushing
the offered load higher makes it *slower* because the injector, the driver and the sink
then share the same eight vCPUs. Both the injected count and `rx indicated` move
together, so nothing is lost inside the driver.

### Both directions at once

Same run, generator on the uplink and injector on the downlink, 10 s:

| direction | pps | Mbps | accounting |
|---|---|---|---|
| uplink (to a remote inner address) | 42,885 | 470.7 | `accepted` 428,515 of 428,935 generated, `rejected=6` |
| downlink (from the server, to the lease) | 46,189 | 433.1 | sink delta, 100% zero copy |
| combined | 89,074 | 903.8 | |

### Uplink, final build

| path | threads | pps | Mbps |
|---|---|---|---|
| guest to host over slirp (1.9.0.0) | 1 / 2 / 4 | 29,572 / 49,787 / 54,000 | 324.6 / 546.5 / ~593 |
| guest to guest over loopback (1.6.0.0) | 2 / 4 / 6 | 65,000 / 115,700 / 147,100 | 718 / 1,270 / 1,614 |

The slirp column is the emulated bearer, not the driver: the same build reaches
1.6 Gbps when the outer socket never leaves the guest, and at four threads every
generated packet is accounted for as either `accepted` or `rejected` - the silent
drops that used to swallow 44% are gone (see the second-level queue in the
architecture notes).
