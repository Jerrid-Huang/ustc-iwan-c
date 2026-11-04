#!/usr/bin/env python3
"""Simulate a "wireless link" in userspace, forwarding the tunnel as a plain UDP flow.

Why it is needed: tc/netem needs root and is unavailable on this machine, but to the
kernel the tunnel is **a single UDP flow**, so a userspace relay can reproduce the four wireless traits:

  * one-way rate cap (token bucket; does not reorder packets, only queues at egress)
  * one-way delay + jitter (sampled independently per packet)
  * packet loss (drop by probability)
  * egress queueing (drop new packets when full, like a wireless driver queue)

Usage:
  python3 tests/link_sim.py --listen 127.0.0.1:16101 \\
      --upstream 202.38.64.106:6001 --rate-mbit 300 --delay-ms 25 \\
      --jitter-ms 10 --loss 0.5%

Then point iwan-client's --server at 127.0.0.1:16101.
"""
import argparse
import collections
import heapq
import random
import select
import socket
import statistics
import sys
import time


class Direction:
    def __init__(self, name, rate_mbit, delay_ms, jitter_ms, loss, qmax):
        self.name = name
        self.rate = rate_mbit * 1e6 / 8 if rate_mbit > 0 else 0
        self.delay = delay_ms / 1000.0
        self.jitter = jitter_ms / 1000.0
        self.loss = loss
        self.qmax = qmax
        self.heap = []
        self.seq = 0
        self.next_free = 0.0
        self.pkts = 0
        self.bytes = 0
        self.dropped = 0
        self.qdrop = 0

    def push(self, payload, now):
        if self.loss and random.random() < self.loss:
            self.dropped += 1
            return
        if len(self.heap) >= self.qmax:
            self.qdrop += 1
            return
        d = self.delay + (random.uniform(-self.jitter, self.jitter)
                          if self.jitter else 0.0)
        heapq.heappush(self.heap, (now + max(d, 0.0), self.seq, payload))
        self.seq += 1

    def pop_due(self, now):
        out = []
        while self.heap and self.heap[0][0] <= now:
            out.append(heapq.heappop(self.heap)[2])
        return out

    def ready_at(self, now, nbytes):
        if not self.rate:
            return now
        t = max(now, self.next_free)
        self.next_free = t + nbytes / self.rate
        return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:16101")
    ap.add_argument("--upstream", required=True, help="host:port")
    ap.add_argument("--rate-mbit", type=float, default=0,
                    help="one-way rate cap (Mbit/s, 0=unlimited)")
    ap.add_argument("--delay-ms", type=float, default=10)
    ap.add_argument("--jitter-ms", type=float, default=0)
    ap.add_argument("--loss", type=float, default=0.0, help="loss rate, e.g. 0.005")
    ap.add_argument("--qmax", type=int, default=300, help="per-direction queue limit (packets)")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()

    random.seed(a.seed)
    lh, _, lp = a.listen.rpartition(":")
    uh, _, up = a.upstream.rpartition(":")
    down = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    down.bind((lh or "127.0.0.1", int(lp)))
    down.setblocking(False)
    up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_sock.connect((uh, int(up)))
    up_sock.setblocking(False)

    c2s = Direction("c2s", a.rate_mbit, a.delay_ms, a.jitter_ms, a.loss,
                    a.qmax)
    s2c = Direction("s2c", a.rate_mbit, a.delay_ms, a.jitter_ms, a.loss,
                    a.qmax)
    client = None
    last_stat = time.time()

    print(f"link_sim {a.listen} -> {a.upstream} rate={a.rate_mbit}Mbit "
          f"delay={a.delay_ms}ms jitter={a.jitter_ms}ms loss={a.loss:.3%} "
          f"qmax={a.qmax}", flush=True)

    while True:
        now = time.time()
        # Wait until the nearest due packet (or 50ms if none); a fixed 2ms poll would
        # throttle the whole link to 500 pps, slower than any real wireless link.
        nxt = None
        for d in (c2s, s2c):
            if d.heap:
                t = d.heap[0][0]
                nxt = t if nxt is None else min(nxt, t)
        wait = 0.05 if nxt is None else max(0.0, min(0.05, nxt - now))
        r, _, _ = select.select([down, up_sock], [], [], wait)
        for s in r:
            try:
                data, addr = s.recvfrom(262144)
            except BlockingIOError:
                continue
            if s is down:
                client = addr
                c2s.push(data, now)
            else:
                if client:
                    s2c.push(data, now)

        # Send when due; the token bucket pushes "too fast" packets back into the queue
        # (by changing their due time) rather than sleeping -- a sleep would block receive and turn the link into stop-and-wait.
        now = time.time()
        for direction, out in ((c2s, up_sock), (s2c, down)):
            while direction.heap and direction.heap[0][0] <= now:
                due, seq, payload = heapq.heappop(direction.heap)
                at = direction.ready_at(now, len(payload))
                if at > now:
                    heapq.heappush(direction.heap, (at, seq, payload))
                    break
                try:
                    if out is down:
                        out.sendto(payload, client)
                    else:
                        out.send(payload)
                    direction.pkts += 1
                    direction.bytes += len(payload)
                except OSError:
                    direction.dropped += 1

        if now - last_stat >= 5.0:
            last_stat = now
            parts = []
            for d in (c2s, s2c):
                parts.append(f"{d.name}: {d.pkts}pkt {d.bytes * 8 / 5e6:.1f}Mbit/s "
                             f"drop={d.dropped} qdrop={d.qdrop} q={len(d.heap)}")
            print(" | ".join(parts), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
