# Runbook: from an installed driver to a session

The steps are in the order the pieces have to work, and each one ends with
something to look at, so a failure points at the step that caused it rather than
at the last thing tried.

## 1. Load the driver

    sc start iwannt

Check:

    iwannt-ctl check

Expected: `device ok`, then `transport NOT running` because the adapter has not
been enabled yet. If the device open fails, the error names this step.

## 2. Enable the adapter

A root-enumerated adapter starts disabled.

    netsh interface set interface "iWAN NT Transport Adapter" admin=enable

Check: `iwannt-ctl check` now prints `transport running`.

## 3. Establish the session

    iwannt-ctl connect <server-ip> <server-port> <user> <password> [mtu] [seconds]

This sends OPEN every two seconds until the server answers, installs the sid,
token and key the driver needs, then keeps ECHO alive and prints the delay the
server measured. The line

    CONNECT ack sid=... token=... mtu=1400 encrypted=1 tun=... gw=...

is the point where the tunnel exists. A `rejected` or `closed` line is not fatal:
the tool drops the session and retries, which is what a restarting server looks
like.

Check: `iwannt-ctl check` prints `session installed`.

The keepalive lives in this process on purpose: the kernel path only transports,
and the session's timeout is the peer's clock. When the tool exits it clears the
session first, so the adapter stops reporting a link it can no longer feed; the
peer drops its side within fifteen seconds of silence. Pass `0` for the seconds to keep it up until
interrupted, and run it as a service for a tunnel that should outlive a shell.

## 4. Give the adapter the address the server assigned

    netsh interface ipv4 set address name="iWAN NT Transport Adapter" static <tun> 255.255.255.0

`connect` prints the exact command with the value from the answer; it does not run
it, because the tool talks to the device and does not own the host's addresses.

Check: `ipconfig` shows the address on the adapter, and the counters in
`iwannt-ctl stats` start moving under traffic:

    rx indicated=... delivered=... tx accepted=...

## Reading the counters

| What you see | What it means |
| --- | --- |
| `receives` grows, `delivered` does not | the peer is sending frames this session cannot accept; look at the `drops:` line |
| `drops: nosession=...` | frames arriving while no session is installed: the handshake is not complete |
| `drops: badinner=...` | the frame opened but the inner packet is not valid IPv4/IPv6 |
| `drops: oversize=...` | a datagram larger than the receive scratch: the MTU is wrong |
| `tx rejected` grows | the stack handed down more than the adapter's MTU, or the send pool is empty under load |
| `inflight` pinned at the pool size | the peer or the carrier is not draining: the send path is backpressured |

Counters are cumulative since the driver loaded and are not reset when a session
is installed, so two readings from different sessions can be subtracted to get the
work of one session only if you also account for what the previous one left. When
a number has to be attributed to one session, take a reading right after the
session comes up and subtract that.

## When it does not come up

1. `iwannt-ctl check` — the three lines name the step that is missing.
2. `iwannt-ctl local` — the port the peer has to answer to. If it is zero, the
   socket is not bound, which means the adapter is not enabled yet.
3. `iwannt-ctl stats` — `Running` and `SessionValid` are the same two facts, and
   the drop counters say whether frames are arriving at all.
4. If `receives` stays at zero while the server claims to answer, the frames are
   not reaching this host: check the port and the route before suspecting the
   protocol. A stale host route pinning the server address to another interface is
   the most common cause and looks exactly like silence.

## One tunnel per adapter

One device carries one session, and `connect` clears the session when it exits.
That makes a second `connect` on the same device a hazard: it would overwrite the
first one's identifiers while it is still running, and its exit would tear the
first one down. `connect` therefore refuses to start when the device already
reports a session; use `iwannt-ctl clear` only after the owning process is gone.

## When the peer accepts less than 1400 bytes

The answer carries the peer's MTU. `connect` prints the command that lowers the
adapter when the peer's value is smaller than the configured one; NDIS does not
allow a running miniport to change its own MTU, so this is a host step:

```
netsh interface ipv4 set subinterface "iWAN NT Transport Adapter" mtu=1380 store=persistent
```

## Outer IPv6

`connect` takes either literal form. The socket family follows the peer: asking
for an IPv6 peer on a running transport recycles the datagram socket and keeps
the session, so a wrong family is a hiccup rather than a restart.
