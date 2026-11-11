# iWAN NT

This repository defines the Windows kernel transport boundary for iWAN NT. It is a design and implementation workspace for an NDIS miniport path that transforms frames synchronously on one kernel thread, sends and receives packets through WSK UDP, and indicates received frames back through NDIS.

The existing user-mode client remains responsible for the protocol session around that transport. The kernel component does not become a second handshake or control-plane implementation.

## Boundary

The intended data path is:

    NDIS miniport -> single-thread synchronous frame transform -> WSK UDP -> NDIS receive indication

Control messages and DATA messages use one UDP port. The kernel path therefore owns the UDP demultiplexing decision and a shared bounded queue between packet ingress, control handling, and DATA handling.

The design excludes multi-core crypto worker pools. Resource ownership, cancellation, shutdown, and queue limits must have bounded and reviewable lifetimes.

## Documentation

- [Architecture](docs/architecture.md) - scope, ownership, staged plan, and non-goals.
- [Runbook](docs/runbook.md) - from an installed driver to a session, and how to read the counters.

## Build status

`driver/iwan_nt.vcxproj` compiles and links on the Windows WDK toolset
(MSVC 14.44, WDK 10.0.26100, x64 Release) with `/W4 /WX /sdl /kernel`:

- every translation unit: 0 warnings, 0 errors
- PREfast (`/p:RunCodeAnalysis=true`): 0 warnings, 0 errors
- output: `iwannt.sys` (size in the build log; it changes with every edit)

The user-mode half builds in the same job with cl (`/W4 /WX /std:c11`) as
`iwannt-ctl.exe`, 0 warnings. It is built with no include path beyond the tree,
which is deliberate: a header that only compiles when the driver directory
happens to be on `-I` is a header that will break the next consumer.

That is a build result, not a runtime result: nothing in this repository has
been loaded on a machine yet.

CI writes the compiler log to the `ci-logs` branch when a job fails. The
annotation only carries an exit status, and downloading an artifact needs
credentials, so the raw log is parked where a plain read can reach it.

## Control interface

The transport owns the outer UDP socket inside the kernel, so both directions
of the control plane cross the control device (`\\.\IwanNt`, admin and SYSTEM
only) instead of a user-mode socket:

| IOCTL | Direction | Purpose |
| --- | --- | --- |
| `SET_SESSION` | write | sid, token, encryption flag and XOR key from OPEN_ACK |
| `CLEAR_SESSION` | - | drop the session; later DATA frames are counted drops |
| `SET_PEER` | write | outer IPv4 endpoint for every send |
| `SEND_CONTROL` | write | one complete control frame, sent verbatim |
| `READ_CONTROL` | read | dequeue one control frame from the bounded ring |
| `GET_STATS` | read | one snapshot of every transport and adapter counter |

`driver/iwan_nt_ioctl.h` is the whole ABI and is shared verbatim with user
mode: fixed-width fields, no padding, no kernel headers. `READ_CONTROL` never
loses a frame to a short buffer: it reports the required length and leaves the
record queued. A full ring drops the newest control frame and counts it, so a
flooding peer cannot make the driver allocate.

`user/` is the other side of that ABI: `iwan_nt_control.c` is a small Win32
wrapper around the six IOCTLs, and `iwannt-ctl.c` is a diagnostic tool that
installs a peer and a session, prints counters, sends one handcrafted control
frame and watches frames arrive:

    iwannt-ctl stats
    iwannt-ctl peer 10.0.2.2 6001
    iwannt-ctl session 1234 12345678 1 0102030405060708
    iwannt-ctl send 1301000000000000...
    iwannt-ctl watch 5
  iwannt-ctl open _rev_m_2 secret 1400        # build an OPEN frame, no driver needed
  iwannt-ctl open _rev_m_2 secret 1400 send   # build it and hand it to the driver
  iwannt-ctl connect 10.0.2.2 6001 _rev_m_2 secret 1400 20
                                               # 0 keeps it up until interrupted
                                               # retries OPEN every 2s while the
                                               # session is down, and again after
                                               # a rejection or a CLOSE

## Project status

Stage 2 lifecycle skeleton is present: NDIS miniport registration, per-adapter
transport state, WSK client registration, one IPv4 UDP datagram socket with a
bounded open/close sequence, and a kernel-free data-frame codec.

A received datagram now has a path: the WSK callback copies it into one
non-paged scratch buffer, the receive pipeline demultiplexes it, DATA frames are
transformed in place and handed to a sink, and control frames are queued as whole
frames on a bounded ring for a PASSIVE consumer. The session (sid, token,
encryption flag, key) is installed through the transport by a future control
interface.

The send direction is a pool: each outbound datagram takes one preallocated
slot (non-paged buffer, MDL, IRP), the frame is transformed into it, and the IRP
completion recycles the slot at DISPATCH_LEVEL. A full pool fails the send
instead of queueing, so backpressure reaches the caller; Stop drains the pool
before closing the socket. The miniport send handler flattens each NBL into a
per-adapter scratch buffer and hands it to that pool.

The receive path has no per-packet allocation either: the indication side owns
64 prebuilt slots (buffer, MDL and NBL each), a datagram claims one slot or is
dropped and counted, and `ReturnNetBufferLists` clears it. Halt waits for the
last frame to come back before freeing the pool. The WSK side still copies each
datagram into one non-paged scratch buffer, because in-place transformation
needs contiguous bytes; that copy is the next thing to remove.

The socket binds the wildcard address with port zero; the peer endpoint arrives
through `SET_PEER` and the session through `SET_SESSION`.

- [NDIS miniport lifecycle](driver/iwan_nt_miniport.h) and [implementation](driver/iwan_nt_miniport.c)
- [WDM driver entry and unload](driver/iwan_nt.c)
- [WSK client lifecycle](driver/iwan_nt_wsk.h) and [implementation](driver/iwan_nt_wsk.c)
- [WSK datagram socket lifecycle](driver/iwan_nt_wsk_socket.h) and [implementation](driver/iwan_nt_wsk_socket.c)
- [Transport lifecycle interface](driver/iwan_nt_transport.h) and [implementation](driver/iwan_nt_transport.c)
- [Data-frame codec](driver/iwan_nt_frame.h) and [implementation](driver/iwan_nt_frame.c)
- [Receive demultiplexer](driver/iwan_nt_demux.h) and [implementation](driver/iwan_nt_demux.c)
- [Bounded control ring](driver/iwan_nt_ring.h) and [implementation](driver/iwan_nt_ring.c)
- [Receive pipeline](driver/iwan_nt_ingress.h) and [implementation](driver/iwan_nt_ingress.c)
- [Send slot pool](driver/iwan_nt_tx.h) and [implementation](driver/iwan_nt_tx.c)
- [Control device](driver/iwan_nt_control.h) and [implementation](driver/iwan_nt_control.c)
- [Shared IOCTL ABI](driver/iwan_nt_ioctl.h)
- [User-mode control library](user/iwan_nt_control.h) and [implementation](user/iwan_nt_control.c)
- [Diagnostic tool](user/iwannt-ctl.c)
- [Codec unit test](tests/frame_test.c)
- [Demultiplexer unit test](tests/demux_test.c)
- [Ring unit test](tests/ring_test.c)
- [Receive pipeline unit test](tests/ingress_test.c)
- [WDK project](driver/iwan_nt.vcxproj)
- [Root-enumerated adapter INF](driver/iwan_nt.inf)

## Local checks

`tools/check-syntax.sh` runs a fast pre-filter on a Linux host: a parser pass
over the kernel-independent sources against stub headers, the frame codec unit
test, and an ASCII check. It is not a WDK build and says nothing about API
semantics; see [tools/kernel-stubs/README.md](tools/kernel-stubs/README.md).

    bash tools/check-syntax.sh

The host tests cover the kernel-free modules and the user-mode half: frame codec
(93 checks), demultiplexer (334), bounded ring (840), receive pipeline (90), the
receive pipeline end to end (22), MD5 and AES-128 (7 known-answer checks), control
framing (47, including one whole OPEN frame against a vector built outside this
code), the handshake state machine (50), and a stress pass (19898) that feeds
random bytes through the demultiplexer and the receive pipeline and asserts that
every rejected input is counted, plus a ring loaded near capacity so its indices
wrap while occupied.

`tools/build-user.sh` builds the user-mode half with MinGW-w64, which is enough
to catch ABI-header mistakes before a CI round:

    bash tools/build-user.sh
    build/user/iwannt-ctl.exe stats

## Socket close ordering

The close sequence is fixed and must not be rearranged:

1. close the operation gate (`ExWaitForRundownProtectionRelease` then
   `ExRundownCompleted`) and wait for calls already inside provider code;
2. disable the receive event callback, whose IRP completion proves that no
   callback is still running;
3. run the callback gate down and wait for a callback that raced the disable;
4. `WskCloseSocket`, which also cancels the provider's pending IRPs.

Disabling the callback must bypass the operation gate: by that point the gate is
already closed on purpose, so acquiring it again would deadlock shutdown.
