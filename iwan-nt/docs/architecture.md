# iWAN NT Architecture

The adapter advertises a 1400-byte MTU, not 1500. The outer datagram is the inner packet plus an 8-byte frame header and the outer IP/UDP headers, so an inner 1500 would leave as 1536 bytes and be fragmented on the way out; the deployed client negotiates 1400 for the same reason.

## Purpose and boundary

The iWAN NT project will provide a Windows kernel transport boundary for the existing iWAN client. The boundary is deliberately narrow:

    NDIS miniport -> single-thread synchronous frame transform -> WSK UDP -> NDIS receive indication

The NDIS miniport side accepts and emits network frames. The frame transform performs the per-frame encapsulation or decapsulation work synchronously on one kernel execution thread. WSK provides the UDP socket path. A valid received DATA frame is finally delivered through an NDIS receive indication.

This project owns the kernel data path, packet classification, bounded queues, and lifetime rules needed to connect those stages. It does not move the full client protocol into kernel mode.

## User-mode responsibilities

The existing user-mode client remains responsible for:

- Handshake and session establishment.
- Keepalive scheduling and liveness policy.
- User-facing control and configuration.
- Protocol policy that does not need to run in the packet path.

The kernel component receives only the state and control operations needed to run the transport boundary. The interface between the existing client and the kernel must make ownership, cancellation, and shutdown explicit.

## UDP port and demultiplexing

Control messages and DATA messages share one UDP port. A packet arriving from WSK must therefore pass through one kernel demultiplexer before it reaches a consumer. The demultiplexer identifies the message class using the authenticated protocol framing and routes it to the appropriate path:

- Control messages go to the bounded shared control path used to update transport state or satisfy a client request.
- DATA messages go to the frame transform path and, after successful validation and decapsulation, to NDIS receive indication.

The demultiplexer and the consumers share one bounded queueing model. Queue entries must carry enough ownership information to make release, cancellation, and shutdown deterministic. A DATA packet must not bypass classification, and a control packet must not be mistaken for a frame.

## Execution model

The frame transform is single-threaded and synchronous. In the initial implementation it runs in the current callback path, one frame at a time. The design does not add a multi-core crypto worker pool, per-core transform state, or an unbounded handoff between crypto workers.

WSK callbacks and NDIS callbacks must not extend an object lifetime implicitly. Each callback must acquire a valid owner reference or be rejected during teardown. Work items, queued packets, socket operations, and indications must have explicit completion paths.

## Lifetime and resource rules

Every resource has an owning context and a bounded lifetime:

1. Device and miniport initialization establishes the top-level owner.
2. Socket creation and binding occur after the owner is ready to accept operations.
3. Received buffers enter the shared bounded queue with one recorded owner.
4. Transform and indication completion release that ownership exactly once.
5. Shutdown stops new ingress, cancels pending WSK operations, drains or rejects queued work according to the shutdown state, and waits for outstanding references and callbacks.
6. Only after callbacks, work items, queues, and socket state are quiescent may the owner be released.

Queue depth, packet size, outstanding operations, and shutdown wait conditions must be bounded and observable. Allocation failure and cancellation are normal paths that must return ownership cleanly.

## Staged plan

1. **Boundary specification** (done): the user-mode control interface is six IOCTLs on one device, with a fixed-size ABI header shared verbatim with user mode (`driver/iwan_nt_ioctl.h`); packet framing, classification, queue limits and state transitions are documented in the driver headers.
2. **Lifecycle skeleton** (done): NDIS miniport lifecycle, per-adapter transport state, and WSK client registration, with no socket operations or frame transform.
3. **WSK socket path** (done, unbuilt): one datagram socket created at PASSIVE_LEVEL, bound, and closed only after the operation gate, the callback gate, and the close IRP have drained. The bind address is still the wildcard with port zero.
4. **Data-frame codec** (done, host-tested): header encode/decode, XOR body transform, inner IPv4/IPv6 sanity, and seal/open. It has no kernel dependencies and is covered by `tests/frame_test.c`.
5. **Shared ingress path** (done, host-tested): the UDP receive callback copies a datagram into one non-paged scratch buffer, the demultiplexer classifies it, DATA is transformed in place and handed to a sink, and control frames are queued whole on a bounded ring for a PASSIVE consumer. Buffer ownership is stated in `driver/iwan_nt_ingress.h`; `tests/ingress_test.c` asserts that every outcome is counted. A control frame that can create the session (the peer's answer, its rejection, a keepalive response, a close) is queued even before a session exists, because otherwise the answer that would have created one is dropped; DATA without a session is still dropped. `tests/pipeline_test.c` walks that whole path: answer before session, session installed from it, DATA decrypted and handed over.
6. **Batched frame path** (done, measured): the send slot pool holds preallocated buffer/MDL/IRP per slot, a full pool fails the send, and Stop drains before close. The miniport copies each packet into a slot and completes the NBL at once, while the slot joins a pending chain that a system thread drains in batches of up to 32 frames per `WskSendMessages` call. The thread is woken when the chain reaches eight frames and otherwise wakes on demand; a fixed one-millisecond poll was measured too (19.8 kpps against 30.0 kpps for the on-demand wake), because the wait itself was the delay. This split exists because measurement, not theory, demanded it: with one provider call per packet the link carried 15 kpps at both 64 B and 1200 B payloads, which is the signature of per-call cost, and the counters proved the average batch was exactly one frame (`batches` equal to `accepted`). Control frames (OPEN, ECHO, CLOSE) still submit immediately: a handshake must not wait behind data. The receive path indicates from a fixed pool of 64 preallocated slots, one chain per WSK callback, and waits for the upper edge to return them before freeing on halt. A slot's net buffer points at the provider's MDL when the datagram is contiguous, so no copy is made and the indication is released only when NDIS returns the NBL; teardown waits for the last release before closing the socket.
7. **Signature checking** (done, host-tested): every control frame carries `md5(header || "mw")` in the sixteen bytes after the header, and the session layer checks it before parsing. Frames that fail are counted as foreign and ignored, so an unsigned CLOSE cannot tear a session down and an unsigned answer cannot fault a healthy one. The signature covers the header only, not the TLVs, exactly as the deployed protocol does.
8. **Session keepalive** (done, host-tested): the state machine implements the deployed 15-second data timeout, measured from the last frame it accepted rather than the last one it sent. A peer that goes quiet resets the session, and the caller mirrors that into the driver every pass, so the adapter's link goes down instead of black-holing traffic. Reconnection is the same OPEN retry as a fresh start.
9. **Client integration** (in progress): the user-mode half exists (`user/iwan_nt_control.c` plus the `iwannt-ctl` diagnostic tool), and the control-plane framing is implemented and host-tested (`user/iwan_nt_session.c`: OPEN builder, OPEN_ACK parser, ECHO request, key derivation, MD5/AES primitives). The OPEN frame our builder emits matches the deployed one byte for byte in layout, and its password block was cross-checked against `openssl enc -aes-128-ecb`. The loop that does it exists as `iwannt-ctl connect` (`user/iwannt_connect.c`): it sends OPEN on the two-second retry the deployed protocol uses, installs the session the driver needs from the answer, then keeps ECHO alive and reports the peer's measured delays. Still open: running that loop against a real server with the driver loaded, and adding the too-obvious missing pieces it will expose (peer address discovery from the adapter, reconnect after CLOSE).
10. **Link state** (done, unbuilt): the adapter reports disconnected until a session exists and flips on every session change (`NDIS_STATUS_LINK_STATE`), so the stack never routes into an adapter that can only drop.
11. **Fault and stress validation**: exercise malformed packets, queue limits, allocation failure, cancellation, device removal, socket errors, concurrent shutdown requests, and repeated start/stop cycles.

## MTU, batching and filtering as built

- The adapter MTU is not a compile-time constant any more. `Parameters\CarrierMtu`
  (default 1500) is read at adapter init, `IwanNtMtuEffective` subtracts the 36-byte
  IPv4 (or 56-byte IPv6) overhead and clamps to [68, 1500], and the result is what
  the miniport advertises and what limits the receive slot buffers. The MTU the
  server advertised in its ACK further caps what may be sent, so a 1500-byte carrier
  with a 1400-byte peer gives an inner payload limit of 1372 bytes. Oversize packets
  are dropped and counted, never fragmented: the peer cannot reassemble an outer
  fragment, and the reference client does the same.
- `IWAN_NT_MAX_PREFIXES` (32) entries of allowed inner prefixes are pushed by user
  mode. On ingress the inner source must match one, on egress the inner destination
  must. An empty table disables both, so a driver that was just installed works
  before anybody configures it. Refusals are counted separately per direction
  (`in refused`, `out refused`).
- Send slots are 256 with a 128-entry chain bound, so a burst can queue without
  waiting for the previous provider call to complete; the pool still fails a send
  rather than growing, which the stack answers by retrying.

## Deferred with evidence, not by omission

Two items from the WireGuardNT comparison are deliberately not built yet:

1. **Tiered packet caches and MDL geometry caching.** WireGuardNT caches
   `{192, 512, 1024, 1500, 9000}`-byte net buffer lists so a packet never allocates.
   Here the send and receive paths already run on preallocated slots and allocate
   nothing per packet (an audit of every `NdisAllocate*`, `ExAllocatePool2` and
   `IoAllocateMdl` call site puts all of them in initialize or finalize paths), so a
   tiered cache would only change how those slots are sized. Measured batch sizes
   stay between 3 and 8 frames, and 64-byte payloads run at the same packet rate as
   1200-byte ones, so packet size is not what limits the link.
2. ~~A second queue level in front of the send pool.~~ Built, because a measurement
   moved the answer. The pool closes at 256 in-flight frames, and when it did the
   staging path returned `NDIS_STATUS_RESOURCES` with no counter at all: four sending
   threads generated 1,015,051 packets and only 570,888 reached the driver, while
   `rejected` stayed 0. A third of the traffic vanished silently. There are now 1024
   flat frame buffers behind an O(1) free-index stack and an order-preserving ring
   (`IWAN_NT_TX_QUEUE_MAX`), claimed when no slot is free and moved into slots by the
   drain path; only a full queue drops, and it is counted in `TxQueueDrops`. The
   earlier objection still stands and is why this queue holds *sealed copies* and not
   net buffer lists: holding the caller's NBL until the provider completes cost half
   the throughput (15.0 vs 30.0 kpps).

The remaining item is revisited when a measurement moves the answer, not before.

## Explicit non-goals

- Replacing or rewriting the existing user-mode handshake, keepalive, or control client.
- Moving user-facing protocol policy into the kernel.
- Adding a multi-core crypto worker pool or per-core transform pipeline.
- Using separate UDP ports for control and DATA.
- Introducing an unbounded queue, unbounded packet allocation, or indefinite shutdown wait.
- Copying GPLv2 WireGuardNT source into this project. The existing project license is MIT, so implementation work must use independently written code and compatible sources.
- Adding frame-transform, shared ingress, or client integration code before its corresponding staged work.
