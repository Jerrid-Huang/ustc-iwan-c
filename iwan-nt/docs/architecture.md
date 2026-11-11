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
6. **Synchronous frame path** (done, unbuilt): the send slot pool exists (preallocated buffer/MDL/IRP per slot, completion recycles at DISPATCH, a full pool fails the send, Stop drains before close) and the miniport send handler feeds it through one per-adapter scratch buffer. The receive path indicates from a fixed pool of 64 preallocated slots and waits for the upper edge to return them before freeing on halt.
7. **Signature checking** (done, host-tested): every control frame carries `md5(header || "mw")` in the sixteen bytes after the header, and the session layer checks it before parsing. Frames that fail are counted as foreign and ignored, so an unsigned CLOSE cannot tear a session down and an unsigned answer cannot fault a healthy one. The signature covers the header only, not the TLVs, exactly as the deployed protocol does.
8. **Client integration** (in progress): the user-mode half exists (`user/iwan_nt_control.c` plus the `iwannt-ctl` diagnostic tool), and the control-plane framing is implemented and host-tested (`user/iwan_nt_session.c`: OPEN builder, OPEN_ACK parser, ECHO request, key derivation, MD5/AES primitives). The OPEN frame our builder emits matches the deployed one byte for byte in layout, and its password block was cross-checked against `openssl enc -aes-128-ecb`. The loop that does it exists as `iwannt-ctl connect` (`user/iwannt_connect.c`): it sends OPEN on the two-second retry the deployed protocol uses, installs the session the driver needs from the answer, then keeps ECHO alive and reports the peer's measured delays. Still open: running that loop against a real server with the driver loaded, and adding the too-obvious missing pieces it will expose (peer address discovery from the adapter, reconnect after CLOSE).
9. **Link state** (done, unbuilt): the adapter reports disconnected until a session exists and flips on every session change (`NDIS_STATUS_LINK_STATE`), so the stack never routes into an adapter that can only drop.
10. **Fault and stress validation**: exercise malformed packets, queue limits, allocation failure, cancellation, device removal, socket errors, concurrent shutdown requests, and repeated start/stop cycles.

## Explicit non-goals

- Replacing or rewriting the existing user-mode handshake, keepalive, or control client.
- Moving user-facing protocol policy into the kernel.
- Adding a multi-core crypto worker pool or per-core transform pipeline.
- Using separate UDP ports for control and DATA.
- Introducing an unbounded queue, unbounded packet allocation, or indefinite shutdown wait.
- Copying GPLv2 WireGuardNT source into this project. The existing project license is MIT, so implementation work must use independently written code and compatible sources.
- Adding frame-transform, shared ingress, or client integration code before its corresponding staged work.
