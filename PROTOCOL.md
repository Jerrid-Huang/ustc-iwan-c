# iwan Wire Protocol — Frozen Specification

**Status: FROZEN.** This document is the authoritative, byte-exact description of
the UDP wire protocol spoken between the client and server of this project and
the reference implementation (yyy1mu/ustc-iwan).

> **Any change to anything described here requires a protocol version bump and a
> coordinated client AND server release.** The wire has no version field of its
> own (see [Frame versioning](#frame-versioning)); a protocol change therefore
> means a *new frame layout*, and old and new implementations must ship together.
> In particular, the following are interop-critical and MUST NOT change:
> the frame layout, the frame-type ids, the TLV ids, the `"mw"` constant,
> the byte order, and the `vlen+2` TLV quirk.
>
> The wire-inherent weaknesses listed in [Security model](#security-model) are
> **frozen by design**: they exist for interop with yyy1mu/ustc-iwan and will
> not be patched on the wire. Fixing them requires a version bump.

Machine-readable compile-time freeze checks live in `src/common/protocol.h`
(`_Static_assert`s on the layout constants).

---

## 1. Conventions

- All multi-byte fields are **big-endian**.
- The transport is UDP. There is **no length field**: the UDP datagram boundary
  delimits frames. A datagram is exactly one frame (except GSO batching, which
  sends a uniform run of same-sized frames — see [Length limits](#6-length-limits)).

## 2. Outer header (8 bytes)

| Offset | Size | Field | Meaning |
|-------:|-----:|-------|---------|
| 0      | 1    | type  | frame type, see below |
| 1      | 1    | enc   | 0 = plaintext, 1 = XOR-encrypted; **the server clamps any nonzero value to 1** |
| 2..4   | 2    | sid   | session id, u16 BE |
| 4..8   | 4    | tok   | session token, u32 BE |

Header length: **8 bytes** (`IWAN_HDR_LEN`).

## 3. Frame types

| Id    | Name        | Signed control? | Purpose |
|-------|-------------|-----------------|---------|
| 0x11  | OPEN_REJECT | yes             | server refuses an OPEN |
| 0x12  | OPEN_ACK    | yes             | server accepts an OPEN |
| 0x13  | OPEN        | yes             | client authentication request |
| 0x14  | DATA        | no              | plaintext inner IPv4 packet |
| 0x15  | ECHO_REQ    | yes             | liveness probe |
| 0x16  | ECHO_RES    | yes             | probe reply (never handled by either side) |
| 0x17  | CLOSE       | yes             | tear the session down |
| 0x18  | DATA_ENC    | no              | XOR-encrypted inner IPv4 packet |
| 0x29  | PING_REQ    | yes             | unauthenticated ping |
| 0x2A  | PING_RSP    | yes             | unauthenticated ping reply |

The ids are **non-contiguous on purpose** (0x11–0x18, then 0x29/0x2A) and are
preserved for interop. **0x19–0x28 are unused** and must not be assigned.

## 4. Control signature and control frames

- Signature: **16 bytes** (`IWAN_SIG_LEN`) =
  `MD5(header[0..8) || "mw")` — 10 input bytes in total. The `"mw"` suffix is a
  **public constant, not a MAC**: it provides no authenticity against anyone who
  knows the protocol (see [Security model](#7-security-model)).
- A signed control frame is `8B header + 16B signature = 24 bytes`
  (`IWAN_CTRL_LEN`), followed by zero or more TLVs.
- The signature covers **only the 8-byte header** — the TLVs are not signed.

## 5. TLV format

| Offset | Size | Field | Meaning |
|-------:|-----:|-------|---------|
| 0      | 1    | type  | TLV type, see below |
| 1      | 1    | length| **vlen + 2** — includes the 2 TLV header bytes themselves |
| 2..    | vlen | value | the payload |

- `vlen` max is **253** (the length byte stores vlen+2; 254/255 would wrap).
- Parsing rejects: `length < 2`, `length > remaining`, and a trailing partial
  TLV header. **Control frames are TLV-exact — no padding, no trailing bytes.**

### TLV types

| Id   | Name        | Value        |
|------|-------------|--------------|
| 0x01 | USERNAME    | username bytes |
| 0x02 | PASSWORD    | 16-byte encrypted password |
| 0x03 | MTU         | mtu, u16 BE |
| 0x04 | IP          | 4-byte IPv4 address |
| 0x05 | DNS         | 4-byte IPv4 address |
| 0x06 | GATEWAY     | 4-byte IPv4 address |
| 0x08 | ENCRYPT     | enc byte (0 or 1) |
| 0x0F | AUTH_VERIFY | 4-byte nonce, u32 BE |
| 0x10 | ERR_MSG     | ASCII reason, no NUL |

**0x07 and 0x09–0x0E are unused.**

## 6. Frame layouts

### OPEN (client → server), `57 + len(user)` bytes

`0x13`, enc, sid = 0, tok = 0, sig, then:

1. TLV MTU — value 4 bytes: mtu u16 BE
2. TLV USERNAME — value `ulen` bytes (total TLV `ulen + 2`)
3. TLV PASSWORD — length byte `0x12`, value 16 bytes ciphertext
4. TLV ENCRYPT — value 1 byte: enc
5. TLV AUTH_VERIFY — value 4 bytes: nonce u32 BE

The client nonce is a fresh 32-bit random value.

### OPEN_ACK (server → client), 55 bytes

`0x12`, enc = echo of the request's enc, sid, tok (**fresh random**), sig, then:

1. TLV MTU (4-byte value: mtu u16 BE)
2. TLV IP (6-byte TLV, 4-byte value)
3. TLV GATEWAY (6-byte TLV, 4-byte value)
4. TLV DNS (6-byte TLV, 4-byte value)
5. TLV ENCRYPT (3-byte TLV, 1-byte value)
6. TLV AUTH_VERIFY (6-byte TLV, 4-byte value: **echo of the client's nonce**)

The reference server may omit the final AUTH_VERIFY TLV — a **49-byte ACK** —
and clients must accept it. (AUTH_VERIFY is required in OPEN but optional in
ACK.)

### OPEN_REJECT (server → client)

`0x11`, enc = 0, sid = 0, tok = 0, sig, then a single TLV ERR_MSG (0x10) whose
value is the ASCII reason with **no NUL terminator**.

### PING_REQ / PING_RSP

Exactly **24 bytes, no TLVs**. `0x29` / `0x2A`, enc = 0, sid = `0xFFFF`,
tok = `0xFFFFFFFF` — the **wildcard** pair; PING is **unauthenticated** (no
session lookup).

### ECHO_REQ / ECHO_RES

24 bytes, `0x15` / `0x16`, carrying the session's enc and sid/tok. The server
echoes the **request's** enc and sid/tok. **ECHO_RES is never handled by either
side.**

### CLOSE

24 bytes, `0x17`, session enc and sid/tok, signed.

### DATA / DATA_ENC

`8 + N` bytes. `0x14` / `0x18`, enc = the session's enc, sid/tok = the session's.
**No signature, no length field** — the payload is the whole rest of the
datagram and **must be a complete inner IPv4 packet**. An encrypted session
accepts only DATA_ENC; a plain session accepts only DATA.

## 7. Password ciphertext (T_PASSWORD)

- Key: `MD5("mw" || username)`.
- Plaintext: the password **zero-padded or truncated to 16 bytes**.
- Cipher: **AES-128-ECB, no padding**.
- The result is **deterministic**: the same username+password always produce
  the same 16 ciphertext bytes (see Security model).

The data session key is separate: `session_key = MD5(username || password)`.

## 8. Data-plane encryption (XOR stream)

- Key: `k = MD5(username || password)[0..8)` — the **first 8 bytes** of the
  session-key MD5.
- The key repeats over the **payload bytes only** (offsets `8..` — after the
  8-byte header): `payload[i] XOR k[i mod 8]`.
- The header itself is never encrypted.

## 9. Authentication flow

### Client side

- Generate a 32-bit random nonce.
- Send OPEN **up to 4 times**: 3 s receive timeout per attempt, 1 s between
  retries.
- A received-but-invalid reply (bad signature, wrong nonce echo, …) **aborts
  immediately without retry**.

### Server side

- Rate-limit OPEN at **20/s/source**.
- Require `len >= 24` and a valid signature.
- Username policy: **≤ 63 bytes** (server-side policy; the wire allows 253).
- A missing AUTH_VERIFY TLV is **rejected**.
- Password check: **constant-time compare** of the received T_PASSWORD against
  the locally computed `encrypt_password()` for the claimed username.
- On success: `session key = MD5(user || pass)`; **one session slot per user** —
  a re-OPEN replaces the old session and refreshes the token.
- `sid = low 16 bits of the assigned IP` (pool ≤ 65536 addresses).
- `tok = fresh 32-bit random`.
- **Idle expiry: 120 s.**

## 10. Length limits

| Limit | Value |
|-------|-------|
| Minimum control frame | 24 B |
| Maximum OPEN | 310 B |
| OPEN_ACK | 49–55 B |
| TLV value | ≤ 253 B |
| Username | ≤ 253 B client / ≤ 63 B server |
| Password | truncated to 16 B |
| UDP datagram | ≤ 65507 B |
| GSO batch unit | capped at 4096 B |

## 11. Security model — FROZEN, wire-inherent weaknesses

These weaknesses are inherent to the wire format and are **frozen for interop
with yyy1mu/ustc-iwan**. They cannot be fixed without a protocol version bump
and a coordinated client/server release.

- **Public signature constant**: the `"mw"` sig suffix is public, so the control
  signature is forgeable by anyone who knows the protocol. It is not a MAC and
  provides no authenticity.
- **Deterministic ECB password encryption**: `AES-128-ECB(MD5("mw"||user), pw)`
  with zero padding is deterministic and keyed only by the username — an offline
  dictionary attack on a sniffed OPEN reveals the password.
- **64-bit repeating XOR data cipher**: the data key is only 8 bytes and repeats;
  this allows known-plaintext key recovery, bit-flip forgery, and provides
  **no integrity**.
- **32-bit token as the only data-plane credential**: DATA/DATA_ENC are
  authenticated by nothing but the 32-bit sid/tok pair, and the token has no
  integrity protection.
- **No server authentication on first connect**: nothing in the handshake
  proves the server's identity.

> **Do NOT send sensitive data through this protocol without an outer
> authenticated tunnel.** Fixes require a protocol version bump.

## 12. Interop quirks (the reference server, memorized)

- Signature key is the string `"mw"` (not a real key).
- AUTH_VERIFY: **required in OPEN**, optional in ACK.
- OPEN must carry sid = 0 and tok = 0.
- ECHO_RES echoes the request's sid/tok (server) versus the session's sid/tok
  (client) — the two sides disagree; the frame is never handled anyway.
- PING uses the wildcard sid/tok `0xFFFF`/`0xFFFFFFFF` and no session.
- Control frames have **no trailing bytes** — TLV-exact.
- `gcm.c`'s AES-256-GCM password decryption is **OIDC-flow only**; it is NOT the
  wire T_PASSWORD scheme above.

## 13. Frame versioning

The wire has **no version field** (`IWAN_PROTO_VERSION` is informational only —
a version bump means a *new frame layout*, not a new constant). New layouts
MUST keep distinct frame-type ids and MUST be shipped with a coordinated
client+server release.
