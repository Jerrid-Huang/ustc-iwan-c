#ifndef IWAN_PROTOCOL_H
#define IWAN_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

/* ============================================================================
 * FROZEN WIRE PROTOCOL -- INTEROP-CRITICAL
 *
 * Everything below this banner is the on-the-wire byte layout of the iwan
 * protocol, shared with the reference implementation (yyy1mu/ustc-iwan).
 * The following MUST NOT change without a protocol version bump AND a
 * coordinated client+server release:
 *
 *   - frame layout:      8B outer header, 16B MD5 signature, 24B signed
 *                         control frame (header + signature)
 *   - frame-type ids     (PT_*): the non-contiguous values (0x11-0x18,
 *                         0x29, 0x2A) are intentional interop constraints
 *   - TLV ids            (T_*)
 *   - the "mw" constant  (signature suffix + key-derivation prefix)
 *   - byte order         all multi-byte fields are big-endian
 *   - the vlen+2 quirk   the TLV length byte stores (value length + 2),
 *                         i.e. it includes the 2 TLV header bytes
 *   - the 32-bit token, the sid semantics, and the PING wildcard
 *     (sid 0xFFFF, tok 0xFFFFFFFF)
 *
 * See PROTOCOL.md (repo root) for the full byte-exact specification and the
 * frozen security model. Any wire change requires a version bump and a
 * coordinated release of client AND server.
 * ========================================================================== */

/* shared "mw" magic used both as the key-derivation prefix (crypto.c) and
 * the ctrl-signature suffix (protocol.c): keep both in sync via one name */
#define IWAN_MW "mw"

/* frame sizes: 8B outer header, 16B md5 signature, 24B signed control
 * frame (header + signature). The literal 8/16/24 used to be scattered
 * across protocol.c, auth.c, server.c, iwan_client.c and socks/proxy. */
#define IWAN_HDR_LEN   8
#define IWAN_SIG_LEN   16
#define IWAN_CTRL_LEN  (IWAN_HDR_LEN + IWAN_SIG_LEN)

/* unauthenticated PING uses the wildcard sid/token pair (interop with
 * the reference server, which replies without a session) */
#define IWAN_PING_SID  0xFFFF
#define IWAN_PING_TOK  0xFFFFFFFFu

/* MTU sane range: the OPEN_ACK is only header-signed, so never trust a
 * huge MTU; clamp to the IPv4-over-UDP range (also the default). */
#define IWAN_MTU_MIN       576
/* The measurement profile (CMake -DIWAN_JUMBO_MTU=N, off by default) overrides these two values: raise the inner MTU
 * close to the maximum the outer link can carry, so the "per-packet fixed cost" is amortized over the MTU -- this is the way
 * to measure the upper bound of amortization gain without writing any GSO/segmentation code. See docs/perf-plan.md. */
/* The inner MTU ceiling follows from the spec: outer IPv4 total length <= 65535, minus encapsulation overhead
 * 20(IP) + 8(UDP) + 8(fixed header) = 36 => 65499. Same value as the kernel module's
 * IWAN_MAX_MTU (65535 - IWAN_OVERHEAD). The carrier link MTU must be able to carry
 * the inner packet + 50B (including the 14B link header), otherwise the outer packet will fragment on the carrier network.
 * The userspace pump sizes dynamically per the negotiated MTU (proxy.c pump_slot_init); there is no 2048 limit. */
#ifndef IWAN_MTU_MAX
#define IWAN_MTU_MAX       65499
#endif
#ifndef IWAN_DEFAULT_MTU
#define IWAN_DEFAULT_MTU   1400
#endif

/* TLV value-length ceiling: the length byte stores vlen+2, so vlen is
 * at most 253 (254/255 would wrap the length byte and corrupt the
 * frame). Callers must reject longer values before tlv_put. */
#define IWAN_TLV_VLEN_MAX 253

/* max UDP payload of one datagram: 65535 (16-bit length field) minus the
 * 20-byte IPv4 header minus the 8-byte UDP header. Shared by the GSO
 * fast paths in socks.c and proxy.c. */
#define IWAN_UDP_GSO_UNIT 65507

/*
 * Two measures for outer v6 (aligned with the kernel's IWAN_OVERHEAD_V6 = 56):
 *   - inner MTU ceiling = 65535 - 56 = 65479 (the outer header is 40B, 20B more than v4);
 *   - single outer UDP datagram payload ceiling = 65535 - 40 - 8 = 65487.
 * Reachability note (do not assume these bite under the current config): the frozen rule requires kernel
 * max_mtu <= 1500, at which the IWAN_MTU_MAX tier is unreachable; only the jumbo measurement profile
 * (CMake -DIWAN_JUMBO_MTU=N and a raised kernel max_mtu) + outer v6 can hit it.
 * When that actually happens, each call site should select these two values by the session's outer family, not keep using the v4 shape. */
#define IWAN_MTU_MAX_V6      65479
#define IWAN_UDP_GSO_UNIT_V6 65487

/* safe ceiling for ONE GSO unit (total payload of a uniform batch).
 * Linux's software GSO segmentation (loopback, veth, ...) drops units
 * above ~4-5KB under load on some kernels (measured 28.6% loss at
 * 5.5KB, 84.8% at 65KB on 7.0.0-28, independent of the rcvbuf size),
 * while units <= ~4KB deliver losslessly. Real NICs offload GSO in
 * hardware and have no such limit, but the syscall cost of 2-3 segment
 * batches is negligible (~8% CPU at 2.6 Gbit/s), so cap every unit at
 * one page and let oversized batches fall back to sendmmsg (still one
 * syscall per batch). */
#ifdef _WIN32
/* Windows has no sendmmsg/recvmmsg; SIO_UDP_NETSEGMENT can batch many
 * segments into one WSASendTo. Use the full UDP payload ceiling there.
 * Linux keeps the conservative 4KB cap because its software GSO drops
 * larger units on some loopback/veth paths. */
#define IWAN_GSO_UNIT_SAFE 65507
#else
#define IWAN_GSO_UNIT_SAFE 4096
#endif

/* floor for ONE GSO unit (mss) in the uniform-batch fast path. The
 * session socket is shared with non-batch senders: the tunnel-DNS
 * worker (inner 20+8+up-to-271B query + 8B outer <= 307B) and control
 * frames (24B) send() on the same fd. While UDP_SEGMENT is armed, the
 * kernel splits ANY datagram longer than the mss -- an ACK-only batch
 * (48B units) armed mss=48 and silently chopped a 69B DNS query into
 * 48+21B fragments, both dropped by the server's inner-packet gate
 * (flaky tunnel-DNS). Every non-batch frame on the socket must stay
 * below the floor; 512 > 307 covers the largest possible DNS frame.
 * Sub-floor batches fall back to sendmmsg, which is equally fast for
 * 2-3 segment batches (see IWAN_GSO_UNIT_SAFE note). */
#define IWAN_GSO_MSS_MIN 512

/* Compile-time freeze checks: pin the interop-critical layout values. If any
 * of these fires, the wire format has changed and a protocol version bump +
 * coordinated client/server release is required (see PROTOCOL.md). */
_Static_assert(IWAN_CTRL_LEN == IWAN_HDR_LEN + IWAN_SIG_LEN,
               "control frame = header + signature");
_Static_assert(IWAN_HDR_LEN == 8, "outer header is exactly 8 bytes");
_Static_assert(IWAN_SIG_LEN == 16, "signature is exactly 16 bytes");
_Static_assert(IWAN_CTRL_LEN == 24, "signed control frame is exactly 24 bytes");
_Static_assert(IWAN_TLV_VLEN_MAX + 2 <= 255,
               "vlen+2 must fit the TLV length byte");
_Static_assert(IWAN_PING_SID == 0xFFFF && IWAN_PING_TOK == 0xFFFFFFFFu,
               "PING wildcard sid/token must fit the header fields");

/* FROZEN WIRE VALUES -- reordering/renumbering breaks interop */
enum {
    PT_OPEN_REJECT = 0x11,
    PT_OPEN_ACK    = 0x12,
    PT_OPEN        = 0x13,
    PT_DATA        = 0x14,
    PT_ECHO_REQ    = 0x15,
    PT_ECHO_RES    = 0x16,
    PT_CLOSE       = 0x17,
    PT_DATA_ENC    = 0x18,
    /* Panabit SD-WAN extensions (docs/sdwan-protocol.md section 8), appended so the
     * frozen 0x11-0x18/PING values above keep their ids */
    PT_DATA_DUP     = 0x19,
    PT_DATA_ENC_DUP = 0x20,
    PT_IPFRAG       = 0x22,
    PT_DATA_IPV6    = 0x23,
    PT_IPFRAG_ALT   = 0x24,
    PT_SEGRT        = 0x28,
    PT_PING_REQ    = 0x29,
    PT_PING_RSP    = 0x2A,
};

/* FROZEN WIRE VALUES -- reordering/renumbering breaks interop */
enum {
    T_USERNAME    = 0x01,
    T_PASSWORD    = 0x02,
    T_MTU         = 0x03,
    T_IP          = 0x04,
    T_DNS         = 0x05,
    T_GATEWAY     = 0x06,
    T_ENCRYPT     = 0x08,
    T_DUPPKT      = 0x09,
    T_PIPE        = 0x0A,
    T_IPV6        = 0x0B,
    T_DNS6        = 0x0C,
    T_GATEWAY6    = 0x0D,
    T_AUTH_VERIFY = 0x0F,
    T_ERR_MSG     = 0x10,
};

void pkt_hdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok,
             uint8_t out[IWAN_HDR_LEN]);
/* Panabit ECHO payload: 36 bytes appended to an ECHO_REQ/ECHO_RES control
 * frame (docs/sdwan-protocol.md section 7). All fields are LITTLE-endian, unlike the
 * rest of the protocol, because the official client memcpy()s them. Layout:
 *   +0  u64 tick (microseconds, echoed back verbatim by the responder)
 *   +8  u32 cur, +12 u32 min, +16 u32 max delay in microseconds
 *   +20 4 pad bytes (the client sends uninitialised stack here -- never trust)
 *   +24 "SDRT", +28 u32 magic, +32 u32 count (route table, always empty) */
#define IWAN_ECHO_LEN 36
/* The official client runs the state machine once per tick (1 s) and sends ECHOREQ every 2 ticks,
 * i.e. a **keepalive probe interval of 2 seconds** (docs/sdwan-protocol.md section 16). The peer tears down the link only after 30 s
 * without a response, so a 10 s send interval "works", but it is not the official cadence. */
#define IWAN_ECHO_INTERVAL_MS 2000u
/* Official client's DATA timeout: reset the state machine when no "valid frame" arrives within 15 seconds
 * (docs/sdwan-protocol.md section 6). This repo only uses it after confirming the peer replies to keepalives. */
#define IWAN_DATA_TIMEOUT_MS 15000u
struct iwan_echo {
    uint64_t tick;
    uint32_t cur, min, max;
    bool     sdrt;
    uint32_t sdrt_magic;
    uint32_t sdrt_cnt;
};
void echo_put(buf_t *out, const struct iwan_echo *e);
bool echo_parse(const uint8_t *p, size_t len, struct iwan_echo *out);

/* md5(h8 + IWAN_MW) */
/* append header WITH sig (for ctrl). out grows. */
void ctrl_hdr(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok);
/* append one TLV (len includes the 2 header bytes). */
void tlv_put(buf_t *out, uint8_t typ, const void *val, uint8_t vlen);
/* iterate TLVs. Returns 0 on success (or when cb stops the iteration:
 * that is not a parse error -- the callback carries the reason in its ud),
 * -1 when the frame is truncated or malformed (a length byte < 2, a TLV
 * overrunning the buffer, or trailing bytes). */
int parse_tlvs(const uint8_t *data, size_t len,
               bool (*cb)(uint8_t typ, const uint8_t *val, uint8_t vlen, void *ud),
               void *ud);
bool verify_sig(const uint8_t *buf, size_t len);

/* "a.b.c.d" from exactly 4 bytes; out must hold >= 16 bytes. */
void ip_to_string(const uint8_t b[4], char out[16]);
/* parse dotted-quad into 4 bytes. Returns false on invalid. */
bool s2ip4(const char *s, uint8_t out[4]);
/* dotted-quad -> uint32 (big-endian value) */
uint32_t ip4_u32(const uint8_t b[4]);
void u32_ip4(uint32_t v, uint8_t out[4]);

/* IPv6 inner addresses: the tunnel assigns only an IPv4 (T_IP, wire
 * format stays IPv4-only), so every IPv6 inner address is derived from
 * it by a fixed rule shared by the lwIP bridge (source address), the
 * SOCKS5 replies (BND.ADDR), the server H1 gate (spoof check) and the
 * TUN config: fd00::/96 + the 32-bit IPv4 (ULA, deterministic). */
#define IWAN_IP6_ULA_BYTE0 0xfd
void ip6_derive_ula(uint32_t v4, uint8_t out[16]);

#endif
