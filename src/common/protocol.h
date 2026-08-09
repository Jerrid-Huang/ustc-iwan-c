#ifndef IWAN_PROTOCOL_H
#define IWAN_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

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
#define IWAN_MTU_MAX       1500
#define IWAN_DEFAULT_MTU   1400

/* TLV value-length ceiling: the length byte stores vlen+2, so vlen is
 * at most 253 (254/255 would wrap the length byte and corrupt the
 * frame). Callers must reject longer values before tlv_put. */
#define IWAN_TLV_VLEN_MAX 253

/* max UDP payload of one datagram: 65535 (16-bit length field) minus the
 * 20-byte IPv4 header minus the 8-byte UDP header. Shared by the GSO
 * fast paths in socks.c and proxy.c. */
#define IWAN_UDP_GSO_UNIT 65507

/* safe ceiling for ONE GSO unit (total payload of a uniform batch).
 * Linux's software GSO segmentation (loopback, veth, ...) drops units
 * above ~4-5KB under load on some kernels (measured 28.6% loss at
 * 5.5KB, 84.8% at 65KB on 7.0.0-28, independent of the rcvbuf size),
 * while units <= ~4KB deliver losslessly. Real NICs offload GSO in
 * hardware and have no such limit, but the syscall cost of 2-3 segment
 * batches is negligible (~8% CPU at 2.6 Gbit/s), so cap every unit at
 * one page and let oversized batches fall back to sendmmsg (still one
 * syscall per batch). */
#define IWAN_GSO_UNIT_SAFE 4096

enum {
    PT_OPEN_REJECT = 0x11,
    PT_OPEN_ACK    = 0x12,
    PT_OPEN        = 0x13,
    PT_DATA        = 0x14,
    PT_ECHO_REQ    = 0x15,
    PT_ECHO_RES    = 0x16,
    PT_CLOSE       = 0x17,
    PT_DATA_ENC    = 0x18,
    PT_PING_REQ    = 0x29,
    PT_PING_RSP    = 0x2A,
};

enum {
    T_USERNAME    = 0x01,
    T_PASSWORD    = 0x02,
    T_MTU         = 0x03,
    T_IP          = 0x04,
    T_DNS         = 0x05,
    T_GATEWAY     = 0x06,
    T_ENCRYPT     = 0x08,
    T_AUTH_VERIFY = 0x0F,
    T_ERR_MSG     = 0x10,
};

void pkt_hdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok,
             uint8_t out[IWAN_HDR_LEN]);
/* md5(h8 + IWAN_MW) */
void pkt_sig(const uint8_t h8[IWAN_HDR_LEN], uint8_t out[IWAN_SIG_LEN]);
/* append header WITH sig (for ctrl). out grows. */
void ctrl_hdr(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok);
/* append one TLV (len includes the 2 header bytes). */
void tlv_put(buf_t *out, uint8_t typ, const void *val, uint8_t vlen);
/* iterate TLVs. Returns 0 on success (or when cb stops the iteration:
 * that is not a parse error — the callback carries the reason in its ud),
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

#endif
