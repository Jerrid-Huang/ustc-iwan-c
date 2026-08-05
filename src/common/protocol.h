#ifndef IWAN_PROTOCOL_H
#define IWAN_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

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

void pkhdr(uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok, uint8_t out[8]);
/* md5(h8 + "mw") */
void sig8(const uint8_t h8[8], uint8_t out[16]);
/* append typ,enc(=1),sid,tok header WITHOUT sig (for data). out grows. */
void data_hdr(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok);
/* append header WITH sig (for ctrl). out grows. */
void ctrl_hdr(buf_t *out, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok);
/* append one TLV (len includes the 2 header bytes). */
void tlv_put(buf_t *out, uint8_t typ, const void *val, uint8_t vlen);
/* iterate TLVs. cb returns false to stop. */
void parse_tlvs(const uint8_t *data, size_t len,
                bool (*cb)(uint8_t typ, const uint8_t *val, uint8_t vlen, void *ud),
                void *ud);
bool verify_sig(const uint8_t *buf, size_t len);

/* "a.b.c.d" from 4 bytes; into out (>=16). "??" if too short. */
void ip_to_string(const uint8_t b[4], char out[16]);
/* parse dotted-quad into 4 bytes. Returns false on invalid. */
bool s2ip4(const char *s, uint8_t out[4]);
/* dotted-quad -> uint32 (big-endian value) */
uint32_t ip4_u32(const uint8_t b[4]);
void u32_ip4(uint32_t v, uint8_t out[4]);

#endif
