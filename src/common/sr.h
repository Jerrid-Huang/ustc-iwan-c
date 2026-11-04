#ifndef IWAN_SR_H
#define IWAN_SR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * SD-WAN source routing (frame type 0x28 "SEGRT")
 *
 * A SEGRT datagram carries NO 8-byte iwan header and NO signature: the source
 * routing header starts at offset 0 of the UDP payload and its first byte is
 * the frame type itself (0x28). Layout, all multi-byte fields big-endian:
 *
 *   +0  u8  type      0x28
 *   +1  u8  nextid    unused by the official client
 *   +2  u8  linkcnt   n, no upper bound checked on the wire
 *   +3  u8  algo:3 | padlen:5   (algo 1 = AES-128, other = AES-256)
 *   +4  u32 links[n]  link ids (the official client never reads them)
 *  4+4n  inner packet: a complete iwan frame, or a fragment header + data
 *
 * The SR key is derived from the configured password plus a hash of the link
 * list (see iwan_sr_key); the payload of the inner frame -- everything after
 * its own 8-byte header -- is AES-ECB encrypted, and `padlen` bytes of padding
 * are appended before encryption so the ciphertext is a whole number of
 * blocks.
 * ========================================================================== */

#define IWAN_SR_MAX_LINKS 6
/* SEGRT packet buffer upper bound: SR header (4+4n) + inner frame (8+inner MTU) + 31 bytes of padding.
 * With the inner MTU capped at 1500 this is about 1.6 KB, leaving a 4 KB margin. */
#define IWAN_SR_BUF_MAX 4096
#define IWAN_SR_TYPE      0x28

struct iwan_sr_hdr {
    uint8_t  type;
    uint8_t  nextid;
    uint8_t  linkcnt;
    uint8_t  algo;        /* 0 = plaintext, 1 = AES-128, other = AES-256 */
    uint8_t  padlen;      /* padding bytes appended before encryption, 0-31 */
    uint32_t links[IWAN_SR_MAX_LINKS];
};

size_t iwan_sr_hdr_len(const struct iwan_sr_hdr *h);
bool iwan_sr_parse(const uint8_t *buf, size_t len, struct iwan_sr_hdr *out,
                   size_t *hdrlen);
size_t iwan_sr_build(uint8_t *out, size_t cap, const struct iwan_sr_hdr *h);

/* The official client's hash (ipe_jhash.h): a Jenkins-style mixer over
 * 12-byte blocks with a = b = 0x9e3779b9, c = initval. It is NOT Linux
 * lookup3/hashlittle -- the SR key derivation depends on this exact variant,
 * so do not "simplify" it. */
uint32_t iwan_jhash(const void *key, size_t len, uint32_t initval);

/* Derive the SR key exactly like the official client's set_sr_encrypt():
 * hash = jhash(links big-endian) + jhash(reversed links big-endian) (0 when no
 * links), then the password (up to 32 bytes) is padded to 32 bytes with the
 * little-endian bytes of that hash repeated. Returns the key length in bytes:
 * 16 for algo 1 (AES-128), 32 otherwise (AES-256). `links` are host-order ids
 * and are serialised big-endian here, matching strtoul()+htonl() in the
 * client. */
size_t iwan_sr_key(const char *password, const uint32_t *links, size_t nlinks,
                   unsigned algo, uint8_t key[32]);

/* AES-ECB over `len` bytes in place. `len` must be a multiple of 16 and
 * `bits` is 128 or 256. Returns false on any OpenSSL failure (the caller
 * then drops the packet; never deliver undecrypted bytes as plaintext). */
bool iwan_sr_crypt(uint8_t *buf, size_t len, const uint8_t *key, unsigned bits,
                   bool encrypt);

#endif
