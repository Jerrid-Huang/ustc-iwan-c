/* SPDX-License-Identifier: GPL-2.0 */
/*
 * interop_c.c - C-side reference implementation for iWAN data-plane cross-implementation interop validation.
 *
 * Used together with kernel/tests/interop_test.sh and kernel/tests/capture_iwan.py:
 * it takes the bytes the kernel module (kernel/iwan_tx.c outbound encapsulation / kernel/iwan_rx.c inbound decapsulation) produces on the wire
 * and compares them byte by byte with the bytes this tool (which goes through the production code path) produces.
 *
 * Frozen wire format (PROTOCOL.md sec. 2/6/8 and src/common/protocol.h):
 *   [outer IPv4 20B][outer UDP 8B][8B frame header: type, enc, sid(u16 BE), tok(u32 BE)]
 *   [inner IPv4 packet after XOR]
 *   - the 8-byte frame header is generated only by the production function pkt_hdr(); this file never assembles bytes itself;
 *   - XOR applies only to the **whole inner IP packet** (including the inner IP header), via the production function xor_crypt(),
 *     with an 8-byte key cycling by byte offset; the frame header and outer header do not take part in XOR;
 *   - session key = first 8 bytes of MD5(username||password) (--user/--pass let the
 *     production function session_key() derive it on the spot instead of hardcoding it in the script).
 *
 * Build (interop_test.sh uses exactly this line):
 *   cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -I src/common -o interop_c \
 *      kernel/tests/interop_c.c src/common/protocol.c src/common/crypto.c -lcrypto
 * -D_GNU_SOURCE cannot be omitted: sendmmsg/recvmmsg/accept4 in src/common/port.h need it,
 * otherwise you get implicit declaration and the build fails outright (measured).
 * pkt_hdr() is in protocol.c, xor_crypt()/session_key()/md5() are in crypto.c (the latter needs
 * libcrypto's EVP_*). Those two .o files also contain functions this tool does not call; they reference util.c's
 * log_err()/oom_abort() and buffer.c's buf_put()/buf_put_u8(); the end of this file provides
 * equivalent minimal implementations, avoiding dragging util.c/port.c's whole dependency tree into the link (those four stubs are never
 * executed by any path of this tool).
 *
 * Modes:
 *   encap  --in <inner IPv4 packet> --out <outer UDP payload>
 *          payload = 8 bytes of pkt_hdr() + xor_crypt(inner packet)
 *   decap  --in <outer UDP payload> --out <inner IPv4 packet>
 *          validate the frame header by type/enc/sid/tok (byte by byte against pkt_hdr()'s output),
 *          decrypt and restore the inner packet; includes one xor_crypt round-trip self-check
 *   mkudp  --out <inner IPv4 packet> [--payload-out <raw payload>]
 *          generate a deterministic inner IPv4+UDP packet (IP/UDP checksums filled in correctly for the plaintext),
 *          for "known content" injection and delivery assertions
 *   cmpin  --got <file> --want <file> [--ignore-stack-fields]
 *          compare two inner packets byte by byte; --ignore-stack-fields skips the
 *          id/frag_off/ttl/checksum fields the stack rewrites (only for packets built by the kernel stack itself),
 *          and also verifies got's IP header is self-consistent (version/length/checksum/not fragmented)
 *   outer  --out <28 bytes> --src <IP> --dst <IP> [--sport N] [--dport N]
 *          [--payload-len N] [--ttl N] [--id N] [--df 0|1]
 *          generate the expected outer IPv4+UDP header (the outer header is not part of the frozen frame format; here the expected
 *          values follow the kernel module's current construction), and print the fields as KEY=value to stdout,
 *          using the same names as capture_iwan.py's metadata so scripts can assert field by field
 *
 * Common options:
 *   --key <16 hex digits>  session key (default 0011223344556677, same as existing tests)
 *   --user <U> --pass <P>  derive the key with production session_key() (overrides --key)
 *   --sid <u16>            default 4660
 *   --tok <u32>            default 3405691582
 *   --enc <0|1>            default 1 (0x18 PT_DATA_ENC + XOR; 0 = 0x14 PT_DATA plaintext)
 *   --quiet                do not print progress info to stderr
 *
 * stdout is stable KEY=value (for scripts to parse), stderr is human-readable progress/diagnostics.
 * Any failure exits non-zero (usage error 2, validation/comparison failure 1).
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "protocol.h"
#include "util.h"

/* PROTOCOL.md sec. 10: UDP datagram limit; an inner packet must fit entirely in one datagram */
#define MAX_DATAGRAM 65507
#define MIN_INNER    20 /* minimum IPv4 header */
#define OUTER_HDR    28 /* outer IPv4 20 + UDP 8 */

#define DEF_KEY "0011223344556677"
#define DEF_SID 4660
#define DEF_TOK 3405691582u
#define DEF_SRC "10.9.0.1"
#define DEF_DST "10.9.0.2"
#define DEF_SPORT 40000
#define DEF_DPORT 9999
#define DEF_TTL 64
#define DEF_ID  0x1234

static bool g_quiet;

static _Noreturn void die(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);

static void info(const char *fmt, ...) IWAN_PRINTF_LIKE(1, 2);

static void info(const char *fmt, ...)
{
    va_list ap;

    if (g_quiet)
        return;
    fputs("interop_c: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static _Noreturn void die(const char *fmt, ...)
{
    va_list ap;

    fputs("interop_c: error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* ---------------------------------------------------------------- helpers */

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static long parse_long(const char *s, long lo, long hi, const char *what)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol(s, &end, 0);
    if (errno != 0 || !end || *end != '\0' || end == s)
        die("%s: not a valid integer: %s", what, s);
    if (v < lo || v > hi)
        die("%s: %ld out of range [%ld, %ld]", what, v, lo, hi);
    return v;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void parse_key_hex(const char *s, uint8_t key[8])
{
    size_t i;

    if (strlen(s) != 16)
        die("--key requires 16 hex digits (8-byte session key), got \"%s\"", s);
    for (i = 0; i < 8; i++) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);

        if (hi < 0 || lo < 0)
            die("--key contains non-hex characters: \"%s\"", s);
        key[i] = (uint8_t)((hi << 4) | lo);
    }
}

static void parse_ip4(const char *s, uint8_t out[4], const char *what)
{
    if (!s2ip4(s, out)) /* production code (protocol.c) dotted-quad parser */
        die("%s: not a valid IPv4 address: %s", what, s);
}

static uint8_t *read_file(const char *path, size_t *lenp)
{
    FILE *f;
    long n;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (!f)
        die("failed to open %s: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0)
        die("failed to seek %s: %s", path, strerror(errno));
    n = ftell(f);
    if (n < 0)
        die("failed to get size of %s: %s", path, strerror(errno));
    if (n > MAX_DATAGRAM)
        die("%s: %ld bytes exceeds UDP datagram limit %d", path, n, MAX_DATAGRAM);
    rewind(f);
    buf = malloc(n > 0 ? (size_t)n : 1);
    if (!buf)
        oom_abort();
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n)
        die("failed to read %s: %s", path, strerror(errno));
    fclose(f);
    *lenp = (size_t)n;
    return buf;
}

static void write_file(const char *path, const uint8_t *p, size_t n)
{
    FILE *f = fopen(path, "wb");

    if (!f)
        die("failed to create %s: %s", path, strerror(errno));
    if (n > 0 && fwrite(p, 1, n, f) != n) {
        fclose(f);
        die("failed to write %s: %s", path, strerror(errno));
    }
    if (fclose(f) != 0)
        die("failed to close %s: %s", path, strerror(errno));
}

/* -------------------------------------------------------------- checksum */

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
    size_t i = 0;

    for (; i + 1 < n; i += 2)
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
    if (i < n)
        sum += (uint32_t)p[i] << 8;
    return sum;
}

static uint16_t csum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* 1 = checksum self-consistent; 0 = invalid */
static int ip_csum_ok(const uint8_t *p, size_t n)
{
    if (n < MIN_INNER)
        return 0;
    return csum_finish(csum_add(0, p, MIN_INNER)) == 0;
}

/* 1 = checksum self-consistent; 2 = field is 0 (IPv4 allows "not computed"); 0 = invalid */
static int udp_csum_state(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    uint16_t uc, len;
    size_t ulen;

    if (n < MIN_INNER + 8 || p[9] != 17)
        return 0;
    ulen = get16(p + 2) - MIN_INNER; /* IP tot_len - IP header */
    if (ulen < 8 || ulen > n - MIN_INNER)
        return 0;
    len = get16(p + MIN_INNER + 4);
    if (len != ulen)
        return 0;
    uc = get16(p + MIN_INNER + 6);
    if (uc == 0)
        return 2;
    s = csum_add(s, p + 12, 8); /* pseudo-header: src + dst */
    s += 17;                    /* pseudo-header: proto (only the low byte of the 16 bits) */
    s += len;                   /* pseudo-header: UDP length */
    s = csum_add(s, p + MIN_INNER, ulen);
    return csum_finish(s) == 0 ? 1 : 0;
}

/* ---------------------------------------------------------------- options */

static void resolve_key(const char *key_hex, const char *user, const char *pass,
                        uint8_t key[8], char hexout[17], const char **source)
{
    if (user || pass) {
        uint8_t full[16];

        if (!user || !pass)
            die("--user and --pass must be given as a pair");
        if (crypto_init() != 0) /* production code: controlled libcrypto init */
            die("libcrypto initialization failed");
        session_key(user, pass, full); /* production code: MD5(username||password) */
        memcpy(key, full, 8);          /* data plane uses only the first 8 bytes (PROTOCOL.md sec. 8) */
        wipe(full, sizeof full);
        *source = "session_key";
    } else {
        parse_key_hex(key_hex, key);
        *source = "hex";
    }
    hex_encode(key, 8, hexout); /* production code: lowercase hex */
}

static void check_inner(const uint8_t *p, size_t n, const char *what)
{
    unsigned ver, ihl, tot;

    if (n < MIN_INNER)
        die("%s: only %zu bytes, shorter than one IPv4 header", what, n);
    ver = p[0] >> 4;
    ihl = (unsigned)(p[0] & 0x0F) * 4;
    if (ver != 4)
        die("%s: version=%u, not IPv4", what, ver);
    if (ihl < MIN_INNER)
        die("%s: ihl=%u invalid", what, ihl);
    tot = get16(p + 2);
    if (tot != n)
        die("%s: IP tot_len=%u does not match length %zu"
            " (the frozen format requires one datagram to be exactly one complete inner packet)",
            what, tot, n);
}

/* ---------------------------------------------------------------- encap */

static int do_encap(int argc, char **argv)
{
    const char *in = NULL, *out = NULL;
    const char *key_hex = DEF_KEY, *user = NULL, *pass = NULL;
    long sid = DEF_SID, tok = (long)DEF_TOK, enc = 1;
    uint8_t key[8], *inner, *frame;
    char hexout[17], hdrhex[2 * IWAN_HDR_LEN + 1];
    const char *ksrc;
    uint8_t want[IWAN_HDR_LEN];
    size_t n;
    int a;

    for (a = 0; a < argc; a++) {
        const char *o = argv[a];
        const char *v = (a + 1 < argc) ? argv[a + 1] : NULL;

        if (!strcmp(o, "--in") && v) { in = v; a++; }
        else if (!strcmp(o, "--out") && v) { out = v; a++; }
        else if (!strcmp(o, "--key") && v) { key_hex = v; a++; }
        else if (!strcmp(o, "--user") && v) { user = v; a++; }
        else if (!strcmp(o, "--pass") && v) { pass = v; a++; }
        else if (!strcmp(o, "--sid") && v) { sid = parse_long(v, 0, 65535, "--sid"); a++; }
        else if (!strcmp(o, "--tok") && v) { tok = parse_long(v, 0, 4294967295L, "--tok"); a++; }
        else if (!strcmp(o, "--enc") && v) { enc = parse_long(v, 0, 1, "--enc"); a++; }
        else if (!strcmp(o, "--quiet")) { g_quiet = true; }
        else die("encap: unknown or incomplete option %s (see --help for usage)", o);
    }
    if (!in || !out)
        die("encap requires --in <inner IPv4 packet> --out <outer UDP payload>");

    resolve_key(key_hex, user, pass, key, hexout, &ksrc);

    inner = read_file(in, &n);
    check_inner(inner, n, "--in");
    if (n + IWAN_HDR_LEN > MAX_DATAGRAM)
        die("--in: %zu bytes + 8-byte frame header exceeds UDP datagram limit %d",
            n, MAX_DATAGRAM);

    frame = malloc(IWAN_HDR_LEN + n);
    if (!frame)
        oom_abort();
    /* (1) production code builds the 8-byte frame header (type/enc/sid BE/tok BE) */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, frame);
    /* (2) XOR only the whole inner IP packet (including the inner IP header), cycling the key from packet offset 0 */
    memcpy(frame + IWAN_HDR_LEN, inner, n);
    xor_crypt(frame + IWAN_HDR_LEN, n, key, 8);

    write_file(out, frame, IWAN_HDR_LEN + n);

    /* self-check: the frame header must match pkt_hdr() output byte by byte (regenerated here to compare) */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, want);
    if (memcmp(frame, want, IWAN_HDR_LEN) != 0)
        die("internal inconsistency: frame header differs from pkt_hdr() output");

    printf("MODE=encap\n");
    printf("INNER_BYTES=%zu\n", n);
    printf("FRAME_BYTES=%zu\n", n + IWAN_HDR_LEN);
    printf("FRAME_TYPE=0x%02x\n", frame[0]);
    printf("FRAME_ENC=%ld\n", enc);
    printf("FRAME_SID=%u\n", get16(frame + 2));
    printf("FRAME_TOK=%lu\n", (unsigned long)get32(frame + 4));
    printf("KEY=%s\n", hexout);
    printf("KEY_SOURCE=%s\n", ksrc);
    printf("INNER_IP_CSUM_OK=%d\n", ip_csum_ok(inner, n));
    printf("INNER_UDP_CSUM_STATE=%d\n", udp_csum_state(inner, n));
    hex_encode(frame, IWAN_HDR_LEN, hdrhex);
    info("frame header bytes: %s", hdrhex);

    free(frame);
    free(inner);
    return 0;
}

/* ---------------------------------------------------------------- decap */

static int do_decap(int argc, char **argv)
{
    const char *in = NULL, *out = NULL;
    const char *key_hex = DEF_KEY, *user = NULL, *pass = NULL;
    long sid = DEF_SID, tok = (long)DEF_TOK, enc = 1;
    uint8_t key[8], want[IWAN_HDR_LEN], *frame, *inner, *again;
    char hexout[17], ip_s[16], ip_d[16];
    const char *ksrc;
    size_t n, inner_len;
    int a;

    for (a = 0; a < argc; a++) {
        const char *o = argv[a];
        const char *v = (a + 1 < argc) ? argv[a + 1] : NULL;

        if (!strcmp(o, "--in") && v) { in = v; a++; }
        else if (!strcmp(o, "--out") && v) { out = v; a++; }
        else if (!strcmp(o, "--key") && v) { key_hex = v; a++; }
        else if (!strcmp(o, "--user") && v) { user = v; a++; }
        else if (!strcmp(o, "--pass") && v) { pass = v; a++; }
        else if (!strcmp(o, "--sid") && v) { sid = parse_long(v, 0, 65535, "--sid"); a++; }
        else if (!strcmp(o, "--tok") && v) { tok = parse_long(v, 0, 4294967295L, "--tok"); a++; }
        else if (!strcmp(o, "--enc") && v) { enc = parse_long(v, 0, 1, "--enc"); a++; }
        else if (!strcmp(o, "--quiet")) { g_quiet = true; }
        else die("decap: unknown or incomplete option %s (see --help for usage)", o);
    }
    if (!in || !out)
        die("decap requires --in <outer UDP payload> --out <inner IPv4 packet>");

    resolve_key(key_hex, user, pass, key, hexout, &ksrc);

    frame = read_file(in, &n);
    if (n < IWAN_HDR_LEN + MIN_INNER)
        die("--in: only %zu bytes, shorter than an 8-byte frame header + an IPv4 header", n);

    /* frame header check: compare directly against production pkt_hdr() output (type/enc/sid BE/tok BE) */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, want);
    if (memcmp(frame, want, IWAN_HDR_LEN) != 0) {
        die("frame header mismatch: got type=0x%02x enc=%u sid=%u tok=%lu, "
            "expected type=0x%02x enc=%ld sid=%ld tok=%ld",
            frame[0], frame[1], get16(frame + 2),
            (unsigned long)get32(frame + 4),
            want[0], enc, sid, tok);
    }

    inner_len = n - IWAN_HDR_LEN;
    inner = malloc(inner_len);
    again = malloc(inner_len);
    if (!inner || !again)
        oom_abort();
    memcpy(inner, frame + IWAN_HDR_LEN, inner_len);
    xor_crypt(inner, inner_len, key, 8); /* production code decryption */
    check_inner(inner, inner_len, "decapsulated inner packet");

    /* round-trip self-check: encrypting once more with the same production function must restore the input frame's payload byte by byte */
    memcpy(again, inner, inner_len);
    xor_crypt(again, inner_len, key, 8);
    if (memcmp(again, frame + IWAN_HDR_LEN, inner_len) != 0)
        die("round-trip self-check failed: xor_crypt is not an involution on the same input");

    write_file(out, inner, inner_len);

    ip_to_string(inner + 12, ip_s);
    ip_to_string(inner + 16, ip_d);
    printf("MODE=decap\n");
    printf("FRAME_BYTES=%zu\n", n);
    printf("FRAME_TYPE=0x%02x\n", frame[0]);
    printf("FRAME_ENC=%u\n", frame[1]);
    printf("FRAME_SID=%u\n", get16(frame + 2));
    printf("FRAME_TOK=%lu\n", (unsigned long)get32(frame + 4));
    printf("KEY=%s\n", hexout);
    printf("KEY_SOURCE=%s\n", ksrc);
    printf("INNER_BYTES=%zu\n", inner_len);
    printf("INNER_IP_SRC=%s\n", ip_s);
    printf("INNER_IP_DST=%s\n", ip_d);
    printf("INNER_IP_PROTO=%u\n", inner[9]);
    printf("INNER_IP_TOT_LEN=%u\n", get16(inner + 2));
    printf("INNER_IP_ID=%u\n", get16(inner + 4));
    printf("INNER_IP_TTL=%u\n", inner[8]);
    printf("INNER_IP_FRAG_OFF=0x%04x\n", get16(inner + 6));
    printf("INNER_IP_CSUM_OK=%d\n", ip_csum_ok(inner, inner_len));
    printf("INNER_UDP_CSUM_STATE=%d\n", udp_csum_state(inner, inner_len));
    printf("ROUNDTRIP=1\n");
    info("frame header check passed, decapsulated a %zu-byte inner packet (%s -> %s proto=%u)",
         inner_len, ip_s, ip_d, inner[9]);

    free(again);
    free(inner);
    free(frame);
    return 0;
}

/* ---------------------------------------------------------------- mkudp */

static int do_mkudp(int argc, char **argv)
{
    const char *out = NULL, *payload_out = NULL;
    const char *src_s = DEF_SRC, *dst_s = DEF_DST;
    const char *phex = NULL, *pstr = NULL;
    long sport = DEF_SPORT, dport = DEF_DPORT, ttl = DEF_TTL, id = DEF_ID;
    long df = 0, plen_opt = -1;
    uint8_t src[4], dst[4], *payload, *pkt;
    size_t plen, total, i;
    uint32_t s;
    uint16_t uc;
    int a;

    for (a = 0; a < argc; a++) {
        const char *o = argv[a];
        const char *v = (a + 1 < argc) ? argv[a + 1] : NULL;

        if (!strcmp(o, "--out") && v) { out = v; a++; }
        else if (!strcmp(o, "--payload-out") && v) { payload_out = v; a++; }
        else if (!strcmp(o, "--src") && v) { src_s = v; a++; }
        else if (!strcmp(o, "--dst") && v) { dst_s = v; a++; }
        else if (!strcmp(o, "--sport") && v) { sport = parse_long(v, 0, 65535, "--sport"); a++; }
        else if (!strcmp(o, "--dport") && v) { dport = parse_long(v, 0, 65535, "--dport"); a++; }
        else if (!strcmp(o, "--ttl") && v) { ttl = parse_long(v, 1, 255, "--ttl"); a++; }
        else if (!strcmp(o, "--id") && v) { id = parse_long(v, 0, 65535, "--id"); a++; }
        else if (!strcmp(o, "--df") && v) { df = parse_long(v, 0, 1, "--df"); a++; }
        else if (!strcmp(o, "--payload-len") && v) { plen_opt = parse_long(v, 0, 65479, "--payload-len"); a++; }
        else if (!strcmp(o, "--payload-hex") && v) { phex = v; a++; }
        else if (!strcmp(o, "--payload-str") && v) { pstr = v; a++; }
        else if (!strcmp(o, "--quiet")) { g_quiet = true; }
        else die("mkudp: unknown or incomplete option %s (see --help for usage)", o);
    }
    if (!out)
        die("mkudp requires --out <inner IPv4 packet>");
    if (phex && pstr)
        die("only one of --payload-hex and --payload-str may be given");

    if (phex) {
        size_t hl = strlen(phex);

        if (hl % 2)
            die("--payload-hex length must be even");
        plen = hl / 2;
        payload = malloc(plen > 0 ? plen : 1);
        if (!payload)
            oom_abort();
        for (i = 0; i < plen; i++) {
            unsigned hi, lo, k;
            int vh = -1, vl = -1;

            for (k = 0; k < 16; k++) {
                static const char hx[] = "0123456789abcdef";

                if (hx[k] == phex[2 * i] || (char)(hx[k] - 32) == phex[2 * i])
                    vh = (int)k;
                if (hx[k] == phex[2 * i + 1] || (char)(hx[k] - 32) == phex[2 * i + 1])
                    vl = (int)k;
            }
            if (vh < 0 || vl < 0)
                die("--payload-hex contains non-hex characters");
            hi = (unsigned)vh;
            lo = (unsigned)vl;
            payload[i] = (uint8_t)((hi << 4) | lo);
        }
    } else if (pstr) {
        plen = strlen(pstr);
        payload = malloc(plen > 0 ? plen : 1);
        if (!payload)
            oom_abort();
        memcpy(payload, pstr, plen);
    } else {
        /* deterministic pattern, same as PAT in kernel/tests/echo_net.py: (i*7+3)&0xFF */
        plen = plen_opt >= 0 ? (size_t)plen_opt : 32;
        payload = malloc(plen > 0 ? plen : 1);
        if (!payload)
            oom_abort();
        for (i = 0; i < plen; i++)
            payload[i] = (uint8_t)((i * 7 + 3) & 0xFF);
    }
    if (plen > 65479)
        die("payload of %zu bytes is too large (inner limit 65479 = 65507 - 20 - 8)", plen);

    parse_ip4(src_s, src, "--src");
    parse_ip4(dst_s, dst, "--dst");

    total = MIN_INNER + 8 + plen;
    pkt = calloc(1, total);
    if (!pkt)
        oom_abort();

    /* inner IPv4 header (plaintext semantics: checksum computed over the plaintext, still self-consistent after XOR) */
    pkt[0] = 0x45;
    pkt[1] = 0x00; /* TOS */
    put16(pkt + 2, (uint16_t)total);
    put16(pkt + 4, (uint16_t)id);
    put16(pkt + 6, df ? 0x4000 : 0x0000);
    pkt[8] = (uint8_t)ttl;
    pkt[9] = 17; /* UDP */
    put16(pkt + 10, 0);
    memcpy(pkt + 12, src, 4);
    memcpy(pkt + 16, dst, 4);
    put16(pkt + 10, csum_finish(csum_add(0, pkt, MIN_INNER)));

    /* inner UDP header + payload */
    put16(pkt + 20, (uint16_t)sport);
    put16(pkt + 22, (uint16_t)dport);
    put16(pkt + 24, (uint16_t)(8 + plen));
    put16(pkt + 26, 0);
    if (plen)
        memcpy(pkt + 28, payload, plen);

    /* UDP checksum = pseudo-header(src,dst,0,proto,len) + UDP header(csum=0) + payload */
    s = csum_add(0, pkt + 12, 8);
    s += 17;
    s += (uint32_t)(8 + plen);
    s = csum_add(s, pkt + 20, 8 + plen);
    uc = csum_finish(s);
    if (uc == 0)
        uc = 0xFFFF; /* 0 means "not computed"; if the result comes out 0 it must be written as 0xFFFF */
    put16(pkt + 26, uc);

    write_file(out, pkt, total);
    if (payload_out)
        write_file(payload_out, payload, plen);

    printf("MODE=mkudp\n");
    printf("INNER_BYTES=%zu\n", total);
    printf("INNER_IP_SRC=%s\n", src_s);
    printf("INNER_IP_DST=%s\n", dst_s);
    printf("INNER_IP_PROTO=17\n");
    printf("INNER_IP_TOT_LEN=%zu\n", total);
    printf("INNER_IP_ID=%ld\n", id);
    printf("INNER_IP_TTL=%ld\n", ttl);
    printf("INNER_IP_FRAG_OFF=0x%04x\n", (unsigned)get16(pkt + 6));
    printf("INNER_IP_CSUM=0x%04x\n", (unsigned)get16(pkt + 10));
    printf("INNER_IP_CSUM_OK=%d\n", ip_csum_ok(pkt, total));
    printf("INNER_UDP_SPORT=%ld\n", sport);
    printf("INNER_UDP_DPORT=%ld\n", dport);
    printf("INNER_UDP_LEN=%zu\n", 8 + plen);
    printf("INNER_UDP_CSUM=0x%04x\n", (unsigned)uc);
    printf("INNER_UDP_CSUM_STATE=%d\n", udp_csum_state(pkt, total));
    printf("PAYLOAD_BYTES=%zu\n", plen);
    if (payload_out)
        printf("PAYLOAD_FILE=%s\n", payload_out);
    info("generated a %zu-byte inner packet (%s:%ld -> %s:%ld, payload %zu bytes)",
         total, src_s, sport, dst_s, dport, plen);

    free(pkt);
    free(payload);
    return 0;
}

/* ---------------------------------------------------------------- cmpin */

static int do_cmpin(int argc, char **argv)
{
    const char *got_f = NULL, *want_f = NULL;
    bool ignore_stack = false;
    uint8_t *got, *want;
    size_t gn, wn, i;
    int a, diff = -1;

    for (a = 0; a < argc; a++) {
        const char *o = argv[a];
        const char *v = (a + 1 < argc) ? argv[a + 1] : NULL;

        if (!strcmp(o, "--got") && v) { got_f = v; a++; }
        else if (!strcmp(o, "--want") && v) { want_f = v; a++; }
        else if (!strcmp(o, "--ignore-stack-fields")) { ignore_stack = true; }
        else if (!strcmp(o, "--quiet")) { g_quiet = true; }
        else die("cmpin: unknown or incomplete option %s (see --help for usage)", o);
    }
    if (!got_f || !want_f)
        die("cmpin requires --got <file> --want <file>");

    got = read_file(got_f, &gn);
    want = read_file(want_f, &wn);

    /* got self-consistency checks: version/length/no fragmentation/IP header checksum */
    if (gn < MIN_INNER || (got[0] >> 4) != 4 || (got[0] & 0x0F) < 5)
        die("%s: not a valid IPv4 packet", got_f);
    if ((got[0] & 0x0F) != 5)
        die("%s: ihl=%u (this tool only compares IPv4 headers without options)", got_f,
            (unsigned)(got[0] & 0x0F));
    if ((size_t)get16(got + 2) != gn)
        die("%s: IP tot_len=%u does not match file length %zu", got_f,
            (unsigned)get16(got + 2), gn);
    if (get16(got + 6) & 0x3FFF)
        die("%s: inner packet is fragmented (frag_off=0x%04x)", got_f,
            (unsigned)get16(got + 6));
    if (!ip_csum_ok(got, gn))
        die("%s: IP header checksum is not self-consistent (plaintext corrupted after decapsulation?)", got_f);
    if (got[9] == 17 && udp_csum_state(got, gn) == 0)
        die("%s: inner UDP length/checksum is not self-consistent", got_f);

    printf("MODE=cmpin\n");
    printf("GOT_BYTES=%zu\n", gn);
    printf("WANT_BYTES=%zu\n", wn);
    printf("GOT_IP_SRC=%u.%u.%u.%u\n", (unsigned)got[12], (unsigned)got[13],
           (unsigned)got[14], (unsigned)got[15]);
    printf("GOT_IP_DST=%u.%u.%u.%u\n", (unsigned)got[16], (unsigned)got[17],
           (unsigned)got[18], (unsigned)got[19]);
    printf("GOT_IP_PROTO=%u\n", (unsigned)got[9]);
    printf("GOT_IP_TOT_LEN=%u\n", (unsigned)get16(got + 2));
    printf("GOT_IP_ID=%u\n", (unsigned)get16(got + 4));
    printf("GOT_IP_TTL=%u\n", (unsigned)got[8]);
    printf("GOT_IP_FRAG_OFF=0x%04x\n", (unsigned)get16(got + 6));
    printf("GOT_IP_CSUM_OK=%d\n", ip_csum_ok(got, gn));
    printf("GOT_UDP_CSUM_STATE=%d\n", udp_csum_state(got, gn));
    printf("IGNORED_STACK_FIELDS=%d\n", ignore_stack ? 1 : 0);

    if (gn != wn) {
        printf("RESULT=diff\n");
        printf("DIFF_OFFSET=-1\n");
        info("lengths differ: got=%zu want=%zu", gn, wn);
        free(got);
        free(want);
        return 1;
    }

    for (i = 0; i < gn; i++) {
        if (ignore_stack) {
            /* fields the stack fills in itself: id(8,9) frag_off(10,11) ttl(12)
             * IP header checksum(16..19); all other bytes must be identical byte for byte */
            if (i == 8 || i == 9 || i == 10 || i == 11 || i == 12 ||
                (i >= 16 && i <= 19))
                continue;
        }
        if (got[i] != want[i]) {
            diff = (int)i;
            break;
        }
    }

    if (diff < 0) {
        printf("RESULT=ok\n");
        info("byte-for-byte identical: %zu bytes%s", gn,
             ignore_stack ? " (skipped id/frag_off/ttl/checksum)" : "");
        free(got);
        free(want);
        return 0;
    }

    printf("RESULT=diff\n");
    printf("DIFF_OFFSET=%d\n", diff);
    printf("GOT_BYTE=0x%02x\n", (unsigned)got[diff]);
    printf("WANT_BYTE=0x%02x\n", (unsigned)want[diff]);
    info("first difference at offset %d: got=0x%02x want=0x%02x", diff,
         (unsigned)got[diff], (unsigned)want[diff]);
    free(got);
    free(want);
    return 1;
}

/* ---------------------------------------------------------------- outer */

static int do_outer(int argc, char **argv)
{
    const char *out = NULL, *src_s = NULL, *dst_s = NULL;
    long sport = -1, dport = 0, ttl = DEF_TTL, id = 0, df = 1, paylen = 0;
    uint8_t hdr[OUTER_HDR], src[4], dst[4];
    uint16_t iplen, udplen, sport_v;
    int a;

    for (a = 0; a < argc; a++) {
        const char *o = argv[a];
        const char *v = (a + 1 < argc) ? argv[a + 1] : NULL;

        if (!strcmp(o, "--out") && v) { out = v; a++; }
        else if (!strcmp(o, "--src") && v) { src_s = v; a++; }
        else if (!strcmp(o, "--dst") && v) { dst_s = v; a++; }
        else if (!strcmp(o, "--sport") && v) { sport = parse_long(v, 0, 65535, "--sport"); a++; }
        else if (!strcmp(o, "--dport") && v) { dport = parse_long(v, 0, 65535, "--dport"); a++; }
        else if (!strcmp(o, "--ttl") && v) { ttl = parse_long(v, 1, 255, "--ttl"); a++; }
        else if (!strcmp(o, "--id") && v) { id = parse_long(v, 0, 65535, "--id"); a++; }
        else if (!strcmp(o, "--df") && v) { df = parse_long(v, 0, 1, "--df"); a++; }
        else if (!strcmp(o, "--payload-len") && v) { paylen = parse_long(v, 0, 65479, "--payload-len"); a++; }
        else if (!strcmp(o, "--quiet")) { g_quiet = true; }
        else die("outer: unknown or incomplete option %s (see --help for usage)", o);
    }
    if (!out || !src_s || !dst_s)
        die("outer requires --out <28-byte header file> --src <IP> --dst <IP>");

    parse_ip4(src_s, src, "--src");
    parse_ip4(dst_s, dst, "--dst");
    /* module's iwan_tx.c: sport = cfg.sport ? cfg.sport : cfg.dport */
    sport_v = (uint16_t)(sport >= 0 ? sport : dport);
    udplen = (uint16_t)(8 + paylen);
    iplen = (uint16_t)(MIN_INNER + udplen);
    if (iplen < MIN_INNER)
        die("outer IP total length overflow");

    /* the outer header is not part of the frozen frame format; this mirrors the kernel module's current construction:
     * version=4 ihl=5 tos=0 id=0 ttl=64 proto=UDP, DF from --df (module default 1),
     * ports and addresses are always **big-endian** (this is exactly where byte-order bugs occurred historically). */
    memset(hdr, 0, sizeof hdr);
    hdr[0] = 0x45;
    put16(hdr + 2, iplen);
    put16(hdr + 4, (uint16_t)id);
    put16(hdr + 6, df ? 0x4000 : 0);
    hdr[8] = (uint8_t)ttl;
    hdr[9] = 17;
    memcpy(hdr + 12, src, 4);
    memcpy(hdr + 16, dst, 4);
    put16(hdr + 10, csum_finish(csum_add(0, hdr, MIN_INNER)));
    put16(hdr + 20, sport_v);
    put16(hdr + 22, (uint16_t)dport);
    put16(hdr + 24, udplen);
    put16(hdr + 26, 0); /* leave UDP checksum 0: under veth's HW_CSUM offload the captured value may be a
                         * partial sum and does not take part in the byte-by-byte comparison (the script only compares the first 26 bytes) */

    write_file(out, hdr, sizeof hdr);

    printf("MODE=outer\n");
    printf("OUTER_HDR_BYTES=%d\n", OUTER_HDR);
    printf("OUTER_IP_SRC=%s\n", src_s);
    printf("OUTER_IP_DST=%s\n", dst_s);
    printf("OUTER_IP_PROTO=17\n");
    printf("OUTER_IP_TTL=%ld\n", ttl);
    printf("OUTER_IP_ID=%ld\n", id);
    printf("OUTER_IP_DF=%ld\n", df);
    printf("OUTER_IP_TOT_LEN=%u\n", iplen);
    printf("OUTER_IP_CSUM=0x%04x\n", get16(hdr + 10));
    printf("OUTER_UDP_SPORT=%u\n", sport_v);
    printf("OUTER_UDP_DPORT=%ld\n", dport);
    printf("OUTER_UDP_LEN=%u\n", udplen);
    info("expected outer header: %s:%u -> %s:%ld proto=17 DF=%ld tot_len=%u (UDP checksum set to 0, not compared)",
         src_s, sport_v, dst_s, dport, df, iplen);
    return 0;
}

/* ---------------------------------------------------------------- main */

static _Noreturn void usage(int rc)
{
    fprintf(rc ? stderr : stdout,
        "usage:\n"
        "  interop_c encap --in <inner IPv4 packet> --out <outer UDP payload> [common options]\n"
        "  interop_c decap --in <outer UDP payload> --out <inner IPv4 packet> [common options]\n"
        "  interop_c mkudp --out <inner IPv4 packet> [--payload-out <raw payload>] [options]\n"
        "  interop_c cmpin --got <file> --want <file> [--ignore-stack-fields]\n"
        "  interop_c outer --out <28-byte header> --src <IP> --dst <IP> [options]\n"
        "\n"
        "common options: --key <16 hex digits> | --user <U> --pass <P> (production session_key())\n"
        "          --sid <u16> --tok <u32> --enc <0|1> --quiet\n"
        "mkudp options: --src --dst --sport --dport --ttl --id --df\n"
        "            --payload-len <N> | --payload-hex <hex> | --payload-str <s>\n"
        "outer options: --sport --dport --payload-len --ttl --id --df\n");
    exit(rc);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        usage(2);
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))
        usage(0);

    if (!strcmp(argv[1], "encap"))
        return do_encap(argc - 2, argv + 2);
    if (!strcmp(argv[1], "decap"))
        return do_decap(argc - 2, argv + 2);
    if (!strcmp(argv[1], "mkudp"))
        return do_mkudp(argc - 2, argv + 2);
    if (!strcmp(argv[1], "cmpin"))
        return do_cmpin(argc - 2, argv + 2);
    if (!strcmp(argv[1], "outer"))
        return do_outer(argc - 2, argv + 2);

    fprintf(stderr, "interop_c: unknown mode %s\n", argv[1]);
    usage(2);
}

/* ---------------------------------------------------------------- link stubs
 *
 * The four functions below are symbols referenced by functions in protocol.c / crypto.c that **this tool does not call**.
 * Defining them (instead of linking util.c + buffer.c) keeps this test tool's dependencies to
 * libcrypto only: util.c/port.c would drag in the whole user-space platform layer (socket/thread/config...),
 * which is unrelated to the goal of "verifying only the wire format". This tool's code paths never reach them.
 */
void log_err(const char *fmt, ...)
{
    va_list ap;

    fputs("interop_c: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

_Noreturn void oom_abort(void)
{
    fputs("interop_c: memory allocation failed\n", stderr);
    abort();
}

void buf_put(buf_t *b, const void *p, size_t n)
{
    (void)b;
    (void)p;
    (void)n;
    fputs("interop_c: should never get here (buf_put stub)\n", stderr);
    abort();
}

void buf_put_u8(buf_t *b, uint8_t v)
{
    (void)b;
    (void)v;
    fputs("interop_c: should never get here (buf_put_u8 stub)\n", stderr);
    abort();
}
