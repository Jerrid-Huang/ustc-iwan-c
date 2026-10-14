/* SPDX-License-Identifier: GPL-2.0 */
/*
 * interop_c.c — iWAN 数据面「跨实现互通」验证的 C 侧参照实现。
 *
 * 配合 kernel/tests/interop_test.sh 与 kernel/tests/capture_iwan.py 使用：
 * 把内核模块（kernel/iwan_tx.c 出站封装 / kernel/iwan_rx.c 入站解封）在线上
 * 产生的字节，与本工具（走生产代码路径）产生的字节做逐字节对拍。
 *
 * 冻结线格式（PROTOCOL.md §2/§6/§8 与 src/common/protocol.h）：
 *   [外层 IPv4 20B][外层 UDP 8B][8B 帧头: type, enc, sid(u16 BE), tok(u32 BE)]
 *   [XOR 后的内层 IPv4 包]
 *   - 帧头 8 字节只由生产函数 pkt_hdr() 生成，本文件不自己拼字节；
 *   - XOR 只作用于**内层 IP 包整体**（含内层 IP 头），用生产函数 xor_crypt()，
 *     密钥 8 字节、按字节偏移循环；帧头与外层头不参与 XOR；
 *   - 会话密钥 = MD5(username||password) 的前 8 字节（可用 --user/--pass 让
 *     生产函数 session_key() 现场推导，而不是在脚本里硬编码）。
 *
 * 编译（interop_test.sh 用的就是这一行）：
 *   cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -I src/common -o interop_c \
 *      kernel/tests/interop_c.c src/common/protocol.c src/common/crypto.c -lcrypto
 * -D_GNU_SOURCE 不可省：src/common/port.h 的 sendmmsg/recvmmsg/accept4 需要它，
 * 否则报 implicit declaration 直接编译失败（实测）。
 * pkt_hdr() 在 protocol.c，xor_crypt()/session_key()/md5() 在 crypto.c（后者需要
 * libcrypto 的 EVP_*）。这两个 .o 里还有本工具不调用的函数，它们引用 util.c 的
 * log_err()/oom_abort() 与 buffer.c 的 buf_put()/buf_put_u8()；本文件末尾给出
 * 等价的最小实现，避免把 util.c/port.c 的整棵依赖树拖进链接（那四个桩不会被
 * 本工具的任何一条路径执行）。
 *
 * 模式：
 *   encap  --in <内层IPv4包> --out <外层UDP载荷>
 *          载荷 = pkt_hdr() 的 8 字节 + xor_crypt(内层包)
 *   decap  --in <外层UDP载荷> --out <内层IPv4包>
 *          按 type/enc/sid/tok 校验帧头（与 pkt_hdr() 的输出逐字节比较），
 *          解密并还原内层包；内含一次 xor_crypt 往返自检
 *   mkudp  --out <内层IPv4包> [--payload-out <纯载荷>]
 *          生成确定性的内层 IPv4+UDP 包（IP/UDP 校验和按明文正确填写），
 *          用于「内容已知」的注入与投递断言
 *   cmpin  --got <文件> --want <文件> [--ignore-stack-fields]
 *          逐字节比较两个内层包；--ignore-stack-fields 跳过协议栈会改写的
 *          id/frag_off/ttl/checksum 字段（仅用于内核协议栈自己造的包），
 *          同时校验 got 的 IP 头自洽（版本/长度/校验和/未分片）
 *   outer  --out <28字节> --src <IP> --dst <IP> [--sport N] [--dport N]
 *          [--payload-len N] [--ttl N] [--id N] [--df 0|1]
 *          生成期望的外层 IPv4+UDP 头（外层头不属于冻结帧格式，这里按内核
 *          模块当前的构造给出期望值），并把字段以 KEY=value 打到 stdout，
 *          与 capture_iwan.py 的元数据同名，便于脚本逐字段断言
 *
 * 公共选项：
 *   --key <16位hex>        会话密钥（默认 0011223344556677，与既有测试一致）
 *   --user <U> --pass <P>  用生产 session_key() 推导密钥（覆盖 --key）
 *   --sid <u16>            默认 4660
 *   --tok <u32>            默认 3405691582
 *   --enc <0|1>            默认 1（0x18 PT_DATA_ENC + XOR；0 = 0x14 PT_DATA 明文）
 *   --quiet                不在 stderr 打印进度信息
 *
 * stdout 是稳定的 KEY=value（给脚本解析），stderr 是人看的进度/诊断。
 * 失败一律退出码非 0（用法错 2，校验/比较失败 1）。
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

/* PROTOCOL.md §10：UDP 数据报上限；内层包必须完整落在一个数据报里 */
#define MAX_DATAGRAM 65507
#define MIN_INNER    20 /* 最小 IPv4 头 */
#define OUTER_HDR    28 /* 外层 IPv4 20 + UDP 8 */

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

    fputs("interop_c: 错误: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* ---------------------------------------------------------------- 小工具 */

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
        die("%s: 不是合法整数: %s", what, s);
    if (v < lo || v > hi)
        die("%s: %ld 超出范围 [%ld, %ld]", what, v, lo, hi);
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
        die("--key 需要 16 位十六进制（8 字节会话密钥），得到 \"%s\"", s);
    for (i = 0; i < 8; i++) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);

        if (hi < 0 || lo < 0)
            die("--key 含非十六进制字符: \"%s\"", s);
        key[i] = (uint8_t)((hi << 4) | lo);
    }
}

static void parse_ip4(const char *s, uint8_t out[4], const char *what)
{
    if (!s2ip4(s, out)) /* 生产代码（protocol.c）的点分四段解析 */
        die("%s: 不是合法 IPv4 地址: %s", what, s);
}

static uint8_t *read_file(const char *path, size_t *lenp)
{
    FILE *f;
    long n;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (!f)
        die("打开 %s 失败: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0)
        die("定位 %s 失败: %s", path, strerror(errno));
    n = ftell(f);
    if (n < 0)
        die("取 %s 长度失败: %s", path, strerror(errno));
    if (n > MAX_DATAGRAM)
        die("%s: %ld 字节超过 UDP 数据报上限 %d", path, n, MAX_DATAGRAM);
    rewind(f);
    buf = malloc(n > 0 ? (size_t)n : 1);
    if (!buf)
        oom_abort();
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n)
        die("读取 %s 失败: %s", path, strerror(errno));
    fclose(f);
    *lenp = (size_t)n;
    return buf;
}

static void write_file(const char *path, const uint8_t *p, size_t n)
{
    FILE *f = fopen(path, "wb");

    if (!f)
        die("创建 %s 失败: %s", path, strerror(errno));
    if (n > 0 && fwrite(p, 1, n, f) != n) {
        fclose(f);
        die("写 %s 失败: %s", path, strerror(errno));
    }
    if (fclose(f) != 0)
        die("关闭 %s 失败: %s", path, strerror(errno));
}

/* -------------------------------------------------------------- 校验和 */

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

/* 1 = 校验和自洽；0 = 不合法 */
static int ip_csum_ok(const uint8_t *p, size_t n)
{
    if (n < MIN_INNER)
        return 0;
    return csum_finish(csum_add(0, p, MIN_INNER)) == 0;
}

/* 1 = 校验和自洽；2 = 字段为 0（IPv4 允许"未计算"）；0 = 不合法 */
static int udp_csum_state(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    uint16_t uc, len;
    size_t ulen;

    if (n < MIN_INNER + 8 || p[9] != 17)
        return 0;
    ulen = get16(p + 2) - MIN_INNER; /* IP tot_len - IP 头 */
    if (ulen < 8 || ulen > n - MIN_INNER)
        return 0;
    len = get16(p + MIN_INNER + 4);
    if (len != ulen)
        return 0;
    uc = get16(p + MIN_INNER + 6);
    if (uc == 0)
        return 2;
    s = csum_add(s, p + 12, 8); /* 伪头：src + dst */
    s += 17;                    /* 伪头：proto（16 位里只有低字节） */
    s += len;                   /* 伪头：UDP 长度 */
    s = csum_add(s, p + MIN_INNER, ulen);
    return csum_finish(s) == 0 ? 1 : 0;
}

/* ---------------------------------------------------------------- 选项 */

static void resolve_key(const char *key_hex, const char *user, const char *pass,
                        uint8_t key[8], char hexout[17], const char **source)
{
    if (user || pass) {
        uint8_t full[16];

        if (!user || !pass)
            die("--user 与 --pass 必须成对给出");
        if (crypto_init() != 0) /* 生产代码：libcrypto 受控初始化 */
            die("libcrypto 初始化失败");
        session_key(user, pass, full); /* 生产代码：MD5(username||password) */
        memcpy(key, full, 8);          /* 数据面只用前 8 字节（PROTOCOL.md §8） */
        wipe(full, sizeof full);
        *source = "session_key";
    } else {
        parse_key_hex(key_hex, key);
        *source = "hex";
    }
    hex_encode(key, 8, hexout); /* 生产代码：小写 hex */
}

static void check_inner(const uint8_t *p, size_t n, const char *what)
{
    unsigned ver, ihl, tot;

    if (n < MIN_INNER)
        die("%s: 只有 %zu 字节，不足一个 IPv4 头", what, n);
    ver = p[0] >> 4;
    ihl = (unsigned)(p[0] & 0x0F) * 4;
    if (ver != 4)
        die("%s: version=%u，不是 IPv4", what, ver);
    if (ihl < MIN_INNER)
        die("%s: ihl=%u 非法", what, ihl);
    tot = get16(p + 2);
    if (tot != n)
        die("%s: IP tot_len=%u 与长度 %zu 不一致"
            "（冻结格式要求一个数据报恰好是一个完整内层包）",
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
        else die("encap: 未知或不完整选项 %s（--help 看用法）", o);
    }
    if (!in || !out)
        die("encap 需要 --in <内层IPv4包> --out <外层UDP载荷>");

    resolve_key(key_hex, user, pass, key, hexout, &ksrc);

    inner = read_file(in, &n);
    check_inner(inner, n, "--in");
    if (n + IWAN_HDR_LEN > MAX_DATAGRAM)
        die("--in: %zu 字节 + 8 字节帧头超过 UDP 数据报上限 %d",
            n, MAX_DATAGRAM);

    frame = malloc(IWAN_HDR_LEN + n);
    if (!frame)
        oom_abort();
    /* ① 生产代码构造 8 字节帧头（type/enc/sid BE/tok BE） */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, frame);
    /* ② 只 XOR 内层 IP 包整体（含内层 IP 头），从包首偏移 0 开始循环密钥 */
    memcpy(frame + IWAN_HDR_LEN, inner, n);
    xor_crypt(frame + IWAN_HDR_LEN, n, key, 8);

    write_file(out, frame, IWAN_HDR_LEN + n);

    /* 自检：帧头必须与 pkt_hdr() 的输出逐字节一致（这里再生成一次比较） */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, want);
    if (memcmp(frame, want, IWAN_HDR_LEN) != 0)
        die("内部不一致：帧头与 pkt_hdr() 输出不同");

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
    info("帧头字节: %s", hdrhex);

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
        else die("decap: 未知或不完整选项 %s（--help 看用法）", o);
    }
    if (!in || !out)
        die("decap 需要 --in <外层UDP载荷> --out <内层IPv4包>");

    resolve_key(key_hex, user, pass, key, hexout, &ksrc);

    frame = read_file(in, &n);
    if (n < IWAN_HDR_LEN + MIN_INNER)
        die("--in: 只有 %zu 字节，不足 8 字节帧头 + 一个 IPv4 头", n);

    /* 帧头校验：直接与生产 pkt_hdr() 的输出比较（type/enc/sid BE/tok BE） */
    pkt_hdr(enc ? (uint8_t)PT_DATA_ENC : (uint8_t)PT_DATA, (uint8_t)enc,
            (uint16_t)sid, (uint32_t)tok, want);
    if (memcmp(frame, want, IWAN_HDR_LEN) != 0) {
        die("帧头不符: 收到 type=0x%02x enc=%u sid=%u tok=%lu，"
            "期望 type=0x%02x enc=%ld sid=%ld tok=%ld",
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
    xor_crypt(inner, inner_len, key, 8); /* 生产代码解密 */
    check_inner(inner, inner_len, "解出的内层包");

    /* 往返自检：同一个生产函数再加密一次必须逐字节还原成输入帧的载荷 */
    memcpy(again, inner, inner_len);
    xor_crypt(again, inner_len, key, 8);
    if (memcmp(again, frame + IWAN_HDR_LEN, inner_len) != 0)
        die("往返自检失败：xor_crypt 在同一输入上不是对合");

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
    info("帧头校验通过，解出 %zu 字节内层包（%s -> %s proto=%u）",
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
        else die("mkudp: 未知或不完整选项 %s（--help 看用法）", o);
    }
    if (!out)
        die("mkudp 需要 --out <内层IPv4包>");
    if (phex && pstr)
        die("--payload-hex 与 --payload-str 只能给一个");

    if (phex) {
        size_t hl = strlen(phex);

        if (hl % 2)
            die("--payload-hex 长度必须是偶数");
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
                die("--payload-hex 含非十六进制字符");
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
        /* 确定性图案，与 kernel/tests/echo_net.py 的 PAT 相同：(i*7+3)&0xFF */
        plen = plen_opt >= 0 ? (size_t)plen_opt : 32;
        payload = malloc(plen > 0 ? plen : 1);
        if (!payload)
            oom_abort();
        for (i = 0; i < plen; i++)
            payload[i] = (uint8_t)((i * 7 + 3) & 0xFF);
    }
    if (plen > 65479)
        die("载荷 %zu 字节太大（内层上限 65479 = 65507 - 20 - 8）", plen);

    parse_ip4(src_s, src, "--src");
    parse_ip4(dst_s, dst, "--dst");

    total = MIN_INNER + 8 + plen;
    pkt = calloc(1, total);
    if (!pkt)
        oom_abort();

    /* 内层 IPv4 头（明文语义：校验和按明文算，XOR 后仍自洽） */
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

    /* 内层 UDP 头 + 载荷 */
    put16(pkt + 20, (uint16_t)sport);
    put16(pkt + 22, (uint16_t)dport);
    put16(pkt + 24, (uint16_t)(8 + plen));
    put16(pkt + 26, 0);
    if (plen)
        memcpy(pkt + 28, payload, plen);

    /* UDP 校验和 = 伪头(src,dst,0,proto,len) + UDP 头(csum=0) + 载荷 */
    s = csum_add(0, pkt + 12, 8);
    s += 17;
    s += (uint32_t)(8 + plen);
    s = csum_add(s, pkt + 20, 8 + plen);
    uc = csum_finish(s);
    if (uc == 0)
        uc = 0xFFFF; /* 0 表示"未计算"，算出来是 0 必须写成 0xFFFF */
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
    info("生成内层包 %zu 字节（%s:%ld -> %s:%ld，载荷 %zu 字节）",
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
        else die("cmpin: 未知或不完整选项 %s（--help 看用法）", o);
    }
    if (!got_f || !want_f)
        die("cmpin 需要 --got <文件> --want <文件>");

    got = read_file(got_f, &gn);
    want = read_file(want_f, &wn);

    /* got 的自洽检查：版本/长度/未分片/IP 头校验和 */
    if (gn < MIN_INNER || (got[0] >> 4) != 4 || (got[0] & 0x0F) < 5)
        die("%s: 不是合法 IPv4 包", got_f);
    if ((got[0] & 0x0F) != 5)
        die("%s: ihl=%u（本工具只比较无选项的 IPv4 头）", got_f,
            (unsigned)(got[0] & 0x0F));
    if ((size_t)get16(got + 2) != gn)
        die("%s: IP tot_len=%u 与文件长度 %zu 不一致", got_f,
            (unsigned)get16(got + 2), gn);
    if (get16(got + 6) & 0x3FFF)
        die("%s: 内层包带分片（frag_off=0x%04x）", got_f,
            (unsigned)get16(got + 6));
    if (!ip_csum_ok(got, gn))
        die("%s: IP 头校验和不自洽（解封后的明文已被破坏？）", got_f);
    if (got[9] == 17 && udp_csum_state(got, gn) == 0)
        die("%s: 内层 UDP 长度/校验和不自洽", got_f);

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
        info("长度不同：got=%zu want=%zu", gn, wn);
        free(got);
        free(want);
        return 1;
    }

    for (i = 0; i < gn; i++) {
        if (ignore_stack) {
            /* 协议栈会自己填的字段：id(8,9) frag_off(10,11) ttl(12)
             * IP 头校验和(16..19)；其余字节必须逐字节相同 */
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
        info("逐字节一致：%zu 字节%s", gn,
             ignore_stack ? "（已跳过 id/frag_off/ttl/校验和）" : "");
        free(got);
        free(want);
        return 0;
    }

    printf("RESULT=diff\n");
    printf("DIFF_OFFSET=%d\n", diff);
    printf("GOT_BYTE=0x%02x\n", (unsigned)got[diff]);
    printf("WANT_BYTE=0x%02x\n", (unsigned)want[diff]);
    info("首个差异在偏移 %d：got=0x%02x want=0x%02x", diff,
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
        else die("outer: 未知或不完整选项 %s（--help 看用法）", o);
    }
    if (!out || !src_s || !dst_s)
        die("outer 需要 --out <28字节头文件> --src <IP> --dst <IP>");

    parse_ip4(src_s, src, "--src");
    parse_ip4(dst_s, dst, "--dst");
    /* 模块的 iwan_tx.c: sport = cfg.sport ? cfg.sport : cfg.dport */
    sport_v = (uint16_t)(sport >= 0 ? sport : dport);
    udplen = (uint16_t)(8 + paylen);
    iplen = (uint16_t)(MIN_INNER + udplen);
    if (iplen < MIN_INNER)
        die("外层 IP 总长溢出");

    /* 外层头不属于冻结帧格式；这里镜像内核模块当前的构造：
     * version=4 ihl=5 tos=0 id=0 ttl=64 proto=UDP，DF 由 --df（模块默认 1），
     * 端口与地址一律**大端**（这正是历史上出过字节序缺陷的地方）。 */
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
    put16(hdr + 26, 0); /* UDP 校验和留 0：veth 的 HW_CSUM 卸载下抓到的值可能是
                         * 部分和，不参与逐字节比较（脚本只比较前 26 字节） */

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
    info("期望外层头：%s:%u -> %s:%ld proto=17 DF=%ld tot_len=%u（UDP 校验和置 0，不比较）",
         src_s, sport_v, dst_s, dport, df, iplen);
    return 0;
}

/* ---------------------------------------------------------------- main */

static _Noreturn void usage(int rc)
{
    fprintf(rc ? stderr : stdout,
        "用法:\n"
        "  interop_c encap --in <内层IPv4包> --out <外层UDP载荷> [公共选项]\n"
        "  interop_c decap --in <外层UDP载荷> --out <内层IPv4包> [公共选项]\n"
        "  interop_c mkudp --out <内层IPv4包> [--payload-out <纯载荷>] [选项]\n"
        "  interop_c cmpin --got <文件> --want <文件> [--ignore-stack-fields]\n"
        "  interop_c outer --out <28字节头> --src <IP> --dst <IP> [选项]\n"
        "\n"
        "公共选项: --key <16位hex> | --user <U> --pass <P>（生产 session_key()）\n"
        "          --sid <u16> --tok <u32> --enc <0|1> --quiet\n"
        "mkudp 选项: --src --dst --sport --dport --ttl --id --df\n"
        "            --payload-len <N> | --payload-hex <hex> | --payload-str <s>\n"
        "outer 选项: --sport --dport --payload-len --ttl --id --df\n");
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

    fprintf(stderr, "interop_c: 未知模式 %s\n", argv[1]);
    usage(2);
}

/* ---------------------------------------------------------------- 链接桩
 *
 * 下面四个函数是 protocol.c / crypto.c 里**本工具不调用**的函数所引用的符号。
 * 定义它们（而不是链接 util.c + buffer.c）是为了让这个测试工具的依赖只有
 * libcrypto：util.c/port.c 会把整个用户态平台层拖进来（socket/线程/配置…），
 * 与「只验证线格式」的目标无关。本工具的代码路径不会执行到它们。
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
    fputs("interop_c: 内存分配失败\n", stderr);
    abort();
}

void buf_put(buf_t *b, const void *p, size_t n)
{
    (void)b;
    (void)p;
    (void)n;
    fputs("interop_c: 不该走到这里（buf_put 桩）\n", stderr);
    abort();
}

void buf_put_u8(buf_t *b, uint8_t v)
{
    (void)b;
    (void)v;
    fputs("interop_c: 不该走到这里（buf_put_u8 桩）\n", stderr);
    abort();
}
