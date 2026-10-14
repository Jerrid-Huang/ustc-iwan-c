/* SPDX-License-Identifier: GPL-2.0 */
/*
 * win_vsrv.c — Windows 侧测速用的虚拟服务端（同一份源码可在 Linux 上跑，便于自检）。
 *
 * 用途：把"服务端"放进被测机器内部，让外层承载只剩客体自身的回环，从而把客户端
 * 数据面从"客体↔宿主"这段模拟网卡（QEMU slirp）的天花板里摘出来。它只做三件事：
 *
 *   · 握手：收到 PT_OPEN 就回 PT_OPEN_ACK（回显客户端首部的 sid/tok 与 nonce）；
 *   · 计数：只数 PT_DATA / PT_DATA_ENC，bytes 记外层 UDP 载荷（8 字节 iwan 首部 +
 *           内层 IP 总长），与 Linux 侧 IWAN_SRV_SINK 同一口径
 *           （src/common/server.c:1678-1682 的 sink_account）；
 *   · 挥手：收到 PT_CLOSE 只计数与打印，不回任何东西。
 *
 * "不检查"的确切含义（刻意的，与 Linux sink 一致）：
 *   · 不验签、不校验用户名/口令、不校验 sid/tok 归属；
 *   · 不解密、不解析内层 IP 与传输层、不转发、不写 TUN；
 *   · 短于 8 字节的报文只记一个 short 计数，不回包也不报错。
 * 唯一的回包是控制帧（OPEN_ACK / ECHO_RES / PING_RSP）：不做这三样，真实客户端
 * 根本进不了数据面（客户端侧约束见 src/common/auth.c:227-279）。
 *
 * 与 Linux sink 的两处差别，都是必需的：
 *   · 签名。控制帧的 16 字节签名是 md5(首部 8 字节 || "mw")
 *     （src/common/protocol.c:22-37 的 pkt_sig），而 mingw 工具链没有 OpenSSL
 *     （树内 md5() 走 EVP，src/common/crypto.c:124）。这里内置一份 RFC 1321
 *     实现，只用于生成控制帧签名；-S 自检把控制帧整帧十六进制打出来，可与树内
 *     ctrl_hdr() 逐字节对照。
 *   · 打印前缀是 VSINK，另含握手/挥手计数与帧长统计。
 *
 * 构建（客体是 x86-64 Windows）：
 *   x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Werror \
 *       -o win_vsrv.exe tests/win_vsrv.c -lws2_32
 * 本机自检：
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -o /tmp/win_vsrv tests/win_vsrv.c -lpthread
 *   /tmp/win_vsrv -S
 *
 * 用法：
 *   win_vsrv [-b 0.0.0.0] [-p 45678] [-s 20] [-t 2] [-k 0]
 *            [-i 198.18.0.2] [-g 198.18.0.1] [-d 114.114.114.114] [-m 1400]
 *            [-S] [-h]
 *   -i 是回给客户端的隧道内地址（T_IP），客户端拿它配置自己的 TUN；打流目标必须
 *   落在同一 /24（客户端只装直连子网路由，不做默认路由劫持）。
 *   -k 是本端主动发 ECHO_REQ 的间隔秒数，默认 0（真实客户端自己每 10 秒发一次
 *   keepalive，见 src/common/proxy.c:798，本端只需回 ECHO_RES）。
 */
#ifndef _WIN32
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE 1   /* clock_gettime/nanosleep/getaddrinfo 在 -std=c11 下需要 */
#  endif
#endif

#ifdef _WIN32
#  ifndef __USE_MINGW_ANSI_STDIO
#    define __USE_MINGW_ANSI_STDIO 1  /* %llu 用 mingw 自己的实现，不依赖 MSVCRT */
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601       /* inet_pton/inet_ntop/getaddrinfo 需要 Vista+ */
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <process.h>
#else
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <pthread.h>
#endif

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
typedef SOCKET sock_t;
#  define SOCK_BAD INVALID_SOCKET
#  define sock_close closesocket
#else
typedef int sock_t;
#  define SOCK_BAD (-1)
#  define sock_close close
#endif

/* ---------------------------------------------------------------- 协议常量 */
#define HDR_LEN      8
#define SIG_LEN      16
#define CTRL_LEN     (HDR_LEN + SIG_LEN)
#define CTRL_SIG_MAX 31u          /* 客户端上限 55 字节减去 24：src/common/auth.c:230 */

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
    PT_PING_RSP    = 0x2A
};

enum {
    T_MTU         = 0x03,
    T_IP          = 0x04,
    T_DNS         = 0x05,
    T_GATEWAY     = 0x06,
    T_ENCRYPT     = 0x08,
    T_AUTH_VERIFY = 0x0F
};

#define PING_SID 0xFFFFu
#define PING_TOK 0xFFFFFFFFu
#define MTU_MIN  576u
#define MTU_MAX  65499u

/* ------------------------------------------------------------ 大端读写 */
static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ------------------------------------------------------- MD5（RFC 1321） */
/*
 * 只为生成控制帧签名。树内 md5() 依赖 OpenSSL，而客体上的工具链没有 OpenSSL，
 * 所以这里自带一份；正确性由 -S 与树内 ctrl_hdr() 的逐字节对照保证，不由"看着
 * 像 MD5"保证。
 */
typedef struct {
    uint32_t h[4];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   n;
} md5_ctx;

static const uint32_t md5_k[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static const uint8_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rol32(uint32_t x, int c)
{
    return (uint32_t)((x << c) | (x >> (32 - c)));
}

static void md5_block(md5_ctx *c, const uint8_t *p)
{
    uint32_t m[16], a, b, cc, d, f, g, tmp;
    int i;

    for (i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
               ((uint32_t)p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & cc) | (~b & d);
            g = (uint32_t)i;
        } else if (i < 32) {
            f = (d & b) | (~d & cc);
            g = (uint32_t)((5 * i + 1) & 15);
        } else if (i < 48) {
            f = b ^ cc ^ d;
            g = (uint32_t)((3 * i + 5) & 15);
        } else {
            f = cc ^ (b | ~d);
            g = (uint32_t)((7 * i) & 15);
        }
        tmp = d;
        d = cc;
        cc = b;
        b = b + rol32(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
}

static void md5_init(md5_ctx *c)
{
    c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u;
    c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u;
    c->bits = 0;
    c->n = 0;
}

static void md5_update(md5_ctx *c, const uint8_t *p, size_t len)
{
    c->bits += (uint64_t)len * 8u;
    while (len > 0) {
        size_t take = 64 - c->n;
        if (take > len)
            take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take;
        p += take;
        len -= take;
        if (c->n == 64) {
            md5_block(c, c->buf);
            c->n = 0;
        }
    }
}

static void md5_final(md5_ctx *c, uint8_t out[16])
{
    uint8_t pad[72];
    size_t  padlen;
    uint64_t bits = c->bits;
    int i;

    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    padlen = (c->n < 56) ? (56 - c->n) : (120 - c->n);
    for (i = 0; i < 8; i++)
        pad[padlen + (size_t)i] = (uint8_t)(bits >> (8 * i));
    md5_update(c, pad, padlen + 8);

    for (i = 0; i < 4; i++) {
        out[i * 4 + 0] = (uint8_t)c->h[i];
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(c->h[i] >> 24);
    }
}

static void md5_buf(const uint8_t *p, size_t len, uint8_t out[16])
{
    md5_ctx c;
    md5_init(&c);
    md5_update(&c, p, len);
    md5_final(&c, out);
}

/* ------------------------------------------------------- 控制帧与 TLV */
/* 签名 = md5(首部 8 字节 || "mw")，与 src/common/protocol.c:22-37 的 pkt_sig 同构 */
static size_t build_ctrl(uint8_t *out, uint8_t typ, uint8_t enc, uint16_t sid,
                         uint32_t tok, const uint8_t *tlvs, size_t tlvlen)
{
    uint8_t x[HDR_LEN + 2];

    out[0] = typ;
    out[1] = enc;
    wr16(out + 2, sid);
    wr32(out + 4, tok);
    memcpy(x, out, HDR_LEN);
    memcpy(x + HDR_LEN, "mw", 2);
    md5_buf(x, sizeof x, out + HDR_LEN);
    if (tlvlen > 0)
        memcpy(out + CTRL_LEN, tlvs, tlvlen);
    return CTRL_LEN + tlvlen;
}

static size_t tlv_add(uint8_t *p, uint8_t typ, const void *val, size_t vlen)
{
    p[0] = typ;
    p[1] = (uint8_t)(vlen + 2);   /* 长度字节存 vlen+2：src/common/protocol.c:39-53 */
    if (vlen > 0)
        memcpy(p + 2, val, vlen);
    return 2 + vlen;
}

/* 找到就返回 0；畸形即停，不检查内容 */
static int tlv_find(const uint8_t *p, size_t len, uint8_t typ,
                    const uint8_t **val, size_t *vlen)
{
    size_t i = 0;

    while (i + 2 <= len) {
        uint8_t t = p[i];
        uint8_t l = p[i + 1];
        if (l < 2 || i + (size_t)l > len)
            return -1;
        if (t == typ) {
            *val = p + i + 2;
            *vlen = (size_t)l - 2;
            return 0;
        }
        i += (size_t)l;
    }
    return -1;
}

/* ------------------------------------------------------------ 运行参数 */
static sock_t   g_sock = SOCK_BAD;
static uint16_t g_mtu = 1400;
static uint32_t g_ip, g_gw, g_dns;      /* 大端字节序存放 */
static int      g_ka_sec = 0;

static volatile int g_stop = 0;
static struct sockaddr_storage g_peer;
static socklen_t g_peerlen = 0;
static volatile int g_have_peer = 0;
static unsigned long long g_ka_tx = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static double now_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
#endif
}

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* ---------------------------------------------------------------- 工作线程 */
typedef struct {
    int id;
    unsigned long long pkts, bytes, opens, closes, echo_req, ping_req;
    unsigned long long other, short_, min, max;
} worker;

static void remember_peer(const struct sockaddr_storage *from, socklen_t len)
{
    memcpy(&g_peer, from, sizeof g_peer);
    g_peerlen = len;
    g_have_peer = 1;
}

static void send_to(const uint8_t *p, size_t n, const struct sockaddr_storage *to,
                    socklen_t tolen)
{
    if (g_sock == SOCK_BAD)
        return;
    (void)sendto(g_sock, (const char *)p, (int)n, 0,
                 (const struct sockaddr *)to, tolen);
}

static const char *addr_str(const struct sockaddr_storage *a, char *buf, size_t sz)
{
    const void *src = NULL;

    if (a->ss_family == AF_INET)
        src = &((const struct sockaddr_in *)a)->sin_addr;
    else if (a->ss_family == AF_INET6)
        src = &((const struct sockaddr_in6 *)a)->sin6_addr;
    if (src == NULL || inet_ntop((int)a->ss_family, src, buf, (size_t)sz) == NULL)
        snprintf(buf, sz, "?");
    return buf;
}

static unsigned addr_port(const struct sockaddr_storage *a)
{
    if (a->ss_family == AF_INET)
        return (unsigned)ntohs(((const struct sockaddr_in *)a)->sin_port);
    if (a->ss_family == AF_INET6)
        return (unsigned)ntohs(((const struct sockaddr_in6 *)a)->sin6_port);
    return 0;
}

/* OPEN_ACK：回显 sid/tok 与 nonce，带客户端要求的六个 TLV（合计正好 31 字节） */
static size_t build_ack(uint8_t *out, const uint8_t *req, size_t reqlen)
{
    const uint8_t *v;
    size_t  vl, o = 0;
    uint8_t tlv[CTRL_SIG_MAX];
    uint8_t enc = req[1];
    uint16_t mtu = g_mtu;
    uint8_t b[4];

    if (reqlen > HDR_LEN &&
        tlv_find(req + HDR_LEN, reqlen - HDR_LEN, T_ENCRYPT, &v, &vl) == 0 && vl == 1)
        enc = v[0];
    if (reqlen > HDR_LEN &&
        tlv_find(req + HDR_LEN, reqlen - HDR_LEN, T_MTU, &v, &vl) == 0 && vl == 2) {
        unsigned m = ((unsigned)v[0] << 8) | v[1];
        if (m >= MTU_MIN && m <= MTU_MAX)
            mtu = (uint16_t)m;
    }

    wr16(b, mtu);
    o += tlv_add(tlv + o, T_MTU, b, 2);
    wr32(b, g_ip);
    o += tlv_add(tlv + o, T_IP, b, 4);
    wr32(b, g_gw);
    o += tlv_add(tlv + o, T_GATEWAY, b, 4);
    wr32(b, g_dns);
    o += tlv_add(tlv + o, T_DNS, b, 4);
    b[0] = enc;
    o += tlv_add(tlv + o, T_ENCRYPT, b, 1);
    /* T_AUTH_VERIFY 在线上可选，但一旦出现客户端就严格校验（auth.c:272-279）：
     * 原样回显 nonce 是最省事也最稳的做法；长度不是 4 就不带。 */
    if (reqlen > HDR_LEN &&
        tlv_find(req + HDR_LEN, reqlen - HDR_LEN, T_AUTH_VERIFY, &v, &vl) == 0 && vl == 4)
        o += tlv_add(tlv + o, T_AUTH_VERIFY, v, 4);

    /* 真实服务端是"分配"会话标识，客户端 OPEN 里 sid/tok 都是 0；照抄就会回一个
     * sid=0 的会话。tok 为 0 客户端直接拒（auth.c:246），sid 为 0 虽不报错但不像
     * 真实服务端，这里两个都给一个固定的非零值。 */
    {
        uint16_t sid = rd16(req + 2);
        uint32_t tok = rd32(req + 4);
        if (sid == 0)
            sid = 0x0002;
        if (tok == 0)
            tok = 0x12345678u;
        return build_ctrl(out, PT_OPEN_ACK, enc, sid, tok, tlv, o);
    }
}

static void handle_frame(worker *w, const uint8_t *buf, size_t n,
                         const struct sockaddr_storage *from, socklen_t fromlen)
{
    uint8_t out[CTRL_LEN + CTRL_SIG_MAX];

    if (n < HDR_LEN) {
        w->short_++;
        return;
    }

    switch (buf[0]) {
    case PT_OPEN:
        w->opens++;
        remember_peer(from, fromlen);
        send_to(out, build_ack(out, buf, n), from, fromlen);
        return;
    case PT_DATA:
    case PT_DATA_ENC:
        w->pkts++;
        w->bytes += n;
        if (n > w->max)
            w->max = n;
        if (w->min == 0 || n < w->min)
            w->min = n;   /* 0 表示"还没有样本"：帧长不可能小于 8 */
        remember_peer(from, fromlen);
        return;
    case PT_ECHO_REQ:
        w->echo_req++;
        remember_peer(from, fromlen);
        send_to(out, build_ctrl(out, PT_ECHO_RES, buf[1], rd16(buf + 2),
                                rd32(buf + 4), NULL, 0), from, fromlen);
        return;
    case PT_PING_REQ:
        w->ping_req++;
        remember_peer(from, fromlen);
        send_to(out, build_ctrl(out, PT_PING_RSP, 0, (uint16_t)PING_SID,
                                PING_TOK, NULL, 0), from, fromlen);
        return;
    case PT_CLOSE: {
        char a[64];
        w->closes++;
        printf("VSINK close from %s:%u (thread %d, DATA frames on this thread %llu)\n",
               addr_str(from, a, sizeof a), addr_port(from), w->id, w->pkts);
        fflush(stdout);
        return;
    }
    default:
        w->other++;
        return;
    }
}

static void recv_loop(worker *w)
{
    uint8_t buf[65536 + 64];

    while (!g_stop) {
        struct sockaddr_storage from;
        socklen_t fromlen = (socklen_t)sizeof from;
        int n = (int)recvfrom(g_sock, (char *)buf, (int)sizeof buf, 0,
                              (struct sockaddr *)&from, &fromlen);
        if (n < 0)
            continue;   /* 收超时、EINTR、真错误：都不计数 */
        handle_frame(w, buf, (size_t)n, &from, fromlen);
    }
}

#ifdef _WIN32
static unsigned __stdcall thread_main(void *arg)
{
    recv_loop((worker *)arg);
    return 0;
}

static int thread_start(worker *w)
{
    uintptr_t h = _beginthreadex(NULL, 0, thread_main, w, 0, NULL);
    return h != 0 ? 0 : -1;
}
#else
static void *thread_main(void *arg)
{
    recv_loop((worker *)arg);
    return NULL;
}

static int thread_start(worker *w)
{
    pthread_t t;
    return pthread_create(&t, NULL, thread_main, w);
}
#endif

/* ---------------------------------------------------------------- 打印 */
typedef struct {
    unsigned long long pkts, bytes, opens, closes, echo_req, ping_req;
    unsigned long long other, short_, min, max;
} total_t;

static void sum_workers(const worker *w, int nw, total_t *t)
{
    int i;

    memset(t, 0, sizeof *t);
    t->min = 0;
    for (i = 0; i < nw; i++) {
        t->pkts    += w[i].pkts;
        t->bytes   += w[i].bytes;
        t->opens   += w[i].opens;
        t->closes  += w[i].closes;
        t->echo_req += w[i].echo_req;
        t->ping_req += w[i].ping_req;
        t->other   += w[i].other;
        t->short_  += w[i].short_;
        if (w[i].max > t->max)
            t->max = w[i].max;
        if (w[i].min != 0 && (t->min == 0 || w[i].min < t->min))
            t->min = w[i].min;
    }
}

static void print_tick(const total_t *t, double elapsed_s, double dt_s,
                       unsigned long long prev_pkts, unsigned long long prev_bytes)
{
    /* t= 是自启动起的秒数：多相测量要靠它把每个 5 秒区间归到某一相。 */
    printf("VSINK t=%.1f pkts=%llu bytes=%llu pps=%.1f mbps=%.2f opens=%llu closes=%llu "
           "echo=%llu ping=%llu other=%llu short=%llu\n",
           elapsed_s, t->pkts, t->bytes,
           (double)(t->pkts - prev_pkts) / dt_s,
           (double)(t->bytes - prev_bytes) * 8.0 / 1e6 / dt_s,
           t->opens, t->closes, t->echo_req, t->ping_req, t->other, t->short_);
    fflush(stdout);
}

static void print_final(const worker *w, int nw, const total_t *t, double elapsed_s)
{
    int i;

    printf("VSINK final pkts=%llu bytes=%llu avg_pps=%.1f avg_mbps=%.2f opens=%llu "
           "closes=%llu echo=%llu ping=%llu other=%llu short=%llu keepalive_tx=%llu "
           "frame_min=%llu frame_max=%llu frame_avg=%.1f elapsed=%.3fs threads=%d\n",
           t->pkts, t->bytes,
           elapsed_s > 0.0 ? (double)t->pkts / elapsed_s : 0.0,
           elapsed_s > 0.0 ? (double)t->bytes * 8.0 / 1e6 / elapsed_s : 0.0,
           t->opens, t->closes, t->echo_req, t->ping_req, t->other, t->short_,
           g_ka_tx, t->min, t->max,
           t->pkts > 0 ? (double)t->bytes / (double)t->pkts : 0.0,
           elapsed_s, nw);
    for (i = 0; i < nw; i++)
        printf("VSINK thread %d pkts=%llu bytes=%llu opens=%llu closes=%llu echo=%llu "
               "ping=%llu other=%llu short=%llu\n",
               w[i].id, w[i].pkts, w[i].bytes, w[i].opens, w[i].closes,
               w[i].echo_req, w[i].ping_req, w[i].other, w[i].short_);
    fflush(stdout);
}

/* ---------------------------------------------------------------- 自检 */
static void hex_dump(const char *tag, const uint8_t *p, size_t n)
{
    size_t i;

    printf("%s ", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void selftest(void)
{
    static const char *const vec_msg[] = {
        "", "a", "abc", "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    };
    size_t i;

    printf("== md5 vectors (cross-check with md5sum) ==\n");
    for (i = 0; i < sizeof vec_msg / sizeof vec_msg[0]; i++) {
        uint8_t d[16];
        md5_buf((const uint8_t *)vec_msg[i], strlen(vec_msg[i]), d);
        hex_dump("md5", d, sizeof d);
    }

    printf("== whole control frames (cross-check with in-tree ctrl_hdr) ==\n");
    {
        uint8_t f[CTRL_LEN];
        const struct { const char *tag; uint8_t typ, enc; uint16_t sid; uint32_t tok; } c[] = {
            { "OPEN_ACK", PT_OPEN_ACK, 1, 0x1234, 0x12345678u },
            { "ECHO_RES", PT_ECHO_RES, 1, 0x1234, 0x12345678u },
            { "PING_RSP", PT_PING_RSP, 0, (uint16_t)PING_SID, PING_TOK },
            { "ECHO_REQ", PT_ECHO_REQ, 1, 0x0002, 0xdeadbeefu }
        };
        for (i = 0; i < sizeof c / sizeof c[0]; i++) {
            build_ctrl(f, c[i].typ, c[i].enc, c[i].sid, c[i].tok, NULL, 0);
            hex_dump(c[i].tag, f, sizeof f);
        }
    }
}

/* ---------------------------------------------------------------- main */
static void usage(const char *argv0)
{
    printf("usage: %s [-b bind-ip] [-p port] [-s seconds(0=until Ctrl-C)] [-t threads]\n"
           "          [-k keepalive-secs(0=off)] [-i inner-ip] [-g gateway] [-d dns]\n"
           "          [-m mtu] [-S selftest] [-h]\n", argv0);
}

static int parse_ip4(const char *s, uint32_t *out)
{
    uint8_t a[4];
    if (inet_pton(AF_INET, s, a) != 1)
        return -1;
    *out = rd32(a);
    return 0;
}

int main(int argc, char **argv)
{
    const char *bind_ip = "0.0.0.0";
    int port = 45678;
    int secs = 20;
    int nthreads = 2;
    int i, rc;
    double t0, next_tick, next_ka, last_tick;
    unsigned long long prev_pkts = 0, prev_bytes = 0;
    struct addrinfo hints, *res = NULL;
    char portbuf[16];
    worker *w;
    total_t tot;

    if (parse_ip4("198.18.0.2", &g_ip) != 0 ||
        parse_ip4("198.18.0.1", &g_gw) != 0 ||
        parse_ip4("114.114.114.114", &g_dns) != 0) {
        fprintf(stderr, "built-in address parse failed\n");
        return 2;
    }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "-S") == 0) {
            selftest();
            return 0;
        } else if (strcmp(a, "-b") == 0 && i + 1 < argc) {
            bind_ip = argv[++i];
        } else if (strcmp(a, "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(a, "-s") == 0 && i + 1 < argc) {
            secs = atoi(argv[++i]);
        } else if (strcmp(a, "-t") == 0 && i + 1 < argc) {
            nthreads = atoi(argv[++i]);
        } else if (strcmp(a, "-k") == 0 && i + 1 < argc) {
            g_ka_sec = atoi(argv[++i]);
        } else if (strcmp(a, "-m") == 0 && i + 1 < argc) {
            int m = atoi(argv[++i]);
            if (m < (int)MTU_MIN || m > (int)MTU_MAX) {
                fprintf(stderr, "-m out of range [%u,%u]\n", MTU_MIN, MTU_MAX);
                return 2;
            }
            g_mtu = (uint16_t)m;
        } else if (strcmp(a, "-i") == 0 && i + 1 < argc) {
            if (parse_ip4(argv[++i], &g_ip) != 0) {
                fprintf(stderr, "-i is not an IPv4 address\n");
                return 2;
            }
        } else if (strcmp(a, "-g") == 0 && i + 1 < argc) {
            if (parse_ip4(argv[++i], &g_gw) != 0) {
                fprintf(stderr, "-g is not an IPv4 address\n");
                return 2;
            }
        } else if (strcmp(a, "-d") == 0 && i + 1 < argc) {
            if (parse_ip4(argv[++i], &g_dns) != 0) {
                fprintf(stderr, "-d is not an IPv4 address\n");
                return 2;
            }
        } else {
            fprintf(stderr, "unknown option %s\n", a);
            usage(argv[0]);
            return 2;
        }
    }
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > 16)
        nthreads = 16;

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup failed\n");
            return 1;
        }
    }
#endif
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(portbuf, sizeof portbuf, "%d", port);
    rc = getaddrinfo(bind_ip, portbuf, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s:%d) failed: %d\n", bind_ip, port, rc);
        return 1;
    }
    g_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (g_sock == SOCK_BAD) {
        fprintf(stderr, "socket failed\n");
        freeaddrinfo(res);
        return 1;
    }
    {
        int one = 1;
        int rcvbuf = 8 << 20, sndbuf = 1 << 20;
        (void)setsockopt(g_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        (void)setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof rcvbuf);
        (void)setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof sndbuf);
#ifdef _WIN32
        {
            DWORD tv = 200;
            (void)setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
        }
#else
        {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            (void)setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
        }
#endif
    }
    if (bind(g_sock, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
        fprintf(stderr, "bind(%s:%d) failed\n", bind_ip, port);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);

    w = (worker *)calloc((size_t)nthreads, sizeof *w);
    if (w == NULL) {
        fprintf(stderr, "calloc failed\n");
        return 1;
    }
    for (i = 0; i < nthreads; i++) {
        w[i].id = i;
        if (thread_start(&w[i]) != 0) {
            fprintf(stderr, "thread %d start failed\n", i);
            return 1;
        }
    }

    printf("VSINK ready on %s:%d threads=%d mtu=%u ip=%u.%u.%u.%u gw=%u.%u.%u.%u "
           "dns=%u.%u.%u.%u secs=%d keepalive=%ds\n",
           bind_ip, port, nthreads, (unsigned)g_mtu,
           (unsigned)((g_ip >> 24) & 0xff), (unsigned)((g_ip >> 16) & 0xff),
           (unsigned)((g_ip >> 8) & 0xff), (unsigned)(g_ip & 0xff),
           (unsigned)((g_gw >> 24) & 0xff), (unsigned)((g_gw >> 16) & 0xff),
           (unsigned)((g_gw >> 8) & 0xff), (unsigned)(g_gw & 0xff),
           (unsigned)((g_dns >> 24) & 0xff), (unsigned)((g_dns >> 16) & 0xff),
           (unsigned)((g_dns >> 8) & 0xff), (unsigned)(g_dns & 0xff),
           secs, g_ka_sec);
    fflush(stdout);

    t0 = now_ms();
    last_tick = t0;
    next_tick = t0 + 5000.0;
    next_ka = t0 + (double)g_ka_sec * 1000.0;
    while (!g_stop) {
        double now;
        sleep_ms(100);
        now = now_ms();
        if (now >= next_tick) {
            sum_workers(w, nthreads, &tot);
            print_tick(&tot, (now - t0) / 1000.0, (now - last_tick) / 1000.0,
                       prev_pkts, prev_bytes);
            prev_pkts = tot.pkts;
            prev_bytes = tot.bytes;
            last_tick = now;
            next_tick = now + 5000.0;
        }
        if (g_ka_sec > 0 && now >= next_ka && g_have_peer) {
            uint8_t f[CTRL_LEN];
            socklen_t plen = g_peerlen;
            struct sockaddr_storage peer;
            memcpy(&peer, &g_peer, sizeof peer);
            send_to(f, build_ctrl(f, PT_ECHO_REQ, 0, 0, 0, NULL, 0), &peer, plen);
            g_ka_tx++;
            next_ka = now + (double)g_ka_sec * 1000.0;
        }
        if (secs > 0 && now - t0 >= (double)secs * 1000.0)
            break;
    }

    sum_workers(w, nthreads, &tot);
    print_final(w, nthreads, &tot, (now_ms() - t0) / 1000.0);

    sock_close(g_sock);
    g_sock = SOCK_BAD;
#ifdef _WIN32
    WSACleanup();
#endif
    free(w);
    return 0;
}
