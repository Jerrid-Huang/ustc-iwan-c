/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iWAN 单向容量发生器 —— 内层跑 tcp / udp / 裸 IP（IP 协议号 253）
 *
 * 用法：
 *   bench_proto send --proto tcp|udp|raw --target A.B.C.D --port P
 *                    [--size N] [--duration S] [--threads K]
 *   bench_proto recv --proto tcp|udp|raw --bind A.B.C.D --port P
 *                    [--duration S] [--threads K] [--idle-ms M]
 *
 * --size 的口径（三种协议不一样，默认值见下）：
 *   udp = UDP 净荷，默认 1200，上限 65507（IPv4 总长 65535 减 20B IP 头
 *         与 8B UDP 头；与 src/common/protocol.h 的 IWAN_UDP_GSO_UNIT 同值）；
 *   raw = **整包**长度（含 20 字节 IP 头），默认 1200，上限 65535 ⇒ 负载
 *         上限 65515。tests/bench_proto.sh 里 SIZE_RAW=1220 就是按这个口径
 *         （整包 1220 / 负载 1200）传的；
 *   tcp = 每次写的块，默认 65536，不设上限（内核按 MSS 切）。
 * 内层 MTU 上限 65499（src/common/protocol.h 的 IWAN_MTU_MAX）⇒ udp 净荷超过
 * 65471、raw 整包超过 65499 时内层会分片，量到的是分片路径而不是单个大包。
 *
 * 输出（stdout，机器可解析，由 tests/bench_proto.sh 汇总成表）：
 *   READY  proto=<p> role=recv addr=<ip>:<port> rcvbuf=<n> threads=<k>
 *   RESULT proto=<p> role=send bytes=<> pkts=<> secs=<> gbps=<> pps=<> errs=<> threads=<> size=<>
 *   RESULT proto=<p> role=recv bytes=<> pkts=<> secs=<> gbps=<> pps=<> bad=<>
 *          conns=<> idle=<0|1> remote=<ip> chg=<n> maxsize=<>
 *
 *   size/maxsize 是负载口径（都放在行尾，既有字段与顺序不动）：send 的 size
 *   是**每包发出去的负载**（raw 已减掉 20B IP 头，tcp 是写块）；recv 的
 *   maxsize 是收到的最大单包净荷（tcp 是单次 recv 读到的最多字节数）——
 *   收包缓冲区一旦装不下，内核会静默截断并少算字节数，maxsize 会明显偏小，
 *   这是从日志核对"大包真的到了"的证据。
 *
 *   remote/chg 是"识破绕过"用的：收到的第一个远端地址（UDP/raw = 包的源地址，
 *   TCP = 连接对端）以及它变化的次数。内层流量若没进隧道、从 veth 直穿，
 *   这里会写成 172.31.201.x 之类而不是隧道地址。
 *
 * 另有自检入口（不需要权限）：bench_proto selftest —— 核对 raw 档拼出来的
 * IP 头（含校验和自校验）与 --size 上限的大包（长度/铺满/缓冲区容量）。
 *
 * 语义（为什么这样测）：
 *   · 单向饱和：发送侧用**阻塞** socket，内核背压 ⇒ 计数就是"链路实际接受的量"，
 *     不会出现"发了 100 Gbps、收到 2 Gbps"的假象；丢包体现在收发计数之差上。
 *   · goodput 的 secs 用接收侧"末包 - 首包"，不是进程运行时间也不含建链/启动时间；
 *     pps 同窗口。基线（lo 直连）与隧道（TUN）用同一把尺，才好比。
 *   · raw 档：IP 头里 src/id/校验和留 0 交给内核按路由代填（Linux raw_send_hdrinc
 *     的行为；id 只有为 0 时才会被 ip_select_ident() 代填），负载以 8 字节魔术
 *     开头，接收侧逐包校验并统计 bad —— 一旦收到别家流量会立刻暴露，而不是被
 *     算进数字里。
 *   · 接收侧收到过包后空闲 idle-ms（默认 700ms）即结束：尾部在途包仍会被计入，
 *     两边不需要严格对表。
 *
 * 注意：_GNU_SOURCE 由 CMakeLists.txt:179 统一定义，本文件不要再定义一次
 * （clang 在 -Werror 下会报 -Wmacro-redefined）。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RAW_PROTO 253
#define MAX_THREADS 64
#define MAGIC_LEN 8
/*
 * --size 的两条硬上限（口径见文件头）。取协议上限而不是"内层 MTU 该有多少"：
 * 超了必须报错退出，不能靠内核回 EMSGSIZE、更不能静默截断。
 */
#define MAX_UDP_SIZE 65507      /* UDP 净荷：65535 - 20(IP) - 8(UDP) */
#define MAX_RAW_SIZE 65535      /* raw 整包：IPv4 总长字段的硬上限 */
/*
 * 收包缓冲区按上面两条里最大的那条开（raw 收上来的整包）。原来这里是 1400
 * （按"内层 MTU 1400"定的），大 MTU 下 recvfrom 会**静默截断**：缓冲区小于
 * 对端报文时内核只拷 buf 那么多并原样返回长度，bad 不涨、看着无损，字节数
 * 却少算 —— 比报错难查得多。也不放栈上：64 个读线程 × 64KiB 会撑爆栈；
 * 每读线程 malloc 一份（dgram_reader）。
 */
#define DGRAM_BUF 65535
static const char MAGIC[MAGIC_LEN] = { 'I', 'W', 'A', 'N', 'B', 'N', 'C', 'H' };

struct cfg {
    const char *proto;
    const char *ip;         /* send: 目的地址; recv: 绑定地址 */
    int port;
    int size;               /* --size: udp=UDP 净荷; raw=整包（含 20B IP 头）;
                             * tcp=每次写多少。口径见文件头 */
    int duration;           /* 打流秒数 */
    int threads;            /* tcp: 连接数; udp/raw: 并发发送线程数 */
    int idle_ms;            /* recv: 空闲多久算结束 */
};

struct result {
    atomic_ullong bytes;
    atomic_ullong pkts;
    atomic_ullong errs;
    atomic_ullong bad;
    atomic_ullong conns;
    atomic_llong first_ms;  /* recv: 首包时刻（自 CLOCK_MONOTONIC 起的毫秒） */
    atomic_llong last_ms;   /* recv: 末包时刻 */
    /* recv: 收到的第一个远端地址（网络序，0=还没收到）与它变化的次数。
     * UDP/raw 是包的源地址，TCP 是连接的对端地址。它的用处是**识破绕过**：
     * 内层流量若没进隧道而从 veth 直穿，这里会写成 172.31.201.2 之类，
     * 而不是隧道地址 —— 比只看字节数可靠。 */
    atomic_uint remote_first;
    atomic_ullong remote_chg;
    /* recv: 收到的最大单包净荷（raw 已减 20B IP 头）。它只有一个用处：
     * 缓冲区装不下时内核会静默截断，这个数会卡在缓冲区大小上，日志里一眼
     * 能看出"报的大包其实只收到 1400"。 */
    atomic_ullong max_payload;
};

struct worker {
    const struct cfg *c;
    struct result *r;
    struct sockaddr_in dst; /* send 用 */
    int fd;                 /* tcp recv 用（accept 到的连接） */
};

/*
 * g_deadline 是普通 double，靠两条 happens-before 边保证安全：
 *   send: 主线程先写 g_deadline，再 release 写 g_go，工作线程 acquire 读 g_go；
 *   recv: 主线程先写 g_deadline，再 pthread_create，工作线程由创建获得可见性。
 * 之后所有线程只读，故不需要原子类型。
 */
static atomic_bool g_go;
static atomic_bool g_stop;
static atomic_bool g_idle_stop;
static atomic_int g_workers_ready;
static double g_deadline;

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static void die_errno(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, strerror(errno));
    exit(2);
}

/* 收包侧的窗口记账：只在真正读到数据时更新，空转不会把首包时刻提前。 */
static void recv_stamp(struct result *r, unsigned long long bytes)
{
    long long t = now_ms();
    unsigned long long prev;

    if (atomic_load_explicit(&r->first_ms, memory_order_relaxed) == 0)
        atomic_store_explicit(&r->first_ms, t, memory_order_relaxed);
    atomic_store_explicit(&r->last_ms, t, memory_order_relaxed);
    atomic_fetch_add_explicit(&r->bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&r->pkts, 1, memory_order_relaxed);
    /* 最大单包净荷（单调不减）：必须 load + CAS，直接 store 会让晚到的较小
     * 值把大值盖掉，看起来就像"没收到过大包"。 */
    prev = atomic_load_explicit(&r->max_payload, memory_order_relaxed);
    while (bytes > prev &&
           !atomic_compare_exchange_weak_explicit(&r->max_payload, &prev, bytes,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
        ;                               /* prev 已被刷成当前值，重比 */
}

static void fill_payload(unsigned char *buf, int size, unsigned long long seq)
{
    memset(buf, 0x5a, (size_t)size);
    memcpy(buf, MAGIC, MAGIC_LEN);
    /* 大端序号：将来排查乱序/重复时直接用 */
    for (int i = 0; i < 8; i++)
        buf[MAGIC_LEN + i] = (unsigned char)((seq >> (56 - 8 * i)) & 0xff);
}

/* 等 fd 可读/可写，最多 200ms。返回 false 就是超时或被打断，调用方回循环头
 * 重新看截止时间 —— 所有热循环都必须经过这里，绝不能出现"无限期阻塞在某次
 * 系统调用里"的路径（对端被 SIGKILL 时那种路径会让整个基准挂死）。 */
static bool wait_fd(int fd, short events)
{
    struct pollfd p = { .fd = fd, .events = events, .revents = 0 };

    return poll(&p, 1, 200) > 0;
}

static int raw_socket(int type)
{
    int fd = socket(AF_INET, type, RAW_PROTO);

    if (fd < 0 && (errno == EPERM || errno == EACCES))
        die("raw socket 需要 root 或 CAP_NET_RAW（IP 协议号 253）");
    if (fd < 0)
        die_errno("socket(SOCK_RAW)");
    return fd;
}

static void resolve(const char *ip, int port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &out->sin_addr) != 1) {
        fprintf(stderr, "error: 不是合法 IPv4 地址: %s\n", ip);
        exit(2);
    }
}

/*
 * 逐字节按网络序装配 16 位字来求和。
 *
 * 不要"优化"成把缓冲区当 uint16_t* 读：那与前面经 struct iphdr * 的写构成
 * 严格别名违规，-O2 下 gcc 会把读提到写之前。实测（selftest 抓到的）：算出来
 * 的校验和少算了 daddr，写进包里是 0xb1f1 而正确值是 0x9fde，每个包都会在
 * 对端被丢。逐字节读的类型是 unsigned char，可以和任何类型别名，编译器必须
 * 守住顺序。
 */
static uint32_t sum_net16(const void *p, int bytes)
{
    const unsigned char *b = (const unsigned char *)p;
    uint32_t sum = 0;

    for (int i = 0; i + 1 < bytes; i += 2)
        sum += ((uint32_t)b[i] << 8) | (uint32_t)b[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return sum;
}

/* 返回值转成主机序，直接赋给 iph->check；写进内存的字节就是网络序校验和 */
static uint16_t ip_checksum(const void *p, int bytes)
{
    return ntohs((uint16_t)~sum_net16(p, bytes));
}

/*
 * IP_HDRINCL 下内核**不会**替我们填源地址：头里写 0 的包在 lo 上会被当
 * martian 源丢掉，实测表现是"发送侧 7 Gbps、接收侧一个包都没有"。
 * 用一次 UDP connect 借内核做路由查找，再 getsockname 拿源地址 ——
 * connect 只查路由不发包，所以不需要对端存在。
 */
static struct in_addr resolve_src(const struct sockaddr_in *dst)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me;
    socklen_t sl = (socklen_t)sizeof me;

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    if (connect(fd, (const struct sockaddr *)dst, sizeof *dst) != 0) {
        close(fd);
        die_errno("raw 档查源地址失败（目标没有路由？）");
    }
    memset(&me, 0, sizeof me);
    if (getsockname(fd, (struct sockaddr *)&me, &sl) != 0) {
        close(fd);
        die_errno("getsockname");
    }
    close(fd);
    return me.sin_addr;
}

/* 拼一个裸 IPv4 包（20 字节头 + 负载）。src/id/校验和都显式填，不依赖内核。 */
static void build_raw_ipv4(unsigned char *buf, int size, unsigned long long seq,
                           struct in_addr src, struct in_addr dst)
{
    struct iphdr *ip = (struct iphdr *)buf;
    int payload = size - (int)sizeof *ip;

    fill_payload(buf + sizeof *ip, payload, seq);
    memset(ip, 0, sizeof *ip);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)size);
    ip->id = htons((uint16_t)(seq & 0xffff));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = RAW_PROTO;
    ip->check = 0;
    ip->saddr = src.s_addr;
    ip->daddr = dst.s_addr;
    ip->check = ip_checksum(buf, (int)sizeof *ip);
}

/* 记录/比较首个远端地址（多个读线程共用，用原子存网络序整数避免字符串竞争） */
static void note_remote(struct result *r, const struct sockaddr_in *peer)
{
    unsigned int a = peer->sin_addr.s_addr;
    unsigned int prev = atomic_load_explicit(&r->remote_first,
                                             memory_order_relaxed);

    if (prev == 0)
        atomic_store_explicit(&r->remote_first, a, memory_order_relaxed);
    else if (prev != a)
        atomic_fetch_add_explicit(&r->remote_chg, 1, memory_order_relaxed);
}


/* ---------------------------------------------------------------- 发送侧 */

static void *send_tcp(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    unsigned char *buf;
    unsigned long long seq = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        die_errno("socket(SOCK_STREAM)");
    if (connect(fd, (const struct sockaddr *)&w->dst, sizeof w->dst) != 0)
        die_errno("connect（对端没在监听？）");
    buf = malloc((size_t)c->size);
    if (buf == NULL)
        die("malloc 失败");

    atomic_fetch_add_explicit(&g_workers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&g_go, memory_order_acquire))
        usleep(200);                        /* 等主线程统一发令 */

    while (now_s() < g_deadline) {
        ssize_t n;

        fill_payload(buf, c->size, seq++);
        /* 阻塞式 send 在对端不读时会永远停在系统调用里（绕过截止时间），
         * 所以走"等可写 + MSG_DONTWAIT"；背压语义不变：缓冲满就等。 */
        if (!wait_fd(fd, POLLOUT))
            continue;
        n = send(fd, buf, (size_t)c->size, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0) {
            /* 连接已死：继续打没有意义，把错误留给汇总侧判断 */
            atomic_fetch_add_explicit(&w->r->errs, 1, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(&w->r->bytes, (unsigned long long)n,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&w->r->pkts, 1, memory_order_relaxed);
    }
    free(buf);
    close(fd);
    return NULL;
}

static void *send_dgram(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    bool raw = strcmp(c->proto, "raw") == 0;
    unsigned char *buf;
    int sndbuf = 8 << 20;
    int fd = raw ? raw_socket(SOCK_RAW) : socket(AF_INET, SOCK_DGRAM, 0);
    unsigned long long seq = 0;
    int payload;
    struct in_addr src = { 0 };

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    if (raw && setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 }, sizeof(int)) != 0)
        die_errno("setsockopt(IP_HDRINCL)");
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    buf = calloc(1, (size_t)c->size);
    if (buf == NULL)
        die("calloc 失败");
    payload = raw ? c->size - (int)sizeof(struct iphdr) : c->size;
    if (raw)
        src = resolve_src(&w->dst);

    atomic_fetch_add_explicit(&g_workers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&g_go, memory_order_acquire))
        usleep(200);

    while (now_s() < g_deadline) {
        ssize_t n;

        if (raw) {
            build_raw_ipv4(buf, c->size, seq++, src, w->dst.sin_addr);
        } else {
            fill_payload(buf, c->size, seq++);
        }
        if (!wait_fd(fd, POLLOUT))
            continue;
        n = sendto(fd, buf, (size_t)c->size, MSG_DONTWAIT,
                   (const struct sockaddr *)&w->dst, sizeof w->dst);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;               /* 缓冲满：不是错误，是背压 */
            /* 无连接协议：单次失败（路由/ICMP 端口不可达）不该终止整轮 */
            unsigned long long e = atomic_fetch_add_explicit(
                &w->r->errs, 1, memory_order_relaxed) + 1;

            if (e > 10000)
                break;                  /* 一直失败就别热转了 */
            usleep(1000);
            continue;
        }
        atomic_fetch_add_explicit(&w->r->bytes, (unsigned long long)payload,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&w->r->pkts, 1, memory_order_relaxed);
    }
    free(buf);
    close(fd);
    return NULL;
}

/* ---------------------------------------------------------------- 接收侧 */

/*
 * 裸 IP 的收包缓冲区**含 20 字节 IP 头**（raw socket 一贯如此），魔术前缀在
 * 它后面。不跳过这段的话每个包都会被记成坏包、字节数恒为 0，症状和"根本没
 * 通"一模一样。非 root 跑不了 raw，所以这条只能靠读代码 + selftest 拦住。
 */
static bool payload_ok(const unsigned char *buf, ssize_t n, bool raw)
{
    if (raw) {
        const struct iphdr *ip = (const struct iphdr *)(const void *)buf;

        if (n < (ssize_t)(sizeof *ip + MAGIC_LEN))
            return false;
        if (ip->version != 4 || ip->protocol != RAW_PROTO)
            return false;
        buf += sizeof *ip;
        n -= (ssize_t)sizeof *ip;
    }
    return n >= MAGIC_LEN && memcmp(buf, MAGIC, MAGIC_LEN) == 0;
}

/*
 * 数据报接收的读线程：多个线程共用同一个 fd（内核按包唤醒其中一个，
 * 每个包只会被读走一次）。所以 recv 拿到 EAGAIN 是**正常竞争**，必须继续，
 * 不能当成错误退出 —— 否则 K 个读线程会在第一个包上互相把对方踢掉。
 */
static void *dgram_reader(void *arg)
{
    struct worker *w = arg;
    /* 每读线程一份，按协议上限开（大 MTU 下 --size 可以给到 65471+） */
    unsigned char *buf = malloc(DGRAM_BUF);
    /* 裸 IP 报的是**负载**字节数（与 udp/tcp 一致），所以要减掉 IP 头 */
    const ssize_t off =
        (strcmp(w->c->proto, "raw") == 0) ? (ssize_t)sizeof(struct iphdr) : 0;

    if (buf == NULL)
        die("malloc 失败");
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed) &&
           now_s() < g_deadline) {
        struct pollfd p = { .fd = w->fd, .events = POLLIN, .revents = 0 };
        ssize_t n;

        /* 必须带超时地等：直接阻塞在 recv 上时，空闲判定置位的 g_stop
         * 要等到硬上限才生效，收场会白等 5 秒（看起来像假死）。 */
        if (poll(&p, 1, 200) <= 0)
            continue;
        /* MSG_DONTWAIT 是必需的，不是优化：K 个读线程共用同一个 fd 时，
         * poll 报可读后可能被别的线程先一步把包取走。fd 是阻塞的话，输掉
         * 这一手的线程会**永久**停在 recv 里（EAGAIN 分支根本没机会执行），
         * 收尾时的 pthread_join 就卡死了 —— 实测卡了 300 秒以上。
         * 带上 MSG_DONTWAIT，输家立刻拿到 EAGAIN 并回到循环头。 */
        {
            struct sockaddr_in peer;
            socklen_t pl = (socklen_t)sizeof peer;

            memset(&peer, 0, sizeof peer);
            n = recvfrom(w->fd, buf, DGRAM_BUF, MSG_DONTWAIT,
                         (struct sockaddr *)&peer, &pl);
            if (n >= 0 && pl == (socklen_t)sizeof peer)
                note_remote(w->r, &peer);
        }
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        if (!payload_ok(buf, n, off != 0)) {
            atomic_fetch_add_explicit(&w->r->bad, 1, memory_order_relaxed);
            continue;
        }
        recv_stamp(w->r, (unsigned long long)(n - off));
    }
    free(buf);
    return NULL;
}

static void *recv_dgram(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    struct sockaddr_in me;
    pthread_t th[MAX_THREADS];
    struct worker ws[MAX_THREADS];
    bool raw = strcmp(c->proto, "raw") == 0;
    int rcvbuf = 16 << 20, got = -1, n;
    socklen_t sl = (socklen_t)sizeof got;
    int fd = raw ? raw_socket(SOCK_RAW) : socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        die_errno("socket(SOCK_DGRAM)");
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    /* raw 档**不要**绑端口：raw socket 的 bind 端口会变成收包过滤条件
     * （比对包里的前 4 个字节），而裸 IP 没有端口概念 ⇒ 一个包都收不到。
     * 非 root 跑不了 raw，所以这个坑只能在真机上踩到，必须写清楚。 */
    resolve(c->ip, raw ? 0 : c->port, &me);
    if (bind(fd, (const struct sockaddr *)&me, sizeof me) != 0)
        die_errno("bind（端口被占？）");
    (void)getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &sl);
    printf("READY proto=%s role=recv addr=%s:%d rcvbuf=%d threads=%d\n", c->proto,
           c->ip, raw ? 0 : c->port, got, c->threads);
    fflush(stdout);

    /* 多读线程不是奢侈：单线程 recv 的天花板约 1.1 Mpps，在 lo 上打 1200 字节
     * 就会先于链路饱和（实测单线程 3.58 Gbps 无损，4 线程发送时接收侧掉 29%
     * —— 那是"接收侧收不过来"，不是链路丢包，会被误读）。 */
    n = c->threads < 1 ? 1 : c->threads;
    for (int i = 0; i < n; i++) {
        ws[i].c = c;
        ws[i].r = w->r;
        ws[i].fd = fd;
        if (pthread_create(&th[i], NULL, dgram_reader, &ws[i]) != 0)
            die("pthread_create 失败");
    }
    for (int i = 0; i < n; i++)
        pthread_join(th[i], NULL);
    close(fd);
    return NULL;
}

static void *recv_one_tcp(void *arg)
{
    struct worker *w = arg;
    unsigned char *buf = malloc(1 << 20);

    if (buf == NULL)
        die("malloc 失败");
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct pollfd p = { .fd = w->fd, .events = POLLIN, .revents = 0 };
        ssize_t n;

        /* 同 recv_dgram：带超时地等，g_stop 一到就散 */
        if (poll(&p, 1, 200) <= 0)
            continue;
        /* 同样带 MSG_DONTWAIT：连接被对端 RST、或对端被 SIGKILL 后不再发数据
         * 时，阻塞的 recv 会越过 g_stop 永远停住，收尾的 join 就挂死。 */
        n = recv(w->fd, buf, 1 << 20, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        if (n == 0)
            break;                      /* 对端正常关闭 */
        recv_stamp(w->r, (unsigned long long)n);
    }
    free(buf);
    close(w->fd);
    return NULL;
}

static void *recv_tcp(void *arg)
{
    struct worker *w = arg;
    const struct cfg *c = w->c;
    struct sockaddr_in me;
    pthread_t th[MAX_THREADS];
    struct worker ws[MAX_THREADS];
    int rcvbuf = 16 << 20, got = -1, n = 0;
    socklen_t sl = (socklen_t)sizeof got;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    if (lfd < 0)
        die_errno("socket(SOCK_STREAM)");
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    (void)setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    resolve(c->ip, c->port, &me);
    if (bind(lfd, (const struct sockaddr *)&me, sizeof me) != 0)
        die_errno("bind（端口被占？）");
    if (listen(lfd, 64) != 0)
        die_errno("listen");
    /* accept 也必须有界：poll 报可读后若那条排队连接被对端 RST 掉，阻塞的
     * accept 会等下一个连接，g_stop 与截止时间都拦不住它。 */
    {
        int fl = fcntl(lfd, F_GETFL, 0);

        if (fl < 0 || fcntl(lfd, F_SETFL, fl | O_NONBLOCK) < 0)
            die_errno("fcntl(O_NONBLOCK)");
    }
    (void)getsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &got, &sl);
    printf("READY proto=%s role=recv addr=%s:%d rcvbuf=%d\n", c->proto, c->ip,
           c->port, got);
    fflush(stdout);

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed) &&
           now_s() < g_deadline) {
        struct pollfd p = { .fd = lfd, .events = POLLIN, .revents = 0 };
        int fd;

        /* 监听 fd 上也必须带超时：阻塞在 accept 上时 g_stop 叫不醒它 */
        if (poll(&p, 1, 200) <= 0)
            continue;
        fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        {
            struct sockaddr_in peer;
            socklen_t pl = (socklen_t)sizeof peer;

            if (getpeername(fd, (struct sockaddr *)&peer, &pl) == 0)
                note_remote(w->r, &peer);
        }
        if (n < c->threads && n < MAX_THREADS) {
            ws[n].c = c;
            ws[n].r = w->r;
            ws[n].fd = fd;
            if (pthread_create(&th[n], NULL, recv_one_tcp, &ws[n]) != 0)
                die("pthread_create 失败");
            n++;
            atomic_store_explicit(&w->r->conns, (unsigned long long)n,
                                  memory_order_relaxed);
        } else {
            close(fd);                  /* 只按约定连接数收，多出来的直接关 */
        }
    }
    close(lfd);
    for (int k = 0; k < n; k++)
        pthread_join(th[k], NULL);
    return NULL;
}

/* ---------------------------------------------------------------- 主流程 */

static int parse_int(const char *s, const char *what)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (end == NULL || *end != '\0' || v <= 0 || v > (1 << 30)) {
        fprintf(stderr, "error: %s 取值非法: %s\n", what, s);
        exit(2);
    }
    return (int)v;
}

static void usage(void)
{
    fprintf(stderr,
            "用法:\n"
            "  bench_proto send --proto tcp|udp|raw --target A.B.C.D --port P\n"
            "                    [--size N] [--duration S] [--threads K]\n"
            "  bench_proto recv --proto tcp|udp|raw --bind A.B.C.D --port P\n"
            "                    [--duration S] [--threads K] [--idle-ms M]\n"
            "  --size: udp = UDP 净荷（<= 65507，默认 1200）\n"
            "          raw = 整包长度，含 20B IP 头（<= 65535，默认 1200）\n"
            "          tcp = 每次写的块（默认 65536）\n");
    exit(2);
}
/* 自检：raw socket 要 CAP_NET_RAW，非 root 跑不了端到端，但"头拼错"是必然
 * 静默失败的一类缺陷，至少把它挡在发车之前。不需要任何权限。 */
static int selftest(void)
{
    unsigned char buf[2048];
    struct iphdr *ip = (struct iphdr *)buf;
    struct in_addr src = { 0 }, dst = { 0 };
    const int size = 1220;
    uint32_t sum = 0;
    int bad = 0;

    if (inet_pton(AF_INET, "10.1.2.3", &src) != 1 ||
        inet_pton(AF_INET, "10.9.9.9", &dst) != 1)
        die("selftest: inet_pton 失败");
    memset(buf, 0, sizeof buf);
    build_raw_ipv4(buf, size, 0x1122334455667788ULL, src, dst);

#define CHK(cond, desc)                                                        \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  ok   %s\n", desc);                                       \
        } else {                                                               \
            printf("  FAIL %s\n", desc);                                       \
            bad++;                                                             \
        }                                                                      \
    } while (0)

    CHK(ip->version == 4 && ip->ihl == 5, "版本/IHL = 4/5");
    CHK((int)ntohs(ip->tot_len) == size, "tot_len = 整包长度");
    CHK(ip->protocol == RAW_PROTO, "协议号 = 253");
    CHK(ip->saddr == src.s_addr, "源地址显式填（0 在 lo 上会被当 martian 丢）");
    CHK(ip->daddr == dst.s_addr, "目的地址正确");
    CHK(ip->id != 0, "id 非 0（不指望内核代填）");
    CHK(memcmp(buf + sizeof *ip, MAGIC, MAGIC_LEN) == 0, "负载魔术前缀正确");
    CHK(payload_ok(buf, size, true), "payload_ok 认得带 IP 头的裸包");
    CHK(!payload_ok(buf, size, false), "payload_ok 不跳过 IP 头时应当拒绝（偏移必须对）");
    {
        unsigned char wrong[2048];   /* 不能叫 bad：会遮蔽上面的计数器 */

        memcpy(wrong, buf, (size_t)size);
        ((struct iphdr *)(void *)wrong)->protocol = 6;
        CHK(!payload_ok(wrong, size, true), "协议号不对的包被拒");
    }
    sum = sum_net16(buf, (int)sizeof *ip);
    CHK(sum == 0xffffU, "IP 头校验和自校验（网络序 16 位和 = 0xffff）");
    if (sum != 0xffffU) {
        printf("       诊断：头 20 字节 =");
        for (int i = 0; i < (int)sizeof *ip; i++)
            printf(" %02x", buf[i]);
        printf("\n       网络序折叠和 = %04x（应为 ffff），check 字段字节 = %02x %02x\n",
               sum, buf[10], buf[11]);
    }
    /*
     * 大包（--size 上限）也自检一遍：raw 非 root 跑不了端到端，而"长度字段
     * 只有 16 位""负载没铺到末字节""收包缓冲区装不下"这三类缺陷只在大包上
     * 暴露，且都是静默失败。用堆：65535 放不进 buf[]。
     */
    {
        const int jsize = MAX_RAW_SIZE;         /* 整包上限 65535 */
        unsigned char *j = malloc((size_t)jsize);

        if (j == NULL)
            die("selftest: malloc 失败");
        build_raw_ipv4(j, jsize, 0xdeadbeefcafef00dULL, src, dst);
        CHK(((struct iphdr *)(void *)j)->tot_len == htons((uint16_t)jsize),
            "大包 tot_len = 整包长度（16 位字段正好封顶）");
        CHK(sum_net16(j, (int)sizeof(struct iphdr)) == 0xffffU,
            "大包 IP 头校验和自校验");
        CHK(payload_ok(j, jsize, true), "大包认得（含 IP 头）");
        CHK(j[jsize - 1] == 0x5a, "大包负载铺满到末字节（长度没算少）");
        CHK(memcmp(j + sizeof(struct iphdr) + MAGIC_LEN,
                   "\xde\xad\xbe\xef\xca\xfe\xf0\x0d", 8) == 0,
            "大包序号按大端写在魔术之后");
        CHK(jsize <= DGRAM_BUF, "收包缓冲区装得下上限整包");
        free(j);
    }
#undef CHK
    printf("selftest: %s（%d 项失败）\n", bad == 0 ? "PASS" : "FAIL", bad);
    return bad == 0 ? 0 : 1;
}



int main(int argc, char **argv)
{
    struct cfg c = { .proto = NULL, .ip = NULL, .port = 0, .size = 0,
                     .duration = 5, .threads = 4, .idle_ms = 700 };
    struct result res;
    struct worker ws[MAX_THREADS];
    pthread_t th[MAX_THREADS];
    const char *role;
    bool is_recv;
    int nthreads = 1;

    memset(&res, 0, sizeof res);
    memset(ws, 0, sizeof ws);
    if (argc < 2)
        usage();
    role = argv[1];
    if (strcmp(role, "selftest") == 0)
        return selftest();
    if (strcmp(role, "send") != 0 && strcmp(role, "recv") != 0)
        usage();
    is_recv = strcmp(role, "recv") == 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];

        if (i + 1 >= argc)
            usage();
        i++;
        if (strcmp(a, "--proto") == 0)
            c.proto = argv[i];
        else if (strcmp(a, "--port") == 0)
            c.port = parse_int(argv[i], "--port");
        else if (strcmp(a, "--size") == 0)
            c.size = parse_int(argv[i], "--size");
        else if (strcmp(a, "--duration") == 0)
            c.duration = parse_int(argv[i], "--duration");
        else if (strcmp(a, "--threads") == 0)
            c.threads = parse_int(argv[i], "--threads");
        else if (strcmp(a, "--idle-ms") == 0)
            c.idle_ms = parse_int(argv[i], "--idle-ms");
        else if (strcmp(a, "--target") == 0 || strcmp(a, "--bind") == 0)
            c.ip = argv[i];
        else
            usage();
    }
    if (c.proto == NULL || c.ip == NULL || c.port == 0)
        usage();
    if (strcmp(c.proto, "tcp") != 0 && strcmp(c.proto, "udp") != 0 &&
        strcmp(c.proto, "raw") != 0) {
        fprintf(stderr, "error: --proto 只能是 tcp/udp/raw: %s\n", c.proto);
        return 2;
    }
    if (c.threads > MAX_THREADS)
        die("--threads 超过上限 64");
    if (c.size == 0)
        c.size = strcmp(c.proto, "tcp") == 0 ? (1 << 16) : 1200;
    if (strcmp(c.proto, "raw") == 0 &&
        (c.size < (int)sizeof(struct iphdr) + MAGIC_LEN + 8 ||
         c.size > MAX_RAW_SIZE))
        die("--size 对 raw 档是整包长度（含 20 字节 IP 头），上限 65535"
            "（即负载 16..65515）");
    if (strcmp(c.proto, "udp") == 0 &&
        (c.size < MAGIC_LEN + 8 || c.size > MAX_UDP_SIZE))
        die("--size 对 udp 档要给 UDP 净荷，上限 65507（16..65507，"
            "再加 28 字节 IP/UDP 头不超过 65535）");

    atomic_store(&g_go, false);
    atomic_store(&g_stop, false);
    atomic_store(&g_idle_stop, false);
    atomic_store(&g_workers_ready, 0);

    if (is_recv) {
        pthread_t mon;

        /* 硬上限 = 打流时长 + 5s：发送侧全挂时接收侧也必须收场 */
        g_deadline = now_s() + (double)c.duration + 5.0;
        /* 必须先填好 worker 再创建线程：线程一起来就会读 c/r */
        ws[0].c = &c;
        ws[0].r = &res;
        if (pthread_create(&mon, NULL,
                           strcmp(c.proto, "tcp") == 0 ? recv_tcp : recv_dgram,
                           &ws[0]) != 0)
            die("pthread_create 失败");
        for (;;) {
            long long last = atomic_load_explicit(&res.last_ms,
                                                  memory_order_relaxed);
            unsigned long long pkts = atomic_load_explicit(&res.pkts,
                                                           memory_order_relaxed);

            if (pkts > 0 && last > 0 && now_ms() - last > c.idle_ms) {
                atomic_store(&g_idle_stop, true);
                printf("IDLE_STOP proto=%s waited_ms=%d\n", c.proto, c.idle_ms);
                fflush(stdout);
                break;
            }
            if (now_s() >= g_deadline)
                break;
            usleep(50 * 1000);
        }
        atomic_store(&g_stop, true);
        pthread_join(mon, NULL);
    } else {
        void *(*fn)(void *) = strcmp(c.proto, "tcp") == 0 ? send_tcp
                                                          : send_dgram;
        struct sockaddr_in dst;
        double t_barrier;

        resolve(c.ip, c.port, &dst);
        nthreads = c.threads;
        for (int i = 0; i < nthreads; i++) {
            ws[i].c = &c;
            ws[i].r = &res;
            ws[i].dst = dst;
            if (pthread_create(&th[i], NULL, fn, &ws[i]) != 0)
                die("pthread_create 失败");
        }
        /* 起跑线：等所有线程就绪（tcp 档含连接建立，建链时间不算进窗口） */
        t_barrier = now_s() + 10.0;
        while (atomic_load_explicit(&g_workers_ready, memory_order_acquire) <
                   nthreads &&
               now_s() < t_barrier)
            usleep(1000);
        if (atomic_load(&g_workers_ready) < nthreads)
            die("工作线程 10s 内没就绪（tcp 档常见原因是对端没在监听）");
        g_deadline = now_s() + (double)c.duration;
        atomic_store(&g_go, true);
        for (int i = 0; i < nthreads; i++)
            pthread_join(th[i], NULL);
    }

    {
        unsigned long long bytes = atomic_load(&res.bytes);
        unsigned long long pkts = atomic_load(&res.pkts);

        if (is_recv) {
            long long f = atomic_load(&res.first_ms);
            long long l = atomic_load(&res.last_ms);
            double secs = (f > 0 && l >= f) ? (double)(l - f) / 1000.0 : 0.0;
            struct in_addr ra;
            char rb[INET_ADDRSTRLEN] = "-";

            ra.s_addr = atomic_load(&res.remote_first);
            if (ra.s_addr != 0)
                (void)inet_ntop(AF_INET, &ra, rb, sizeof rb);
            if (secs < 1e-3)
                secs = 1e-3;
            printf("RESULT proto=%s role=recv bytes=%llu pkts=%llu secs=%.3f "
                   "gbps=%.3f pps=%.0f bad=%llu conns=%llu idle=%d remote=%s "
                   "chg=%llu maxsize=%llu\n",
                   c.proto, bytes, pkts, secs,
                   (double)bytes * 8.0 / secs / 1e9, (double)pkts / secs,
                   atomic_load(&res.bad), atomic_load(&res.conns),
                   atomic_load(&g_idle_stop) ? 1 : 0, rb,
                   atomic_load(&res.remote_chg),
                   atomic_load(&res.max_payload));
        } else {
            double secs = (double)c.duration;
            /* 行尾的 size 是每包负载：raw 的 --size 是整包，这里要减掉 IP 头，
             * 否则日志上的口径和 recv 的 maxsize 对不上。 */
            int payload = strcmp(c.proto, "raw") == 0
                              ? c.size - (int)sizeof(struct iphdr) : c.size;

            printf("RESULT proto=%s role=send bytes=%llu pkts=%llu secs=%.3f "
                   "gbps=%.3f pps=%.0f errs=%llu threads=%d size=%d\n",
                   c.proto, bytes, pkts, secs,
                   (double)bytes * 8.0 / secs / 1e9, (double)pkts / secs,
                   atomic_load(&res.errs), nthreads, payload);
        }
    }
    return 0;
}
