#ifndef IWAN_SERVER_H
#define IWAN_SERVER_H

#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/socket.h>

#define SERVER_MAX_SESSIONS 256
#define SERVER_MAX_USERS    256
#define SERVER_USER_MAX     63
/* max uplink recv threads (SO_REUSEPORT fan-out); the session table's
 * rwlock and the rate-table mutex are the shared state */
#define IWAN_SRV_THREADS_MAX 16

/* 外层对端的族无关表示。外层 v4+v6 双栈后 sockaddr_in 不再够用：会话表、
 * 快照、handle_udp 入参、限速键全部改用本结构。接收路径一进来就规范化
 * （唯一入口 iwan_peer_from_sockaddr，v4-mapped 的 AF_INET6 在那里归一到
 * AF_INET），此后服务端只认这一种表示。
 *
 * 所有字段都由构造函数确定性填充（未用的地址字节为 0，scope_id 默认 0），
 * 但比较一律走 iwan_peer_eq()/iwan_peer_eq_addr()，绝不对整个结构体做
 * memcmp —— 那会算进结构体填充字节，同源判定会随机为假（每帧走 rebind 写
 * 锁路径、OPEN 侧误判 "session active elsewhere"）。 */
struct iwan_peer {
    uint8_t addr[16];   /* 网络序；AF_INET 只用 addr[0..3]，其余为 0 */
    uint16_t port;      /* 主机序 */
    uint32_t scope_id;  /* 仅 AF_INET6（fe80:: 链路本地需要），否则 0 */
    sa_family_t family; /* AF_INET / AF_INET6 */
};

/* iwan_peer_to_string 的最长输出加余量：v6 文面 45 + "%scope" 11 + "[]" 2
 * + ":port" 6 + NUL = 65，取 80。原来 v4 专用的 INET_ADDRSTRLEN + 8 缓冲
 * 装不下 v6，所有 peerstr 缓冲一律用这个尺寸。 */
#define IWAN_PEER_STRLEN 80

/* sockaddr -> peer（接收侧唯一的规范化点）。族不支持、或 len 小于该族的
 * sockaddr 长度（内核截断）时返回 false，调用方丢弃该报文。 */
bool iwan_peer_from_sockaddr(struct iwan_peer *p, const struct sockaddr *sa,
                             socklen_t len);
/* peer -> sockaddr_storage；返回可传给 sendto/sendmsg 的长度
 * （AF_INET 16 / AF_INET6 28），族非法时返回 0。 */
socklen_t iwan_peer_to_sockaddr(const struct iwan_peer *p,
                                struct sockaddr_storage *ss);
/* 族 + 地址 + scope，忽略端口：会话顶替判定用（旧代码只比 4 字节 v4 地址，
 * 端口变化不算换了源，这里保持同一口径）。 */
bool iwan_peer_eq_addr(const struct iwan_peer *a, const struct iwan_peer *b);
/* 族 + 地址 + scope + 端口：会话绑定判定用（等价于旧代码的
 * memcmp(&s->peer, peer, sizeof(sockaddr_in))）。 */
bool iwan_peer_eq(const struct iwan_peer *a, const struct iwan_peer *b);
/* v4 输出 "%s:%u"（与旧日志逐字节相同）；v6 输出 "[%s]:%u"，scope_id 非 0
 * 时输出 "[%s%%%u]:%u"（链路本地）。out 至少 IWAN_PEER_STRLEN 字节。 */
void iwan_peer_to_string(const struct iwan_peer *p, char *out, size_t outlen);

/* One authenticated client. Sessions are shared between the UDP main
 * thread (writes) and TUN reader threads (downlink lookups); every
 * mutation happens under ctx->sess_lock, readers take a snapshot under
 * the read lock. last_active_ms is atomic and updated lock-free. */
struct server_session {
    bool valid;
    uint16_t sid;
    uint32_t token;
    struct iwan_peer peer;   /* 外层源（v4 或 v6；见 iwan_peer） */
    uint8_t ip[4];
    uint8_t xor_key[8];      /* session_key(user,pass)[0..7] */
    uint8_t enc;
    atomic_uint_fast64_t last_active_ms; /* monotonic ms */
    /* R37 R1-D-1: per-session DATA/CLOSE token-guess budget. Two counters
     * because "who is guessing" changes what a guess costs:
     *   tok_mis_cnt   - wrong-token frames from a source that is NOT the
     *                   session's current peer (the generic brute-force
     *                   path, and the same-NAT stale-device path);
     *   tok_mis_bound - wrong-token frames that claim the session's
     *                   current peer address verbatim. CHARGED BUT NEVER
     *                   GATED (R37 R2): a third party can spend this
     *                   counter by forging the peer's ip:port, so using it
     *                   as a pre-compare budget would blackhole the real
     *                   peer's own (correct-token) data. It saturates at
     *                   RATE_TOKEN_MISMATCH_BOUND_MAX for observability
     *                   (a bound-address mismatch storm is the signature
     *                   of source spoofing); only tok_mis_cnt gates.
     * Both are windowed by tok_mis_win and mutated only under
     * ctx->sess_lock's WRITE lock; the pre-check reads tok_mis_cnt under
     * the READ lock. Budgets and rationale live in server.c
     * (RATE_TOKEN_MISMATCH_*). */
    uint32_t tok_mis_cnt, tok_mis_bound;
    uint64_t tok_mis_win;   /* window start (monotonic ms); 0 = none yet */
    /* R47-H2-M1: congestion-reactive per-session uplink throttle. Set to
     * now + g_up_throttle_ms (server.c) when THIS session's own TUN write
     * just failed on a full device queue; while in the future, the DATA
     * path drops the session's frames immediately (counted) so a flooding
     * client yields the shared TUN queue to other sessions. Only ever set
     * by the queue-full drop path, so uncongested sessions see 0 and no
     * normal throughput is capped. Atomic + relaxed like last_active_ms;
     * updated only under ctx->sess_lock (write for sess_wipe's memset,
     * read for the drop-path store) — see server.c. */
    atomic_uint_fast64_t throttle_until_ms;
    char user[SERVER_USER_MAX + 1]; /* owning account; one slot per user */
    /* IWAN_SRV_SINK=1（仅计量模式）：本会话的报文数与“外层 UDP 净荷字节
     * 数”计数（口径见 server.c sink_account）。只在 server.c 的 DATA
     * 分支里 relaxed 原子加，其他模式下恒为 0；handle_open 对新会话的
     * memset(s, 0) 会归零，所以不跨会话累计。 */
    _Atomic uint64_t sink_pkts, sink_bytes;
};

/* Snapshot of a session taken under the read lock; the only fields a
 * downlink thread needs to build and send a packet without holding the
 * lock during sendto(). */
struct server_sess_snap {
    struct iwan_peer peer;   /* 外层目的（v4 或 v6） */
    uint8_t xor_key[8];
    uint16_t sid;
    uint32_t token;
    uint8_t enc;
};

/* Global server state, owned by main(). */
struct server_ctx {
    struct server_session sess[SERVER_MAX_SESSIONS];
    pthread_rwlock_t sess_lock;  /* guards sess[] (see above) */
    /* O(1) sid -> slot index (M-8); -1 = no live session with that sid.
     * A session's sid is unique: sid = low 16 bits of its assigned IP
     * (see handle_open), so the map is exact.  All writes happen under
     * the WRITE lock (handle_open/sess_wipe); readers take a snapshot
     * under the read lock and never mutate the map (a heal write would
     * race concurrent readers). The sess[] scan stays authoritative as a
     * read-side fallback. */
    int16_t sid_map[65536];
    uint8_t server_ip[4], dns[4];
    uint32_t next_ip;        /* BE u32; next client IP to hand out */
    uint32_t ip_base;        /* BE u32; first usable host address */
    uint32_t ip_end;         /* BE u32; last usable host address (pre-broadcast) */
    /* R12 T1: the tunnel's OWN address space as configured by the
     * operator (`-S/--subnet` network+mask, `-s/--server-ip` above).
     * The uplink H1 gate rejects host-local destinations (server.c
     * up_inner_dst_blocked4) so an authenticated client cannot use the
     * server as a springboard to the server host's own loopback /
     * link-local addresses (R38 P1-4).  That reject set is a property of
     * the HOST, not of the tunnel, and it unconditionally contains
     * ranges an operator may legitimately have chosen for the tunnel
     * itself: with `-s 169.254.0.1 -S 169.254.0.0/16` every uplink
     * packet addressed to the gateway was silently dropped as
     * "host-local".  The gate therefore exempts the gateway and anything
     * inside `--subnet` — those are addresses this server hands out and
     * routes, not springboards.  subnet_set == false (the
     * zero-initialized default) means "no subnet known" and keeps the
     * pre-R12 strict behavior (full reject set). */
    uint32_t subnet_base;    /* BE u32; --subnet network address */
    uint32_t subnet_mask;    /* BE u32; --subnet netmask (length 8..30) */
    bool subnet_set;         /* false => full reject set (strict) */
    int tun_fd;              /* -1 when running in --no-tun mode */
    /* 外层 v6 下行兜底 socket：main 在建好第二套 AF_INET6 套接字后写入，
     * -1 表示宿主没有 IPv6（这套套接字整体不存在）。下行目的 peer 是 v6
     * 时 handle_tun_downlink 必须用它 —— 调用方传入的 fd 可能是报文到达
     * 的 v4 套接字（--no-tun echo 模式下跨族的内层转发），族不匹配的
     * sendmsg 会 EAFNOSUPPORT/EINVAL 而丢掉整批。v4 下行保持调用方传入的
     * fd 不变，所以这里不存 v4 的那套。 */
    int dl_fd6;
    /* IWAN_SRV_SINK=1：仅计量接收端点 —— 不建 TUN，数据帧只计数（不解密、
     * 不解析内层、不写 TUN、不回发），控制面路径不变。main 在起线程前
     * 设置一次，之后只读；零初始化为 false，默认行为不变。 */
    bool sink;
    void *qpool;             /* struct tun_pool *, owned by main() */
};

/* One "user:pass" line from the users file. */
struct server_user {
    char name[SERVER_USER_MAX + 1];
    char pass[SERVER_USER_MAX + 1];
};

/* Initialize/destroy the session-table lock. */
void server_ctx_init(struct server_ctx *ctx);
void server_ctx_destroy(struct server_ctx *ctx);

/* Read IWAN_RATE_OPEN_MAX / IWAN_RATE_ECHO_MAX once at startup
 * (malformed values fall back to the defaults with a logged warning).
 * Call once from main before the packet loop starts. */
void server_rate_limits_init(void);

/* Multithread-safe printf (server log lines). */

/* Handle one UDP packet from peer (v4 或 v6 外层源，已在接收侧规范化；见
 * iwan_peer). May write decrypted data to the TUN (only when
 * ctx->tun_fd >= 0, else dropped). Called from the uplink recv threads
 * (tid selects the per-thread stats slot). sockfd is the socket the
 * datagram arrived on, i.e. the matching address family for peer. */
void handle_udp(struct server_ctx *ctx, const struct server_user *users, int nusers,
                const uint8_t *raw, size_t len,
                const struct iwan_peer *peer, int sockfd, unsigned tid);

/* Send one IP packet from the TUN to the session owning dst IP.
 * Thread-safe: called from TUN reader threads. Takes a session snapshot
 * under the read lock and sends without holding the lock. The payload
 * is XORed in place (the caller's scratch buffer), so ip_pkt must be
 * writable. */
void handle_tun_downlink(struct server_ctx *ctx, uint8_t *ip_pkt, size_t len,
                         int sockfd);
/* gate + session snapshot + outer header + in-place XOR; false when the
 * packet was dropped or consumed locally. Shared by the direct-send
 * path (handle_tun_downlink) and the TUN reader pool's per-queue
 * sendmmsg batching (iwan_server.c). */
bool tun_prep_downlink(struct server_ctx *ctx, uint8_t *ip_pkt, size_t len,
                       struct server_sess_snap *snap_out, uint8_t *hdr_out);
/* count n failed downlink sends (batch remainder; see server.c) */
void server_add_send_drops(unsigned long long n);

/* Drop sessions idle for more than 120s; log each. Main thread only. */
void purge_expired(struct server_ctx *ctx, uint64_t now_ms);

/* IWAN_SRV_SINK=1: 打印计量统计 —— 一行总计
 *   SINK pkts=<报文数> bytes=<外层 UDP 净荷字节数> pps=<区间报文率>
 *   gbps=<区间比特率>
 * 外加每个有计数会话一行。非 final 调用按 5s 间隔门控（多余调用直接
 * 返回）；final=true（退出前）无条件打印并以“距上次打印”为区间。
 * 区间 latch 是普通静态变量：只能由主 recv 线程的 1s 心跳和 main 在
 * join 完所有 recv 线程之后调用（同 server_up_stats_print 的约定）。 */
void server_sink_print(struct server_ctx *ctx, bool final);

/* [prof] server stage byte counters (IWAN_PROFILE=1); incremented by
 * recv threads / tun readers, printed by the primary recv thread. */
extern atomic_uint_fast64_t g_prof_srv_recv, g_prof_srv_tunw, g_prof_srv_tunr,
    g_prof_srv_dlsend;

/* Cumulative UDP send failures (nonblocking socket: EAGAIN drops). */
uint64_t server_send_drops(void);

/* Cumulative UDP datagrams sent to clients (includes control frames
 * such as OPEN_ACK/PING_RSP, not only tunnel data). */

/* IWAN_DEBUG=1: print per-step uplink timing averages once per second.
 * R38 P2-14: PRIMARY RECV THREAD ONLY. It writes the file-static
 * g_rate_drops_reported latch (server.c) that server_rate_drops_maybe_print()
 * also reads/writes; that latch is deliberately a plain uint64_t, not an
 * atomic, so the mutual exclusion is the single-thread invariant kept at
 * the call site (src/iwan_server.c, the tid==0 housekeeping tick), not the
 * type. Do not call from a secondary recv thread, a TUN reader, or main. */
void server_up_stats_print(void);
/* R37 R7 (R3-L37): report g_rate_drops growth once per second, in EVERY
 * build — Release (IWAN_DEBUG_STRIP=ON) compiles the debug tier out, so
 * without this the per-source rate-limit drop counter is unobservable in
 * a shipped binary. Silent while the counter does not move; at most one
 * stderr line per second. Call from the 1 Hz housekeeping tick.
 * R38 P2-14: PRIMARY RECV THREAD ONLY — same non-atomic latches as
 * server_up_stats_print() above (g_rate_drops_reported plus the function's
 * own static last_ms), same tid==0 call-site invariant in src/iwan_server.c.
 * Calling it concurrently would be a C11 data race on both latches. */
void server_rate_drops_maybe_print(void);
/* record the number of uplink recv threads (stats are per-thread) */
void server_up_stats_set_threads(int n);

#endif
