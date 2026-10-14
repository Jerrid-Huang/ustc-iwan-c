/*
 * iWAN 内核数据面监督器（Linux only）。设计见 kdp.h。
 *
 * 与 TUN 泵（proxy.c run_pump）的分工：
 *   相同：路由展开/劫持与回滚、进程级停止处理、10s keepalive 发送、
 *         IWAN_RX_STALE_MS 判死、三态返回码；
 *   不同：没有 TUN fd、没有读写线程；数据面完全在内核，用户态只
 *         1s 轮询 /dev/iwan 的 last_rx_ms + 1s 排空可选的 events 组。
 */

#if defined(__linux__)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>	/* kdp_bind_ok：从内核现读接口/地址状态 */
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../kernel/iwan_shm.h"
#include "common.h"
#include "genl_iwan.h"
#include "kdp.h"
#include "reply_route.h"
#include "protocol.h"
#include "proxy.h"
#include "route.h"
#include "util.h"

/* 共享内存轮询周期（决策：1s）与循环让步粒度（Ctrl-C 响应）。
 * 判死阈值/保活周期不在这里复制：用 proxy.c 导出的同一套访问器，避免
 * 两条数据面在 IWAN_RX_STALE_MS 语义上漂移。 */
#define KDP_POLL_MS  1000u
#define KDP_SLEEP_MS 100u

/* 模块固定用它（SESSION_UP 回执里的 DEVNAME 才是权威，这里只用于启动前
 * 的归属预检） */
#define KDP_DEV_DEFAULT "iwan0"

struct kdp {
    int         sockfd;
    genl_iwan  *genl;
    uint16_t    sid;
    uint32_t    tok;
    uint8_t     enc;
    const char *server;

    genl_iwan_session sess;
    char        dev[IFNAMSIZ];
    uint32_t    dev_mtu;

    const char *auth_tun_ip;
    uint16_t    auth_mtu;

    int             shm_fd;
    const uint8_t  *shm;
    size_t          shm_len;

    char    ogw[16];
    char    odev[16];
    char    ogw_metric[16];
    slist_t routes;
    slist_t routes6;
    bool    had_routes;

    /* 承载网卡绑定（由调用方填，见 kdp.h 的 kdp_bind）：会话建立时写进
     * sess.oif/sess.bind_ip，1s 节拍里每次重新判定有效性。 */
    kdp_bind bind;

    bool    session_up;
    bool    routes_up;
    bool    shm_ok;
    bool    events_ok;
    bool    session_lost;
    reply_route_state rr;      /* 回程路由（conntrack）状态 */
};

/* ------------------------------------------------------------ 小工具 */

static uint64_t ms_since(uint64_t now, uint64_t then)
{
    return now > then ? now - then : 0;
}

/* 进程级停止处理：与 run_pump 同一套（port_set_stop_handler + 共享的
 * g_stop/g_user_stop），所以重连循环的三态语义完全一致。 */
static void kdp_on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    g_user_stop = 1;
}

/* 与 run_pump 的 send_ctrl 同形（同一个 24B 签名控制帧、同一条会话套接字）。
 * 内核模式下套接字保持阻塞（只有 10s 一条的控制帧），不做 GSO 处理。 */
/* ---------------------------------------------------------- 绑定有效性
 *
 * 判据每次从内核现读（getifaddrs），不保存"上一次看到的地址/状态"：
 * 地址与链路状态的事实来源是内核，用户态缓存只会制造两份真相。
 *   · 绑 IP：该地址必须仍在某张本机接口上，且那张接口 UP 且有载波；
 *   · 绑网卡：该接口必须存在，且 UP 且有载波。
 * IFF_RUNNING 就是链路载波（IFF_LOWER_UP 的同一事实）：载波丢失时设备仍然
 * UP、内核侧外层查找也仍然成功，报文会被链路层丢弃且不回传错误 —— 这是
 * 数据面唯一没有信号的失效分支，只能在这里判。veth 的载波恒为 up，
 * 所以靶场测不到这一分支（需要真实网卡）。
 */
static bool ifa_flags_ok(const char *name, unsigned flags, char *why,
                         size_t whysz)
{
    if (!(flags & IFF_UP)) {
        snprintf(why, whysz, "承载网卡 %s 已 down（flags=0x%x）", name, flags);
        return false;
    }
    if (!(flags & IFF_RUNNING)) {
        snprintf(why, whysz, "承载网卡 %s 无载波（flags=0x%x）", name, flags);
        return false;
    }
    return true;
}

bool kdp_bind_ok(const kdp_bind *b, char *why, size_t whysz)
{
    struct ifaddrs *ifa0 = NULL;
    struct ifaddrs *ifa;
    bool seen_dev = false;
    bool ok = true;

    if (b == NULL || (b->oif == 0 && b->bind_ip == 0 && !b->bind_v6 &&
                      IN6_IS_ADDR_UNSPECIFIED(&b->bind_ip6)))
        return true;
    if (why != NULL && whysz != 0)
        why[0] = '\0';
    if (getifaddrs(&ifa0) != 0)
        return true;	/* 状态未知：不动作，正确性由内核侧兜底 */

    for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;
        if (b->bind_v6) {
            /* 外层 v6 的绑 IP：同一套判据，地址是 16 字节 */
            const struct sockaddr_in6 *sin6;
            char a6[INET6_ADDRSTRLEN];

            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_INET6)
                continue;
            sin6 = (const struct sockaddr_in6 *)(const void *)ifa->ifa_addr;
            if (!IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &b->bind_ip6))
                continue;
            if (b->oif != 0 && if_nametoindex(ifa->ifa_name) != b->oif) {
                if (why != NULL && whysz != 0)
                    snprintf(why, whysz,
                             "绑定的出口 IP %s 不在承载网卡 %s 上（它在 %s）",
                             inet_ntop(AF_INET6, &b->bind_ip6, a6,
                                       sizeof(a6)),
                             b->dev != NULL ? b->dev : "(ifindex)",
                             ifa->ifa_name);
                ok = false;
                seen_dev = true;
                break;
            }
            if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
                ok = false;
            seen_dev = true;
            break;
        }
        if (b->bind_ip != 0) {
            const struct sockaddr_in *sin;

            if (ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_INET)
                continue;
            sin = (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
            if (ntohl(sin->sin_addr.s_addr) != b->bind_ip)
                continue;
            /* 同时给了网卡时两者必须指向同一张接口（内核侧同样会 -EINVAL
             * 拒绝；这里早一步给出更具体的原因）。 */
            if (b->oif != 0 &&
                if_nametoindex(ifa->ifa_name) != b->oif) {
                if (why != NULL && whysz != 0) {
                    struct in_addr a;

                    a.s_addr = htonl(b->bind_ip);
                    snprintf(why, whysz,
                             "绑定的出口 IP %s 不在承载网卡 %s 上（它在 %s）",
                             inet_ntop(AF_INET, &a,
                                       (char[INET_ADDRSTRLEN]){0},
                                       INET_ADDRSTRLEN),
                             b->dev != NULL ? b->dev : "(ifindex)",
                             ifa->ifa_name);
                }
                ok = false;
                seen_dev = true;
                break;
            }
            if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
                ok = false;
            seen_dev = true;
            break;
        }
        if (b->dev != NULL ? strcmp(ifa->ifa_name, b->dev) != 0
                           : if_nametoindex(ifa->ifa_name) != b->oif)
            continue;
        if (!ifa_flags_ok(ifa->ifa_name, ifa->ifa_flags, why, whysz))
            ok = false;
        seen_dev = true;
        break;
    }
    freeifaddrs(ifa0);
    if (!seen_dev) {
        if (why != NULL && whysz != 0) {
            if (b->bind_v6) {
                char a6[INET6_ADDRSTRLEN];

                snprintf(why, whysz, "绑定的出口 IP %s 已不在本机地址表里",
                         inet_ntop(AF_INET6, &b->bind_ip6, a6, sizeof(a6)));
            } else if (b->bind_ip != 0) {
                struct in_addr a;

                a.s_addr = htonl(b->bind_ip);
                snprintf(why, whysz,
                         "绑定的出口 IP %s 已不在本机地址表里",
                         inet_ntop(AF_INET, &a, (char[INET_ADDRSTRLEN]){0},
                                   INET_ADDRSTRLEN));
            } else {
                snprintf(why, whysz, "绑定的承载网卡 %s 已不存在",
                         b->dev != NULL ? b->dev : "(ifindex)");
            }
        }
        return false;
    }
    return ok;
}

void kdp_bind_wait(const kdp_bind *b)
{
    char why[256];

    for (;;) {
        if (kdp_bind_ok(b, why, sizeof(why)))
            return;
        log_err("内核数据面: 绑定尚不可用（%s），等待恢复后再握手", why);
        port_sleep_ms(1000);
        if (g_user_stop)
            return;
    }
}

static int kdp_send_ctrl(const struct kdp *k, uint8_t typ)
{
    buf_t pkt;
    size_t want;
    ssize_t r;

    buf_init(&pkt);
    ctrl_hdr(&pkt, typ, k->enc, k->sid, k->tok);
    want = pkt.len;
    r = port_send(k->sockfd, pkt.data, want, 0);
    buf_free(&pkt);
    return (r < 0 || (size_t)r != want) ? -1 : 0;
}

/* ------------------------------------------------------------ /dev/iwan */

static void kdp_shm_close(struct kdp *k)
{
    if (k->shm != NULL) {
        munmap((void *)(uintptr_t)k->shm, k->shm_len);
        k->shm = NULL;
    }
    if (k->shm_fd >= 0) {
        close(k->shm_fd);
        k->shm_fd = -1;
    }
    k->shm_ok = false;
}

/* 打开并只读映射本 netns 的共享内存页。/dev/iwan 不存在时**明确报错**，
 * 不静默降级成 TUN（决策 6）。必须在 SESSION_UP 之前调用：一旦建立会话，
 * 钩子就开始吞包，那时才发现监控不可用就晚了。 */
static bool kdp_shm_open(struct kdp *k, char *err, size_t errsz)
{
    void *p;
    long pg;
    uint32_t ver = 0;

    k->shm_fd = open("/dev/iwan", O_RDONLY | O_CLOEXEC);
    if (k->shm_fd < 0) {
        if (errno == ENOENT)
            snprintf(err, errsz,
                     "内核数据面需要 /dev/iwan（共享内存页），但该设备不存在。\n"
                     "  请加载与本客户端同批构建的内核模块"
                     "（sudo insmod kernel/iwan.ko），\n"
                     "  或改用 --data-plane tun");
        else if (errno == EACCES || errno == EPERM)
            snprintf(err, errsz,
                     "打开 /dev/iwan 被拒: %s（需要该设备的读权限）",
                     strerror(errno));
        else
            snprintf(err, errsz, "打开 /dev/iwan 失败: %s", strerror(errno));
        return false;
    }
    pg = sysconf(_SC_PAGESIZE);
    k->shm_len = pg > 0 ? (size_t)pg : 4096u;
    p = mmap(NULL, k->shm_len, PROT_READ, MAP_SHARED, k->shm_fd, 0);
    if (p == MAP_FAILED) {
        snprintf(err, errsz, "mmap(/dev/iwan) 失败: %s", strerror(errno));
        close(k->shm_fd);
        k->shm_fd = -1;
        return false;
    }
    k->shm = (const uint8_t *)p;
    memcpy(&ver, k->shm + IWAN_SHM_OFF_VERSION, sizeof(ver));
    if (ver != (uint32_t)IWAN_SHM_VERSION) {
        snprintf(err, errsz,
                 "/dev/iwan 共享内存布局版本 %u 与本客户端期望的 %u 不一致："
                 "内核模块与客户端不是同批构建",
                 ver, (unsigned)IWAN_SHM_VERSION);
        kdp_shm_close(k);
        return false;
    }
    k->shm_ok = true;
    return true;
}

/* 最近一次通过凭据闸门的帧的单调毫秒；0 = 从未收到 / 已断开。
 * 与 now_ms() 同一时基（ktime_get_mono_fast_ns 折算），对齐的 64 位读用
 * 原子内建，避免 32 位平台上读到撕裂值。 */
static uint64_t kdp_shm_last_rx(const struct kdp *k)
{
    if (!k->shm_ok || k->shm == NULL)
        return 0;
    return __atomic_load_n(
        (const uint64_t *)(const void *)(k->shm + IWAN_SHM_OFF_LAST_RX_MS),
        __ATOMIC_RELAXED);
}

/* ------------------------------------------- 启动前预检（握手之前） */

static bool kdp_precheck_device(char *err, size_t errsz);

/* 共享内存页说"这条会话最近还有人在用"吗。
 *
 * 判据只有三个字段：enabled=1（会话级数据面开关）、last_rx_ms 非 0、且距今
 * 小于 2×keepalive（10s → 20s）。读时间戳分不清"刚建立、还没收到任何帧"与
 * "崩溃残留且从未收帧"，所以只在"最近确实收到过帧"时判活；更旧的会话按残留
 * 处理，仍交给 SESSION_UP 的冲突检查兜底 —— 预检绝不能把残留会话挡死，否则
 * 一次 SIGKILL 之后客户端再也起不来（E2 用例覆盖的场景）。
 *
 * age_ms（可为 NULL）收到"最后收帧距今多少毫秒"，0 表示从未收到。 */
static bool kdp_session_is_live(const struct kdp *k, uint64_t *age_ms)
{
    uint32_t enabled = 0;
    uint64_t last_rx;
    uint64_t now;
    uint64_t age;

    if (age_ms != NULL)
        *age_ms = 0;
    if (!k->shm_ok || k->shm == NULL)
        return false;
    memcpy(&enabled, k->shm + IWAN_SHM_OFF_ENABLED, sizeof(enabled));
    last_rx = kdp_shm_last_rx(k);
    now = now_ms();
    age = (last_rx != 0 && now > last_rx) ? now - last_rx : 0;
    if (age_ms != NULL)
        *age_ms = age;
    return enabled != 0 && last_rx != 0 && now > last_rx &&
           age < (uint64_t)pump_keepalive_ms() * 2u;
}

/* 预检主体：共享内存页已映射好（k->shm_ok）之后的两件事 —— 本 netns 是否
 * 已有活会话、iwan0 归属。kdp_run 与 kdp_plane_precheck 共用同一份判据与
 * 报错文本，两条路径不会漂移。 */
static bool kdp_precheck_core(const struct kdp *k, char *err, size_t errsz,
                              bool *busy)
{
    uint64_t age = 0;

    if (busy != NULL)
        *busy = false;
    if (kdp_session_is_live(k, &age)) {
        snprintf(err, errsz,
                 "本 netns 已有一条活会话：%llu ms 前还收到过对端帧"
                 "（enabled=1，判活窗口 %u ms）。\n"
                 "  内核模块 iwan 的会话是**按 netns 单例**的："
                 "一条 netns 只能有一条内核会话。\n"
                 "  请先停掉那个客户端（Ctrl-C），或换一个 netns 运行；"
                 "确认是崩溃残留时用 sudo iwan_ctl session-down 清掉再试。",
                 (unsigned long long)age, pump_keepalive_ms() * 2u);
        if (busy != NULL)
            *busy = true;
        return false;
    }
    return kdp_precheck_device(err, errsz);
}

bool kdp_plane_precheck(char *err, size_t errsz, bool *busy)
{
    struct kdp k;
    bool ok;

    if (busy != NULL)
        *busy = false;
    memset(&k, 0, sizeof k);
    k.shm_fd = -1;
    /* /dev/iwan 缺失 / 权限 / 布局版本不符的报错由 kdp_shm_open 给出，与
     * kdp_run 内部那条一字不差。这里只借它做一次临时映射，读完立刻关。 */
    if (!kdp_shm_open(&k, err, errsz))
        return false;
    ok = kdp_precheck_core(&k, err, errsz, busy);
    kdp_shm_close(&k);
    return ok;
}

/* 模块的 SESSION_UP 冲突报错来自 kernel/iwan_netlink.c 的 extack
 * （"SESSION_UP 与已有会话冲突（<字段> 不同）"，e2e 里断言过）。用它把
 * "已有会话"这一类失败与"参数不合法/设备被占"区分开：前者不能回退到 TUN
 * （回退会拿同一账号把那条会话顶掉），后者可以。措辞变了也不会变危险 ——
 * 认不出来时按"不 busy"处理，回退到 TUN 会在 iwan0 被模块占着时失败退出。 */
static bool kdp_err_is_conflict(const char *err)
{
    return err != NULL && strstr(err, "冲突") != NULL;
}

/* --------------------------------------------------- 设备归属预检 */

/* `ip -d link show dev iwan0` 的 detail 行给出 kind（TUN 设备是
 * "tun type tun ..."，模块建的卡是 "iwan"）。ARPHRD 都是 65534，名字/
 * 类型无法区分，只能看这一行。
 *
 * 三种结果：
 *   设备不存在        -> 放行（SESSION_UP 按需创建）
 *   kind == "iwan"    -> 放行
 *   kind 是别的      -> 硬报错（本机 iwan0 被真实隧道当 TUN 占用的情形）
 *   iproute2 没给 kind -> 放行 + debug 提示（老版本 iproute2；此时由
 *                        SESSION_UP 的 -EBUSY/-EEXIST 兜底） */
static bool kdp_precheck_device(char *err, size_t errsz)
{
    char *out;
    char kind[64] = "";
    bool have_detail = false;
    char *line;
    int lineno = 0;

    out = cmd_capture((char *[]){ "-d", "link", "show", "dev",
                                  KDP_DEV_DEFAULT, NULL });
    if (out == NULL) {
        /* 设备不存在，或者 `ip` 本身不可用（两者都继续：路由代码随后会
         * 报出真正的原因） */
        return true;
    }
    line = out;
    while (line != NULL && *line != '\0') {
        char *nl = strchr(line, '\n');

        if (nl != NULL)
            *nl = '\0';
        if (lineno > 0) {
            const char *p = line;
            size_t i = 0;

            while (*p == ' ' || *p == '\t')
                p++;
            while (p[i] != '\0' && p[i] != ' ' && p[i] != '\t' &&
                   i + 1 < sizeof(kind)) {
                kind[i] = p[i];
                i++;
            }
            kind[i] = '\0';
            if (kind[0] != '\0') {
                have_detail = true;
                break;
            }
        }
        lineno++;
        if (nl == NULL)
            break;
        line = nl + 1;
    }

    if (have_detail && strcmp(kind, "iwan") != 0) {
        snprintf(err, errsz,
                 "%s 已存在，但不是 iwan 内核模块创建的设备"
                 "（ip -d 显示类型 \"%s\"）：\n"
                 "  内核数据面固定使用 %s，模块不会接管别人的设备"
                 "（会返回 -EBUSY）。\n"
                 "  请先删除它（sudo ip link del %s）后重试，"
                 "或改用 --data-plane tun",
                 KDP_DEV_DEFAULT, kind, KDP_DEV_DEFAULT, KDP_DEV_DEFAULT);
        free(out);
        return false;
    }
    if (!have_detail)
        log_debug("内核数据面: %s 已存在但 ip -d 未给出 kind，"
                  "无法预检归属（由 SESSION_UP 兜底）", KDP_DEV_DEFAULT);
    free(out);
    return true;
}

/* --------------------------------------------------- 会话五元组 */

/* dport = 服务器端口、sport = 本地实际端口、outer_src = 本地外层地址，
 * 全部取自已连接的套接字本身（getsockname/getpeername）：
 *   · 模块 TX 用 SPORT 当源端口、RX 认"目的端口 = SPORT"，
 *     outer_src 又是对端 peer 绑定的依据，任何一处用错都会漂；
 *   · 会话参数从第一次 SESSION_UP 起固定，所以这里取的值会在整个会话
 *     生命周期里保持不变（重连换端口 -> 先 SESSION_DOWN，见 kdp_teardown）。 */
/* 把 --server 的字面量解析成 v6 地址：接受裸地址与 [地址] 两种写法（与
 * cli_common.c 的 check_server_ip 同一套）。带 %scope 的链路本地字面量在
 * 这里就拒：内核 ABI 的外层 v6 属性只有 16 字节地址、没有 scope_id，链路
 * 本地外层在数据面无法保证发到正确接口。 */
static bool kdp_server_ip6(const char *s, struct in6_addr *out)
{
    char buf[INET6_ADDRSTRLEN];
    size_t n;

    if (s == NULL)
        return false;
    n = strlen(s);
    if (n >= 2 && s[0] == '[' && s[n - 1] == ']') {
        s++;
        n -= 2;
    }
    if (n == 0 || n >= sizeof(buf) || memchr(s, '%', n) != NULL)
        return false;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return inet_pton(AF_INET6, buf, out) == 1;
}

static bool kdp_socket_params(struct kdp *k, char *err, size_t errsz)
{
    struct sockaddr_storage local;
    struct sockaddr_storage peer;
    socklen_t sl;
    char src_s[INET6_ADDRSTRLEN + 8] = "";
    char dst_s[INET6_ADDRSTRLEN + 8] = "";

    memset(&local, 0, sizeof(local));
    memset(&peer, 0, sizeof(peer));
    sl = (socklen_t)sizeof(local);
    if (getsockname(k->sockfd, (struct sockaddr *)(void *)&local, &sl) != 0) {
        snprintf(err, errsz, "getsockname 会话套接字失败: %s", strerror(errno));
        return false;
    }
    sl = (socklen_t)sizeof(peer);
    if (getpeername(k->sockfd, (struct sockaddr *)(void *)&peer, &sl) != 0) {
        snprintf(err, errsz, "getpeername 会话套接字失败: %s", strerror(errno));
        return false;
    }
    if (local.ss_family != peer.ss_family) {
        snprintf(err, errsz,
                 "会话套接字两端地址族不一致（本端 %d，对端 %d）",
                 (int)local.ss_family, (int)peer.ss_family);
        return false;
    }
    if (local.ss_family == AF_INET) {
        const struct sockaddr_in *l4 =
            (const struct sockaddr_in *)(const void *)&local;
        const struct sockaddr_in *p4 =
            (const struct sockaddr_in *)(const void *)&peer;
        uint8_t b4[4];
        uint32_t src = ntohl(l4->sin_addr.s_addr);
        uint32_t dst = ntohl(p4->sin_addr.s_addr);

        /* 外层版本由会话族决定：v4 会话必须把 v6 侧显式清零（结构体在
         * 调用方是 memset 过的，这里再清一次是为了不依赖那个前提）。 */
        k->sess.outer_v6 = false;
        memset(&k->sess.outer_src6, 0, sizeof(k->sess.outer_src6));
        memset(&k->sess.outer_dst6, 0, sizeof(k->sess.outer_dst6));
        k->sess.outer_src = src;
        k->sess.outer_dst = dst;
        k->sess.sport = ntohs(l4->sin_port);
        k->sess.dport = ntohs(p4->sin_port);

        if (k->sess.sport == 0 || k->sess.dport == 0) {
            snprintf(err, errsz,
                     "会话套接字端口不完整（sport=%u dport=%u）：套接字未 connect？",
                     (unsigned)k->sess.sport, (unsigned)k->sess.dport);
            return false;
        }
        if (src == 0) {
            snprintf(err, errsz, "会话套接字本地地址还是 0.0.0.0：请先 connect");
            return false;
        }
        /* 回环外层不可用：本机发出的回环包会重新进入自己的钩子被自己吞掉
         * （CONTROL-PLANE.md 与 tests/tun_local_test.sh 的同机拓扑陷阱）。 */
        if ((src >> 24) == 127u || (dst >> 24) == 127u) {
            (void)inet_ntop(AF_INET, &l4->sin_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET, &p4->sin_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "外层地址是回环地址（本端 %s，对端 %s）：回环包会重新进入"
                     "本机钩子被吞掉，\n  内核数据面不能用于同机回环拓扑。"
                     "请用两个 netns + veth 互联（见 kernel/tests/netlink_test.sh）",
                     src_s, dst_s);
            return false;
        }
        /* route_setup 要给服务器装 /32 经物理网关的 pin；地址必须和实际对端
         * 一致，否则外层包会命中被劫持的 default dev iwan0 而被环路检查丢弃。 */
        if (!s2ip4(k->server, b4)) {
            snprintf(err, errsz, "服务器地址 '%s' 不是合法 IPv4 字面量",
                     k->server);
            return false;
        }
        if (ip4_u32(b4) != dst) {
            (void)inet_ntop(AF_INET, &p4->sin_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "--server %s 与套接字实际对端 %s 不一致；"
                     "外层地址必须与服务器的 /32 pin 一致",
                     k->server, dst_s);
            return false;
        }
        return true;
    }
    if (local.ss_family == AF_INET6) {
        const struct sockaddr_in6 *l6 =
            (const struct sockaddr_in6 *)(const void *)&local;
        const struct sockaddr_in6 *p6 =
            (const struct sockaddr_in6 *)(const void *)&peer;
        struct in6_addr want;

        /* 外层 v6：端点直接取已连接套接字的两端（与 v4 同一条事实来源，
         * 母须再查路由表 —— 握手走的就是这条路） */
        k->sess.outer_v6 = true;
        k->sess.outer_src = 0;
        k->sess.outer_dst = 0;
        k->sess.outer_src6 = l6->sin6_addr;
        k->sess.outer_dst6 = p6->sin6_addr;
        k->sess.sport = ntohs(l6->sin6_port);
        k->sess.dport = ntohs(p6->sin6_port);

        if (k->sess.sport == 0 || k->sess.dport == 0) {
            snprintf(err, errsz,
                     "会话套接字端口不完整（sport=%u dport=%u）：套接字未 connect？",
                     (unsigned)k->sess.sport, (unsigned)k->sess.dport);
            return false;
        }
        if (IN6_IS_ADDR_UNSPECIFIED(&l6->sin6_addr)) {
            snprintf(err, errsz, "会话套接字本地地址还是 ::: 请先 connect");
            return false;
        }
        if (IN6_IS_ADDR_V4MAPPED(&l6->sin6_addr) ||
            IN6_IS_ADDR_V4MAPPED(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "会话套接字是 v4-mapped 地址（对端 %s）：v4 外层应当用 "
                     "AF_INET 套接字", dst_s);
            return false;
        }
        if (IN6_IS_ADDR_LINKLOCAL(&l6->sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &l6->sin6_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "外层 v6 不支持链路本地地址（本端 %s，对端 %s）：内核 ABI "
                     "的外层 v6 属性\n  只有 16 字节地址、不带 scope_id，无法"
                     "保证发到正确接口。请给服务器配全局地址或唯一本地地址",
                     src_s, dst_s);
            return false;
        }
        if (IN6_IS_ADDR_LOOPBACK(&l6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &l6->sin6_addr, src_s, sizeof(src_s));
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "外层地址是回环地址（本端 %s，对端 %s）：回环包会重新进入"
                     "本机钩子被吞掉，\n  内核数据面不能用于同机回环拓扑。",
                     src_s, dst_s);
            return false;
        }
        if (!kdp_server_ip6(k->server, &want)) {
            snprintf(err, errsz,
                     "服务器地址 '%s' 不是合法 IPv6 字面量（外层 v6 会话要求"
                     "字面量，不支持链路本地 %%scope 写法）", k->server);
            return false;
        }
        if (!IN6_ARE_ADDR_EQUAL(&want, &p6->sin6_addr)) {
            (void)inet_ntop(AF_INET6, &p6->sin6_addr, dst_s, sizeof(dst_s));
            snprintf(err, errsz,
                     "--server %s 与套接字实际对端 %s 不一致；"
                     "外层地址必须与服务器的 /128 pin 一致",
                     k->server, dst_s);
            return false;
        }
        return true;
    }
    snprintf(err, errsz,
             "会话套接字的地址族不受支持（family=%d）：外层只支持 IPv4 与 IPv6",
             (int)local.ss_family);
    return false;
}

/* --------------------------------------------------- 路由（与 run_pump 同序） */

static bool kdp_routes_up(struct kdp *k)
{
    if (k->had_routes) {
        if (!route_setup(k->dev, k->auth_tun_ip, k->auth_mtu, k->server,
                         k->ogw, k->odev, k->ogw_metric, &k->routes,
                         &k->routes6)) {
            /* route_setup 已自行回滚并打过日志 */
            return false;
        }
        log_info("tun %s ready: %llu route%s", k->dev,
                 (unsigned long long)k->routes.n, k->routes.n == 1 ? "" : "s");
        for (size_t i = 0; i < k->routes.n; i++)
            log_debug("route %s -> dev %s", k->routes.v[i], k->dev);
    } else {
        if (!route_iface_up(k->dev, k->auth_tun_ip, k->auth_mtu)) {
            /* 与 run_pump 的失败回滚一致（Windows 上还有 v6 侧的清理，
             * 内核数据面是 Linux-only，route_rollback_v6 在 Linux 是空操作
             * 之外没有额外语义） */
            route_rollback_v6(k->dev, k->auth_tun_ip, &k->routes6);
            route_iface_down(k->dev);
            return false;
        }
        log_info("tun %s up with IP %s/24 (no route hijack)", k->dev,
                 k->auth_tun_ip);
    }
    if (k->routes6.n > 0) {
        route_setup6(k->dev, &k->routes6);
        for (size_t i = 0; i < k->routes6.n; i++)
            log_debug("route6 %s -> dev %s", k->routes6.v[i], k->dev);
    }
    k->routes_up = true;
    return true;
}

static void kdp_routes_down(struct kdp *k)
{
    if (!k->routes_up)
        return;
    route_teardown6(k->dev, k->auth_tun_ip, &k->routes6);
    if (k->had_routes)
        route_teardown(k->dev, k->server, k->ogw, k->odev, k->ogw_metric,
                       &k->routes);
    else
        route_iface_down(k->dev);
    k->routes_up = false;
}

/* --------------------------------------------------- 可选 events 通道 */

static void kdp_event_cb(void *ud, uint8_t ev, const uint8_t *frame, size_t len)
{
    (void)ud;
    (void)frame;   /* IWAN_DEBUG_STRIP 下 log_debug 是 no-op，参数被丢弃 */
    switch (ev) {
    case IWAN_EV_PEER_CLOSE:
        log_debug("内核数据面: 事件 PEER_CLOSE（对端主动断开）");
        break;
    case IWAN_EV_CTRL_FRAME:
        if (len > 0)
            log_debug("内核数据面: 事件 CTRL_FRAME type=0x%02x len=%llu",
                      (unsigned)frame[0], (unsigned long long)len);
        break;
    default:
        log_debug("内核数据面: 事件 %u len=%llu", (unsigned)ev,
                  (unsigned long long)len);
        break;
    }
}

/* ------------------------------------------------------------ 退出 */

/* 退出顺序（决策 8）：停轮询/事件 -> PT_CLOSE（关 socket 之前）->
 * 拆路由（route_iface_down/route_teardown 依赖设备名，必须在删卡前）->
 * SESSION_DOWN -> 关 fd。任何失败路径都执行相应子集，**绝不留已建立的
 * 会话**（残留会话会让钩子继续吞包，用户只会看到"网络坏了"）。 */
static void kdp_teardown(struct kdp *k)
{
    char err[256];

    reply_route_teardown(&k->rr);

    if (k->session_up) {
        if (kdp_send_ctrl(k, PT_CLOSE) != 0)
            log_debug("内核数据面: PT_CLOSE 发送失败: %s", strerror(errno));
        else
            /* 无条件打印（同 kdp_run 结尾的"已停"日志、以及 proxy.c 的 TUN 路径）：
             * 这是客户端侧唯一一处"已向对端发出告别帧"的可见证据，每条会话最多一行；
             * 放在 debug_enabled() 后面会让默认 Release 构建（IWAN_DEBUG_STRIP=ON，
             * IWAN_DEBUG 根本不被解析）永远看不到它，验收也就分不清"没发"与"发了没记录"。 */
            err_printf("CLOSE sent\n");
    }
    kdp_routes_down(k);
    if (k->session_up && k->genl != NULL) {
        if (genl_iwan_session_down(k->genl, err, sizeof(err)) != 0) {
            log_err("内核数据面: SESSION_DOWN 失败: %s", err);
            log_err("  会话与 %s 可能残留（钩子会继续吞包）："
                    "请执行 sudo ip link del %s 并重启模块，或重启系统",
                    k->dev, k->dev);
        } else {
            /* 复核：GET_STATS 没有 NLM_F_DUMP，判"有没有会话"看
             * sid==0 && tok==0（不是 DEVNAME —— 无会话时它是 "-"）。 */
            genl_iwan_stats st;
            char e2[256];

            if (genl_iwan_get_stats(k->genl, &st, e2, sizeof(e2)) == 0 &&
                (st.sid != 0 || st.tok != 0))
                log_err("内核数据面: SESSION_DOWN 之后会话仍在"
                        "（sid=0x%04x tok=0x%08x）：钩子可能继续吞包，"
                        "请手动再执行一次 SESSION_DOWN", st.sid, st.tok);
        }
        k->session_up = false;
    }
    if (k->genl != NULL) {
        genl_iwan_close(k->genl);
        k->genl = NULL;
    }
    kdp_shm_close(k);
    slist_free(&k->routes);
    slist_free(&k->routes6);
}

/* ------------------------------------------------------------ 主入口 */

int kdp_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
            uint8_t enc, const char *server, const slist_t *route_targets,
            const slist_t *route_targets6, const char *auth_tun_ip,
            uint16_t auth_mtu, const kdp_bind *bind, bool *ns_busy)
{
    struct kdp k;
    char err[512];
    uint64_t t_up;
    uint64_t next_tick;
    uint64_t last_ka;
    uint64_t last_seen = 0;
    int ka_fail = 0;
    bool seen_rx = false;
    bool busy_local = false;
    unsigned stale;
    unsigned ka_ms;
    unsigned ka_fail_max;

    if (ns_busy != NULL)
        *ns_busy = false;

    memset(&k, 0, sizeof(k));
    k.sockfd = sockfd;
    k.sid = sid;
    k.tok = tok;
    k.enc = enc;
    k.server = server;
    k.auth_tun_ip = auth_tun_ip;
    k.auth_mtu = auth_mtu;
    k.shm_fd = -1;
    k.sess.sid = sid;
    k.sess.tok = tok;
    k.sess.enc = enc;
    memcpy(k.sess.key, xor_key, sizeof(k.sess.key));
    k.sess.mtu = auth_mtu;
    k.sess.sport = 0;
    if (bind != NULL) {
        k.bind = *bind;
        k.sess.oif = bind->oif;
        k.sess.bind_ip = bind->bind_ip;
        k.sess.bind_ip6 = bind->bind_ip6;
    }
    snprintf(k.dev, sizeof(k.dev), "%s", KDP_DEV_DEFAULT);
    slist_init(&k.routes);
    slist_init(&k.routes6);

    /* run_pump 的第一件事：在任何阻塞设置之前装好停止处理（同一套
     * g_stop/g_user_stop 语义） */
    port_set_stop_handler(kdp_on_signal);

    if (expand_route_targets(route_targets, &k.routes) != 0) {
        kdp_teardown(&k);
        return -1;
    }
    if (expand_route_targets6(route_targets6, &k.routes6) != 0) {
        kdp_teardown(&k);
        return -1;
    }
    k.had_routes = k.routes.n > 0;
    if (k.had_routes) {
        if (!capture_default(k.ogw, k.odev, k.ogw_metric)) {
            log_err("cannot detect default route");
            kdp_teardown(&k);
            return -1;
        }
        log_debug("default route: via %s dev %s%s%s", k.ogw, k.odev,
                  k.ogw_metric[0] != '\0' ? " metric " : "", k.ogw_metric);
    }

    /* 启动前预检之一：会话五元组（getsockname/getpeername） */
    if (!kdp_socket_params(&k, err, sizeof(err))) {
        log_err("内核数据面: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    /* "绑 IP"模式下外层源地址就是该 IP（内核侧 iwan_carrier_resolve 要求
     * 二者一致，不一致直接 -EINVAL）。握手套接字已按它 bind（见
     * authenticate()），所以正常情况下面两值相等；不等说明系统路由把连接
     * 指到了别的源地址 —— 那种情况下对端学到的是另一个端点，数据面再用
     * 绑定地址发就会与对端记录不符，必须报出来。 */
    if (k.bind.bind_v6) {
        /* 外层 v6 的"绑 IP"：与下面 v4 分支同一套判断与文本 */
        if (!IN6_ARE_ADDR_EQUAL(&k.sess.outer_src6, &k.bind.bind_ip6)) {
            char a[INET6_ADDRSTRLEN], c[INET6_ADDRSTRLEN];

            log_err("内核数据面: 绑定的出口 IP %s 与会话套接字的源地址 %s "
                    "不一致（对端按握手源地址记录本端端点，数据面却用绑定"
                    "地址发送）；按绑定地址下发",
                    inet_ntop(AF_INET6, &k.bind.bind_ip6, a, sizeof(a)),
                    inet_ntop(AF_INET6, &k.sess.outer_src6, c, sizeof(c)));
        }
        k.sess.outer_src6 = k.bind.bind_ip6;
    } else if (k.bind.bind_ip != 0) {
        if (k.sess.outer_src != k.bind.bind_ip) {
            struct in_addr a, c;

            a.s_addr = htonl(k.bind.bind_ip);
            c.s_addr = htonl(k.sess.outer_src);
            log_err("内核数据面: 绑定的出口 IP %s 与会话套接字的源地址 %s "
                    "不一致（对端按握手源地址记录本端端点，数据面却用绑定"
                    "地址发送）；按绑定地址下发",
                    inet_ntop(AF_INET, &a, (char[INET_ADDRSTRLEN]){0},
                              INET_ADDRSTRLEN),
                    inet_ntop(AF_INET, &c, (char[INET_ADDRSTRLEN]){0},
                              INET_ADDRSTRLEN));
        }
        k.sess.outer_src = k.bind.bind_ip;
    }

    /* 预检之二：/dev/iwan 必须存在且版本匹配（不静默降级成 TUN） */
    if (!kdp_shm_open(&k, err, sizeof(err))) {
        log_err("内核数据面: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    /* 预检之三：本 netns 是否已有活会话 + iwan0 归属（与 kdp_plane_precheck
     * 同一套判据与文本；正常路径上调用者已在握手前跑过一次，这里是其它调
     * 用者（OIDC 等）与竞态的兜底） */
    if (!kdp_precheck_core(&k, err, sizeof(err), &busy_local)) {
        log_err("内核数据面: %s", err);
        if (ns_busy != NULL)
            *ns_busy = busy_local;
        kdp_teardown(&k);
        return -1;
    }

    k.genl = genl_iwan_open(err, sizeof(err));
    if (k.genl == NULL) {
        log_err("内核数据面: %s", err);
        kdp_teardown(&k);
        return -1;
    }
    if (genl_iwan_session_up(k.genl, &k.sess, k.dev, sizeof(k.dev),
                             &k.dev_mtu, err, sizeof(err)) != 0) {
        char os[INET6_ADDRSTRLEN] = "";
        char od[INET6_ADDRSTRLEN] = "";

        log_err("内核数据面: %s", err);
        /* 把**我们发出去的**会话参数原样打出来：拒绝的原因要么是它越界
         * （典型：内层 MTU 超过模块 max_mtu，默认 1500 —— 度量档构建
         * IWAN_JUMBO_MTU 会把默认 MTU 抬到上限，本行一眼可见），要么是
         * 与内核里已有会话不一致（对照下面 GET_STATS 的模块视角）。 */
        if (k.sess.outer_v6) {
            (void)inet_ntop(AF_INET6, &k.sess.outer_src6, os, sizeof(os));
            (void)inet_ntop(AF_INET6, &k.sess.outer_dst6, od, sizeof(od));
        } else {
            struct in_addr a;

            a.s_addr = htonl(k.sess.outer_src);
            (void)inet_ntop(AF_INET, &a, os, sizeof(os));
            a.s_addr = htonl(k.sess.outer_dst);
            (void)inet_ntop(AF_INET, &a, od, sizeof(od));
        }
        log_err("内核数据面: 本次 SESSION_UP 请求 sid=0x%04x enc=%u mtu=%u "
                "外层%s %s:%u -> %s:%u oif=%u bind_ip=%s flags=%s",
                (unsigned)sid, (unsigned)k.sess.enc, (unsigned)k.sess.mtu,
                k.sess.outer_v6 ? "v6" : "v4", os, (unsigned)k.sess.sport,
                od, (unsigned)k.sess.dport, (unsigned)k.sess.oif,
                (k.sess.outer_v6 ?
                     !IN6_IS_ADDR_UNSPECIFIED(&k.sess.bind_ip6) :
                     k.sess.bind_ip != 0) ? "有" : "无",
                k.sess.mtu != 0 && k.sess.mtu > 1500u
                    ? "注意：MTU 超过模块 max_mtu 默认值 1500，必被拒"
                    : "正常");
        /* "已有会话"这一类失败不能回退到别的数据面：回退会拿同一账号把那
         * 条会话顶掉。两条判据取或：模块的冲突 extack，或者共享内存里确实
         * 有一条活会话（对端静默时前者才认得出）。 */
        if (ns_busy != NULL)
            *ns_busy = kdp_err_is_conflict(err) ||
                       kdp_session_is_live(&k, NULL);
        kdp_teardown(&k);
        return -1;
    }
    k.session_up = true;
    {
        /* inet_ntoa 用静态缓冲区，一次 printf 里两个地址会互相覆盖；
         * 地址串缓冲按 v6 的长度给（族由 outer_v6 决定） */
        char os[INET6_ADDRSTRLEN] = "";
        char od[INET6_ADDRSTRLEN] = "";

        if (k.sess.outer_v6) {
            (void)inet_ntop(AF_INET6, &k.sess.outer_src6, os, sizeof(os));
            (void)inet_ntop(AF_INET6, &k.sess.outer_dst6, od, sizeof(od));
        } else {
            struct in_addr a;

            a.s_addr = htonl(k.sess.outer_src);
            (void)inet_ntop(AF_INET, &a, os, sizeof(os));
            a.s_addr = htonl(k.sess.outer_dst);
            (void)inet_ntop(AF_INET, &a, od, sizeof(od));
        }
        log_info("内核数据面: 会话已建立 dev=%s mtu=%u sid=0x%04x "
                 "外层%s %s:%u -> %s:%u", k.dev, (unsigned)k.dev_mtu,
                 (unsigned)sid, k.sess.outer_v6 ? "v6" : "v4", os,
                 (unsigned)k.sess.sport, od, (unsigned)k.sess.dport);
    }
    /* 回程路由：这里才拿到承载网卡 ifindex（设备与承载都定了），所以在这里装。
     * 先决检查不满足就拒绝本次会话 —— 那意味着规则会静默不生效（回包仍走物理
     * 网卡），比直接出错更难查。 */
    if (bind != NULL && bind->reply_via_tunnel) {
        reply_route_opts  ro;
        genl_iwan_stats   rst;
        char              ifname[IF_NAMESIZE] = "";
        char              why[512];
        char              rerr[256];

        memset(&ro, 0, sizeof(ro));
        memset(&rst, 0, sizeof(rst));
        ro.tun = k.dev;
        ro.served4 = route_targets;
        ro.served6 = route_targets6;
        ro.kernel_plane = true;
        /* 承载网卡 ifindex 只在 GET_STATS 里导出（会话回执没有这一项），
         * 所以此处补一次查询；承载一钉住就不会再变。 */
        if (genl_iwan_get_stats(k.genl, &rst, why, sizeof(why)) != 0 ||
            rst.carrier == 0 ||
            if_indextoname(rst.carrier, ifname) == NULL) {
            log_err("回程路由: 取不到承载网卡（GET_STATS %s，carrier=%u），"
                    "定不了入方向匹配接口；本次会话拒绝",
                    rst.carrier == 0 ? "读到 carrier=0" : "失败",
                    (unsigned)rst.carrier);
            kdp_teardown(&k);
            return -1;
        }
        ro.in_if = ifname;
        if (!reply_route_precheck(&ro, why, sizeof(why))) {
            log_err("回程路由: 先决检查未过，本次会话拒绝: %s", why);
            kdp_teardown(&k);
            return -1;
        }
        if (!reply_route_setup(&ro, &k.rr, rerr, sizeof(rerr))) {
            log_err("回程路由: 装规则失败，本次会话拒绝: %s", rerr);
            kdp_teardown(&k);
            return -1;
        }
    }
    if (k.dev_mtu != 0 && k.dev_mtu != (uint32_t)auth_mtu)
        log_err("内核数据面: 回执 MTU %u 与协商 MTU %u 不一致，"
                "按协商值配置地址/路由", (unsigned)k.dev_mtu,
                (unsigned)auth_mtu);
    /* 设备归属：本轮模块若回了 IWAN_A_DEV_OWNED 也不额外处理（枚举常量
     * 无法 #ifdef 探测）；"别人的卡"由预检 + SESSION_UP 的 -EBUSY 覆盖。 */

    /* events 组降级为可选/诊断：拿不到就只少了日志，不影响数据面 */
    if (genl_iwan_events_subscribe(k.genl, err, sizeof(err)) == 0) {
        k.events_ok = true;
    } else {
        log_debug("内核数据面: events 多播组不可用（仅影响诊断日志）: %s",
                  err);
    }

    /* 地址/路由/MTU 仍归用户态：模块只建卡、置 UP、设 MTU */
    if (!kdp_routes_up(&k)) {
        log_err("内核数据面: 地址/路由配置失败，回滚已建立的会话");
        kdp_teardown(&k);
        return -1;
    }

    /* 与 run_pump 相同的窗口：setup 期间按下 Ctrl-C 就不再启动数据面，
     * 但要先把路由与会话回滚干净 */
    if (g_user_stop) {
        log_info("kernel data plane: stop requested during setup; aborting");
        kdp_teardown(&k);
        return 0;
    }
    g_stop = 0;

    log_info("kernel data plane running (dev %s) -- press Ctrl-C to stop",
             k.dev);

    stale = (unsigned)pump_rx_stale_ms();       /* 0 = 关闭看门狗 */
    ka_ms = pump_keepalive_ms();
    ka_fail_max = pump_ka_fail_max();
    t_up = now_ms();
    next_tick = t_up;
    last_ka = t_up > ka_ms ? t_up - ka_ms : 0;  /* 立即发第一条 keepalive */

    while (!g_stop && !g_user_stop) {
        char bwhy[256];

        /* 0) 绑定有效性。内核只在"外层查找失败"时反应，而绑定的出口 IP
         *    被删并不构成查找失败（实测：报文照发），承载网卡失去载波同理
         *    —— 这一条只能在这里判。失效即"关闭内核部分"：teardown 落
         *    SESSION_DOWN 并让经 iwan0 的那条路由失效，内层流量改由路由表
         *    的下一条目承担；重连循环在重新握手**之前**等绑定恢复
         *    （kdp_bind_wait）。 */
        if (!kdp_bind_ok(&k.bind, bwhy, sizeof(bwhy))) {
            log_err("内核数据面: 绑定失效（%s），停用数据面", bwhy);
            k.session_lost = true;
            break;
        }

        uint64_t now;
        uint64_t lr;

        port_sleep_ms(KDP_SLEEP_MS);
        now = now_ms();

        if (k.events_ok)
            (void)genl_iwan_events_drain(k.genl, kdp_event_cb, &k);

        if (now < next_tick)
            continue;
        next_tick = now + KDP_POLL_MS;

        /* 1) 存活：/dev/iwan 时间戳（内核每收到一个过闸帧就写，PT_CLOSE
         *    置 0）。0 在会话刚建立时也表示"还没收到过"，所以用 seen_rx
         *    区分"从未收到"和"收到过又归零"。 */
        lr = kdp_shm_last_rx(&k);
        if (lr != 0) {
            if (!seen_rx) {
                seen_rx = true;
                log_info("内核数据面: 收到对端首个有效帧"
                         "（/dev/iwan 时间戳已非零）");
            }
            /* 收到**新**帧 = 对端活着，清零"无人应答"失败预算。判据只能是
             * 收到帧：一次成功的 send 不证明对端存在 —— 连通 UDP 套接字把
             * ICMP 端口不可达隔次上报，中间那次 send 会成功，按"发送成功"
             * 清零会让 3 次的预算永远到不了（实测：服务端消失后日志反复
             * 出现"重试 1/3"，最后靠 IWAN_RX_STALE_MS 看门狗判死）。 */
            if (lr != last_seen)
                ka_fail = 0;
            last_seen = lr;
        } else if (seen_rx) {
            log_err("内核数据面: /dev/iwan 时间戳归零"
                    "（对端 PT_CLOSE / 会话被清），会话丢失");
            k.session_lost = true;
            break;
        }
        if (stale != 0) {
            uint64_t quiet = seen_rx ? ms_since(now, last_seen)
                                     : ms_since(now, t_up);
            if (quiet > stale) {
                log_err("内核数据面: %llu ms 没有收到任何有效帧"
                        "（IWAN_RX_STALE_MS=%u），会话丢失",
                        (unsigned long long)quiet, stale);
                k.session_lost = true;
                break;
            }
        }

        /* 2) keepalive 发送仍在用户态（10s PT_ECHO_REQ，与 TUN 泵同参数） */
        if (ms_since(now, last_ka) >= ka_ms) {
            if (kdp_send_ctrl(&k, PT_ECHO_REQ) != 0) {
                int e = errno;

                if (++ka_fail >= (int)ka_fail_max) {
                    log_err("内核数据面: 无下行帧期间 keepalive 失败累计 %d 次"
                            "（最后错误: %s）；会话丢失", ka_fail,
                            strerror(e));
                    k.session_lost = true;
                    break;
                }
                err_printf("内核数据面: keepalive 发送失败: %s"
                           "（无下行帧期间累计 %d/%u）\n", strerror(e),
                           ka_fail, ka_fail_max);
            }
            /* 成功与否都推进节奏：失败要每 ka_ms 重试一次，而不是每个
             * 1 秒节拍都重试 */
            last_ka = now_ms();
        }

        /* 3) 设备被外部删除（ip link del / netns 拆）：重放幂等的
         *    SESSION_UP 会重建网卡，但地址/路由要重跑一遍。 */
        if (if_nametoindex(k.dev) == 0) {
            log_err("内核数据面: 设备 %s 被外部删除，重放 SESSION_UP 重建",
                    k.dev);
            k.routes_up = false;   /* 路由随设备一起消失 */
            if (genl_iwan_session_up(k.genl, &k.sess, k.dev, sizeof(k.dev),
                                     &k.dev_mtu, err, sizeof(err)) != 0) {
                log_err("内核数据面: 重建 %s 失败: %s；会话丢失", k.dev, err);
                k.session_lost = true;
                break;
            }
            if (!kdp_routes_up(&k)) {
                log_err("内核数据面: 重建后地址/路由配置失败；会话丢失");
                k.session_lost = true;
                break;
            }
            log_info("内核数据面: %s 已重建", k.dev);
        }
    }

    kdp_teardown(&k);

    /* 无条件打印（刻意不放在 debug_enabled() 后面）：这是"内核数据面已停"唯一一条
     * 用户可见的收尾日志，每条会话最多一行，没有刷屏风险；而放在调试开关后面会让
     * 默认的 Release 构建（IWAN_DEBUG_STRIP=ON，IWAN_DEBUG 根本不被解析）永远看不到
     * 它 —— 用户按 Ctrl-C 后只看到"卡住"，验收脚本的退出语义断言也无从下手。 */
    err_printf("kernel data plane stopped (%s)\n",
               k.session_lost ? "session lost" : "user stop");
    /* 1 = 会话丢失（重连）; 0 = 用户停止 —— 与 run_pump 同语义 */
    return k.session_lost ? 1 : 0;
}

#endif /* __linux__ */
