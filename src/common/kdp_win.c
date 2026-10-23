/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdp_win.c — 见 kdp_win.h。与 Linux 侧 kdp.c 的循环逐条对应：
 *
 *   kdp.c（Linux）                       kdp_win.c（Windows）
 *   -----------------------------------  ------------------------------------
 *   kdp_plane_precheck()                 kdp_win_plane_precheck()
 *   genl SESSION_UP + oif/bind 属性      IOCTL_IWAN_SESSION_OPEN（外层四元组 +
 *                                        承载 MTU + 目标集合）
 *   mmap(/dev/iwan)                      IOCTL_IWAN_SHM_QUERY 的只读映射
 *   1s 节拍读 last_rx_ms                 windev_shm_last_rx_ms()
 *   10s PT_ECHO_REQ（用户态套接字）      同一份 ctrl_hdr() + port_send()
 *   IWAN_RX_STALE_MS 看门狗              pump_rx_stale_ms()，同一默认值
 *   SESSION_DOWN + 路由回滚              route_teardown/route_iface_down +
 *                                        IOCTL_IWAN_SESSION_CLOSE
 *
 * 刻意不做的事（与 M1 边界一致）：不绑出口 IP（那是 linux 侧 --bind-ip 的能力，
 * Windows 侧需要时再加）；--reply-via-tunnel 在 Windows 上要靠 WFP 流上下文，
 * 尚未实现，用户显式要求时必须报错而不是静默忽略（由调用方判）。
 */
#if defined(_WIN32)

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>      /* wcscmp：按设备路径判别是哪个内核平面 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>

#include "kdp_win.h"

#include "protocol.h"   /* PT_ECHO_REQ/PT_CLOSE、ctrl_hdr */
#include "proxy.h"      /* expand_route_targets(_6)、pump_keepalive_ms 等 */
#include "route.h"      /* capture_default、route_setup/teardown、route_iface_up */
#include "util.h"       /* now_ms、ms_since、日志 */
#include "windev.h"     /* 设备层 */

#define KDP_WIN_POLL_MS  1000u
#define KDP_WIN_SLEEP_MS 100u

/* 与 kdp.c 的 ms_since 同义：单调毫秒差，now 落后于 then 时返回 0 */
static uint64_t kdp_win_ms_since(uint64_t now, uint64_t then)
{
    return now > then ? now - then : 0;
}

/* ---- 外层四元组与承载 MTU -------------------------------------------- */

/* 从已 connect 的会话套接字读出外层四元组（网络序），与 kdp.c 的
 * kdp_outer_tuple 同一意图：驱动要靠它认领入向数据帧、构造外层头。 */
static bool kdp_win_outer_tuple(int fd, IWAN_WIN_SESSION_OPEN *req,
                                char *err, size_t errsz)
{
    struct sockaddr_storage local, peer;
    socklen_t ll = sizeof(local), pl = sizeof(peer);
    struct sockaddr_in *l4, *p4;

    if (getsockname(fd, (struct sockaddr *)&local, &ll) != 0 ||
        getpeername(fd, (struct sockaddr *)&peer, &pl) != 0) {
        snprintf(err, errsz, "读会话套接字地址失败: %s", strerror(errno));
        return false;
    }
    if (local.ss_family != peer.ss_family) {
        snprintf(err, errsz, "会话套接字两端地址族不一致");
        return false;
    }
    if (local.ss_family == AF_INET) {
        l4 = (struct sockaddr_in *)&local;
        p4 = (struct sockaddr_in *)&peer;
        req->sport = l4->sin_port;
        req->dport = p4->sin_port;
        req->outer_src = l4->sin_addr.s_addr;
        req->outer_dst = p4->sin_addr.s_addr;
        /* v6 字段必须清零：驱动按"两个 v6 字段同时非零"判定外层 v6 */
        memset(req->outer_src6, 0, sizeof(req->outer_src6));
        memset(req->outer_dst6, 0, sizeof(req->outer_dst6));
        return true;
    }
    if (local.ss_family == AF_INET6) {
        struct sockaddr_in6 *l6 = (struct sockaddr_in6 *)&local;
        struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)&peer;

        req->sport = l6->sin6_port;
        req->dport = p6->sin6_port;
        memcpy(req->outer_src6, &l6->sin6_addr, sizeof(req->outer_src6));
        memcpy(req->outer_dst6, &p6->sin6_addr, sizeof(req->outer_dst6));
        req->outer_src = 0;
        req->outer_dst = 0;
        return true;
    }
    snprintf(err, errsz, "不支持的外层地址族 %d", (int)local.ss_family);
    return false;
}

/* 到服务器那一跳的承载路由：给出承载接口 MTU（驱动用它算内层可用 MTU）、
 * 下一跳地址（驱动用它解析承载网卡的邻居地址）与承载接口索引（NDIS 平面
 * 用它把会话钉在"恰好一张下游网卡"上）。
 * 取不到就退回 1500 / 0 / 0：宁可保守，也不要让驱动按 0 算出荒谬的 MTU，
 * 更不要让它按一个编出来的下一跳去 ARP。 */
/* 到服务器那一跳的承载路由：给出承载接口 MTU（驱动用它算内层可用 MTU）、
 * 下一跳地址（驱动用它解析承载网卡的邻居地址）与承载接口索引（NDIS 平面
 * 用它把会话钉在"恰好一张下游网卡"上）。
 *
 * 实现上刻意不用 GetBestRoute2：本机（mingw 交叉编译的客户端，客体 Windows
 * 11 24H2）上它稳定返回 87 ERROR_INVALID_PARAMETER（同一份代码里
 * GetIpForwardTable2 与 ConvertInterfaceLuids 都正常），两参数源地址写法都
 * 一样失败 —— 与其赌结构布局，不如只用一张表自己挑。
 *
 * 判据与内核的 FIB 查找同序：**前缀最长者胜**，平手看 metric 最小，再平手
 * 看接口索引最小。直连路由的 NextHop 是全零，此时对端就在链路上，按驱动的
 * 约定写 0（表示"对端在链路上"），不要编一个下一跳出来。
 *
 * 返回 0 表示"查不到可用承载"，调用方必须让会话建立失败：静默给 0 索引会
 * 被驱动按"没指定承载"拒掉，但报出来的是 Win32 87，看不出是路由问题。 */
static uint32_t kdp_win_carrier_route(uint32_t dst_be, uint32_t *hop_be,
                                      uint32_t *oif_out, uint8_t *guid_out)
{
    MIB_IPFORWARD_TABLE2 *ft = NULL;
    MIB_IPFORWARD_ROW2 *best = NULL;
    MIB_IPINTERFACE_ROW ifrow;
    NET_LUID luid;
    ULONG i, best_plen = 0;
    ULONG best_metric = 0;
    ULONG mtu = 0;

    *hop_be = 0;
    *oif_out = 0;
    memset(guid_out, 0, 16);

    if (GetIpForwardTable2(AF_INET, &ft) != NO_ERROR || ft == NULL)
        return 0;

    for (i = 0; i < ft->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *r = &ft->Table[i];
        const uint8_t *pfx;
        uint8_t d[4];
        ULONG plen, bit;
        BOOLEAN hit = TRUE;

        if (r->DestinationPrefix.Prefix.si_family != AF_INET)
            continue;
        plen = r->DestinationPrefix.PrefixLength;
        if (plen > 32)
            continue;
        pfx = (const uint8_t *)&r->DestinationPrefix.Prefix.Ipv4.sin_addr;
        d[0] = (uint8_t)(dst_be >> 24);
        d[1] = (uint8_t)(dst_be >> 16);
        d[2] = (uint8_t)(dst_be >> 8);
        d[3] = (uint8_t)dst_be;
        for (bit = 0; bit < plen; bit++) {
            uint8_t mask = (uint8_t)(0x80u >> (bit & 7u));

            if ((pfx[bit >> 3] & mask) != (d[bit >> 3] & mask)) {
                hit = FALSE;
                break;
            }
        }
        if (!hit)
            continue;
        if (best == NULL || plen > best_plen ||
            (plen == best_plen && r->Metric < best_metric) ||
            (plen == best_plen && r->Metric == best_metric &&
             r->InterfaceIndex < best->InterfaceIndex)) {
            best = r;
            best_plen = plen;
            best_metric = r->Metric;
        }
    }
    if (best == NULL) {
        FreeMibTable(ft);
        return 0;
    }
    *oif_out = (uint32_t)best->InterfaceIndex;
    if (best->NextHop.si_family == AF_INET)
        *hop_be = best->NextHop.Ipv4.sin_addr.s_addr;
    luid = best->InterfaceLuid;
    FreeMibTable(ft);

    if (*oif_out == 0)
        return 0;

    /* 接口 GUID 是唯一能跨两种索引口径对上号的东西。客体实测：以太网的
     * netio 索引是 7，而协议驱动绑定回调报的 BoundIfIndex 是 23/26 ——
     * 两套编号并不一致，按索引挑承载等于猜（猜错的症状就是"绑定明明有、
     * OPEN 一律 DEVICE_NOT_READY"，从计数上完全看不出来）。协议边把
     * NDIS_BIND_PARAMETERS.AdapterName 里的同一个 GUID 解析出来，驱动按
     * GUID 匹配；取不到 GUID 才退回索引口径。 */
    {
        GUID g;

        memset(&g, 0, sizeof(g));
        if (ConvertInterfaceLuidToGuid(&luid, &g) == NO_ERROR)
            memcpy(guid_out, &g, 16);
    }

    memset(&ifrow, 0, sizeof(ifrow));
    ifrow.Family = AF_INET;
    ifrow.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&ifrow) != NO_ERROR)
        return 0;
    mtu = ifrow.NlMtu;
    if (mtu < 576 || mtu > 65535)
        return 0;
    return (uint32_t)mtu;
}

/* ---- 目标集合 --------------------------------------------------------- */

/* "<cidr>" 或裸主机地址 -> IWAN_WIN_TARGET。v4 的 addr 只填前 4 字节
 * （与 ABI 的约定一致：其余字节必须为 0，驱动也会校验）。 */
static bool kdp_win_target_parse(const char *s, IWAN_WIN_TARGET *out,
                                 char *err, size_t errsz)
{
    char buf[128];
    char *slash;
    long plen = -1;

    if (strlen(s) >= sizeof(buf)) {
        snprintf(err, errsz, "路由目标过长: %s", s);
        return false;
    }
    snprintf(buf, sizeof(buf), "%s", s);
    slash = strchr(buf, '/');
    if (slash != NULL) {
        char *end = NULL;

        *slash = '\0';
        plen = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || plen < 0) {
            snprintf(err, errsz, "路由目标前缀非法: %s", s);
            return false;
        }
    }

    memset(out, 0, sizeof(*out));
    if (strchr(buf, ':') != NULL) {
        struct in6_addr a6;

        if (inet_pton(AF_INET6, buf, &a6) != 1) {
            snprintf(err, errsz, "路由目标非法: %s", s);
            return false;
        }
        if (plen < 0)
            plen = 128;
        if (plen > 128) {
            snprintf(err, errsz, "路由目标前缀越界: %s", s);
            return false;
        }
        out->family = IWAN_WIN_AF_V6;
        out->prefix_len = (uint32_t)plen;
        memcpy(out->addr, &a6, 16);
        return true;
    }

    {
        struct in_addr a4;

        if (inet_pton(AF_INET, buf, &a4) != 1) {
            snprintf(err, errsz, "路由目标非法: %s", s);
            return false;
        }
        if (plen < 0)
            plen = 32;
        if (plen > 32) {
            snprintf(err, errsz, "路由目标前缀越界: %s", s);
            return false;
        }
        out->family = IWAN_WIN_AF_V4;
        out->prefix_len = (uint32_t)plen;
        memcpy(out->addr, &a4, 4);
    }
    return true;
}

static int kdp_win_targets_build(const slist_t *v4, const slist_t *v6,
                                 IWAN_WIN_TARGET **out, size_t *nout,
                                 char *err, size_t errsz)
{
    size_t n = (v4 != NULL ? v4->n : 0) + (v6 != NULL ? v6->n : 0);
    IWAN_WIN_TARGET *t;
    size_t i, k = 0;

    *out = NULL;
    *nout = 0;
    if (n == 0)
        return 0;
    if (n > IWAN_WIN_MAX_TARGETS) {
        snprintf(err, errsz, "目标集合条目过多（%llu > %u）",
                 (unsigned long long)n, (unsigned)IWAN_WIN_MAX_TARGETS);
        return -1;
    }
    t = (IWAN_WIN_TARGET *)calloc(n, sizeof(*t));
    if (t == NULL) {
        snprintf(err, errsz, "内存不足（目标集合 %llu 条）",
                 (unsigned long long)n);
        return -1;
    }
    for (i = 0; i < (v4 != NULL ? v4->n : 0); i++, k++)
        if (!kdp_win_target_parse(v4->v[i], &t[k], err, errsz)) {
            free(t);
            return -1;
        }
    for (i = 0; i < (v6 != NULL ? v6->n : 0); i++, k++)
        if (!kdp_win_target_parse(v6->v[i], &t[k], err, errsz)) {
            free(t);
            return -1;
        }
    *out = t;
    *nout = k;
    return 0;
}

/* ---- 启动预检 --------------------------------------------------------- */

bool kdp_win_plane_precheck(const wchar_t *device_path, char *err, size_t errsz,
                            bool *busy)
{
    windev_t *d = NULL;
    IWAN_WIN_SESSION_INFO info;
    int rc;

    if (busy != NULL)
        *busy = false;

    rc = windev_open_named(&d, device_path, err, errsz);
    if (rc != WINDEV_OK) {
        /* 驱动没装 → 调用者可以回退 TUN 面；其余（版本不符、权限）由
         * windev 的中文原因说明，同样不回退。 */
        return false;
    }

    rc = windev_session_get(d, &info, err, errsz);
    if (rc == WINDEV_OK && info.enabled != 0 && info.last_rx_ms != 0) {
        uint64_t window = (uint64_t)pump_keepalive_ms() * 2u;

        if (window == 0)
            window = 20000;
        if (kdp_win_ms_since(now_ms(), (uint64_t)info.last_rx_ms) < window) {
            if (busy != NULL)
                *busy = true;
            snprintf(err, errsz,
                     "本机已有活会话（sid=%u 最近收到对端帧在 %llu ms 前）："
                     "同一账号再开一条会把那条顶掉，先停掉它再试",
                     (unsigned)info.sid,
                     (unsigned long long)kdp_win_ms_since(now_ms(),
                                                  (uint64_t)info.last_rx_ms));
            windev_close(d);
            return false;
        }
    }
    /* 设备在、没有活会话：可以继续（会话信息里的 abi_version 已由
     * windev_session_get 校验过）。 */
    windev_close(d);
    return true;
}

/* ---- 主循环 ----------------------------------------------------------- */

int kdp_win_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
                uint8_t enc, const char *server, const char *dev,
                const wchar_t *device_path,
                const slist_t *route_targets, const slist_t *route_targets6,
                const char *auth_tun_ip, uint16_t auth_mtu, bool *ns_busy)
{
    IWAN_WIN_SESSION_OPEN req;
    IWAN_WIN_SESSION_INFO info;
    IWAN_WIN_TARGET *targets = NULL;
    size_t ntargets = 0;
    const IWAN_WIN_SHM *shm = NULL;
    windev_t *d = NULL;
    char err[512];
    const char *tun = (dev != NULL && dev[0] != '\0') ? dev : IWAN_WIN_DEF_DEV;

    slist_t routes, routes6, empty;
    char ogw[16] = "", odev[16] = "", ometric[16] = "";
    bool iface_up = false, session_up = false, routes_up = false;
    bool seen_rx = false, session_lost = false;
    uint64_t last_seen = 0;
    uint64_t t_up = 0;
    unsigned ka_ms, ka_fail_max, stale;
    unsigned ka_fail = 0;
    uint64_t last_ka, next_tick;
    int rc = 0;

    if (ns_busy != NULL)
        *ns_busy = false;
    slist_init(&routes);
    slist_init(&routes6);
    err[0] = '\0';

    /* 0) 目标集合：与 kdp.c 用同一套展开（裸 IP、CIDR、去重与规范化都在
     *    expand_route_targets 里），驱动只做最长前缀匹配。 */
    slist_init(&empty);
    if (expand_route_targets(route_targets != NULL ? route_targets : &empty,
                            &routes) != 0 ||
        expand_route_targets6(route_targets6 != NULL ? route_targets6 : &empty,
                              &routes6) != 0) {
        log_err("Windows 内核数据面: 目标集合展开失败");
        rc = -1;
        goto out;
    }
    if (kdp_win_targets_build(&routes, &routes6, &targets, &ntargets,
                              err, sizeof(err)) != 0) {
        log_err("Windows 内核数据面: %s", err);
        rc = -1;
        goto out;
    }

    /* 1) 打开驱动设备。这一步失败 = 本机内核面起不来，允许调用者回退 TUN。 */
    if (windev_open_named(&d, device_path, err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows 内核数据面: %s", err);
        rc = -1;
        goto out;
    }

    /* 2) 会话套接字五元组 + 承载 MTU + 内层 MTU */
    memset(&req, 0, sizeof(req));
    if (!kdp_win_outer_tuple(sockfd, &req, err, sizeof(err))) {
        log_err("Windows 内核数据面: %s", err);
        rc = -1;
        goto out;
    }
    req.carrier_mtu = kdp_win_carrier_route(req.outer_dst, &req.outer_hop,
                                            &req.oif_index,
                                            req.outer_if_guid);
    if (req.carrier_mtu == 0) {
        /* 查不到承载就等于没有外层出口：NDIS 平面按 oif_index=0 拒会话，
         * WFP 平面会建立一条发不出包的会话。两种都不许静默发生。 */
        log_err("Windows 内核数据面: 找不到到 %s 的承载路由（无默认路由？）",
                server);
        rc = -1;
        goto out;
    }
    {
        /* 内层 MTU = min(服务器协商值, 承载网卡 MTU - 封装开销)。承载 MTU 是
         * 硬上限（封不下就一个字节都发不出去），协商值是服务端的接收能力；
         * 只信协商值会在承载小于 1500 的链路上封出超长外层帧，只信网卡会在
         * 服务端更保守时被对端丢。声明给驱动的值、netsh 写进适配器的值必须是
         * 同一个 —— 否则就是"上层以为能发、驱动静默丢"的 PMTU 黑洞。 */
        uint32_t overhead = (req.outer_dst != 0) ? IWAN_WIN_OVERHEAD_V4
                                                 : IWAN_WIN_OVERHEAD_V6;
        uint32_t cap, mtu;

        if (req.carrier_mtu <= overhead + IWAN_WIN_MTU_MIN) {
            log_err("Windows 内核数据面: 承载 MTU %u 装不下隧道"
                    "（封装开销 %u，内层最少 %u）",
                    (unsigned)req.carrier_mtu, (unsigned)overhead,
                    (unsigned)IWAN_WIN_MTU_MIN);
            rc = -1;
            goto out;
        }
        cap = req.carrier_mtu - overhead;
        mtu = (auth_mtu == 0 || (uint32_t)auth_mtu > cap) ? cap
                                                         : (uint32_t)auth_mtu;
        req.inner_mtu = (uint16_t)mtu;
        if (mtu != (uint32_t)auth_mtu)
            log_info("Windows 内核数据面: 内层 MTU 由 %u 下调到 %u"
                     "（承载 MTU %u，封装开销 %u）",
                     (unsigned)auth_mtu, (unsigned)mtu,
                     (unsigned)req.carrier_mtu, (unsigned)overhead);
        auth_mtu = (uint16_t)mtu;
    }
    memcpy(req.key, xor_key, sizeof(req.key));
    req.sid = sid;
    req.tok = tok;
    req.enc = enc;
    req.flags = 0;

    /* 内层地址必须交给驱动。出向分类把它当"会话可用"守卫
     * （iwan_win_wfp.c：inner_ip == 0 就地放行、一条都不封装），漏填的
     * 后果是内核面看着建立成功、实际没有任何报文进隧道。
     * 外层四元组里的地址都是网络序，inner_ip 保持一致（ABI 注释：be32）。 */
    {
        struct in_addr a4;
        uint8_t b4[4];

        if (inet_pton(AF_INET, auth_tun_ip, &a4) != 1) {
            log_err("Windows 内核数据面: 内层地址 %s 不是合法 IPv4",
                    auth_tun_ip);
            rc = -1;
            goto out;
        }
        memcpy(b4, &a4.s_addr, sizeof(b4));
        req.inner_ip = a4.s_addr;
        /* 内层 v6 用同一份内层地址派生的 ULA：驱动目前只存不用，
         * 但填上才和 ABI 的语义一致（proxy/socks 也是这么派的）。 */
        ip6_derive_ula(ip4_u32(b4), req.inner_ip6);
    }

    /* 3) 地址与路由（在会话之前：失败时不用撤已建立的会话）。
     *    与 kdp.c 同序：有目标集合就"劫持"这些前缀的路由，没有就只把
     *    适配器带内层地址拉起来。 */
    if (capture_default(ogw, odev, ometric) && odev[0] != '\0') {
        log_debug("Windows 内核数据面: 默认路由 %s dev %s metric %s",
                  ogw, odev, ometric);
    }
    /* NDIS 平面：内层适配器是本驱动自己的那张，Windows 给它的连接名由系统
     * 决定（"Local Area Connection"，重装后带序号），而 route_setup 与 netsh
     * 只认名字 —— 先把它对上我们约定的别名。WFP 平面的内层适配器是用户用
     * KM-TEST 建的、名字由 --dev 给定，不走这一步。 */
    if (device_path != NULL && wcscmp(device_path, IWAN_WIN_USER_PATH_MP) == 0 &&
        !route_iface_ensure_name(tun, IWAN_WIN_MP_ADAPTER_DESC)) {
        log_err("Windows 内核数据面: 找不到描述为 \"%s\" 的内层适配器"
                "（--dev %s）", IWAN_WIN_MP_ADAPTER_DESC, tun);
        rc = -1;
        goto out;
    }

    if (routes.n > 0 || routes6.n > 0) {
        if (!route_setup(tun, auth_tun_ip, auth_mtu, server, ogw, odev,
                         ometric, &routes, &routes6)) {
            log_err("Windows 内核数据面: 地址/路由配置失败（route_setup 已回滚）");
            rc = -1;
            goto out;
        }
        routes_up = true;
        iface_up = true;
        log_info("tun %s ready: %llu route%s", tun,
                 (unsigned long long)routes.n, routes.n == 1 ? "" : "s");
    } else {
        if (!route_iface_up(tun, auth_tun_ip, auth_mtu)) {
            route_rollback_v6(tun, auth_tun_ip, &routes6);
            route_iface_down(tun);
            log_err("Windows 内核数据面: 适配器 %s 起不来", tun);
            rc = -1;
            goto out;
        }
        iface_up = true;
        log_info("tun %s up with IP %s (no route hijack)", tun, auth_tun_ip);
    }

    /* 4) 建立内核会话：数据面从此交给驱动 */
    if (windev_session_open(d, &req, targets, ntargets, &info,
                            err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows 内核数据面: 建立会话失败: %s", err);
        rc = -1;
        goto out;
    }
    session_up = true;
    log_info("内核数据面: 会话已建立 dev=%s mtu=%u carrier_mtu=%u sid=%u",
             tun, (unsigned)info.effective_mtu, (unsigned)req.carrier_mtu,
             (unsigned)info.sid);

    /* 5) 存活共享内存页（驱动建立会话时已映射好，这里只是取指针） */
    if (windev_shm_map(d, &shm, err, sizeof(err)) != WINDEV_OK) {
        log_err("Windows 内核数据面: %s", err);
        rc = -1;
        goto out;
    }

    ka_ms = pump_keepalive_ms();
    ka_fail_max = pump_ka_fail_max();
    stale = pump_rx_stale_ms();
    t_up = now_ms();
    last_ka = t_up;
    next_tick = t_up;

    /* 6) 主循环：与 kdp.c 同一节拍（100ms 睡眠、1s 判定、10s keepalive） */
    while (!g_stop && !g_user_stop) {
        uint64_t now, lr;

        port_sleep_ms(KDP_WIN_SLEEP_MS);
        now = now_ms();
        if (now < next_tick)
            continue;
        next_tick = now + KDP_WIN_POLL_MS;

        /* 6a) 会话还在不在（驱动被卸载、被别的客户端接管都会让它失效） */
        if (windev_session_get(d, &info, err, sizeof(err)) != WINDEV_OK ||
            info.enabled == 0) {
            log_err("Windows 内核数据面: 会话已失效（%s），会话丢失",
                    err[0] != '\0' ? err : "驱动报告有效位为 0");
            session_lost = true;
            break;
        }

        /* 6b) 存活：时间戳 0 = 对端 PT_CLOSE / 会话被清；新时间戳 = 对端活着 */
        lr = windev_shm_last_rx_ms(shm);
        if (lr != 0) {
            if (!seen_rx) {
                seen_rx = true;
                log_info("内核数据面: 收到对端首个有效帧（共享内存时间戳已非零）");
            }
            /* 只有"收到新帧"才清零失败预算：一次成功的 send 不证明对端存在，
             * 连通 UDP 套接字会把 ICMP 端口不可达隔次上报。 */
            if (lr != last_seen)
                ka_fail = 0;
            last_seen = lr;
        } else if (seen_rx) {
            log_err("内核数据面: 共享内存时间戳归零"
                    "（对端 PT_CLOSE / 会话被清），会话丢失");
            session_lost = true;
            break;
        }
        if (stale != 0) {
            /* 从未收到过帧时从"会话建立时刻"起算（kdp.c 的 t_up 同义） */
            uint64_t quiet = seen_rx ? kdp_win_ms_since(now, last_seen)
                                     : kdp_win_ms_since(now, t_up);
            if (quiet > stale) {
                log_err("内核数据面: %llu ms 没有收到任何有效帧"
                        "（IWAN_RX_STALE_MS=%u），会话丢失",
                        (unsigned long long)quiet, stale);
                session_lost = true;
                break;
            }
        }

        /* 6c) keepalive 仍在用户态（10s PT_ECHO_REQ，走客户端自己的套接字） */
        if (ka_ms != 0 && kdp_win_ms_since(now, last_ka) >= ka_ms) {
            buf_t pkt;

            buf_init(&pkt);
            ctrl_hdr(&pkt, PT_ECHO_REQ, enc, sid, tok);
            {
                ssize_t w = port_send(sockfd, pkt.data, pkt.len, 0);

                if (w < 0 || (size_t)w != pkt.len) {
                    int e = errno;

                    buf_free(&pkt);
                    if (++ka_fail >= ka_fail_max) {
                        log_err("内核数据面: 无下行帧期间 keepalive 失败累计 %u 次"
                                "（最后错误: %s）；会话丢失", ka_fail,
                                strerror(e));
                        session_lost = true;
                        break;
                    }
                    err_printf("内核数据面: keepalive 发送失败: %s"
                               "（无下行帧期间累计 %u/%u）\n", strerror(e),
                               ka_fail, ka_fail_max);
                }
            }
            buf_free(&pkt);
            /* 成功与否都推进节奏：失败要每 ka_ms 重试一次 */
            last_ka = now_ms();
        }
    }

    /* 7) 退出：先礼后兵 —— PT_CLOSE、统计、撤会话、撤地址路由 */
    if (session_up) {
        buf_t pkt;

        buf_init(&pkt);
        ctrl_hdr(&pkt, PT_CLOSE, enc, sid, tok);
        if (port_send(sockfd, pkt.data, pkt.len, 0) < 0)
            log_debug("内核数据面: PT_CLOSE 发送失败: %s", strerror(errno));
        else
            err_printf("CLOSE sent\n");
        buf_free(&pkt);
    }

    if (session_up) {
        /* 口径与 Linux 侧一致：tx_bytes 是外层字节（含封装开销）。
         * M1 只有出向封装，所以 rx_delivered 为 0 属正常（入向解封在 M2）。 */
        log_info("内核数据面: 统计 收外层 %llu 帧（交付 %llu），"
                 "发 %llu 帧 / %llu 字节，丢弃 %llu，异常 %llu",
                 (unsigned long long)info.stats.rx_outer,
                 (unsigned long long)info.stats.rx_delivered,
                 (unsigned long long)info.stats.tx_pkts,
                 (unsigned long long)info.stats.tx_bytes,
                 (unsigned long long)info.stats.ev_dropped,
                 (unsigned long long)info.stats.tx_err);
    }

out:
    if (routes_up)
        route_teardown(tun, server, ogw, odev, ometric, &routes);
    else if (iface_up)
        route_iface_down(tun);
    if (session_up)
        (void)windev_session_close(d, err, sizeof(err));
    if (d != NULL)
        windev_close(d);
    free(targets);
    slist_free(&routes);
    slist_free(&routes6);
    slist_free(&empty);

    if (rc == 0 && session_lost)
        rc = 1;         /* 会话丢失：调用者应重连（与 kdp_run 同义） */
    return rc;
}

#endif /* _WIN32 */
