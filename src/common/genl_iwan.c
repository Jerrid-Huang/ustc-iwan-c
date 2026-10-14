/*
 * iWAN 内核数据面的 genetlink 控制面客户端（Linux only）。
 *
 * 手法与 kernel/tests/iwan_ctl.c 完全一致：纯 libc、自己拼 nlmsghdr/nlattr、
 * CTRL_CMD_GETFAMILY 解析家族 id（等价 libnl 的 genl_ctrl_resolve），不引入
 * 新依赖。区别只在错误处理：本文件是库代码，失败返回负 errno + 中文 err 文本，
 * 不 exit()。
 *
 * 线程模型：一个 genl_iwan 对应一个套接字，单线程使用（kdp.c 的监督循环）。
 *
 * 注意 libc 的 UAPI 宏：linux/netlink.h 的 NLMSG 与 NLA 宏在
 * -Wsign-conversion 下不可用（展开式里的 "& ~3" 把 int -4 隐式转成 size_t，
 * 而 CI 红线是 -Werror）。下面的 GENL 常量/函数与那些宏语义完全相同，
 * 只是每一步都显式转换。
 */

#if defined(__linux__)

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "genl_iwan.h"
#include "util.h"

#define GENL_BUF 8192

/* 对齐/头部长度（等价 NLMSG_ALIGN / NLMSG_HDRLEN / NLA_ALIGN / NLA_HDRLEN） */
#define GENL_ALIGN4(n)   (((size_t)(n) + 3u) & ~(size_t)3u)
#define GENL_NLMSG_HDR   ((int)sizeof(struct nlmsghdr))
#define GENL_GENL_HDR    ((int)sizeof(struct genlmsghdr))
#define GENL_NLA_HDR     ((size_t)sizeof(struct nlattr))

/* 编译期钉住"头文件用了 8 字节密钥"这一条：IWAN_KEY_LEN 来自冻结 ABI。 */
_Static_assert(IWAN_KEY_LEN == 8, "IWAN_KEY_LEN 变了，同步 genl_iwan_session");

struct genl_iwan {
    int      fd;
    bool     resolved;
    uint16_t fam_id;
    int      grp_id;    /* -1 = 家族没有 events 组 */
    uint32_t seq;
};

/* ------------------------------------------------------------ 消息构造 */

struct genl_req {
    uint8_t          buf[GENL_BUF];
    struct nlmsghdr *nlh;
};

static void *nlmsg_data(struct nlmsghdr *h)
{
    return (void *)((char *)(void *)h + sizeof(*h));
}

static bool nlmsg_ok(const struct nlmsghdr *h, int rem)
{
    return rem >= GENL_NLMSG_HDR && h->nlmsg_len >= sizeof(*h) &&
           h->nlmsg_len <= (uint32_t)rem;
}

static struct nlmsghdr *nlmsg_next(struct nlmsghdr *h, int *rem)
{
    int step = (int)GENL_ALIGN4(h->nlmsg_len);

    *rem -= step;
    return (struct nlmsghdr *)(void *)((char *)(void *)h + step);
}

static void req_init(struct genl_iwan *g, struct genl_req *r, uint16_t type,
                     uint16_t flags, uint8_t cmd)
{
    struct genlmsghdr *gh;

    memset(r, 0, sizeof(*r));
    r->nlh = (struct nlmsghdr *)(void *)r->buf;
    r->nlh->nlmsg_len = (uint32_t)(GENL_NLMSG_HDR + GENL_GENL_HDR);
    r->nlh->nlmsg_type = type;
    r->nlh->nlmsg_flags = flags;
    r->nlh->nlmsg_seq = ++g->seq;
    r->nlh->nlmsg_pid = 0;
    gh = (struct genlmsghdr *)nlmsg_data(r->nlh);
    gh->cmd = cmd;
    gh->version = IWAN_GENL_VERSION;
    gh->reserved = 0;
}

static bool nla_put(struct genl_req *r, uint16_t type, const void *data,
                    size_t len)
{
    size_t off = GENL_ALIGN4(r->nlh->nlmsg_len);
    struct nlattr *nla;

    if (off + GENL_NLA_HDR + len > sizeof(r->buf))
        return false;
    nla = (struct nlattr *)(void *)(r->buf + off);
    nla->nla_type = type;
    nla->nla_len = (uint16_t)(GENL_NLA_HDR + len);
    if (len != 0 && data != NULL)
        memcpy((char *)(void *)nla + GENL_NLA_HDR, data, len);
    r->nlh->nlmsg_len = (uint32_t)(off + GENL_NLA_HDR + len);
    return true;
}

static bool nla_put_u8(struct genl_req *r, uint16_t t, uint8_t v)
{
    return nla_put(r, t, &v, sizeof(v));
}

static bool nla_put_u16(struct genl_req *r, uint16_t t, uint16_t v)
{
    return nla_put(r, t, &v, sizeof(v));
}

static bool nla_put_u32(struct genl_req *r, uint16_t t, uint32_t v)
{
    return nla_put(r, t, &v, sizeof(v));
}

/* 主机序地址 -> htonl 后再进属性（字节序转换只在这一层做一次） */
/* 16 字节地址（外层 v6 端点 / 出口 v6 IP）原样进属性：内核侧按
 * NLA_BINARY + 长度恰好 16 校验，字节序就是网络序（in6_addr 本来就是） */
static bool nla_put_addr6(struct genl_req *r, uint16_t t,
                          const struct in6_addr *a)
{
    return nla_put(r, t, a, sizeof(*a));
}

static bool nla_put_addr(struct genl_req *r, uint16_t t, uint32_t host)
{
    uint32_t be = htonl(host);

    return nla_put(r, t, &be, sizeof(be));
}

/* 主机序端口 -> htons 后再进属性 */
static bool nla_put_port(struct genl_req *r, uint16_t t, uint16_t host)
{
    uint16_t be = htons(host);

    return nla_put(r, t, &be, sizeof(be));
}

static bool nla_put_str(struct genl_req *r, uint16_t t, const char *s)
{
    return nla_put(r, t, s, strlen(s) + 1);
}

/* ------------------------------------------------------------ 属性解析 */

/* NLA_OK/NLA_NEXT 是内核内部宏（include/net/netlink.h），UAPI 头里没有；
 * 按同样语义自己写一份（与 iwan_ctl.c 一致）。 */
static bool nla_ok(const struct nlattr *nla, int rem)
{
    return rem >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
           (int)nla->nla_len <= rem;
}

static struct nlattr *nla_next(const struct nlattr *nla, int *rem)
{
    int step = (int)GENL_ALIGN4(nla->nla_len);

    *rem -= step;
    return (struct nlattr *)(void *)((char *)(const void *)nla + step);
}

static void parse_attrs(const void *data, int len, struct nlattr **tb, int max)
{
    const struct nlattr *nla;
    int rem = len;

    memset(tb, 0, sizeof(*tb) * (size_t)max);
    for (nla = (const struct nlattr *)data; nla_ok(nla, rem);
         nla = nla_next(nla, &rem)) {
        int t = (int)(nla->nla_type & NLA_TYPE_MASK);

        if (t > 0 && t < max)
            tb[t] = (struct nlattr *)(void *)nla;   /* 只读使用 */
    }
}

static int nla_payload_len(const struct nlattr *nla)
{
    return (int)nla->nla_len - (int)GENL_NLA_HDR;
}

static const void *nla_data(const struct nlattr *nla)
{
    return (const void *)((const char *)(const void *)nla + GENL_NLA_HDR);
}

static bool attr_u8(struct nlattr *const *tb, int t, uint8_t *out)
{
    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(*out))
        return false;
    memcpy(out, nla_data(tb[t]), sizeof(*out));
    return true;
}

static bool attr_u16(struct nlattr *const *tb, int t, uint16_t *out)
{
    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(*out))
        return false;
    memcpy(out, nla_data(tb[t]), sizeof(*out));
    return true;
}

static bool attr_u32(struct nlattr *const *tb, int t, uint32_t *out)
{
    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(*out))
        return false;
    memcpy(out, nla_data(tb[t]), sizeof(*out));
    return true;
}

/* be32 属性 -> 主机序地址（读方向；写方向见 nla_put_addr） */
static bool attr_addr(struct nlattr *const *tb, int t, uint32_t *out)
{
    uint32_t be;

    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(be))
        return false;
    memcpy(&be, nla_data(tb[t]), sizeof(be));
    *out = ntohl(be);
    return true;
}

/* 16 字节地址属性 -> struct in6_addr（读方向）。长度必须恰好 16：
 * 内核按 NLA_BINARY(.len=16) + 显式长度校验发出来，短了就是 ABI 不对。 */
static bool attr_addr6(struct nlattr *const *tb, int t, struct in6_addr *out)
{
    if (tb[t] == NULL || nla_payload_len(tb[t]) != (int)sizeof(*out))
        return false;
    memcpy(out, nla_data(tb[t]), sizeof(*out));
    return true;
}

static bool attr_u64(struct nlattr *const *tb, int t, uint64_t *out)
{
    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(*out))
        return false;
    memcpy(out, nla_data(tb[t]), sizeof(*out));
    return true;
}

static bool attr_str(struct nlattr *const *tb, int t, char *out, size_t outsz)
{
    int l;

    if (tb[t] == NULL || outsz == 0)
        return false;
    l = nla_payload_len(tb[t]);
    if (l <= 0)
        return false;
    if ((size_t)l > outsz)
        l = (int)outsz;
    memcpy(out, nla_data(tb[t]), (size_t)l);
    out[l - 1] = '\0';
    return true;
}

/* ------------------------------------------------------------ 套接字 */

genl_iwan *genl_iwan_open(char *err, size_t errsz)
{
    struct genl_iwan *g;
    struct sockaddr_nl sa;
    struct timeval tv;

    g = calloc(1, sizeof(*g));
    if (g == NULL) {
        snprintf(err, errsz, "内存不足");
        return NULL;
    }
    g->grp_id = -1;
    g->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (g->fd < 0) {
        snprintf(err, errsz, "创建 genetlink 套接字失败: %s", strerror(errno));
        free(g);
        return NULL;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(g->fd, (struct sockaddr *)(void *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errsz, "绑定 genetlink 套接字失败: %s", strerror(errno));
        close(g->fd);
        free(g);
        return NULL;
    }
    /* 回执超时：内核没应答时报错而不是挂死 */
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(g->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        snprintf(err, errsz, "设置 genetlink 超时失败: %s", strerror(errno));
        close(g->fd);
        free(g);
        return NULL;
    }
    return g;
}

void genl_iwan_close(genl_iwan *g)
{
    if (g == NULL)
        return;
    if (g->fd >= 0)
        close(g->fd);
    free(g);
}

/* 发一条请求并等回执。返回 0 或负 errno；reply 带回第一条数据消息
 * （genlmsghdr + 属性）。语义与 iwan_ctl.c 的 nl_talk 一致：带 NLM_F_ACK
 * 时先收数据消息再等 ACK，只收到数据消息时也算成功。 */
static int nl_talk(struct genl_iwan *g, struct genl_req *r, char *reply,
                   size_t replysz, size_t *replylen)
{
    struct sockaddr_nl dst;
    char buf[GENL_BUF];
    bool want_ack = (r->nlh->nlmsg_flags & NLM_F_ACK) != 0;

    if (replylen != NULL)
        *replylen = 0;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    if (sendto(g->fd, r->buf, r->nlh->nlmsg_len, 0,
               (struct sockaddr *)(void *)&dst, sizeof(dst)) < 0)
        return -errno;

    for (;;) {
        ssize_t n = recv(g->fd, buf, sizeof(buf), 0);
        int rem;
        struct nlmsghdr *h;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return (replylen != NULL && *replylen != 0) ? 0 : -ETIMEDOUT;
            return -errno;
        }
        rem = (int)n;
        for (h = (struct nlmsghdr *)(void *)buf; nlmsg_ok(h, rem);
             h = nlmsg_next(h, &rem)) {
            if (h->nlmsg_seq != r->nlh->nlmsg_seq)
                continue;   /* 不是本请求的回执（事件 seq=0 也走这里） */
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e =
                    (const struct nlmsgerr *)nlmsg_data(h);

                if (e->error != 0)
                    return e->error;    /* 负 errno */
                return 0;               /* ACK */
            }
            if (h->nlmsg_type == NLMSG_DONE)
                return 0;
            if (reply != NULL && replysz != 0) {
                size_t l = (size_t)h->nlmsg_len -
                           (size_t)GENL_NLMSG_HDR;

                if (l > replysz)
                    l = replysz;
                memcpy(reply, nlmsg_data(h), l);
                if (replylen != NULL)
                    *replylen = l;
            }
            if (!want_ack)
                return 0;
        }
    }
}

/* err 里补一条"模块没加载？"的提示；调用方给操作名。 */
static void err_from_errno(char *err, size_t errsz, const char *what, int e)
{
    snprintf(err, errsz, "%s 失败: %s（内核模块 iwan 未加载或版本不匹配？）",
             what, strerror(e < 0 ? -e : e));
}

int genl_iwan_resolve(genl_iwan *g, char *err, size_t errsz)
{
    struct genl_req r;
    char reply[GENL_BUF];
    size_t rl = 0;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    uint16_t fam_id = 0;
    int grp_id = -1;
    int e;

    if (g->resolved)
        return 0;

    req_init(g, &r, GENL_ID_CTRL, NLM_F_REQUEST, CTRL_CMD_GETFAMILY);
    if (!nla_put_str(&r, CTRL_ATTR_FAMILY_NAME, IWAN_GENL_NAME)) {
        snprintf(err, errsz, "构造家族查询消息失败");
        return -EMSGSIZE;
    }
    e = nl_talk(g, &r, reply, sizeof(reply), &rl);
    if (e != 0) {
        if (e == -ETIMEDOUT)
            snprintf(err, errsz,
                     "查询 genetlink 家族 \"%s\" 超时：内核模块 iwan 未加载"
                     "（insmod iwan.ko），或与客户端不是同批构建",
                     IWAN_GENL_NAME);
        else
            err_from_errno(err, errsz, "查询 genetlink 家族 \"iwan\"", e);
        return e;
    }
    if (rl < (size_t)GENL_GENL_HDR) {
        snprintf(err, errsz, "家族查询回执过短（%zu 字节）", rl);
        return -EIO;
    }
    parse_attrs(reply + GENL_GENL_HDR, (int)rl - GENL_GENL_HDR, tb,
                CTRL_ATTR_MAX + 1);
    if (!attr_u16(tb, CTRL_ATTR_FAMILY_ID, &fam_id) || fam_id == 0) {
        snprintf(err, errsz, "内核回执里没有 CTRL_ATTR_FAMILY_ID");
        return -EIO;
    }

    /* events 组是可选的（诊断通道）：解析不到不算错误，只是没有它 */
    if (tb[CTRL_ATTR_MCAST_GROUPS] != NULL) {
        int glen = nla_payload_len(tb[CTRL_ATTR_MCAST_GROUPS]);
        const struct nlattr *grp;

        for (grp = (const struct nlattr *)nla_data(tb[CTRL_ATTR_MCAST_GROUPS]);
             nla_ok(grp, glen); grp = nla_next(grp, &glen)) {
            struct nlattr *gtb[CTRL_ATTR_MCAST_GRP_MAX + 1];
            char name[64] = "";
            uint32_t id = 0;

            parse_attrs(nla_data(grp), nla_payload_len(grp), gtb,
                        CTRL_ATTR_MCAST_GRP_MAX + 1);
            if (!attr_str(gtb, CTRL_ATTR_MCAST_GRP_NAME, name, sizeof(name)))
                continue;
            if (!attr_u32(gtb, CTRL_ATTR_MCAST_GRP_ID, &id))
                continue;
            if (strcmp(name, IWAN_GENL_MCGRP_EVENTS) == 0)
                grp_id = (int)id;
        }
    }
    g->fam_id = fam_id;
    g->grp_id = grp_id;
    g->resolved = true;
    return 0;
}

/* ------------------------------------------------------------ 命令 */

int genl_iwan_session_up(genl_iwan *g, const genl_iwan_session *s,
                         char *dev, size_t devsz, uint32_t *mtu_out,
                         char *err, size_t errsz)
{
    struct genl_req r;
    char reply[GENL_BUF];
    size_t rl = 0;
    struct nlattr *tb[IWAN_A_MAX + 1];
    uint32_t flags = IWAN_A_FLAG_CREATE_DEV;
    uint32_t rmtu = 0;
    int e;

    if (devsz != 0)
        dev[0] = '\0';
    if (mtu_out != NULL)
        *mtu_out = 0;

    e = genl_iwan_resolve(g, err, errsz);
    if (e != 0)
        return e;

    req_init(g, &r, g->fam_id, NLM_F_REQUEST | NLM_F_ACK,
             IWAN_CMD_SESSION_UP);
    /* SPORT 一律显式给出：模块首次存下的值参与幂等比较，省略会存 0，
     * 之后显式给值直接 -EINVAL（CONTROL-PLANE.md §10.2） */
    if (!nla_put_u16(&r, IWAN_A_SID, s->sid) ||
        !nla_put_u32(&r, IWAN_A_TOK, s->tok) ||
        !nla_put_u8(&r, IWAN_A_ENC, s->enc) ||
        !nla_put(&r, IWAN_A_KEY, s->key, IWAN_KEY_LEN) ||
        /* 外层端点：按族只发一对 —— 内核按"给了哪一对"判族，两对同时给
         * 是 -EINVAL（族的切换是重建会话，不是改一个地址） */
        (s->outer_v6 ?
             (!nla_put_addr6(&r, IWAN_A_OUTER_SRC6, &s->outer_src6) ||
              !nla_put_addr6(&r, IWAN_A_OUTER_DST6, &s->outer_dst6)) :
             (!nla_put_addr(&r, IWAN_A_OUTER_SRC, s->outer_src) ||
              !nla_put_addr(&r, IWAN_A_OUTER_DST, s->outer_dst))) ||
        !nla_put_port(&r, IWAN_A_DPORT, s->dport) ||
        !nla_put_port(&r, IWAN_A_SPORT, s->sport) ||
        !nla_put_u32(&r, IWAN_A_FLAGS, flags) ||
        /* 绑定规格：0 一律不发（= 不绑），保持旧客户端逐位语义不变 */
        (s->oif != 0 && !nla_put_u32(&r, IWAN_A_OIF, s->oif)) ||
        (s->outer_v6 ?
             (!IN6_IS_ADDR_UNSPECIFIED(&s->bind_ip6) &&
              !nla_put_addr6(&r, IWAN_A_IP6, &s->bind_ip6)) :
             (s->bind_ip != 0 && !nla_put_addr(&r, IWAN_A_IP, s->bind_ip))) ||
        (s->mtu != 0 && !nla_put_u32(&r, IWAN_A_MTU, s->mtu))) {
        snprintf(err, errsz, "构造 SESSION_UP 消息失败（属性超长）");
        return -EMSGSIZE;
    }

    e = nl_talk(g, &r, reply, sizeof(reply), &rl);
    if (e != 0) {
        if (e == -EBUSY)
            snprintf(err, errsz,
                     "SESSION_UP 失败: 设备名被占用（-EBUSY）——"
                     "iwan0 已存在且不是 iwan 模块创建的设备，"
                     "请先删除它（ip link del iwan0）或改用 --data-plane tun");
        else if (e == -EINVAL)
            snprintf(err, errsz,
                     "SESSION_UP 失败: 参数被拒（-EINVAL）——两种可能："
                     "①本 netns 已有会话且参数漂移（sid/tok/key/enc/外层端点/"
                     "sport/oif/绑定 IP 任一项与内核里那条不一致，必须先 "
                     "SESSION_DOWN 再重建）；②参数本身越界（内层 MTU 超过模块 "
                     "max_mtu，默认 1500；ENC/FLAGS 非法；外层地址或端口为 0）。"
                     "内核日志里有具体字段与数值：sudo dmesg | grep iwan");
        else if (e == -ENODEV || e == -EOPNOTSUPP)
            snprintf(err, errsz,
                     "SESSION_UP 失败: %s（内核不支持按需建卡？模块需要与本"
                     "客户端同批构建）", strerror(-e));
        else
            err_from_errno(err, errsz, "SESSION_UP", e);
        return e;
    }

    parse_attrs(reply + GENL_GENL_HDR, (int)rl - GENL_GENL_HDR, tb,
                IWAN_A_MAX + 1);
    if (!attr_str(tb, IWAN_A_DEVNAME, dev, devsz) || dev[0] == '\0' ||
        strcmp(dev, "-") == 0) {
        /* 回执缺 DEVNAME（或内核回了"无会话"占位符 "-"）：按设计默认名继续，
         * 但要说出来 —— 否则后面拿 "-" 当接口名去配地址/路由，报错看不懂 */
        if (devsz != 0)
            snprintf(dev, devsz, "iwan0");
        log_err("SESSION_UP 回执的 IWAN_A_DEVNAME 不可用，按 \"iwan0\" 处理");
    }
    if (attr_u32(tb, IWAN_A_MTU, &rmtu) && mtu_out != NULL)
        *mtu_out = rmtu;
    return 0;
}

int genl_iwan_session_down(genl_iwan *g, char *err, size_t errsz)
{
    struct genl_req r;
    int e;

    e = genl_iwan_resolve(g, err, errsz);
    if (e != 0)
        return e;
    req_init(g, &r, g->fam_id, NLM_F_REQUEST | NLM_F_ACK,
             IWAN_CMD_SESSION_DOWN);
    e = nl_talk(g, &r, NULL, 0, NULL);
    if (e != 0)
        err_from_errno(err, errsz, "SESSION_DOWN", e);
    return e;
}

int genl_iwan_get_stats(genl_iwan *g, genl_iwan_stats *st, char *err,
                        size_t errsz)
{
    struct genl_req r;
    char reply[GENL_BUF];
    size_t rl = 0;
    struct nlattr *tb[IWAN_A_MAX + 1];
    struct nlattr *sn[IWAN_S_MAX + 1];
    int e;

    memset(st, 0, sizeof(*st));
    e = genl_iwan_resolve(g, err, errsz);
    if (e != 0)
        return e;
    req_init(g, &r, g->fam_id, NLM_F_REQUEST | NLM_F_ACK, IWAN_CMD_GET_STATS);
    e = nl_talk(g, &r, reply, sizeof(reply), &rl);
    if (e != 0) {
        err_from_errno(err, errsz, "GET_STATS", e);
        return e;
    }
    parse_attrs(reply + GENL_GENL_HDR, (int)rl - GENL_GENL_HDR, tb,
                IWAN_A_MAX + 1);
    (void)attr_u16(tb, IWAN_A_SID, &st->sid);
    (void)attr_u32(tb, IWAN_A_TOK, &st->tok);
    (void)attr_u32(tb, IWAN_A_MTU, &st->mtu);
    (void)attr_u32(tb, IWAN_A_OIF, &st->oif);
    (void)attr_u32(tb, IWAN_A_CARRIER, &st->carrier);
    (void)attr_addr(tb, IWAN_A_IP, &st->bind_ip);
    /* 外层 v6 会话：内核回执里只在这时发这三个属性，"在不在"就是族判据
     * （详见 kernel/iwan_netlink.c 的回执处说明）。 */
    st->outer_v6 = attr_addr6(tb, IWAN_A_OUTER_SRC6, &st->outer_src6);
    (void)attr_addr6(tb, IWAN_A_OUTER_DST6, &st->outer_dst6);
    (void)attr_addr6(tb, IWAN_A_IP6, &st->bind_ip6);
    (void)attr_u64(tb, IWAN_A_LAST_KEEPALIVE_MS, &st->last_keepalive_ms);
    (void)attr_u8(tb, IWAN_A_PEER_STATE, &st->peer_state);
    (void)attr_str(tb, IWAN_A_DEVNAME, st->dev, sizeof(st->dev));
    if (tb[IWAN_A_STATS] != NULL) {
        parse_attrs(nla_data(tb[IWAN_A_STATS]),
                    nla_payload_len(tb[IWAN_A_STATS]), sn, IWAN_S_MAX + 1);
        (void)attr_u64(sn, IWAN_S_RX_FRAMES, &st->rx_frames);
        (void)attr_u64(sn, IWAN_S_RX_CTRL_FRAME, &st->rx_ctrl_frame);
        (void)attr_u64(sn, IWAN_S_RX_DELIVERED, &st->rx_delivered);
        (void)attr_u64(sn, IWAN_S_TX_PKTS, &st->tx_pkts);
        (void)attr_u64(sn, IWAN_S_TX_ERR, &st->tx_err);
    }
    return 0;
}

int genl_iwan_events_subscribe(genl_iwan *g, char *err, size_t errsz)
{
    int one;
    int e = genl_iwan_resolve(g, err, errsz);

    if (e != 0)
        return e;
    if (g->grp_id < 0) {
        snprintf(err, errsz, "家族 \"%s\" 没有多播组 \"%s\"",
                 IWAN_GENL_NAME, IWAN_GENL_MCGRP_EVENTS);
        return -ENOENT;
    }
    one = g->grp_id;
    if (setsockopt(g->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &one,
                   sizeof(one)) < 0) {
        snprintf(err, errsz, "加入多播组 \"%s\"(id=%d) 失败: %s",
                 IWAN_GENL_MCGRP_EVENTS, g->grp_id, strerror(errno));
        return -errno;
    }
    return 0;
}

int genl_iwan_events_drain(genl_iwan *g, genl_iwan_ev_cb cb, void *ud)
{
    int got = 0;

    for (;;) {
        char buf[GENL_BUF];
        ssize_t n = recv(g->fd, buf, sizeof(buf), MSG_DONTWAIT);
        int rem;
        struct nlmsghdr *h;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return got;
            return -1;
        }
        rem = (int)n;
        for (h = (struct nlmsghdr *)(void *)buf; nlmsg_ok(h, rem);
             h = nlmsg_next(h, &rem)) {
            struct genlmsghdr *gh;
            struct nlattr *tb[IWAN_EVA_MAX + 1];
            struct nlattr *fr;
            const uint8_t *fp = NULL;
            size_t flen = 0;
            int alen;

            /* 事件：nlmsg_type == fam_id 且 nlmsg_seq == 0 —— 不能按 seq
             * 过滤（CONTROL-PLANE.md / iwan_ctl.c 的同一口径） */
            if (h->nlmsg_type != g->fam_id)
                continue;
            if (h->nlmsg_len <
                (uint32_t)(GENL_NLMSG_HDR + GENL_GENL_HDR))
                continue;
            gh = (struct genlmsghdr *)nlmsg_data(h);
            alen = (int)h->nlmsg_len - GENL_NLMSG_HDR - GENL_GENL_HDR;
            parse_attrs((const char *)(void *)gh + GENL_GENL_HDR, alen, tb,
                        IWAN_EVA_MAX + 1);
            fr = tb[IWAN_EVA_FRAME];
            if (fr != NULL) {
                int l = nla_payload_len(fr);

                if (l > 0) {
                    fp = (const uint8_t *)nla_data(fr);
                    flen = (size_t)l;
                }
            }
            if (cb != NULL)
                cb(ud, gh->cmd, fp, flen);
            got++;
        }
    }
}

#endif /* __linux__ */
