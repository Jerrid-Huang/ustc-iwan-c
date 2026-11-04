/*
 * iWAN kernel data plane genetlink control-plane client (Linux only).
 *
 * Approach is identical to kernel/tests/iwan_ctl.c: plain libc, hand-built nlmsghdr/nlattr,
 * CTRL_CMD_GETFAMILY to resolve the family id (equivalent to libnl's genl_ctrl_resolve), no new
 * dependencies. The only difference is error handling: this file is library code, on failure it returns a negative errno + err text,
 * it does not exit().
 *
 * Thread model: one genl_iwan corresponds to one socket, used single-threaded (kdp.c's supervision loop).
 *
 * Beware libc's UAPI macros: linux/netlink.h's NLMSG and NLA macros are unusable under
 * -Wsign-conversion (the "& ~3" in the expansion implicitly converts int -4 to size_t,
 * and the CI red line is -Werror). The GENL constants/functions below are semantically identical to those macros,
 * only every step uses explicit casts.
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

/* Alignment/header lengths (equivalent to NLMSG_ALIGN / NLMSG_HDRLEN / NLA_ALIGN / NLA_HDRLEN) */
#define GENL_ALIGN4(n)   (((size_t)(n) + 3u) & ~(size_t)3u)
#define GENL_NLMSG_HDR   ((int)sizeof(struct nlmsghdr))
#define GENL_GENL_HDR    ((int)sizeof(struct genlmsghdr))
#define GENL_NLA_HDR     ((size_t)sizeof(struct nlattr))

/* Pin at compile time that "the header uses an 8-byte key": IWAN_KEY_LEN comes from the frozen ABI. */
_Static_assert(IWAN_KEY_LEN == 8, "IWAN_KEY_LEN changed; sync genl_iwan_session");

struct genl_iwan {
    int      fd;
    bool     resolved;
    uint16_t fam_id;
    int      grp_id;    /* -1 = family has no events group */
    uint32_t seq;
};

/* ------------------------------------------------------------ message construction */

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

/* host-order address -> htonl, then into the attribute (byte-order conversion happens only once, at this layer) */
/* 16-byte address (outer v6 endpoint / egress v6 IP) goes into the attribute as-is: the kernel validates it as
 * NLA_BINARY + exactly 16 bytes; the byte order is network order (in6_addr already is) */
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

/* host-order port -> htons, then into the attribute */
static bool nla_put_port(struct genl_req *r, uint16_t t, uint16_t host)
{
    uint16_t be = htons(host);

    return nla_put(r, t, &be, sizeof(be));
}

static bool nla_put_str(struct genl_req *r, uint16_t t, const char *s)
{
    return nla_put(r, t, s, strlen(s) + 1);
}

/* ------------------------------------------------------------ attribute parsing */

/* NLA_OK/NLA_NEXT are kernel-internal macros (include/net/netlink.h), absent from UAPI headers;
 * we provide our own with the same semantics (consistent with iwan_ctl.c). */
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
            tb[t] = (struct nlattr *)(void *)nla;   /* read-only use */
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

/* be32 attribute -> host-order address (read direction; for write see nla_put_addr) */
static bool attr_addr(struct nlattr *const *tb, int t, uint32_t *out)
{
    uint32_t be;

    if (tb[t] == NULL || nla_payload_len(tb[t]) < (int)sizeof(be))
        return false;
    memcpy(&be, nla_data(tb[t]), sizeof(be));
    *out = ntohl(be);
    return true;
}

/* 16-byte address attribute -> struct in6_addr (read direction). Length must be exactly 16:
 * the kernel emits it with NLA_BINARY(.len=16) + explicit length check; anything shorter means a broken ABI. */
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

/* ------------------------------------------------------------ socket */

genl_iwan *genl_iwan_open(char *err, size_t errsz)
{
    struct genl_iwan *g;
    struct sockaddr_nl sa;
    struct timeval tv;

    g = calloc(1, sizeof(*g));
    if (g == NULL) {
        snprintf(err, errsz, "out of memory");
        return NULL;
    }
    g->grp_id = -1;
    g->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (g->fd < 0) {
        snprintf(err, errsz, "failed to create genetlink socket: %s", strerror(errno));
        free(g);
        return NULL;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(g->fd, (struct sockaddr *)(void *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errsz, "failed to bind genetlink socket: %s", strerror(errno));
        close(g->fd);
        free(g);
        return NULL;
    }
    /* reply timeout: report an error instead of hanging when the kernel does not answer */
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(g->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        snprintf(err, errsz, "failed to set genetlink timeout: %s", strerror(errno));
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

/* Send one request and wait for the reply. Returns 0 or a negative errno; reply carries the first data message
 * (genlmsghdr + attributes). Semantics match nl_talk in iwan_ctl.c: with NLM_F_ACK
 * it first receives the data message and then waits for the ACK; receiving only the data message also counts as success. */
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
                continue;   /* not a reply to this request (event seq=0 also lands here) */
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e =
                    (const struct nlmsgerr *)nlmsg_data(h);

                if (e->error != 0)
                    return e->error;    /* negative errno */
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

/* Append a "module not loaded?" hint to err; the caller supplies the operation name. */
static void err_from_errno(char *err, size_t errsz, const char *what, int e)
{
    snprintf(err, errsz, "%s failed: %s (kernel module iwan not loaded or version mismatch?)",
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
        snprintf(err, errsz, "failed to build the family query message");
        return -EMSGSIZE;
    }
    e = nl_talk(g, &r, reply, sizeof(reply), &rl);
    if (e != 0) {
        if (e == -ETIMEDOUT)
            snprintf(err, errsz,
                     "querying genetlink family \"%s\" timed out: kernel module iwan not loaded"
                     " (insmod iwan.ko), or not built from the same batch as the client",
                     IWAN_GENL_NAME);
        else
            err_from_errno(err, errsz, "query genetlink family \"iwan\"", e);
        return e;
    }
    if (rl < (size_t)GENL_GENL_HDR) {
        snprintf(err, errsz, "family query reply too short (%llu bytes)",
                 (unsigned long long)rl);
        return -EIO;
    }
    parse_attrs(reply + GENL_GENL_HDR, (int)rl - GENL_GENL_HDR, tb,
                CTRL_ATTR_MAX + 1);
    if (!attr_u16(tb, CTRL_ATTR_FAMILY_ID, &fam_id) || fam_id == 0) {
        snprintf(err, errsz, "kernel reply has no CTRL_ATTR_FAMILY_ID");
        return -EIO;
    }

    /* the events group is optional (diagnostic channel): failure to resolve it is not an error, it is just absent */
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

/* ------------------------------------------------------------ commands */

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
    /* SPORT is always given explicitly: the value stored by the module on the first call participates in idempotent comparison; omitting it stores 0,
     * and explicitly giving it later returns -EINVAL directly (CONTROL-PLANE.md section 10.2) */
    if (!nla_put_u16(&r, IWAN_A_SID, s->sid) ||
        !nla_put_u32(&r, IWAN_A_TOK, s->tok) ||
        !nla_put_u8(&r, IWAN_A_ENC, s->enc) ||
        !nla_put(&r, IWAN_A_KEY, s->key, IWAN_KEY_LEN) ||
        /* Outer endpoint: send only one pair according to the family -- the kernel decides the family by "which pair was given"; giving both pairs
         * returns -EINVAL (switching family means rebuilding the session, not changing one address) */
        (s->outer_v6 ?
             (!nla_put_addr6(&r, IWAN_A_OUTER_SRC6, &s->outer_src6) ||
              !nla_put_addr6(&r, IWAN_A_OUTER_DST6, &s->outer_dst6)) :
             (!nla_put_addr(&r, IWAN_A_OUTER_SRC, s->outer_src) ||
              !nla_put_addr(&r, IWAN_A_OUTER_DST, s->outer_dst))) ||
        !nla_put_port(&r, IWAN_A_DPORT, s->dport) ||
        !nla_put_port(&r, IWAN_A_SPORT, s->sport) ||
        !nla_put_u32(&r, IWAN_A_FLAGS, flags) ||
        /* Binding spec: never send 0 (= unbound), preserving the old client's per-bit semantics */
        (s->oif != 0 && !nla_put_u32(&r, IWAN_A_OIF, s->oif)) ||
        (s->outer_v6 ?
             (!IN6_IS_ADDR_UNSPECIFIED(&s->bind_ip6) &&
              !nla_put_addr6(&r, IWAN_A_IP6, &s->bind_ip6)) :
             (s->bind_ip != 0 && !nla_put_addr(&r, IWAN_A_IP, s->bind_ip))) ||
        (s->mtu != 0 && !nla_put_u32(&r, IWAN_A_MTU, s->mtu))) {
        snprintf(err, errsz, "failed to build the SESSION_UP message (attribute too long)");
        return -EMSGSIZE;
    }

    e = nl_talk(g, &r, reply, sizeof(reply), &rl);
    if (e != 0) {
        if (e == -EBUSY)
            snprintf(err, errsz,
                     "SESSION_UP failed: device name is taken (-EBUSY) -- "
                     "iwan0 already exists and is not a device created by the iwan module; "
                     "delete it first (ip link del iwan0) or use --data-plane tun");
        else if (e == -EINVAL)
            snprintf(err, errsz,
                     "SESSION_UP failed: parameters rejected (-EINVAL) -- two possibilities: "
                     "(1) this netns already has a session and parameters drifted (sid/tok/key/enc/outer endpoint/"
                     "sport/oif/bound IP, any item inconsistent with the entry in the kernel; you must "
                     "SESSION_DOWN and rebuild first); (2) the parameters themselves are out of range (inner MTU exceeds the module's "
                     "max_mtu, default 1500; ENC/FLAGS invalid; outer address or port is 0). "
                     "The kernel log has the specific field and value: sudo dmesg | grep iwan");
        else if (e == -ENODEV || e == -EOPNOTSUPP)
            snprintf(err, errsz,
                     "SESSION_UP failed: %s (kernel cannot create the device on demand? the module must be built from the same "
                     "batch as this client)", strerror(-e));
        else
            err_from_errno(err, errsz, "SESSION_UP", e);
        return e;
    }

    parse_attrs(reply + GENL_GENL_HDR, (int)rl - GENL_GENL_HDR, tb,
                IWAN_A_MAX + 1);
    if (!attr_str(tb, IWAN_A_DEVNAME, dev, devsz) || dev[0] == '\0' ||
        strcmp(dev, "-") == 0) {
        /* Reply lacks DEVNAME (or the kernel returned the "no session" placeholder "-"): continue with the designed default name,
         * but say so -- otherwise later "-" is used as the interface name for address/route setup and the error is incomprehensible */
        if (devsz != 0)
            snprintf(dev, devsz, "iwan0");
        log_err("IWAN_A_DEVNAME in the SESSION_UP reply is unusable; treating it as \"iwan0\"");
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
    /* Outer v6 sessions: the kernel emits these three attributes only in that case; "present or not" is the family criterion
     * (see the explanation at the reply site in kernel/iwan_netlink.c). */
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
        snprintf(err, errsz, "family \"%s\" has no multicast group \"%s\"",
                 IWAN_GENL_NAME, IWAN_GENL_MCGRP_EVENTS);
        return -ENOENT;
    }
    one = g->grp_id;
    if (setsockopt(g->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &one,
                   sizeof(one)) < 0) {
        snprintf(err, errsz, "failed to join multicast group \"%s\"(id=%d): %s",
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

            /* event: nlmsg_type == fam_id and nlmsg_seq == 0 -- cannot filter by seq
             * (same criterion as CONTROL-PLANE.md / iwan_ctl.c) */
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
