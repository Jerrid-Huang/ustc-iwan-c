#ifndef IWAN_GENL_IWAN_H
#define IWAN_GENL_IWAN_H

/*
 * iWAN 内核数据面的 genetlink 控制面客户端（Linux only）。
 *
 * ABI 唯一权威是 kernel/iwan_genl.h（冻结），本文件直接 include 它，不复制
 * 常量；设计说明见 kernel/CONTROL-PLANE.md。实现手法照搬
 * kernel/tests/iwan_ctl.c：纯 libc + 自己拼 netlink 消息，不引入
 * libnl/libmnl。
 *
 * 字节序：本文件的入参结构体一律用**主机序**（地址也是如此），转换只在
 * genl_iwan.c 的属性封装处做一次 —— 与 kernel/iwan_genl.h 的"转换只在
 * netlink 边界做一次"一致。
 *
 * Linux-only 的原因与接线方式见 CMakeLists.txt：本文件与 genl_iwan.c、
 * kdp.c 一起只进 Linux 分支；文件体再用 __linux__ 包住，是因为
 * src/iwan_client.c 同时被编进 Windows 的 iwan-winsvc.exe，非 Linux 下
 * include 到它也必须能编过（只有声明消失，没有半成品 stub）。
 */

#if defined(__linux__)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>		/* struct in6_addr（外层 v6 端点） */

#include "../../kernel/iwan_genl.h"

/* IWAN_CMD_SESSION_UP 的会话参数（主机序）。
 *
 * sport 必须**从第一次起就显式给出**并且每次一致：模块把首次 SESSION_UP
 * 的 sport 存下来参与幂等比较，首次省略存 0，之后显式给值会 -EINVAL
 * （见 CONTROL-PLANE.md §10.2）。调用方用 getsockname() 取本地实际端口，
 * 于是"重连换了临时端口"必须先 SESSION_DOWN（kdp.c 就是这么做的）。 */
typedef struct {
    uint16_t sid;
    uint32_t tok;
    uint8_t  enc;                    /* 1 = PT_DATA_ENC + XOR, 0 = 明文 */
    uint8_t  key[IWAN_KEY_LEN];      /* MD5(user||pass)[0..8) */
    uint32_t outer_src;              /* 本端外层地址（v4，主机序） */
    uint32_t outer_dst;              /* 对端外层地址（v4，主机序） */
    /* 外层版本（切片 2）：由**调用方按会话套接字的族**决定，与
     * outer_src/outer_dst 互斥 —— outer_v6=true 时只用下面两个 16 字节
     * 字段，并把 v4 字段留 0（内核侧按"给了哪一对"判族，两对同时给会
     * -EINVAL）。v4 会话必须显式给 outer_v6=false。 */
    bool     outer_v6;
    struct in6_addr outer_src6;      /* 本端外层地址（v6） */
    struct in6_addr outer_dst6;      /* 对端外层地址（v6） */
    uint16_t dport;                  /* 服务器端口，主机序 */
    uint16_t sport;                  /* 本端实际端口，主机序 */
    uint32_t mtu;                    /* 0 = 不带 IWAN_A_MTU（用模块默认） */
    /* 承载网卡绑定（三模式，见 docs/kernel-data-plane.md）：
     *   oif=0, bind_ip=0   什么都不绑：内核按 FIB 解析一次后钉住，路径失效自愈
     *   oif!=0             绑网卡：严格用这张接口，失败逐包拒绝（不漂移）
     *   bind_ip!=0         绑 IP：内核按地址表解析出持有该地址的接口，
     *                      等价于绑那张接口；该地址同时是外层头的源地址，
     *                      所以必须等于 outer_src（内核会 -EINVAL 拒绝不一致）
     * 两者同时给出时必须指向同一张接口（内核 -EINVAL 拒绝）。 */
    uint32_t oif;                    /* 绑定的承载网卡 ifindex，0 = 不绑 */
    uint32_t bind_ip;                /* 绑定的出口 IP（v4，主机序），0 = 不绑 */
    /* 绑定的出口 v6 地址：全零 = 不绑（语义与 bind_ip 逐条对应：必须等于
     * outer_src6、必须是本机地址、与 oif 同时给出时必须同接口） */
    struct in6_addr bind_ip6;
} genl_iwan_session;

/* GET_STATS 快照（诊断用；判断"有没有会话"看 sid==0 && tok==0，
 * 不要看 dev 是否为空 —— 无会话时 DEVNAME 是 "-" 而不是空串）。 */
typedef struct {
    uint16_t sid;
    uint32_t tok;
    char     dev[16];
    uint32_t mtu;
    uint64_t last_keepalive_ms;
    uint8_t  peer_state;             /* enum iwan_peer_state */
    uint64_t rx_frames;
    uint64_t rx_ctrl_frame;
    uint64_t rx_delivered;
    uint64_t tx_pkts;
    uint64_t tx_err;                 /* 数据面在外层查找阶段丢弃的分组数
                                      * （显式绑定不可用时只会涨这一项） */
    /* 绑定状态（只读导出，用于对账）：请求的绑定规格 + 实际生效的承载网卡 */
    uint32_t oif;                    /* 请求的绑定网卡，0 = 未指定 */
    uint32_t bind_ip;                /* 请求的绑定出口 IP（v4），0 = 未指定 */
    uint32_t carrier;                /* 实际承载网卡 ifindex，0 = 尚未解析 */
    /* 外层 v6 会话才有效的三项：回执里"属性在不在"就是族判据
     * （v4 会话这三个属性一个都不发） */
    bool     outer_v6;
    struct in6_addr outer_src6;
    struct in6_addr outer_dst6;
    struct in6_addr bind_ip6;
} genl_iwan_stats;

/* 事件回调（events 组是可选/诊断通道，见 kdp.c 的用法）。
 * ev = enum iwan_genl_event，frame = IWAN_EVA_FRAME 原始字节（可为 NULL）。 */
typedef void (*genl_iwan_ev_cb)(void *ud, uint8_t ev, const uint8_t *frame,
                                size_t len);

typedef struct genl_iwan genl_iwan;

/* 打开 genetlink 套接字。失败返回 NULL 并把中文原因写进 err。 */
genl_iwan *genl_iwan_open(char *err, size_t errsz);
void genl_iwan_close(genl_iwan *g);

/* 解析家族 id（+ 可选的 events 组 id），幂等；0 成功，负 errno 失败。 */
int genl_iwan_resolve(genl_iwan *g, char *err, size_t errsz);

/* IWAN_CMD_SESSION_UP（幂等重放）。0 成功；负 errno 失败。
 *
 * 成功时 dev/devsz 收到回执里的 IWAN_A_DEVNAME（属性缺失、为空或内核回了
 * 无会话占位符 "-" 时回落 "iwan0" 并记一条 log_err），mtu_out 收到实测
 * MTU（可为 NULL）。
 *
 * 设备归属只在这里的回执契约内处理：不回执可选的 IWAN_A_DEV_OWNED
 * 一类新增属性的值（枚举常量无法用 #ifdef 探测，硬引用会与"冻结 ABI"的
 * 编译顺序打架）；"iwan0 已被非 iwan 设备占用"由 kdp.c 的启动前
 * `ip -d link show dev iwan0` 预检 + SESSION_UP 回 -EBUSY 两条腿覆盖。 */
int genl_iwan_session_up(genl_iwan *g, const genl_iwan_session *s,
                         char *dev, size_t devsz, uint32_t *mtu_out,
                         char *err, size_t errsz);

/* IWAN_CMD_SESSION_DOWN：清零凭据并删除模块创建的那张网卡。 */
int genl_iwan_session_down(genl_iwan *g, char *err, size_t errsz);

/* IWAN_CMD_GET_STATS（本 netns 视图）。 */
int genl_iwan_get_stats(genl_iwan *g, genl_iwan_stats *st, char *err,
                        size_t errsz);

/* 可选：加入 "events" 多播组。家族没有该组或失败都只返回 -1，调用方按
 * 诊断通道处理，绝不因此判定数据面不可用。 */
int genl_iwan_events_subscribe(genl_iwan *g, char *err, size_t errsz);

/* 非阻塞排空已就绪的事件，逐条回调。返回处理条数，-1 表示套接字错误。 */
int genl_iwan_events_drain(genl_iwan *g, genl_iwan_ev_cb cb, void *ud);

#endif /* __linux__ */

#endif /* IWAN_GENL_IWAN_H */
