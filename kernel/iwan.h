/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iwan — 零用户态数据路径（内核侧）。
 *
 * 入站（RX，默认 NF_INET_PRE_ROUTING prio=-300）：
 *   外层 IP[DF=1] / UDP / 8B iWAN 帧头 / XOR(内层 IPv4 包)
 *   钩子内先做外层重组（非首片没有 UDP/iWAN 头，必须拼完整才能看端口），
 *   再校验帧头（type/enc/sid/tok），剥掉外层与帧头，按会话密钥 XOR 还原，
 *   置 CHECKSUM_NONE 让内核按明文校验内层校验和，然后 NF_ACCEPT。
 *   内层若也是分片，交给 ip_local_deliver 里的 ip_defrag 重组（本机）或
 *   下一跳（转发）——本模块不碰内层重组。
 *
 * 出站（TX，内核虚拟网卡 ndo_start_xmit）：
 *   栈在到达 ndo_start_xmit 之前已经完成 GSO 分段与 L4 校验和计算
 *   （本设备的 features/hw_features 全为 0，validate_xmit_skb 会替我们做），
 *   所以此处拿到的一定是"完整的单个 IP 报文 + 校验和已就绪"，XOR 才安全。
 *   随后加 8B 帧头 + UDP + 外层 IP（DF=1）交给 ip_local_out。
 *
 * 配置面（v1，见 kernel/CONTROL-PLANE.md）：
 *   · 模块参数降级为**默认值**：只在该 netns 尚未建立 genetlink 会话
 *     （struct iwan_session.valid == false）时生效，行为与引入控制面之前
 *     逐位一致；/proc/net/iwan 读路径保持不变，写路径保留但已废弃。
 *   · 每 netns 会话由 genetlink 控制面（iwan_netlink.c）写入；数据面只读。
 *
 * 断线依据（v1，共享内存页，见 kernel/iwan_shm.h 与 CONTROL-PLANE.md §5）：
 *   keepalive 的**发送**在用户态，内核只负责"收到就盖时间戳"：每个通过凭据
 *   闸门的帧（数据/控制）都把 iwan_now_ms() 写进该 netns 的共享内存页
 *   （/dev/iwan，mmap 给用户态，只读）。netlink 的 IWAN_A_LAST_KEEPALIVE_MS
 *   与页面里的 last_rx_ms 是**同一个存储**，没有再存第二份。
 *
 * 帧常量镜像 PROTOCOL.md 与 src/common/protocol.h 的冻结值，禁止改动；
 * 内核侧按数值自己定义，不 include src/ 下的头。
 */
#ifndef IWAN_KERNEL_H
#define IWAN_KERNEL_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/timekeeping.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst_cache.h>	/* 出站外层路由缓存（按路由代数自动失效） */

#include "iwan_genl.h"	/* enum iwan_peer_state：页面 peer_state 复用它 */
#include "iwan_shm.h"	/* 共享内存页布局（/dev/iwan），冻结 ABI */

struct page;		/* iwan_net.shm_page：只需指针，避免拖进 linux/mm.h */

#define IWAN_HDR_LEN	8	/* 帧头：type, enc, sid(u16 BE), tok(u32 BE) */
#define IWAN_KEY_LEN	8	/* MD5(username||password)[0..8) */

/* 帧类型（镜像 src/common/protocol.h 的冻结数值）：
 *   0x11-0x18 数据/握手帧，0x29/0x2A keepalive。 */
#define PT_OPEN_REJECT	0x11
#define PT_OPEN_ACK	0x12
#define PT_OPEN		0x13	/* 客户端 OPEN（sid/tok = 0/0） */
#define PT_DATA		0x14	/* 明文内层 IPv4 包 */
#define PT_ECHO_REQ	0x15
#define PT_ECHO_RES	0x16
#define PT_CLOSE	0x17
#define PT_DATA_ENC	0x18	/* XOR 后的内层 IPv4 包 */
#define PT_PING_REQ	0x29
#define PT_PING_RSP	0x2A

/* PT_PING_REQ/RSP 用的是协议固定凭据，不是会话凭据（见 src/common/protocol.h）：
 * 所以控制帧的凭据口径必须按类型分，规则与理由见 iwan_rx.c 的
 * iwan_ctrl_cred_ok()：
 *   · PING_REQ/RSP  → 固定 0xFFFF/0xFFFFFFFF（也容忍会话凭据）；
 *   · ECHO_REQ/RES、CLOSE → 必须等于会话 sid/tok；
 *   · OPEN/OPEN_ACK/OPEN_REJECT → 内核无法预知（ACK 带的是服务端新分配的
 *     sid/tok，OPEN 是 0/0），只做外层四元组 + dport 过滤后原样转交用户态，
 *     由用户态的 HMAC 签名（IWAN_CTRL_LEN=24）做真正的凭据校验。 */
#define IWAN_PING_SID	0xFFFF
#define IWAN_PING_TOK	0xFFFFFFFFu

/* 外层开销：8B 帧头 + 8B UDP + 20B IPv4（无选项） */
#define IWAN_OVERHEAD	(IWAN_HDR_LEN + 8 + 20)

/* 外层 IPv6 的开销：IPv6 基本头固定 40B（比 v4 多 20B），没有选项字段。
 * 两处必须用它而不是 IWAN_OVERHEAD：needed_headroom（每包预留）与内层
 * MTU 的硬上限（外层 UDP 长度字段仍是 16 位，v6 也一样）。 */
#define IWAN_OVERHEAD_V6	(IWAN_HDR_LEN + 8 + 40)

/* SESSION_UP 按需创建的网卡名；MTU 上下限与 iwan_dev_setup() 一致 */
#define IWAN_DEV_NAME	"iwan0"
#define IWAN_MIN_MTU	68
/* 内层 MTU 上限的**默认值**，可被模块参数 max_mtu 覆盖（默认 1500）。
 * 为什么默认仍收回在 1500：内核数据面只在 <=1500 的内层包上验证过。
 * 2026-10-07 实测把内层 MTU 抬到 60000（CMake -DIWAN_JUMBO_MTU=60000）后，
 * 内核档跑出 kernel panic —— 该尺寸下的 TX/RX 路径（尤其是
 * iwan_rx.c:377 的 skb_gso_segment 批处理与 ndo_start_xmit 的 60KB skb）
 * 尚未审计。现在上限是模块参数，所以复现阶梯（1600/2048/4096/9000/…）不需要
 * 重编译，超限的 SESSION_UP 仍会被 iwan_netlink.c 干净拒绝而不是 panic。 */
#define IWAN_MAX_MTU	1500

/* 规范硬上限：外层 IPv4 总长是 16 位字段，封装开销 36B 必须装得下，
 * 超过它就是封装时 tot_len 溢出（所以 max_mtu 再大也会被这一条夹住）。 */
#define IWAN_MTU_HARD_MAX	(65535 - IWAN_OVERHEAD)
#define IWAN_MTU_HARD_MAX_V6	(65535 - IWAN_OVERHEAD_V6)

enum iwan_hooknum {
	IWAN_HOOK_PRE_ROUTING = 0,	/* 默认：两次重组之间 */
	IWAN_HOOK_LOCAL_IN    = 1,	/* 兜底：外层已由内核重组，内层分片需 reinject */
};

/* 全局默认配置（模块参数）。字段各自 READ_ONCE/WRITE_ONCE：改配置时不应
 * 有在途流量（测试脚本先配后打），不做原子快照。
 *
 * genetlink 控制面引入后：本结构只在该 netns 没有会话时供数据面取参
 * （见 iwan_dp_get），即"模块参数 = 会话未建立时的默认值"。 */
struct iwan_cfg {
	bool		enabled;
	bool		any_dir;	/* 外层 (src,dst) 允许反向（对等/本机双向测试） */
	bool		batch;		/* 处理 GRO 合并后的 GSO skb */
	bool		reinject;	/* 解封后用 netif_rx 回到 ip_defrag 之前 */
	bool		verbose;
	int		hooknum;	/* enum iwan_hooknum */
	int		hookprio;	/* 默认 -300（defrag 之后、conntrack 之前） */
	__be32		outer_src;	/* RX 过滤：外层源（服务端） */
	__be32		outer_dst;	/* RX 过滤：外层目的（本机隧道地址） */
	__be32		inner_src;	/* 可选：内层源地址白名单，0 = 关闭 */
	__be16		dport;		/* RX 匹配 & TX 使用的隧道目的端口 */
	__be16		sport;		/* TX 外层源端口（0 = 用 dport） */
	u16		sid;		/* 会话 id（数据面唯一凭据） */
	u32		tok;		/* 会话 token */
	u8		key[IWAN_KEY_LEN];
	u8		enc;		/* 1 = 数据面 XOR，0 = 明文会话 */
	bool		df;		/* 外层置 DF=1（默认）；置 0 允许外层分片，
					 * 用来验证"外层分片 → 钩子内联重组"这条路径 */
	u32		max_mtu;	/* 内层 MTU 上限（模块参数，默认 IWAN_MAX_MTU） */
};

struct iwan_stats {
	atomic64_t	rx_pkts;	/* 经过钩子的、封装形状合法的 UDP 外层包
					 * （v4/v6 合计；地址还没比 —— 与引入
					 * v6 之前"进入钩子的 IPv4 包"是同一
					 * 口径在 v4 上的取值） */
	atomic64_t	rx_outer;	/* 外层地址对命中本会话 */
	atomic64_t	rx_reasm;	/* 钩子内完成的**v4**外层重组 */
	atomic64_t	rx_frag6;	/* 外层 v6 分片：本设计外层 v6 不分片
					 * （会话建立时按承载网卡 MTU 校验），
					 * 见到分片说明对端配置不符；不吞、不
					 * 当完整包处理，交回协议栈 */
	atomic64_t	rx_frames;	/* 通过帧头校验的**数据**帧 */
	atomic64_t	rx_delivered;	/* 解密并交给栈的内层包 */
	atomic64_t	rx_batch;	/* 看到的 GSO 合并 skb */
	atomic64_t	rx_batch_skip;	/* 合并 skb 无法安全拆包而放行 */
	atomic64_t	rx_bad_hdr;	/* 帧头/长度/sid/tok 不合法 */
	atomic64_t	rx_bad_inner;	/* 内层不是合法 IPv4/IPv6（判据见
					 * iwan_inner_hdr_check） */
	atomic64_t	rx_nomem;
	atomic64_t	rx_ctrl_frame;	/* **过了凭据闸门**的非数据帧（IWAN_S_RX_CTRL_FRAME）。
					 * 其中被事件限速丢弃的那部分见 ev_dropped：
					 * ev_dropped ≤ rx_ctrl_frame。 */
	atomic64_t	tx_pkts;	/* 出站帧 */
	atomic64_t	tx_bytes;
	atomic64_t	tx_bad_state;	/* 仍是 GSO 或校验和未完成（拒绝，避免出脏包） */
	atomic64_t	tx_bad_inner;
	atomic64_t	tx_err;		/* 路由/内存/发送失败 */
	/* 事件通道被令牌桶丢掉的控制帧（IWAN_S_EV_DROPPED）。
	 * 只出现在 GET_STATS：/proc/net/iwan 的列序已冻结，不往里加列。 */
	atomic64_t	ev_dropped;
};

/*
 * 每 netns 会话状态（genetlink 控制面写入，数据面只读）。
 *
 * 字段口径沿用模块参数：端口是**主机序**，地址是 be32；netlink 侧在
 * 入/出口各转换一次（ABI 里端口是 be16、地址是 be32）。
 * 写者/读者之间没有锁：沿用 struct iwan_cfg 的既有约定（改会话时没有在途
 * 流量），标量用 READ_ONCE/WRITE_ONCE，valid 最后置位、最先清零，避免数据面
 * 读到"半套凭据"的持久状态（极端竞态下最多丢一帧）。
 *
 * 这里**没有** keepalive 时间戳与 peer_state：这两个字段的唯一存储是每 netns
 * 的共享内存页（pn->shm，见 iwan_shm.h），netlink 的 IWAN_A_LAST_KEEPALIVE_MS
 * / IWAN_A_PEER_STATE 与用户态 mmap 读到的是同一份，不允许各存一份。
 */
struct iwan_session {
	bool		valid;		/* netlink 会话已建立（数据面切换开关） */
	bool		enabled;	/* 数据面开关（SET_ENABLED，不丢凭据） */
	/* iwan0 由**本次会话**（或此前未删掉的那次会话）创建 ⇒ SESSION_DOWN
	 * 负责删除。刻意不按名字记：设备可被改名（ip link set name），名字对不
	 * 上就找不到设备，于是"报成功但设备还在"。身份判据是 dev_ifindex
	 * （见下），dev_owned 只表示"上一次我们认领过"。 */
	bool		dev_owned;
	bool		create_dev;	/* SESSION_UP 的 IWAN_A_FLAG_CREATE_DEV */
	u8		enc;
	u16		sid;
	u32		tok;
	u32		mtu;		/* 请求的设备 MTU */
	/* 显式绑定的外层出口网卡 ifindex（0 = 未指定，由 FIB 解析一次后钉住）。
	 * 一条会话始终只用一张下游网卡，见 iwan.h 的 iwan_net.carrier 说明。 */
	u32		oif;
	/* 显式绑定的外层出口 IP（0 = 未指定）。它同时是外层头的源地址与**绑定
	 * 规格**：内核用本机地址表解析出持有该地址的接口，据此固定承载网卡。
	 * 与 oif 同时给出时必须指向同一张接口（见 iwan_carrier_resolve）。 */
	__be32		bind_ip;
	/* 会话认领的网卡 ifindex（0 = 没认领）。删除走 ifindex 而不是名字：
	 * 改名后仍能删掉，也不会误删"同名但已换成别的设备"的那张。ifindex 会
	 * 被复用，所以是否删除必须 dev_owned && ifindex 同时成立。 */
	int		dev_ifindex;
	u8		key[IWAN_KEY_LEN];
	__be32		outer_src;	/* 本端外层地址 */
	__be32		outer_dst;	/* 对端外层地址 */
	u16		dport;		/* 主机序 */
	u16		sport;		/* 主机序，0 = 用 dport */
	char		devname[IFNAMSIZ];
	/* 外层 IPv6（切片 2）：outer_v6 为真时上面那对 __be32 恒为 0，数据面
	 * 只认下面这一对；族在会话存续期内不可变（换族必须 SESSION_DOWN 后
	 * 重建，与"凭据/本端地址必须重建会话"同一口径）。 */
	bool		outer_v6;
	struct in6_addr	outer_src6;	/* 本端外层 v6 地址 */
	struct in6_addr	outer_dst6;	/* 对端外层 v6 地址 */
	struct in6_addr	bind_ip6;	/* 显式绑定外层出口 v6 地址；
					 * 全零 = 未按 IP 绑定 */
};

/* 数据面参数快照：每 netns 会话优先、模块参数回落（iwan_dp_get）。
 * session == false 时每个字段都与引入控制面之前逐位一致：
 *   RX 用 cfg.*，TX 的外层端点用 /proc 配的 pn->tx_*，开关用
 *   cfg.enabled && pn->enabled。 */
struct iwan_dp {
	bool	session;	/* 以上会话字段是否来自 netlink 会话 */
	bool	enabled;
	bool	any_dir;	/* 外层 (src,dst) 是否允许反向匹配。
				 * 会话路径恒为 true（OUTER_SRC/DST 是"本端/对端"
				 * 这一对身份，入站天然是反向）；模块参数
				 * any_dir 只在回落路径上生效。 */
	u8	enc;
	u16	sid;
	u32	tok;
	u8	key[IWAN_KEY_LEN];
	__be32	outer_src;
	__be32	outer_dst;
	__be32	inner_src;	/* 仅模块参数（ABI 无此项） */
	u16	dport;		/* 主机序 */
	u16	sport;		/* 主机序，0 = 用 dport */
	u32	oif;		/* 显式绑定的承载网卡 ifindex；0 = 由 FIB
				 * 解析后钉住（会话取 sess.oif，回落路径取
				 * pn->tx_oif）。 */
	__be32	bind_ip;	/* 显式绑定的外层出口 IP（"绑 IP"模式）；
				 * 0 = 未按 IP 绑定。它与 oif 都只是"控制面是否
				 * 指定了绑定"的判据：实际承载网卡都记录在
				 * pn->carrier 上（会话建立时已解析）。 */
	/* 外层 v6（切片 2）。outer_v6 = true 时上面那三个 v4 字段恒为 0，
	 * 数据面只看下面这三个。 */
	bool		outer_v6;
	struct in6_addr	outer_src6;
	struct in6_addr	outer_dst6;
	struct in6_addr	bind_ip6;	/* 全零 = 未按 IP 绑定 */
};

/* 控制面是否显式下发了绑定规格（网卡或出口 IP）。有绑定规格时，数据面在
 * 外层查找失败后**绝不**漂移到别的网卡（丢弃并计数）；没有时才按 FIB 重新
 * 解析（那是"什么都不绑"模式的自愈路径）。 */
static inline bool iwan_dp_bound(const struct iwan_dp *dp)
{
	/* 族决定看哪一个 bind_ip：v4 会话的 bind_ip6 恒为零，v6 会话的
	 * bind_ip 恒为零（SESSION_UP/SESSION_DOWN 都按族清零），但判据仍显式
	 * 按族分开 —— 免得将来有人只清一半就悄悄改变"是否已绑定"的语义。 */
	if (dp->outer_v6)
		return dp->oif != 0 || !ipv6_addr_any(&dp->bind_ip6);
	return dp->oif != 0 || dp->bind_ip != 0;
}

/* 本会话的外层封装开销（needed_headroom、内层 MTU 硬上限都用它） */
static inline unsigned int iwan_dp_overhead(const struct iwan_dp *dp)
{
	return dp->outer_v6 ? IWAN_OVERHEAD_V6 : IWAN_OVERHEAD;
}

/* 外层五元组（事件载荷用；地址/端口保持网络序，与线上一致） */
struct iwan_outer_tuple {
	__be32	src;
	__be32	dst;
	__be16	sport;
	__be16	dport;
};

/*
 * 事件通道令牌桶（每 netns 一份）。
 *
 * 为什么要有：控制帧路径**没有**可用的凭据闸门 —— PT_OPEN/PT_OPEN_ACK/
 * PT_OPEN_REJECT 出现在握手期，那时内核还没有会话（iwan_ctrl_cred_ok 对这三种
 * 无条件放行），否则用户态永远收不到握手包。于是"伪造控制帧打满 events 多播"
 * 只能靠限速兜住。数据帧不受影响：它们走 iwan_decap_one 的凭据校验，不进桶。
 *
 * 口径：按**帧**计（不按字节）—— 事件通道的开销是 genlmsg 分配与多播，与帧长
 * 无关。默认 100 帧/秒、突发 200 帧，即稳态 1s 最多 100 个事件、最多攒 200 个
 * 令牌。超过就丢，丢掉的帧计入 IWAN_S_EV_DROPPED。
 *
 * 实现约束：调用点可能在软中断里（RX 钩子），所以只用原子操作 —— 不加锁、不
 * 睡眠、不分配。因此限速是"约等于"而不是精确值（两个 CPU 可能同时补充令牌，
 * 最坏情况多放一两个），这是刻意的取舍：宁可偶尔多放一个，也不让数据面路径
 * 去拿锁。字段在 netns 创建时被 kzalloc 清零，tokens/last_ms 都是 0 表示"还
 * 没用过"，首次收帧时由 iwan_ev_rate_ok() 灌满并立时基。
 *
 * tokens 是**定点**值：1 个令牌 = IWAN_EV_TOK_SCALE 个单位，这样补充令牌只需
 * 一次整数乘加，不用在软中断里做除法。
 */
#define IWAN_EV_RATE_PER_SEC	100u	/* 令牌补充速率（帧/秒） */
#define IWAN_EV_BURST		200u	/* 桶容量（帧），也是突发上限 */
#define IWAN_EV_TOK_SCALE	1000u	/* 定点放大：1 令牌 = 1000 单位 */

struct iwan_ev_bucket {
	atomic64_t	tokens;		/* 可用令牌 × IWAN_EV_TOK_SCALE */
	atomic64_t	last_ms;	/* 上次补充令牌的单调毫秒（iwan_now_ms） */
};

/* 每 netns 状态。TX 外层端点刻意放在这里：一个模块实例服务所有 netns，
 * 而两个方向的外层目的地址不同，所以由每个 netns 通过 /proc/net/iwan 配
 * （没有 netlink 会话时）或 genetlink 会话（有会话时）决定。
 *
 * shm/shm_page：该 netns 的共享内存页（/dev/iwan mmap 给用户态，只读）。
 *   · shm 是页面头部指针，数据面与 netlink 都只通过它读/写页面字段，
 *     全部访问都用 READ_ONCE(pn->shm) 取值并容忍 NULL（pernet exit 摘除后）；
 *   · shm_page 只在 open()/mmap()/释放引用时用，与 shm 同生共死；
 *   · 生命周期与引用计数见 iwan_shm.c 头部注释。 */
struct iwan_net {
	struct net		*net;
	/* 收包钩子：v4 与 v6 各一个（netfilter 钩子表本身分族），两个钩子
	 * 指向同一个 iwan_rx_hook，族差异只在钩子里的外层头解析那一层
	 * （见 iwan_rx.c 的 iwan_outer_view）。 */
	struct nf_hook_ops	rx_ops4;
	struct nf_hook_ops	rx_ops6;
	struct proc_dir_entry	*proc;
	struct iwan_stats	st;
	struct iwan_session	sess;	/* genetlink 会话（iwan_netlink.c 写） */
	struct iwan_shm		*shm;	/* 每 netns 一页共享内存；NULL = 已摘除 */
	struct page		*shm_page;	/* 对应的 struct page */
	struct iwan_ev_bucket	ev_bucket;	/* events 多播限速（软中断里用） */
	bool			rx_hooked;
	bool			enabled;	/* 每 netns 开关，默认 true（无会话时生效） */
	__be32			tx_src;		/* 无会话时的出站外层源（/proc 配） */
	__be32			tx_dst;		/* 无会话时的出站外层目的（/proc 配） */
	u32			tx_oif;		/* 无会话时显式绑定的承载网卡
						 * （/proc 配，0 = 由 FIB 解析后钉住） */
	__be32			tx_bind_ip;	/* 无会话时显式绑定的出口 IP
						 * （/proc 配，0 = 未按 IP 绑定）。
						 * 与 tx_src 同值：它既是外层头的
						 * 源地址，也是"哪张网卡"的判据。 */
	u32			carrier;	/* 已钉住的承载网卡 ifindex
						 * （0 = 尚未解析）。一条会话始终
						 * 只用一张下游网卡：出站查找带
						 * flowi4_oif、入站按 ifindex 过滤、
						 * needed_headroom 按它的
						 * LL_RESERVED_SPACE 推导。由
						 * iwan_tx.c 的 iwan_carrier_pin()
						 * 写；控制面在会话建立/结束、
						 * 端点变更时清 0 让下一次重新
						 * 解析。 */
	struct dst_cache	tx_route;	/* 出站外层路由缓存：外层端点在会话
						 * 存续期内不变，逐包 FIB 查找是纯
						 * 重复劳动；dst_check 按路由代数自
						 * 动失效，端点一致性在取用时校验 */
	bool			tx_route_ok;	/* tx_route 初始化成功；失败则退化为
						 * 逐包 FIB 查找，不影响正确性 */
	__be32			tx_route_dst;	/* 缓存建立时的外层目的/源：端点被
						 * 改（/proc 或新会话）时据此作废缓存 */
	__be32			tx_route_src;
	u32			tx_route_oif;	/* 缓存建立时的承载网卡：钉住结果被
						 * 改（换会话/换绑定）时据此作废缓存。
						 * 控制面**不**直接 dst_cache_reset
						 * （那个必须在 BH 关闭下做），只清
						 * pn->carrier，由数据面按这三个记录
						 * 值惰性作废。 */
	bool			tx_route_v6;	/* 缓存建立时的外层族；与端点一起参与
						 * 取用校验，换族必然失配 */
	struct in6_addr		tx_route_dst6;
	struct in6_addr		tx_route_src6;
};

extern unsigned int iwan_net_id;

struct rtnl_link_ops;
extern struct rtnl_link_ops iwan_link_ops;	/* iwan_tx.c：网卡创建/删除用 */

static inline struct iwan_net *iwan_net_of(struct net *net)
{
	return net_generic(net, iwan_net_id);
}

/* 解开承载网卡钉住：外层端点或绑定变更、会话结束时调用。只清标量，**不**做
 * dst_cache_reset —— 后者要求 BH 关闭，控制面在进程上下文里不碰它；数据面靠
 * tx_route_dst/src/oif 三个记录值发现"建缓存时的参数已变"，自己在软中断关闭
 * 的环境里惰性作废（见 iwan_tx.c 的 ⑥）。 */
static inline void iwan_carrier_forget(struct iwan_net *pn)
{
	WRITE_ONCE(pn->carrier, 0);
}

/* 单调时钟毫秒：keepalive/存活时间戳（共享内存页、GET_STATS 与 KEEPALIVE
 * 事件都用这一个时间源，不允许引入 jiffies 或第二套基准） */
static inline u64 iwan_now_ms(void)
{
	return div_u64(ktime_get_mono_fast_ns(), NSEC_PER_MSEC);
}

/* ---- 共享内存页访问器（/dev/iwan，见 iwan_shm.h）----------------------
 *
 * 页面的分配/释放与引用计数都在 iwan_shm.c；这里只做字段读写，供数据面
 * （iwan_rx.c，软中断上下文）与控制面（iwan_netlink.c）共用：
 *   · 每个访问器都用 READ_ONCE(pn->shm) 取指针并**容忍 NULL**（pernet exit
 *     已把页面摘除时读到 NULL，直接不做任何事，不 deref）；
 *   · 数据面只做普通 store（WRITE_ONCE 只防编译器撕裂），无锁、无分配、
 *     无其它同步原语；页面是"内核写、用户态只读"的单向快照；
 *   · last_rx_ms 与 netlink 的 IWAN_A_LAST_KEEPALIVE_MS 是同一个存储。
 */
static inline struct iwan_shm *iwan_shm_of(const struct iwan_net *pn)
{
	return READ_ONCE(pn->shm);
}

/* netlink GET_STATS 的 keepalive 快照：无页面/无会话时回 0（与旧口径一致） */
static inline u64 iwan_shm_last_rx_ms(const struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	return shm ? READ_ONCE(shm->last_rx_ms) : 0;
}

static inline u32 iwan_shm_peer_state(const struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	return shm ? READ_ONCE(shm->peer_state) : IWAN_PEER_UNKNOWN;
}

static inline void iwan_shm_set_peer_state(struct iwan_net *pn, u32 state)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->peer_state, state);
}

/*
 * 通过凭据闸门的**每一个**帧（数据帧或控制帧）都刷新时间戳：这就是用户态
 * "对端还活着吗"的唯一依据。时基 = iwan_now_ms()（与 GET_STATS 完全一致）。
 * 收到 PT_CLOSE 时由 iwan_shm_note_close() 覆盖成 0。
 */
static inline void iwan_shm_note_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->last_rx_ms, iwan_now_ms());
}

/*
 * 页面里的两个计数器是 pn->st 对应 atomic64 的**镜像快照**：必须在
 * atomic64_inc() 之后调用，页面值因此与 /proc/net/iwan、GET_STATS 同源
 * （同一份权威计数，不另做一份计数）。并发 RX 时镜像可能短暂滞后一拍，
 * 但不会丢计数 —— 用户态用它确认"链路在动"，不用于对账。
 */
static inline void iwan_shm_note_data_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->rx_frames,
			   (u64)atomic64_read(&pn->st.rx_frames));
}

static inline void iwan_shm_note_ctrl_frame(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (shm)
		WRITE_ONCE(shm->rx_ctrl_frame,
			   (u64)atomic64_read(&pn->st.rx_ctrl_frame));
}

/* 收到 PT_CLOSE(0x17)：时间戳置 0（用户态见 0 即判定断线）+ peer_state=CLOSED */
static inline void iwan_shm_note_close(struct iwan_net *pn)
{
	struct iwan_shm *shm = iwan_shm_of(pn);

	if (!shm)
		return;
	WRITE_ONCE(shm->last_rx_ms, 0);
	WRITE_ONCE(shm->peer_state, IWAN_PEER_CLOSED);
}

/* iwan_core.c */
struct iwan_cfg *iwan_cfg_get(void);
void iwan_dp_get(struct iwan_net *pn, const struct iwan_cfg *c, bool tx,
		 struct iwan_dp *dp);
void iwan_xor(u8 *p, size_t len, const u8 *key, size_t off);
int iwan_xor_skb(struct sk_buff *skb, const u8 *key);
/* 内层 IP 头校验，v4/v6 两种内层共用一份判据（TX 与 RX 都调它）。
 * exact_len = 声明长度必须等于 skb->len（TX 用）；
 * 出参 *net_hdr_len = 内层网络头长度，用于设置传输层偏移。
 * 返回 0 = 合法，-EINVAL = 非法。详见 iwan_core.c 的实现注释。 */
int iwan_inner_hdr_check(struct sk_buff *skb, bool exact_len,
			 u32 *net_hdr_len);

/* iwan_shm.c：/dev/iwan 设备注册 + 每 netns 页面的分配/释放 + 会话级字段 */
int iwan_shm_init(void);
void iwan_shm_exit(void);
int iwan_shm_net_init(struct iwan_net *pn);
void iwan_shm_net_exit(struct iwan_net *pn);
void iwan_shm_session_up(struct iwan_net *pn);
void iwan_shm_session_down(struct iwan_net *pn);
void iwan_shm_set_enabled(struct iwan_net *pn, bool sess_enabled);

/* iwan_rx.c */
int iwan_rx_net_init(struct iwan_net *pn);
void iwan_rx_net_exit(struct iwan_net *pn);

/* iwan_tx.c：rtnl_link_ops 注册/注销（网卡由 rtnl_create_link 或
 * `ip link add ... type iwan` 创建） */
int iwan_tx_init(void);
void iwan_tx_exit(void);

/* iwan_tx.c：按外层端点解析承载网卡并钉住（进程上下文；显式绑定解析失败返回
 * errno，调用者据此拒绝会话）。成功后 pn->carrier 与 iwan0 的 needed_headroom
 * 都已就位。 */
int iwan_carrier_resolve(struct net *net, struct iwan_net *pn,
			 struct net_device *dev, __be32 src, __be32 dst,
			 u32 oif, __be32 bind_ip);
/* 出口 IP 绑定的一致性检查（只查地址表，不解析路由也不钉网卡）：
 * ip 为 0 = 不按 IP 绑定，直接通过；ip 不属于任何本机接口返回
 * -EADDRNOTAVAIL；同时给了网卡 oif 而地址不在那张卡上返回 -EINVAL。
 * 控制面（genetlink SESSION_UP 与 /proc 的 ip=/oif=）都用它，保证
 * "两个绑定规格必须指向同一张接口"只有一份实现。 */
int iwan_bind_ip_check(struct net *net, __be32 ip, u32 oif);
int iwan_bind_ip_check6(struct net *net, const struct in6_addr *ip6, u32 oif);
int iwan_carrier_resolve6(struct net *net, struct iwan_net *pn,
			  struct net_device *dev, u32 mtu,
			  const struct in6_addr *src,
			  const struct in6_addr *dst, u32 oif,
			  const struct in6_addr *bind_ip);

/* iwan_netlink.c：genetlink 控制面（注册/注销 + 事件上报）。
 * 事件只投递到会话所属 netns 的 "events" 多播组；调用点可能在软中断里
 * （RX 钩子），实现全部 GFP_ATOMIC、失败只计数不报错。 */
int iwan_netlink_init(void);
void iwan_netlink_exit(void);

/* 原样转交控制帧 + 补发语义事件；返回 false = 被事件令牌桶限速丢弃
 * （已计入 st.ev_dropped），调用者应跳过后续语义事件的多播，但**不能**
 * 跳过共享内存的副作用（last_rx_ms/peer_state 的记账与限速无关）。 */
bool iwan_ev_ctrl_frame(struct iwan_net *pn, u16 sid,
			const struct iwan_outer_tuple *t,
			const u8 *frame, size_t len);
void iwan_ev_peer_close(struct iwan_net *pn, u16 sid);
void iwan_ev_keepalive(struct iwan_net *pn, u64 timestamp_ms);

#endif /* IWAN_KERNEL_H */
