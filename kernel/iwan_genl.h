/* iWAN 控制面 ABI（genetlink）v1 —— 内核与用户态共用。
 *
 * 冻结接口，设计说明见 kernel/CONTROL-PLANE.md。本文件只使用标准整数类型，
 * 不含内核专用头，因此用户态可以直接 include；内核侧的 nla_policy 必须与本
 * 文件的类型注释一致，改这里就要同步改 policy。
 */
#ifndef IWAN_GENL_H
#define IWAN_GENL_H

#define IWAN_GENL_NAME		"iwan"
#define IWAN_GENL_VERSION	1

/* 多播组名：内核 -> 用户态 */
#define IWAN_GENL_MCGRP_EVENTS	"events"

/* 事件载荷上限：非数据帧（OPEN/OPEN_ACK/PING/CLOSE 等）都远小于此值 */
#define IWAN_CTRL_FRAME_MAX	512

/* 会话密钥长度：IWAN_A_KEY 必须恰好是这么多字节。与 kernel/iwan.h 的
 * IWAN_KEY_LEN 同值，这里再定义一份是为了让用户态不必硬编码。 */
#ifndef IWAN_KEY_LEN
#define IWAN_KEY_LEN	8
#endif

/* ------------------------------------------------------------ 字节序约定
 *
 * 属性分两类，混用会得到"模块自打自收正常、只有真实对端失败"的缺陷：
 *
 *   - 普通整数（SID/TOK/ENC/MTU/FLAGS/ENABLED 与全部计数器）：**主机序**；
 *   - 地址与端口（OUTER_SRC/OUTER_DST/SPORT/DPORT）：**网络序**，
 *     用户态必须先 htonl/htons 再放进属性，内核侧对应 be32/be16。
 *
 * 内核内部 struct iwan_cfg / struct iwan_session 的 dport/sport 按**主机序**
 * 存放（出站写外层头时 htons，入站比较时 htons）。因此转换只发生在 netlink
 * 边界这一处：进来 ntohs() 之后存，出去 htons() 之后回。
 * 改动任何一侧前先确认另一侧仍然对齐 —— 这正是历史上出错的地方。
 */

/* ---------------------------------------------------------------- 命令 */

enum iwan_genl_cmd {
	IWAN_CMD_UNSPEC = 0,
	IWAN_CMD_SESSION_UP,	/* 建立会话，幂等 */
	IWAN_CMD_SESSION_DOWN,	/* 拆会话：清零状态并删除模块建的网卡 */
	IWAN_CMD_SET_PEER,	/* 只更新对端地址/端口（漂移、换线） */
	IWAN_CMD_SET_ENABLED,	/* 临时停/启数据面，不丢会话状态 */
	IWAN_CMD_GET_STATS,	/* 配置快照 + 计数器 + keepalive 时间戳 */
	__IWAN_CMD_MAX,
};
#define IWAN_CMD_MAX (__IWAN_CMD_MAX - 1)

/* ---------------------------------------------------------------- 属性 */

enum iwan_genl_attr {
	IWAN_A_UNSPEC = 0,
	/* --- SESSION_UP / SET_PEER --- */
	IWAN_A_SID,		/* u16 */
	IWAN_A_TOK,		/* u32 */
	IWAN_A_ENC,		/* u8，1 = PT_DATA_ENC + XOR，0 = PT_DATA 明文 */
	IWAN_A_KEY,		/* 8 字节，MD5(user||pass)[0..8) */
	IWAN_A_OUTER_SRC,	/* be32，本端外层地址 */
	IWAN_A_OUTER_DST,	/* be32，对端外层地址 */
	IWAN_A_DPORT,		/* be16 */
	IWAN_A_SPORT,		/* be16，省略则用 DPORT */
	IWAN_A_MTU,		/* u32，省略则 1500 - IWAN_OVERHEAD */
	IWAN_A_FLAGS,		/* u32，见 IWAN_A_FLAG_* */
	/* --- SET_ENABLED --- */
	IWAN_A_ENABLED,		/* u8 */
	/* --- SESSION_UP / GET_STATS 回执 --- */
	IWAN_A_DEVNAME,		/* string，实际设备名 */
	IWAN_A_LAST_KEEPALIVE_MS,	/* u64，单调时钟毫秒；无 keepalive 时为 0 */
	IWAN_A_PEER_STATE,	/* u8，见 IWAN_PEER_* */
	IWAN_A_STATS,		/* nested，见 iwan_stats_attr */
	/* --- SESSION_UP 回执（新增属性，旧客户端忽略即可） --- */
	IWAN_A_DEV_OWNED,	/* u32，设备归属：1 = 这张设备由本模块创建/认领，
				 * 后续 SESSION_DOWN 会删除它；0 = 不是我们建的
				 * （例如用户自己 `ip link add ... type iwan` 的
				 * 设备，我们不删）。主机序，与同表其它标量一致。
				 * 注意本属性表达的是"要不要由会话负责删"，不是
				 * "netdev kind 是不是 iwan"：同名但非本模块的设备
				 * （TUN/veth 占着 iwan0）会被直接拒绝，SESSION_UP
				 * 返回 -EBUSY，根本不会有回执。
				 * 旧客户端不认识这个属性，按 genetlink 惯例忽略即可。 */
	/* --- SESSION_UP 入参（新增属性，追加在末尾以保证既有属性编号不变；
	 *     旧客户端不发 = 由 FIB 解析后钉住，行为与引入绑定之前一致） --- */
	IWAN_A_OIF,		/* u32，主机序：显式绑定外层出口网卡（ifindex）。
				 * 0 或省略 = 不指定，由 FIB 解析一次并把结果钉住
				 * —— 两种情况下"这条会话只用一张下游网卡"都成立，
				 * 区别只在于是谁选的：显式绑定严格用指定那张（内核
				 * 的 flowi4_oif 是硬绑：设备 UP 且有 IPv4 地址时，即使
				 * FIB 无路由也会为它合成 scope link 路由，即
				 * SO_BINDTODEVICE 语义，绑到没有回程路由的卡上会照发
				 * 而被网络侧丢弃；设备不存在/解析不到路由则返回
				 * -ENETUNREACH，绝不漂移到别的卡）；未指定则由 FIB
				 * 选，选完固定，此后不再逐包变化。 */
	IWAN_A_IP,		/* be32：显式绑定外层出口 IP（"绑 IP"模式）。
				 * 语义有两层：① 该地址写进外层 IP 头的源地址字段
				 * （与 OUTER_SRC 同值时二者须一致）；② 它是**绑定
				 * 规格**——内核用本机地址表把它解析成持有该地址的
				 * 接口，并按该接口固定承载网卡，等价于"绑网卡"。
				 * 0 或省略 = 不按 IP 绑定。与 OIF 同时给出时必须指向
				 * 同一张接口，否则 SESSION_UP 返回 -EINVAL（两个绑定
				 * 规格互相矛盾时不能取其一）。解析不到（该地址不属于
				 * 任何本机接口）返回 -EADDRNOTAVAIL。
				 * 注意：解析用的是**地址表**（本机地址挂在接口上），
				 * 不是路由表——按路由反查会把"绑 IP"退化成"由 FIB
				 * 决定"，与"什么都不绑"失去区分。 */
	IWAN_A_CARRIER,		/* u32，只读（GET/回执）：当前实际承载网卡的
				 * ifindex，0 = 尚未解析。供控制面对账与诊断
				 * （"绑 IP/绑网卡"下内核选了哪张卡，日志之外
				 * 只有这一个可读来源）。写路径忽略本属性。 */
	/* --- 外层 IPv6 增补（追加在末尾，既有属性编号一个不动） ---------
	 * 外层地址族由属性**成对出现**决定，不另设"族"开关：给了
	 * OUTER_SRC6 + OUTER_DST6 就是外层 v6 会话，给了 v4 那对就是 v4
	 * 会话；两对同时给出返回 -EINVAL（族必须唯一，不能让数据面去猜）。
	 * 内层不受影响：内层版本仍逐包判（iwan_inner_hdr_check），外层 v6
	 * 里照样可以跑内层 v4。 */
	IWAN_A_OUTER_SRC6,	/* 16 字节 struct in6_addr：本端外层 IPv6 地址。
				 * 必须与 OUTER_DST6 同时给出，且不能全零。 */
	IWAN_A_OUTER_DST6,	/* 16 字节：对端外层 IPv6 地址 */
	IWAN_A_IP6,		/* 16 字节：显式绑定外层出口 IPv6 地址
				 * （"绑 IP"模式的 v6 形态）。语义与 IWAN_A_IP
				 * 逐条对应：① 它就是外层 IPv6 头的源地址，故必须
				 * 等于 OUTER_SRC6；② 它是**绑定规格** —— 内核用
				 * 本机 v6 地址表解析出持有该地址的接口并按该接口
				 * 固定承载网卡；与 OIF 同时给出时必须指向同一张
				 * 接口（-EINVAL），解析不到返回 -EADDRNOTAVAIL。
				 * 全零或省略 = 不按 IP 绑定。 */
	__IWAN_A_MAX,
};
#define IWAN_A_MAX (__IWAN_A_MAX - 1)

/* GET_STATS 回执契约（v1 实现口径，改动前先改这里）：
 *  - 只回**发送 socket 所在 netns** 的视图；没有 NLM_F_DUMP 枚举，跨 netns
 *    请逐个 netns 查询。
 *  - **无 netlink 会话时不报错、也不清零**，回的是模块参数层（回落路径）视图，
 *    即"从未 SESSION_UP"时数据面真正在用的那份配置；用户态靠 SID/DEVNAME
 *    判断有无会话。SESSION_DOWN 之后凭据与 LAST_KEEPALIVE_MS 清零。
 *  - LAST_KEEPALIVE_MS 是只读快照（SESSION_UP/SET_PEER 携带该属性返回 -EINVAL），
 *    由 PT_PING_REQ/RSP 更新，SESSION_DOWN 清零。
 *  - SESSION_UP 回执必带 DEVNAME；MTU 回**实测值**（设备已 UP 且无法改时可能与
 *    请求值不同）；DEV_OWNED 回设备归属（见 IWAN_A_DEV_OWNED）。
 *  - **KEY 会回传**（明文 8 字节，与下发值逐字节相同）：实现按"下发即可读回"
 *    处理，用户态据此校验会话是否为本进程下发的。这条与旧版注释"KEY 不回传"
 *    相反，**以实现为准**；正因为会回传，不要把 get-stats 的输出写进日志/
 *    工单/上报（含 KEY、SID、TOK 在内的完整会话凭据）。
 */

/* SESSION_UP 的 FLAGS 位 */
#define IWAN_A_FLAG_CREATE_DEV	(1u << 0)	/* 按需创建 iwan0（默认置位） */
#define IWAN_A_FLAG_ANSWER_PING	(1u << 1)	/* 保留位：v1 不实现内核代答
						 * PT_PING_REQ，置位即 -EINVAL
						 * （宁可拒绝，也不假装支持） */

/* 对端状态（IWAN_A_PEER_STATE） */
enum iwan_peer_state {
	IWAN_PEER_UNKNOWN = 0,
	IWAN_PEER_UP,		/* 收过有效帧 */
	IWAN_PEER_SILENT,	/* 保留编号：v1 从不赋值 —— 内核无定时器，
				 * 判活由用户态轮询 last_rx_ms 承担 */
	IWAN_PEER_CLOSED,	/* 收到 PT_CLOSE */
};

/* GET_STATS 的计数器（IWAN_A_STATS 内嵌一层）。
 * 嵌套表用 iwan_stats_attr，值一律 u64 主机序；未实现的计数器回 0。
 * 名称/语义与 /proc/net/iwan 现有计数器一致，便于两条路径对照。 */
enum iwan_stats_attr {
	IWAN_S_UNSPEC = 0,
	IWAN_S_RX_PKTS,
	IWAN_S_RX_OUTER,
	IWAN_S_RX_REASM,
	IWAN_S_RX_FRAMES,
	IWAN_S_RX_DELIVERED,
	IWAN_S_RX_BATCH,
	IWAN_S_RX_BATCH_SKIP,
	IWAN_S_RX_BAD_HDR,
	IWAN_S_RX_BAD_INNER,
	IWAN_S_RX_NOMEM,
	IWAN_S_RX_CTRL_FRAME,	/* 过了凭据闸门的非数据帧；被事件限速丢弃的看
				 * IWAN_S_EV_DROPPED（ev_dropped ≤ 本项） */
	IWAN_S_TX_PKTS,
	IWAN_S_TX_BYTES,
	IWAN_S_TX_BAD_STATE,
	IWAN_S_TX_BAD_INNER,
	IWAN_S_TX_ERR,
	/* 新增计数器（追加在末尾，前面的序号不动，旧客户端忽略即可）：
	 * 事件通道被限速丢弃的帧数。控制帧路径没有凭据可校验
	 * （PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT 必须放行给用户态），
	 * 所以用每 netns 的令牌桶兜住"伪造/风暴帧打满事件通道"这一路。
	 * 与 IWAN_S_RX_CTRL_FRAME 的关系：那一项记的是**过了凭据闸门**的
	 * 控制帧总数（含被限速丢掉的），因此恒有 ev_dropped ≤ rx_ctrl_frame；
	 * 被限速丢掉时共享内存页的时间戳/peer_state 记账照旧发生（只有多播
	 * 被丢），断线检测不受限速影响。
	 * /proc/net/iwan 的列序已冻结，这个计数器只在 GET_STATS 里可见。 */
	IWAN_S_EV_DROPPED,
	/* 新增计数器（同样追加在末尾）：外层 v6 分片。本设计外层 v6 不分片
	 * （v6 无 DF 位，源端分片只会换到对端拒收；会话建立时按承载网卡 MTU
	 * 校验过"内层 MTU + 封装 <= MTU"），所以这一项非零就说明对端配置与
	 * 本端不一致（或对端在跑外层 v6 的 jumbo 档）。这些包**不**按本隧道
	 * 解封：计数后原样交回协议栈（NF_ACCEPT）。
	 * /proc/net/iwan 的列序已冻结，本项只在 GET_STATS 里可见。 */
	IWAN_S_RX_FRAG6,
	__IWAN_S_MAX,
};
#define IWAN_S_MAX (__IWAN_S_MAX - 1)

/* ---------------------------------------------------------------- 事件 */

enum iwan_genl_event {
	IWAN_EV_UNSPEC = 0,
	IWAN_EV_CTRL_FRAME,	/* 收到非数据帧，原样转交用户态 */
	IWAN_EV_PEER_CLOSE,	/* 收到 PT_CLOSE */
	IWAN_EV_PEER_SILENT,	/* 保留编号：v1 不产生（无内核定时器） */
	IWAN_EV_KEEPALIVE,	/* 收到 PT_PING_REQ/RSP（可选订阅） */
	__IWAN_EV_MAX,
};
#define IWAN_EV_MAX (__IWAN_EV_MAX - 1)

enum iwan_ev_attr {
	IWAN_EVA_UNSPEC = 0,
	IWAN_EVA_SID,		/* u16 */
	IWAN_EVA_FRAME,		/* 原始帧字节（外层 IP/UDP 头之后），≤ IWAN_CTRL_FRAME_MAX */
	IWAN_EVA_OUTER_SRC,	/* be32 */
	IWAN_EVA_OUTER_DST,	/* be32 */
	IWAN_EVA_SPORT,		/* be16 */
	IWAN_EVA_DPORT,		/* be16 */
	IWAN_EVA_SILENT_MS,	/* 保留编号：仅曾计划的 PEER_SILENT 用 */
	IWAN_EVA_TIMESTAMP_MS,	/* u64，仅 KEEPALIVE */
	__IWAN_EVA_MAX,
};
#define IWAN_EVA_MAX (__IWAN_EVA_MAX - 1)

#endif /* IWAN_GENL_H */
