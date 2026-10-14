// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_netlink.c — genetlink 控制面（内核侧，v1）。
 *
 * ABI 冻结在 kernel/iwan_genl.h，设计见 kernel/CONTROL-PLANE.md。本文件负责：
 *   ① 家族注册：netnsok = true —— 一切状态按**发送 socket 所在 netns**
 *      （genl_info_net，来自 sock_net）取，绝不用 current 的 netns 猜；
 *   ② 会话建立/拆除（SESSION_UP/DOWN）：按需用 rtnl_link_ops 创建/删除 iwan0
 *      （进程上下文，绝不放在 pernet 初始化里）；
 *   ③ 会话参数更新与统计回执（SET_PEER/SET_ENABLED/GET_STATS）；
 *   ④ 事件多播（CTRL_FRAME/PEER_CLOSE/KEEPALIVE，供 iwan_rx.c 调用）。
 *      没有 PEER_SILENT：内核不做静默判定（无定时器），判活全在用户态
 *      轮询共享内存的 last_rx_ms。
 *
 * 参数口径：会话状态内部沿用模块参数的习惯（端口**主机序**、地址 be32），
 * netlink 上端口是 be16、地址是 be32、其余整数是主机序 —— 入/出各转换一次。
 *
 * 单一数据源（v1 共享内存页）：存活时间戳与对端状态只有一份存储 —— 该 netns
 * 的共享内存页（pn->shm，见 iwan_shm.h）。GET_STATS 的
 * IWAN_A_LAST_KEEPALIVE_MS/IWAN_A_PEER_STATE 从这里读，SESSION_UP/DOWN 与
 * SET_ENABLED 从这里写；struct iwan_session 里不再保留第二份。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/timekeeping.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>

#include "iwan.h"
#include "iwan_genl.h"

/*
 * 家族对象（完整定义见文件末尾）：回执/事件构造函数要用它，而家族对象又要引用
 * 命令处理器表 —— 这里先做一次前置声明解环。
 */
static struct genl_family iwan_genl_family;

/* ------------------------------------------------------------ nla_policy */

/*
 * 每个命令一张表：本命令用得到的属性给类型，其余一律 NLA_REJECT —— 属性写错
 * 命令不会静默生效。刻意不用 strict_start_type（老内核没有这个字段），
 * NLA_REJECT 在严格/宽松两种校验下都生效。
 */
#define IWAN_A_REJECT	{ .type = NLA_REJECT }

static const struct nla_policy iwan_policy_up[IWAN_A_MAX + 1] = {
	/* 必需：SID/TOK/ENC/KEY/OUTER_SRC/OUTER_DST/DPORT */
	[IWAN_A_SID]		= { .type = NLA_U16 },
	[IWAN_A_TOK]		= { .type = NLA_U32 },
	[IWAN_A_ENC]		= { .type = NLA_U8 },
	[IWAN_A_KEY]		= { .type = NLA_BINARY, .len = IWAN_KEY_LEN },
	[IWAN_A_OUTER_SRC]	= { .type = NLA_BE32 },
	[IWAN_A_OUTER_DST]	= { .type = NLA_BE32 },
	[IWAN_A_DPORT]		= { .type = NLA_BE16 },
	/* 可选：SPORT 省略 = 用 DPORT；MTU 省略 = 1500-IWAN_OVERHEAD；
	 * FLAGS 省略 = IWAN_A_FLAG_CREATE_DEV；OIF 省略 = 由 FIB 解析后钉住 */
	[IWAN_A_SPORT]		= { .type = NLA_BE16 },
	[IWAN_A_MTU]		= { .type = NLA_U32 },
	[IWAN_A_FLAGS]		= { .type = NLA_U32 },
	[IWAN_A_OIF]		= { .type = NLA_U32 },
	[IWAN_A_IP]		= { .type = NLA_BE32 },
	/* 外层 v6（切片 2）：族由**给了哪一对地址**决定，不设单独的族开关。
	 * 两对都给 / 只给一半都在处理函数里按 -EINVAL 拒掉（见那里的说明）。
	 * NLA_BINARY 的 .len 是上限，长度必须恰好 16，处理函数里另判。 */
	[IWAN_A_OUTER_SRC6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_OUTER_DST6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_IP6]		= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_CARRIER]	= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* 只出现在 SESSION_UP 回执里，不接受作为入参 */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_down[IWAN_A_MAX + 1] = {
	/* 不需要入参，幂等 */
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* 只出现在 SESSION_UP 回执里，不接受作为入参 */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_peer[IWAN_A_MAX + 1] = {
	/* 只更新对端地址/端口（漂移、换线），凭据与本端地址必须重建会话 */
	[IWAN_A_OUTER_DST]	= { .type = NLA_BE32 },
	/* 对端外层 v6 地址：漂移/换线时改这一项（族的切换是重建会话，不在这里） */
	[IWAN_A_OUTER_DST6]	= { .type = NLA_BINARY, .len = 16 },
	[IWAN_A_SPORT]		= { .type = NLA_BE16 },
	[IWAN_A_DPORT]		= { .type = NLA_BE16 },
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* 只出现在 SESSION_UP 回执里，不接受作为入参 */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_enabled[IWAN_A_MAX + 1] = {
	[IWAN_A_ENABLED]	= { .type = NLA_U8 },
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* 只出现在 SESSION_UP 回执里，不接受作为入参 */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

static const struct nla_policy iwan_policy_stats[IWAN_A_MAX + 1] = {
	/* 无入参：只回本 netns 一份快照（逐 netns dump 见 GET_STATS 里的 TODO） */
	[IWAN_A_SID]		= IWAN_A_REJECT,
	[IWAN_A_TOK]		= IWAN_A_REJECT,
	[IWAN_A_ENC]		= IWAN_A_REJECT,
	[IWAN_A_KEY]		= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_SRC6]	= IWAN_A_REJECT,
	[IWAN_A_OUTER_DST6]	= IWAN_A_REJECT,
	[IWAN_A_IP6]		= IWAN_A_REJECT,
	[IWAN_A_DPORT]		= IWAN_A_REJECT,
	[IWAN_A_SPORT]		= IWAN_A_REJECT,
	[IWAN_A_MTU]		= IWAN_A_REJECT,
	[IWAN_A_FLAGS]		= IWAN_A_REJECT,
	[IWAN_A_ENABLED]	= IWAN_A_REJECT,
	[IWAN_A_DEVNAME]	= IWAN_A_REJECT,
	[IWAN_A_LAST_KEEPALIVE_MS] = IWAN_A_REJECT,
	[IWAN_A_PEER_STATE]	= IWAN_A_REJECT,
	[IWAN_A_STATS]		= IWAN_A_REJECT,
	/* 只出现在 SESSION_UP 回执里，不接受作为入参 */
	[IWAN_A_DEV_OWNED]	= IWAN_A_REJECT,
};

/* 多播组在 mcgrps[] 里的下标（genlmsg_multicast_netns 的 group 参数） */
enum { IWAN_MCGRP_EVENTS_IDX = 0 };

/* ------------------------------------------------------------ 权限 */

/*
 * 与 /proc/net/iwan 写路径、以及 rtnetlink 自己的规则一致：要求发送 socket
 * 在**目标 netns 的 user_ns** 里有 CAP_NET_ADMIN。刻意不用 GENL_ADMIN_PERM：
 * 那个检查落在 init_user_ns 上，rootless netns 里配自己的会话会被无谓拒绝。
 */
static bool iwan_genl_capable(const struct sk_buff *skb, const struct net *net)
{
	return netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN);
}

/* ------------------------------------------------------------ 设备（iwan0） */

struct iwan_dev_info {
	char	name[IFNAMSIZ];
	u32	mtu;
	int	ifindex;
	bool	ours;	/* 是 iwan 类型设备（rtnl_link_ops 对齐） */
	bool	owned;	/* 由模块创建（含此前会话建的），SESSION_DOWN 负责删 */
};

/*
 * 按需在该 netns 创建 iwan0，或复用已存在的那张。
 *
 * 只在 genetlink doit（进程上下文）里调用：pernet 初始化阶段设备表还没建好，
 * 在那里建设备会重演 rtnl_fill_ifinfo 的 oops（见 iwan_core.c 的注释）。
 * rtnl_create_link() 的行为随内核版本而异（有的只分配、由调用者注册），这里
 * 按 reg_state 补齐注册，两条路径结果一致。设备建好/复用时顺手置 UP：
 * SESSION_UP 的语义是"数据面就绪"，up/地址/路由之外的手工配置仍归用户态
 * （CONTROL-PLANE §6）。
 *
 * 设备类型闸门（本函数最重要的约束）：同名设备**不是**本模块建的
 * （dev->rtnl_link_ops != &iwan_link_ops）时一律拒绝，返回 -EBUSY：
 *   · 本项目的 iwan-client 就用 TUN 建了一张 iwan0 跑真实隧道，而 TUN 与
 *     iwan 的 ARPHRD 同为 65534（ARPHRD_TUNNEL），只看名字/类型根本分不出来；
 *   · 老实现只 pr_warn 然后**继续复用**：用户态拿到"成功"的回执，数据面却
 *     是死的（TUN 收到的密文包不会进本模块的钩子），而且后续还会去改它的
 *     MTU —— 那会直接打断用户正在跑的隧道；
 *   · 因此这里既不复用、也不置 UP、也不碰它的 MTU，让失败明确可见。
 *
 * 所有权用 ifindex 记账（prev_ifindex），不用名字：设备可被改名，按名字在
 * SESSION_DOWN 里就找不到它，于是"报成功但设备还在、dev_owned 还留着"。
 * 反过来 ifindex 会被内核复用（删掉后新建很可能拿回同一个号），所以"还是
 * 同一张设备"必须 prev_owned 与 ifindex 同时成立。
 */
static int iwan_dev_ensure(struct net *net, u32 req_mtu, bool create,
			   bool prev_owned, int prev_ifindex,
			   struct iwan_dev_info *out)
{
	struct net_device *dev;
	/*
	 * rtnl_create_link() 的 tb 参数是 IFLA_* 属性数组，本内核在函数入口就
	 * 无条件读 tb[IFLA_NUM_TX_QUEUES]（+0x22 处的 0xf8(%tb)），**不接受
	 * NULL**。传 NULL 的后果已实测：空指针 → 而此处持有 rtnl 锁 → 任务带锁
	 * 退出（日志 "exited with irqs disabled"）→ 路由/网络子系统连同依赖它
	 * 的用户态一起僵死，整机表现如同卡死（ping 仍通、SSH 不响应、切不了
	 * TTY）。给一个全零数组即等价于"不带任何属性"，num_tx_queues 取默认。
	 */
	struct nlattr *tb[IFLA_MAX + 1] = {};
	bool created = false;
	int err;

	memset(out, 0, sizeof(*out));
	strscpy(out->name, "-", sizeof(out->name));
	out->mtu = req_mtu;

	rtnl_lock();
	dev = __dev_get_by_name(net, IWAN_DEV_NAME);
	if (dev)
		goto have_dev;
	if (!create) {
		rtnl_unlock();
		return 0;	/* 不建且不存在：只回执请求的 MTU */
	}

	dev = rtnl_create_link(net, IWAN_DEV_NAME, NET_NAME_UNKNOWN,
			       &iwan_link_ops, tb, NULL);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		rtnl_unlock();
		pr_err("netns %u: 创建 %s 失败 %d\n",
		       net->ns.inum, IWAN_DEV_NAME, err);
		return err;
	}
	if (dev->reg_state != NETREG_REGISTERED) {
		err = register_netdevice(dev);
		if (err) {
			free_netdev(dev);
			rtnl_unlock();
			pr_err("netns %u: 注册 %s 失败 %d\n",
			       net->ns.inum, IWAN_DEV_NAME, err);
			return err;
		}
	}
	/* rtnl 建链的收尾：标记 RTNL_LINK_INITIALIZED 并通知 RTNLGRP_LINK，
	 * 等价于 `ip link add` 走完的那一步。返回值必须看（旧实现丢掉了）：
	 * 失败说明设备没完成初始化，注册表里留着一张半成品，宁可当场删掉并
	 * 返回错误，也不要让用户态以为"设备好了"。 */
	err = rtnl_configure_link(dev, NULL, 0, NULL);
	if (err) {
		pr_err("netns %u: 配置 %s 失败 %d\n", net->ns.inum, dev->name, err);
		rtnl_delete_link(dev, 0, NULL);
		rtnl_unlock();
		return err;
	}
	created = true;

have_dev:
	strscpy(out->name, dev->name, sizeof(out->name));
	out->mtu = dev->mtu;
	out->ifindex = dev->ifindex;
	out->ours = (dev->rtnl_link_ops == &iwan_link_ops);
	if (!out->ours) {
		pr_err("netns %u: %s 已被非 iwan 设备占用（kind=%s ifindex=%d），拒绝复用\n",
		       net->ns.inum, dev->name,
		       dev->rtnl_link_ops && dev->rtnl_link_ops->kind ?
				dev->rtnl_link_ops->kind : "?",
		       dev->ifindex);
		rtnl_unlock();
		return -EBUSY;
	} else if (created || !(dev->flags & IFF_UP)) {
		/* 刚建的设备必然 DOWN，已存在但还没 up 的也一样。
		 * 直接赋值与 setup() 同口径：刻意不调 dev_set_mtu() —— 它能发
		 * NETDEV_CHANGEMTU 通知（可观测性更好）也会做 MTU 范围校验，但
		 * 是否内部再取一次 rtnl 随内核版本而异，而这里已经持有 rtnl，
		 * 重入就是死锁。取舍：一条通知不值得冒整机僵死的风险；设备是
		 * 刚建/还没 UP 的，没有别的观察者依赖这次 MTU 变化，范围也已在
		 * SESSION_UP 入口校验过（IWAN_MIN_MTU..IWAN_MAX_MTU）。 */
		dev->mtu = req_mtu;
		if (!(dev->flags & IFF_UP)) {
			/* SESSION_UP 承诺"数据面就绪"：设备必须 UP，否则用户态
			 * 还得自己 ip link set up（验收 T2b/T2d 就是这么查的）。 */
			err = dev_open(dev, NULL);
			if (err) {
				pr_err("netns %u: 打开 %s 失败 %d\n",
				       net->ns.inum, dev->name, err);
				if (created)
					rtnl_delete_link(dev, 0, NULL);
				rtnl_unlock();
				return err;
			}
		}
		out->mtu = dev->mtu;
	} else if (dev->mtu != (int)req_mtu) {
		pr_info("netns %u: %s 已 up，忽略 MTU=%u（实际 %u，要改请 ip link set mtu）\n",
			net->ns.inum, dev->name, req_mtu, dev->mtu);
	}
	/* 所有权：本次创建，或此前会话创建且设备身份（ifindex）未变
	 * ⇒ SESSION_DOWN 负责删。两处细节都是刻意的：
	 *   · 不按名字认领：改过名的设备仍然删得掉；
	 *   · 不只看 dev_owned：ifindex 会被复用，用户删掉我们的设备再建一张
	 *     同号别的设备时，光看标志会误删。
	 * 残留窗口（已知、可接受）：用户删掉我们的设备后又建了一张 **iwan 类型**
	 * 的设备，而内核正好把它分配到同一个 ifindex，此时会被误认成"还是那一张"。
	 * 触发它要同时满足这三个条件，而且被删的仍是一张本模块能服务的 iwan 设备
	 * （不是用户的 TUN）；相比之下，按名字认领的误删窗口大得多（同名即中）。 */
	out->owned = created || (prev_owned && prev_ifindex &&
				 prev_ifindex == dev->ifindex);
	rtnl_unlock();
	return 0;
}

/* 删除模块建的网卡：走 rtnl_link_ops → dellink，即 `ip link del` 同一条路径。
 *
 * 定位设备优先用 ifindex（会话认领时记下），忘了/没有才回落到名字：设备被
 * 改名后按名字找会"找不到 → 报成功"，而设备其实还在。
 * 两道闸门都要过：kind 必须是本模块的 rtnl_link_ops（同名但别的类型的设备，
 * 比如用户自己的 TUN iwan0，绝不碰），ifindex 也必须与会话记的一致。 */
static int iwan_dev_remove(struct net *net, const char *name, int ifindex)
{
	struct net_device *dev;
	int err = 0;

	rtnl_lock();
	dev = ifindex ? __dev_get_by_index(net, ifindex) :
			__dev_get_by_name(net, name);
	if (!dev)
		goto out;			/* 已经不在了：删除幂等 */
	if (dev->rtnl_link_ops != &iwan_link_ops) {
		pr_warn("netns %u: ifindex %d (%s) 不是 iwan 设备，不删\n",
			net->ns.inum, dev->ifindex, dev->name);
		goto out;
	}
	err = rtnl_delete_link(dev, 0, NULL);
out:
	rtnl_unlock();
	return err;
}

/* 快照里的设备名：有会话用会话记的名字；没有会话就查该 netns 里的同名设备，
 * 便于和 `ip link` 对照（查不到回 "-"）。 */
static void iwan_devname_of(struct net *net, const struct iwan_session *s,
			    char *out, size_t len)
{
	struct net_device *dev;

	if (READ_ONCE(s->valid) && s->devname[0]) {
		strscpy(out, s->devname, len);
		return;
	}
	strscpy(out, "-", len);
	rtnl_lock();
	dev = __dev_get_by_name(net, IWAN_DEV_NAME);
	if (dev)
		strscpy(out, dev->name, len);
	rtnl_unlock();
}

/* ------------------------------------------------------------ 回执/快照 */

#define IWAN_PUT_CTR(skb, pn, attr, field)				\
	do {								\
		u64 __v = (u64)atomic64_read(&(pn)->st.field);		\
									\
		if (nla_put((skb), (attr), (int)sizeof(__v), &__v))	\
			goto nla_put_failure;				\
	} while (0)

/* 计数器嵌套（IWAN_A_STATS）。u64 用普通属性：接收侧 nla_get_u64 是 memcpy，
 * 不要求 8 字节对齐，也不需要往属性流里插 pad 属性。 */
static int iwan_genl_put_stats(struct sk_buff *skb, struct iwan_net *pn)
{
	struct nlattr *nest = nla_nest_start(skb, IWAN_A_STATS);

	if (!nest)
		return -EMSGSIZE;
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_PKTS, rx_pkts);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_OUTER, rx_outer);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_REASM, rx_reasm);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_FRAMES, rx_frames);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_DELIVERED, rx_delivered);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BATCH, rx_batch);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BATCH_SKIP, rx_batch_skip);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BAD_HDR, rx_bad_hdr);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_BAD_INNER, rx_bad_inner);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_NOMEM, rx_nomem);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_CTRL_FRAME, rx_ctrl_frame);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_PKTS, tx_pkts);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BYTES, tx_bytes);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BAD_STATE, tx_bad_state);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_BAD_INNER, tx_bad_inner);
	IWAN_PUT_CTR(skb, pn, IWAN_S_TX_ERR, tx_err);
	IWAN_PUT_CTR(skb, pn, IWAN_S_EV_DROPPED, ev_dropped);
	IWAN_PUT_CTR(skb, pn, IWAN_S_RX_FRAG6, rx_frag6);
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

/*
 * 配置快照（会话优先、模块参数回落，与数据面同源 iwan_dp_get）+ keepalive
 * 时间戳 + peer_state + 全部计数器。没有会话时回的就是"模块参数默认值"这
 * 一层，/proc/net/iwan 的读路径不受影响。
 */
static int iwan_genl_put_snapshot(struct sk_buff *skb, struct iwan_net *pn,
				  const char *devname)
{
	struct iwan_session *s = &pn->sess;
	struct iwan_dp dp;
	u64 keepalive;
	u32 flags = 0;
	u32 mtu;
	u16 sport;

	iwan_dp_get(pn, iwan_cfg_get(), false, &dp);
	mtu = READ_ONCE(s->valid) ? READ_ONCE(s->mtu) : (1500 - IWAN_OVERHEAD);
	if (READ_ONCE(s->create_dev))
		flags |= IWAN_A_FLAG_CREATE_DEV;
	/* SPORT 省略（0）时线上用的是 DPORT，回执里给实际生效值 */
	sport = dp.sport ? dp.sport : dp.dport;
	/* keepalive 时间戳与 peer_state 都取自该 netns 的共享内存页
	 * （/dev/iwan，用户态 mmap 读到的是同一份）：单一数据源，不另存一份。 */
	keepalive = iwan_shm_last_rx_ms(pn);

	if (nla_put_u16(skb, IWAN_A_SID, dp.sid) ||
	    nla_put_u32(skb, IWAN_A_TOK, dp.tok) ||
	    nla_put_u8(skb, IWAN_A_ENC, dp.enc) ||
	    nla_put(skb, IWAN_A_KEY, IWAN_KEY_LEN, dp.key) ||
	    nla_put_be32(skb, IWAN_A_OUTER_SRC, dp.outer_src) ||
	    nla_put_be32(skb, IWAN_A_OUTER_DST, dp.outer_dst) ||
	    /* 外层 v6 会话才发这三个属性（v4 会话一个都不发）：族由"属性在不在"
	     * 表达，与 SESSION_UP 入参的规则一致 —— 靠"全零 v6 地址"来判断族
	     * 会把"v6 会话但未绑 IP"和"v4 会话"混在一起。 */
	    (dp.outer_v6 && nla_put(skb, IWAN_A_OUTER_SRC6,
				    sizeof(dp.outer_src6), &dp.outer_src6)) ||
	    (dp.outer_v6 && nla_put(skb, IWAN_A_OUTER_DST6,
				    sizeof(dp.outer_dst6), &dp.outer_dst6)) ||
	    (dp.outer_v6 && nla_put(skb, IWAN_A_IP6, sizeof(s->bind_ip6),
				    &s->bind_ip6)) ||
	    nla_put_be16(skb, IWAN_A_DPORT, htons(dp.dport)) ||
	    nla_put_be16(skb, IWAN_A_SPORT, htons(sport)) ||
	    nla_put_u32(skb, IWAN_A_MTU, mtu) ||
	    nla_put_u32(skb, IWAN_A_FLAGS, flags) ||
	    nla_put_u8(skb, IWAN_A_ENABLED, dp.enabled ? 1 : 0) ||
	    /* 绑定规格与解析结果：控制面的对账输入。carrier 是**实际**
	     * 生效的那张（由会话建立时的解析结果决定，0 = 还没解析），
	     * 与请求的 oif/ip 一起才能判断"要绑的"和"绑上的"是否一致。 */
	    nla_put_u32(skb, IWAN_A_OIF, READ_ONCE(s->oif)) ||
	    nla_put_be32(skb, IWAN_A_IP, READ_ONCE(s->bind_ip)) ||
	    nla_put_u32(skb, IWAN_A_CARRIER, READ_ONCE(pn->carrier)) ||
	    nla_put_string(skb, IWAN_A_DEVNAME, devname) ||
	    nla_put(skb, IWAN_A_LAST_KEEPALIVE_MS, (int)sizeof(keepalive),
		    &keepalive) ||
	    nla_put_u8(skb, IWAN_A_PEER_STATE,
		       (u8)iwan_shm_peer_state(pn)) ||
	    iwan_genl_put_stats(skb, pn))
		return -EMSGSIZE;
	return 0;
}

static int iwan_genl_reply_snapshot(struct genl_info *info, u8 cmd,
				    const char *devname)
{
	struct sk_buff *rep;
	void *hdr;

	rep = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	hdr = genlmsg_put_reply(rep, info, &iwan_genl_family, 0, cmd);
	if (!hdr || iwan_genl_put_snapshot(rep, iwan_net_of(genl_info_net(info)),
					   devname)) {
		nlmsg_free(rep);
		return -EMSGSIZE;
	}
	genlmsg_end(rep, hdr);
	return genlmsg_reply(rep, info);
}

/* SESSION_UP 的回执：设备名 + 实际 MTU + 设备归属（CONTROL-PLANE §3） */
static int iwan_genl_reply_up(struct genl_info *info, const char *devname,
			      u32 mtu, bool owned)
{
	struct sk_buff *rep;
	void *hdr;

	rep = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	hdr = genlmsg_put_reply(rep, info, &iwan_genl_family, 0,
				IWAN_CMD_SESSION_UP);
	if (!hdr ||
	    nla_put_string(rep, IWAN_A_DEVNAME, devname) ||
	    nla_put_u32(rep, IWAN_A_MTU, mtu) ||
	    /* DEV_OWNED：1 = 这张设备是模块建/认领的（SESSION_DOWN 会删它），
	     * 0 = 不是我们建的（比如用户自己 ip link add 的 iwan 设备）。
	     * 普通 u32 主机序，与同表其它标量一致；旧客户端不认识这个属性，
	     * 按 genetlink 惯例忽略即可。 */
	    nla_put_u32(rep, IWAN_A_DEV_OWNED, owned ? 1 : 0)) {
		nlmsg_free(rep);
		return -EMSGSIZE;
	}
	genlmsg_end(rep, hdr);
	return genlmsg_reply(rep, info);
}

/* ------------------------------------------------------------ 命令 */

static int iwan_genl_session_up(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	struct iwan_dev_info dev;
	struct iwan_session req;
	const char *conflict = NULL;
	bool was_valid;
	u32 flags, mtu;
	int err;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	/*
	 * RX 钩子闸门：iwan_rx_net_init() 的返回值在 iwan_core.c 里刻意不传播
	 * （让整个 netns 建不起来代价太大），失败时 pn->rx_hooked 保持 false。
	 * 那种 netns 的数据面是死的 —— 钩子没挂上，一个入站包都不会被解封。
	 * 若这里放行，用户态会拿到"SESSION_UP 成功 + iwan0 已 UP"的回执，
	 * 却永远收不到包，排障时会一路怀疑对端。所以在这里明确失败。
	 */
	if (!READ_ONCE(pn->rx_hooked)) {
		GENL_SET_ERR_MSG(info, "该 netns 的 RX 钩子未挂上（nf_register_net_hook 曾失败），数据面不可用");
		pr_err("netns %u: SESSION_UP 拒绝：RX 钩子未挂上（见 iwan_rx_net_init 的日志）\n",
		       net->ns.inum);
		return -EIO;
	}

	/* 必需属性；只有 SPORT（省略 = 用 DPORT）、MTU（省略 =
	 * 1500-IWAN_OVERHEAD）、FLAGS（省略 = CREATE_DEV）有文档化缺省。
	 * 外层地址必须给**恰好一对**：v4 的 (OUTER_SRC, OUTER_DST) 或 v6 的
	 * (OUTER_SRC6, OUTER_DST6) —— 给了哪一对就是哪一族，没有单独的族开关
	 * （两族同时给必然有歧义：外层头只能有一种版本）。 */
	if (!info->attrs[IWAN_A_SID] || !info->attrs[IWAN_A_TOK] ||
	    !info->attrs[IWAN_A_ENC] || !info->attrs[IWAN_A_KEY] ||
	    !info->attrs[IWAN_A_DPORT]) {
		GENL_SET_ERR_MSG(info, "SESSION_UP 需要 SID/TOK/ENC/KEY/DPORT 与外层地址对（OUTER_SRC+OUTER_DST 或 OUTER_SRC6+OUTER_DST6）");
		return -EINVAL;
	}
	if (nla_len(info->attrs[IWAN_A_KEY]) != IWAN_KEY_LEN) {
		GENL_SET_ERR_MSG(info, "KEY 必须是 8 字节");
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	req.sid = nla_get_u16(info->attrs[IWAN_A_SID]);
	req.tok = nla_get_u32(info->attrs[IWAN_A_TOK]);
	req.enc = nla_get_u8(info->attrs[IWAN_A_ENC]);
	memcpy(req.key, nla_data(info->attrs[IWAN_A_KEY]), IWAN_KEY_LEN);
	{
		const bool any4 = info->attrs[IWAN_A_OUTER_SRC] ||
				  info->attrs[IWAN_A_OUTER_DST];
		const bool pair4 = info->attrs[IWAN_A_OUTER_SRC] &&
				   info->attrs[IWAN_A_OUTER_DST];
		const bool any6 = info->attrs[IWAN_A_OUTER_SRC6] ||
				  info->attrs[IWAN_A_OUTER_DST6];
		const bool pair6 = info->attrs[IWAN_A_OUTER_SRC6] &&
				   info->attrs[IWAN_A_OUTER_DST6];

		if (!pair4 && !pair6) {
			GENL_SET_ERR_MSG(info, "外层地址必须成对：OUTER_SRC+OUTER_DST（v4）或 OUTER_SRC6+OUTER_DST6（v6）");
			return -EINVAL;
		}
		if (any4 && any6) {
			GENL_SET_ERR_MSG(info, "外层地址族必须唯一：v4 与 v6 两对不能同时给");
			return -EINVAL;
		}
		if (pair6) {
			if (nla_len(info->attrs[IWAN_A_OUTER_SRC6]) !=
					sizeof(struct in6_addr) ||
			    nla_len(info->attrs[IWAN_A_OUTER_DST6]) !=
					sizeof(struct in6_addr)) {
				GENL_SET_ERR_MSG(info, "OUTER_SRC6/OUTER_DST6 必须是 16 字节");
				return -EINVAL;
			}
			req.outer_v6 = true;
			nla_memcpy(&req.outer_src6,
				   info->attrs[IWAN_A_OUTER_SRC6],
				   sizeof(req.outer_src6));
			nla_memcpy(&req.outer_dst6,
				   info->attrs[IWAN_A_OUTER_DST6],
				   sizeof(req.outer_dst6));
		} else {
			req.outer_src = nla_get_be32(info->attrs[IWAN_A_OUTER_SRC]);
			req.outer_dst = nla_get_be32(info->attrs[IWAN_A_OUTER_DST]);
		}
	}
	req.dport = ntohs(nla_get_be16(info->attrs[IWAN_A_DPORT]));
	if (info->attrs[IWAN_A_SPORT])
		req.sport = ntohs(nla_get_be16(info->attrs[IWAN_A_SPORT]));
	/* 省略 MTU 的默认值要按**本会话的族**算开销：外层 v6 比 v4 多 20B，
	 * 用 v4 的默认值会让默认配置在 1500 承载上直接违反下面的 MTU 判据。 */
	mtu = info->attrs[IWAN_A_MTU] ? nla_get_u32(info->attrs[IWAN_A_MTU]) :
		(u32)(1500 - (req.outer_v6 ? IWAN_OVERHEAD_V6 : IWAN_OVERHEAD));
	flags = info->attrs[IWAN_A_FLAGS] ?
		nla_get_u32(info->attrs[IWAN_A_FLAGS]) : IWAN_A_FLAG_CREATE_DEV;
	/* 省略 = 0 = 不指定：由 FIB 解析一次后钉住（见 iwan_tx.c 的说明） */
	req.oif = info->attrs[IWAN_A_OIF] ?
		nla_get_u32(info->attrs[IWAN_A_OIF]) : 0;
	/* 省略 = 0 = 不按出口 IP 绑定；给了就必须是本机地址，且与 oif
	 * （若也给）指向同一张接口 —— 见下面的显式校验。 */
	req.bind_ip = info->attrs[IWAN_A_IP] ?
		nla_get_be32(info->attrs[IWAN_A_IP]) : 0;
	/* "绑 IP"在外层 v6 上是 IWAN_A_IP6（同一份语义：出口地址必须等于外层
	 * 源地址、必须属于某张本机接口）。两个族各一个入口，给错族就是
	 * -EINVAL，不做隐式转换。 */
	if (info->attrs[IWAN_A_IP6]) {
		if (!req.outer_v6) {
			GENL_SET_ERR_MSG(info, "IWAN_A_IP6 只用于外层 v6 会话");
			return -EINVAL;
		}
		if (nla_len(info->attrs[IWAN_A_IP6]) != sizeof(struct in6_addr)) {
			GENL_SET_ERR_MSG(info, "IWAN_A_IP6 必须是 16 字节");
			return -EINVAL;
		}
		nla_memcpy(&req.bind_ip6, info->attrs[IWAN_A_IP6],
			   sizeof(req.bind_ip6));
	} else if (info->attrs[IWAN_A_IP] && req.outer_v6) {
		GENL_SET_ERR_MSG(info, "IWAN_A_IP 是 v4 的出口地址，外层 v6 请用 IWAN_A_IP6");
		return -EINVAL;
	}

	/* 自洽校验：数据面就是靠这五元组过滤，缺一不可 */
	if (!req.dport || req.enc > 1 ||
	    (req.outer_v6 ? (ipv6_addr_any(&req.outer_src6) ||
			     ipv6_addr_any(&req.outer_dst6))
			  : (!req.outer_src || !req.outer_dst)) ||
	    mtu < IWAN_MIN_MTU ||
	    /* 上限 = 模块参数 max_mtu，再用规范硬上限夹一次。硬上限按族不同：
	     * 外层 v4 的总长只有 16 位（超过 65499 会让 tot_len 溢出）；外层
	     * v6 的负载长度也是 16 位，但基本头多 20 字节，所以硬上限低
	     * 20（IWAN_MTU_HARD_MAX_V6）。 */
	    mtu > min_t(u32, READ_ONCE(iwan_cfg_get()->max_mtu),
			(u32)(req.outer_v6 ? IWAN_MTU_HARD_MAX_V6 :
					     IWAN_MTU_HARD_MAX)) ||
	    (flags & ~IWAN_A_FLAG_CREATE_DEV)) {
		GENL_SET_ERR_MSG(info, "参数非法：外层地址/端口不能为 0，ENC∈{0,1}，"
				      "MTU 越界；FLAGS 只定义了 CREATE_DEV（bit0），"
				      "bit1 是保留位（代答未实现），置位即拒绝");
		if (req.outer_v6)
			pr_info("netns %u: SESSION_UP 参数非法 src=%pI6c dst=%pI6c dport=%u enc=%u mtu=%u\n",
				net->ns.inum, &req.outer_src6,
				&req.outer_dst6, req.dport, req.enc, mtu);
		else
			pr_info("netns %u: SESSION_UP 参数非法 src=%pI4 dst=%pI4 dport=%u enc=%u mtu=%u\n",
				net->ns.inum, &req.outer_src,
				&req.outer_dst, req.dport, req.enc, mtu);
		return -EINVAL;
	}

	/* 与已有会话冲突：sid/tok/key/enc/外层端点属于会话身份，改这些必须先
	 * SESSION_DOWN（对端漂移用 SET_PEER）。参数完全一致 = 幂等重放：只刷新
	 * 设备与开关，不重置 keepalive/peer_state。 */
	was_valid = READ_ONCE(s->valid);
	if (was_valid) {
		if (req.sid != READ_ONCE(s->sid))
			conflict = "sid";
		else if (req.tok != READ_ONCE(s->tok))
			conflict = "tok";
		else if (memcmp(req.key, s->key, IWAN_KEY_LEN))
			conflict = "key";
		else if (req.enc != READ_ONCE(s->enc))
			conflict = "enc";
		else if (req.outer_v6 != READ_ONCE(s->outer_v6))
			conflict = "outer_family";
		else if (req.outer_v6 &&
			 !ipv6_addr_equal(&req.outer_src6, &s->outer_src6))
			conflict = "outer_src6";
		else if (req.outer_v6 &&
			 !ipv6_addr_equal(&req.outer_dst6, &s->outer_dst6))
			conflict = "outer_dst6";
		else if (!req.outer_v6 &&
			 req.outer_src != READ_ONCE(s->outer_src))
			conflict = "outer_src";
		else if (!req.outer_v6 &&
			 req.outer_dst != READ_ONCE(s->outer_dst))
			conflict = "outer_dst";
		else if (!ipv6_addr_equal(&req.bind_ip6, &s->bind_ip6))
			conflict = "ip6";
		else if (req.dport != READ_ONCE(s->dport))
			conflict = "dport";
		else if (req.sport != READ_ONCE(s->sport))
			conflict = "sport";
		else if (req.oif != READ_ONCE(s->oif))
			conflict = "oif";
		else if (req.bind_ip != READ_ONCE(s->bind_ip))
			conflict = "ip";
		if (conflict) {
			GENL_SET_ERR_MSG(info, "SESSION_UP 与已有会话冲突（dmesg 有字段名）");
			pr_info("netns %u: SESSION_UP 拒绝：%s 与已有会话不一致（先 SESSION_DOWN，端点漂移用 SET_PEER）\n",
				net->ns.inum, conflict);
			return -EINVAL;
		}
	}

	/* 设备：按需创建/复用（只在本 netns；绝不在 pernet 初始化里建）。
	 * prev_owned/prev_ifindex **都不加 was_valid 条件**：上一次 SESSION_DOWN
	 * 若是删设备失败，valid 已经落了、而 dev_owned/dev_ifindex 还留着，
	 * 那次会话没删掉的设备必须由下一次 SESSION_UP 接着认领 —— 老实现写成
	 * `was_valid && dev_owned`，于是"DOWN 失败 → 再来一次 UP"就把所有权
	 * 抹掉了，那张设备此后谁也删不掉（永久残留）。 */
	err = iwan_dev_ensure(net, mtu, flags & IWAN_A_FLAG_CREATE_DEV,
			      READ_ONCE(s->dev_owned),
			      READ_ONCE(s->dev_ifindex), &dev);
	if (err)
		return err;

	/* 写会话状态：valid 最后置位，数据面不会读到半套凭据 */
	WRITE_ONCE(s->enabled, true);
	WRITE_ONCE(s->create_dev, !!(flags & IWAN_A_FLAG_CREATE_DEV));
	WRITE_ONCE(s->dev_owned, dev.owned);
	WRITE_ONCE(s->dev_ifindex, dev.ifindex);
	WRITE_ONCE(s->enc, req.enc);
	WRITE_ONCE(s->sid, req.sid);
	WRITE_ONCE(s->tok, req.tok);
	memcpy(s->key, req.key, IWAN_KEY_LEN);
	/* 外层族与端点：只写当前这一族，另一族清零 —— iwan_dp_get() 会把两个
	 * 都拷给数据面，留着一族的陈旧地址只会让"到底绑的是哪族"需要靠标志位
	 * 推断（iwan_dp_bound() 就得同时看两个族的 bind_ip）。 */
	WRITE_ONCE(s->outer_v6, req.outer_v6);
	if (req.outer_v6) {
		s->outer_src6 = req.outer_src6;
		s->outer_dst6 = req.outer_dst6;
		WRITE_ONCE(s->outer_src, 0);
		WRITE_ONCE(s->outer_dst, 0);
	} else {
		WRITE_ONCE(s->outer_src, req.outer_src);
		WRITE_ONCE(s->outer_dst, req.outer_dst);
		memset(&s->outer_src6, 0, sizeof(s->outer_src6));
		memset(&s->outer_dst6, 0, sizeof(s->outer_dst6));
	}
	s->bind_ip6 = req.bind_ip6;
	WRITE_ONCE(s->dport, req.dport);
	WRITE_ONCE(s->sport, req.sport);
	WRITE_ONCE(s->oif, req.oif);
	WRITE_ONCE(s->bind_ip, req.bind_ip);
	/*
	 * 存**生效值**而不是请求值：设备已存在且已 UP 时 iwan_dev_ensure() 会
	 * 忽略请求的 MTU（见其 256-258 分支），此时若把请求值记进会话，
	 * GET_STATS 报的 MTU 就是没生效的那个，与"回实测值"的 ABI 描述不符。
	 */
	WRITE_ONCE(s->mtu, dev.mtu);
	strscpy(s->devname, dev.name, sizeof(s->devname));

	/*
	 * 承载网卡：会话建立时解析一次并钉住（显式绑定则严格用绑定那张）。
	 * 必须在 valid 置位之前完成 —— 数据面（含 RX 的网卡过滤）只认这个已
	 * 发布的结果。失败语义按绑定方式分：
	 *   · 显式绑定 ⇒ 拒绝会话：绑定的意义就是不许漂移，宁可在控制面报错，
	 *     也不偷偷换到别的卡上（能判的是"解析得到的那张就是绑定的
	 *     那张"；绑到没有回程路由的卡上时内核会为它合成 scope link
	 *     路由，那种黑洞控制面判不了）；
	 *   · 未显式绑定 ⇒ 只记日志，等首包出站时再解析（那时路由可能已就绪）。
	 * 会话字段虽已写好但 valid 未置位，所以拒绝不会让数据面用到半套状态；
	 * 设备所有权（dev_owned/dev_ifindex）已在上面的字段写入里记录，拒绝也
	 * 不会漏掉设备。
	 */
	if (req.outer_v6 && !ipv6_addr_any(&req.bind_ip6)) {
		/* v6 的"绑 IP"：与 v4 逐条对应（属于本机接口 + 等于外层源地址） */
		int aerr = iwan_bind_ip_check6(net, &req.bind_ip6, req.oif);

		if (aerr == -EADDRNOTAVAIL) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不属于任何本机接口");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI6c 不在本机地址表里（strict：tentative 地址不算）\n",
				net->ns.inum, &req.bind_ip6);
			return aerr;
		}
		if (aerr) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不在指定的承载网卡上");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI6c 不在绑定的网卡 ifindex=%u 上\n",
				net->ns.inum, &req.bind_ip6, req.oif);
			return aerr;
		}
		if (!ipv6_addr_equal(&req.bind_ip6, &req.outer_src6)) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 必须与 OUTER_SRC6 一致");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI6c 与外层源地址 %pI6c 不一致\n",
				net->ns.inum, &req.bind_ip6, &req.outer_src6);
			return -EINVAL;
		}
	} else if (req.bind_ip) {
		/* "绑 IP"的两条硬要求先单独判，错误消息才能指到具体哪一条：
		 *   · 该地址必须属于某张本机接口（地址表，"IP 在哪张卡上"的
		 *     唯一事实来源）；
		 *   · 它同时是外层头的源地址，所以必须等于 OUTER_SRC。 */
		int aerr = iwan_bind_ip_check(net, req.bind_ip, req.oif);

		if (aerr == -EADDRNOTAVAIL) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不属于任何本机接口");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI4 不在本机地址表里\n",
				net->ns.inum, &req.bind_ip);
			return aerr;
		}
		if (aerr) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不在指定的承载网卡上");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI4 不在绑定的网卡 ifindex=%u 上\n",
				net->ns.inum, &req.bind_ip, req.oif);
			return aerr;
		}
		if (req.bind_ip != req.outer_src) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 必须与 OUTER_SRC 一致");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI4 与外层源地址 %pI4 不一致\n",
				net->ns.inum, &req.bind_ip, &req.outer_src);
			return -EINVAL;
		}
	}
	{
		struct net_device *idev = dev_get_by_index(net, dev.ifindex);
		int cerr;

		if (req.outer_v6)
			cerr = iwan_carrier_resolve6(net, pn, idev, dev.mtu,
						     &req.outer_src6,
						     &req.outer_dst6, req.oif,
						     &req.bind_ip6);
		else
			cerr = iwan_carrier_resolve(net, pn, idev, req.outer_src,
						    req.outer_dst, req.oif,
						    req.bind_ip);
		dev_put(idev);
		/* 外层 v6 多一个失败码：内层 MTU + 封装装不进承载网卡 MTU。
		 * 这不是"暂时解析不到"，而是这条会话在当前 MTU 下**不可能**
		 * 正确工作（外层 v6 不分片），所以无论有没有绑定都要拒。 */
		if (cerr == -EMSGSIZE) {
			GENL_SET_ERR_MSG(info, "外层 v6 装不下：内层 MTU + 封装开销 超过承载网卡 MTU（外层 v6 不分片）");
			return cerr;
		}
		/* 无绑定时"解析不到"是设计上要容忍的（设备先建、路由后到），
		 * 但容忍不等于无事发生：把错误码与成因打进 dmesg，别让它变成
		 * 静默的洞（外层 v6 的 MTU 判据正是挂在这条解析上的）。 */
		if (cerr && req.outer_v6 && ipv6_addr_any(&req.bind_ip6))
			pr_info("netns %u: 外层 v6 未解析到承载（%d），按“设备先建、路由后到”容忍；MTU 判据此刻未求值，交给发送侧\n",
				net->ns.inum, cerr);
		if (cerr && req.outer_v6 && !ipv6_addr_any(&req.bind_ip6)) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不可用：经它所属网卡解析不到外层路由（设备不存在/不可用）");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI6c 所属网卡上没有到 %pI6c 的路由（%d）\n",
				net->ns.inum, &req.bind_ip6, &req.outer_dst6,
				cerr);
			return cerr;
		}
		if (cerr && req.outer_v6 && req.oif) {
			GENL_SET_ERR_MSG(info, "绑定的承载网卡不可用：解析不到经它的外层路由（设备不存在/不可用）");
			pr_info("netns %u: SESSION_UP 拒绝：绑定 ifindex=%u 上没有到 %pI6c 的路由（%d）\n",
				net->ns.inum, req.oif, &req.outer_dst6, cerr);
			return cerr;
		}
		if (cerr && req.bind_ip) {
			GENL_SET_ERR_MSG(info, "绑定的出口 IP 不可用：经它所属网卡解析不到外层路由（设备不存在/不可用）");
			pr_info("netns %u: SESSION_UP 拒绝：出口 IP %pI4 所属网卡上没有到 %pI4 的路由（%d）\n",
				net->ns.inum, &req.bind_ip, &req.outer_dst, cerr);
			return cerr;
		}
		if (cerr && req.oif) {
			GENL_SET_ERR_MSG(info, "绑定的承载网卡不可用：解析不到经它的外层路由（设备不存在/不可用）");
			pr_info("netns %u: SESSION_UP 拒绝：绑定 ifindex=%u 上没有到 %pI4 的路由（%d）\n",
				net->ns.inum, req.oif, &req.outer_dst, cerr);
			return cerr;
		}
		if (cerr)
			pr_info("netns %u: 承载网卡暂未解析（%d），等首包出站时再解析\n",
				net->ns.inum, cerr);
		/* v6 未显式绑定时不在这里拒：与 v4 同一口径（等首包出站时再
		 * 解析）。区别是 v6 的出站路径每次都会重新查找并同样校验 MTU，
		 * 所以"路由后出现"照样能被接住。 */
	}
	if (!was_valid) {
		/* 新会话：共享内存页从零开始（时间戳 0 = 还没收到过帧、
		 * peer_state = UNKNOWN、会话级计数器归零）。幂等重放
		 * （was_valid）刻意不重置 —— 与"参数完全一致的重放不打断
		 * keepalive/peer_state"的既有口径一致。 */
		iwan_shm_session_up(pn);
	}
	WRITE_ONCE(s->valid, true);
	/* 会话已生效，才把数据面开关发布到共享内存页（用户态据此判断内核
	 * 数据面是否已为该会话打开）。 */
	iwan_shm_set_enabled(pn, true);

	if (req.outer_v6)
		pr_info("netns %u: SESSION_UP(外层 v6) sid=%u enc=%u dport=%u sport=%u dev=%s ifindex=%d mtu=%u owned=%d oif=%u src=%pI6c dst=%pI6c ip6=%pI6c carrier=%u\n",
			net->ns.inum, req.sid, req.enc, req.dport,
			req.sport ? req.sport : req.dport, dev.name, dev.ifindex,
			dev.mtu, dev.owned, req.oif, &req.outer_src6,
			&req.outer_dst6, &req.bind_ip6, READ_ONCE(pn->carrier));
	else
		pr_info("netns %u: SESSION_UP sid=%u enc=%u dport=%u sport=%u dev=%s ifindex=%d mtu=%u owned=%d oif=%u ip=%pI4 carrier=%u\n",
			net->ns.inum, req.sid, req.enc, req.dport,
			req.sport ? req.sport : req.dport, dev.name, dev.ifindex,
			dev.mtu, dev.owned, req.oif, &req.bind_ip,
			READ_ONCE(pn->carrier));

	/* 回执只差一个 EMSGSIZE 失败：会话已经建立，重放一次 SESSION_UP 幂等 */
	return iwan_genl_reply_up(info, dev.name, dev.mtu, dev.owned);
}

static int iwan_genl_session_down(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	int ifindex;
	bool owned;
	int err = 0;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	memcpy(devname, s->devname, sizeof(devname));
	devname[sizeof(devname) - 1] = '\0';
	/* 注意这里**不**看 valid：上一次 DOWN 若是删设备失败，valid 已经落了，
	 * 但 dev_owned/dev_ifindex/devname 还留着，重复 SESSION_DOWN 必须能接着删。
	 * 判据也不再依赖名字：改名后名字对不上，但 ifindex 仍然指向那张设备。 */
	ifindex = READ_ONCE(s->dev_ifindex);
	owned = READ_ONCE(s->dev_owned) && (ifindex || devname[0] != '\0');

	/* ① 关数据面：valid 先落，避免删设备期间还在用半套状态 */
	WRITE_ONCE(s->valid, false);

	/* ② 只删由模块创建的那张网卡（rtnl_link_ops 对齐路径）。失败就保留
	 *    dev_owned/dev_ifindex/devname，重复 SESSION_DOWN 可重试；用户也可以
	 *    直接 `ip link del`。 */
	if (owned) {
		err = iwan_dev_remove(net, devname, ifindex);
		if (err)
			pr_warn("netns %u: 删除 %s(ifindex=%d) 失败 %d（保留所有权以便重试）\n",
				net->ns.inum, devname, ifindex, err);
	}

	/* ③ 清零凭据与 keepalive：之后数据面回到模块参数默认值。
	 * 共享内存页整页清零（保留 version）：last_rx_ms=0、peer_state=UNKNOWN、
	 * enabled=0、会话级计数器归零 —— 与 GET_STATS 的"SESSION_DOWN 之后
	 * keepalive/peer_state 清零"是同一份存储。 */
	WRITE_ONCE(s->enabled, false);
	WRITE_ONCE(s->create_dev, false);
	WRITE_ONCE(s->enc, 0);
	WRITE_ONCE(s->sid, 0);
	WRITE_ONCE(s->tok, 0);
	memset(s->key, 0, IWAN_KEY_LEN);
	WRITE_ONCE(s->outer_src, 0);
	WRITE_ONCE(s->outer_dst, 0);
	/* 族标志必须一起清：留着 outer_v6=true 会让下一条 v4 会话在
	 * iwan_dp_get() 里被当成 v6（外层头就会用零地址去发）。 */
	WRITE_ONCE(s->outer_v6, false);
	memset(&s->outer_src6, 0, sizeof(s->outer_src6));
	memset(&s->outer_dst6, 0, sizeof(s->outer_dst6));
	memset(&s->bind_ip6, 0, sizeof(s->bind_ip6));
	WRITE_ONCE(s->dport, 0);
	WRITE_ONCE(s->sport, 0);
	WRITE_ONCE(s->oif, 0);
	WRITE_ONCE(s->bind_ip, 0);
	WRITE_ONCE(s->mtu, 0);
	/* 解开承载网卡钉住：会话结束，数据面回到"由 FIB 自己决定"（或 /proc 里
	 * 的显式绑定）。路由缓存的作废由数据面按 tx_route_* 记录值惰性完成。 */
	iwan_carrier_forget(pn);
	iwan_shm_session_down(pn);
	if (!err) {
		WRITE_ONCE(s->dev_owned, false);
		WRITE_ONCE(s->dev_ifindex, 0);
		memset(s->devname, 0, sizeof(s->devname));
	} else {
		return err;	/* 让用户态看到失败并重试 */
	}

	pr_info("netns %u: SESSION_DOWN（dev=%s ifindex=%d 已删，行为回到模块参数默认值）\n",
		net->ns.inum, devname[0] ? devname : "-", ifindex);
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SESSION_DOWN,
					devname[0] ? devname : "-");
}

static int iwan_genl_set_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	__be32 dst;
	u16 port;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;
	if (!READ_ONCE(s->valid)) {
		GENL_SET_ERR_MSG(info, "尚无会话：先 SESSION_UP");
		return -ENOENT;
	}
	/* 只有 OUTER_DST/OUTER_DST6/SPORT/DPORT 可热改：凭据与本端地址必须重建
	 * 会话（族也是会话身份的一部分：换族 = 换外层头版本，走 SESSION_UP） */
	if (info->attrs[IWAN_A_SID] || info->attrs[IWAN_A_TOK] ||
	    info->attrs[IWAN_A_ENC] || info->attrs[IWAN_A_KEY] ||
	    info->attrs[IWAN_A_OUTER_SRC] || info->attrs[IWAN_A_OUTER_SRC6]) {
		GENL_SET_ERR_MSG(info, "SET_PEER 只接受 OUTER_DST/OUTER_DST6/SPORT/DPORT");
		return -EINVAL;
	}
	if (!info->attrs[IWAN_A_OUTER_DST] &&
	    !info->attrs[IWAN_A_OUTER_DST6] && !info->attrs[IWAN_A_SPORT] &&
	    !info->attrs[IWAN_A_DPORT]) {
		GENL_SET_ERR_MSG(info, "SET_PEER 至少要给 OUTER_DST/OUTER_DST6/SPORT/DPORT 之一");
		return -EINVAL;
	}
	if (info->attrs[IWAN_A_OUTER_DST6] && info->attrs[IWAN_A_OUTER_DST]) {
		GENL_SET_ERR_MSG(info, "OUTER_DST 与 OUTER_DST6 只能给一个");
		return -EINVAL;
	}

	if (info->attrs[IWAN_A_OUTER_DST6]) {
		/* v6 会话的对端漂移。族的判据是会话自己的 outer_v6：给错族就
		 * 拒绝，不做隐式转换（"v6 会话收到 OUTER_DST"只可能是控制面
		 * 搞错了族）。 */
		struct in6_addr d6;

		if (!READ_ONCE(s->outer_v6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 只用于外层 v6 会话");
			return -EINVAL;
		}
		if (nla_len(info->attrs[IWAN_A_OUTER_DST6]) !=
		    sizeof(struct in6_addr)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 必须是 16 字节");
			return -EINVAL;
		}
		nla_memcpy(&d6, info->attrs[IWAN_A_OUTER_DST6], sizeof(d6));
		if (ipv6_addr_any(&d6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST6 不能为 ::");
			return -EINVAL;
		}
		/* 16 字节地址的更新不在原子性上做文章：漂移是低频控制面事件，
		 * 最坏情况是漂移瞬间几个包按旧地址匹配不上（丢弃），与
		 * SESSION_UP 里写端点同一口径。 */
		s->outer_dst6 = d6;
		iwan_carrier_forget(pn);
	} else if (info->attrs[IWAN_A_OUTER_DST]) {
		if (READ_ONCE(s->outer_v6)) {
			GENL_SET_ERR_MSG(info, "OUTER_DST 是 v4 的对端地址，外层 v6 请用 OUTER_DST6");
			return -EINVAL;
		}
		dst = nla_get_be32(info->attrs[IWAN_A_OUTER_DST]);
		if (!dst) {
			GENL_SET_ERR_MSG(info, "OUTER_DST 不能为 0");
			return -EINVAL;
		}
		WRITE_ONCE(s->outer_dst, dst);
		/* 对端漂移可能落到另一张承载网卡上：解开钉住，下一包按新端点重新
		 * 解析（显式绑定照旧生效，那张卡不通就计入 tx_err）。 */
		iwan_carrier_forget(pn);
	}
	if (info->attrs[IWAN_A_DPORT]) {
		port = ntohs(nla_get_be16(info->attrs[IWAN_A_DPORT]));
		if (!port) {
			GENL_SET_ERR_MSG(info, "DPORT 不能为 0");
			return -EINVAL;
		}
		WRITE_ONCE(s->dport, port);
	}
	/* SPORT = 0 是合法值（表示"用 DPORT"） */
	if (info->attrs[IWAN_A_SPORT])
		WRITE_ONCE(s->sport,
			   ntohs(nla_get_be16(info->attrs[IWAN_A_SPORT])));

	if (READ_ONCE(s->outer_v6))
		pr_info("netns %u: SET_PEER(外层 v6) dst=%pI6c dport=%u sport=%u\n",
			net->ns.inum, &s->outer_dst6, READ_ONCE(s->dport),
			READ_ONCE(s->sport));
	else
		pr_info("netns %u: SET_PEER dst=%pI4 dport=%u sport=%u\n",
			net->ns.inum, &s->outer_dst, READ_ONCE(s->dport),
			READ_ONCE(s->sport));
	iwan_devname_of(net, s, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SET_PEER, devname);
}

static int iwan_genl_set_enabled(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_session *s = &pn->sess;
	char devname[IFNAMSIZ];
	bool en;

	if (!iwan_genl_capable(skb, net))
		return -EPERM;
	if (!READ_ONCE(s->valid)) {
		GENL_SET_ERR_MSG(info, "尚无会话：先 SESSION_UP");
		return -ENOENT;
	}
	if (!info->attrs[IWAN_A_ENABLED]) {
		GENL_SET_ERR_MSG(info, "SET_ENABLED 需要 ENABLED");
		return -EINVAL;
	}
	en = nla_get_u8(info->attrs[IWAN_A_ENABLED]) ? true : false;
	WRITE_ONCE(s->enabled, en);
	/* 共享内存页的 enabled 也跟上（用户态零系统调用就能看出数据面被停了）；
	 * 口径与数据面 dp.enabled 一致：会话开关 && 模块参数总开关。 */
	iwan_shm_set_enabled(pn, en);
	pr_info("netns %u: SET_ENABLED %d（会话状态保留）\n", net->ns.inum, en);
	iwan_devname_of(net, s, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_SET_ENABLED, devname);
}

static int iwan_genl_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct iwan_net *pn = iwan_net_of(net);
	char devname[IFNAMSIZ];

	if (!iwan_genl_capable(skb, net))
		return -EPERM;

	/* 没有会话也能读：回的是模块参数默认值这一层的配置 + 现有计数器，
	 * 与数据面回落路径同源（GET_STATS 是排障入口）。
	 * TODO(dump)：CONTROL-PLANE §3 允许以后加 NLM_F_DUMP 逐 netns 枚举；
	 * 现在没有 .dumpit，内核直接回 -EOPNOTSUPP。 */
	iwan_devname_of(net, &pn->sess, devname, sizeof(devname));
	return iwan_genl_reply_snapshot(info, IWAN_CMD_GET_STATS, devname);
}

/* ------------------------------------------------------------ 事件多播 */

/*
 * 事件令牌桶：还能不能再投递一个控制帧事件。软中断安全（只用原子操作，
 * 不加锁、不睡眠、不分配），口径与字段见 iwan.h 的 iwan_ev_bucket。
 *
 * 返回 false = 桶空，调用者负责计数并跳过本次多播。
 *
 * 为什么要限速：控制帧**没有**可用的凭据闸门 —— iwan_ctrl_cred_ok() 对
 * PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT 无条件放行（握手期内核还没有会话，
 * 不放行用户态就永远收不到握手包）。没有这一层，一个任意源就能用伪造的
 * PT_OPEN 帧把 events 多播（每次一个 genlmsg 分配 + 全组多播）打满。
 *
 * 实现要点：
 *   · 首次使用（last_ms == 0）：灌满桶并立时基；CAS 让并发者共享同一时基；
 *   · 补充令牌只由"成功把 last_ms 从旧值推进到 now"的那个 CPU 做，避免多
 *     个 CPU 重复补充；补充量 = 经过毫秒数 × 速率 —— 因为 SCALE=1000 正好
 *     与"每秒"相抵，单位就是令牌×SCALE，不用除法；
 *   · 取令牌用 CAS 循环，拿不到就说明桶空。并发下最多多放一两个令牌，这是
 *     刻意接受的误差（见 iwan.h 的说明）。
 */
static bool iwan_ev_rate_ok(struct iwan_net *pn)
{
	struct iwan_ev_bucket *b = &pn->ev_bucket;
	const u64 cap = (u64)IWAN_EV_BURST * IWAN_EV_TOK_SCALE;
	u64 now = iwan_now_ms();
	u64 last = (u64)atomic64_read(&b->last_ms);
	u64 tokens;

	if (unlikely(!last)) {
		atomic64_set(&b->tokens, (s64)cap);
		atomic64_cmpxchg(&b->last_ms, 0, (s64)now);
		last = (u64)atomic64_read(&b->last_ms);
	}
	if (now > last &&
	    atomic64_cmpxchg(&b->last_ms, (s64)last, (s64)now) == (s64)last) {
		tokens = (u64)atomic64_read(&b->tokens) +
			 (now - last) * IWAN_EV_RATE_PER_SEC;
		if (tokens > cap)
			tokens = cap;	/* 桶满：空闲再久也不会攒出更多突发 */
		atomic64_set(&b->tokens, (s64)tokens);
	}
	for (;;) {
		tokens = (u64)atomic64_read(&b->tokens);
		if (tokens < IWAN_EV_TOK_SCALE)
			return false;
		if (atomic64_cmpxchg(&b->tokens, (s64)tokens,
				     (s64)(tokens - IWAN_EV_TOK_SCALE)) ==
		    (s64)tokens)
			return true;
	}
}

/* 事件只投递到会话所属 netns；调用点可能在软中断里（RX 钩子），一律 GFP_ATOMIC。
 * 多播成功与否不影响数据面：失败只计数，不打印。 */
static void iwan_ev_send(struct iwan_net *pn, struct sk_buff *skb, void *hdr)
{
	genlmsg_end(skb, hdr);
	(void)genlmsg_multicast_netns(&iwan_genl_family, pn->net, skb, 0,
				      IWAN_MCGRP_EVENTS_IDX, GFP_ATOMIC);
}

static struct sk_buff *iwan_ev_new(struct iwan_net *pn, u8 cmd, void **hdr)
{
	struct sk_buff *skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);

	if (!skb) {
		atomic64_inc(&pn->st.rx_nomem);
		return NULL;
	}
	*hdr = genlmsg_put(skb, 0, 0, &iwan_genl_family, 0, cmd);
	if (!*hdr) {
		nlmsg_free(skb);
		atomic64_inc(&pn->st.rx_nomem);
		return NULL;
	}
	return skb;
}

/*
 * IWAN_EV_CTRL_FRAME：非数据帧原样转交用户态。
 * frame 是**外层 IP/UDP 头之后**的原始帧字节（8B 帧头 + 载荷，已按
 * IWAN_CTRL_FRAME_MAX 截断），用户态自己验签（IWAN_CTRL_LEN=24 的 HMAC）。
 * SID 用会话 sid（事件属于哪个会话），帧里自己的 sid 在 FRAME 原样字节里。
 *
 * 返回值：true = 通过限速（后续语义事件照常补发）；false = 被令牌桶丢弃，
 * 已计入 st.ev_dropped。两种情况下**共享内存的记账都已经发生**
 * （iwan_decap_one 里的 last_rx_ms/peer_state，以及 PT_CLOSE 的置 0），
 * 限速只影响多播，不影响"对端是否活着"的判定。
 *
 * 注意 rx_ctrl_frame 计数器与它在共享内存页里的镜像是在调用者
 * （iwan_rx_ctrl）里、进桶之前累加的：它记的是"过了凭据闸门的非数据帧"，
 * 与被限速丢掉多少无关；两个数的关系是 ev_dropped ≤ rx_ctrl_frame。
 */
bool iwan_ev_ctrl_frame(struct iwan_net *pn, u16 sid,
			const struct iwan_outer_tuple *t,
			const u8 *frame, size_t len)
{
	struct sk_buff *skb;
	void *hdr;

	/* 限速放在最前面：超限的帧连 genlmsg 都不分配 —— 限速的意义就在于
	 * 省掉这个 GFP_ATOMIC 分配与多播，而不是先花掉再丢。 */
	if (!iwan_ev_rate_ok(pn)) {
		atomic64_inc(&pn->st.ev_dropped);
		return false;
	}

	skb = iwan_ev_new(pn, IWAN_EV_CTRL_FRAME, &hdr);
	if (!skb)
		return true;	/* 分配失败已计入 rx_nomem，不是限速丢弃 */
	if (nla_put_u16(skb, IWAN_EVA_SID, sid) ||
	    nla_put(skb, IWAN_EVA_FRAME, (int)len, frame) ||
	    nla_put_be32(skb, IWAN_EVA_OUTER_SRC, t->src) ||
	    nla_put_be32(skb, IWAN_EVA_OUTER_DST, t->dst) ||
	    nla_put_be16(skb, IWAN_EVA_SPORT, t->sport) ||
	    nla_put_be16(skb, IWAN_EVA_DPORT, t->dport)) {
		nlmsg_free(skb);
		return true;
	}
	iwan_ev_send(pn, skb, hdr);
	return true;
}

void iwan_ev_peer_close(struct iwan_net *pn, u16 sid)
{
	struct sk_buff *skb;
	void *hdr;

	skb = iwan_ev_new(pn, IWAN_EV_PEER_CLOSE, &hdr);
	if (!skb)
		return;
	if (nla_put_u16(skb, IWAN_EVA_SID, sid)) {
		nlmsg_free(skb);
		return;
	}
	iwan_ev_send(pn, skb, hdr);
}

void iwan_ev_keepalive(struct iwan_net *pn, u64 timestamp_ms)
{
	struct sk_buff *skb;
	void *hdr;

	skb = iwan_ev_new(pn, IWAN_EV_KEEPALIVE, &hdr);
	if (!skb)
		return;
	if (nla_put_u16(skb, IWAN_EVA_SID, READ_ONCE(pn->sess.sid)) ||
	    nla_put(skb, IWAN_EVA_TIMESTAMP_MS, (int)sizeof(timestamp_ms),
		    &timestamp_ms)) {
		nlmsg_free(skb);
		return;
	}
	iwan_ev_send(pn, skb, hdr);
}

/* ------------------------------------------------------------ 家族 */

static const struct genl_multicast_group iwan_mcgrps[] = {
	/*
	 * events 携带控制帧原文（用户态验签用的那 24 字节）、对端外层地址与
	 * 端口、会话 SID，必须要求 CAP_NET_ADMIN：genetlink 的每 netns socket
	 * 以 NL_CFG_F_NONROOT_RECV 注册，"能否 bind 多播组"**只**由组自己的
	 * flags 决定 —— genl_bind() 仅在带该 flag 时才查
	 * ns_capable(net->user_ns, CAP_NET_ADMIN)。不设它等于同 netns 任意
	 * 本地用户都能订阅，属实际权限缺口而非优化项。
	 */
	{ .name = IWAN_GENL_MCGRP_EVENTS, .flags = GENL_MCAST_CAP_NET_ADMIN },
};

static const struct genl_ops iwan_genl_ops[] = {
	{
		.cmd		= IWAN_CMD_SESSION_UP,
		.doit		= iwan_genl_session_up,
		.policy		= iwan_policy_up,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SESSION_DOWN,
		.doit		= iwan_genl_session_down,
		.policy		= iwan_policy_down,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SET_PEER,
		.doit		= iwan_genl_set_peer,
		.policy		= iwan_policy_peer,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_SET_ENABLED,
		.doit		= iwan_genl_set_enabled,
		.policy		= iwan_policy_enabled,
		.maxattr	= IWAN_A_MAX,
	},
	{
		.cmd		= IWAN_CMD_GET_STATS,
		.doit		= iwan_genl_get_stats,
		.policy		= iwan_policy_stats,
		.maxattr	= IWAN_A_MAX,
	},
};

static struct genl_family iwan_genl_family = {
	.hdrsize	= 0,
	.name		= IWAN_GENL_NAME,
	.version	= IWAN_GENL_VERSION,
	.maxattr	= IWAN_A_MAX,
	.netnsok	= true,		/* 一切状态按发送 socket 的 netns 取 */
	.module		= THIS_MODULE,
	.ops		= iwan_genl_ops,
	.n_ops		= ARRAY_SIZE(iwan_genl_ops),
	.mcgrps		= iwan_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(iwan_mcgrps),
	/* resv_start_op 保持 0：命令都带 policy，语义按老家族处理 */
};

int iwan_netlink_init(void)
{
	return genl_register_family(&iwan_genl_family);
}

void iwan_netlink_exit(void)
{
	genl_unregister_family(&iwan_genl_family);
}

MODULE_ALIAS_GENL_FAMILY(IWAN_GENL_NAME);
