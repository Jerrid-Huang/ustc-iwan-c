// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_tx.c — 出站：内核虚拟网卡 + ndo_start_xmit 内封装。
 *
 * 为什么必须是内核发送路径（而不是 LWT/tc/XDP 上的 eBPF）：
 *   XOR 会覆盖内层 IP 包的**全部字节**，包括 TCP/UDP 校验和字段。而校验和
 *   在 TX 上是延迟计算的（CHECKSUM_PARTIAL，由驱动/硬件在最后一步算），
 *   GSO 超包也是在最后才分段。任何 eBPF 钩子（LWT_XMIT / tc egress / XDP）
 *   都跑在"校验和未算、GSO 未分段"之前，此时 XOR 出来的包到了对端必然
 *   校验和错误（握手 SYN 都过不去）。参考实现之所以没问题，是因为它的
 *   用户态 daemon 从 TUN 读到的是**已经算完校验和的成品包**。
 *
 * 本设备的 features 只声明 SG（scatter-gather），校验和卸载与 TSO 留空，
 * 于是 validate_xmit_skb 会：
 *   ① 按 GSO 分段（ip_finish_output_gso 也会按路由 MTU 先分好）；
 *   ② 在设备不支持硬件校验和时用软件把 L4 校验和算完（skb_checksum_help，
 *      按页帧迭代，不要求线性）；
 *   ③ 不再强制线性化 —— 分页载荷原样到达 ndo_start_xmit，
 * 由 iwan_xor_paged() 对线性区与页帧逐段做原地变换。
 * 到 ndo_start_xmit 时拿到的就是"完整的单个 IP 报文 + 校验和已就绪"，
 * 此时 XOR 才安全；分片由栈在到达本函数之前完成 ⇒ 天然满足"逐片 XOR"
 * 的冻结语义。
 *
 * 内层版本：v4 与 v6 都封（判据是 iwan_inner_hdr_check()，与 RX 共用一份，
 *   见 iwan_core.c）。XOR 覆盖 skb->data 起的全部字节，与版本无关。
 *
 * 外层版本（切片 2）：v4 与 v6 都封，族由会话决定（iwan_dp.outer_v6）。
 *   到 UDP 头为止完全共用；分岔只有三处：传输层校验和助手（udp_set_csum /
 *   udp6_set_csum）、外层 IP 头（20B/40B）、发出用的栈入口（ip_local_out /
 *   ip6_local_out）。外层 v6 **不分片**：v6 没有 DF 位，源端分片会产生对端
 *   钩子按"外层 v6 分片"丢弃的分片，所以内层 MTU + IWAN_OVERHEAD_V6 必须
 *   装得进承载网卡 MTU —— 会话建立时校验（iwan_carrier_resolve6），出站
 *   路径上再兜一次（超了就丢弃并计 tx_err，绝不悄悄分片）。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>	/* __ip_dev_find：出口 IP -> 所属接口 */
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>		/* struct ipv6hdr：外层 v6 头 40B */
#include <linux/inet.h>		/* INET_ADDRSTRLEN / INET6_ADDRSTRLEN */
#include <net/ip.h>
#include <net/udp.h>
#include <net/ipv6.h>		/* ip6_local_out */
#include <net/ip6_route.h>	/* ip6_route_output（内联） */
#include <net/ip6_checksum.h>	/* udp6_set_csum（v6 伪头校验和） */
#include <net/addrconf.h>	/* ipv6_chk_addr：v6 出口 IP -> 所属接口 */
#include <net/route.h>
#include <net/netns/generic.h>

#include <net/rtnetlink.h>
#include "iwan.h"

static netdev_tx_t iwan_xmit(struct sk_buff *skb, struct net_device *dev);
static netdev_tx_t iwan_tx_outer4(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen);
static netdev_tx_t iwan_tx_outer6(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen);

static const struct net_device_ops iwan_netdev_ops = {
	.ndo_start_xmit		= iwan_xmit,
};

static void iwan_dev_setup(struct net_device *dev)
{
	dev->netdev_ops		= &iwan_netdev_ops;
	dev->type		= ARPHRD_TUNNEL;	/* L3，无 MAC */
	dev->flags		= IFF_POINTOPOINT | IFF_NOARP;
	dev->hard_header_len	= 0;
	dev->addr_len		= 4;	/* dev_addr/broadcast 各一个 IPv4（同 ipip） */
	dev->mtu		= 1500 - IWAN_OVERHEAD;
	dev->min_mtu		= 68;
	dev->max_mtu		= 65535 - IWAN_OVERHEAD;
	/* 预设值：只够本模块自己 push 的外层头。承载网卡一旦钉住（会话建立时
	 * 或首包出站时解析），iwan_carrier_pin() 会把它抬到
	 * IWAN_OVERHEAD + LL_RESERVED_SPACE(承载)，让发送方一次预留够 ——
	 * 于是 ip_finish_output2 的重分配（线性 skb 上是整包拷贝）不再发生。 */
	dev->needed_headroom	= IWAN_OVERHEAD;
	/*
	 * 特性集：只声明 SG（scatter-gather），其余留空。
	 *
	 * 留空校验和卸载与 TSO 仍是 XOR 的正确性前提：栈在进入本驱动之前
	 * 完成软件校验和（skb_checksum_help，按页帧迭代计算，不要求线性）
	 * 与 GSO 分段，变换仍作用于"校验和已冻结的完整单个分组"。
	 * 声明 SG 后 validate_xmit_skb 不再对非线性 skb 执行 __skb_linearize，
	 * 分页载荷得以原样到达 ndo_start_xmit，配合 iwan_xor_paged() 免去
	 * 发送侧整包复制（大 MTU 档每包一次 65KB 级拷贝）。
	 */
	dev->features		= NETIF_F_SG;
	dev->hw_features	= NETIF_F_SG;
	dev->vlan_features	= 0;
	dev->priv_flags		|= IFF_NO_QUEUE;
	/*
	 * 由 rtnl_link_ops 建的设备由核心在注销时释放（netdev_run_todo() 只在
	 * needs_free_netdev 时 free）。漏掉这一行会让每次
	 * `ip link del` / SESSION_DOWN 泄漏一个 net_device —— 控制面会按需
	 * 反复建删，必须在这里声明所有权。
	 */
	dev->needs_free_netdev	= true;
}

/*
 * 承载网卡（下游网卡）绑定。
 *
 * 语义（2026-10-09 定）：**一条会话始终只用一张下游网卡**。
 *   · 会话显式绑定（IWAN_A_OIF）→ 严格用指定那张：外层查找带 flowi4_oif，
 *     数据面绝不漂移到别的卡。注意内核的 flowi4_oif 是"硬绑"：设备 UP 且有
 *     IPv4 地址时，即使 FIB 里没有经它的路由，ip_route_output_flow() 也会为它
 *     合成一条 scope link 路由（SO_BINDTODEVICE 语义）——所以绑到没有回程路由
 *     的卡上不会在控制面报错，而是照发、由网络侧丢弃（黑洞）；设备不存在/解析
 *     不到路由时才失败（SESSION_UP 返回 -ENETUNREACH）；
 *   · 未显式绑定 → 由 FIB 解析一次，把结果（ifindex）钉在 pn->carrier 上，
 *     之后所有外层查找都带这个 flowi4_oif，选路结果不再逐包变化。
 * 钉住结果同时被三处使用：出站查找（⑥）、入站过滤（iwan_rx.c）、
 * needed_headroom 推导（本文件）。
 */

/*
 * 钉住承载网卡并据此推导本设备的 needed_headroom。
 *
 * 为什么要推导 needed_headroom：外层要 push IWAN_OVERHEAD 字节，push 完承载
 * 设备插链路头还需要 LL_RESERVED_SPACE(承载) 字节（该宏已含承载的
 * hard_header_len、承载自己声明的 needed_headroom，以及 16 字节对齐余量）。
 * 发送方（UDP 的 ip_append_data、raw/IP_HDRINCL 的 raw_sendmsg、TCP 的
 * hh_len）按 LL_RESERVED_SPACE(iwan0) 预留头空间 —— 预留够，push 完就还有
 * 富余，ip_finish_output2 里那句 skb_realloc_headroom 不会再触发。那次重分配
 * 要把整个**线性区**搬一遍：线性 skb（raw/IP_HDRINCL 发送方）上 headlen 就是
 * 整包，65KB 档实测约 15µs，占该档发送路径的 20%；分页 skb 上 headlen 只有
 * 几十字节，本来就不付这笔钱。
 *
 * 只增不减（取 max）：承载换成需求更小的设备时改小没有收益，只会让头空间
 * 随会话建立/结束来回抖动。上限用 LL_MAX_HEADER 夹住，防止某张承载设备声明
 * 一个离谱的 needed_headroom 把每包预留都抬上去。
 */
/* overhead = 本会话外层封装开销（v4 36 / v6 56 之类的整段，见 iwan.h）；
 * bind_desc != NULL 表示"按出口 IP 绑定"，内容是已格式化的地址（v4/v6
 * 都用 %pI4/%pI6 先格式化好再传进来 —— 这条日志不能按族分叉两份）。 */
static void iwan_carrier_pin(struct iwan_net *pn, const struct net_device *carrier,
			     struct net_device *dev, bool explicit,
			     const char *bind_desc, unsigned int overhead)
{
	unsigned int want = overhead + LL_RESERVED_SPACE(carrier);

	WRITE_ONCE(pn->carrier, carrier->ifindex);
	if (want > overhead + LL_MAX_HEADER)
		want = overhead + LL_MAX_HEADER;
	if (dev && READ_ONCE(dev->needed_headroom) < want)
		WRITE_ONCE(dev->needed_headroom, want);
	if (bind_desc)
		pr_info("netns %u: 承载网卡 %s ifindex=%u（按出口 IP %s 解析）needed_headroom=%u\n",
			pn->net->ns.inum, carrier->name, carrier->ifindex,
			bind_desc,
			dev ? READ_ONCE(dev->needed_headroom) : 0);
	else
		pr_info("netns %u: 承载网卡 %s ifindex=%u（%s）needed_headroom=%u\n",
			pn->net->ns.inum, carrier->name, carrier->ifindex,
			explicit ? "显式绑定" : "FIB 解析后钉住",
			dev ? READ_ONCE(dev->needed_headroom) : 0);
}

/* "某个 v6 地址属于哪张网卡"：与 v4 的 __ip_dev_find 同一事实来源
 * （本机地址表），只是 v6 没有等价的"一次调用拿到设备"的导出接口，按
 * 设备表逐个问 ipv6_chk_addr(..., strict=1)（strict 会把 DAD 未完成的
 * tentative 地址排除在外 —— 拿一个还用不了的地址当源地址没有意义）。
 * 只在会话建立/绑定重解析时走一次，不在逐包路径上。 */
static struct net_device *iwan_bind_ip6_dev(struct net *net,
					    const struct in6_addr *ip6)
{
	struct net_device *d, *found = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(net, d) {
		if (ipv6_chk_addr(net, ip6, d, 1)) {
			dev_hold(d);
			found = d;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

int iwan_bind_ip_check6(struct net *net, const struct in6_addr *ip6, u32 oif)
{
	struct net_device *ipdev;

	if (ipv6_addr_any(ip6))
		return 0;
	ipdev = iwan_bind_ip6_dev(net, ip6);
	if (!ipdev)
		return -EADDRNOTAVAIL;
	if (oif && ipdev->ifindex != oif) {
		dev_put(ipdev);
		return -EINVAL;
	}
	dev_put(ipdev);
	return 0;
}

int iwan_bind_ip_check(struct net *net, __be32 ip, u32 oif)
{
	const struct net_device *ipdev;

	if (!ip)
		return 0;
	/* __ip_dev_find 走本机地址表（RTN_LOCAL）：某个地址属于哪张接口由
	 * **地址配置**决定。devref=false ⇒ 不取引用，只用 ifindex。 */
	ipdev = __ip_dev_find(net, ip, false);
	if (!ipdev)
		return -EADDRNOTAVAIL;
	if (oif && ipdev->ifindex != oif)
		return -EINVAL;
	return 0;
}

/* 解析并钉住承载网卡（会话建立时调用一次；此后只有数据面在外层查找失败且
 * **没有**显式绑定时才会重新解析 —— 见 iwan_xmit 块 ⑥）。
 *
 * 三个输入共同决定"这条会话用哪张下游网卡"：
 *   oif      控制面显式指定的网卡（"绑网卡"）；
 *   bind_ip  控制面显式指定的出口 IP（"绑 IP"）：用地址表解析出持有该地址
 *            的接口，等价于绑那张接口；
 *   都不给   由 FIB 解析一次（"什么都不绑"）。
 *
 * 失败语义（返回值直接交给控制面，不在这里"退而求其次"换一张卡——绑定的
 * 意义就是不许漂移）：
 *   -EINVAL         两个绑定规格互相矛盾（IP 不在指定的网卡上），或
 *                   出口 IP 与会话的外层源地址不一致；
 *   -EADDRNOTAVAIL  该 IP 不属于任何本机接口；
 *   -ENETUNREACH    经该网卡解析不到外层路由（设备不存在 / 不 UP）；
 *   -ELOOP          外层端点指向隧道自身。
 */
int iwan_carrier_resolve(struct net *net, struct iwan_net *pn,
			 struct net_device *dev, __be32 src, __be32 dst,
			 u32 oif, __be32 bind_ip)
{
	struct flowi4 fl4 = {
		.daddr		= dst,
		.saddr		= src,
		.flowi4_proto	= IPPROTO_UDP,
		.flowi4_oif	= oif,
	};
	struct net_device *ipdev = NULL;
	struct rtable *rt;
	int err;

	/* "绑 IP"的第一层语义：它就是外层头的源地址（OUTER_SRC 已写进外层头，
	 * 见 iwan_xmit 的 oiph->saddr）。两者不一致属于配置错误：报文会带一个
	 * 与"绑定"无关的源地址出去，对端按五元组过滤时无法对应。 */
	if (bind_ip && bind_ip != src)
		return -EINVAL;

	/* 第二层语义：地址表解析。"某个 IP 属于哪张网卡"由**地址配置**决定
	 * （in_device 挂在 net_device 上），不是路由表，也不是网卡驱动；按路由
	 * 反查会把"绑 IP"退化成"由 FIB 决定"，与"什么都不绑"失去区分。 */
	if (bind_ip) {
		ipdev = __ip_dev_find(net, bind_ip, true);
		if (!ipdev)
			return -EADDRNOTAVAIL;
		if (oif && ipdev->ifindex != oif) {
			err = -EINVAL;
			goto out;
		}
		oif = ipdev->ifindex;
		fl4.flowi4_oif = oif;
	}

	rt = ip_route_output_flow(net, &fl4, NULL);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto out;
	}
	/* flowi4_oif 只是"首选设备"，内核不保证一定选它（实测：绑 lo 时仍会
	 * 解析出 vethbp1 的直连路由）。显式绑定必须自己复核，否则"绑一张卡"
	 * 会静默退化成"随便一张卡"。 */
	if (oif && rt->dst.dev->ifindex != oif) {
		ip_rt_put(rt);
		err = -ENETUNREACH;
		goto out;
	}
	/* 外层端点指向隧道自身：钉住没有意义，交给 iwan_xmit 的回环闸门拒绝 */
	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		err = -ELOOP;
		goto out;
	}
	{
		char desc[INET_ADDRSTRLEN];

		if (bind_ip)
			snprintf(desc, sizeof(desc), "%pI4", &bind_ip);
		iwan_carrier_pin(pn, rt->dst.dev, dev, oif != 0,
				 bind_ip ? desc : NULL, IWAN_OVERHEAD);
	}
	ip_rt_put(rt);
	err = 0;
out:
	if (ipdev)
		dev_put(ipdev);
	return err;
}

/* 外层 v6 的会话级解析：与 v4 版逐条对应（绑 IP 的两层语义、显式绑定不许
 * 漂移、外层端点指向隧道自身即拒），差别只在族与下面这条**硬前提**。
 *
 * 外层 v6 不分片（见本文件头部说明），所以这里把"内层 MTU + v6 封装开销
 * <= 承载网卡 MTU"作为会话能否建立的判据：承载网卡 MTU 是这条会话唯一
 * 已知的路径 MTU 下界（内核数据面没有 socket，收不到 ICMPv6 PTB）。不满足
 * 就返回 -EMSGSIZE 让控制面报清楚，而不是让首包在 ip6_finish_output 里
 * 被默默分片、到对端再被按"外层 v6 分片"丢掉。
 *
 * 失败语义与 v4 完全一致：-EINVAL/-EADDRNOTAVAIL/-ENETUNREACH/-ELOOP，
 * 另外多一个 -EMSGSIZE（内层 MTU 装不下）。 */
int iwan_carrier_resolve6(struct net *net, struct iwan_net *pn,
			  struct net_device *dev, u32 mtu,
			  const struct in6_addr *src,
			  const struct in6_addr *dst, u32 oif,
			  const struct in6_addr *bind_ip)
{
	struct flowi6 fl6 = {
		.daddr		= *dst,
		.saddr		= *src,
		.flowi6_proto	= IPPROTO_UDP,
		.flowi6_oif	= oif,
	};
	struct net_device *ipdev = NULL;
	struct dst_entry *rt;
	char desc[INET6_ADDRSTRLEN];
	int err;

	if (!ipv6_addr_any(bind_ip) && !ipv6_addr_equal(bind_ip, src))
		return -EINVAL;

	if (!ipv6_addr_any(bind_ip)) {
		ipdev = iwan_bind_ip6_dev(net, bind_ip);
		if (!ipdev)
			return -EADDRNOTAVAIL;
		if (oif && ipdev->ifindex != oif) {
			err = -EINVAL;
			goto out;
		}
		oif = ipdev->ifindex;
		fl6.flowi6_oif = oif;
	}

	rt = ip6_route_output(net, NULL, &fl6);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		pr_info("netns %u: 外层 v6 解析失败 ip6_route_output=%d（src %pI6c dst %pI6c oif %u bind %pI6c dev %s mtu %u）\n",
			net->ns.inum, err, src, dst, oif, bind_ip,
			dev ? dev->name : "(无)", mtu);
		goto out;
	}
	/* 不可达目的地会返回一个 error 非 0 的 dst（典型是 ip6_null_entry）：
	 * 那不是"解析成功"，必须当成失败 —— 否则会把承载钉成 lo，还会让
	 * 上面的 MTU 判据按 lo 的 MTU 得出"装得下"的结论。 */
	if (rt->error) {
		err = rt->error;
		pr_info("netns %u: 外层 v6 只解析到不可用路由 %d（src %pI6c dst %pI6c oif %u dev %s）\n",
			net->ns.inum, err, src, dst, oif, rt->dev->name);
		dst_release(rt);
		goto out;
	}
	/* flowi6_oif 在 v6 里是硬绑（内核按 oif 过滤路由），但仍自己复核一次：
	 * 与 v4 同样的理由 —— "绑一张卡"不许静默退化成"随便一张卡"。 */
	if (oif && rt->dev->ifindex != oif) {
		dst_release(rt);
		err = -ENETUNREACH;
		goto out;
	}
	if (rt->dev == dev) {
		dst_release(rt);
		err = -ELOOP;
		goto out;
	}
	if (mtu && mtu + IWAN_OVERHEAD_V6 > READ_ONCE(rt->dev->mtu)) {
		pr_info("netns %u: 外层 v6 会话拒绝：内层 MTU %u + 封装 %u 超过承载网卡 %s 的 MTU %u\n",
			net->ns.inum, mtu, (unsigned int)IWAN_OVERHEAD_V6,
			rt->dev->name, READ_ONCE(rt->dev->mtu));
		dst_release(rt);
		err = -EMSGSIZE;
		goto out;
	}
	if (!ipv6_addr_any(bind_ip))
		snprintf(desc, sizeof(desc), "%pI6c", bind_ip);
	pr_info("netns %u: 外层 v6 承载已解析 %s（mtu %u，src %pI6c dst %pI6c ，内层 MTU %u）\n",
		net->ns.inum, rt->dev->name, READ_ONCE(rt->dev->mtu), src, dst,
		mtu);
	iwan_carrier_pin(pn, rt->dev, dev, oif != 0,
			 ipv6_addr_any(bind_ip) ? NULL : desc, IWAN_OVERHEAD_V6);
	dst_release(rt);
	err = 0;
out:
	if (ipdev)
		dev_put(ipdev);
	return err;
}

static netdev_tx_t iwan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net *net = dev_net(dev);
	struct iwan_net *pn = iwan_net_of(net);
	struct iwan_cfg *c = iwan_cfg_get();
	struct iwan_dp dp;
	struct udphdr *uh;
	u16 sport;
	u8 fh[IWAN_HDR_LEN];
	unsigned int flen;
	u32 tok;
	u16 sid;

	/* 会话优先、模块参数回落：没有 netlink 会话时外层端点取 /proc 配的
	 * pn->tx_src/tx_dst，端口/凭据取模块参数，开关取 cfg.enabled &&
	 * pn->enabled —— 与引入控制面之前逐位一致。 */
	iwan_dp_get(pn, c, true, &dp);
	sport = dp.sport ? dp.sport : dp.dport;

	/* 端点判据按族：v4 会话看 __be32 是否为 0，v6 会话看 16 字节是否全零。
	 * 两个字段不会同时有效（iwan_dp_get 只填会话那一族），所以这里必须
	 * 分开判 —— 用 v4 的判据去判 v6 会话会把每条会话都丢掉。 */
	if (unlikely(!dp.enabled))
		goto drop;
	if (dp.outer_v6) {
		if (ipv6_addr_any(&dp.outer_src6) ||
		    ipv6_addr_any(&dp.outer_dst6))
			goto drop;
	} else if (!dp.outer_src || !dp.outer_dst) {
		goto drop;
	}

	/*
	 * 不变量检查：到这里必须已经是"单个完整 IP 报文 + 校验和完成"。
	 * 不满足就丢弃并计数 —— 宁可丢包也不能出脏包。
	 */
	if (unlikely(skb_is_gso(skb) || skb->ip_summed == CHECKSUM_PARTIAL ||
		     skb_network_offset(skb) != 0)) {
		atomic64_inc(&pn->st.tx_bad_state);
		goto drop;
	}
	{
		/* 内层 v4/v6 共用一份判据（iwan_core.c）；TX 要求声明长度
		 * 恰好等于 skb->len —— 出站只封"一个完整内层报文"。
		 * 失败原因只有一个：不是这两种版本的合法内层头（含内层
		 * 分片以外的残缺报文）。 */
		u32 nhlen;

		if (unlikely(iwan_inner_hdr_check(skb, true, &nhlen))) {
			atomic64_inc(&pn->st.tx_bad_inner);
			goto drop;
		}
	}
	flen = skb->len;

	/* ① XOR 内层 IP 包（此刻校验和已是明文校验和，XOR 后仍自洽） */
	if (dp.enc && unlikely(iwan_xor_skb(skb, dp.key))) {
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}

	/* ② 8 字节 iWAN 帧头 */
	if (unlikely(skb_cow_head(skb, IWAN_OVERHEAD)))
		goto drop;
	sid = dp.sid;
	tok = dp.tok;
	fh[0] = dp.enc ? PT_DATA_ENC : PT_DATA;
	fh[1] = dp.enc;
	fh[2] = (u8)(sid >> 8);
	fh[3] = (u8)sid;
	fh[4] = (u8)(tok >> 24);
	fh[5] = (u8)(tok >> 16);
	fh[6] = (u8)(tok >> 8);
	fh[7] = (u8)tok;
	memcpy(skb_push(skb, IWAN_HDR_LEN), fh, IWAN_HDR_LEN);

	/* ③ 丢掉内层路径的元数据（内层 conntrack 引用、dst、trace） */
	skb_scrub_packet(skb, false);

	/* ④ 外层 UDP */
	uh = skb_push(skb, sizeof(*uh));
	memset(uh, 0, sizeof(*uh));
	/* cfg/会话里的端口是主机序（module_param 与 netlink 入参都转成主机序），
	 * 线上是网络序，必须在这里显式转换 —— 与上面对 sid/tok 的移位序列化
	 * 同一约定。漏掉这一步线上端口会变成字节交换后的值：模块自打自收看不出
	 * 来，对端按配置端口发过来会被 RX 全部拒掉。 */
	uh->source = htons(sport);
	uh->dest = htons(dp.dport);
	uh->len = htons(skb->len);
	skb_reset_transport_header(skb);

	/* ⑤ 外层发出按族分流：到这里为止（帧头、UDP 头、长度与端口）完全
	 * 共用，分岔只有校验和助手、IP 头与栈入口三处。 */
	if (dp.outer_v6)
		udp6_set_csum(false, skb, &dp.outer_src6, &dp.outer_dst6,
			      skb->len);
	else
		udp_set_csum(false, skb, dp.outer_src, dp.outer_dst,
			     skb->len);	/* 交给驱动/硬件算 */

	return dp.outer_v6 ? iwan_tx_outer6(pn, net, dev, &dp, skb, flen) :
			     iwan_tx_outer4(pn, net, dev, &dp, skb, flen);

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

/* 外层 v4 的发出：头构造、路由缓存、承载网卡钉住与自愈、计数口径都原样
 * 保留（切片 2 只是把这段从 iwan_xmit 里搬出来，逐位不变）。 */
static netdev_tx_t iwan_tx_outer4(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen)
{
	struct iwan_cfg *c = iwan_cfg_get();
	struct iphdr *oiph;
	struct flowi4 fl4;
	struct rtable *rt;
	__be32 src = dp->outer_src, dst = dp->outer_dst;
	u32 oif;
	int err;

	/* ⑤ 外层 IPv4（默认 DF=1：外层不再分片，MTU 由 iwan0 的 mtu 保证；
	 *    df=0 时允许外层分片，用来验证对端钩子里的内联重组） */
	oiph = skb_push(skb, sizeof(*oiph));
	memset(oiph, 0, sizeof(*oiph));
	oiph->version = 4;
	oiph->ihl = 5;
	oiph->ttl = 64;
	oiph->protocol = IPPROTO_UDP;
	oiph->tot_len = htons(skb->len);
	oiph->frag_off = READ_ONCE(c->df) ? htons(IP_DF) : 0;
	oiph->saddr = src;
	oiph->daddr = dst;
	ip_send_check(oiph);
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IP);

	/* ⑥ 走物理路由发出。会话级路由缓存：外层端点在会话存续期内不变，
	 * 逐包 FIB 查找是纯重复劳动（高分组速率场景的主要每分组开销之一）。
	 * dst_cache 内部按路由代数做 dst_check，路由表变更自动失效；外层端点
	 * 变更（/proc 写或新会话）由这里记住的一对地址比对发现，发现即
	 * dst_cache_reset() 惰性作废。命中与未命中两种路径下 rt 的引用都归
	 * 缓存所有，交给 skb 的引用用 dst_clone 另取。
	 * 注：本函数在 ndo_start_xmit 上下文运行，dev_queue_xmit 已持
	 * rcu_read_lock_bh()，满足 dst_cache 对"本地 BH 关闭"的要求。 */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = dst;
	fl4.saddr = src;
	fl4.flowi4_proto = IPPROTO_UDP;
	/* 承载网卡：已钉住则参与查找（严格绑定）；尚未钉住但会话显式指定了
	 * 绑定网卡时也按它查（首个包就不得漂移）。为 0 表示本次由 FIB 决定，
	 * 解析成功后立刻钉住（见下面的 iwan_carrier_pin）。 */
	oif = READ_ONCE(pn->carrier);
	if (!oif && dp->bind_ip) {
		/* "绑 IP"模式但钉住已被清掉（SET_PEER 与改写外层端点都会清，
		 * 见 iwan_carrier_forget）：出口 IP 仍决定承载网卡，先按地址表
		 * 解析出来，绝不交给 FIB 选一张别的卡。不在稳态路径上——钉住
		 * 有效时不会走到这里，因此稳态下不付地址表查找。地址已不属于
		 * 任何本机接口时按绑定失败处理（计入 tx_err）。 */
		const struct net_device *ipdev =
			__ip_dev_find(net, dp->bind_ip, false);

		if (!ipdev) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		oif = ipdev->ifindex;
	}
	if (!oif)
		oif = dp->oif;
	fl4.flowi4_oif = oif;
	rt = NULL;
	if (pn->tx_route_ok) {
		rt = dst_cache_get_ip4(&pn->tx_route, &fl4.saddr);
		if (rt && unlikely(pn->tx_route_dst != dst ||
				   pn->tx_route_src != src ||
				   pn->tx_route_oif != oif)) {
			dst_cache_reset(&pn->tx_route);
			fl4.saddr = src;
			rt = NULL;
		}
	}
	if (!rt) {
		rt = ip_route_output_flow(net, &fl4, NULL);
		if (!IS_ERR(rt) && oif && rt->dst.dev->ifindex != oif) {
			/* flowi4_oif 只是"首选设备"，内核不保证一定选它（实测：
			 * 绑 lo 时仍会解析出 vethbp1 的直连路由）。绑定必须自己
			 * 复核，否则"绑一张卡"会静默退化成"随便一张卡"。 */
			ip_rt_put(rt);
			rt = ERR_PTR(-ENETUNREACH);
		}
		if (IS_ERR(rt) && oif) {
			/* 两种情况都在这里：查找失败（设备被删/路由被撤），或
			 * 查找成功但解析出来的不是绑定的那张。自动钉住的走回落
			 * —— 清掉钉住、按 FIB 重解析一次并改钉，保持"同时只用
			 * 一张卡"而不是从此永久失败；显式绑定刻意不回落：绑定的
			 * 意义就是不许漂移，那张卡不通就失败（计入 tx_err）。
			 * 显式绑定有两种下发方式：绑网卡（dp->oif）与绑出口 IP
			 * （dp->bind_ip，已在会话建立时解析成同一张卡），两者
			 * 都属于"不许漂移"。 */
			if (iwan_dp_bound(dp))
				pr_info_ratelimited("netns %u: 绑定的承载网卡 ifindex=%u 上没有到 %pI4 的路由（%ld），丢弃\n",
						    net->ns.inum, oif, &dst,
						    PTR_ERR(rt));
			else {
				pr_info("netns %u: 承载网卡 ifindex=%u 已不通（%ld），按 FIB 重新解析外层路由\n",
					net->ns.inum, oif, PTR_ERR(rt));
				WRITE_ONCE(pn->carrier, 0);
				if (pn->tx_route_ok)
					dst_cache_reset(&pn->tx_route);
				oif = 0;	/* 改钉后由 FIB 选，下面按"非显式"记 */
				fl4.saddr = src;
				fl4.flowi4_oif = 0;
				rt = ip_route_output_flow(net, &fl4, NULL);
			}
		}
		if (IS_ERR(rt)) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		if (pn->tx_route_ok) {
			dst_cache_set_ip4(&pn->tx_route, &rt->dst, src);
			pn->tx_route_dst = dst;
			pn->tx_route_src = src;
			pn->tx_route_oif = rt->dst.dev->ifindex;
		}
	}
	/* 首次成功解析即钉住承载网卡（显式绑定则恒等于绑定值）。
	 * 必须放在上面的回环闸门**之后**：外层端点若指向隧道自己，那张
	 * "网卡"就是 iwan0，钉住它只会在 RX 侧造成误伤。 */
	if (unlikely(rt->dst.dev == dev)) {	/* 路由回环：拒绝 */
		if (pn->tx_route_ok)
			dst_cache_reset(&pn->tx_route);
		else
			ip_rt_put(rt);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(pn->carrier) != rt->dst.dev->ifindex)) {
		char desc[INET_ADDRSTRLEN];

		if (dp->bind_ip)
			snprintf(desc, sizeof(desc), "%pI4", &dp->bind_ip);
		iwan_carrier_pin(pn, rt->dst.dev, dev, oif != 0,
				 dp->bind_ip ? desc : NULL, IWAN_OVERHEAD);
	}
	skb_dst_drop(skb);
	/* 缓存持有引用（未命中时已由 dst_cache_set_ip4 接管），这里另取一份 */
	skb_dst_set(skb, pn->tx_route_ok ? dst_clone(&rt->dst) : &rt->dst);
	skb->dev = rt->dst.dev;

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += flen;
	atomic64_inc(&pn->st.tx_pkts);
	atomic64_add(flen, &pn->st.tx_bytes);

	/* ip_local_out() 在所有路径上都消费 skb */
	err = ip_local_out(net, NULL, skb);
	if (unlikely(err))
		atomic64_inc(&pn->st.tx_err);
	return NETDEV_TX_OK;

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

/* 外层 v6 的发出。与 v4 逐条对应（头构造、回环闸门、绑定的"自愈 vs 不漂移"、
 * 计数口径），按族不同的三处：
 *   · 头 40B 固定，长度字段是**负载长度**（不含头），hop_limit 代替 ttl；
 *   · 校验和已在共用段用 udp6_set_csum() 设好（v6 伪头是 16B 地址）；
 *   · v6 没有 DF 位，也**不分片**：装不下承载 MTU 就丢弃并计 tx_err。
 *     （会话建立时已按同一判据拒绝过，这里兜"承载 MTU 中途变小"。）
 * 刻意不用 v4 那个 dst_cache：dst_cache_get_ip6() 会回填 prefsrc，与"硬源
 * 地址绑定"的交互要单独审计；外层 v6 目前不在性能基准口径内，先按逐包
 * 查找，正确优先（缓存留给性能切片，与 v4 的 dst_cache 一并做）。
 */
static netdev_tx_t iwan_tx_outer6(struct iwan_net *pn, struct net *net,
				  struct net_device *dev,
				  const struct iwan_dp *dp,
				  struct sk_buff *skb, unsigned int flen)
{
	struct ipv6hdr *oiph;
	struct flowi6 fl6;
	struct dst_entry *dst;
	u32 oif;
	int err;

	/* ⑤ 外层 IPv6 */
	oiph = skb_push(skb, sizeof(*oiph));
	memset(oiph, 0, sizeof(*oiph));
	oiph->version = 6;
	oiph->nexthdr = IPPROTO_UDP;
	oiph->hop_limit = 64;
	oiph->payload_len = htons(skb->len - sizeof(*oiph));
	oiph->saddr = dp->outer_src6;
	oiph->daddr = dp->outer_dst6;
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IPV6);

	/* ⑥ 逐包外层查找：与 v4 同一套绑定语义（显式绑定严格用指定那张，
	 * 未绑定时按 FIB 解析后钉住；钉住那张不通则清掉重解析一次）。 */
	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = dp->outer_dst6;
	fl6.saddr = dp->outer_src6;
	fl6.flowi6_proto = IPPROTO_UDP;
	oif = READ_ONCE(pn->carrier);
	if (!oif && !ipv6_addr_any(&dp->bind_ip6)) {
		/* "绑 IP"模式但钉住已被清掉（SET_PEER 与改写外层端点都会清，
		 * 见 iwan_carrier_forget）：出口 IP 仍决定承载网卡，先按地址表
		 * 解析出来，绝不交给 FIB 选一张别的卡。稳态下不走到这里。 */
		struct net_device *ipdev = iwan_bind_ip6_dev(net, &dp->bind_ip6);

		if (!ipdev) {
			atomic64_inc(&pn->st.tx_err);
			goto drop;
		}
		oif = ipdev->ifindex;
		dev_put(ipdev);
	}
	if (!oif)
		oif = dp->oif;
	fl6.flowi6_oif = oif;
	dst = ip6_route_output(net, NULL, &fl6);
	/* v6 的查找失败有两种形态：ERR_PTR，或"带 error 的 dst"（null_entry
	 * 一族）。两者都要当失败处理，只判 IS_ERR 会把后者当可用路由发出去。 */
	if (!IS_ERR(dst) && oif && dst->dev->ifindex != oif) {
		dst_release(dst);
		dst = ERR_PTR(-ENETUNREACH);
	}
	if (!IS_ERR(dst) && unlikely(dst->error)) {
		int e2 = dst->error;

		dst_release(dst);
		dst = ERR_PTR(e2);
	}
	if (IS_ERR(dst) && oif) {
		if (iwan_dp_bound(dp)) {
			pr_info_ratelimited("netns %u: 绑定的承载网卡 ifindex=%u 上没有到 %pI6c 的路由（%ld），丢弃\n",
					    net->ns.inum, oif,
					    &dp->outer_dst6, PTR_ERR(dst));
		} else {
			pr_info("netns %u: 承载网卡 ifindex=%u 已不通（%ld），按 FIB 重新解析外层路由\n",
				net->ns.inum, oif, PTR_ERR(dst));
			WRITE_ONCE(pn->carrier, 0);
			oif = 0;
			fl6.flowi6_oif = 0;
			dst = ip6_route_output(net, NULL, &fl6);
		}
	}
	if (IS_ERR(dst)) {
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(dst->dev == dev)) {	/* 路由回环：拒绝 */
		dst_release(dst);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(dev->mtu) + IWAN_OVERHEAD_V6 >
		     READ_ONCE(dst->dev->mtu))) {
		pr_info_ratelimited("netns %u: 外层 v6 装不下：内层 MTU %u + 封装 %u 超过承载 %s 的 MTU %u，丢弃\n",
				    net->ns.inum, READ_ONCE(dev->mtu),
				    (unsigned int)IWAN_OVERHEAD_V6,
				    dst->dev->name, READ_ONCE(dst->dev->mtu));
		dst_release(dst);
		atomic64_inc(&pn->st.tx_err);
		goto drop;
	}
	if (unlikely(READ_ONCE(pn->carrier) != dst->dev->ifindex)) {
		char desc[INET6_ADDRSTRLEN];

		if (!ipv6_addr_any(&dp->bind_ip6))
			snprintf(desc, sizeof(desc), "%pI6c", &dp->bind_ip6);
		iwan_carrier_pin(pn, dst->dev, dev, oif != 0,
				 ipv6_addr_any(&dp->bind_ip6) ? NULL : desc,
				 IWAN_OVERHEAD_V6);
	}
	skb_dst_drop(skb);
	/* 查找得来的引用随 skb 交给发送路径（与 v4 的 &rt->dst 同一约定） */
	skb_dst_set(skb, dst);
	skb->dev = dst->dev;

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += flen;
	atomic64_inc(&pn->st.tx_pkts);
	atomic64_add(flen, &pn->st.tx_bytes);

	err = ip6_local_out(net, NULL, skb);
	if (unlikely(err))
		atomic64_inc(&pn->st.tx_err);
	return NETDEV_TX_OK;

drop:
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}


/* 网卡不再由 pernet init 创建。
 *
 * 原因（实测）：pernet 的 device 类 init 反而排在整个 netns 初始化最前面，
 * register_netdevice() 会撞在还没建好的设备表上把内核打崩（模块随后永远
 * 卡在 "正在加载"，只能重启）；建出来的设备还会反引用模块让 rmmod 失败。
 * 改用 rtnl_link_ops：设备要么由 `ip link add <名> type iwan` 创建，要么由
 * genetlink 的 SESSION_UP 在进程上下文里用 rtnl_create_link() 按需创建
 * （iwan_netlink.c）；删除、netns 销毁、rmmod 都走内核标准路径。
 */
struct rtnl_link_ops iwan_link_ops = {
	.kind		= "iwan",
	.priv_size	= 0,
	.setup		= iwan_dev_setup,
	.dellink	= unregister_netdevice_queue,
};

int iwan_tx_init(void)
{
	return rtnl_link_register(&iwan_link_ops);
}

void iwan_tx_exit(void)
{
	rtnl_link_unregister(&iwan_link_ops);
}
