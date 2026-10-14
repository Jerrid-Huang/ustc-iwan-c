// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_rx.c — 入站：netfilter 钩子内解封。
 *
 * 为什么在 PRE_ROUTING（默认 prio=-300）：
 *   内核的两个重组点分别在 -400（nf_defrag_ipv4，只有 conntrack/nft 之类
 *   才会去 enable）与 ip_local_deliver（LOCAL_IN 之后）。隧道的外层分片必须
 *   在**看端口之前**拼完整（非首片没有 UDP/iWAN 头），所以在 -300 自己调一次
 *   导出的 ip_defrag()：返回非 0 = 本片已入队 → NF_STOLEN（skb 归重组机制，
 *   不能再碰）；返回 0 = 数据报此刻完整，就在这一次调用里继续解封。
 *   这就是内核 nf_ct_ipv4_gather_frags() 的同一套约定，不是新语义。
 *
 * 内层分片：本模块**不**做内层重组。解出的内层包 NF_ACCEPT 后自然落到
 *   ip_local_deliver 的 ip_defrag（本机）或下一跳（转发）——这也正是
 *   "要不要重组内层"只有在路由之后才答得出来的原因。
 *
 * 内层版本（v4/v6）：两种都收，判据是 iwan_inner_hdr_check()（TX 与 RX 共用
 *   一份，见 iwan_core.c）。投递方式分两种：
 *     · 内层版本 == 外层版本（v4 in v4，v1 的老路径）：NF_ACCEPT，让当前协议栈
 *       路径继续走，逐位不变；
 *     · 内层版本 != 外层版本（v6 in v4）：必须 netif_rx 重新入栈 —— NF_ACCEPT
 *       是"接着走外层那条路"，而它是按外层版本进来的（v4 钩子 → ip_rcv_finish
 *       会拿内层头当 v4 解析），版本一变必然误判。重新入栈时协议类型按**内层**
 *       版本给（ETH_P_IPV6），传输层偏移也按内层版本算（v6 = 40 + 扩展头）。
 *   模块参数 reinject=true 则无论版本一律重新入栈（旧行为不变）。
 *
 * 取参（genetlink 控制面引入后）：每包用 iwan_dp_get() 取一次快照 —— 该 netns
 *   有 netlink 会话时用会话参数，否则回落模块参数（逐位等于旧实现）。
 * 非数据帧（OPEN/OPEN_ACK/ECHO/PING/CLOSE）：不当内层包投递，改为原样转交
 *   用户态（IWAN_EV_CTRL_FRAME）—— 见 iwan_rx_ctrl()。事件多播经每 netns 的
 *   令牌桶限速（超限丢进 IWAN_S_EV_DROPPED）：限速只影响"发多少事件"，不改变
 *   共享内存记账与 PT_CLOSE 语义 —— 那两件事在进桶之前/之外完成。
 *
 * 存活时间戳（v1 共享内存页，布局见 kernel/iwan_shm.h）：
 *   每个**通过凭据闸门**的帧（数据帧或控制帧）都把当前单调毫秒写进该 netns
 *   的共享内存页（/dev/iwan，用户态只读 mmap），PT_CLOSE 把它置 0。写入点只有
 *   iwan_decap_one() 与 iwan_rx_ctrl() 两处，都在软中断上下文：只有普通 store
 *   （WRITE_ONCE），无锁、无分配，也不引入第二套时间基准（iwan_now_ms()）。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>		/* ipv6_ext_hdr / ipv6_optlen / ipv6_authlen */
#include <net/gso.h>
#include <net/netns/generic.h>

#include "iwan.h"
#include "iwan_genl.h"	/* IWAN_CTRL_FRAME_MAX / IWAN_PEER_* */

/*
 * 外层头的族无关视图（切片 2）。
 *
 * 收包路径上"分流"只发生在两处最外层的地方：内核按 skb->protocol 选
 * ip_rcv / ipv6_rcv，netfilter 钩子表本身也分族（hooks_ipv4/hooks_ipv6）。
 * 我们不去抢那个分流之前的位置（netdev_rx_handler / NF_NETDEV_INGRESS 都是
 * **按网卡**挂钩的，而"什么都不绑"模式要求任意承载网卡都能收、且承载网卡
 * 可以在运行中由 FIB 自愈换卡 —— 按网卡挂钩会把这条语义砍掉）。取而代之：
 * 两个族各挂一个钩子，钩子体共用，族只在下面这层"怎么找到 UDP 头、怎么
 * 比地址"里出现一次，之后的端口检查、解封、投递完全同一条路径。
 *
 * src/dst 指向 skb 里的地址字段（v4 4 字节 / v6 16 字节），由 match 按族比较。
 */
struct iwan_outer_view {
	const void	*src;
	const void	*dst;
	unsigned int	l3;	/* UDP 头偏移（含 IP 头与扩展头） */
	bool		v6;
	bool		frag;	/* 外层分片 */
};

/* 外层 v4 解析：判据与切片 1 及之前逐位一致 */
static bool iwan_outer_parse4(struct sk_buff *skb, struct iwan_outer_view *o)
{
	const struct iphdr *iph;

	if (skb->protocol != htons(ETH_P_IP))
		return false;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return false;
	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5 || iph->protocol != IPPROTO_UDP)
		return false;
	o->src = &iph->saddr;
	o->dst = &iph->daddr;
	o->l3 = iph->ihl * 4;
	o->v6 = false;
	o->frag = ip_is_fragment(iph);
	return true;
}

/*
 * 外层 v6 解析。与 v4 的两处结构差异：
 *   · 基本头固定 40B，传输层位置只能靠走扩展头链得到（v4 用 ihl）；
 *   · 分片包只有首片带 UDP 头，非首片连端口都看不到。
 *
 * 分片策略：**任何带分片头的 v6 外层包一律不当完整包处理**。本设计里外层
 * v6 不分片（v6 没有 DF 位，源端分片只会换到对端拒收，见 iwan_tx.c），
 * 内层 MTU + IWAN_OVERHEAD_V6 装不进承载网卡 MTU 的会话在控制面已被
 * -EMSGSIZE 拒绝。所以见到分片就是"对端配置与本端不一致"，计数（rx_frag6）
 * 后交给协议栈按它自己的规则处理（NF_ACCEPT：不吞、不冒充完整包）。
 * 首片也拒：它的 UDP 头虽在，载荷却是残缺的，而 RX 的内层判据是宽松口径，
 * 会把一个被截断的内层头当合法包解出来投递。
 */
static bool iwan_outer_parse6(struct sk_buff *skb, struct iwan_outer_view *o)
{
	const struct ipv6hdr *iph;
	unsigned int off;
	u8 nexthdr;

	if (skb->protocol != htons(ETH_P_IPV6))
		return false;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return false;
	iph = ipv6_hdr(skb);
	if (iph->version != 6)
		return false;
	o->src = &iph->saddr;
	o->dst = &iph->daddr;
	o->v6 = true;
	o->frag = false;
	o->l3 = 0;

	off = sizeof(*iph);
	nexthdr = iph->nexthdr;
	while (ipv6_ext_hdr(nexthdr)) {
		const struct ipv6_opt_hdr *hp;
		unsigned int hlen;

		if (nexthdr == NEXTHDR_FRAGMENT) {
			o->frag = true;
			return true;	/* 分片：调用方按策略处理 */
		}
		if (nexthdr == NEXTHDR_NONE)
			return false;
		if (!pskb_may_pull(skb, off + sizeof(*hp)))
			return false;
		hp = (const struct ipv6_opt_hdr *)(skb->data + off);
		/* AH 的长度字段语义与其它扩展头不同（(len+2)*4 而不是 (len+1)*8） */
		hlen = nexthdr == NEXTHDR_AUTH ? ipv6_authlen(hp) :
						 ipv6_optlen(hp);
		nexthdr = hp->nexthdr;
		off += hlen;
		if (off > skb->len)
			return false;
	}
	if (nexthdr != IPPROTO_UDP)
		return false;
	o->l3 = off;
	return true;
}

static bool iwan_outer_parse(struct sk_buff *skb, struct iwan_outer_view *o)
{
	return skb->protocol == htons(ETH_P_IPV6) ? iwan_outer_parse6(skb, o) :
						    iwan_outer_parse4(skb, o);
}

/* 外层地址匹配（any_dir 允许反向：对等/本机双向验证用）。按族比较：v4 会话
 * 只认 v4 包、v6 会话只认 v6 包 —— 不这样卡的话，一个 v4 包的 4 字节源地址
 * 有可能"等于"某条 v6 会话地址的前 4 字节（比较长度都不一样，必须先用族
 * 把它们分开）。 */
static bool iwan_outer_match(const struct iwan_dp *dp,
			     const struct iwan_outer_view *o)
{
	if (dp->outer_v6 != o->v6)
		return false;
	if (o->v6) {
		const struct in6_addr *s = o->src, *d = o->dst;

		if (ipv6_addr_any(&dp->outer_src6) ||
		    ipv6_addr_any(&dp->outer_dst6))
			return false;
		if (ipv6_addr_equal(s, &dp->outer_src6) &&
		    ipv6_addr_equal(d, &dp->outer_dst6))
			return true;
		if (dp->any_dir &&
		    ipv6_addr_equal(s, &dp->outer_dst6) &&
		    ipv6_addr_equal(d, &dp->outer_src6))
			return true;
		return false;
	}
	{
		const struct iphdr *iph = container_of(o->src, struct iphdr,
						       saddr);

		if (!dp->outer_src || !dp->outer_dst)
			return false;
		if (iph->saddr == dp->outer_src &&
		    iph->daddr == dp->outer_dst)
			return true;
		if (dp->any_dir && iph->saddr == dp->outer_dst &&
		    iph->daddr == dp->outer_src)
			return true;
		return false;
	}
}

enum iwan_frame_kind {
	IWAN_FRAME_BAD  = -1,
	IWAN_FRAME_DATA = 0,	/* 内层 IPv4 包，解封后交给协议栈 */
	IWAN_FRAME_CTRL = 1,	/* 非数据帧，转交用户态 */
};

/*
 * 控制帧的内核侧凭据口径（与 src/common/protocol.h 的线上语义对齐）：
 *
 *   · PT_PING_REQ/RSP：keepalive 用的是**协议固定凭据** 0xFFFF/0xFFFFFFFF，
 *     不是会话凭据 —— 若按会话 sid/tok 卡，keepalive 永远不会上报；这里
 *     同时接受会话凭据，容忍"用会话凭据发 ping"的实现。
 *   · PT_ECHO_REQ/RES、PT_CLOSE：带会话 sid/tok（用户态就是这么发的）。
 *   · PT_OPEN/PT_OPEN_ACK/PT_OPEN_REJECT：握手帧。OPEN_ACK 携带的是服务端
 *     **新分配**的 sid/tok，接收侧内核不可能预先知道；OPEN/OPEN_REJECT 用
 *     0/0。所以这些帧只能靠用户态做凭据校验（IWAN_CTRL_LEN=24 的 HMAC
 *     签名，verify_sig），这正是 CONTROL-PLANE.md §4 要求内核把非数据帧
 *     原样转交的原因。
 *
 * 三种情形都仍然要求外层四元组 + dport 命中（钩子里已完成），注入面被压缩
 * 到"能伪造对端外层地址与隧道端口"这一档；这也与任务里"sid/tok 匹配才上报"
 * 的意图一致：能校验会话凭据的类型一律校验。
 */
static bool iwan_ctrl_cred_ok(const struct iwan_dp *dp, u8 type, u16 sid, u32 tok)
{
	switch (type) {
	case PT_PING_REQ:
	case PT_PING_RSP:
		return (sid == IWAN_PING_SID && tok == IWAN_PING_TOK) ||
		       (sid == dp->sid && tok == dp->tok);
	case PT_OPEN:
	case PT_OPEN_ACK:
	case PT_OPEN_REJECT:
		return true;
	default:		/* PT_ECHO_REQ/PT_ECHO_RES/PT_CLOSE */
		return sid == dp->sid && tok == dp->tok;
	}
}

/*
 * 帧头校验：类型 + 凭据。sid/tok 放在解密之前（伪造帧连 XOR 都不做），
 * 与旧实现同口径：数据帧的 type 必须与 enc 模式一致。
 *
 * 控制帧只在**已建立 netlink 会话**时才算"可转交"：没有会话时它们和以前
 * 一样走到 IWAN_FRAME_BAD（rx_bad_hdr++ 后丢弃）—— 这就是"不建会话时行为与
 * 引入控制面之前逐位一致"的保证点。
 */
static enum iwan_frame_kind iwan_frame_check(const struct iwan_dp *dp, const u8 *h)
{
	u16 sid = ((u16)h[2] << 8) | h[3];
	u32 tok = ((u32)h[4] << 24) | ((u32)h[5] << 16) |
		  ((u32)h[6] << 8) | h[7];

	switch (h[0]) {
	case PT_DATA:
		if (dp->enc)
			return IWAN_FRAME_BAD;
		break;
	case PT_DATA_ENC:
		if (!dp->enc)
			return IWAN_FRAME_BAD;
		break;
	case PT_OPEN_REJECT:
	case PT_OPEN_ACK:
	case PT_OPEN:
	case PT_ECHO_REQ:
	case PT_ECHO_RES:
	case PT_CLOSE:
	case PT_PING_REQ:
	case PT_PING_RSP:
		if (!dp->session)
			return IWAN_FRAME_BAD;
		return iwan_ctrl_cred_ok(dp, h[0], sid, tok) ?
			IWAN_FRAME_CTRL : IWAN_FRAME_BAD;
	default:
		return IWAN_FRAME_BAD;
	}
	return sid == dp->sid && tok == dp->tok ? IWAN_FRAME_DATA : IWAN_FRAME_BAD;
}

/*
 * 控制帧分流：计数、更新 peer 状态、按类型补发语义事件，原样转交用户态。
 *
 * 单独一个 noinline 函数：512B 的帧缓冲只在这一条冷路径上花栈，不进每包都
 * 走的热路径（数据帧根本不会调用它）。
 */
static noinline void iwan_rx_ctrl(struct iwan_net *pn, struct sk_buff *skb,
				  unsigned int off, unsigned int len, u8 type,
				  const struct iphdr *iph,
				  const struct udphdr *uh)
{
	struct iwan_outer_tuple t = {
		.src	= iph->saddr,
		.dst	= iph->daddr,
		.sport	= uh->source,
		.dport	= uh->dest,
	};
	u8 buf[IWAN_CTRL_FRAME_MAX];
	const u8 *frame;
	u16 sid = READ_ONCE(pn->sess.sid);
	u64 ts;
	bool delivered;

	atomic64_inc(&pn->st.rx_ctrl_frame);
	iwan_shm_note_ctrl_frame(pn);	/* 共享内存页的计数镜像（普通 store） */

	/* 超过上限就截断并记日志（ABI 上限见 IWAN_CTRL_FRAME_MAX） */
	if (len > (unsigned int)IWAN_CTRL_FRAME_MAX) {
		pr_info_ratelimited("iwan: 控制帧 %u 字节超过上限 %d，已截断转交\n",
				    len, IWAN_CTRL_FRAME_MAX);
		len = IWAN_CTRL_FRAME_MAX;
	}
	frame = skb_header_pointer(skb, off, (int)len, buf);
	if (!frame)
		return;		/* 已计入 rx_ctrl_frame，不投递、不再上报 */

	/*
	 * 原样帧先转交（用户态自己验签/解析），随后补语义事件。
	 *
	 * delivered == false 只表示**事件多播**被令牌桶限速丢了（见
	 * iwan_ev_ctrl_frame），共享内存的副作用不受它影响：进桶之前
	 * iwan_decap_one() 已经写过 last_rx_ms/peer_state，下面的 PT_CLOSE
	 * 语义也照旧执行。否则攻击者用洪水打空令牌桶，就能让一个真实对端的
	 * PT_CLOSE 变成"用户态看不见、时间戳还停在非 0"—— 那等于把断线检测
	 * 关掉。限速只该限制"发多少事件"，不该改变"数据面看到了什么"。
	 */
	delivered = iwan_ev_ctrl_frame(pn, sid, &t, frame, len);

	if (type == PT_PING_REQ || type == PT_PING_RSP) {
		/* keepalive 时间戳已由 iwan_decap_one() 的通用路径写进共享内存
		 * （每个通过凭据闸门的帧都写，PING 不特殊）；这里只补发语义事件，
		 * 事件载荷仍用当前的同一时基 iwan_now_ms()。 */
		ts = iwan_now_ms();
		if (delivered)
			iwan_ev_keepalive(pn, ts);
	} else if (type == PT_CLOSE) {
		/* PT_CLOSE：共享内存页的时间戳置 0（用户态见到 0 即判定断线），
		 * 同时把 peer_state 落成 IWAN_PEER_CLOSED。这两件事与限速无关，
		 * 必须无条件做。 */
		iwan_shm_note_close(pn);
		if (delivered)
			iwan_ev_peer_close(pn, sid);
	}
}

/*
 * 把已经完整的外层数据报解封成内层明文包。
 * 返回 0 = 内层明文包已就绪（skb 已剥头/解密）；1 = 控制帧（已转交用户态，
 * skb 保持原样，由调用者决定丢弃）；<0 = 丢弃（计数器已在内部累加）。
 *
 * 分流点：外层重组 → 四元组 → dport → 帧头类型/凭据（iwan_frame_check）之后，
 * 也就是与数据帧**完全相同的前置校验之后**才分叉。
 */
static int iwan_decap_one(struct iwan_net *pn, struct sk_buff *skb,
			  const struct iwan_dp *dp, unsigned int l3)
{
	struct udphdr *uh;
	u8 hdrbuf[IWAN_HDR_LEN];
	const u8 *fh;
	enum iwan_frame_kind kind;
	unsigned int ulen, need;

	/* 外层 IP+UDP 头必须先拉进线性区才能直接解引用。UDP 大报文发送路径
	 * （ip_generic_getfrag → page frags）交来的 skb 线性区可能只有 IP+UDP
	 * 头那 28 字节：外层数据报一超过 ~16KB，载荷几乎全在 frags 里。 */
	if (unlikely(!pskb_may_pull(skb, l3 + sizeof(*uh)))) {
		atomic64_inc(&pn->st.rx_nomem);
		return -ENOMEM;
	}
	uh = (struct udphdr *)((u8 *)ip_hdr(skb) + l3);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) + IWAN_HDR_LEN) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	need = l3 + sizeof(*uh) + IWAN_HDR_LEN;
	if (skb->len < need) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	fh = skb_header_pointer(skb, l3 + sizeof(*uh), IWAN_HDR_LEN, hdrbuf);
	if (!fh) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}
	kind = iwan_frame_check(dp, fh);
	if (kind == IWAN_FRAME_BAD) {
		atomic64_inc(&pn->st.rx_bad_hdr);
		return -EINVAL;
	}

	/* 通过凭据闸门 ⇒ 对端活着：把当前单调毫秒写进共享内存页（数据帧与
	 * 控制帧都算）。PT_CLOSE 会在 iwan_rx_ctrl() 里把它覆盖成 0。
	 * 软中断上下文：只有普通 store，无锁、无分配。 */
	iwan_shm_note_frame(pn);

	/* 有效帧 ⇒ 对端活着（IWAN_PEER_UP = 收过有效帧）；
	 * PT_CLOSE 在 iwan_rx_ctrl() 里覆盖成 IWAN_PEER_CLOSED。 */
	if (dp->session && iwan_shm_peer_state(pn) != IWAN_PEER_CLOSED)
		iwan_shm_set_peer_state(pn, IWAN_PEER_UP);

	if (kind == IWAN_FRAME_CTRL) {
		/* UDP 载荷 = 外层 IP/UDP 头之后的原始帧字节（8B 帧头 + 载荷）。
		 * 长度按 UDP 头的 len 取，并用 skb 实际长度兜底。 */
		unsigned int flen = ulen - sizeof(*uh);
		unsigned int avail = skb->len - l3 - sizeof(*uh);

		if (flen > avail)
			flen = avail;
		iwan_rx_ctrl(pn, skb, l3 + sizeof(*uh), flen, fh[0],
			     ip_hdr(skb), uh);
		return 1;
	}

	atomic64_inc(&pn->st.rx_frames);
	iwan_shm_note_data_frame(pn);	/* 共享内存页的计数镜像 */

	/* 剥掉 外层 IPv4 + UDP + iWAN 帧头 —— 必须先保证这 need 字节在线性区：
	 * 大外层数据报（内层 > ~16KB ⇒ 外层 > ~16KB）的载荷在 page frags，
	 * 线性区可能不足 need，直接 skb_pull 会踩 __skb_pull 的
	 * BUG_ON(skb->len < skb->data_len)。2026-10-08 崩溃靶场 trace：
	 * skb_pull+0x40 ← iwan_decap_one ← iwan_rx_hook（softirq panic），
	 * 内层 20000B + s2c（服务端中继的大外层包）实测必炸；1200B 探针与
	 * 9000B（外层 9036，尚在线性分配范围内）都不炸，所以此前漏网。 */
	if (unlikely(!pskb_may_pull(skb, need))) {
		atomic64_inc(&pn->st.rx_nomem);
		return -ENOMEM;
	}
	skb_pull(skb, need);
	skb_reset_network_header(skb);

	/* 解密：整段内层 IP 包（含内层 IP 头）按会话密钥 XOR 还原 */
	if (dp->enc) {
		if (iwan_xor_skb(skb, dp->key)) {
			atomic64_inc(&pn->st.rx_nomem);
			return -ENOMEM;
		}
	}

	/* 明文内层头校验（v4/v6 共用一份判据；RX 保持既有的宽松长度口径：
	 * 内层头声明的长度盖不住整帧才拒，多余尾字节不拒）。传输层偏移按版本
	 * 算 —— v6 是 40 + 扩展头，不能照搬 v4 的 ihl。 */
	{
		u32 nhlen;

		if (iwan_inner_hdr_check(skb, false, &nhlen)) {
			atomic64_inc(&pn->st.rx_bad_inner);
			return -EINVAL;
		}
		/* inner_src 白名单是**模块参数**（ABI 里没有会话级对应项），
		 * 类型是 __be32，只能表达内层 v4 源地址：它只对 v4 生效。
		 * 内层 v6 不做等价过滤 —— 静默丢弃 v6 会变成另一种黑洞，
		 * 而 v6 的准入过滤（派生 ULA：目的必须是本会话 ULA、源不许
		 * 是本会话 ULA）在用户态 TUN 面实现，内核面暂不复制该策略
		 * （模块是数据面；要复制得先给 ABI 加内层地址项）。 */
		if (skb->data[0] >> 4 == 4 && dp->inner_src) {
			const struct iphdr *iph = ip_hdr(skb);

			if (iph->saddr != dp->inner_src) {
				atomic64_inc(&pn->st.rx_bad_inner);
				return -EINVAL;
			}
		}
		skb_set_transport_header(skb, nhlen);
	}
	/* 链路上是密文校验和，XOR 已把它还原成明文校验和 → 让内核按明文校验 */
	skb->ip_summed = CHECKSUM_NONE;
	/* 外层 dst 在本钩子里本来还没建立，但防上游残留 */
	skb_dst_drop(skb);
	return 0;
}

/* LOCAL_IN 兜底：解封后送回 ip_rcv，即回到 ip_defrag 之前 */
static unsigned int iwan_reinject(struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	/* 内层头已由 iwan_decap_one 校验过，skb->data 就是内层 IP 头 */
	u8 ver = skb->data[0] >> 4;

	skb->dev = state->in;
	/* 协议类型必须按**内层**版本给：netif_rx 之后由它选协议处理器，
	 * 选错了（v6 包挂 ETH_P_IP）会被 ip_rcv 按版本不符丢掉。 */
	skb->protocol = htons(ver == 6 ? ETH_P_IPV6 : ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	/* 传输层偏移在 iwan_decap_one 里已按版本设好（v4 = ihl*4；
	 * v6 = 40 + 扩展头），这里不再按 v4 的 ihl 覆写。 */
	/*
	 * netif_rx() 无条件接管 skb：成功则入 backlog，拥塞/协议栈丢弃时返回
	 * NET_RX_DROP 且**已经自己释放**。两个分支所有权都已转移，所以只能返回
	 * NF_STOLEN —— 返回 NF_DROP 会让 nf_hook_slow() 对同一个 skb 再释放一次
	 * （双重释放）。netfilter.h 的约定原文：hook 若已 kfree_skb，就必须
	 * NF_STOLEN 并自行承担后果。
	 */
	netif_rx(skb);
	return NF_STOLEN;
}

static unsigned int iwan_rx_single(struct iwan_net *pn, struct sk_buff *skb,
				   const struct iwan_cfg *c,
				   const struct iwan_dp *dp, unsigned int l3,
				   const struct nf_hook_state *state)
{
	int ret = iwan_decap_one(pn, skb, dp, l3);

	if (ret < 0) {
		/* 四元组+端口都命中了却过不了帧校验：伪造或损坏，丢掉 */
		return NF_DROP;
	}
	if (ret > 0) {
		/* 控制帧：已转交用户态，绝不当内层包投递。
		 * NF_DROP 由框架释放 skb（我们不持有它）。 */
		return NF_DROP;
	}
	atomic64_inc(&pn->st.rx_delivered);
	/* 投递方式：模块参数 reinject=true 一律 netif_rx 回协议栈；此外还有
	 * 一种**必须**重新入栈的情形 —— 内层版本 ≠ 外层版本（v6 in v4，本片
	 * 起支持）。NF_ACCEPT 是"让当前这条协议栈路径继续走"，而它是按外层
	 * 版本进来的（v4 钩子 → ip_rcv_finish 会拿内层头按 v4 解析，读出来的
	 * 地址/长度全是错的），版本一变就必然误判，只能重新入栈让 skb->protocol
	 * 重新选处理器。同版本时保持旧行为（NF_ACCEPT），逐位不变。 */
	if (READ_ONCE(c->reinject) ||
	    (skb->data[0] >> 4) != (state->pf == NFPROTO_IPV6 ? 6 : 4))
		return iwan_reinject(skb, state);
	return NF_ACCEPT;
}

/*
 * GSO 批处理：参考客户端用 UDP_SEGMENT 把 N 个等长帧发成一串 UDP 报文，
 * 接收侧 GRO 可能把它们合并成一个 skb（外层头 + N 段等长负载）。协议文档
 * 特意规定"等长帧"就是为了让接收侧能这样做：按 gso_size 拆回单个报文，每个
 * 报文各自剥头/解密（XOR 逐帧从偏移 0 开始），再各自送回栈。
 * 拆包会消费原 skb，而 netfilter 钩子无法替换手里的 skb 指针 ⇒ NF_STOLEN，
 * 由我们自己把解出的内层包交给 netif_receive_skb（回到 ip_rcv 之前）。
 * 混合了控制帧的合并包：控制帧照常上报（iwan_decap_one 返回 1），只是不再投递。
 */
static unsigned int iwan_rx_batch(struct iwan_net *pn, struct sk_buff *skb,
				  const struct iwan_cfg *c,
				  const struct iwan_dp *dp,
				  const struct nf_hook_state *state)
{
	struct net_device *indev = state->in;
	struct sk_buff *segs, *seg;

	atomic64_inc(&pn->st.rx_batch);
	if (!READ_ONCE(c->batch))
		return NF_ACCEPT;
	if (unlikely(skb_cloned(skb) || skb_shared(skb))) {
		atomic64_inc(&pn->st.rx_batch_skip);
		return NF_ACCEPT;
	}
	segs = skb_gso_segment(skb, 0);	/* features=0：各段校验和由软件算好 */
	if (IS_ERR(segs)) {
		/*
		 * skb_gso_segment() 在 IS_ERR 时**不消费**原 skb（上游为"原 skb
		 * 仍归调用者"专门修过 ownership），所以这里自己释放；既然已经
		 * 释放，就必须 NF_STOLEN：返回 NF_DROP 会被框架再释放一次。
		 */
		kfree_skb(skb);
		atomic64_inc(&pn->st.rx_bad_hdr);
		return NF_STOLEN;
	}
	if (!segs)
		return NF_ACCEPT;	/* 没有实际分段，原 skb 仍然有效 */
	consume_skb(skb);

	while ((seg = segs) != NULL) {
		struct iwan_outer_view so;
		unsigned int l3;
		int ret;

		segs = seg->next;
		seg->next = NULL;
		seg->prev = NULL;
		/* 分段的外层头与入口那个 skb 同族同形（GSO 只切载荷，每段各带
		 * 一份 IP+UDP 头），所以这里用与 single 路径同一套按族解析取
		 * UDP 头偏移，不另写一份 v4/v6 判断。 */
		if (!iwan_outer_parse(seg, &so) || so.frag)
			goto drop;
		l3 = so.l3;
		/* 与 single 路径对称：iwan_decap_one() 要读 uh->len，先把 UDP 头
		 * 拉进线性区。不要把契约建立在"分段器保证每段线性含 IP+UDP 头"
		 * 这个实现细节上。 */
		if (!pskb_may_pull(seg, l3 + sizeof(struct udphdr)))
			goto drop;
		ret = iwan_decap_one(pn, seg, dp, l3);
		if (ret)
			goto drop;	/* <0 坏帧；>0 控制帧已上报，不投递 */
		atomic64_inc(&pn->st.rx_delivered);
		seg->dev = indev;
		/* 按**内层**版本选协议（batch 路径一律 netif_receive_skb 重新
		 * 入栈）：内层 v6 挂 ETH_P_IP 会被 ip_rcv 按版本不符丢掉。 */
		seg->protocol = htons((seg->data[0] >> 4) == 6 ? ETH_P_IPV6
							       : ETH_P_IP);
		seg->pkt_type = PACKET_HOST;
		skb_reset_mac_header(seg);
		netif_receive_skb(seg);
		continue;
drop:
		kfree_skb(seg);
	}
	return NF_STOLEN;
}

static unsigned int iwan_rx_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iwan_net *pn = iwan_net_of(state->net);
	struct iwan_cfg *c = iwan_cfg_get();
	struct iwan_dp dp;
	struct iwan_outer_view o;
	struct udphdr *uh;
	u16 lport;

	(void)priv;
	/* 会话优先、模块参数回落：没有会话时 dp 的每个字段都等于旧实现
	 * 直接读 cfg/pn 的值（含 cfg.enabled && pn->enabled 的开关口径）。 */
	iwan_dp_get(pn, c, false, &dp);
	if (!dp.enabled)
		return NF_ACCEPT;
	/* 承载网卡限定：一条会话只认一张下游网卡。显式绑定（dp.oif）优先，否则
	 * 用已经钉住的那张（pn->carrier；0 = 尚未解析，此时不限制，行为与引入
	 * 绑定之前一致）。state->in 为 NULL 的本机自生成路径（钩子配在
	 * OUTPUT/POST_ROUTING 时）不做限定。
	 * 这一层同时收紧伪造面：外层四元组可伪造，不限接口就等于任意接口上的
	 * 伪包都能进解封装流程（凭据闸门在后面才做）。代价是一次 ifindex 比较。 */
	if (dp.oif || READ_ONCE(pn->carrier)) {
		u32 want = dp.oif ? dp.oif : READ_ONCE(pn->carrier);

		if (state->in && state->in->ifindex != want)
			return NF_ACCEPT;
	}
	if (!iwan_outer_parse(skb, &o))
		return NF_ACCEPT;
	/* 计数器口径（两族合计）：rx_pkts = 经过本钩子的、封装形状合法的 UDP
	 * 外层包（地址还没比）；rx_outer = 其中外层地址属于本会话的。 */
	atomic64_inc(&pn->st.rx_pkts);
	if (!iwan_outer_match(&dp, &o))
		return NF_ACCEPT;
	atomic64_inc(&pn->st.rx_outer);

	/* ① 外层分片 */
	if (o.frag) {
		if (o.v6) {
			/* 外层 v6 不分片（见 iwan_outer_parse6）：不吞、不当完整包
			 * 处理，计数后交回协议栈。 */
			atomic64_inc(&pn->st.rx_frag6);
			pr_info_ratelimited("iwan: 外层 v6 分片：本设计外层 v6 不分片（会话建立时按承载网卡 MTU 校验过），该包不按本隧道解封\n");
			return NF_ACCEPT;
		}
		/* v4：只在 PRE_ROUTING 需要重组（LOCAL_IN 时内核已重组过） */
		if (READ_ONCE(c->hooknum) != IWAN_HOOK_PRE_ROUTING)
			return NF_ACCEPT;
		{
			int ret;

			local_bh_disable();
			ret = ip_defrag(state->net, skb, IP_DEFRAG_LOCAL_DELIVER);
			local_bh_enable();
			if (ret) {
				/* 已入队（或超限被丢）：skb 已被重组机制消费 */
				atomic64_inc(&pn->st.rx_reasm);
				return NF_STOLEN;
			}
		}
		/* 返回 0：数据报此刻完整，就在这次调用里继续解封 */
		atomic64_inc(&pn->st.rx_reasm);
		if (!iwan_outer_parse(skb, &o) || o.frag)
			return NF_ACCEPT;
		if (!iwan_outer_match(&dp, &o))
			return NF_ACCEPT;
	}

	/*
	 * ② 端口只在完整数据报上可见，所以放在重组之后。
	 *
	 * 本端接收端口 = SPORT（显式给出时）；没给则沿用 DPORT，即"两端同端口"
	 * 的旧口径，行为与引入 SPORT 之前逐位一致。必须这样区分：TX 用 SPORT 作
	 * **源**端口，而真实客户端的本地端口是临时端口，与对端 DPORT 不同——
	 * 只认 DPORT 的话，真实客户端的入站包永远不匹配，内核数据面等于死的
	 * （此前两端都用同一个端口的测试恰好掩盖了这一点）。
	 * 刻意不写成"两个端口都接受"：那会把发给对端端口的包也吞掉。
	 */
	if (!pskb_may_pull(skb, o.l3 + sizeof(*uh)))
		return NF_ACCEPT;
	uh = (struct udphdr *)(skb_network_header(skb) + o.l3);
	lport = dp.sport ? dp.sport : dp.dport;
	if (uh->dest != htons(lport)) {
		/* 会话/参数里存主机序，包里是网络序：比较前必须转换。
		 * 目的端口不符同样属于"封装头不是我们的"，计入 rx_bad_hdr：
		 * 这条路径以前是静默返回，出问题时计数器上一个都看不到。
		 * ratelimited 打印实际值：端口不匹配只能靠对数值定位。 */
		pr_info_ratelimited("iwan: 目的端口不符: 收到 %u 期望 %u\n",
				    ntohs(uh->dest), lport);
		atomic64_inc(&pn->st.rx_bad_hdr);
		return NF_ACCEPT;
	}

	/* ③ 逐帧解封（GSO 合并包另走批处理路径）；
	 *    数据帧与控制帧在 iwan_decap_one() 里凭据校验之后分叉 */
	if (skb_is_gso(skb) && skb_shinfo(skb)->gso_size)
		return iwan_rx_batch(pn, skb, c, &dp, state);
	return iwan_rx_single(pn, skb, c, &dp, o.l3, state);
}

int iwan_rx_net_init(struct iwan_net *pn)
{
	struct iwan_cfg *c = iwan_cfg_get();
	int err;

	/* 两个族各挂一个钩子、指向同一个钩子函数。netfilter 的钩子表本身
	 * 分族（nf_hooks_ipv4 / nf_hooks_ipv6），没有"族无关的钩子"可用；
	 * 而按网卡挂钩（netdev_rx_handler / NF_NETDEV_INGRESS）会破坏"什么都
	 * 不绑"时任意承载网卡都能收、且承载网卡可自愈换卡的语义，所以走
	 * "两族各一钩子 + 共用钩子体"这条路。 */
	pn->rx_ops4.hook = iwan_rx_hook;
	pn->rx_ops4.pf = NFPROTO_IPV4;
	pn->rx_ops6.hook = iwan_rx_hook;
	pn->rx_ops6.pf = NFPROTO_IPV6;
	for (int i = 0; i < 2; i++) {
		struct nf_hook_ops *ops = i ? &pn->rx_ops6 : &pn->rx_ops4;

		ops->hooknum = READ_ONCE(c->hooknum) == IWAN_HOOK_LOCAL_IN ?
			       NF_INET_LOCAL_IN : NF_INET_PRE_ROUTING;
		ops->priority = READ_ONCE(c->hookprio);
		err = nf_register_net_hook(pn->net, ops);
		if (err) {
			pr_err("netns %u: nf_register_net_hook(%s) 失败 %d\n",
			       pn->net->ns.inum, i ? "v6" : "v4", err);
			if (i)
				nf_unregister_net_hook(pn->net, &pn->rx_ops4);
			return err;
		}
	}
	/* WRITE_ONCE 与 SESSION_UP 的 READ_ONCE(pn->rx_hooked) 配对：这个标志是
	 * "钩子闸门"的唯一依据（netns 创建与 SESSION_UP 可能在不同 CPU 上）。 */
	WRITE_ONCE(pn->rx_hooked, true);
	return 0;
}

void iwan_rx_net_exit(struct iwan_net *pn)
{
	if (pn->rx_hooked) {
		nf_unregister_net_hook(pn->net, &pn->rx_ops4);
		nf_unregister_net_hook(pn->net, &pn->rx_ops6);
		WRITE_ONCE(pn->rx_hooked, false);
		/*
		 * 摘掉钩子之后必须再等一个 RCU 宽限期，才能认为"没有在途钩子"：
		 * nf_unregister_net_hook() 只是把钩子从数组里摘掉、把旧数组交给
		 * call_rcu() 释放，一次**已经开始**的遍历（NF_HOOK 全程在
		 * rcu_read_lock() 里）仍可能调用到本钩子，而本钩子会写该 netns 的
		 * 共享内存页。调用者紧接着就要放页面的 pernet 引用
		 * （iwan_net_exit → iwan_shm_net_exit）：少了这道栅栏，就是
		 * "钩子还在跑、页面已回收"的 use-after-free。
		 * pernet exit 是进程上下文，synchronize_rcu() 可以睡眠。
		 */
		synchronize_rcu();
	}
}
