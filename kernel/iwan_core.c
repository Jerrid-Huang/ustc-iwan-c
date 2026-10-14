// SPDX-License-Identifier: GPL-2.0
/*
 * iwan_core.c — 模块入口：全局配置（模块参数）、每 netns 生命周期、
 *               /proc/net/iwan（读统计 + 写每 netns 的出站端点）。
 *
 * 配置面分三层（v1 起，见 kernel/CONTROL-PLANE.md）：
 *   - 全局（模块参数）：**默认值**，只在该 netns 尚未建立 genetlink 会话时生效；
 *   - 每 netns 会话（genetlink，iwan_netlink.c 写）：会话建立后数据面只认它
 *     （iwan_dp_get 做"会话优先、参数回落"）；
 *   - 每 netns（/proc/net/iwan 可写）：无会话时的出站外层源/目的地址。一个模块
 *     实例服务所有 netns，而两个方向的出站目的地址不同，所以必须按 netns 配置
 *     —— 本机双向验证（两个 netns）正是靠这一点。
 *
 * 没有 netlink 会话时，数据面取到的每个字段都与引入控制面之前逐位一致：
 * 这是既有 13 项验收（kernel/tests/tcp_echo_test.sh）不回归的前提。
 *
 * /dev/iwan（共享内存页，iwan_shm.c）：每个 netns 一页，记录"最近一次收到
 * 有效帧"的单调毫秒（以及 peer_state/计数器），mmap 给用户态只读轮询。
 * 页面在 pernet init 分配、pernet exit 释放（引用计数，见 iwan_shm.c）。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>	/* kmap_local_page：分页 XOR 逐页映射 */
#include <linux/capability.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>	/* ipv6_skip_exthdr：内层 v6 的传输层偏移 */
#include <net/netns/generic.h>

#include "iwan.h"
#include "iwan_genl.h"	/* IWAN_GENL_NAME/VERSION：只用于启动日志 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#error "iwan 需要 Linux >= 4.18"
#endif

/* ---- 全局配置（模块参数 = 会话未建立时的默认值） ---------------------- */

static struct iwan_cfg cfg = {
	.enabled	= true,
	.any_dir	= false,
	.batch		= true,
	.reinject	= false,
	.verbose	= false,
	.hooknum	= IWAN_HOOK_PRE_ROUTING,
	.hookprio	= -300,
	.enc		= 1,
	.df		= true,
	.max_mtu	= IWAN_MAX_MTU,
};

struct iwan_cfg *iwan_cfg_get(void) { return &cfg; }

/*
 * 数据面取参：每 netns 会话优先，模块参数回落。
 *
 * 没有会话（sess.valid == false）时，这里给出的每个字段都与引入 genetlink
 * 控制面之前逐位一致：
 *   · RX 的外层过滤/端口/凭据 = 模块参数，开关 = cfg.enabled && pn->enabled；
 *   · TX 的外层端点 = /proc 配的 pn->tx_src/tx_dst，端口/凭据 = 模块参数。
 * 有会话时整组换成会话参数（含会话级 enabled 开关）。
 * 每包调用一次，取一份一致快照，避免同一包里读到两次不同的配置。
 *
 * 锁：没有锁，沿用 struct iwan_cfg 的既有约定（改配置时没有在途流量）；
 * 标量逐个 READ_ONCE，会话侧 valid 由控制面最后置位/最先清零。
 */
void iwan_dp_get(struct iwan_net *pn, const struct iwan_cfg *c, bool tx,
		 struct iwan_dp *dp)
{
	struct iwan_session *s = &pn->sess;
	bool up = READ_ONCE(s->valid);

	dp->session = up;
	/* inner_src 的 ABI 里没有会话级对应项，恒取模块参数 */
	dp->inner_src = READ_ONCE(c->inner_src);

	if (up) {
		/* any_dir 对会话恒为真：ABI 把 OUTER_SRC/DST 定义成"本端/对端"
		 * 这一对**身份**（不是方向），TX 用 (src→dst)，而同一个会话的
		 * 入站包恰好是反向的 (dst→src)，所以 RX 必须按无序对匹配。
		 * 模块参数 any_dir 只对下面的回落路径有意义（旧语义不变）。 */
		dp->any_dir = true;
		dp->enabled = READ_ONCE(c->enabled) && READ_ONCE(s->enabled);
		dp->outer_src = READ_ONCE(s->outer_src);
		dp->outer_dst = READ_ONCE(s->outer_dst);
		dp->outer_v6 = READ_ONCE(s->outer_v6);
		dp->outer_src6 = s->outer_src6;
		dp->outer_dst6 = s->outer_dst6;
		dp->bind_ip6 = s->bind_ip6;
		dp->dport = READ_ONCE(s->dport);
		dp->sport = READ_ONCE(s->sport);
		dp->oif = READ_ONCE(s->oif);
		dp->bind_ip = READ_ONCE(s->bind_ip);
		dp->sid = READ_ONCE(s->sid);
		dp->tok = READ_ONCE(s->tok);
		dp->enc = READ_ONCE(s->enc);
		memcpy(dp->key, s->key, IWAN_KEY_LEN);
		return;
	}

	dp->any_dir = READ_ONCE(c->any_dir);
	dp->enabled = READ_ONCE(c->enabled) && READ_ONCE(pn->enabled);
	dp->outer_src = tx ? READ_ONCE(pn->tx_src) : READ_ONCE(c->outer_src);
	dp->outer_dst = tx ? READ_ONCE(pn->tx_dst) : READ_ONCE(c->outer_dst);
	/* 外层 v6 只由会话（netlink）表达，/proc 回落路径没有对应项：显式清零。
	 * 调用方的 struct iwan_dp 在栈上，漏掉这一步就等于让"外层头用哪个版本"
	 * 由栈垃圾决定（TX 会走 v6 分支拿零地址发）。 */
	dp->outer_v6 = false;
	memset(&dp->outer_src6, 0, sizeof(dp->outer_src6));
	memset(&dp->outer_dst6, 0, sizeof(dp->outer_dst6));
	memset(&dp->bind_ip6, 0, sizeof(dp->bind_ip6));
	/* 承载网卡绑定是设备属性（不分方向）：回落路径统一取 /proc 配的
	 * tx_oif，0 = 由 FIB 解析一次后钉住。 */
	dp->oif = READ_ONCE(pn->tx_oif);
	dp->bind_ip = READ_ONCE(pn->tx_bind_ip);
	dp->dport = READ_ONCE(c->dport);
	dp->sport = READ_ONCE(c->sport);
	dp->sid = READ_ONCE(c->sid);
	dp->tok = READ_ONCE(c->tok);
	dp->enc = READ_ONCE(c->enc);
	memcpy(dp->key, c->key, IWAN_KEY_LEN);
}

unsigned int iwan_net_id __read_mostly;

module_param_named(enabled, cfg.enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "总开关（默认 1）");
module_param_named(any_dir, cfg.any_dir, bool, 0644);
MODULE_PARM_DESC(any_dir, "外层 (src,dst) 允许反向，便于本机双向/对等测试");
module_param_named(batch, cfg.batch, bool, 0644);
MODULE_PARM_DESC(batch, "处理 GRO 合并后的 GSO skb（默认 1）");
module_param_named(reinject, cfg.reinject, bool, 0644);
MODULE_PARM_DESC(reinject, "解封后 netif_rx 回到 ip_defrag 之前（LOCAL_IN 兜底）");
module_param_named(verbose, cfg.verbose, bool, 0644);
module_param_named(hooknum, cfg.hooknum, int, 0644);
MODULE_PARM_DESC(hooknum, "0=PRE_ROUTING（默认）, 1=LOCAL_IN（兜底）");
module_param_named(hookprio, cfg.hookprio, int, 0644);
MODULE_PARM_DESC(hookprio, "钩子优先级，默认 -300（defrag 之后、conntrack 之前）");
module_param_named(max_mtu, cfg.max_mtu, uint, 0644);
MODULE_PARM_DESC(max_mtu, "内层 MTU 上限（默认 1500；规范硬上限 65499）。"
			  "超过硬上限的值会被夹住而不是生效");
module_param_named(dport, cfg.dport, ushort, 0644);
MODULE_PARM_DESC(dport, "隧道 UDP 目的端口（RX 匹配、TX 使用）");
module_param_named(sport, cfg.sport, ushort, 0644);
MODULE_PARM_DESC(sport, "隧道 UDP 源端口（仅 TX；0 = 用 dport）");
module_param_named(sid, cfg.sid, ushort, 0644);
MODULE_PARM_DESC(sid, "会话 id（OPEN_ACK 下发）");
module_param_named(tok, cfg.tok, uint, 0644);
MODULE_PARM_DESC(tok, "会话 token（u32，OPEN_ACK 下发）");
module_param_named(enc, cfg.enc, byte, 0644);
MODULE_PARM_DESC(enc, "1 = 数据面 XOR（DATA_ENC），0 = 明文（DATA）");
module_param_named(df, cfg.df, bool, 0644);
MODULE_PARM_DESC(df, "外层 IP 置 DF=1（默认 1）；置 0 允许外层分片，用来验证钩子内联重组");

/* ---- 字符串型参数 ---------------------------------------------------- */

static char key_hex[2 * IWAN_KEY_LEN + 1] = "0000000000000000";
static char outer_src_str[16] = "0.0.0.0";
static char outer_dst_str[16] = "0.0.0.0";
static char inner_src_str[16] = "0.0.0.0";

static int iwan_hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int iwan_set_key(const char *val, const struct kernel_param *kp)
{
	u8 tmp[IWAN_KEY_LEN];
	int i;

	(void)kp;
	if (strcspn(val, "\n") != 2 * IWAN_KEY_LEN)
		return -EINVAL;
	for (i = 0; i < IWAN_KEY_LEN; i++) {
		int hi = iwan_hexval(val[2 * i]);
		int lo = iwan_hexval(val[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		tmp[i] = (u8)((hi << 4) | lo);
	}
	memcpy(cfg.key, tmp, IWAN_KEY_LEN);
	strscpy(key_hex, val, sizeof(key_hex));
	return 0;
}

static int iwan_get_key(char *buf, const struct kernel_param *kp)
{
	(void)kp;
	return scnprintf(buf, PAGE_SIZE, "%s\n", key_hex);
}

static const struct kernel_param_ops iwan_key_ops = {
	.set = iwan_set_key,
	.get = iwan_get_key,
};

static int iwan_set_addr(const char *val, const struct kernel_param *kp)
{
	__be32 a;
	char *dst = kp->arg;

	if (!in4_pton(val, strcspn(val, "\n"), (u8 *)&a, -1, NULL))
		return -EINVAL;
	if (dst == (char *)&cfg.outer_src) {
		WRITE_ONCE(cfg.outer_src, a);
		strscpy(outer_src_str, val, sizeof(outer_src_str));
	} else if (dst == (char *)&cfg.outer_dst) {
		WRITE_ONCE(cfg.outer_dst, a);
		strscpy(outer_dst_str, val, sizeof(outer_dst_str));
	} else {
		WRITE_ONCE(cfg.inner_src, a);
		strscpy(inner_src_str, val, sizeof(inner_src_str));
	}
	return 0;
}

static int iwan_get_addr(char *buf, const struct kernel_param *kp)
{
	char *src = kp->arg;

	if (src == (char *)&cfg.outer_src)
		src = outer_src_str;
	else if (src == (char *)&cfg.outer_dst)
		src = outer_dst_str;
	else
		src = inner_src_str;
	return scnprintf(buf, PAGE_SIZE, "%s\n", src);
}

static const struct kernel_param_ops iwan_addr_ops = {
	.set = iwan_set_addr,
	.get = iwan_get_addr,
};

module_param_cb(outer_src, &iwan_addr_ops, &cfg.outer_src, 0644);
MODULE_PARM_DESC(outer_src, "RX 过滤：外层源地址（服务端 IP）");
module_param_cb(outer_dst, &iwan_addr_ops, &cfg.outer_dst, 0644);
MODULE_PARM_DESC(outer_dst, "RX 过滤：外层目的地址（本机隧道地址）");
module_param_cb(inner_src, &iwan_addr_ops, &cfg.inner_src, 0644);
MODULE_PARM_DESC(inner_src, "可选：内层源地址白名单，0.0.0.0 = 关闭");
module_param_cb(key, &iwan_key_ops, NULL, 0644);
MODULE_PARM_DESC(key, "16 位十六进制数据面密钥 = MD5(user||pass)[0..8)");

/* ---- XOR ------------------------------------------------------------- */

/*
 * 会话密钥是 8 字节循环密钥，作用在内层 IPv4 包的**全部字节**（含内层 IP
 * 头）——所以入站必须先解密再读内层头，出站必须在校验和算完之后再 XOR。
 * 与用户态 xor_crypt() 的 64 位字实现逐字节等价；off 供跨区续算。
 */
void iwan_xor(u8 *p, size_t len, const u8 *key, size_t off)
{
	u64 k, v;
	size_t i = 0;

	memcpy(&k, key, IWAN_KEY_LEN);
	while (i < len && ((off + i) & 7))
		p[i] ^= key[(off + i) & 7], i++;
	while (i + 8 <= len) {
		memcpy(&v, p + i, 8);
		v ^= k;
		memcpy(p + i, &v, 8);
		i += 8;
	}
	while (i < len) {
		p[i] ^= key[(off + i) & 7];
		i++;
	}
}

/*
 * 对 skb 全部载荷（线性区 + 页帧 + frag_list）按 8 字节会话密钥做就地 XOR，
 * off 跨段连续递增 —— 与对"整包逻辑字节序列"的变换严格等价，但不要求物理
 * 连续，从而免去整包线性化。此前大 MTU 档（载荷超过内核分页分配阈值后，
 * 发送侧 validate_xmit_skb 线性化 + 接收侧 skb_ensure_writable 线性化）的
 * 两次全包复制是与裸 lo 基线 6 倍差距的主体。kmap_local_page 可在软中断
 * 上下文使用；frag_list 子 skb 递归处理（外层 df=0 分片重组后的形态）。
 * 调用前提：调用方已确认整包可写（见 iwan_xor_skb）。
 */
static void iwan_xor_paged(struct sk_buff *skb, const u8 *key, u32 off)
{
	struct sk_buff *it;
	skb_frag_t *f;
	u8 *p;
	u32 n, i;

	p = skb->data;
	n = skb_headlen(skb);
	iwan_xor(p, n, key, off);
	off += n;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		void *base;

		f = &skb_shinfo(skb)->frags[i];
		n = skb_frag_size(f);
		if (n) {
			base = kmap_local_page(skb_frag_page(f));
			iwan_xor(base + skb_frag_off(f), n, key, off);
			kunmap_local(base);
		}
		off += n;
	}

	for (it = skb_shinfo(skb)->frag_list; it; it = it->next) {
		iwan_xor_paged(it, key, off);
		off += it->len;
	}
}

/*
 * 就地 XOR 整个 skb（含页帧）。
 *
 * 可写性前提：就地修改要求对缓冲区的独占写权。skb 克隆（克隆双方共享
 * shinfo 与页帧，典型如 TCP 重传队列的原始 skb）与 MSG_ZEROCOPY 固定的
 * 用户页都不可写 —— 这两类回退到旧路径：skb_ensure_writable() 处理克隆
 * （必要时 pskb_expand_head）并把数据拉进线性区，skb_linearize() 兜底，
 * 再对线性区变换。独占情形走 iwan_xor_paged()，无复制。
 */
int iwan_xor_skb(struct sk_buff *skb, const u8 *key)
{
	if (unlikely(skb_cloned(skb) || skb_header_cloned(skb) ||
		     (skb_shinfo(skb)->flags & SKBFL_ALL_ZEROCOPY))) {
		if (unlikely(skb_ensure_writable(skb, skb->len)))
			return -ENOMEM;
		if (unlikely(skb_is_nonlinear(skb)) && skb_linearize(skb))
			return -ENOMEM;
		iwan_xor(skb->data, skb->len, key, 0);
		return 0;
	}
	iwan_xor_paged(skb, key, 0);
	return 0;
}

/*
 * 内层 IP 头校验 —— TX（iwan_tx.c）与 RX（iwan_rx.c）共用同一份判据，免得
 * 两条路径的版本支持各自漂移（v6 支持是"两处一起开"的能力）。
 *
 * 只判"头部自洽"，不判策略：模块是数据面，源/目的地址过滤留给用户态
 * （TUN 路径有 inner_ip 与派生 ULA 的准入过滤；内核面历史上只有模块参数
 * inner_src 这个 v4 白名单，语义见 iwan_rx.c 的调用点）。
 *
 * exact_len=true（TX）：数据帧恰好承载**一个**完整内层报文，声明长度必须
 *   等于 skb->len —— 出站绝不能把残缺/多尾字节的报文封进隧道。
 * exact_len=false（RX）：保持引入 v6 之前就有的宽松口径 —— 内层头声明的
 *   长度盖不住整帧才拒，多余尾字节不拒（不改既有行为）。
 *
 * v4：version=4、ihl≥5、tot_len ∈ [ihl*4, skb->len]（exact_len 时取等）；
 * v6：version=6、payload_len+40 == skb->len（exact_len 时取等）、
 *     不认 payload_len=0 的逐跳巨帧形式（真实长度在逐跳选项里，本模块不做
 *     巨帧）、扩展头链必须走得通（ipv6_skip_exthdr 不返回负值）。
 *     内层分片与 v4 一样交给协议栈重组（本模块不重组内层）。
 * 出参 *net_hdr_len = 内层网络头长度（v4 = ihl*4；v6 = 40 + 扩展头），
 * 调用方据此设置传输层偏移 —— v6 不能照搬 v4 的 ihl 算法。
 *
 * 返回 0 = 合法，-EINVAL = 非法（调用方按 tx_bad_inner / rx_bad_inner 计数）。
 */
int iwan_inner_hdr_check(struct sk_buff *skb, bool exact_len, u32 *net_hdr_len)
{
	const struct iphdr *iph;
	const struct ipv6hdr *ip6h;
	u8 ver, nexthdr;
	__be16 frag_off;
	u32 tot, hdrlen;
	int off;

	/* 先保证版本字节在线性区（skb->data 可能整个在页帧里） */
	if (unlikely(!pskb_may_pull(skb, 1)))
		return -EINVAL;
	ver = skb->data[0] >> 4;

	if (ver == 4) {
		if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
			return -EINVAL;
		iph = ip_hdr(skb);
		if (iph->version != 4 || iph->ihl < 5)
			return -EINVAL;
		hdrlen = (u32)iph->ihl * 4;
		tot = ntohs(iph->tot_len);
		if (tot < hdrlen)
			return -EINVAL;
		if (exact_len ? tot != skb->len : tot > skb->len)
			return -EINVAL;
		*net_hdr_len = hdrlen;
		return 0;
	}

	if (ver == 6) {
		if (unlikely(!pskb_may_pull(skb, sizeof(*ip6h))))
			return -EINVAL;
		ip6h = (const struct ipv6hdr *)skb_network_header(skb);
		if (ip6h->version != 6 || ntohs(ip6h->payload_len) == 0)
			return -EINVAL;
		tot = (u32)ntohs(ip6h->payload_len) + (u32)sizeof(*ip6h);
		if (exact_len ? tot != skb->len : tot > skb->len)
			return -EINVAL;
		/* 扩展头链（含分片头）：拿到传输层偏移；坏链一律拒 */
		nexthdr = ip6h->nexthdr;
		off = ipv6_skip_exthdr(skb, (int)sizeof(*ip6h), &nexthdr,
				       &frag_off);
		if (off < 0 || (u32)off > skb->len)
			return -EINVAL;
		*net_hdr_len = (u32)off;
		return 0;
	}

	return -EINVAL;
}

/* ---- /proc/net/iwan：读统计、写每 netns 出站端点 --------------------- */

/*
 * 读路径**冻结**：格式与字段一个都不能动（既有 13 项验收按名字读计数器），
 * 所以这里显示的一直是"模块参数 + 每 netns 开关/端点"这一层；netlink 会话
 * 的状态/计数器请走 IWAN_CMD_GET_STATS（新计数器 rx_ctrl_frame 也只在那边）。
 */
static void iwan_proc_format(struct iwan_net *pn, char *buf, size_t size)
{
	struct iwan_stats *s = &pn->st;

	snprintf(buf, size,
		"enabled %d any_dir %d batch %d reinject %d hooknum %d prio %d\n"
		"outer_src %pI4 outer_dst %pI4 inner_src %pI4 dport %u sport %u\n"
		"sid %u tok %u enc %u df %d key %s\n"
		"netns_enabled %d tx_src %pI4 tx_dst %pI4 dev %s\n"
		"tx_oif %u tx_bind_ip %pI4 carrier %u\n"
		"rx_pkts %lld\nrx_outer %lld\nrx_reasm %lld\nrx_frames %lld\n"
		"rx_delivered %lld\nrx_batch %lld\nrx_batch_skip %lld\n"
		"rx_bad_hdr %lld\nrx_bad_inner %lld\nrx_nomem %lld\n"
		"tx_pkts %lld\ntx_bytes %lld\ntx_bad_state %lld\n"
		"tx_bad_inner %lld\ntx_err %lld\n",
		READ_ONCE(cfg.enabled), READ_ONCE(cfg.any_dir), READ_ONCE(cfg.batch),
		READ_ONCE(cfg.reinject), READ_ONCE(cfg.hooknum),
		READ_ONCE(cfg.hookprio), &cfg.outer_src, &cfg.outer_dst,
		&cfg.inner_src, READ_ONCE(cfg.dport),
		READ_ONCE(cfg.sport) ? READ_ONCE(cfg.sport) : READ_ONCE(cfg.dport),
		READ_ONCE(cfg.sid), READ_ONCE(cfg.tok), READ_ONCE(cfg.enc),
		READ_ONCE(cfg.df), key_hex,
		READ_ONCE(pn->enabled), &pn->tx_src, &pn->tx_dst,
		"-",	/* 网卡改由 rtnl_link_ops 创建，不再挂在 netns 状态里 */
		READ_ONCE(pn->tx_oif), &pn->tx_bind_ip, READ_ONCE(pn->carrier),
		(long long)atomic64_read(&s->rx_pkts),
		(long long)atomic64_read(&s->rx_outer),
		(long long)atomic64_read(&s->rx_reasm),
		(long long)atomic64_read(&s->rx_frames),
		(long long)atomic64_read(&s->rx_delivered),
		(long long)atomic64_read(&s->rx_batch),
		(long long)atomic64_read(&s->rx_batch_skip),
		(long long)atomic64_read(&s->rx_bad_hdr),
		(long long)atomic64_read(&s->rx_bad_inner),
		(long long)atomic64_read(&s->rx_nomem),
		(long long)atomic64_read(&s->tx_pkts),
		(long long)atomic64_read(&s->tx_bytes),
		(long long)atomic64_read(&s->tx_bad_state),
		(long long)atomic64_read(&s->tx_bad_inner),
		(long long)atomic64_read(&s->tx_err));
}

static ssize_t iwan_proc_read(struct file *file, char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	struct iwan_net *pn = pde_data(file_inode(file));
	char *buf;
	ssize_t ret;

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	iwan_proc_format(pn, buf, 1024);
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, strlen(buf));
	kfree(buf);
	return ret;
}

/* 写：tx_src=A.B.C.D tx_dst=A.B.C.D enabled=0/1 oif=<ifindex> ip=A.B.C.D
 *
 * oif = 显式绑定的承载网卡（下游网卡）ifindex；省略或 0 表示由 FIB 解析一次后
 * 钉住。两种情况下数据面都只用一张卡，语义见 iwan_tx.c 的 iwan_carrier_pin()。
 *
 * ip = 显式绑定的**出口 IP**（"绑 IP"模式）：它同时设定 tx_src（外层头的源
 * 地址）并按本机地址表决定承载网卡——地址挂在哪张接口上就用哪张，与 oif
 * 给的网卡冲突（地址不在该卡上）则整条写入失败（-EINVAL）。地址当时不属于
 * 任何本机接口则失败（-EADDRNOTAVAIL）：绑一个不存在的地址没有意义，这里
 * 刻意与 oif 的"只校验格式"不同。ip=0.0.0.0 清除按 IP 的绑定。
 *
 * 一次 write() 是**一个配置事务**：全部令牌先解析并针对提交后的状态校验，
 * 最后一次性提交；任一处不合法则整条不生效（不会留下"半个配置"）。因此
 * `oif=2 ip=<不在该卡上的地址>` 这类写入失败后，oif 也不会被改掉。
 *
 * 已废弃（deprecated）：新功能一律加在 genetlink 控制面（iwan_netlink.c）。
 * 保留是为了既有测试脚本与排障：**没有 netlink 会话时**这里配的就是数据面
 * 实际用的每 netns 出站端点/开关；一旦该 netns 建立了会话，数据面改认会话
 * 参数（iwan_dp_get），本文件写的值只作为回落默认值存在。
 */
static ssize_t iwan_proc_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct iwan_net *pn = pde_data(file_inode(file));
	char buf[128], *p, *tok;
	/* 一次 write() 是一个配置事务：先在本地把整条写入解析并针对**提交后**
	 * 的状态校验，最后一次性提交。逐令牌边解析边生效会留下"半个配置"
	 * —— 前半段生效、后半段报错，那个中间态既没有对应的命令行，又会让下一
	 * 条本应成功的写入莫名冲突（实测：`oif=2 ip=<别的网卡地址>` 失败后
	 * oif 已经落成 2）。 */
	__be32 n_src = READ_ONCE(pn->tx_src);
	__be32 n_dst = READ_ONCE(pn->tx_dst);
	__be32 n_bind = READ_ONCE(pn->tx_bind_ip);
	u32 n_oif = READ_ONCE(pn->tx_oif);
	bool n_enabled = READ_ONCE(pn->enabled);
	bool touch_tx = false;
	bool touch_en = false;
	bool saw_src = false;
	bool saw_ip = false;
	__be32 v_src = 0;
	__be32 v_ip = 0;
	int err;

	(void)ppos;
	if (!ns_capable(pn->net->user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	p = buf;
	while ((tok = strsep(&p, " \t\r\n")) != NULL) {
		char *eq = strchr(tok, '=');
		__be32 a;
		bool b;

		if (!*tok)
			continue;
		if (!eq)
			return -EINVAL;
		*eq++ = '\0';
		if (!strcmp(tok, "tx_src")) {
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_src = a;
			v_src = a;
			saw_src = true;
			touch_tx = true;
		} else if (!strcmp(tok, "tx_dst")) {
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_dst = a;
			touch_tx = true;
		} else if (!strcmp(tok, "oif")) {
			/* 显式绑定承载网卡（ifindex，0 = 由 FIB 解析后钉住）。
			 * 只校验格式不校验存在性：/proc 常在网卡/路由之前配，
			 * 真正的解析在会话建立或首包出站时做，失败计入 tx_err。 */
			if (kstrtou32(eq, 0, &n_oif))
				return -EINVAL;
			touch_tx = true;
		} else if (!strcmp(tok, "ip")) {
			/* 出口 IP 绑定：它同时是外层头的源地址（外层头用
			 * OUTER_SRC，所以这里一并改写 n_src）。 */
			if (!in4_pton(eq, -1, (u8 *)&a, -1, NULL))
				return -EINVAL;
			n_bind = a;
			v_ip = a;
			saw_ip = true;
			if (a)
				n_src = a;
			touch_tx = true;
		} else if (!strcmp(tok, "enabled")) {
			if (kstrtobool(eq, &b))
				return -EINVAL;
			n_enabled = b;
			touch_en = true;
		} else {
			return -EINVAL;
		}
	}

	/* 事务级校验，针对提交后的状态：
	 *   ① 出口 IP 必须属于某张本机接口（地址表），且若同时绑了网卡，就
	 *      必须在那张卡上（地址不在本机 = -EADDRNOTAVAIL，冲突 = -EINVAL）；
	 *   ② 出口 IP 必须就是外层源地址 —— 外层头写的是 OUTER_SRC，两者不
	 *      一致等于"绑定"与"实际发出的源地址"不是同一个值。
	 * 只在这次写入真的动了端点/绑定（tx_src/tx_dst/oif/ip）时才校验：
	 * 否则一条只改 enabled 的写入会被既有的失效绑定连坐 —— 那样连
	 * "关掉数据面"都写不进去，排障时无路可走。 */
	if (touch_tx) {
		err = iwan_bind_ip_check(pn->net, n_bind, n_oif);
		if (err)
			return err;
		if (n_bind && n_bind != n_src)
			return -EINVAL;
		/* 同一条写入里 tx_src 与 ip 都给了却不一致：两个令牌设的是同一
		 * 个字段，按顺序取后者会变成"谁写在后面谁赢"，直接拒绝。
		 * ip=0.0.0.0 是"清除绑定"，不参与比较。 */
		if (saw_src && saw_ip && v_ip != 0 && v_src != v_ip)
			return -EINVAL;
	}

	if (touch_tx) {
		WRITE_ONCE(pn->tx_src, n_src);
		WRITE_ONCE(pn->tx_dst, n_dst);
		WRITE_ONCE(pn->tx_oif, n_oif);
		WRITE_ONCE(pn->tx_bind_ip, n_bind);
		/* 端点或绑定规格变了：钉住的那张卡不再代表本次配置 */
		iwan_carrier_forget(pn);
	}
	if (touch_en)
		WRITE_ONCE(pn->enabled, n_enabled);
	return count;
}

static const struct proc_ops iwan_proc_ops = {
	.proc_read	= iwan_proc_read,
	.proc_write	= iwan_proc_write,
};

/* ---- 每 netns 生命周期 -----------------------------------------------
 *
 * 只用**一个 device 类** pernet 操作，做两件事：注册 netfilter 钩子、建
 * /proc/net/iwan。顺序是硬约束，这里踩过坑（insmod 正常，ip netns add 把
 * 内核打崩，随后模块永远卡在 "正在加载"，只能重启）：
 *
 *  · device 类的 init 整体排在所有 subsys 类 init 之后 —— 实测依据：早先按
 *    subsys 注册时我们的 init 跑在 loopback_net_init 之前，register_netdevice()
 *    在还没建好的 netns 设备表上炸掉。
 *  · 而 netfilter 的 netns 钩子数组与 /proc/net 目录分别由
 *    netfilter_net_init、proc_net_ns_init 这两个 subsys 操作建立，必须等它们
 *    跑完再动：否则钩子会被随后初始化的数组冲掉，/proc/net 也还不存在。
 *
 * 网卡一律不在这里建：pernet init 的上下文既受上面这个顺序摆布，建出来的
 * 设备还会反引用模块、让 rmmod 永远失败。改用 rtnl_link_ops，由
 * `ip link add <name> type iwan` 显式创建，生命周期完全交给内核。
 */
static int __net_init iwan_net_init(struct net *net)
{
	struct iwan_net *pn = iwan_net_of(net);
	int err;

	pn->net = net;
	pn->enabled = true;
	/* 会话状态：net_generic 的内存本已清零，这里显式初始化以防将来改动。
	 * valid == false ⇒ 数据面走"模块参数默认值"的回落路径，行为与引入
	 * genetlink 控制面之前逐位一致；会话只能由 SESSION_UP 建立。 */
	memset(&pn->sess, 0, sizeof(pn->sess));
	/* 共享内存页（/dev/iwan）：放在 RX 钩子之前分配，于是"钩子在跑"就
	 * 意味着 pn->shm 一定非 NULL（RX 侧仍然按可空写，见 iwan.h）。
	 * 注意 pernet init 失败时内核不会回调对应的 exit（setup_net 的
	 * out_undo 只回滚已成功的 ops），所以返回错误前不能有任何已分配资源
	 * —— 这也是把页面分配放在最前面的原因。 */
	err = iwan_shm_net_init(pn);
	if (err) {
		pr_err("netns %u: 共享内存页分配失败 %d\n", net->ns.inum, err);
		return err;
	}
	/* 出站外层路由缓存：放在 shm 之后初始化。同因（pernet init 失败不会
	 * 回调 exit），这里不因分配失败返回错误 —— 标记不可用即可，数据面
	 * 退化为逐包 FIB 查找，正确性不受影响。 */
	if (dst_cache_init(&pn->tx_route, GFP_KERNEL)) {
		pr_warn("netns %u: 出站路由缓存分配失败，退化为逐包 FIB 查找\n",
			net->ns.inum);
	} else {
		pn->tx_route_ok = true;
	}
	/*
	 * 返回值刻意不传播（写成 (void) 是为了让"故意丢弃"一眼可见）：
	 * netns 创建失败的代价太大 —— 那会让整个 netns 建不起来，连排障用的
	 * 最基本工具都跑不了。失败时 iwan_rx_net_init() 内部已经 pr_err 并让
	 * pn->rx_hooked 保持 false，数据面在这个 netns 里等于关闭；SESSION_UP
	 * 会检查 rx_hooked 并回 -EIO（见 iwan_netlink.c），用户态因此能看到
	 * 明确失败，而不会拿到"会话成功但收不到包"的假象。
	 */
	(void)iwan_rx_net_init(pn);
	if (!net->proc_net) {
		/* 正常不会走到：proc_net 由 netns 框架的 subsys 初始化建好。
		 * 真出现也只是没有配置文件，绝不能在这里解空指针。 */
		pr_err("netns %u: proc_net 尚未就绪，跳过 /proc/net/iwan\n",
		       net->ns.inum);
		return 0;
	}
	pn->proc = proc_create_data("iwan", 0644, net->proc_net,
				    &iwan_proc_ops, pn);
	return 0;
}

static void __net_exit iwan_net_exit(struct net *net)
{
	struct iwan_net *pn = iwan_net_of(net);

	/* 会话里那张网卡：netns 销毁时由设备框架一并回收，这里不碰设备 ——
	 * device 类的 pernet exit 跑在 rtnl 锁内，再取 rtnl 会死锁。 */
	if (pn->proc) {
		remove_proc_entry("iwan", net->proc_net);
		pn->proc = NULL;
	}
	/* 顺序是硬约束：先摘钩子（iwan_rx_net_exit 内部 synchronize_rcu 保证
	 * 没有在途钩子还会写共享内存页），再放页面的 pernet 引用。反过来就是
	 * "钩子还在跑、页面已回收"的 use-after-free。 */
	iwan_rx_net_exit(pn);
	iwan_shm_net_exit(pn);
	/* 路由缓存最后销毁：其中 dst 引用可能指向本 netns 的外层设备，等在途
	 * 引用（skb_dst_set 的 dst_clone）全部释放后统一 drop。 */
	if (pn->tx_route_ok)
		dst_cache_destroy(&pn->tx_route);
}

static struct pernet_operations iwan_net_ops = {
	.init = iwan_net_init,
	.exit = iwan_net_exit,
	.id   = &iwan_net_id,
	.size = sizeof(struct iwan_net),
};

/*
 * 注册顺序（退出反序）：pernet 设备类 → /dev/iwan（misc）→ netdev 的
 * rtnl_link_ops → genetlink 家族。
 *   · /dev/iwan 的 open() 要按 opener 的 netns 取 net_generic 状态，所以必须
 *     排在 register_pernet_device() 之后（先有 pernet 区域，再有设备节点）；
 *   · genetlink 放最后：控制面的 SESSION_UP 要用 rtnl_link_ops 建 iwan0，家族
 *     一旦可见就必须具备全部依赖；unregister 反序则保证命令先消失、再拆设备
 *     类型、/dev/iwan 与 pernet 状态。
 */
static int __init iwan_init(void)
{
	static const u8 zero[IWAN_KEY_LEN];
	int err;

	if (!memcmp(cfg.key, zero, IWAN_KEY_LEN))
		pr_warn("key 仍为全零：只适合功能验证，生产必须用会话密钥\n");

	err = register_pernet_device(&iwan_net_ops);
	if (err)
		return err;
	err = iwan_shm_init();
	if (err) {
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}
	err = iwan_tx_init();
	if (err) {
		iwan_shm_exit();
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}
	err = iwan_netlink_init();
	if (err) {
		iwan_tx_exit();
		iwan_shm_exit();
		unregister_pernet_device(&iwan_net_ops);
		return err;
	}

	pr_info("loaded: hooknum=%d prio=%d dport=%u sid=%u enc=%d key=%s（模块参数 = 会话未建立时的默认值；控制面 genetlink \"%s\" v%d；存活状态 /dev/%s mmap 只读一页/netns）\n",
		cfg.hooknum, cfg.hookprio, cfg.dport, cfg.sid, cfg.enc, key_hex,
		IWAN_GENL_NAME, IWAN_GENL_VERSION, IWAN_SHM_DEV_NAME);
	return 0;
}

static void __exit iwan_exit(void)
{
	iwan_netlink_exit();
	iwan_tx_exit();
	iwan_shm_exit();
	unregister_pernet_device(&iwan_net_ops);
	pr_info("unloaded\n");
}

module_init(iwan_init);
module_exit(iwan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("USTC iWAN");
MODULE_DESCRIPTION("iWAN zero-user-space data path: netfilter RX decap + virtual NIC TX encap");
MODULE_VERSION("0.1.0");
