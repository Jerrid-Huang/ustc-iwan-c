#ifndef IWAN_REPLY_ROUTE_H
#define IWAN_REPLY_ROUTE_H

/*
 * 回程路由：让"从隧道进来的连接"的回包按来路回去。
 *
 * 为什么必须是 conntrack：Linux 对本机发出的包只按目的地址查 FIB，入接口不参与
 * 决策，也没有"记住来路"的机制。对端地址事先不可知（反向访问、远端从任意地址
 * 发起），所以只能把"入接口"记在连接跟踪表项上（CONNMARK），回包再还原成
 * fwmark 交给 `ip rule` 选一张只有隧道默认路由的表。设计全文见
 * docs/reply-routing.md。
 *
 * 判别式 = `-i <隧道入接口> -d <被服务地址集合>`：被服务地址集合是已知的
 * （来自 --proxy-cidr*），未知的只有对端；不能只按入接口标记，否则同一张承载
 * 网卡上的正常业务连接也会被塞进隧道。
 *
 * 两个数据面的入接口不同：
 *   · TUN 面    → iwan0（用户态把内层包写进 TUN，内核按"从 iwan0 收到"处理）；
 *   · kernel 面 → 承载网卡（模块在 PRE_ROUTING 解封后原地 NF_ACCEPT，不改
 *                 skb->dev；承载网卡名取自 SESSION_UP 回执/日志的承载解析）。
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

typedef struct {
	const char *tun;	     /* 隧道 netdev：回包路由的 dev，永远是 iwan0 */
	const char *in_if;	     /* 入方向匹配的接口名；NULL = 用 tun（TUN 面）。
			      * kernel 面必须给承载网卡名：解封后 skb->dev 仍是
			      * 物理口，而回包要从 iwan0 出去 —— 两者不是同一个 */
	const char *srv;	     /* 服务端外层地址（只用于日志/提示） */
	const slist_t *served4;	     /* 被服务地址集合 v4（CIDR/地址/域名；可 NULL） */
	const slist_t *served6;	     /* 被服务地址集合 v6（可 NULL）。两个列表在
			      * setup/teardown 期间必须一直有效（调用方持有） */
	uint32_t    mark;	     /* fwmark 值；0 = 默认 0x1 */
	uint32_t    table;	     /* 路由表号；0 = 默认 100 */
	bool	    kernel_plane;    /* true = 内核数据面（要查模块钩子参数） */
} reply_route_opts;

typedef struct {
	reply_route_opts o;	     /* 值拷贝：setup 返回后调用方可以释放自己的 opts */
	bool	installed;
	bool	nft;		     /* true = 用 nft，false = 退回 iptables */
	bool	v6;		     /* 是否也装了 v6 的 rule/表 */
	uint32_t mark;
	uint32_t table;
} reply_route_state;

/*
 * 先决检查。**这是"静默失效"防线**：内核面的模块钩子必须在 conntrack(-200)
 * 之前解封（默认 hooknum=0/PRE_ROUTING + hookprio=-300），或者 reinject=1
 * 让内层包重新入栈；否则内层连接根本不会进 conntrack 表，回包 --restore-mark
 * 得到 0，规则永远不命中 —— 不报错、也不生效。不满足时返回 false 并把可直接
 * 执行的修复命令写进 why。
 */
bool reply_route_precheck(const reply_route_opts *o, char *why, size_t whysz);

/* 装规则：nft（优先）或 iptables + ip rule/ip route。失败时把自己装过的部分
 * 回滚干净，并把原因写进 err。幂等：进入前先清掉同名残留。 */
bool reply_route_setup(const reply_route_opts *o, reply_route_state *st,
		       char *err, size_t errsz);

/* 只回滚自己装过的东西（与 route_teardown 同一口径）。可重复调用。 */
void reply_route_teardown(reply_route_state *st);

#endif /* IWAN_REPLY_ROUTE_H */
