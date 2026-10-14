/*
 * 回程路由实现：conntrack（CONNMARK）+ fwmark 策略路由。
 * 设计与取舍见 docs/reply-routing.md；接口语义见 reply_route.h。
 *
 * 命令一律走 port_run_cmd（不经 shell），参数按 argv 逐个给，所以地址/接口名
 * 里的字符不会被解释。装规则时先把同名残留清掉（幂等），失败按逆序回滚自己
 * 装过的部分。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "port.h"
#include "reply_route.h"
#include "util.h"

#define RR_DEF_MARK  0x1u
#define RR_DEF_TABLE 100u
/* fwmark 规则的优先级：比 main(32766)/default(32767) 小，比常见的 ip rule
 * 用户规则（1000 起）同一档；只匹配 fwmark，不影响未标记的包。 */
#define RR_RULE_PREF 1000u

static uint32_t rr_mark(const reply_route_opts *o)
{
	return o->mark ? o->mark : RR_DEF_MARK;
}

static uint32_t rr_table(const reply_route_opts *o)
{
	return o->table ? o->table : RR_DEF_TABLE;
}

static bool rr_is_v6(const char *s)
{
	return strchr(s, ':') != NULL;
}

static size_t rr_n_served(const reply_route_opts *o)
{
	return (o->served4 ? o->served4->n : 0) + (o->served6 ? o->served6->n : 0);
}

static const char *rr_served_at(const reply_route_opts *o, size_t i)
{
	size_t n4 = o->served4 ? o->served4->n : 0;

	if (i < n4)
		return o->served4->v[i];
	return o->served6->v[i - n4];
}

/* 跑一条命令；失败只记 debug（调用方决定是否致命）。 */
static bool rr_run(char *const argv[], const char *what)
{
	(void)what;	/* release 档 log_debug 会被编掉，别让参数变未使用 */
	if (port_run_cmd(argv) == 0)
		return true;
	log_debug("回程路由: %s 没成功（可能本来就不存在）", what);
	return false;
}

/* 读 /sys/module/iwan/parameters/<name>；成功返回 true。 */
static bool rr_sysfs(const char *name, long *out)
{
	char path[128];
	char buf[32];
	FILE *f;

	snprintf(path, sizeof(path), "/sys/module/iwan/parameters/%s", name);
	f = fopen(path, "r");
	if (f == NULL)
		return false;
	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		return false;
	}
	fclose(f);
	*out = strtol(buf, NULL, 10);
	return true;
}

bool reply_route_precheck(const reply_route_opts *o, char *why, size_t whysz)
{
	long hooknum = -1;
	long hookprio = 0;
	long reinject = -1;
	bool ct_ok = false;

	if (o->tun == NULL || o->tun[0] == '\0') {
		snprintf(why, whysz, "回程路由需要隧道接口名（内核面是 iwan0）");
		return false;
	}
	if (rr_n_served(o) == 0) {
		snprintf(why, whysz,
			 "回程路由需要\"被服务地址集合\"，但这一轮一个都没给："
			 "至少要有一个 --proxy-cidr/--proxy-ip/--proxy-domain"
			 "（v6 用 --proxy-cidr6）——\n  只按入接口标记会把承载网卡上"
			 "所有非隧道流量也塞进隧道，所以必须有 -d 这一半");
		return false;
	}
	if (!o->kernel_plane)
		return true;	/* TUN 面：内层包由 iwan0 重新入栈，必然过 conntrack */

	/* 内核面：模块的钩子必须在 conntrack(-200) 之前解封，或者 reinject=1
	 * 让包重新入栈。否则内层连接不进 conntrack 表 → 回包 restore 得到 0 →
	 * 规则静默不生效（不报错、也不通）。 */
	if (!rr_sysfs("hooknum", &hooknum) || !rr_sysfs("reinject", &reinject)) {
		snprintf(why, whysz,
			 "读不到 /sys/module/iwan/parameters/{hooknum,reinject}："
			 "内核模块 iwan 没加载？回程路由在内核面需要它");
		return false;
	}
	(void)rr_sysfs("hookprio", &hookprio);
	if (hooknum == 0 && hookprio < -200)
		ct_ok = true;
	if (reinject == 1)
		ct_ok = true;
	if (!ct_ok) {
		snprintf(why, whysz,
			 "内核面的模块钩子不在 conntrack 之前（hooknum=%ld hookprio=%ld "
			 "reinject=%ld）：解封后的内层包不会再经过 conntrack，"
			 "内层连接没有表项，\n  回包 --restore-mark 得到 0 —— 回程规则"
			 "会**静默不生效**（不报错，但回包仍走物理网卡）。修复二选一：\n"
			 "    echo 0 > /sys/module/iwan/parameters/hooknum\n"
			 "    echo -300 > /sys/module/iwan/parameters/hookprio\n"
			 "  或\n"
			 "    echo 1 > /sys/module/iwan/parameters/reinject",
			 hooknum, hookprio, reinject);
		return false;
	}
	return true;
}

/* ---------------------------------------------------------------- nft 路径 */

static bool rr_nft(bool add, const reply_route_opts *o, const char *in_if,
		   uint32_t mark, char *err, size_t errsz)
{
	char marks[16];
	char vtun[128];
	char *tbl[] = { "nft", add ? "add" : "delete", "table", "inet",
			"iwan_reply", NULL };
	char *chk[] = { "nft", "add", "chain", "inet", "iwan_reply", "pre",
			"{", "type", "filter", "hook", "prerouting",
			"priority", "mangle;", "}", NULL };
	char *cho[] = { "nft", "add", "chain", "inet", "iwan_reply", "out",
			"{", "type", "filter", "hook", "output",
			"priority", "mangle;", "}", NULL };
	size_t i;

	if (!add) {
		rr_run(tbl, "nft delete table inet iwan_reply");
		return true;
	}
	snprintf(marks, sizeof(marks), "0x%x", mark);
	snprintf(vtun, sizeof(vtun), "%s", in_if);
	rr_run(tbl, "nft add table inet iwan_reply");
	if (!rr_run(chk, "nft add chain pre")) {
		snprintf(err, errsz, "nft 建 prerouting 链失败（nft 可用？）");
		return false;
	}
	if (!rr_run(cho, "nft add chain out")) {
		snprintf(err, errsz, "nft 建 output 链失败");
		return false;
	}
	for (i = 0; i < rr_n_served(o); i++) {
		/* ip|ip6 daddr <集合元素>：同一张 inet 表里两族都能写 */
		char *r[] = { "nft", "add", "rule", "inet", "iwan_reply", "pre",
			      "iifname", vtun,
			      rr_is_v6(rr_served_at(o, i)) ? "ip6" : "ip", "daddr",
			      (char *)rr_served_at(o, i),
			      "ct", "mark", "set", marks, NULL };

		if (!rr_run(r, "nft add rule pre（被服务地址）")) {
			snprintf(err, errsz,
				 "nft 装 prerouting 规则失败（地址 %s）",
				 rr_served_at(o, i));
			return false;
		}
	}
	{
		char *r[] = { "nft", "add", "rule", "inet", "iwan_reply", "out",
			      "ct", "mark", marks, "meta", "mark", "set", marks,
			      NULL };

		if (!rr_run(r, "nft add rule out（还原标记）")) {
			snprintf(err, errsz, "nft 装 output 还原规则失败");
			return false;
		}
	}
	return true;
}

/* ----------------------------------------------------------- iptables 路径 */

static bool rr_ipt(bool add, const reply_route_opts *o, const char *in_if,
		   uint32_t mark, char *err, size_t errsz)
{
	char marks[32];
	char vtun[128];
	char *restore[] = { "iptables", "-t", "mangle", add ? "-A" : "-D",
			    "OUTPUT", "-j", "CONNMARK", "--restore-mark", NULL };
	size_t i;

	snprintf(marks, sizeof(marks), "0x%x", mark);
	snprintf(vtun, sizeof(vtun), "%s", in_if);
	if (!rr_run(restore, "iptables CONNMARK --restore-mark")) {
		if (add) {
			snprintf(err, errsz,
				 "iptables 装 OUTPUT 还原规则失败（iptable_mangle/"
				 "xt_connmark 加载了吗？）");
			return false;
		}
	}
	if (!add)
		return true;
	for (i = 0; i < rr_n_served(o); i++) {
		char *r[] = { rr_is_v6(rr_served_at(o, i)) ? "ip6tables" : "iptables",
			      "-t", "mangle", "-A", "PREROUTING",
			      "-i", vtun, "-d", (char *)rr_served_at(o, i),
			      "-j", "CONNMARK", "--set-mark", marks, NULL };

		if (!rr_run(r, "iptables CONNMARK --set-mark（被服务地址）")) {
			snprintf(err, errsz,
				 "iptables 装 PREROUTING 标记规则失败（地址 %s）",
				 rr_served_at(o, i));
			return false;
		}
	}
	return true;
}

/* ------------------------------------------------------- ip rule / ip route */

/* 是否至少有一个 v6 被服务地址（决定要不要装 v6 的 rule/表）。 */
static bool rr_any_v6(const reply_route_opts *o)
{
	size_t i;

	for (i = 0; i < rr_n_served(o); i++)
		if (rr_is_v6(rr_served_at(o, i)))
			return true;
	return false;
}

static bool rr_ip(bool add, const reply_route_opts *o, uint32_t mark,
		  uint32_t table, bool v6, char *err, size_t errsz)
{
	char ms[16], ts[16];
	const char *fw = add ? "add" : "del";
	/* 两族各一份 argv：**不能**把可空的 "-6" 放进 argv 里占位 ——
	 * execvp 在第一个 NULL 处截断，v4 时会变成执行不带参数的 `ip`
	 * （打出 usage 就算失败），这是"装了半个再回滚"的现场根因。 */
	char *rule4[] = { "ip", "rule", (char *)fw,
			  "fwmark", ms, "lookup", ts, "pref", "1000", NULL };
	char *rule6[] = { "ip", "-6", "rule", (char *)fw,
			  "fwmark", ms, "lookup", ts, "pref", "1000", NULL };
	char *rt4[] = { "ip", "route", (char *)fw,
			"default", "dev", (char *)o->tun, "table", ts, NULL };
	char *rt6[] = { "ip", "-6", "route", (char *)fw,
			"default", "dev", (char *)o->tun, "table", ts, NULL };
	char **rule = v6 ? rule6 : rule4;
	char **rt = v6 ? rt6 : rt4;

	snprintf(ms, sizeof(ms), "0x%x", mark);
	snprintf(ts, sizeof(ts), "%u", (unsigned)table);
	if (!rr_run(rule, add ? "ip rule add fwmark" : "ip rule del fwmark")) {
		if (add) {
			snprintf(err, errsz,
				 "装 ip%s rule（fwmark 0x%x → 表 %u）失败",
				 v6 ? " -6" : "", mark, (unsigned)table);
			return false;
		}
	}
	if (!rr_run(rt, add ? "ip route add default table" :
			      "ip route del default table")) {
		if (add) {
			snprintf(err, errsz,
				 "装 ip%s route（表 %u 的 default dev %s）失败",
				 v6 ? " -6" : "", (unsigned)table, o->tun);
			return false;
		}
	}
	return true;
}

/* ------------------------------------------------------------------ 对外 */

bool reply_route_setup(const reply_route_opts *o, reply_route_state *st,
		       char *err, size_t errsz)
{
	const char *in_if = o->in_if ? o->in_if : o->tun;
	bool v6 = rr_any_v6(o);

	memset(st, 0, sizeof(*st));
	st->o = *o;
	st->mark = rr_mark(o);
	st->table = rr_table(o);
	st->v6 = v6;

	/* 幂等：先清掉同名残留（nft 整表 / iptables 按规则描述删 / rule+route） */
	if (rr_run((char *[]) { "nft", "--version", NULL }, "nft --version")) {
		st->nft = true;
		rr_nft(false, o, in_if, st->mark, err, errsz);
	} else {
		st->nft = false;
		rr_ipt(false, o, in_if, st->mark, err, errsz);
	}
	rr_ip(false, o, st->mark, st->table, false, err, errsz);
	if (v6)
		rr_ip(false, o, st->mark, st->table, true, err, errsz);

	if (st->nft) {
		if (!rr_nft(true, o, in_if, st->mark, err, errsz))
			goto fail;
	} else {
		if (!rr_ipt(true, o, in_if, st->mark, err, errsz))
			goto fail;
	}
	if (!rr_ip(true, o, st->mark, st->table, false, err, errsz))
		goto fail;
	if (v6 && !rr_ip(true, o, st->mark, st->table, true, err, errsz))
		goto fail;

	st->installed = true;
	log_info("回程路由: 已开（conntrack 标记 -i %s -d <%zu 个被服务地址>"
		 " → fwmark 0x%x → 表 %u 的 default dev %s，%s）",
		 in_if, rr_n_served(o), st->mark, (unsigned)st->table, o->tun,
		 st->nft ? "nft" : "iptables");
	return true;

fail:
	log_err("回程路由: %s；回滚已装的部分", err);
	reply_route_teardown(st);
	return false;
}

void reply_route_teardown(reply_route_state *st)
{
	const reply_route_opts *o = &st->o;
	const char *in_if;
	char err[128];

	if (o == NULL)
		return;
	in_if = o->in_if ? o->in_if : o->tun;
	memset(err, 0, sizeof(err));

	if (st->installed) {
		if (st->v6)
			rr_ip(false, o, st->mark, st->table, true,
			      err, sizeof(err));
		rr_ip(false, o, st->mark, st->table, false, err, sizeof(err));
		if (st->nft)
			rr_nft(false, o, in_if, st->mark, err, sizeof(err));
		else
			rr_ipt(false, o, in_if, st->mark, err, sizeof(err));
		log_info("回程路由: 已回滚（rule/表 %u/%s 都按自己装过的删）",
			 (unsigned)st->table,
			 st->nft ? "nft 表" : "iptables 规则");
	}
	st->installed = false;
}
