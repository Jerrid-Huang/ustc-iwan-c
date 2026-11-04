/*
 * Reply route implementation: conntrack (CONNMARK) + fwmark policy routing.
 * For design and tradeoffs see docs/reply-routing.md; for interface semantics see reply_route.h.
 *
 * All commands go through port_run_cmd (without a shell); arguments are passed one by one in argv, so characters in addresses/interface names
 * are not interpreted. When installing rules, same-named leftovers are removed first (idempotent); on failure, roll back what was
 * installed in reverse order.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "port.h"
#include "reply_route.h"
#include "util.h"

#define RR_DEF_MARK  0x1u
#define RR_DEF_TABLE 100u
/* fwmark rule priority: lower than main(32766)/default(32767), in the same range as common ip rule
 * user rules (starting at 1000); it matches only fwmark and does not affect unmarked packets. */
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

/* Run one command; on failure only log debug (the caller decides whether it is fatal). */
static bool rr_run(char *const argv[], const char *what)
{
	(void)what;	/* in release builds log_debug is compiled out; keep the parameter from becoming unused */
	if (port_run_cmd(argv) == 0)
		return true;
	log_debug("reply route: %s did not succeed (it may simply not exist)", what);
	return false;
}

/* Read /sys/module/iwan/parameters/<name>; returns true on success. */
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
		snprintf(why, whysz, "reply route needs a tunnel interface name (iwan0 on the kernel plane)");
		return false;
	}
	if (rr_n_served(o) == 0) {
		snprintf(why, whysz,
			 "reply route needs the \"served address set\", but none was given this round: "
			 "at least one --proxy-cidr/--proxy-ip/--proxy-domain is required "
			 "(use --proxy-cidr6 for v6) --\n  marking by ingress interface alone would push all "
			 "non-tunnel traffic on the carrier NIC into the tunnel too, so the -d half is required");
		return false;
	}
	if (!o->kernel_plane)
		return true;	/* TUN plane: inner packets re-enter via iwan0 and necessarily pass conntrack */

	/* Kernel plane: the module hook must decapsulate before conntrack(-200), or reinject=1
	 * must make packets re-enter the stack. Otherwise inner connections do not enter the conntrack table -> reply restore gets 0 ->
	 * rules silently take no effect (no error, no connectivity). */
	if (!rr_sysfs("hooknum", &hooknum) || !rr_sysfs("reinject", &reinject)) {
		snprintf(why, whysz,
			 "cannot read /sys/module/iwan/parameters/{hooknum,reinject}: "
			 "is the iwan kernel module not loaded? reply route needs it on the kernel plane");
		return false;
	}
	(void)rr_sysfs("hookprio", &hookprio);
	if (hooknum == 0 && hookprio < -200)
		ct_ok = true;
	if (reinject == 1)
		ct_ok = true;
	if (!ct_ok) {
		snprintf(why, whysz,
			 "the kernel plane module hook is not before conntrack (hooknum=%ld hookprio=%ld "
			 "reinject=%ld): decapsulated inner packets no longer pass through conntrack, "
			 "inner connections have no entry,\n  reply packets --restore-mark get 0 -- reply route rules "
			 "will **silently take no effect** (no error, but replies still use the physical NIC). Fix by choosing one:\n"
			 "    echo 0 > /sys/module/iwan/parameters/hooknum\n"
			 "    echo -300 > /sys/module/iwan/parameters/hookprio\n"
			 "  or\n"
			 "    echo 1 > /sys/module/iwan/parameters/reinject",
			 hooknum, hookprio, reinject);
		return false;
	}
	return true;
}

/* ---------------------------------------------------------------- nft path */

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
		snprintf(err, errsz, "nft failed to create the prerouting chain (is nft available?)");
		return false;
	}
	if (!rr_run(cho, "nft add chain out")) {
		snprintf(err, errsz, "nft failed to create the output chain");
		return false;
	}
	for (i = 0; i < rr_n_served(o); i++) {
		/* ip|ip6 daddr <set element>: both families can be written in the same inet table */
		char *r[] = { "nft", "add", "rule", "inet", "iwan_reply", "pre",
			      "iifname", vtun,
			      rr_is_v6(rr_served_at(o, i)) ? "ip6" : "ip", "daddr",
			      (char *)rr_served_at(o, i),
			      "ct", "mark", "set", marks, NULL };

		if (!rr_run(r, "nft add rule pre (served address)")) {
			snprintf(err, errsz,
				 "nft failed to install the prerouting rule (address %s)",
				 rr_served_at(o, i));
			return false;
		}
	}
	{
		char *r[] = { "nft", "add", "rule", "inet", "iwan_reply", "out",
			      "ct", "mark", marks, "meta", "mark", "set", marks,
			      NULL };

		if (!rr_run(r, "nft add rule out (restore mark)")) {
			snprintf(err, errsz, "nft failed to install the output restore rule");
			return false;
		}
	}
	return true;
}

/* ----------------------------------------------------------- iptables path */

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
				 "iptables failed to install the OUTPUT restore rule (is iptable_mangle/"
				 "xt_connmark loaded?)");
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

		if (!rr_run(r, "iptables CONNMARK --set-mark (served address)")) {
			snprintf(err, errsz,
				 "iptables failed to install the PREROUTING mark rule (address %s)",
				 rr_served_at(o, i));
			return false;
		}
	}
	return true;
}

/* ------------------------------------------------------- ip rule / ip route */

/* Whether there is at least one v6 served address (decides whether v6 rule/table is installed). */
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
	/* One argv per family: **never** put an optional "-6" in argv as a placeholder --
	 * execvp truncates at the first NULL, so for v4 it would run `ip` with no arguments
	 * (printing usage counts as failure); this is the root cause of the "install half then roll back" scenario. */
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
				 "failed to install ip%s rule (fwmark 0x%x -> table %u)",
				 v6 ? " -6" : "", mark, (unsigned)table);
			return false;
		}
	}
	if (!rr_run(rt, add ? "ip route add default table" :
			      "ip route del default table")) {
		if (add) {
			snprintf(err, errsz,
				 "failed to install ip%s route (table %u default dev %s)",
				 v6 ? " -6" : "", (unsigned)table, o->tun);
			return false;
		}
	}
	return true;
}

/* ------------------------------------------------------------------ public */

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

	/* Idempotent: first clear same-named leftovers (whole nft table / iptables deleted by rule description / rule+route) */
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
	log_info("reply route: enabled (conntrack mark -i %s -d <%llu served addresses>"
		 " -> fwmark 0x%x -> table %u default dev %s, %s)",
		 in_if, (unsigned long long)rr_n_served(o), st->mark,
		 (unsigned)st->table, o->tun,
		 st->nft ? "nft" : "iptables");
	return true;

fail:
	log_err("reply route: %s; rolling back installed parts", err);
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
		log_info("reply route: rolled back (rule/table %u/%s deleted per what we installed)",
			 (unsigned)st->table,
			 st->nft ? "nft table" : "iptables rules");
	}
	st->installed = false;
}
