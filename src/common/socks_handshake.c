#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "socks_handshake.h"
#include "socks_auth_guard.h"
#include "socks_dns.h"
#include "addr.h"
#include "ipv4.h"
#include "port.h"
#include "protocol.h"
#include "util.h"

void socks_reply(Flow *f, uint8_t rep, uint32_t bnd_ip,
                        uint16_t bnd_port)
{
    uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    r[4] = (uint8_t)(bnd_ip >> 24);
    r[5] = (uint8_t)(bnd_ip >> 16);
    r[6] = (uint8_t)(bnd_ip >> 8);
    r[7] = (uint8_t)bnd_ip;
    r[8] = (uint8_t)(bnd_port >> 8);
    r[9] = (uint8_t)bnd_port;
    queue_flow_output(f, r, sizeof r);
}

void socks_reply6(Flow *f, uint8_t rep, const uint8_t bnd6[16],
                         uint16_t bnd_port)
{
    uint8_t r[22] = {5, rep, 0, 4};
    memcpy(r + 4, bnd6, 16);
    r[20] = (uint8_t)(bnd_port >> 8);
    r[21] = (uint8_t)bnd_port;
    queue_flow_output(f, r, sizeof r);
}

static bool socks_ssrf_off(void)
{
    static int off = -1;
    if (off < 0) {
        const char *v = getenv("IWAN_SOCKS_ALLOW_LOOPBACK");
        off = v && strcmp(v, "1") == 0;
    }
    return off;
}

static bool socks_peer_is_loopback(const Flow *f)
{
    return (f->peer_ip & htonl(0xFF000000u)) == htonl(0x7F000000u);
}

static bool socks_target_blocked(const Flow *f, int af, const uint8_t *p)
{
    if (socks_ssrf_off() || socks_peer_is_loopback(f))
        return false;
    if (af == 4)
        return p[0] == 0 ||
               p[0] == 127 ||
               (p[0] == 169 && p[1] == 254);
    if (af == 6) {
        static const uint8_t lo[16] = {
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 };
        static const uint8_t unspec[16] = { 0 };
        static const uint8_t v4map[12] = {
            0,0,0,0,0,0,0,0, 0,0,0xff,0xff };
        if (memcmp(p, lo, 16) == 0)
            return true;
        if (memcmp(p, unspec, 16) == 0)
            return true;
        if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
            return true;
        if (memcmp(p, v4map, 12) == 0)
            return p[12] == 0 ||
                   p[12] == 127 ||
                   (p[12] == 169 && p[13] == 254);
    }
    return false;
}

bool flow_open_gated(Flow *f, int af, uint32_t rip,
                     const uint8_t rip6[16], uint16_t port)
{
    uint8_t b4[4];
    if (af == 6) {
        if (socks_target_blocked(f, 6, rip6)) {
            queue_socks_error(f, 2);
            return false;
        }
        open_tcp_connection6(f, rip6, port);
    } else {
        u32_ip4(rip, b4);
        if (socks_target_blocked(f, 4, b4)) {
            queue_socks_error(f, 2);
            return false;
        }
        open_tcp_connection(f, rip, port);
    }
    return true;
}

static void auth_reject(Flow *f)
{
    uint8_t r[2] = {1, 1};
    queue_flow_output(f, r, 2);
    set_flow_state(f, ST_CLOSING);
}

static void greet_reject(Flow *f)
{
    uint8_t r[2] = {5, 0xff};
    char ipbuf[INET_ADDRSTRLEN] = "";
    if (g_socks_cfg && g_socks_cfg->auth_token) {
        static _Atomic uint64_t last_greet_reject_ms;
        uint64_t gr_now = now_ms();
        if (gr_now - atomic_load_explicit(&last_greet_reject_ms,
                                          memory_order_relaxed) >= 1000) {
            atomic_store_explicit(&last_greet_reject_ms, gr_now,
                                  memory_order_relaxed);
            inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                      ipbuf, sizeof ipbuf);
            log_err("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                    "method while auth is required",
                    (unsigned long)f->id, ipbuf, f->peer_port);
        }
    } else if (debug_enabled()) {
        static _Atomic uint64_t last_greet_reject_dbg_ms;
        uint64_t grd_now = now_ms();
        if (grd_now - atomic_load_explicit(&last_greet_reject_dbg_ms,
                                           memory_order_relaxed) >= 1000) {
            atomic_store_explicit(&last_greet_reject_dbg_ms, grd_now,
                                  memory_order_relaxed);
            inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                      ipbuf, sizeof ipbuf);
            log_debug("[flow %lu] SOCKS5 client %s:%u offered no acceptable "
                      "method", (unsigned long)f->id, ipbuf, f->peer_port);
        }
    }
    queue_flow_output(f, r, 2);
    set_flow_state(f, ST_CLOSING);
}

void flow_start_target(Flow *f, const pp_target *t)
{
    if (t->af == 4) {
        f->target_af = 4;
        flow_open_gated(f, 4, ntohl(t->ip4), NULL, t->port);
    } else if (t->af == 6) {
        if (!(g_socks_cfg && g_socks_cfg->ipv6)) {
            queue_socks_error(f, 8);
            return;
        }
        f->target_af = 6;
        flow_open_gated(f, 6, 0, t->ip6, t->port);
    } else {
        f->target_af = 0;
        set_flow_state(f, ST_RESOLVING);
        spawn_dns((int)f->id, t->host, t->port);
    }
}

static void http_handshake(Flow *f)
{
    uint8_t *d = f->input.data;
    size_t n = f->input.len;
    size_t hdr, eol, mn, ts;
    pp_target t;

    {
        size_t start = f->http_scan_off;
        if (start < 3 || start > n)
            start = 3;
        for (hdr = start; hdr < n; hdr++) {
            if (d[hdr - 3] == '\r' && d[hdr - 2] == '\n' &&
                d[hdr - 1] == '\r' && d[hdr] == '\n')
                break;
        }
    }
    if (hdr >= n) {
        f->http_scan_off = n >= 3 ? n - 3 : 0;
        return;
    }
    hdr += 1;
    for (eol = 0; eol < n && d[eol] != '\r' && d[eol] != '\n'; eol++)
        ;
    for (mn = 0; mn < eol && d[mn] != ' '; mn++)
        ;
    if (mn == 0 || mn >= eol)
        goto bad;
    f->http_connect = (mn == 7 && memcmp(d, "CONNECT", 7) == 0);
    for (ts = mn + 1; ts < eol && d[ts] == ' '; ts++)
        ;
    if (ts >= eol)
        goto bad;
    if (pp_http_target((const char *)d + ts, eol - ts, f->http_connect,
                       &t) != 0)
        goto bad;
    if (f->http_connect)
        buf_consume(&f->input, hdr);
    flow_start_target(f, &t);
    return;
bad:
    queue_socks_error(f, 5);
}

static bool handshake_greeting(Flow *f)
{
    if (!f->auth_pending) {
        const char *tok = g_socks_cfg ? g_socks_cfg->auth_token : NULL;
        if (f->input.len < 2)
            return false;
        if (f->input.data[0] != 5 &&
            (!g_socks_cfg || !g_socks_cfg->auth_token)) {
            int pr = pp_http_probe(f->input.data, f->input.len);
            if (pr == 1) {
                f->http_mode = true;
                http_handshake(f);
                return false;
            }
            if (pr == -1)
                return false;
        }
        uint8_t method = 0;
        if (f->input.data[0] != 5) {
            greet_reject(f);
            return false;
        }
        if (pp_socks_greeting(f->input.data, f->input.len, tok != NULL,
                              &method) != 0)
            return false;
        method = pp_socks_pick_method(tok != NULL, method);
        if (method == 0xff) {
            greet_reject(f);
            return false;
        }
        {
            size_t nm = 2 + (size_t)f->input.data[1];
            buf_consume(&f->input, nm);
        }
        if (method == 2) {
            uint8_t ok[2] = {5, 2};
            queue_flow_output(f, ok, 2);
            f->auth_pending = true;
            return false;
        }
        uint8_t ok[2] = {5, 0};
        queue_flow_output(f, ok, 2);
        set_flow_state(f, ST_REQUEST);
        return true;
    }

    char ipbuf[INET_ADDRSTRLEN] = "";
    char user[64];
    const uint8_t *pass;
    size_t plen;
    int pr = pp_socks_auth_frame(f->input.data, f->input.len, user,
                                 sizeof user, &pass, &plen);
    if (pr < 0)
        return false;
    if (pr == 0 || pr == 2) {
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_debug("[flow %lu] RFC1929 auth frame malformed "
                  "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);
        return false;
    }
    const char *tok = g_socks_cfg ? g_socks_cfg->auth_token : NULL;
    bool ok = pp_socks_auth_ok(pass, plen, tok);
    {
        size_t nm = 2 + (size_t)f->input.data[1] + 1 + plen;
        buf_consume(&f->input, nm);
    }
    f->auth_pending = false;
    if (!ok) {
        auth_fail_note(f->peer_ip, false);
        inet_ntop(AF_INET, &(struct in_addr){ .s_addr = f->peer_ip },
                  ipbuf, sizeof ipbuf);
        log_err("[flow %lu] SOCKS5 RFC1929 auth failed (wrong password) "
                "from %s:%u", (unsigned long)f->id, ipbuf, f->peer_port);
        auth_reject(f);
        return false;
    }
    auth_fail_note(f->peer_ip, true);
    uint8_t okr[2] = {1, 0};
    queue_flow_output(f, okr, 2);
    set_flow_state(f, ST_REQUEST);
    return true;
}

static void handshake_request(Flow *f)
{
    uint8_t cmd, rep;
    pp_target t;

    if (pp_socks_request(f->input.data, f->input.len, &cmd, &rep, &t) != 0)
        return;
    if (rep != 0) {
        queue_socks_error(f, rep);
        return;
    }
    if (t.af == 4) {
        buf_consume(&f->input, 10);
        flow_start_target(f, &t);
        return;
    }
    if (t.af == 6) {
        buf_consume(&f->input, 22);
        flow_start_target(f, &t);
        return;
    }
    {
        size_t dlen = (size_t)f->input.data[4];
        size_t req_len = 5 + dlen + 2;
        buf_consume(&f->input, req_len);
        flow_start_target(f, &t);
        return;
    }
}

void process_socks_handshake(Flow *f)
{
    for (int pass = 0; pass < 3; pass++) {
        if (f->state != ST_GREETING && f->state != ST_REQUEST)
            return;
        if (f->state == ST_GREETING) {
            if (f->http_mode) {
                http_handshake(f);
                return;
            }
            size_t before = f->input.len;
            if (handshake_greeting(f)) {
                if (f->state == ST_REQUEST && f->input.len > 0)
                    continue;
                return;
            }
            if (f->input.len >= before)
                return;
            continue;
        }
        handshake_request(f);
        return;
    }
}
