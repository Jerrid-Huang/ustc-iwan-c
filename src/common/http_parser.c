#include "http_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "port.h"
#include "util.h"

static size_t https_utf8_seq(const char *in, size_t avail)
{
    unsigned char c = (unsigned char)in[0];
    size_t len;
    unsigned char lo = 0x80, hi = 0xBF;

    if (c >= 0xC2 && c <= 0xDF)
        len = 2;
    else if (c >= 0xE0 && c <= 0xEF) {
        len = 3;
        if (c == 0xE0)      lo = 0xA0;
        else if (c == 0xED) hi = 0x9F;
    } else if (c >= 0xF0 && c <= 0xF4) {
        len = 4;
        if (c == 0xF0)      lo = 0x90;
        else if (c == 0xF4) hi = 0x8F;
    } else
        return 0;

    if (avail < 2 || ((unsigned char)in[1] & 0xC0) != 0x80)
        return 0;
    if ((unsigned char)in[1] < lo || (unsigned char)in[1] > hi)
        return 0;
    if (len >= 3 && (avail < 3 || ((unsigned char)in[2] & 0xC0) != 0x80))
        return 0;
    if (len >= 4 && (avail < 4 || ((unsigned char)in[3] & 0xC0) != 0x80))
        return 0;
    return len;
}

void https_log_san(const char *in, size_t inlen, char out[], size_t outsz)
{
    size_t budget, i = 0, n = 0;

    if (outsz == 0)
        return;
    budget = (outsz > 4) ? outsz - 4 : 0;
    while (n < inlen && i < budget) {
        unsigned char c = (unsigned char)in[n];
        size_t seq = https_utf8_seq(in + n, inlen - n);

        if (seq >= 2) {
            if (i + seq > budget)
                break;
            if (seq == 2 && c == 0xC2 &&
                (unsigned char)in[n + 1] >= 0x80 &&
                (unsigned char)in[n + 1] <= 0x9F) {
                out[i++] = '?';
                n += seq;
                continue;
            }
            memcpy(out + i, in + n, seq);
            i += seq;
            n += seq;
            continue;
        }
        if (c == 0 || c < 0x20 || c >= 0x7f)
            c = '?';
        out[i++] = (char)c;
        n++;
    }
    if (n < inlen && outsz >= 4) {
        memcpy(out + i, "...", 3);
        i += 3;
    }
    out[i] = '\0';
}

long hex_parse_sz(const char *s, size_t n)
{
    long v = 0;
    for (size_t i = 0; i < n; i++) {
        int h = hex_nibble(s[i]);
        if (h < 0)
            return -1;
        if (v > (HTTPS_CHUNK_SZ_CAP - h) / 16)
            return -1;
        v = v * 16 + h;
    }
    return v;
}

int chunk_decode(const char *in, size_t in_len, struct sbuf *out,
                 char *err, size_t errsz)
{
    size_t i = 0;
    int saw_terminal = 0;
    while (i < in_len) {
        size_t j = i;
        long sz;
        while (j < in_len && in[j] != '\r' && in[j] != '\n' && in[j] != ';')
            j++;
        sz = hex_parse_sz(in + i, j - i);
        if (sz < 0) {
            snprintf(err, errsz, "bad chunk size at offset %llu",
                   (unsigned long long)i);
            return 0;
        }
        while (j < in_len && in[j] != '\r' && in[j] != '\n')
            j++;
        while (j < in_len && (in[j] == '\r' || in[j] == '\n'))
            j++;
        if (sz == 0) {
            saw_terminal = 1;
            break;
        }
        if ((size_t)sz > in_len - j) {
            snprintf(err, errsz, "chunk overruns body at offset %llu",
                   (unsigned long long)i);
            return 0;
        }
        sbuf_app(out, in + j, (size_t)sz);
        j += (size_t)sz;
        while (j < in_len && (in[j] == '\r' || in[j] == '\n'))
            j++;
        i = j;
    }
    if (!saw_terminal) {
        snprintf(err, errsz, "chunked body truncated: missing terminal chunk");
        return 0;
    }
    return 1;
}

char *https_hdr_value(const char *hdr, size_t len, const char *name,
                      size_t *vlen_out)
{
    size_t nl = strlen(name);
    struct sbuf val = {0};
    const char *end = hdr + len;
    const char *line = hdr;
    int matched = 0;

    while (line < end) {
        const char *eol = memchr(line, '\n', (size_t)(end - line));
        const char *nlpos = eol ? eol : end;
        const char *next = eol ? eol + 1 : end;
        size_t llen = (size_t)(nlpos - line);
        const char *colon;
        const char *p;

        if (llen > 0 && line[llen - 1] == '\r')
            llen--;
        if (llen == 0)
            break;
        if (line[0] == ' ' || line[0] == '\t') {
            if (matched) {
                p = line;
                while (p < line + llen && (*p == ' ' || *p == '\t'))
                    p++;
                sbuf_app(&val, " ", 1);
                sbuf_app(&val, p, (size_t)(line + llen - p));
            }
            line = next;
            continue;
        }
        colon = memchr(line, ':', llen);
        if (!colon) {
            line = next;
            continue;
        }
        if ((size_t)(colon - line) == nl &&
            port_strncasecmp(line, name, nl) == 0) {
            p = colon + 1;
            while (p < line + llen && (*p == ' ' || *p == '\t'))
                p++;
            if (val.len)
                sbuf_app(&val, ", ", 2);
            sbuf_app(&val, p, (size_t)(line + llen - p));
            matched = 1;
        }
        line = next;
    }
    if (!val.len) {
        free(val.d);
        return NULL;
    }
    while (val.len > 0 &&
           (val.d[val.len - 1] == ' ' || val.d[val.len - 1] == '\t'))
        val.d[--val.len] = '\0';
    if (vlen_out)
        *vlen_out = val.len;
    return val.d;
}

int https_te_is_chunked(const char *val)
{
    static const char chunked[] = "chunked";
    const char *p = val;
    int codings = 0, ok = 0;

    for (;;) {
        const char *q;
        size_t n;

        while (*p == ' ' || *p == '\t')
            p++;
        q = strchr(p, ',');
        n = q ? (size_t)(q - p) : strlen(p);
        while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
            n--;
        if (n == 0)
            return 0;
        codings++;
        if (n == sizeof chunked - 1 &&
            port_strncasecmp(p, chunked, sizeof chunked - 1) == 0)
            ok = 1;
        else
            ok = 0;
        if (!q)
            break;
        p = q + 1;
    }
    return ok && codings == 1;
}

bool https_te_header_chunked(const char *hdrs, size_t hlen)
{
    static const char te[] = "Transfer-Encoding:";
    size_t i = 0;

    while (i < hlen) {
        size_t eol = i;
        while (eol < hlen && hdrs[eol] != '\r' && hdrs[eol] != '\n')
            eol++;
        if (eol - i >= sizeof te - 1 &&
            port_strncasecmp(hdrs + i, te, sizeof te - 1) == 0) {
            struct sbuf v = {0};
            const char *p;
            size_t vlen;
            size_t j = eol;
            bool yes = false;

            p = hdrs + i + sizeof te - 1;
            while (p < hdrs + eol && (*p == ' ' || *p == '\t'))
                p++;
            sbuf_app(&v, p, (size_t)(hdrs + eol - p));

            while (j < hlen) {
                size_t leol = j;
                const char *lp;
                if (hdrs[j] == '\r') j++;
                if (j < hlen && hdrs[j] == '\n') j++;
                if (j >= hlen || (hdrs[j] != ' ' && hdrs[j] != '\t'))
                    break;
                while (leol < hlen && hdrs[leol] != '\r' && hdrs[leol] != '\n')
                    leol++;
                lp = hdrs + j;
                while (lp < hdrs + leol && (*lp == ' ' || *lp == '\t'))
                    lp++;
                sbuf_app(&v, " ", 1);
                sbuf_app(&v, lp, (size_t)(hdrs + leol - lp));
                j = leol;
            }

            vlen = v.len;
            while (vlen > 0 &&
                   (v.d[vlen - 1] == ' ' || v.d[vlen - 1] == '\t'))
                vlen--;
            if (v.d)
                v.d[vlen] = '\0';

            if (v.d) {
                const char *cur = v.d;
                for (;;) {
                    const char *q = strchr(cur, ',');
                    size_t n = q ? (size_t)(q - cur) : strlen(cur);
                    const char *elem = cur;
                    while (n > 0 && (*elem == ' ' || *elem == '\t')) {
                        elem++;
                        n--;
                    }
                    while (n > 0 && (elem[n - 1] == ' ' || elem[n - 1] == '\t'))
                        n--;
                    {
                        size_t semi = 0;
                        while (semi < n && elem[semi] != ';')
                            semi++;
                        while (semi > 0 && (elem[semi - 1] == ' ' || elem[semi - 1] == '\t'))
                            semi--;
                        if (semi == sizeof "chunked" - 1 &&
                            port_strncasecmp(elem, "chunked", sizeof "chunked" - 1) == 0) {
                            yes = true;
                            break;
                        }
                    }
                    if (!q)
                        break;
                    cur = q + 1;
                }
            }
            free(v.d);
            if (yes)
                return true;
        }
        i = eol;
        while (i < hlen && (hdrs[i] == '\r' || hdrs[i] == '\n'))
            i++;
    }
    return false;
}

bool http_ctrl_in(const char *s, size_t n)
{
    if (!s)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f)
            return true;
    }
    return false;
}

int https_url_split(const char *url, char **host_out, char **path_out)
{
    static const char scheme[] = "https://";
    const char *auth, *slash, *cut, *frag;
    size_t alen, plen;

    if (port_strncasecmp(url, scheme, sizeof scheme - 1) != 0)
        return 0;
    auth = url + sizeof scheme - 1;
    slash = strchr(auth, '/');
    cut = slash ? slash : auth + strlen(auth);
    {
        const char *q = strchr(auth, '?');
        const char *h = strchr(auth, '#');
        if (q && q < cut)
            cut = q;
        if (h && h < cut)
            cut = h;
    }
    alen = (size_t)(cut - auth);
    if (alen == 0)
        return 0;
    if (memchr(auth, '@', alen))
        return 0;
    if (memchr(auth, ':', alen))
        return 0;
    if (http_ctrl_in(auth, alen))
        return 0;
    if (slash) {
        frag = strchr(slash, '#');
        plen = frag ? (size_t)(frag - slash) : strlen(slash);
        if (http_ctrl_in(slash, plen))
            return 0;
    } else {
        plen = 0;
    }
    *host_out = malloc(alen + 1);
    if (!*host_out)
        oom_abort();
    memcpy(*host_out, auth, alen);
    (*host_out)[alen] = '\0';
    if (slash) {
        char *p = malloc(plen + 1);
        if (!p)
            oom_abort();
        memcpy(p, slash, plen);
        p[plen] = '\0';
        *path_out = p;
    } else {
        *path_out = xstrdup("/");
    }
    return 1;
}

int https_req_build(struct sbuf *req, const char *host,
                    const char *path, const char *body,
                    const char *const *headers, bool is_get)
{
    char cl[64];

    if (http_ctrl_in(path, strlen(path))) {
        log_err("HTTPS request refused: control character in the request path");
        return 0;
    }
    if (http_ctrl_in(host, strlen(host))) {
        log_err("HTTPS request refused: control character in the host name");
        return 0;
    }
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            if (http_ctrl_in(headers[i], strlen(headers[i]))) {
                log_err("HTTPS request refused: control character in a request header");
                return 0;
            }
        }
    }
    if (!body)
        body = "";
    snprintf(cl, sizeof cl, "Content-Length: %llu",
             (unsigned long long)strlen(body));
    sbuf_app(req, is_get ? "GET " : "POST ",
             is_get ? sizeof "GET " - 1 : sizeof "POST " - 1);
    sbuf_app(req, path, strlen(path));
    sbuf_app(req, " HTTP/1.1\r\nHost: ", sizeof " HTTP/1.1\r\nHost: " - 1);
    sbuf_app(req, host, strlen(host));
    sbuf_app(req, "\r\nConnection: close\r\n",
             sizeof "\r\nConnection: close\r\n" - 1);
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            sbuf_app(req, headers[i], strlen(headers[i]));
            sbuf_app(req, "\r\n", 2);
        }
    }
    if (!is_get) {
        sbuf_app(req, cl, strlen(cl));
        sbuf_app(req, "\r\n", 2);
    }
    sbuf_app(req, "\r\n", 2);
    if (!is_get)
        sbuf_app(req, body, strlen(body));
    return 1;
}

long long https_content_length(const char *hdrs, size_t hlen)
{
    size_t i = 0;
    while (i < hlen) {
        size_t eol = i;
        while (eol < hlen && hdrs[eol] != '\r' && hdrs[eol] != '\n')
            eol++;
        size_t llen = eol - i;
        if (llen >= 15 &&
            port_strncasecmp(hdrs + i, "Content-Length:", 15) == 0) {
            size_t j = i + 15;
            while (j < eol && (hdrs[j] == ' ' || hdrs[j] == '\t'))
                j++;
            long long v = 0;
            for (; j < eol; j++) {
                if (hdrs[j] < '0' || hdrs[j] > '9')
                    return -1;
                v = v * 10 + (long long)(hdrs[j] - '0');
                if (v > (long long)HTTPS_MAX_RESP)
                    return -1;
            }
            return v;
        }
        i = eol;
        while (i < hlen && (hdrs[i] == '\r' || hdrs[i] == '\n'))
            i++;
    }
    return -1;
}

const char *sbuf_find(const char *hay, size_t hlen,
                      const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen)
        return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    return NULL;
}

void https_hdr_body(const char *d, size_t len,
                    const char **hdr_start, const char **body)
{
    const char *term = strstr(d, "\r\n\r\n");
    size_t tlen = 4;
    const char *eol;

    if (!term) {
        term = strstr(d, "\n\n");
        tlen = 2;
    }
    if (!term) {
        eol = memchr(d, '\n', len);
        *hdr_start = eol ? eol + 1 : d;
        *body = d + len;
        return;
    }
    eol = memchr(d, '\n', (size_t)(term - d));
    *hdr_start = eol ? eol + 1 : term;
    *body = term + tlen;
}

int https_resp_status(const char *d, size_t len)
{
    const char *p = d, *end = d + len, *sp;
    char *endp;
    long code;

    while (p < end && (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t'))
        p++;
    if ((size_t)(end - p) < 7 || strncmp(p, "HTTP/1.", 7) != 0)
        return -1;
    sp = memchr(p, ' ', (size_t)(end - p));
    if (!sp)
        return -1;
    code = strtol(sp + 1, &endp, 10);
    if (endp == sp + 1 || code < 100 || code > 999)
        return -1;
    return (int)code;
}

int https_resp_parse(struct sbuf *resp, int *status, char **body_out)
{
    const char *hdr_start, *body;
    size_t hdr_len;
    int chunked = 0;
    char *out, *te;
    size_t te_len = 0;

    free(*body_out);
    *body_out = NULL;

    *status = https_resp_status(resp->d, resp->len);
    if (*status < 0) {
        free(resp->d);
        *body_out = xstrdup("");
        return 0;
    }

    https_hdr_body(resp->d, resp->len, &hdr_start, &body);
    hdr_len = (body > hdr_start) ? (size_t)(body - hdr_start) : 0;
    te = https_hdr_value(hdr_start, hdr_len, "transfer-encoding", &te_len);
    if (te) {
        if (!https_te_is_chunked(te)) {
            char san[HTTPS_LOG_SAN_MAX];
            https_log_san(te, te_len, san, sizeof san);
            log_err("unsupported Transfer-Encoding: %s", san);
            free(te);
            free(resp->d);
            *body_out = xstrdup("");
            return 0;
        }
        chunked = 1;
        free(te);
    }

    if (chunked) {
        struct sbuf dec = {0};
        char err[128];
        if (!chunk_decode(body, resp->len - (size_t)(body - resp->d), &dec,
                          err, sizeof err)) {
            log_err("malformed chunked response: %s", err);
            free(dec.d);
            free(resp->d);
            *body_out = xstrdup("");
            return 0;
        }
        out = dec.d ? dec.d : xstrdup("");
    } else {
        size_t tail = resp->len - (size_t)(body - resp->d);
        long long cl = https_content_length(hdr_start, hdr_len);
        size_t blen;

        if (cl < 0) {
            blen = tail;
        } else if ((unsigned long long)tail < (unsigned long long)cl) {
            log_err("HTTPS: response body truncated (%llu of %lld bytes)",
                    (unsigned long long)tail, cl);
            free(resp->d);
            *body_out = xstrdup("");
            return 0;
        } else {
            blen = (size_t)cl;
        }
        out = malloc(blen + 1);
        if (!out)
            oom_abort();
        memcpy(out, body, blen);
        out[blen] = '\0';
    }
    free(resp->d);
    *body_out = out;
    return 1;
}
