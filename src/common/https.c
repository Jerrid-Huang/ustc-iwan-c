#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/tcp.h>   /* TCP_NODELAY (E3) */
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>   /* OPENSSL_cleanse (L-7): wipe Bearer/token */
#ifdef _WIN32
#  include <wincrypt.h>
#endif

#include "common.h"
#include "https.h"
#include "util.h"

/* hard ceilings for one response read: whole-transfer size and the whole
 * round-trip time (redirect hops included), plus the per-op socket
 * timeout cap used to enforce them */
#define HTTPS_POLL_MS       25000
#define HTTPS_TIMEOUT_MS    60000
#define HTTPS_MAX_RESP      (16u * 1024 * 1024)
#define HTTPS_MAX_REDIRECTS 5
#define HTTPS_READ_CHUNK    4096    /* SSL_read granularity */
/* chunk-size ceiling in Transfer-Encoding: chunked (the on-wire length
 * is hex; anything above INT_MAX is rejected as absurd) */
#define HTTPS_CHUNK_SZ_CAP  0x7FFFFFFFL

/* sbuf/sbuf_app come from util.h (single shared definition). The local
 * copy that used to live here carried the gcc noinline/-Wrestrict
 * workarounds for riscv64/i686 musl cross builds; those attributes now
 * live on the shared implementation in util.c. */

/* R38-C4-4: remaining milliseconds until `deadline` from ONE clock read.
 *
 * The deadline checks used to read the clock twice — once for the
 * `now_ms() >= deadline_ms` test and again for the `deadline_ms - now_ms()`
 * subtraction. The clock can cross the deadline in between, and because both
 * values are uint64_t the subtraction then UNDERFLOWS to ~1.8e19, which is
 * armed as SO_RCVTIMEO/SO_SNDTIMEO (and, at the poll site, truncated to a
 * negative int). Measured effect: a single connect blocking ~25 s instead of
 * the configured timeout, i.e. far past HTTPS_TIMEOUT_MS. One read removes
 * the window by construction.
 *
 * Returns 0 once the deadline has passed, and callers MUST keep their
 * `now >= deadline` test before arming a timeout: 0 means "already expired",
 * not "wait forever", and passing 0 to setsockopt would do the latter on
 * some platforms. */
static uint64_t https_remain_ms(uint64_t deadline, uint64_t *now_out)
{
    uint64_t now = now_ms();
    if (now_out != NULL)
        *now_out = now;
    return now < deadline ? deadline - now : 0;
}

static long hex_parse_sz(const char *s, size_t n)
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

/* Decode a chunked body into out. Returns 1 on success; 0 with *err set
 * when the stream is malformed (bad hex size, chunk overrunning the
 * buffer, or the body ends without a terminal zero-size chunk, i.e. a
 * truncated transfer). Trailer junk after the terminal chunk is ignored.
 * The caller reports the failure instead of silently shipping a
 * truncated body. */
static int chunk_decode(const char *in, size_t in_len, struct sbuf *out,
                        char *err, size_t errsz)
{
    size_t i = 0;
    int saw_terminal = 0;   /* 1 once a zero-size chunk has been parsed */
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
            /* terminal chunk: only trailer junk may follow; ignore it */
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

/* Locate header `name` (case-insensitive) in the header block
 * [hdr, hdr + len); returns a malloc'd trimmed value, or NULL when absent.
 * Multiple occurrences are joined with ", " (RFC 7230 §3.2.2) and obs-fold
 * continuation lines are folded into the value with a single space. */
static char *https_hdr_value(const char *hdr, size_t len, const char *name)
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
            break;   /* blank line: end of the header block */
        if (line[0] == ' ' || line[0] == '\t') {
            /* obs-fold continuation of the previous header */
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
        /* R37 WG-E2 (R3-L11): a matched header with an EMPTY value built
         * no text, but sbuf_app() already allocated the 256-byte initial
         * buffer — returning NULL here without freeing leaked it once per
         * response (remote-controlled: one "Transfer-Encoding:" line per
         * reply is enough). */
        free(val.d);
        return NULL;
    }
    /* trim trailing whitespace */
    while (val.len > 0 &&
           (val.d[val.len - 1] == ' ' || val.d[val.len - 1] == '\t'))
        val.d[--val.len] = '\0';
    return val.d;
}

/* Transfer-Encoding values are a comma-separated coding list; the body is
   only chunk-decodable when the list is exactly the single coding
   "chunked" (any other coding, e.g. gzip, is an explicit error). */
static int https_te_is_chunked(const char *val)
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
            return 0;   /* empty coding in the list: malformed */
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

/* R12 T4 (R41-1A2-1): scan a complete header block (NUL-free, len bytes)
 * for a Transfer-Encoding field whose coding list contains the "chunked"
 * token — case-insensitive, comma-separated, tolerant of the optional
 * OWS / parameters the parser below allows. This answers the FRAMING
 * question only ("is the body chunked?"); the strict single-coding
 * validation happens later in https_resp_parse, unchanged.
 *
 * RFC 7230 §3.3.3: when a message carries both Transfer-Encoding and
 * Content-Length, Transfer-Encoding overrides it (a sender that emits
 * both is buggy, but a receiver must still frame by chunked). The raw
 * read must then run to EOF/close_notify instead of stopping at the CL
 * count — CL counts DECODED payload bytes, the wire holds the chunk
 * framing on top of them, so cutting at CL truncates the chunk stream
 * and the downstream chunk_decode hard-fails ("chunked body truncated",
 * observed e.g. for CL:0 which returned at the "declared empty body"
 * check with an empty, non-chunked "body").
 *
 * R14 (R13-A4-1): obs-fold continuation lines — "Transfer-Encoding:\r\n
 * chunked" (RFC 7230 §3.2.4 old-style folding) — are folded into the
 * value exactly as the parse side already does (https_hdr_value folds
 * them, https_te_is_chunked then accepts "chunked").  Before this the
 * first line carried an empty value, so the helper answered "not
 * chunked" while the parser saw "chunked": framing (CL-count early
 * exit) and parsing (chunked, truncated) disagreed and a real chunked
 * body was cut at the bogus CL.  http_ctrl_in() does not gate this
 * path — it guards only OUTGOING request components (auth/path/host/
 * request headers) — and obs-fold in a locally-consumed response is
 * legitimate old syntax, so there is no CRLF conflict: this is purely
 * folding, the value itself never reaches the wire. */
static bool https_te_header_chunked(const char *hdrs, size_t hlen)
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

            sbuf_app(&v, hdrs + i + sizeof te - 1,
                     eol - (i + sizeof te - 1));
            /* obs-fold continuation lines (RFC 7230 §3.2.4): a line that
             * starts with SP/TAB continues the previous field.  Fold each
             * trimmed fragment after one space, exactly as https_hdr_value
             * does, so framing and parsing agree.  Like that parser, an
             * empty line (end of the header block) or a normal field line
             * terminates the fold. */
            if (j < hlen && hdrs[j] == '\r')
                j++;             /* consume exactly the TE line CRLF... */
            if (j < hlen && hdrs[j] == '\n')
                j++;             /* ...so a following blank line survives */
            for (;;) {
                size_t leol;
                if (j >= hlen)
                    break;
                leol = j;
                while (leol < hlen && hdrs[leol] != '\r' &&
                       hdrs[leol] != '\n')
                    leol++;
                if (leol == j || (hdrs[j] != ' ' && hdrs[j] != '\t'))
                    break;   /* blank line or a new field line: stop */
                p = hdrs + j;
                vlen = leol - j;
                while (vlen && (*p == ' ' || *p == '\t')) {
                    p++;
                    vlen--;
                }
                if (vlen) {
                    sbuf_app(&v, " ", 1);
                    sbuf_app(&v, p, vlen);
                }
                j = leol;
                if (j < hlen && hdrs[j] == '\r')
                    j++;
                if (j < hlen && hdrs[j] == '\n')
                    j++;
            }
            /* token scan over the (folded) value — unchanged semantics */
            p = v.d;
            vlen = v.len;
            if (p) {
                for (;;) {
                    size_t n;
                    while (vlen && (*p == ' ' || *p == '\t')) {
                        p++;
                        vlen--;
                    }
                    n = 0;
                    while (n < vlen && p[n] != ',' && p[n] != ';' &&
                           p[n] != ' ' && p[n] != '\t')
                        n++;
                    if (n == 7 && port_strncasecmp(p, "chunked", 7) == 0) {
                        yes = true;
                        break;
                    }
                    /* skip past this coding (and its ;parameters) */
                    while (vlen && *p != ',') {
                        p++;
                        vlen--;
                    }
                    if (!vlen)
                        break;
                    p++;            /* consume ',' */
                    vlen--;
                }
            }
            free(v.d);
            return yes;
        }
        i = eol;
        while (i < hlen && (hdrs[i] == '\r' || hdrs[i] == '\n'))
            i++;
    }
    return false;
}

/* R10: true when the n bytes at s contain a byte that must never reach the
   wire verbatim inside a request line or a header field. CR and LF are the
   classic request-splitting/header-injection vector (RFC 7230 3.2.4: a
   request target and a field value carry no bare CR or LF); the rest of the
   C0 range and DEL are rejected by the same rule because no request target,
   hostname or header value produced by this program contains them, and one
   uniform rule is easier to keep true than a blacklist. TAB is deliberately
   included: RFC 7230 tolerates it only as optional whitespace around a field
   value, the request target allows no TAB at all, and every caller here
   passes base64url tokens / hostnames / paths, none of which need it.
   The data comes from remote input: the Authorization value is built from
   the token endpoint's access_token, and path/host come from jwks_uri and
   from redirect Location headers, where a JSON "\u000d"/"\u000a" escape
   decodes to a real CR/LF (json.c:98). */
static bool http_ctrl_in(const char *s, size_t n)
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

/* Split an absolute https:// URL into malloc'd host and path. Returns 1 on
   success; 0 when the URL is not an absolute https URL (other schemes,
   userinfo, an explicit port, or a control character anywhere in the
   authority or the request target are rejected). The authority ends at the
   first '/', '?' or '#': a query must never leak into the Host header. */
int https_url_split(const char *url, char **host_out, char **path_out)
{
    static const char scheme[] = "https://";
    const char *auth, *slash, *cut, *frag;
    size_t alen, plen;

    /* strncasecmp reads exactly 8 bytes but stops at the NUL of a
     * shorter string, unlike the old per-char loop which read url[0..7]
     * unconditionally (out-of-bounds on URLs shorter than 8 bytes —
     * the URL here is attacker-influenced via the JWKS document) */
    if (port_strncasecmp(url, scheme, sizeof scheme - 1) != 0)
        return 0;
    auth = url + sizeof scheme - 1;
    slash = strchr(auth, '/');
    /* the authority ends at the first '/', '?' or '#' */
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
    /* R37 WG6 #2: userinfo is REJECTED, as https.h has always documented.
     * The old code stripped everything up to the FIRST '@' and returned
     * success (while the comment claimed "last '@'"), which made the
     * host/path split depend on which parser looks at it
     * ("https://host/x@evil/y": we see evil, a naive consumer sees host) —
     * and this URL comes from remote input (Location redirect, jwks_uri).
     * No legitimate IdP puts userinfo there, and an explicit port is
     * rejected right below for exactly the same reason. */
    if (memchr(auth, '@', alen))
        return 0;
    if (memchr(auth, ':', alen))
        return 0;   /* explicit port: unsupported */
    /* R10 (CRLF injection): reject CR/LF and the rest of the C0 range plus
     * DEL before any allocation, so a rejected URL leaves *host_out and
     * *path_out untouched (every caller frees them on failure). This is
     * remote input: jwks_uri out of the discovery document and the Location
     * header of a redirect. https_req_build() re-checks both fields, but a
     * URL that could split the request must be refused here, at the parse
     * site, while there is still a diagnostic that names the URL. */
    if (http_ctrl_in(auth, alen))
        return 0;
    if (slash) {
        /* strip the fragment from the request path ('#' and beyond);
         * the query ('?') is part of the path */
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

static char *empty_str(void)
{
    return xstrdup("");
}

/* Assemble the request (request line, headers, body) into *req.
 * is_get: GET with no Content-Length and no body; else POST.
 *
 * Returns 1 when the request was built, 0 when it was REFUSED: path, host
 * and every header are checked for control characters first, and nothing is
 * appended when one of them fails (fail closed — the caller must not send
 * the request). The values are not logged: an offending header can be the
 * "Authorization: Bearer <token>" line.
 *
 * R10 (CRLF injection): the three inputs are remote-controlled — the path
 * comes from jwks_uri / a redirect Location, the Authorization header from
 * the token endpoint's access_token — and appending them verbatim let a
 * "\r\n" inside one of them start a new header on the wire (audit probe:
 * "X-Injected-Header: pwned"). The body is NOT checked: it is written after
 * the blank line, where CR/LF is ordinary JSON content. */
static int https_req_build(struct sbuf *req, const char *host,
                           const char *path, const char *body,
                           const char *const *headers, bool is_get)
{
    char cl[64];

    if (http_ctrl_in(path, strlen(path))) {
        log_err("HTTPS request refused: control character in the request "
                "path");
        return 0;
    }
    if (http_ctrl_in(host, strlen(host))) {
        log_err("HTTPS request refused: control character in the host name");
        return 0;
    }
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            if (http_ctrl_in(headers[i], strlen(headers[i]))) {
                log_err("HTTPS request refused: control character in a "
                        "request header");
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

/* Fetch the first OpenSSL error from the queue as a single-line string
   (the queue usually holds one or two entries; the first is the most
   specific). Falls back to strerror(errno) when no SSL error is queued,
   which covers pure socket failures (ECONNREFUSED, ...). */
static void https_ssl_err(char *buf, size_t sz)
{
    unsigned long e = ERR_get_error();

    if (e != 0) {
        ERR_error_string_n(e, buf, sz);
        return;
    }
    snprintf(buf, sz, "%s", strerror(errno));
}

/* Arm SO_RCVTIMEO / SO_SNDTIMEO for the blocking socket. Every SSL
   read/write is capped at min(remaining budget, HTTPS_POLL_MS) — the
   same chunking the old poll loop used — so a dead peer surfaces as a
   timeout after at most HTTPS_POLL_MS instead of hanging the round
   trip; the caller re-checks the deadline itself around every call.
   Returns 0 on success, -1 on failure. */
static int https_set_io_timeo(int fd, int opt, uint64_t ms)
{
    struct timeval tv;

    if (ms > HTTPS_POLL_MS)
        ms = HTTPS_POLL_MS;
    /* mingw's timeval.tv_sec is a 32-bit long while time_t is 64-bit:
     * an explicit cast keeps -Wconversion quiet; the value is bounded by
     * HTTPS_POLL_MS a few lines above. */
    tv.tv_sec = (long)(ms / 1000);
    tv.tv_usec = (long)((ms % 1000) * 1000);
    return port_setsockopt(fd, SOL_SOCKET, opt, &tv, sizeof tv);
}

/* Load the CA trust anchors into ctx. Linux: SSL_CERT_FILE wins when it
   loads, otherwise (or when it does not load) the first usable bundle of
   the usual per-distro paths (the same candidates the fork-based
   transport handed to `openssl s_client -CAfile`); no usable bundle ->
   -1 (the caller decides about the embedded fallback roots). Windows:
   the system ROOT store via Crypt32. Returns 0 on success, -1 with the
   specific reason already logged. */
static int https_ctx_load_cas(SSL_CTX *ctx)
{
#ifdef _WIN32
    HCERTSTORE store;
    PCCERT_CONTEXT cert = NULL;
    X509_STORE *xstore = SSL_CTX_get_cert_store(ctx);
    int n = 0;

    /* CertOpenSystemStore opens the CURRENT_USER system store, which on
     * real Windows (fresh profiles, service accounts) can hold no roots
     * at all while the machine-wide ROOT store carries the CA trust
     * anchors. Open the machine store with the user store as fallback
     * (the combined-flag form is the standard Node/Go pattern; wine
     * only implements the single-location forms, hence the chain). */
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE |
                          CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store)
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                              CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (!store)
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");
    if (!store)
        store = CertOpenSystemStoreA(0, "ROOT");
    if (!store) {
        log_err("HTTPS: cannot open the Windows ROOT certificate store "
                "(error %lu)", (unsigned long)GetLastError());
        return -1;
    }
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
        const unsigned char *p = cert->pbCertEncoded;
        X509 *x = d2i_X509(NULL, &p, (long)cert->cbCertEncoded);

        if (x) {
            if (X509_STORE_add_cert(xstore, x) == 1)
                n++;
            X509_free(x);
        }
    }
    CertCloseStore(store, 0);
    if (n == 0) {
        log_err("HTTPS: the Windows ROOT certificate store is empty; "
                "cannot verify the server certificate");
        return -1;
    }
    log_info("HTTPS: loaded %d CA certificates from the Windows ROOT "
             "store", n);
    return 0;
#else
    /* macOS: /etc/ssl/cert.pem is a stale symlink; prefer the current
     * bundle from the Homebrew keg (the keg paths simply do not exist on
     * Linux). SSL_CERT_FILE still takes precedence over everything. */
    static const char *const cands[] = {
        "/opt/homebrew/etc/openssl@3/cert.pem",   /* macOS: Homebrew (arm64) */
        "/usr/local/etc/openssl@3/cert.pem",      /* macOS: Homebrew (x86_64) */
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/cacert.pem",
    };
    const char *ca = getenv("SSL_CERT_FILE");

    if (ca && !ca[0])
        ca = NULL;
    /* R37 WG-E2 (R3-L15): SSL_CERT_FILE still wins when it loads, but a
     * stale value must no longer discard the system trust anchors — the
     * candidate bundle paths are tried next, one by one, and only when
     * every one of them failed too does this return -1 (the caller then
     * falls back to the two embedded roots).
     *
     * R37 R5 WG-C (R4-M1): "stale" is now decided explicitly instead of
     * treating every SSL_CERT_FILE failure as stale. An explicit CA that
     * EXISTS and is READABLE but that OpenSSL cannot use (junk bytes,
     * empty file, a directory, corrupted PEM) means the operator's
     * pinned trust set is unmet; silently swapping it for the system
     * bundle turned a pinned store into the whole public WebPKI
     * (measured: 2 -> 122 anchors). That case now fails closed. Only
     * paths that cannot denote a readable file at all (ENOENT, ENOTDIR,
     * ENAMETOOLONG, ELOOP — and any other errno we did not model, e.g.
     * EACCES: default deny) fall back, which keeps the R3-L15 scenario
     * (an inherited SSL_CERT_FILE=/nonexistent) working. No verification
     * is relaxed anywhere. */
    if (ca) {
        char ebuf[256];
        int aerr;

        /* R14 (R13-B1-L2): clear the residual queue first so a failed
         * load is attributed to THIS call, not a stale SSL error. */
        ERR_clear_error();
        if (SSL_CTX_load_verify_locations(ctx, ca, NULL) == 1)
            return 0;
        https_ssl_err(ebuf, sizeof ebuf);
        log_err("HTTPS: cannot load CA bundle '%s' (SSL_CERT_FILE): %s",
                ca, ebuf);
        /* Classify with access(), not with OpenSSL's errno: measured on
         * a readable junk file OpenSSL leaves errno at 0, so errno from
         * the call above cannot tell "unreadable path" from "readable
         * but unusable bundle". */
        errno = 0;
        if (access(ca, R_OK) == 0) {
            log_err("HTTPS: SSL_CERT_FILE '%s' is readable but not a "
                    "usable CA bundle; refusing to fall back to the system "
                    "trust store (fail-closed)", ca);
            return -1;
        }
        aerr = errno;
        switch (aerr) {
        case ENOENT:
        case ENOTDIR:
        case ENAMETOOLONG:
        case ELOOP:
            break;      /* the path cannot denote a file: stale value */
        default:
            log_err("HTTPS: SSL_CERT_FILE '%s' is not readable (%s) and "
                    "that is not a stale-path error; refusing to fall back "
                    "to the system trust store (fail-closed)", ca,
                    strerror(aerr));
            return -1;
        }
        log_err("HTTPS: SSL_CERT_FILE '%s' cannot be used as a CA file "
                "(%s); treating it as a stale value and trying the system "
                "CA bundle candidates", ca, strerror(aerr));
    }
    for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++) {
        char ebuf[256];

        if (access(cands[i], R_OK) != 0)
            continue;   /* not installed here: try the next candidate */
        ERR_clear_error();   /* R14 (R13-B1-L2): same residual-queue rule */
        if (SSL_CTX_load_verify_locations(ctx, cands[i], NULL) == 1) {
            if (ca)
                log_info("HTTPS: falling back to system CA bundle '%s'",
                         cands[i]);
            return 0;
        }
        https_ssl_err(ebuf, sizeof ebuf);
        log_err("HTTPS: CA bundle '%s' exists but is unusable: %s",
                cands[i], ebuf);
    }
    if (ca) {
        log_err("HTTPS: SSL_CERT_FILE '%s' could not be loaded and no "
                "system CA bundle could be loaded either", ca);
    } else {
        log_err("no CA bundle found: set SSL_CERT_FILE or install one of "
                "/etc/ssl/certs/ca-certificates.crt, "
                "/etc/pki/tls/certs/ca-bundle.crt, /etc/ssl/cert.pem, "
                "/etc/pki/tls/cacert.pem");
    }
    return -1;
#endif
}

static const char iwan_embedded_cas[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB\n"
    "iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl\n"
    "cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV\n"
    "BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw\n"
    "MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV\n"
    "BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU\n"
    "aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy\n"
    "dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n"
    "AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B\n"
    "3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY\n"
    "tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/\n"
    "Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2\n"
    "VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT\n"
    "79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6\n"
    "c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT\n"
    "Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l\n"
    "c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee\n"
    "UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE\n"
    "Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd\n"
    "BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G\n"
    "A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF\n"
    "Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO\n"
    "VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3\n"
    "ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs\n"
    "8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR\n"
    "iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze\n"
    "Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ\n"
    "XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/\n"
    "qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB\n"
    "VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB\n"
    "L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG\n"
    "jjxDah2nGN59PRbxYvnKkKj9\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFijCCA3KgAwIBAgIQdY39i658BwD6qSWn4cetFDANBgkqhkiG9w0BAQwFADBf\n"
    "MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQD\n"
    "Ey1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYw\n"
    "HhcNMjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEY\n"
    "MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1Ymxp\n"
    "YyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEB\n"
    "AQUAA4ICDwAwggIKAoICAQCTvtU2UnXYASOgHEdCSe5jtrch/cSV1UgrJnwUUxDa\n"
    "ef0rty2k1Cz66jLdScK5vQ9IPXtamFSvnl0xdE8H/FAh3aTPaE8bEmNtJZlMKpnz\n"
    "SDBh+oF8HqcIStw+KxwfGExxqjWMrfhu6DtK2eWUAtaJhBOqbchPM8xQljeSM9xf\n"
    "iOefVNlI8JhD1mb9nxc4Q8UBUQvX4yMPFF1bFOdLvt30yNoDN9HWOaEhUTCDsG3X\n"
    "ME6WW5HwcCSrv0WBZEMNvSE6Lzzpng3LILVCJ8zab5vuZDCQOc2TZYEhMbUjUDM3\n"
    "IuM47fgxMMxF/mL50V0yeUKH32rMVhlATc6qu/m1dkmU8Sf4kaWD5QazYw6A3OAS\n"
    "VYCmO2a0OYctyPDQ0RTp5A1NDvZdV3LFOxxHVp3i1fuBYYzMTYCQNFu31xR13NgE\n"
    "SJ/AwSiItOkcyqex8Va3e0lMWeUgFaiEAin6OJRpmkkGj80feRQXEgyDet4fsZfu\n"
    "+Zd4KKTIRJLpfSYFplhym3kT2BFfrsU4YjRosoYwjviQYZ4ybPUHNs2iTG7sijbt\n"
    "8uaZFURww3y8nDnAtOFr94MlI1fZEoDlSfB1D++N6xybVCi0ITz8fAr/73trdf+L\n"
    "HaAZBav6+CuBQug4urv7qv094PPK306Xlynt8xhW6aWWrL3DkJiy4Pmi1KZHQ3xt\n"
    "zwIDAQABo0IwQDAdBgNVHQ4EFgQUVnNYZJX5khqwEioEYnmhQBWIIUkwDgYDVR0P\n"
    "AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAC9c\n"
    "mTz8Bl6MlC5w6tIyMY208FHVvArzZJ8HXtXBc2hkeqK5Duj5XYUtqDdFqij0lgVQ\n"
    "YKlJfp/imTYpE0RHap1VIDzYm/EDMrraQKFz6oOht0SmDpkBm+S8f74TlH7Kph52\n"
    "gDY9hAaLMyZlbcp+nv4fjFg4exqDsQ+8FxG75gbMY/qB8oFM2gsQa6H61SilzwZA\n"
    "Fv97fRheORKkU55+MkIQpiGRqRxOF3yEvJ+M0ejf5lG5Nkc/kLnHvALcWxxPDkjB\n"
    "JYOcCj+esQMzEhonrPcibCTRAUH4WAP+JWgiH5paPHxsnnVI84HxZmduTILA7rpX\n"
    "DhjvLpr3Etiga+kFpaHpaPi8TD8SHkXoUsCjvxInebnMMTzD9joiFgOgyY9mpFui\n"
    "TdaBJQbpdqQACj7LzTWb4OE4y2BThihCQRxEV+ioratF4yUQvNs+ZUH7G6aXD+u5\n"
    "dHn5HrwdVw1Hr8Mvn4dGp+smWg9WY7ViYG4A++MnESLn/pmPNPW56MORcr3Ywx65\n"
    "LvKRRFHQV80MNNVIIb/bE/FmJUNS0nAiNs2fxBx1IK1jcmMGDw4nztJqDby1ORrp\n"
    "0XZ60Vzk50lJLVU3aPAaOpg+VBeHVOmmJ1CJeyAvP/+/oYtKR5j/K3tJPsMpRmAY\n"
    "QqszKbrAKbkTidOIijlBO8n9pu0f9GBj39ItVQGL\n"
    "-----END CERTIFICATE-----\n"
    "";

/* Load the bundled fallback roots into the store. Returns the number
 * added (0 only if the embedded PEM block fails to parse — a build
 * bug, not a runtime condition). */
static int https_ctx_add_embedded_cas(SSL_CTX *ctx)
{
    BIO *bio = BIO_new_mem_buf(iwan_embedded_cas,
                               (int)strlen(iwan_embedded_cas));
    X509_STORE *xstore = SSL_CTX_get_cert_store(ctx);
    int n = 0;

    if (!bio)
        return 0;
    ERR_clear_error();
    for (;;) {
        X509 *x = PEM_read_bio_X509(bio, NULL, NULL, NULL);

        if (!x)
            break;
        if (X509_STORE_add_cert(xstore, x) == 1)
            n++;
        X509_free(x);
    }
    BIO_free(bio);
    ERR_clear_error();
    return n;
}

/* One client TLS context with peer verification and CA loading, cached
   per CA mode (0 = system store, 1 = bundled fallback roots): a single
   auth/OIDC round trip builds the context up to twice (attempt 1 system
   store, attempt 2 + bundled roots), and later exchanges reuse it. The
   cache is process-lifetime and lazily initialized by the serial login
   path (https_transport runs on one thread at a time); SSL objects are
   always created fresh from the shared context, which OpenSSL allows. */
static SSL_CTX *g_https_ctx[2];   /* [0] system store, [1] + fallback CAs */

static SSL_CTX *https_ctx_new(bool with_fallback);

static SSL_CTX *https_ctx_get(bool with_fallback)
{
    SSL_CTX **slot = &g_https_ctx[with_fallback ? 1 : 0];

    if (*slot)
        return *slot;
    *slot = https_ctx_new(with_fallback);
    return *slot;
}

static SSL_CTX *https_ctx_new(bool with_fallback)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx)
        return NULL;
    /* HTTP/1.1 "Connection: close" servers routinely close the TCP
     * stream without a TLS close_notify; OpenSSL 3 reports that as
     * error 0A000126. The old pipe-based transport saw plain EOF, so
     * restore that semantics: SSL_read then returns 0 (clean end).
     * The option is OpenSSL 3.0+; 1.1.1 lacks it (and never surfaces
     * 0A000126 — it already treats the missing close_notify as EOF),
     * so keep the fallback path below for older versions. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (https_ctx_load_cas(ctx) != 0) {
        if (!with_fallback) {
            SSL_CTX_free(ctx);
            return NULL;
        }
        /* (cache callers never see this NULL: with_fallback continues) */
        /* no system bundle usable (the specific reason — a bad
         * SSL_CERT_FILE, an unusable candidate, or nothing installed —
         * was just logged by https_ctx_load_cas): bundled roots only */
        log_err("HTTPS: no usable system CA bundle; using the bundled "
                "fallback roots only");
    }
    if (with_fallback) {
        int n = https_ctx_add_embedded_cas(ctx);

        if (n == 0)
            log_err("HTTPS: embedded fallback CA bundle failed to parse");
        else
            log_info("HTTPS: added %d bundled fallback CA(s) "
                     "(USERTrust RSA, Sectigo R46)", n);
    }
    return ctx;
}

/* E2: simplified Happy Eyeballs. The resolved addresses are split into
   an IPv6 and an IPv4 lane (the resolver's AF_UNSPEC order decides which
   lane an address belongs to), both lanes run concurrently and the first
   lane whose socket becomes writable with SO_ERROR==0 wins; the other
   lane's in-flight socket is closed. A lane whose attempt fails moves to
   its next address. Not full RFC 8305 (no delayed v4 start): both lanes
   start together, which is enough to avoid the sequential whiteout where
   a dead IPv6 path stalls the login for the whole 25s deadline before
   IPv4 is even tried. The TLS exchange that follows is unchanged. */

/* one lane: the address slice it still has to try, its in-flight socket
   and connect state */
typedef struct {
    struct addrinfo *next;      /* next address to try (NULL = exhausted) */
    struct addrinfo *cur;       /* address currently being tried */
    int fd;                     /* in-flight socket, -1 = none */
    bool waiting;               /* connect in progress on fd */
    bool failed;                /* all addresses tried */
} he_lane;

/* start (or restart) a lane's connect attempt on its next address.
 * Returns with either an in-flight connect or the lane failed/exhausted. */
static void he_lane_start(he_lane *ln, char *diag, size_t diagsz)
{
#ifndef _WIN32
    (void)diag;
    (void)diagsz;
#endif
    for (;;) {
        struct addrinfo *ai = ln->next;
        int fd;

        ln->next = ai ? ai->ai_next : NULL;
        if (!ai) {
            ln->failed = true;
            if (ln->fd >= 0) {
                port_close(ln->fd);
                ln->fd = -1;
            }
            ln->waiting = false;
            return;
        }
        ln->cur = ai;
        fd = port_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
#ifdef _WIN32
            snprintf(diag, diagsz, "socket(family %d): wsa %d (errno %d)",
                     ai->ai_family, WSAGetLastError(), errno);
#endif
            continue;   /* try the lane's next address */
        }
        if (port_set_nonblock(fd, true) != 0) {
#ifdef _WIN32
            snprintf(diag, diagsz,
                     "ioctlsocket(FIONBIO): family %d, wsa %d (errno %d)",
                     ai->ai_family, WSAGetLastError(), errno);
#endif
            port_close(fd);
            continue;
        }
        {
            /* E3: Nagle delays the small TLS handshake records behind
             * each other (40-200ms per hop with delayed ACK); the tunnel
             * sockets all disable it */
            int nd = 1;
            (void)port_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nd,
                                  sizeof nd);
        }
        if (port_connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) != 0 &&
            errno != EINPROGRESS && errno != EAGAIN &&
            errno != EWOULDBLOCK && errno != EINTR) {
            /* nonblocking connect: WSAEWOULDBLOCK -> EAGAIN on Windows,
             * EINPROGRESS on Linux; both mean "wait for POLLOUT".
             * R37 WG-E2 (R3-L3): EINTR means the connect is still in
             * progress (POSIX resumes it asynchronously), NOT that this
             * address failed — it must be waited for like EINPROGRESS,
             * else a single delivered signal fails the whole host when
             * the resolver returned one address ("Interrupted system
             * call"). Anything else is an immediate failure: next
             * address. */
#ifdef _WIN32
            snprintf(diag, diagsz, "connect: wsa %d (errno %d)",
                     WSAGetLastError(), errno);
#endif
            port_close(fd);
            continue;
        }
        ln->fd = fd;
        ln->waiting = true;
        return;
    }
}

/* reap a lane after poll reported it: writable+SO_ERROR==0 wins (the fd
 * stays open), anything else moves the lane to its next address. */
static bool he_lane_check(he_lane *ln, char *diag, size_t diagsz)
{
#ifndef _WIN32
    (void)diag;
    (void)diagsz;
#endif
    int soerr = 0;
    socklen_t slen = sizeof soerr;

    if (!ln->waiting || ln->fd < 0)
        return false;
    ln->waiting = false;
    if (port_getsockopt(ln->fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 &&
        soerr == 0)
        return true;   /* the winner */
    if (soerr != 0)
        errno = soerr;
#ifdef _WIN32
    snprintf(diag, diagsz, "connect SO_ERROR: soerr=%d wsa %d (errno %d)",
             soerr, WSAGetLastError(), errno);
#endif
    port_close(ln->fd);
    ln->fd = -1;
    he_lane_start(ln, diag, diagsz);
    return false;
}

static int https_connect_tcp(const char *host, uint16_t port,
                             uint64_t deadline_ms,
                             char *diag, size_t diagsz)
{
    struct addrinfo hints, *res = NULL;
    struct addrinfo *v6_head = NULL, *v6_tail = NULL;
    struct addrinfo *v4_head = NULL, *v4_tail = NULL;
    he_lane l6 = { NULL, NULL, -1, false, false };
    he_lane l4 = { NULL, NULL, -1, false, false };
    struct addrinfo *ai;
    char service[8];
    int gai, fd = -1;
    bool expired = false;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof service, "%u", (unsigned)port);

    gai = getaddrinfo(host, service, &hints, &res);
    if (gai != 0) {
        snprintf(diag, diagsz, "cannot resolve %s: %s", host,
                 gai_strerror(gai));
        return -1;
    }

    /* split the resolver's order into the two lanes (per-lane order is
     * the system's preference order) */
    for (ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET6) {
            if (v6_tail)
                v6_tail->ai_next = ai;
            else
                v6_head = ai;
            v6_tail = ai;
        } else {
            if (v4_tail)
                v4_tail->ai_next = ai;
            else
                v4_head = ai;
            v4_tail = ai;
        }
    }
    if (v6_tail)
        v6_tail->ai_next = NULL;
    if (v4_tail)
        v4_tail->ai_next = NULL;
    l6.next = v6_head;
    l4.next = v4_head;
    he_lane_start(&l6, diag, diagsz);
    he_lane_start(&l4, diag, diagsz);

    while (!l6.failed || !l4.failed) {
        struct pollfd pfd[2];
        nfds_t npfd = 0;
        int l6_idx = -1, l4_idx = -1;
        int pr;

        if (now_ms() >= deadline_ms) {
            snprintf(diag, diagsz, "timed out connecting to %s", host);
            break;
        }
        /* v6 first in the poll set: it wins ties (preferred family) */
        if (l6.waiting && l6.fd >= 0) {
            l6_idx = (int)npfd;
            pfd[npfd].fd = PORT_FD_ARG(l6.fd);
            pfd[npfd].events = POLLOUT;
            npfd++;
        }
        if (l4.waiting && l4.fd >= 0) {
            l4_idx = (int)npfd;
            pfd[npfd].fd = PORT_FD_ARG(l4.fd);
            pfd[npfd].events = POLLOUT;
            npfd++;
        }
        if (npfd == 0)
            break;   /* both lanes between attempts or exhausted */
        {
            /* one clock read (R38-C4-4): see https_remain_ms */
            uint64_t remain = https_remain_ms(deadline_ms, NULL);
            int to = remain > HTTPS_POLL_MS ? (int)HTTPS_POLL_MS
                                            : (int)remain;

            for (;;) {
                pr = port_poll(pfd, npfd, to);
                if (pr >= 0 || errno != EINTR)
                    break;
                /* R37 WG-E2 (R3-L2): every EINTR retry must recompute the
                 * budget. The old loop retried with the ORIGINAL timeout
                 * and never re-checked the deadline (that check sits
                 * outside this block), so a steady stream of signals kept
                 * it polling forever — the documented 60s round-trip bound
                 * did not exist. Same shape as relay_proxy.c rp_poll_retry. */
                {
                    uint64_t now = now_ms();

                    if (now >= deadline_ms) {
                        expired = true;
                        break;
                    }
                    remain = deadline_ms - now;
                    to = remain > HTTPS_POLL_MS ? (int)HTTPS_POLL_MS
                                                : (int)remain;
                }
            }
        }
        if (expired) {
            snprintf(diag, diagsz, "timed out connecting to %s", host);
            break;
        }
        if (pr == 0)
            errno = ETIMEDOUT;
        if (pr > 0) {
            /* reap the loser first (both revents may be set when both
             * connect in the same window): v6 wins ties */
            if (l4_idx >= 0 &&
                (pfd[l4_idx].revents & (POLLOUT | POLLERR | POLLHUP)) &&
                he_lane_check(&l4, diag, diagsz)) {
                fd = l4.fd;
                break;
            }
            if (l6_idx >= 0 &&
                (pfd[l6_idx].revents & (POLLOUT | POLLERR | POLLHUP)) &&
                he_lane_check(&l6, diag, diagsz)) {
                fd = l6.fd;
                break;
            }
        } else {
            /* timeout/error: retire both in-flight sockets, lanes move
             * to their next addresses */
            if (l6.waiting && l6.fd >= 0) {
                port_close(l6.fd);
                l6.fd = -1;
                l6.waiting = false;
                he_lane_start(&l6, diag, diagsz);
            }
            if (l4.waiting && l4.fd >= 0) {
                port_close(l4.fd);
                l4.fd = -1;
                l4.waiting = false;
                he_lane_start(&l4, diag, diagsz);
            }
        }
    }
    /* loser cleanup: close the non-winner's in-flight socket */
    if (fd >= 0) {
        he_lane *loser = (fd == l6.fd) ? &l4 : &l6;
        if (loser->fd >= 0)
            port_close(loser->fd);
    } else {
        if (l6.fd >= 0)
            port_close(l6.fd);
        if (l4.fd >= 0)
            port_close(l4.fd);
    }
    /* the split reuses the original chain nodes, so `res` is now the
     * head of only one of the two subchains: free both (each exactly
     * once) — freeing only `res` leaks the other subchain
     * (SUMMARY-2 M3) */
    if (v6_head)
        freeaddrinfo(v6_head);
    if (v4_head)
        freeaddrinfo(v4_head);

    if (fd < 0 && diag[0] == '\0') {
#ifdef _WIN32
        int wsa = WSAGetLastError();
        snprintf(diag, diagsz, "cannot connect to %s:%u: %s (wsa %d)",
                 host, (unsigned)port, strerror(errno), wsa);
#else
        snprintf(diag, diagsz, "cannot connect to %s:%u: %s", host,
                 (unsigned)port, strerror(errno));
#endif
    }
    /* C-1 (E2 regression, af7308a): Happy Eyeballs connects on
     * nonblocking fds (set above). The TLS stage that follows
     * (https_tls_connect/write/read) is designed for a BLOCKING fd
     * parked on SO_RCVTIMEO/SO_SNDTIMEO; on a nonblocking fd
     * SSL_ERROR_WANT_READ/WANT_WRITE return immediately and the old
     * "continue" loop would spin one core for the whole deadline.
     * Restore blocking on the winner at this single return funnel so
     * every path hands a blocking fd to https_connect_tls. */
    if (fd >= 0 && port_set_nonblock(fd, false) != 0) {
#ifdef _WIN32
        snprintf(diag, diagsz,
                 "ioctlsocket(FIONBIO): fd %d, wsa %d (errno %d)",
                 fd, WSAGetLastError(), errno);
#endif
        port_close(fd);
        fd = -1;
    }
    return fd;
}

/* Bind the connected socket to a new SSL session for `host`: SNI, peer
   verification, and the hostname check — the in-process equivalent of
   `openssl s_client -servername/-verify_hostname -verify_return_error`. */
/* Verify callback: on chain/hostname verification failure, log the
   precise reason and the offending certificate immediately (this is the
   only point where the peer certificate is still available — OpenSSL
   clears it from the session once the handshake fails). The callback
   always rejects (returns 0) so the handshake fails as before. */
static int https_verify_cb(int preverify_ok, X509_STORE_CTX *xctx)
{
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(xctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(xctx);
        char subj[128];

        if (cert)
            X509_NAME_oneline(X509_get_subject_name(cert), subj,
                              sizeof subj);
        else
            snprintf(subj, sizeof subj, "?");
        log_err("HTTPS: server certificate rejected: %s (%d), "
                "cert subject=%s",
                X509_verify_cert_error_string(err), err, subj);
    }
    /* keep the default verification decision (reject on failure) */
    return preverify_ok;
}

static SSL *https_ssl_new(SSL_CTX *ctx, int fd, const char *host)
{
    SSL *ssl = SSL_new(ctx);

    if (!ssl)
        return NULL;
    if (SSL_set_fd(ssl, fd) != 1 ||
        SSL_set_tlsext_host_name(ssl, host) != 1 ||
        SSL_set1_host(ssl, host) != 1) {
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_verify(ssl, SSL_VERIFY_PEER, https_verify_cb);
    return ssl;
}

/* Drive the TLS handshake to completion. SO_RCVTIMEO / SO_SNDTIMEO are
   re-armed to min(remaining budget, HTTPS_POLL_MS) before every SSL
   call, and the deadline is re-checked whenever a call is interrupted
   by its socket timeout, so a dead or stalling peer cannot hang the
   round trip. Returns 0 on success, -1 with a reason in diag. */
static int https_tls_connect(SSL *ssl, int fd, uint64_t deadline_ms,
                             char *diag, size_t diagsz, long *verify_err)
{
    for (;;) {
        uint64_t remain;
        int r;
        if (verify_err)
            *verify_err = X509_V_OK;

        {
            uint64_t now;
            remain = https_remain_ms(deadline_ms, &now);
            if (now >= deadline_ms) {
                snprintf(diag, diagsz, "TLS handshake timed out");
                return -1;
            }
        }
        if (https_set_io_timeo(fd, SO_RCVTIMEO, remain) != 0 ||
            https_set_io_timeo(fd, SO_SNDTIMEO, remain) != 0) {
            snprintf(diag, diagsz, "cannot arm socket timeout: %s",
                     strerror(errno));
            return -1;
        }
        ERR_clear_error();
        r = SSL_connect(ssl);
        if (r == 1)
            return 0;   /* handshake complete, peer verified */
        {
            int e = SSL_get_error(ssl, r);

            if (e == SSL_ERROR_ZERO_RETURN) {
                /* R14 (R13-B1-L1): the peer half-closed the TCP connection
                 * during the handshake (accepted then FIN) — OpenSSL 3.x
                 * reports the raw FIN here as ZERO_RETURN with r<0, errno==0
                 * and an empty queue (verified by probe); a close_notify
                 * mid-handshake lands here too.  Without this branch the
                 * failure fell through to https_ssl_err which printed
                 * strerror(errno) == "Success". */
                snprintf(diag, diagsz,
                         "peer closed the connection during TLS handshake");
                return -1;
            }
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                /* socket-timeout semantics hold only on a BLOCKING fd;
                 * https_connect_tcp restored it to blocking (C-1), so a
                 * WANT_* here means the SO_RCVTIMEO/SNDTIMEO fired and we
                 * re-check the deadline. On a nonblocking fd this would
                 * return instantly and spin one core until the deadline. */
                continue;
            if (e == SSL_ERROR_SYSCALL) {
                /* R14 (R13-B1-L1): the peer sent FIN/close_notify before
                 * the handshake finished (accepted then closed).  OpenSSL
                 * documents r==0 as the "unexpected EOF" return, but the
                 * handshake path in practice surfaces r<0 with errno==0 and
                 * an empty error queue (verified on OpenSSL 3.x) — either
                 * way there is NO OS error to report, so name the real
                 * cause instead of letting https_ssl_err print
                 * strerror(errno) == "Success".  The read side has had the
                 * r==0 rule since 21a4a50; this mirrors it plus the
                 * observed r<0/errno==0 shape. */
                if (r == 0 || (r < 0 && errno == 0 &&
                               ERR_peek_error() == 0)) {
                    snprintf(diag, diagsz,
                             "peer closed the connection during TLS handshake");
                    return -1;
                }
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == ETIMEDOUT) {
                    if (now_ms() >= deadline_ms) {
                        snprintf(diag, diagsz, "TLS handshake timed out");
                        return -1;
                    }
                    continue;
                }
            }
            https_ssl_err(diag, diagsz);
            /* certificate/hostname verification failures surface as the
             * generic "certificate verify failed" SSL error; append the
             * precise X509 reason (the verify callback above already
             * logged the offending certificate) and hand the verify
             * code to the transport (anchor-missing codes trigger the
             * bundled-fallback retry). */
            if (verify_err)
                *verify_err = SSL_get_verify_result(ssl);
            {
                long vr = *verify_err ? *verify_err : SSL_get_verify_result(ssl);
                size_t used = strlen(diag);
                int left = (int)diagsz - (int)used;

                if (vr != X509_V_OK && left > 0)
                    snprintf(diag + used, (size_t)left,
                             "; X509 verify: %s (%ld)",
                             X509_verify_cert_error_string(vr), vr);
            }
            return -1;
        }
    }
}

/* Send the request. SSL_write on a blocking socket writes the whole
   buffer or fails; a short count is resumed from where it stopped. A
   send timeout is final: a record may be half-committed and the
   connection cannot be resumed (mirrors the old pump, which also gave
   up the moment the child's pipe broke). Returns 0 on success, -1 with
   a reason in diag. */
static int https_tls_write(SSL *ssl, int fd, const char *req,
                           size_t req_len, uint64_t deadline_ms,
                           char *diag, size_t diagsz)
{
    size_t off = 0;

    while (off < req_len) {
        uint64_t remain;
        int w;

        {
            uint64_t now;
            remain = https_remain_ms(deadline_ms, &now);
            if (now >= deadline_ms) {
                snprintf(diag, diagsz, "timed out sending request");
                return -1;
            }
        }
        if (https_set_io_timeo(fd, SO_SNDTIMEO, remain) != 0) {
            snprintf(diag, diagsz, "cannot arm send timeout: %s",
                     strerror(errno));
            return -1;
        }
        ERR_clear_error();
        w = SSL_write(ssl, req + off,
                      req_len - off > INT_MAX ? INT_MAX
                                              : (int)(req_len - off));
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        {
            int e = SSL_get_error(ssl, w);

            if (e == SSL_ERROR_ZERO_RETURN) {
                /* R14 (R13-B1-L1): the peer closed the connection (FIN /
                 * close_notify) before the request was fully written;
                 * OpenSSL reports it as ZERO_RETURN with no errno/queue.
                 * Same fix as the handshake side: name the real cause
                 * instead of https_ssl_err's strerror(errno) == "Success". */
                snprintf(diag, diagsz,
                         "peer closed the connection while sending request");
                return -1;
            }
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                /* fd is blocking (restored by C-1); WANT_* means the send
                 * timeout fired — re-check the deadline next iteration */
                continue;
            if (e == SSL_ERROR_SYSCALL) {
                /* R14 (R13-B1-L1): the peer closed (FIN/close_notify)
                 * while the request was still going out.  Mirror of the
                 * handshake/read r==0 rules: r==0 is the documented
                 * "peer went away" return, and a partially-written request
                 * to a just-closed peer can also surface r<0 with
                 * errno==0 and an empty queue; both must not fall through
                 * to strerror(errno) == "Success". */
                if (w == 0 || (w < 0 && errno == 0 &&
                               ERR_peek_error() == 0)) {
                    snprintf(diag, diagsz,
                             "peer closed the connection while sending request");
                    return -1;
                }
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == ETIMEDOUT) {
                    snprintf(diag, diagsz, "timed out sending request");
                    return -1;
                }
            }
            https_ssl_err(diag, diagsz);
            return -1;
        }
    }
    return 0;
}

/* Parse Content-Length from a complete header block (NUL-free, len
 * bytes). Returns the byte count, or -1 when absent/malformed (the
 * caller then falls back to EOF-delimited reads, which still work for
 * "Connection: close" and chunked responses). */
static long long https_content_length(const char *hdrs, size_t hlen)
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
                    return -1;   /* malformed: use EOF-delimited mode */
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

/* memmem is a GNU extension absent from mingw-w64: hand-roll the two
 * tiny needle searches we need (header terminator) so the code builds
 * on every toolchain. */
static const char *sbuf_find(const char *hay, size_t hlen,
                             const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen)
        return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    return NULL;
}

/* Read the raw response until EOF or close_notify, enforcing the 16 MiB
   ceiling and the round-trip deadline (re-armed before every read, like
   the old poll loop chunked at HTTPS_POLL_MS). Returns 0 on success,
   -1 with a reason in diag. */
static int https_tls_read(SSL *ssl, int fd, struct sbuf *resp,
                          uint64_t deadline_ms, char *diag, size_t diagsz)
{
    char buf[HTTPS_READ_CHUNK];
    long long content_len = -1;   /* -1: unknown (EOF-delimited) */
    bool chunked = false;         /* TE: chunked wins over CL (R12 T4) */
    size_t body_start = 0;
    /* R1-B1-1: the header scan below used to restart at byte 0 after every
     * 4 KiB read, so a peer that pushes the terminator late (or never)
     * made the read O(n^2) — 12 MiB of header cost ~10 s of CPU (CWE-407,
     * remotely triggerable). Each needle is now scanned at most once per
     * byte: a hit is permanent (the buffer only ever grows) and a miss
     * resumes at the last offset that can still start a match. The
     * Content-Length parse is likewise a pure function of
     * resp->d[0..body_start), so body_start doubles as its memo key and
     * a huge header block is not re-parsed on every read. */
    bool crlf_hit = false, lf_hit = false;
    size_t crlf_pos = 0, lf_pos = 0;
    size_t crlf_probe = 0, lf_probe = 0;

    for (;;) {
        uint64_t remain;
        int r;

        if (resp->len > HTTPS_MAX_RESP) {
            snprintf(diag, diagsz, "response exceeded %u MiB",
                     (unsigned)(HTTPS_MAX_RESP >> 20));
            return -1;
        }
        {
            uint64_t now;
            remain = https_remain_ms(deadline_ms, &now);
            if (now >= deadline_ms) {
                snprintf(diag, diagsz, "timed out waiting for response");
                return -1;
            }
        }
        if (https_set_io_timeo(fd, SO_RCVTIMEO, remain) != 0) {
            snprintf(diag, diagsz, "cannot arm receive timeout: %s",
                     strerror(errno));
            return -1;
        }
        ERR_clear_error();
        r = SSL_read(ssl, buf, sizeof buf);
        if (r > 0) {
            sbuf_app(resp, buf, (size_t)r);
            if (content_len < 0) {
                /* once the header block has fully arrived, learn the
                 * body length so we can stop at the last body byte
                 * instead of waiting for the peer to close (a
                 * keep-alive server would otherwise stall every
                 * request until the 60s deadline) */
                if (!crlf_hit) {
                    const char *p = sbuf_find(resp->d + crlf_probe,
                                              resp->len - crlf_probe,
                                              "\r\n\r\n", 4);
                    if (p) {
                        crlf_hit = true;
                        crlf_pos = (size_t)(p - resp->d);
                    } else if (resp->len >= 4) {
                        crlf_probe = resp->len - 3;
                    }
                }
                if (!crlf_hit && !lf_hit) {
                    const char *p = sbuf_find(resp->d + lf_probe,
                                              resp->len - lf_probe,
                                              "\n\n", 2);
                    if (p) {
                        lf_hit = true;
                        lf_pos = (size_t)(p - resp->d);
                    } else if (resp->len >= 2) {
                        lf_probe = resp->len - 1;
                    }
                }
                if ((crlf_hit || lf_hit) &&
                    body_start != (crlf_hit ? crlf_pos + 4 : lf_pos + 2)) {
                    /* the terminator choice can still move from LF-only to
                     * CRLF (preferred) while content_len is unknown; that
                     * is the only case that re-parses */
                    body_start = crlf_hit ? crlf_pos + 4 : lf_pos + 2;
                    if (!chunked) {
                        /* R12 T4 (R41-1A2-1): decide the framing ONCE, at
                         * the first settled header block. TE: chunked
                         * overrides any Content-Length (RFC 7230 §3.3.3):
                         * keep content_len == -1 so the raw read runs to
                         * EOF/close_notify and the FULL chunk stream is
                         * captured — CL counts decoded payload bytes, not
                         * the chunk-framed wire octets, so stopping at CL
                         * would truncate the stream and chunk_decode()
                         * below would hard-fail. Only the non-chunked
                         * path parses Content-Length (behavior unchanged). */
                        chunked = https_te_header_chunked(resp->d,
                                                          body_start);
                        if (!chunked) {
                            content_len =
                                https_content_length(resp->d, body_start);
                            if (content_len == 0)
                                return 0;   /* declared empty body */
                        }
                    }
                }
            }
            if (content_len > 0 &&
                resp->len - body_start >= (size_t)content_len)
                return 0;   /* full body in hand: no need to await EOF */
            continue;
        }
        {
            int e = SSL_get_error(ssl, r);

            if (e == SSL_ERROR_ZERO_RETURN) {
                /* close_notify: clean end — unless a declared body is
                 * still short (truncated transfer) */
                if (content_len > 0 &&
                    resp->len - body_start < (size_t)content_len) {
                    snprintf(diag, diagsz,
                             "response truncated (%llu of %lld bytes)",
                             (unsigned long long)(resp->len - body_start), content_len);
                    return -1;
                }
                return 0;
            }
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                /* socket-timeout semantics hold only on a BLOCKING fd
                 * (restored by C-1); here WANT_* means SO_RCVTIMEO fired
                 * and we re-check the deadline — on a nonblocking fd this
                 * returns instantly and spins until the deadline */
                continue;
            if (e == SSL_ERROR_SYSCALL) {
                if (r == 0) {
                    /* EOF without close_notify: the peer closed after
                     * "Connection: close" — truncated if a declared
                     * body is incomplete */
                    if (content_len > 0 &&
                        resp->len - body_start < (size_t)content_len) {
                        snprintf(diag, diagsz,
                                 "response truncated (%llu of %lld bytes)",
                                 (unsigned long long)(resp->len - body_start), content_len);
                        return -1;
                    }
                    return 0;
                }
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == ETIMEDOUT) {
                    if (now_ms() >= deadline_ms) {
                        snprintf(diag, diagsz,
                                 "timed out waiting for response");
                        return -1;
                    }
                    continue;
                }
            }
            https_ssl_err(diag, diagsz);
            return -1;
        }
    }
}

/* Locate the start of the header lines and of the body in a response.
 * R37 WG-E2 (R3-L10): the header start is derived from the SAME
 * terminator that delimits the body. The old code located the header
 * start from the first CRLF and the body from the first CRLFCRLF/LFLF
 * independently; an LF-only header block followed by a CRLF inside the
 * body made body < hdr_start, so (size_t)(body - hdr_start) underflowed
 * (pointer-overflow UB in https_hdr_value's `hdr + len` and the whole
 * header block — Transfer-Encoding, Location — became invisible). With
 * one ruler hdr_start <= body holds for every input.
 *
 * R37 R5 WG-D (R4-L1): with a terminator the two pointers are on the
 * same ruler exactly as above (byte-identical behaviour). WITHOUT one
 * the header block now runs to the END OF THE BUFFER instead of
 * collapsing to zero length: the R3-L10 rewrite set both pointers to
 * `d + len`, so hdr_len == 0 and every header line of an EOF-truncated
 * response (Content-Length, Location, Transfer-Encoding) became
 * invisible a second time — a redirect whose header block ends at EOF
 * was no longer followed and an EOF-delimited body was handed out whole
 * (status line included). hdr_start is therefore the first LF + 1 (the
 * buffer start when it contains no LF at all, so the ruler still never
 * crosses), which is what https_tls_read()'s "peer closed after a
 * complete header block" path relies on. */
static void https_hdr_body(const char *d, size_t len,
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
        /* no header terminator: the header block runs to the buffer end
         * (same semantics as before R3-L10) */
        eol = memchr(d, '\n', len);
        *hdr_start = eol ? eol + 1 : d;
        *body = d + len;
        return;
    }
    /* the first LF after the status line ends it; the header block runs
     * from there to the terminator */
    eol = memchr(d, '\n', (size_t)(term - d));
    *hdr_start = eol ? eol + 1 : term;
    *body = term + tlen;
}

/* Parse just the HTTP status code out of a raw response; -1 on malformed. */
static int https_resp_status(const char *d, size_t len)
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

/* Parse the HTTP status line and body (chunk-decoded if needed) out of
   the raw response; frees resp. Returns 1 on success, else 0. */
static int https_resp_parse(struct sbuf *resp, int *status, char **body_out)
{
    const char *hdr_start, *body;
    size_t hdr_len;
    int chunked = 0;
    char *out, *te;

    /* M3-3: the caller seeds *body_out with empty_str() before the
     * redirect loop; every return path below overwrites it, so free the
     * seed once here — otherwise 1 heap byte leaked per HTTPS request.
     * parse runs at most once per round-trip (on the final response). */
    free(*body_out);
    *body_out = NULL;

    *status = https_resp_status(resp->d, resp->len);
    if (*status < 0) {
        free(resp->d);
        *body_out = empty_str();
        return 0;
    }

    https_hdr_body(resp->d, resp->len, &hdr_start, &body);
    /* belt and braces: https_hdr_body now guarantees body >= hdr_start,
     * but a negative difference must never reach https_hdr_value again
     * (that subtraction is what wrapped the pointer and hid the headers) */
    hdr_len = (body > hdr_start) ? (size_t)(body - hdr_start) : 0;
    te = https_hdr_value(hdr_start, hdr_len, "transfer-encoding");
    if (te) {
        if (!https_te_is_chunked(te)) {
            log_err("unsupported Transfer-Encoding: %s", te);
            free(te);
            free(resp->d);
            *body_out = empty_str();
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
            *body_out = empty_str();
            return 0;
        }
        out = dec.d ? dec.d : empty_str();
    } else {
        size_t blen = resp->len - (size_t)(body - resp->d);
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

/* One request/response exchange over a fresh TLS connection: resolve +
   connect, verified handshake, write the request, read the raw response
   (deadline-bounded, 16 MiB ceiling). Returns 1 on success with *resp
   holding the raw bytes (caller parses), else 0 with a diagnostic
   logged in the "HTTPS transport failed for %s" shape: the OpenSSL
   error string for TLS failures (certificate, hostname, protocol), the
   errno text for socket failures, or the timeout message. */
static bool https_transport(const char *host, struct sbuf *req,
                            struct sbuf *resp, uint64_t deadline_ms)
{
    /* zeroed: when both Happy-Eyeballs lanes exhaust their addresses
     * nothing writes diag, and https_connect_tcp checks diag[0]=='\0'
     * to decide whether to fill in the errno text — a garbage
     * non-empty buffer would skip that and reach the log (SUMMARY-2
     * M6) */
    char diag[512] = { 0 };
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    bool ok = false;
    bool connected = false;   /* R14 (R13-B1-L3): handshake completed */

    if (debug_enabled())
        log_debug("https_transport: %s start (deadline %llu ms)",
                  host, (unsigned long long)deadline_ms);

    /* Attempt 1 uses the system trust store only; if the chain's anchor
     * is missing there (trimmed Windows root stores — observed: campus
     * images with ~18 roots), attempt 2 retries once with the bundled
     * fallback roots added. Never retried for hostname or other
     * verification classes. */
    for (int attempt = 0; attempt < 2; attempt++) {
        bool fallback = attempt == 1;

        if (debug_enabled())
            log_debug("https_transport: %s attempt %d%s", host,
                      attempt + 1, fallback ? " (bundled fallback CAs)" : "");

        ctx = https_ctx_get(fallback);
        if (!ctx) {
            /* CA problem: https_ctx_new already logged the specific
             * reason (missing bundle on Linux, empty ROOT store on
             * Windows). A broken/empty system store still gets one
             * attempt with the bundled fallback roots. */
            if (!fallback) {
                log_info("HTTPS: no usable system CA bundle; retrying "
                         "with bundled fallback CAs");
                continue;
            }
            free(req->d);
            return false;
        }

        fd = https_connect_tcp(host, 443, deadline_ms, diag, sizeof diag);
        if (fd < 0) {
            if (debug_enabled())
                log_debug("https_transport: %s connect failed: %s", host,
                          diag);
            goto out;
        }
        if (debug_enabled())
            log_debug("https_transport: %s connected fd=%d", host, fd);

        /* R14 (R13-B1-L2): clear the residual queue so a failure here is
         * attributed to THIS SSL_new (or https_ssl_new's SSL_set_*), not
         * to a stale error left by an earlier operation in the process. */
        ERR_clear_error();
        ssl = https_ssl_new(ctx, fd, host);
        if (!ssl) {
            https_ssl_err(diag, sizeof diag);
            goto out;
        }
        {
            long verr = X509_V_OK;

            if (https_tls_connect(ssl, fd, deadline_ms, diag, sizeof diag,
                                  &verr) != 0) {
                if (!fallback &&
                    (verr == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
                     verr == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                     verr == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)) {
                    log_info("HTTPS: system trust store lacks the chain "
                             "anchor (%ld); retrying with bundled "
                             "fallback CAs", verr);
                    SSL_free(ssl);
                    port_close(fd);
                    /* ctx stays cached (attempt 2 fetches the fallback
                     * one); only the SSL object and fd are per-attempt */
                    ssl = NULL;
                    ctx = NULL;
                    fd = -1;
                    continue;
                }
                goto out;
            }
            connected = true;
        }
        if (https_tls_write(ssl, fd, req->d, req->len, deadline_ms, diag,
                            sizeof diag) != 0)
            goto out;
        if (https_tls_read(ssl, fd, resp, deadline_ms, diag, sizeof diag) != 0)
            goto out;
        ok = true;
        break;
    }

out:
    /* L-7: the request buffer may hold the caller's Authorization:
     * Bearer <token> (and the token-endpoint POST body); scrub it from
     * the heap before release instead of leaving the credential in a
     * freed chunk. */
    if (req->d && req->len)
        OPENSSL_cleanse(req->d, req->len);
    free(req->d);
    if (ssl) {
        /* R14 (R13-B1-L3): send close_notify so a connection that got as
         * far as a completed handshake ends with a clean FIN instead of
         * an RST (a server logging close_notify warnings no longer
         * sees one per request).  Only the first SSL_shutdown phase runs
         * — it writes close_notify; awaiting the peer's echo could stall,
         * so the socket timeouts are capped to 1 s for this write and
         * the result is discarded (close() still flushes the record). */
        if (connected) {
            https_set_io_timeo(fd, SO_SNDTIMEO, 1000);
            https_set_io_timeo(fd, SO_RCVTIMEO, 1000);
            ERR_clear_error();
            (void)SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
    /* ctx is process-cached (https_ctx_get): never freed here */
    if (fd >= 0)
        port_close(fd);
    if (debug_enabled())
        log_debug("https_transport: %s done ok=%d", host, ok);
    if (!ok || resp->len == 0) {
        /* an empty response is a failure too (the old code treated a
         * child that produced no bytes the same way) */
        log_err("HTTPS transport failed for %s: %s", host,
                ok ? "no response from server" : diag);
        free(resp->d);
        resp->d = NULL;
        resp->len = 0;
        resp->cap = 0;
        return false;
    }
    return true;
}

/* Return a NULL-terminated copy of `headers` with any Authorization
   entry dropped: a redirect to a different host must not carry the
   caller's Bearer token. Results go into store[] (needs >= n+1 slots;
   callers pass a small fixed array). Returns NULL on overflow. */
static const char *const *https_drop_auth(const char *const *headers,
                                          const char **store, size_t store_sz)
{
    size_t src, dst = 0;

    for (src = 0; headers[src]; src++) {
        if (port_strncasecmp(headers[src], "Authorization:",
                             strlen("Authorization:")) == 0)
            continue;   /* drop it */
        if (dst + 1 >= store_sz)
            return NULL;
        store[dst++] = headers[src];
    }
    store[dst] = NULL;
    return store;
}

/* shared transport for the request builders below: follows redirect
   chains (301/302/303/307/308 with an absolute https:// Location, at most
   HTTPS_MAX_REDIRECTS hops) inside one round-trip time budget.
 *
 * Security: a redirect to a DIFFERENT host must not carry the caller's
 * Authorization header (Bearer tokens would leak to the redirect
 * target); 303 always downgrades POST to GET, and 301/302 downgrade a
 * POST to GET per RFC 7231 §6.4.2-3 (307/308 preserve the method). */
static bool https_roundtrip(const char *host, const char *path,
                            const char *body, const char *const *headers,
                            bool is_get, int *status_out, char **body_out)
{
    char *cur_host = xstrdup(host);
    char *cur_path = xstrdup(path);
    const char *const *cur_headers = headers;
    const char *no_auth[8];      /* headers minus Authorization (cross-host
                                  * redirects); callers pass <= 2 headers */
    uint64_t deadline = now_ms() + HTTPS_TIMEOUT_MS;
    int status = 0;
    int failed = 0;

    if (status_out)
        *status_out = 0;
    *body_out = empty_str();     /* contract: always assigned on return */

    for (int hop = 0; hop <= HTTPS_MAX_REDIRECTS; hop++) {
        struct sbuf req = {0}, resp = {0};
        int st;

        if (now_ms() >= deadline) {
            log_err("HTTPS round-trip timed out (redirect hops included)");
            failed = 1;
            break;
        }

        /* R10: a refused build (control character in path/host/header —
         * the token endpoint or a redirect handed us CR/LF) must never
         * reach the transport. req is still empty here, but free it
         * anyway so the ownership rule is the same on every exit. */
        if (!https_req_build(&req, cur_host, cur_path, body, cur_headers,
                             is_get)) {
            free(req.d);
            failed = 1;
            break;
        }
        if (!https_transport(cur_host, &req, &resp, deadline)) {
            failed = 1;
            break;
        }

        st = https_resp_status(resp.d, resp.len);
        if (st < 0) {
            free(resp.d);
            failed = 1;
            break;
        }
        if (st >= 300 && st < 400) {
            int follow = st == 301 || st == 302 || st == 303 ||
                         st == 307 || st == 308;
            char *loc = NULL;

            /* sensitive non-GET (token endpoint POST) must never follow
             * a redirect: 307/308 preserve the body, leaking the
             * code+code_verifier to whatever host the IdP points at
             * (audit L9) */
            if (follow && !is_get) {
                log_err("HTTPS request failed: refusing to follow HTTP %d "
                        "redirect for a non-GET request", st);
                status = st;
                free(resp.d);
                failed = 1;
                break;
            }
            if (follow) {
                const char *hs, *bd;
                https_hdr_body(resp.d, resp.len, &hs, &bd);
                loc = https_hdr_value(hs, (bd > hs) ? (size_t)(bd - hs) : 0,
                                      "location");
            }
            if (!loc) {
                log_err("HTTPS request failed: HTTP %d%s", st,
                        follow ? " without a Location header"
                               : " (unfollowable redirect)");
                status = st;
                free(resp.d);
                failed = 1;
                break;
            }
            {
                char *new_host = NULL, *new_path = NULL;
                if (!https_url_split(loc, &new_host, &new_path)) {
                    log_err("HTTPS redirect to unsupported URL '%s' "
                            "(HTTP %d)", loc, st);
                    free(loc);
                    status = st;
                    free(resp.d);
                    failed = 1;
                    break;
                }
                /* cross-host hop: drop the Authorization header. L1:
                 * hostnames are case-insensitive (RFC 3986), compare
                 * case-insensitively. Same host requires EQUAL
                 * hostnames: a prefix match (new shorter than cur, or
                 * vice versa) is a different host — e.g. new="a.com"
                 * vs cur="a.com.attacker.io" — and MUST drop the
                 * Authorization header (C-2). */
                if (!(strlen(new_host) == strlen(cur_host) &&
                      port_strncasecmp(new_host, cur_host,
                                       strlen(new_host)) == 0) &&
                    cur_headers) {
                    cur_headers = https_drop_auth(
                        cur_headers, no_auth,
                        sizeof no_auth / sizeof no_auth[0]);
                    if (!cur_headers) {
                        log_err("too many request headers for redirect "
                                "sanitization");
                        free(loc);
                        free(new_host);
                        free(new_path);
                        status = st;
                        free(resp.d);
                        failed = 1;
                        break;
                    }
                }
                /* 303 -> GET; 301/302 downgrade POST to GET */
                if (st == 303 || ((st == 301 || st == 302) && !is_get))
                    is_get = true;
                free(loc);
                free(resp.d);
                free(cur_host);
                free(cur_path);
                cur_host = new_host;
                cur_path = new_path;
                continue;   /* next hop with the new host/path */
            }
        }

        /* final response: parse status and body */
        if (!https_resp_parse(&resp, &st, body_out)) {
            /* parse failure already freed resp and set *body_out */
            free(cur_host);
            free(cur_path);
            if (status_out)
                *status_out = status;
            return false;
        }
        status = st;
        free(cur_host);
        free(cur_path);
        if (status_out)
            *status_out = status;
        return true;
    }

    /* loop exited without a final response: transport failure or too many
     * redirects (body_out already set at entry) */
    if (!failed)
        log_err("HTTPS redirect limit (%d) exceeded", HTTPS_MAX_REDIRECTS);
    free(cur_host);
    free(cur_path);
    if (status_out)
        *status_out = status;
    return false;
}

bool https_post(const char *host, const char *path,
                const char *body,
                const char *const *headers,
                int *status_out, char **body_out)
{
    return https_roundtrip(host, path, body, headers, false,
                           status_out, body_out);
}

bool https_get(const char *host, const char *path, int *status_out,
               char **body_out)
{
    return https_roundtrip(host, path, NULL, NULL, true,
                           status_out, body_out);
}
