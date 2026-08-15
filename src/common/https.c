#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
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

struct sbuf {
    char  *d;
    size_t len;
    size_t cap;
};

/* memmove, not memcpy: gcc >= 16 -Wrestrict cannot prove the caller
 * buffer does not alias the sbuf and errors on the (in practice
 * impossible) huge-length path. noinline: gcc 16's IPA then cannot
 * fold caller arguments into a -Wstringop-overflow false positive
 * either (observed on riscv64/i686 musl cross builds). */
#if defined(__GNUC__) && __GNUC__ >= 12
__attribute__((noinline))
#endif
static void sbuf_app(struct sbuf *s, const void *p, size_t n)
{
    if (n > SIZE_MAX - s->len - 1)
        oom_abort();   /* length overflow: no representable buffer */
    size_t need = s->len + n + 1;
    if (need > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 256;
        while (nc < need) {
            if (nc > SIZE_MAX / 2) {
                nc = need;
                break;
            }
            nc *= 2;
        }
        s->d = realloc(s->d, nc);
        if (!s->d)
            oom_abort();
        s->cap = nc;
    }
    /* memmove, not memcpy: gcc >= 16 -Wrestrict cannot prove the caller
     * buffer does not alias the sbuf and errors on the (in practice
     * impossible) huge-length path */
    memmove(s->d + s->len, p, n);
    s->len += n;
    s->d[s->len] = '\0';
}

static long hex_parse_sz(const char *s, size_t n)
{
    long v = 0;
    for (size_t i = 0; i < n; i++) {
        int h;
        char c = s[i];
        if (c >= '0' && c <= '9')
            h = c - '0';
        else if (c >= 'a' && c <= 'f')
            h = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            h = c - 'A' + 10;
        else
            return -1;
        if (v > (HTTPS_CHUNK_SZ_CAP - h) / 16)
            return -1;
        v = v * 16 + h;
    }
    return v;
}

/* Decode a chunked body into out. Returns 1 on success; 0 with *err set
 * when the stream is malformed (bad hex size, chunk overrunning the
 * buffer, or garbage after the terminal chunk). The caller reports the
 * failure instead of silently shipping a truncated body. */
static int chunk_decode(const char *in, size_t in_len, struct sbuf *out,
                        char *err, size_t errsz)
{
    size_t i = 0;
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
    if (!val.len)
        return NULL;
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

/* Split an absolute https:// URL into malloc'd host and path. Returns 1 on
   success; 0 when the URL is not an absolute https URL (other schemes,
   userinfo, or an explicit port are rejected). The authority ends at the
   first '/', '?' or '#': a query must never leak into the Host header. */
static int https_url_split(const char *url, char **host_out, char **path_out)
{
    static const char scheme[] = "https://";
    const char *auth, *slash, *at, *cut;
    size_t alen;

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
    at = memchr(auth, '@', alen);
    if (at) {
        /* strip userinfo; the host is what follows the last '@' */
        alen -= (size_t)(at + 1 - auth);
        auth = at + 1;
        if (alen == 0)
            return 0;
    }
    if (memchr(auth, ':', alen))
        return 0;   /* explicit port: unsupported */
    *host_out = malloc(alen + 1);
    if (!*host_out)
        oom_abort();
    memcpy(*host_out, auth, alen);
    (*host_out)[alen] = '\0';
    if (slash) {
        /* strip the fragment from the request path ('#' and beyond);
         * the query ('?') is part of the path */
        const char *frag = strchr(slash, '#');
        size_t plen = frag ? (size_t)(frag - slash) : strlen(slash);
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
 * is_get: GET with no Content-Length and no body; else POST. */
static void https_req_build(struct sbuf *req, const char *host,
                            const char *path, const char *body,
                            const char *const *headers, bool is_get)
{
    char cl[64];

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
    tv.tv_sec = (time_t)(ms / 1000);
    tv.tv_usec = (long)((ms % 1000) * 1000);
    return port_setsockopt(fd, SOL_SOCKET, opt, &tv, sizeof tv);
}

/* Load the CA trust anchors into ctx. Linux: SSL_CERT_FILE wins,
   otherwise the first of the usual per-distro bundle paths (the same
   candidates the fork-based transport handed to `openssl s_client
   -CAfile`); no usable bundle -> the historical "no CA bundle found"
   message. Windows: the system ROOT store via Crypt32. Returns 0 on
   success, -1 with the specific reason already logged. */
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

    if (ca && ca[0]) {
        /* trust the env var even if the file is unreadable; the load
         * below reports the failure */
    } else {
        ca = NULL;
        for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++)
            if (access(cands[i], R_OK) == 0) {
                ca = cands[i];
                break;
            }
    }
    if (!ca) {
        log_err("no CA bundle found: set SSL_CERT_FILE or install one of "
                "/etc/ssl/certs/ca-certificates.crt, "
                "/etc/pki/tls/certs/ca-bundle.crt, /etc/ssl/cert.pem, "
                "/etc/pki/tls/cacert.pem");
        return -1;
    }
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        char ebuf[256];

        https_ssl_err(ebuf, sizeof ebuf);
        log_err("HTTPS: cannot load CA bundle '%s': %s", ca, ebuf);
        return -1;
    }
    return 0;
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

/* One client TLS context with peer verification and CA loading. The
   context is created per exchange (https_transport) rather than cached:
   HTTPS round trips are rare (auth/OIDC), and per-exchange ownership
   keeps the Windows store enumeration and the OpenSSL state clear of
   static data and locking in a process that spawns threads elsewhere. */
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
        /* system store unusable: fall back to the bundled roots alone */
        log_err("HTTPS: system CA store unusable; using bundled fallback "
                "roots only");
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

/* Open a TCP connection to host:port. The connect is driven on a
   nonblocking socket with a POLLOUT wait (bounded by the remaining
   deadline), then the socket is switched back to blocking: from there
   on SO_RCVTIMEO / SO_SNDTIMEO bound every SSL read/write. Returns the
   fd, or -1 with a reason in diag. */
static int https_connect_tcp(const char *host, uint16_t port,
                             uint64_t deadline_ms,
                             char *diag, size_t diagsz)
{
    struct addrinfo hints, *res = NULL, *ai;
    char service[8];
    int gai, fd = -1;

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

    for (ai = res; ai; ai = ai->ai_next) {
        struct pollfd pfd;
        int pr = 0;

        if (now_ms() >= deadline_ms) {
            snprintf(diag, diagsz, "timed out connecting to %s", host);
            break;
        }
        fd = port_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
#ifdef _WIN32
            snprintf(diag, diagsz, "socket(family %d): wsa %d (errno %d)",
                     ai->ai_family, WSAGetLastError(), errno);
#endif
            continue;
        }
        if (port_set_nonblock(fd, true) != 0) {
#ifdef _WIN32
            snprintf(diag, diagsz, "ioctlsocket(FIONBIO): wsa %d (errno %d)",
                     WSAGetLastError(), errno);
#endif
            port_close(fd);
            fd = -1;
            continue;
        }
        if (port_connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            /* nonblocking connect: WSAEWOULDBLOCK -> EAGAIN on Windows,
             * EINPROGRESS on Linux; both mean "wait for POLLOUT" */
            if (errno != EINPROGRESS && errno != EAGAIN &&
                errno != EWOULDBLOCK) {
#ifdef _WIN32
                snprintf(diag, diagsz, "connect: wsa %d (errno %d)",
                         WSAGetLastError(), errno);
#endif
                port_close(fd);
                fd = -1;
                continue;
            }
            pfd.fd = fd;
            pfd.events = POLLOUT;
            for (;;) {
                uint64_t remain = deadline_ms - now_ms();
                int to = remain > HTTPS_POLL_MS ? (int)HTTPS_POLL_MS
                                                : (int)remain;

                pr = port_poll(&pfd, 1, to);
                if (pr >= 0 || errno != EINTR)
                    break;
            }
            if (pr == 0)
                errno = ETIMEDOUT;
            if (pr <= 0 || !(pfd.revents & POLLOUT)) {
#ifdef _WIN32
                snprintf(diag, diagsz,
                         "poll connect: pr=%d revents=0x%x wsa %d "
                         "(errno %d)",
                         pr, pfd.revents, WSAGetLastError(), errno);
#endif
                port_close(fd);
                fd = -1;
                continue;
            }
            {
                int soerr = 0;
                socklen_t slen = sizeof soerr;

                if (port_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr,
                                    &slen) != 0 ||
                    soerr != 0) {
                    if (soerr != 0)
                        errno = soerr;
#ifdef _WIN32
                    snprintf(diag, diagsz,
                             "connect SO_ERROR: soerr=%d wsa %d "
                             "(errno %d)",
                             soerr, WSAGetLastError(), errno);
#endif
                    port_close(fd);
                    fd = -1;
                    continue;
                }
            }
        }
        /* connected; back to blocking for the TLS exchange */
        if (port_set_nonblock(fd, false) != 0) {
            port_close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(res);

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

        if (now_ms() >= deadline_ms) {
            snprintf(diag, diagsz, "TLS handshake timed out");
            return -1;
        }
        remain = deadline_ms - now_ms();
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

            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                continue;   /* interrupted by the socket timeout */
            if (e == SSL_ERROR_SYSCALL) {
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

        if (now_ms() >= deadline_ms) {
            snprintf(diag, diagsz, "timed out sending request");
            return -1;
        }
        remain = deadline_ms - now_ms();
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

            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                continue;
            if (e == SSL_ERROR_SYSCALL) {
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
    size_t body_start = 0;

    for (;;) {
        uint64_t remain;
        int r;

        if (resp->len > HTTPS_MAX_RESP) {
            snprintf(diag, diagsz, "response exceeded %u MiB",
                     (unsigned)(HTTPS_MAX_RESP >> 20));
            return -1;
        }
        if (now_ms() >= deadline_ms) {
            snprintf(diag, diagsz, "timed out waiting for response");
            return -1;
        }
        remain = deadline_ms - now_ms();
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
                const char *he = sbuf_find(resp->d, resp->len, "\r\n\r\n", 4);
                size_t hesz = he ? 4 : 0;
                if (!he) {
                    he = sbuf_find(resp->d, resp->len, "\n\n", 2);
                    hesz = he ? 2 : 0;
                }
                if (he) {
                    body_start = (size_t)(he - resp->d) + hesz;
                    content_len =
                        https_content_length(resp->d, body_start);
                    if (content_len == 0)
                        return 0;   /* declared empty body */
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
                continue;   /* interrupted by the socket timeout */
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

/* Locate the start of the header lines and of the body in a response. */
static void https_hdr_body(const char *d, size_t len,
                           const char **hdr_start, const char **body)
{
    const char *h = strstr(d, "\r\n");
    if (!h)
        h = strstr(d, "\n");
    if (!h)
        h = d + len;
    else if (h[0] == '\r')
        h += 2;
    else
        h += 1;

    *body = strstr(d, "\r\n\r\n");
    if (*body)
        *body += 4;
    else {
        *body = strstr(d, "\n\n");
        if (*body)
            *body += 2;
        else
            *body = d + len;
    }
    *hdr_start = h;
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

    *status = https_resp_status(resp->d, resp->len);
    if (*status < 0) {
        free(resp->d);
        *body_out = empty_str();
        return 0;
    }

    https_hdr_body(resp->d, resp->len, &hdr_start, &body);
    hdr_len = (size_t)(body - hdr_start);
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
    char diag[512];
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    bool ok = false;

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

        ctx = https_ctx_new(fallback);
        if (!ctx) {
            /* CA problem: https_ctx_new already logged the specific
             * reason (missing bundle on Linux, empty ROOT store on
             * Windows). A broken/empty system store still gets one
             * attempt with the bundled fallback roots. */
            if (!fallback) {
                log_info("HTTPS: system CA store unusable; retrying "
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
                    SSL_CTX_free(ctx);
                    port_close(fd);
                    ssl = NULL;
                    ctx = NULL;
                    fd = -1;
                    continue;
                }
                goto out;
            }
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
    free(req->d);
    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
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

        https_req_build(&req, cur_host, cur_path, body, cur_headers, is_get);
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

            if (follow) {
                const char *hs, *bd;
                https_hdr_body(resp.d, resp.len, &hs, &bd);
                loc = https_hdr_value(hs, (size_t)(bd - hs), "location");
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
                /* cross-host hop: drop the Authorization header */
                if (strcmp(new_host, cur_host) != 0 && cur_headers) {
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
