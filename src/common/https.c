#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "https.h"
#include "util.h"

/* hard ceilings for one response read: whole-transfer size and the whole
 * round-trip time (redirect hops included), plus the poll granularity used
 * to enforce them */
#define HTTPS_POLL_MS       25000
#define HTTPS_TIMEOUT_MS    60000
#define HTTPS_MAX_RESP      (16u * 1024 * 1024)
#define HTTPS_MAX_REDIRECTS 5

struct sbuf {
    char  *d;
    size_t len;
    size_t cap;
};

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
    memcpy(s->d + s->len, p, n);
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
        if (v > (0x7FFFFFFFL - h) / 16)
            return -1;
        v = v * 16 + h;
    }
    return v;
}

static void chunk_decode(const char *in, size_t in_len, struct sbuf *out)
{
    size_t i = 0;
    while (i < in_len) {
        size_t j = i;
        long sz;
        while (j < in_len && in[j] != '\r' && in[j] != '\n' && in[j] != ';')
            j++;
        sz = hex_parse_sz(in + i, j - i);
        if (sz < 0)
            break;
        while (j < in_len && in[j] != '\r' && in[j] != '\n')
            j++;
        while (j < in_len && (in[j] == '\r' || in[j] == '\n'))
            j++;
        if (sz == 0)
            break;
        if ((size_t)sz > in_len - j)
            break;
        sbuf_app(out, in + j, (size_t)sz);
        j += (size_t)sz;
        while (j < in_len && (in[j] == '\r' || in[j] == '\n'))
            j++;
        i = j;
    }
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
            strncasecmp(line, name, nl) == 0) {
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
            strncasecmp(p, chunked, sizeof chunked - 1) == 0)
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
   userinfo, or an explicit port are rejected). */
static int https_url_split(const char *url, char **host_out, char **path_out)
{
    static const char scheme[] = "https://";
    const char *auth, *slash, *at;
    size_t alen;

    for (size_t i = 0; i < sizeof scheme - 1; i++)
        if (tolower((unsigned char)url[i]) != scheme[i])
            return 0;
    auth = url + sizeof scheme - 1;
    slash = strchr(auth, '/');
    alen = slash ? (size_t)(slash - auth) : strlen(auth);
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
    *path_out = xstrdup(slash ? slash : "/");
    return 1;
}

static char *empty_str(void)
{
    char *s = malloc(1);
    if (!s)
        oom_abort();
    s[0] = '\0';
    return s;
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
    snprintf(cl, sizeof cl, "Content-Length: %zu", strlen(body));
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

/* Resolve the CA bundle to hand to openssl s_client: SSL_CERT_FILE wins,
   otherwise the first of the common per-distro locations that exists,
   else NULL. */
static const char *https_ca_path(void)
{
    static const char *const cands[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/cacert.pem",
    };
    const char *env = getenv("SSL_CERT_FILE");

    if (env && env[0])
        return env;
    for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++)
        if (access(cands[i], R_OK) == 0)
            return cands[i];
    return NULL;
}

/* Fork `openssl s_client` with stdin/stdout wired to the pipes;
   returns the child pid, or -1 on failure. */
static pid_t https_spawn_client(const char *host, int in_pipe[2],
                                int out_pipe[2])
{
    char connect_arg[1024];
    pid_t pid;
    const char *ca_path = https_ca_path();

    if (!ca_path) {
        log_err("no CA bundle found: set SSL_CERT_FILE or install one of "
                "/etc/ssl/certs/ca-certificates.crt, "
                "/etc/pki/tls/certs/ca-bundle.crt, /etc/ssl/cert.pem, "
                "/etc/pki/tls/cacert.pem");
        return -1;
    }

    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0)
        return -1;

    pid = fork();
    if (pid < 0) {
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        exec_sanitize();
        int devnull;
        close(in_pipe[1]);
        close(out_pipe[0]);
        if (dup2(in_pipe[0], 0) < 0 || dup2(out_pipe[1], 1) < 0)
            _exit(127);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 2);
            if (devnull > 2)
                close(devnull);
        }
        snprintf(connect_arg, sizeof connect_arg, "%s:443", host);
        execlp("openssl", "openssl", "s_client", "-quiet", "-connect",
               connect_arg, "-servername", host,
               "-verify_hostname", host,
               "-verify_return_error",
               "-CAfile", ca_path,
               (char *)NULL);
        _exit(127);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);
    return pid;
}

/* Write the assembled request into the child's stdin pipe, then close it. */
static void https_req_pump(int in_fd, const char *req, size_t req_len)
{
    size_t off = 0;

    /* the child (openssl s_client) may exit before consuming the request
     * (e.g. TLS handshake failure): a dying pipe must surface EPIPE on the
     * write, not kill us with the default SIGPIPE disposition (pipes have
     * no MSG_NOSIGNAL, so ignore the signal instead). Restore the old
     * disposition before returning: callers may rely on SIGPIPE. */
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);

    while (off < req_len) {
        ssize_t w = write(in_fd, req + off, req_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        off += (size_t)w;
    }
    close(in_fd);
    signal(SIGPIPE, old_pipe);
}

/* Read the child's stdout until EOF, timeout, or error; on timeout or
   runaway response size SIGKILL the child; reap it. Returns 1 if
   failed (timeout, oversized response, or a child that exited without
   producing any response), else 0. deadline_ms bounds the whole
   round-trip (redirect hops included). */
static int https_resp_read(int out_fd, pid_t pid, struct sbuf *resp,
                           uint64_t deadline_ms)
{
    struct pollfd pfd;
    int timed_out = 0;

    pfd.fd = out_fd;
    pfd.events = POLLIN;
    for (;;) {
        uint64_t now = now_ms();
        int pr;
        char buf[4096];
        ssize_t r;

        /* hard ceilings for the whole transfer: size (16 MiB) and the
         * round-trip deadline, checked before polling so an overrun cannot
         * ride out a full poll interval */
        if (resp->len > HTTPS_MAX_RESP || now >= deadline_ms) {
            timed_out = 1;
            break;
        }
        /* poll no longer than the remaining budget */
        {
            uint64_t remain = deadline_ms - now;
            int to = remain > HTTPS_POLL_MS ? (int)HTTPS_POLL_MS
                                            : (int)remain;
            pr = poll(&pfd, 1, to);
        }
        if (pr == 0) {
            timed_out = 1;
            break;
        }
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            timed_out = 1;
            break;
        }
        r = read(out_fd, buf, sizeof buf);
        if (r == 0)
            break;
        if (r > 0) {
            sbuf_app(resp, buf, (size_t)r);
            continue;
        }
        if (errno != EINTR) {
            timed_out = 1;
            break;
        }
    }
    if (timed_out)
        kill(pid, SIGKILL);
    {
        int wst = 0;
        while (waitpid(pid, &wst, 0) < 0 && errno == EINTR)
            ;
        /* a child that died without emitting a response (e.g. failed
         * TLS handshake) is a failure; once bytes arrived the response
         * stands on its own and the exit code is irrelevant */
        if (!timed_out && resp->len == 0 &&
            ((WIFEXITED(wst) && WEXITSTATUS(wst) != 0) || WIFSIGNALED(wst)))
            timed_out = 1;
    }
    close(out_fd);
    return timed_out;
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
        chunk_decode(body, resp->len - (size_t)(body - resp->d), &dec);
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

/* One request/response exchange with a fresh openssl s_client: spawn,
   pump the request, read the raw response (deadline-bounded). Returns 1 on
   success with *resp holding the raw bytes (caller parses), else 0. */
static bool https_transport(const char *host, struct sbuf *req,
                            struct sbuf *resp, uint64_t deadline_ms)
{
    int in_pipe[2], out_pipe[2];
    pid_t pid;

    pid = https_spawn_client(host, in_pipe, out_pipe);
    if (pid < 0) {
        free(req->d);
        return false;
    }

    https_req_pump(in_pipe[1], req->d, req->len);
    free(req->d);

    if (https_resp_read(out_pipe[0], pid, resp, deadline_ms) ||
        resp->len == 0) {
        free(resp->d);
        return false;
    }
    return true;
}

/* shared transport for the JSON request builders below: follows redirect
   chains (301/302/303/307/308 with an absolute https:// Location, at most
   HTTPS_MAX_REDIRECTS hops) inside one round-trip time budget */
static bool https_roundtrip(const char *host, const char *path,
                            const char *body, const char *const *headers,
                            bool is_get, int *status_out, char **body_out)
{
    char *cur_host = xstrdup(host);
    char *cur_path = xstrdup(path);
    uint64_t deadline = now_ms() + HTTPS_TIMEOUT_MS;
    int status = 0;
    int failed = 0;

    if (status_out)
        *status_out = 0;

    for (int hop = 0; hop <= HTTPS_MAX_REDIRECTS; hop++) {
        struct sbuf req = {0}, resp = {0};
        int st;

        if (now_ms() >= deadline) {
            log_err("HTTPS round-trip timed out (redirect hops included)");
            failed = 1;
            break;
        }

        https_req_build(&req, cur_host, cur_path, body, headers, is_get);
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
                    free(new_host);
                    free(new_path);
                    failed = 1;
                    break;
                }
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
     * redirects */
    if (!failed)
        log_err("HTTPS redirect limit (%d) exceeded", HTTPS_MAX_REDIRECTS);
    free(cur_host);
    free(cur_path);
    if (status_out)
        *status_out = status;
    *body_out = empty_str();
    return false;
}

bool https_post_json(const char *host, const char *path,
                     const char *body,
                     const char *const *headers,
                     int *status_out, char **body_out)
{
    return https_roundtrip(host, path, body, headers, false,
                           status_out, body_out);
}

bool https_get_json(const char *host, const char *path, int *status_out,
                    char **body_out)
{
    return https_roundtrip(host, path, NULL, NULL, true,
                           status_out, body_out);
}
