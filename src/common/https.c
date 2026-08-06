#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "https.h"

struct sbuf {
    char  *d;
    size_t len;
    size_t cap;
};

static void sbuf_app(struct sbuf *s, const void *p, size_t n)
{
    if (s->len + n + 1 > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 256;
        while (nc < s->len + n + 1)
            nc *= 2;
        s->d = realloc(s->d, nc);
        s->cap = nc;
    }
    memcpy(s->d + s->len, p, n);
    s->len += n;
    s->d[s->len] = '\0';
}

static int region_has_ci(const char *base, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    if (n < nl)
        return 0;
    for (size_t i = 0; i + nl <= n; i++) {
        size_t j;
        for (j = 0; j < nl; j++)
            if (tolower((unsigned char)base[i + j]) !=
                tolower((unsigned char)needle[j]))
                break;
        if (j == nl)
            return 1;
    }
    return 0;
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

static char *empty_str(void)
{
    char *s = malloc(1);
    s[0] = '\0';
    return s;
}

/* Assemble the POST request (request line, headers, body) into *req. */
static void https_req_build(struct sbuf *req, const char *host,
                            const char *path, const char *body,
                            const char *const *headers)
{
    char cl[64];

    if (!body)
        body = "";
    snprintf(cl, sizeof cl, "Content-Length: %zu", strlen(body));
    sbuf_app(req, "POST ", 5);
    sbuf_app(req, path, strlen(path));
    sbuf_app(req, " HTTP/1.1\r\nHost: ", 17);
    sbuf_app(req, host, strlen(host));
    sbuf_app(req, "\r\nConnection: close\r\n", 21);
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            sbuf_app(req, headers[i], strlen(headers[i]));
            sbuf_app(req, "\r\n", 2);
        }
    }
    sbuf_app(req, cl, strlen(cl));
    sbuf_app(req, "\r\n\r\n", 4);
    sbuf_app(req, body, strlen(body));
}

/* Fork `openssl s_client` with stdin/stdout wired to the pipes;
   returns the child pid, or -1 on failure. */
static pid_t https_spawn_client(const char *host, int in_pipe[2],
                                int out_pipe[2])
{
    char connect_arg[1024];
    pid_t pid;

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
               "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
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
}

/* Read the child's stdout until EOF, timeout, or error; on timeout
   SIGKILL the child; reap it. Returns 1 if timed out, else 0. */
static int https_resp_read(int out_fd, pid_t pid, struct sbuf *resp)
{
    struct pollfd pfd;
    int timed_out = 0;

    pfd.fd = out_fd;
    pfd.events = POLLIN;
    for (;;) {
        int pr = poll(&pfd, 1, 25000);
        char buf[4096];
        ssize_t r;
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
        int wst;
        while (waitpid(pid, &wst, 0) < 0 && errno == EINTR)
            ;
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

/* Parse the HTTP status line and body (chunk-decoded if needed) out of
   the raw response; frees resp. Returns 1 on success, else 0. */
static int https_resp_parse(struct sbuf *resp, int *status, char **body_out)
{
    char *p = resp->d;
    const char *hdr_start, *body;
    char *end;
    long code;
    size_t hdr_len;
    int chunked;
    char *out;

    while (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t')
        p++;
    if (strncmp(p, "HTTP/1.", 7) != 0) {
        free(resp->d);
        *body_out = empty_str();
        return 0;
    }
    p = strchr(p, ' ');
    if (!p) {
        free(resp->d);
        *body_out = empty_str();
        return 0;
    }
    code = strtol(p + 1, &end, 10);
    if (end == p + 1 || code < 100 || code > 999) {
        free(resp->d);
        *body_out = empty_str();
        return 0;
    }
    *status = (int)code;

    https_hdr_body(resp->d, resp->len, &hdr_start, &body);
    hdr_len = (size_t)(body - hdr_start);
    chunked = region_has_ci(hdr_start, hdr_len, "transfer-encoding") &&
              region_has_ci(hdr_start, hdr_len, "chunked");

    if (chunked) {
        struct sbuf dec = {0};
        chunk_decode(body, resp->len - (size_t)(body - resp->d), &dec);
        out = dec.d ? dec.d : empty_str();
    } else {
        size_t blen = resp->len - (size_t)(body - resp->d);
        out = malloc(blen + 1);
        memcpy(out, body, blen);
        out[blen] = '\0';
    }
    free(resp->d);
    *body_out = out;
    return 1;
}

bool https_post_json(const char *host, const char *path,
                     const char *body,
                     const char *const *headers,
                     int *status_out, char **body_out)
{
    struct sbuf req = {0};
    struct sbuf resp = {0};
    int in_pipe[2], out_pipe[2];
    pid_t pid;
    int status = 0;

    if (status_out)
        *status_out = 0;

    https_req_build(&req, host, path, body, headers);

    pid = https_spawn_client(host, in_pipe, out_pipe);
    if (pid < 0) {
        free(req.d);
        *body_out = empty_str();
        return false;
    }

    https_req_pump(in_pipe[1], req.d, req.len);
    free(req.d);

    if (https_resp_read(out_pipe[0], pid, &resp) || resp.len == 0) {
        free(resp.d);
        *body_out = empty_str();
        return false;
    }

    if (!https_resp_parse(&resp, &status, body_out))
        return false;

    if (status_out)
        *status_out = status;
    return true;
}
