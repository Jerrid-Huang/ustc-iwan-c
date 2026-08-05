#include "common.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void buf_clear(buf_t *b)
{
    b->len = 0;
}

void buf_ensure(buf_t *b, size_t extra)
{
    size_t need = b->len + extra;
    if (need >= b->len && need <= b->cap)
        return;
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2) {
            ncap = need;
            break;
        }
        ncap *= 2;
    }
    b->data = realloc(b->data, ncap);
    b->cap = ncap;
}

void buf_put(buf_t *b, const void *p, size_t n)
{
    if (n == 0)
        return;
    buf_ensure(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void buf_put_u8(buf_t *b, uint8_t v)
{
    buf_put(b, &v, 1);
}

void buf_put_be16(buf_t *b, uint16_t v)
{
    uint8_t tmp[2];
    tmp[0] = (uint8_t)(v >> 8);
    tmp[1] = (uint8_t)v;
    buf_put(b, tmp, 2);
}

void buf_put_be32(buf_t *b, uint32_t v)
{
    uint8_t tmp[4];
    tmp[0] = (uint8_t)(v >> 24);
    tmp[1] = (uint8_t)(v >> 16);
    tmp[2] = (uint8_t)(v >> 8);
    tmp[3] = (uint8_t)v;
    buf_put(b, tmp, 4);
}

void buf_put_str(buf_t *b, const char *s)
{
    buf_put(b, s, strlen(s));
}

void buf_consume(buf_t *b, size_t n)
{
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void slist_init(slist_t *s)
{
    s->v = NULL;
    s->n = 0;
    s->cap = 0;
}

void slist_free(slist_t *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    s->v = NULL;
    s->n = 0;
    s->cap = 0;
}

void slist_push(slist_t *s, const char *str)
{
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 4;
        s->v = realloc(s->v, ncap * sizeof(char *));
        s->cap = ncap;
    }
    s->v[s->n++] = xstrdup(str);
}

void slist_push_csv(slist_t *s, const char *csv)
{
    const char *p = csv;
    while (*p) {
        while (*p == ',')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ',')
            p++;
        const char *end = p;
        while (end > start && isspace((unsigned char)end[-1]))
            end--;
        while (start < end && isspace((unsigned char)*start))
            start++;
        if (start < end) {
            size_t n = (size_t)(end - start);
            char *piece = malloc(n + 1);
            memcpy(piece, start, n);
            piece[n] = '\0';
            slist_push(s, piece);
            free(piece);
        }
    }
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    memcpy(out, s, n);
    return out;
}

uint32_t rand_u32(void)
{
    uint32_t v;
    if (getrandom(&v, sizeof(v), 0) == (ssize_t)sizeof(v))
        return v;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&v, 1, sizeof(v), f) == sizeof(v)) {
            fclose(f);
            return v;
        }
        fclose(f);
    }
    v = (uint32_t)((uintptr_t)&v ^ (uintptr_t)time(NULL) ^ (uintptr_t)getpid());
    return v;
}

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int parse_uint(const char *s, uint64_t max, uint64_t *out)
{
    if (!s || !*s)
        return -1;
    const char *p = s;
    while (*p) {
        if (*p < '0' || *p > '9')
            return -1;
        p++;
    }
    uint64_t v = 0;
    for (p = s; *p; p++) {
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (max - d) / 10)
            return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

int str_to_u16(const char *s, uint16_t *out)
{
    uint64_t v;
    if (parse_uint(s, UINT16_MAX, &v) != 0)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

int str_to_u8(const char *s, uint8_t *out)
{
    uint64_t v;
    if (parse_uint(s, UINT8_MAX, &v) != 0)
        return -1;
    *out = (uint8_t)v;
    return 0;
}

const char *unbracket_ipv6(const char *s, char *buf, size_t n)
{
    if (s[0] == '[') {
        size_t len = strlen(s);
        if (len >= 3 && s[len - 1] == ']' && len - 2 < n) {
            memcpy(buf, s + 1, len - 2);
            buf[len - 2] = '\0';
            return buf;
        }
    }
    return s;
}