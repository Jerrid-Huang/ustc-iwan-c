#include "common.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
    size_t ncap;
    if (!grow_cap(b->len, extra, b->cap, 64, 1, &ncap))
        oom_abort();   /* length overflow: no representable buffer */
    if (ncap == b->cap)
        return;
    b->data = realloc(b->data, ncap);
    if (!b->data)
        oom_abort();
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
