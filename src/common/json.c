#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "util.h"

/* recursion guard: nesting deeper than this is rejected at parse time
 * and abandoned at free time, so hostile input cannot overflow the C
 * stack (one C frame per nesting level) */
#define JSON_MAX_DEPTH 256

struct Json {
    int type;
    union {
        double num;
        char  *str;
        int    boolean;
        struct {
            Json **arr;
            size_t len;
            size_t cap;
        } a;
        struct {
            struct {
                char *key;
                Json *val;
            } *items;
            size_t len;
            size_t cap;
        } o;
    } u;
};

struct P {
    const char *start, *s, *end;
    char err[128];   /* serde-style error, set on failure */
};

static void p_fail(struct P *p, size_t off, int eof, const char *msg)
{
    /* serde position: (offending byte)+1, or input length at EOF */
    size_t i = eof ? (size_t)(p->end - p->start)
                   : (size_t)(p->s - p->start) + off + 1;
    size_t line = 1, col, last_nl = (size_t)-1;
    for (size_t k = 0; k < i; k++)
        if (p->start[k] == '\n') {
            line++;
            last_nl = k;
        }
    col = last_nl == (size_t)-1 ? i : i - last_nl - 1;
    snprintf(p->err, sizeof p->err, "%s at line %zu column %zu", msg, line,
             col);
}

struct jbuf {
    char  *d;
    size_t len;
    size_t cap;
};

static void jbuf_app(struct jbuf *b, const void *p, size_t n)
{
    if (n > SIZE_MAX - b->len - 1)
        oom_abort();   /* length overflow: no representable buffer */
    size_t need = b->len + n + 1;
    if (need > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 64;
        while (nc < need) {
            if (nc > SIZE_MAX / 2) {
                nc = need;
                break;
            }
            nc *= 2;
        }
        b->d = realloc(b->d, nc);
        if (!b->d)
            oom_abort();
        b->cap = nc;
    }
    memcpy(b->d + b->len, p, n);
    b->len += n;
    b->d[b->len] = '\0';
}

static Json *parse_value(struct P *p, int depth);

static void skip_ws(struct P *p)
{
    while (isspace((unsigned char)p->s[0]))
        p->s++;
}

static int hex4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h;
        char c = s[i];
        if (c >= '0' && c <= '9')
            h = c - '0';
        else if (c >= 'a' && c <= 'f')
            h = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            h = c - 'A' + 10;
        else
            return 0;
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return 1;
}

static size_t utf8_encode(uint32_t cp, uint8_t out[4])
{
    if (cp < 0x80) {
        out[0] = (uint8_t)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (uint8_t)(0xC0 | (cp >> 6));
        out[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            out[0] = '?';
            return 1;
        }
        out[0] = (uint8_t)(0xE0 | (cp >> 12));
        out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (uint8_t)(0xF0 | (cp >> 18));
    out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

static Json *parse_string(struct P *p)
{
    struct jbuf b = {0};
    Json *j;

    p->s++; /* '"' */
    for (;;) {
        unsigned char c = (unsigned char)p->s[0];
        if (c == '\0') {
            p_fail(p, 0, 1, "EOF while parsing a string");
            free(b.d);
            return NULL;
        }
        if (c == '"') {
            p->s++;
            break;
        }
        if (c == '\\') {
            char e = p->s[1];
            unsigned char map;
            switch (e) {
            case '"':
                jbuf_app(&b, "\"", 1);
                p->s += 2;
                break;
            case '\\':
                jbuf_app(&b, "\\", 1);
                p->s += 2;
                break;
            case '/':
                jbuf_app(&b, "/", 1);
                p->s += 2;
                break;
            case 'b':
                map = '\b';
                jbuf_app(&b, &map, 1);
                p->s += 2;
                break;
            case 'f':
                map = '\f';
                jbuf_app(&b, &map, 1);
                p->s += 2;
                break;
            case 'n':
                map = '\n';
                jbuf_app(&b, &map, 1);
                p->s += 2;
                break;
            case 'r':
                map = '\r';
                jbuf_app(&b, &map, 1);
                p->s += 2;
                break;
            case 't':
                map = '\t';
                jbuf_app(&b, &map, 1);
                p->s += 2;
                break;
            case 'u': {
                uint32_t cp = 0;
                uint8_t enc[4];
                size_t elen;
                int bad = 0, eof = 0;
                /* serde reads 4 chars; EOF on the 4th read -> EOF error,
                 * any non-hex -> invalid escape; position is always the end */
                for (int k = 0; k < 4; k++) {
                    unsigned char h = (unsigned char)p->s[2 + k];
                    if (h == '\0') {
                        eof = 1;
                        break;
                    }
                    if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                          (h >= 'A' && h <= 'F')))
                        bad = 1;
                }
                if (eof) {
                    p_fail(p, 0, 1, "EOF while parsing a string");
                    free(b.d);
                    return NULL;
                }
                if (bad) {
                    /* position = right after the 4-char hex window */
                    p_fail(p, 5, 0, "invalid escape");
                    free(b.d);
                    return NULL;
                }
                hex4(p->s + 2, &cp);
                /* a high surrogate (U+D800-U+DBFF) must be immediately
                 * followed by a \uXXXX low surrogate (U+DC00-U+DFFF) to
                 * spell one supplementary code point; merge the pair into
                 * a single code point and consume both escapes. An
                 * isolated high/low surrogate falls through and is
                 * rendered as '?' by utf8_encode. */
                if (cp >= 0xD800 && cp <= 0xDBFF &&
                    p->s[6] == '\\' && p->s[7] == 'u') {
                    uint32_t lo = 0;
                    int lbad = 0, leof = 0;
                    for (int k = 0; k < 4; k++) {
                        unsigned char h = (unsigned char)p->s[8 + k];
                        if (h == '\0') {
                            leof = 1;
                            break;
                        }
                        if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                              (h >= 'A' && h <= 'F')))
                            lbad = 1;
                    }
                    if (leof) {
                        p_fail(p, 0, 1, "EOF while parsing a string");
                        free(b.d);
                        return NULL;
                    }
                    if (!lbad) {
                        hex4(p->s + 8, &lo);
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) +
                                 (lo - 0xDC00);
                            elen = utf8_encode(cp, enc);
                            jbuf_app(&b, enc, elen);
                            p->s += 12; /* consumed both escapes */
                            break;
                        }
                    }
                    /* not a low surrogate: leave \uXXXX for the next loop
                     * iteration, so the pair-decoding only ever goes
                     * forward */
                }
                elen = utf8_encode(cp, enc);
                jbuf_app(&b, enc, elen);
                p->s += 6;
                break;
            }
            case '\0':
                p_fail(p, 0, 1, "EOF while parsing a string");
                free(b.d);
                return NULL;
            default:
                p_fail(p, 1, 0, "invalid escape");
                free(b.d);
                return NULL;
            }
        } else if (c < 0x20) {
            p_fail(p, 0, 0,
                   "control character (\\u0000-\\u001F) found while parsing a string");
            free(b.d);
            return NULL;
        } else {
            jbuf_app(&b, p->s, 1);
            p->s++;
        }
    }

    j = calloc(1, sizeof *j);
    if (!j)
        oom_abort();
    j->type = JSON_STR;
    if (!b.d) {
        b.d = calloc(1, 1);
        if (!b.d)
            oom_abort();
    }
    j->u.str = b.d;
    return j;
}

static Json *parse_number(struct P *p)
{
    const char *start = p->s;
    double d;
    Json *j;

    if (p->s[0] == '-') {
        p->s++;
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing a value");
            return NULL;
        }
        if (p->s[0] < '0' || p->s[0] > '9') {
            p_fail(p, 0, 0, "invalid number");
            return NULL;
        }
    }
    if (p->s[0] == '0') {
        p->s++;
        if (p->s[0] >= '0' && p->s[0] <= '9') {
            p_fail(p, 0, 0, "invalid number");
            return NULL;
        }
    } else {
        while (p->s[0] >= '0' && p->s[0] <= '9')
            p->s++;
    }
    if (p->s[0] == '.') {
        p->s++;
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing a value");
            return NULL;
        }
        if (p->s[0] < '0' || p->s[0] > '9') {
            p_fail(p, 0, 0, "invalid number");
            return NULL;
        }
        while (p->s[0] >= '0' && p->s[0] <= '9')
            p->s++;
    }
    if (p->s[0] == 'e' || p->s[0] == 'E') {
        p->s++;
        if (p->s[0] == '+' || p->s[0] == '-')
            p->s++;
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing a value");
            return NULL;
        }
        if (p->s[0] < '0' || p->s[0] > '9') {
            p_fail(p, 0, 0, "invalid number");
            return NULL;
        }
        while (p->s[0] >= '0' && p->s[0] <= '9')
            p->s++;
    }

    /* strict grammar validated the span; convert from a copy so strtod's
     * hex/NaN extensions cannot consume beyond it */
    size_t n = (size_t)(p->s - start);
    if (n >= 128) {
        p->s = start;   /* report at the number's start, not at EOF */
        p_fail(p, 0, 0, "number out of range");
        return NULL;
    }
    char tmp[128];
    memcpy(tmp, start, n);
    tmp[n] = '\0';
    /* e.g. 1e999 is grammatically legal but overflows a double; reject the
     * value instead of storing +-inf (or 0 on underflow) */
    errno = 0;
    d = strtod(tmp, NULL);
    if (errno == ERANGE) {
        p_fail(p, 0, 0, "number out of range");
        return NULL;
    }
    j = calloc(1, sizeof *j);
    if (!j)
        oom_abort();
    j->type = JSON_NUM;
    j->u.num = d;
    return j;
}

static Json *parse_array(struct P *p, int depth)
{
    Json *arr;
    int after_comma = 0;

    p->s++; /* '[' */
    arr = calloc(1, sizeof *arr);
    if (!arr)
        oom_abort();
    arr->type = JSON_ARR;
    for (;;) {
        Json *v;
        skip_ws(p);
        if (p->s[0] == ']') {
            if (after_comma) {
                p_fail(p, 0, 0, "trailing comma");
                json_free(arr);
                return NULL;
            }
            p->s++;
            return arr;
        }
        if (!p->s[0]) {
            p_fail(p, 0, 1, after_comma ? "EOF while parsing a value"
                                        : "EOF while parsing a list");
            json_free(arr);
            return NULL;
        }
        v = parse_value(p, depth + 1);
        if (!v) {
            json_free(arr);
            return NULL;
        }
        if (arr->u.a.len == arr->u.a.cap) {
            size_t nc = arr->u.a.cap ? arr->u.a.cap * 2 : 8;
            /* guard the *2 and the byte-size multiply at the size ceiling */
            if (nc < arr->u.a.cap || nc > SIZE_MAX / sizeof(Json *)) {
                if (arr->u.a.len == SIZE_MAX)
                    oom_abort();
                nc = arr->u.a.len + 1;
            }
            arr->u.a.arr = realloc(arr->u.a.arr, nc * sizeof(Json *));
            if (!arr->u.a.arr)
                oom_abort();
            arr->u.a.cap = nc;
        }
        arr->u.a.arr[arr->u.a.len++] = v;
        after_comma = 0;
        skip_ws(p);
        if (p->s[0] == ',') {
            p->s++;
            after_comma = 1;
            continue;
        }
        if (p->s[0] == ']') {
            p->s++;
            return arr;
        }
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing a list");
            json_free(arr);
            return NULL;
        }
        p_fail(p, 0, 0, "expected `,` or `]`");
        json_free(arr);
        return NULL;
    }
}

static Json *parse_object(struct P *p, int depth)
{
    Json *obj;
    int after_comma = 0;

    p->s++; /* '{' */
    obj = calloc(1, sizeof *obj);
    if (!obj)
        oom_abort();
    obj->type = JSON_OBJ;
    for (;;) {
        Json *ks, *v;
        skip_ws(p);
        if (p->s[0] == '}') {
            if (after_comma) {
                p_fail(p, 0, 0, "trailing comma");
                json_free(obj);
                return NULL;
            }
            p->s++;
            return obj;
        }
        if (!p->s[0]) {
            p_fail(p, 0, 1, after_comma ? "EOF while parsing a value"
                                        : "EOF while parsing an object");
            json_free(obj);
            return NULL;
        }
        if (p->s[0] != '"') {
            p_fail(p, 0, 0, "key must be a string");
            json_free(obj);
            return NULL;
        }
        ks = parse_string(p);
        if (!ks) {
            json_free(obj);
            return NULL;
        }
        after_comma = 0;
        skip_ws(p);
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing an object");
            json_free(ks);
            json_free(obj);
            return NULL;
        }
        if (p->s[0] != ':') {
            p_fail(p, 0, 0, "expected `:`");
            json_free(ks);
            json_free(obj);
            return NULL;
        }
        p->s++;
        v = parse_value(p, depth + 1);
        if (!v) {
            json_free(ks);
            json_free(obj);
            return NULL;
        }
        if (obj->u.o.len == obj->u.o.cap) {
            size_t nc = obj->u.o.cap ? obj->u.o.cap * 2 : 8;
            /* guard the *2 and the byte-size multiply at the size ceiling */
            if (nc < obj->u.o.cap ||
                nc > SIZE_MAX / sizeof *obj->u.o.items) {
                if (obj->u.o.len == SIZE_MAX)
                    oom_abort();
                nc = obj->u.o.len + 1;
            }
            obj->u.o.items = realloc(obj->u.o.items, nc * sizeof *obj->u.o.items);
            if (!obj->u.o.items)
                oom_abort();
            obj->u.o.cap = nc;
        }
        obj->u.o.items[obj->u.o.len].key = ks->u.str;
        obj->u.o.items[obj->u.o.len].val = v;
        obj->u.o.len++;
        free(ks);
        skip_ws(p);
        if (p->s[0] == ',') {
            p->s++;
            after_comma = 1;
            continue;
        }
        if (p->s[0] == '}') {
            p->s++;
            return obj;
        }
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing an object");
            json_free(obj);
            return NULL;
        }
        p_fail(p, 0, 0, "expected `,` or `}`");
        json_free(obj);
        return NULL;
    }
}

static Json *parse_lit(struct P *p, const char *lit, int type, int val)
{
    for (const char *l = lit; *l; l++) {
        if (!p->s[0]) {
            p_fail(p, 0, 1, "EOF while parsing a value");
            return NULL;
        }
        if (p->s[0] != *l) {
            p_fail(p, 0, 0, "expected ident");
            return NULL;
        }
        p->s++;
    }
    Json *j = calloc(1, sizeof *j);
    if (!j)
        oom_abort();
    j->type = type;
    if (type == JSON_BOOL)
        j->u.boolean = val;
    return j;
}

static Json *parse_value(struct P *p, int depth)
{
    skip_ws(p);
    if (depth > JSON_MAX_DEPTH) {
        p_fail(p, 0, 0, "maximum depth exceeded");
        return NULL;
    }
    if (!p->s[0]) {
        p_fail(p, 0, 1, "EOF while parsing a value");
        return NULL;
    }
    if (p->s[0] == '{')
        return parse_object(p, depth);
    if (p->s[0] == '[')
        return parse_array(p, depth);
    if (p->s[0] == '"')
        return parse_string(p);
    if (p->s[0] == 't')
        return parse_lit(p, "true", JSON_BOOL, 1);
    if (p->s[0] == 'f')
        return parse_lit(p, "false", JSON_BOOL, 0);
    if (p->s[0] == 'n')
        return parse_lit(p, "null", JSON_NULL, 0);
    if (p->s[0] == '-' || (p->s[0] >= '0' && p->s[0] <= '9'))
        return parse_number(p);
    p_fail(p, 0, 0, "expected value");
    return NULL;
}

Json *json_parse_ex(const char *text, char *err, size_t errsz)
{
    struct P p;
    Json *v;

    p.start = text;
    p.s = text;
    p.end = text + strlen(text);
    p.err[0] = '\0';
    v = parse_value(&p, 0);
    if (!v) {
        if (err && errsz)
            snprintf(err, errsz, "%s", p.err);
        return NULL;
    }
    skip_ws(&p);
    if (p.s[0] != '\0') {
        p_fail(&p, 0, 0, "trailing characters");
        json_free(v);
        if (err && errsz)
            snprintf(err, errsz, "%s", p.err);
        return NULL;
    }
    return v;
}

Json *json_parse(const char *text)
{
    return json_parse_ex(text, NULL, 0);
}

static void json_free_d(Json *j, int depth)
{
    if (!j)
        return;
    if (depth > JSON_MAX_DEPTH)
        return;   /* abandoned subtree: parser never builds this deep, so
                   * bailing here only guards hand-built trees from a stack
                   * overflow instead of leaking reachable memory */
    switch (j->type) {
    case JSON_STR:
        free(j->u.str);
        break;
    case JSON_ARR:
        for (size_t i = 0; i < j->u.a.len; i++)
            json_free_d(j->u.a.arr[i], depth + 1);
        free(j->u.a.arr);
        break;
    case JSON_OBJ:
        for (size_t i = 0; i < j->u.o.len; i++) {
            free(j->u.o.items[i].key);
            json_free_d(j->u.o.items[i].val, depth + 1);
        }
        free(j->u.o.items);
        break;
    default:
        break;
    }
    free(j);
}

void json_free(Json *j)
{
    json_free_d(j, 0);
}

int json_type(const Json *j)
{
    return j ? j->type : JSON_NULL;
}

const char *json_str(const Json *j)
{
    return (j && j->type == JSON_STR) ? j->u.str : NULL;
}

double json_num(const Json *j)
{
    return (j && j->type == JSON_NUM) ? j->u.num : 0;
}

int json_bool(const Json *j)
{
    return (j && j->type == JSON_BOOL) ? j->u.boolean : 0;
}

size_t json_arr_len(const Json *j)
{
    return (j && j->type == JSON_ARR) ? j->u.a.len : 0;
}

Json *json_arr_at(const Json *j, size_t i)
{
    return (j && j->type == JSON_ARR && i < j->u.a.len) ? j->u.a.arr[i] : NULL;
}

Json *json_obj_get(const Json *j, const char *key)
{
    Json *found = NULL;
    if (!j || j->type != JSON_OBJ)
        return NULL;
    for (size_t i = 0; i < j->u.o.len; i++) {
        if (strcmp(j->u.o.items[i].key, key) == 0)
            found = j->u.o.items[i].val;
    }
    return found;
}

Json *json_get(const Json *root, const char *path)
{
    const Json *cur;
    const char *a;

    if (!root)
        return NULL;
    if (!path || !path[0])
        return (Json *)root;   /* borrowed view: callers must not free */
    cur = root;
    a = path;
    for (;;) {
        const char *b = strchr(a, '.');
        size_t seglen = b ? (size_t)(b - a) : strlen(a);
        int allnum = 1;
        Json *next;

        if (seglen == 0)
            return NULL;
        for (size_t i = 0; i < seglen; i++)
            if (!isdigit((unsigned char)a[i])) {
                allnum = 0;
                break;
            }
        if (cur->type == JSON_ARR && allnum) {
            size_t idx = 0;
            for (size_t i = 0; i < seglen; i++)
                idx = idx * 10 + (size_t)(a[i] - '0');
            next = json_arr_at(cur, idx);
        } else {
            char key[64];
            if (seglen >= sizeof key)
                return NULL;
            memcpy(key, a, seglen);
            key[seglen] = '\0';
            next = json_obj_get(cur, key);
        }
        if (!next)
            return NULL;
        cur = next;
        if (!b)
            break;
        a = b + 1;
    }
    return (Json *)cur;   /* borrowed view: callers must not free */
}

const char *json_get_str(const Json *root, const char *path)
{
    Json *v = json_get(root, path);
    return v ? json_str(v) : NULL;
}

char *json_escape(const char *s)
{
    static const char d[] = "0123456789abcdef";
    size_t n = 0;
    char *out, *o;

    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\' || c < 0x20)
            n += 6;
        else
            n += 1;
    }
    out = malloc(n + 1);
    o = out;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"') {
            *o++ = '\\';
            *o++ = '"';
        } else if (c == '\\') {
            *o++ = '\\';
            *o++ = '\\';
        } else if (c < 0x20) {
            *o++ = '\\';
            *o++ = 'u';
            *o++ = '0';
            *o++ = '0';
            *o++ = d[c >> 4];
            *o++ = d[c & 0xF];
        } else {
            *o++ = (char)c;
        }
    }
    *o = '\0';
    return out;
}