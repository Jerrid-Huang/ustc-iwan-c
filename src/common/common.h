#ifndef IWAN_COMMON_H
#define IWAN_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ---------- growable byte buffer ---------- */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_clear(buf_t *b);                 /* len = 0, keep capacity */
void buf_ensure(buf_t *b, size_t extra);  /* ensure room for `extra` more bytes */
void buf_put(buf_t *b, const void *p, size_t n);
void buf_put_u8(buf_t *b, uint8_t v);
void buf_put_be16(buf_t *b, uint16_t v);
void buf_put_be32(buf_t *b, uint32_t v);
void buf_put_str(buf_t *b, const char *s);
/* remove from the front; memmoves remaining down */
void buf_consume(buf_t *b, size_t n);

/* ---------- string list ---------- */
typedef struct {
    char  **v;
    size_t  n;
    size_t  cap;
} slist_t;

void  slist_init(slist_t *s);
void  slist_free(slist_t *s);
void  slist_push(slist_t *s, const char *str);    /* strdup + push */
/* split on ',' and push each non-empty trimmed piece */
void  slist_push_csv(slist_t *s, const char *csv);

/* duplicate a string (never NULL-halts on OOM for our sizes) */
char *xstrdup(const char *s);

/* ---------- misc ---------- */
uint32_t rand_u32(void);
uint64_t now_ms(void);          /* monotonic, for timeouts */
/* strict decimal parse (digits only, bounds-checked). 0 on success,
 * -1 on empty/non-digit/overflow. Shared by cli.c and the str_to_u* */
int      parse_uint(const char *s, uint64_t max, uint64_t *out);
int      str_to_u16(const char *s, uint16_t *out);
int      str_to_u8(const char *s, uint8_t *out);
/* Rust-style "[::1]" -> "::1" for getaddrinfo; returns s when unbracketed */
const char *unbracket_ipv6(const char *s, char *buf, size_t n);
/* read proxy routes: one or more comma-separated entries per line, '#' comments.
 * Missing file is OK. Returns 0 on success, -1 on other errors. */
int load_cidr_file(const char *path, slist_t *out);
/* resolve dir: leading "~/" -> home (sudo-aware on Linux) */
char    *resolve_config_dir(const char *dir); /* caller frees */

#endif
