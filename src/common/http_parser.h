#ifndef IWAN_HTTP_PARSER_H
#define IWAN_HTTP_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "util.h"

#define HTTPS_CHUNK_SZ_CAP  0x7FFFFFFFL
#define HTTPS_LOG_SAN_MAX   64
#define HTTPS_MAX_RESP      (16u * 1024 * 1024)

/* Bounded, printable-only copy of a remote-controlled header value */
void https_log_san(const char *in, size_t inlen, char out[], size_t outsz);

/* Scan for chunk-size in hex string */
long hex_parse_sz(const char *s, size_t n);

/* Decode a chunked body into out */
int chunk_decode(const char *in, size_t in_len, struct sbuf *out,
                 char *err, size_t errsz);

/* Locate header `name` (case-insensitive) in the header block [hdr, hdr + len) */
char *https_hdr_value(const char *hdr, size_t len, const char *name,
                      size_t *vlen_out);

/* Check if Transfer-Encoding is chunked */
int https_te_is_chunked(const char *val);
bool https_te_header_chunked(const char *hdrs, size_t hlen);

/* Check for control characters in request target / header components */
bool http_ctrl_in(const char *s, size_t n);

/* Split an absolute https:// URL into host and path (from https.h) */
int https_url_split(const char *url, char **host_out, char **path_out);

/* Assemble the request (request line, headers, body) into *req */
int https_req_build(struct sbuf *req, const char *host,
                    const char *path, const char *body,
                    const char *const *headers, bool is_get);

/* Parse Content-Length from header block */
long long https_content_length(const char *hdrs, size_t hlen);

/* Search needle in hay */
const char *sbuf_find(const char *hay, size_t hlen,
                      const char *needle, size_t nlen);

/* Locate the start of header lines and body */
void https_hdr_body(const char *d, size_t len,
                    const char **hdr_start, const char **body);

/* Parse HTTP status code from raw response */
int https_resp_status(const char *d, size_t len);

/* Parse response status and body (decoding chunked / clamping content-length) */
int https_resp_parse(struct sbuf *resp, int *status, char **body_out);

#endif /* IWAN_HTTP_PARSER_H */
