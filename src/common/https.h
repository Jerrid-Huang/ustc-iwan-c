#ifndef IWAN_HTTPS_H
#define IWAN_HTTPS_H

#include <stdbool.h>

/* POST a request body via `openssl s_client` (the payload is a bare
 * string; the _json suffix historically lied — JSON handling lives in
 * json.c at the call sites). Returns true on HTTP round-trip.
 *
 * Guarantees on return: *body_out is ALWAYS assigned (malloc'd, caller
 * frees; empty string on failure), and *status_out gets the HTTP status
 * code (0 on transport error). */
bool https_post(const char *host, const char *path,
                const char *body,
                const char *const *headers /* NULL-terminated "Name: value" */,
                int *status_out, char **body_out);

/* GET without a body; same semantics otherwise. */
bool https_get(const char *host, const char *path,
               int *status_out, char **body_out);

#endif
