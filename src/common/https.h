#ifndef IWAN_HTTPS_H
#define IWAN_HTTPS_H

#include <stdbool.h>

/* POST JSON via `openssl s_client`. Returns true on HTTP round-trip.
 * status_out gets HTTP code (0 on transport error). body_out is malloc'd. */
bool https_post_json(const char *host, const char *path,
                     const char *body,
                     const char *const *headers /* NULL-terminated "Name: value" */,
                     int *status_out, char **body_out);

/* GET without a body; same semantics otherwise. */
bool https_get_json(const char *host, const char *path,
                    int *status_out, char **body_out);

#endif
