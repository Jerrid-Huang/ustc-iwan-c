#ifndef IWAN_RELAY_PROXY_H
#define IWAN_RELAY_PROXY_H

#include <stdbool.h>

/* Local SOCKS5 + HTTP proxy for TUN mode. Accepted connections are
 * opened on the local kernel stack, so they follow the TUN routing
 * rules exactly like any other system traffic (the chosen design: the
 * proxy is an alternative ENTRY into the same tunnel, not a second
 * data plane — the lwIP userspace stack stays SOCKS-mode-only).
 *
 * One listener serves both protocols (same-port mix, like SOCKS mode):
 * a SOCKS5 greeting (0x05) or an HTTP method token selects the parser.
 * auth_token: RFC1929 password (NULL = no auth); open_proxy: explicit
 * --socks-no-token opt-out; allow_remote: non-loopback binds. Returns
 * 0 on success (out != NULL), -1 on failure (invalid listen address,
 * bind error, or a non-loopback bind without auth/opt-out/allow). */
struct RelayProxy;
int  relay_proxy_start(const char *listen_str, const char *auth_token,
                       bool open_proxy, bool allow_remote,
                       struct RelayProxy **out);
/* Close the listener and stop accepting. In-flight connection threads
 * finish on their own (their sockets close with the process). */
void relay_proxy_stop(struct RelayProxy *rp);

#endif /* IWAN_RELAY_PROXY_H */
