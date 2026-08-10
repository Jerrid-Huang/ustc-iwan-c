#ifndef IWAN_ADDR_H
#define IWAN_ADDR_H

#include <stdbool.h>
#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <netinet/in.h>
#endif

/*
 * Parse an IPv4 listener as "a.b.c.d:port" into an AF_INET sockaddr.
 * Rejects empty host, non-numeric port, and any second colon (no brackets).
 * Returns 0 on success, -1 on invalid input.
 */
int parse_host_port(const char *s, struct sockaddr_in *out);

#endif