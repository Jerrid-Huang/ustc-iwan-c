#include "addr.h"

#include <string.h>

#include "common.h"   /* port.h: winsock2/ws2tcpip on Windows, arpa/inet.h on POSIX */

int parse_host_port(const char *s, struct sockaddr_in *out)
{
    const char *colon = strchr(s, ':');
    if (!colon || colon == s || strchr(colon + 1, ':') != NULL)
        return -1;
    size_t ilen = (size_t)(colon - s);   /* > 0: colon == s was rejected */
    if (ilen >= 128)
        return -1;
    char ip[128];
    memcpy(ip, s, ilen);
    ip[ilen] = '\0';
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
        return -1;
    uint16_t port;
    if (str_to_u16(colon + 1, &port) != 0)
        return -1;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    *out = sa;
    return 0;
}