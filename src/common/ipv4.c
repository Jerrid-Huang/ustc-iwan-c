#include "ipv4.h"

/* 224.0.0.0/4 multicast */
#define IPV4_MULTICAST(a) (((a) & 0xF0000000u) == 0xE0000000u)
/* 255.255.255.255 limited broadcast */
#define IPV4_BROADCAST(a) ((a) == 0xFFFFFFFFu)

/* first-octet-most-significant value of a 4-byte on-wire address */
static uint32_t be32_value(const uint8_t p[4])
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int ipv4_pkt_ok(const uint8_t *pkt, size_t len,
                uint32_t *saddr, uint32_t *daddr)
{
    unsigned ihl;
    uint32_t tot, src, dst;

    if (pkt == NULL || saddr == NULL || daddr == NULL)
        return -1;
    if (len < 20)
        return -1;
    if ((pkt[0] >> 4) != 4)          /* version */
        return -1;
    ihl = (unsigned)(pkt[0] & 0x0F); /* header length in 32-bit words */
    if (ihl < 5 || (size_t)ihl * 4 > len)
        return -1;
    tot = ((uint32_t)pkt[2] << 8) | (uint32_t)pkt[3]; /* total length */
    if (tot < (uint32_t)ihl * 4 || (size_t)tot > len)
        return -1;
    src = be32_value(pkt + 12);
    dst = be32_value(pkt + 16);
    /* loopback src (127/8) is allowed here: the server's own services
     * (e.g. systemd-resolved on 127.0.0.53) answer tunneled queries with
     * a loopback source. Uplink direction is still protected by the
     * caller's src == session ip check, which loopback can never pass. */
    if (src == 0 || IPV4_MULTICAST(src) || IPV4_BROADCAST(src))
        return -1;
    if (IPV4_MULTICAST(dst) || IPV4_BROADCAST(dst))
        return -1;
    *saddr = src;
    *daddr = dst;
    return 0;
}
