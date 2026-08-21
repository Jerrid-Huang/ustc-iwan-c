/*
 * iWAN lwIP configuration.
 *
 * Constraints that shape every choice below:
 *   - The stack runs in the existing single-threaded SOCKS event loop
 *     (NO_SYS=1, raw/callback API, no lwIP socket layer).
 *   - The tunnel carries inner IPv4/TCP and IPv6/TCP (tunnel DNS is built
 *     and consumed OUTSIDE lwIP by socks_flow.c as inner IPv4 UDP);
 *     UDP/ICMP/DNS/ARP/DHCP are disabled to keep the surface minimal.
 *   - The inner IP+TCP checksums MUST be generated/verified in software:
 *     the peer (remote host kernel) verifies them after the XOR decap.
 *   - A desktop client (not embedded): memory is generous and sized for
 *     up to MAX_FLOWS=256 concurrent PCBs with 256KB windows, tuned at the
 *     bench milestone.
 */
#ifndef IWAN_LWIPOPTS_H
#define IWAN_LWIPOPTS_H

/* ---- no OS, single-threaded (driven by ns_tick / sys_check_timeouts) ---- */
#define NO_SYS            1
#define LWIP_TIMERS       1
#define LWIP_SOCKET       0
#define LWIP_NETCONN      0
/* Single-threaded event loop: no task/interrupt critical sections, so the
 * SYS_ARCH_PROTECT/UNPROTECT primitives (which need arch/sys_arch.h, only
 * included when !NO_SYS) must be compiled out. */
#define SYS_LIGHTWEIGHT_PROT 0

/* ---- protocol surface: TCP / IPv4 + IPv6 ---- */
#define LWIP_IPV4         1
#define LWIP_IPV6         1
/* IPv6 extras kept minimal: ICMPv6 stays ON (upstream ip6.c calls
 * icmp6_param_problem() on malformed packets outside any LWIP_ICMP6
 * guard, so the function must exist; ICMPv6 is RFC-mandatory anyway).
 * MLD and IPv6 fragmentation are OFF: no multicast on a point-to-point
 * tunnel, and fragments are dropped like the IPv4 policy. Compiled
 * surface: ip6.c + ip6_addr.c + nd6.c + icmp6.c. */
#define LWIP_ICMP6        1
#define LWIP_IPV6_MLD     0
#define LWIP_IPV6_FRAG    0
#define LWIP_IPV6_REASS   0
/* No Router Advertisements on a point-to-point tunnel: with RA updates
 * on (the default), netif_mtu6 stays 0 (only RA sets it) and
 * tcp_eff_send_mss_netif falls back to the unclamped TCP_MSS, so v6
 * segments would be 40+20+1460=1520B > the 1500 inner MTU. Off, the
 * v6 MTU is netif->mtu and the effective v6 MSS becomes 1500-60=1440. */
#define LWIP_ND6_ALLOW_RA_UPDATES 0
#define LWIP_TCP          1
#define LWIP_UDP          0
#define LWIP_RAW          0
#define LWIP_ICMP         0
#define LWIP_IGMP         0
#define LWIP_DNS          0
#define LWIP_DHCP         0
#define LWIP_AUTOIP       0
#define LWIP_ARP          0
#define LWIP_ETHERNET     0

/* ---- single point-to-point tun netif (no link layer) ---- */
#define LWIP_SINGLE_NETIF 1
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF  0
#define LWIP_NETIF_API    0
#define LWIP_NETIF_HOSTNAME 0
/* (ENABLE_LOOPBACK is derived in netif.h as
 *   (LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF) == 0
 *  so lwIP's software loopback short-circuit is already disabled. We only
 *  ever talk to remote hosts, never 127.0.0.0/8 or our own inner IP.) */

/* ---- fragmentation: drop, matching the native rx policy ---- */
#define IP_FRAG           0
#define IP_REASSEMBLY     0

/* ---- TCP tuning ---- */
#define TCP_MSS           1460
/* Initial TCP retransmission timeout: 1000ms (RFC 6298 fast-network
 * value) instead of lwIP's 3000ms default. A single lost inner segment
 * (UDP loss / local TX backpressure) would otherwise stall the flow for
 * a full 3s before the first retransmit — measured as multi-second
 * "tail" stalls on small TLS/HTTP requests over the real line, where
 * there is no dupACK traffic to trigger fast retransmit. SYN retries
 * follow the same 1s cadence (6 retries -> ~6.5s connect timeout
 * instead of ~18.5s). */
#define LWIP_TCP_RTO_TIME 1000
/* 256KB receive window, matching native NS_WINDOW; WSCALE=4 keeps the
 * wire field at 16KB (<<16 fits). */
#define TCP_WND           (256 * 1024)
/* Per-conn send buffer: doubles as the in-flight ceiling AND the initial
 * slow-start ssthresh. 256KB keeps single-conn high-BDP throughput (and
 * loopback ramp) close to the native stack while still bounding the
 * aggregate in-flight well inside the tunnel's UDP sndbuf (native's
 * NS_SND_INFLIGHT_MAX concern). */
#define TCP_SND_BUF       (256 * 1024)
#define LWIP_WND_SCALE    1
#define TCP_RCV_SCALE     4
#define TCP_SND_QUEUELEN  (8 * (TCP_SND_BUF) / (TCP_MSS))
/* Low-water mark for the (unused) socket select() path. TCP_SNDLOWAT lives
 * in a u16_t context (sanity-checked against 0xFFFF - 4*MSS), so a 256KB
 * snd_buf cannot use the default SND_BUF/2; 32KB is an arbitrary valid
 * value — the bridge never reads it (raw API). */
#define TCP_SNDLOWAT      (32 * 1024)
/* Out-of-order reassembly + SACK output (lwIP is a SACK *sender*: it
 * reports OOS holes so the peer selectively retransmits; recovery is
 * still dup-ACK fast-retransmit + RTO). */
#define TCP_QUEUE_OOSEQ   1
#define LWIP_TCP_SACK_OUT 1
#define LWIP_TCP_MAX_SACK_NUM 4
#define TCP_OOSEQ_MAX_PBUFS 32
/* Idle/keepalive: lwIP's built-in probes (SOF_KEEPALIVE is set per-pcb in
 * lwip_bridge.c), tuned to the native NS_IDLE_TIMEOUT(120s)/NS_KEEPALIVE_MS
 * (30s)/NS_KEEPALIVE_MAX(3) semantics: probe after 120s idle, every 30s, and
 * abort after ~3 unanswered probes (idle + cnt*intvl). The *_DEFAULT values
 * are in MILLISECONDS (tcp_priv.h). */
#define LWIP_TCP_KEEPALIVE 1
#define TCP_KEEPIDLE_DEFAULT   120000UL
#define TCP_KEEPINTVL_DEFAULT  30000UL
#define TCP_KEEPCNT_DEFAULT    3U
#define TCP_TTL           64

/* ---- checksums: software (the tunnel peer verifies them) ---- */
#define CHECKSUM_GEN_IP   1
#define CHECKSUM_GEN_TCP  1
#define CHECKSUM_CHECK_IP   1
#define CHECKSUM_CHECK_TCP  1

/* The bridge TU includes the system socket headers (netinet/in.h), which
 * already provide htons/ntohs/htonl/ntohl; don't let lwIP redefine them.
 * lwip_htonl() & co. remain available regardless. */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

/* ---- memory pools (desktop client; generous, tuned at bench) ----
 * The bridge guarantees tcp_write never fails: per-conn snd_buf is capped
 * at TCP_SND_BUF (256KB) and there are at most NS_MAX_CONN=64 conns, so the
 * aggregate TX in-flight is <= 16MB. MEM_SIZE must hold that TX data (COPY
 * mode PBUF_RAM payloads) plus headroom; MEMP_NUM_PBUF / MEMP_NUM_TCP_SEG
 * hold one struct per in-flight segment (~11200 at 16MB/1460). */
#define MEM_LIBC_MALLOC   1
/* 8-byte alignment: struct pbuf (and the TCP seg/pbuf pools) contain 64-bit
 * pointers, and UBSan flags 4-byte-aligned accesses to them; 8 also matches
 * the native alignment of every 64-bit target and is harmless on 32-bit. */
#define MEM_ALIGNMENT     8
#define MEM_SIZE          (20 * 1024 * 1024)
#define MEMP_NUM_TCP_PCB  256                /* == MAX_FLOWS */
#define MEMP_NUM_TCP_SEG  16384              /* tcp_seg structs, all conns */
#define MEMP_NUM_PBUF     16384              /* struct pbuf for PBUF_RAM/ROM */
#define PBUF_POOL_SIZE    4096               /* RX pbufs (short-lived + OOS) */
#define PBUF_POOL_BUFSIZE 1600               /* one full inner IP packet (MTU 1500) */
/* Zero-copy RX: the SOCKS bridge wraps pool-owned receive buffers in
 * PBUF_REF custom pbufs (see lwip_bridge.c). */
#define LWIP_SUPPORT_CUSTOM_PBUF 1

/* ---- diagnostics (off in release; LWIP_DEBUGF compiles out) ---- */
#define LWIP_STATS        0
#define LWIP_STATS_DISPLAY 0
#define LWIP_DEBUG        0

/* lwIP's LWIP_ASSERT is for genuine invariant bugs, but a malformed packet
 * must never abort the whole proxy: disable it, matching the project's
 * "no runtime assert()s" stance (the native stack has none either). */
#define LWIP_NOASSERT     1

#endif /* IWAN_LWIPOPTS_H */
