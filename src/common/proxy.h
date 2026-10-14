#ifndef IWAN_PROXY_H
#define IWAN_PROXY_H

#include <stdint.h>
#include "common.h"

/* TUN <-> UDP pump. Blocks until Ctrl-C/error. sockfd already authenticated.
 * route_targets: list of CIDR/"default"/IPv4/domain strings (may be empty);
 * route_targets6: IPv6 CIDRs/addresses/domains (may be NULL). */
int run_pump(int tun_fd, const char *tun_name, int sockfd,
             const uint8_t xor_key[8], uint16_t sid, uint32_t tok, uint8_t enc,
             const char *server, const slist_t *route_targets,
             const slist_t *route_targets6,
             const char *auth_tun_ip, uint16_t auth_mtu);

/* ---------------------------------------------------------------------------
 * Shared with the kernel data plane supervisor (src/common/kdp.c, Linux-only).
 * run_pump stays the only other user and its behavior is unchanged (the
 * definitions were un-static'ed / extracted verbatim).
 * ------------------------------------------------------------------------- */

/* IWAN_RX_STALE_MS watchdog in ms: default 120000, 0 disables the watchdog,
 * parsed once per process with the 30s..24h range (util.c env_ms_range).
 * kdp_run() uses the same value so both data planes declare a session lost
 * under identical conditions. */
unsigned pump_rx_stale_ms(void);
/* Keepalive cadence (ms) and the "peer not answering" budget that declares
 * the session lost, i.e. PUMP_KEEPALIVE_MS / PUMP_KA_FAIL_MAX.
 *
 * 口径（两条数据面一致，2026-10-10 实测后修正）：这个预算统计的是**无人应答
 * 的失败**，只有"收到过门限的有效帧"才清零 ——
 *   · 成功的 send **不**清零：连通的 UDP 套接字把 ICMP 端口不可达隔次上报，
 *     中间那次 send 会成功；按发送成功清零会让 3 次的预算永远到不了（实测：
 *     服务端消失后日志反复"重试 1/3"，最后靠 IWAN_RX_STALE_MS 看门狗判死）。
 *   · 计入预算的事件：keepalive 发送失败（内核数据面走这条），以及接收侧看到
 *     的硬传输错误 ECONNREFUSED/EHOSTUNREACH/ENETUNREACH/ECONNRESET（TUN 泵
 *     走这条：错误先被 recvmmsg 消费，发送侧看不到）。
 *   · TUN 泵在内层循环里按帧清零，位置与 last_rx 相同（过了 sid/token 门限），
 *     避免伪造帧把重连吊住；内核数据面按 /dev/iwan 的 last_rx_ms 变化清零，
 *     该时间戳只在过闸帧上写。
 * 看门狗（IWAN_RX_STALE_MS，默认 120s）仍是外层兜底：对端"收得下但一个都不
 * 回"时（例如被黑洞吸收），失败预算不会涨，只能由它判死。 */
unsigned pump_keepalive_ms(void);
unsigned pump_ka_fail_max(void);

/* Expand route targets into the concrete CIDR list handed to the platform
 * router (fam = AF_INET / AF_INET6). Returns 0 on success, -1 on a malformed
 * target. Used by run_pump and kdp_run for identical route semantics. */
int expand_route_targets(const slist_t *targets, slist_t *out);
int expand_route_targets6(const slist_t *targets, slist_t *out);

#endif
