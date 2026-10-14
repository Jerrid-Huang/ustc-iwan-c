/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdp_win.h — Windows 内核数据面监督器（对应 Linux 侧 kdp.c）。
 *
 * 语义与 kdp.h 逐条对齐，差别只在平台原语：
 *   · 会话交给内核：IOCTL_IWAN_SESSION_OPEN（Linux 是 genetlink SESSION_UP）；
 *   · 存活判据：驱动那一页只读共享内存的 last_rx_ms（Linux 是 /dev/iwan mmap），
 *     布局逐字段相同，所以"归零 = 对端 CLOSE、超 IWAN_RX_STALE_MS = 静默丢线"
 *     这条判据两边完全一致；
 *   · keepalive 全在用户态：10s 一次的 PT_ECHO_REQ 走**客户端自己的 UDP
 *     套接字**（与 Linux 相同 —— 控制帧不进隧道，驱动只吞数据帧），
 *     失败预算与静默判死也都在这里；
 *   · 地址/路由仍由用户态配置：内层 IP 挂到承载适配器（KM-TEST 回环），
 *     被代理前缀的路由指向它 —— 复用 route.c 的跨平台实现，与 TUN 面同一套。
 *
 * 返回值与 kdp_run / run_pump 一致：
 *   0 = 用户停止（Ctrl-C 等），1 = 会话丢失（应重连），-1 = 启动失败。
 * -1 时 *ns_busy 区分：true = 本机已有活会话（调用者**不要**回退 TUN 面，
 * 回退会用同一账号把那条会话顶掉），false = 驱动不可用（auto 可以回退）。
 */
#ifndef IWAN_KDP_WIN_H
#define IWAN_KDP_WIN_H

#if defined(_WIN32)

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"   /* slist_t */
#include "iwan_win_abi.h"   /* IWAN_WIN_USER_PATH_MP：两个内核平面的设备名 */

/* 默认承载适配器名：系统自带的 KM-TEST 回环适配器，装好后改名为 iWAN
 * （见 win-driver/README.md）。 */
#define IWAN_WIN_DEF_DEV "iWAN"

/* NDIS 平面（--data-plane kernel-mp）内层适配器的别名与驱动描述。别名是
 * 约定的连接名；描述是 iwanmp.inf 里的 DeviceDesc，用来在系统自取的
 * 连接名（"Local Area Connection"、重装后可能带序号）与别名之间对上号。 */
#define IWAN_WIN_DEF_DEV_MP "iwanmp"
#define IWAN_WIN_MP_ADAPTER_DESC "iWAN Tunnel Adapter"

/* 握手前的启动预检（**在 authenticate() 之前调用**，与 kdp_plane_precheck
 * 同一契约）：驱动在位、ABI 版本匹配、本机没有活会话。
 * device_path 选择设备（NULL = WFP 面 \\.\iwan；见 iwan_win_abi.h 的
 * IWAN_WIN_USER_PATH_MP），两个内核平面共用这一份监督器。
 * 返回 true = 可以继续；false = 原因写进 err（中文，可直接打印）。
 * *busy = true 表示失败原因是"本机已有活会话"：调用者不要回退到 TUN 面。 */
bool kdp_win_plane_precheck(const wchar_t *device_path, char *err, size_t errsz,
                            bool *busy);

/* 见文件头。dev 可为 NULL（用 IWAN_WIN_DEF_DEV）；device_path 可为 NULL
 * （用 WFP 面设备 \\.\iwan）。 */
int kdp_win_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
                uint8_t enc, const char *server, const char *dev,
                const wchar_t *device_path,
                const slist_t *route_targets, const slist_t *route_targets6,
                const char *auth_tun_ip, uint16_t auth_mtu, bool *ns_busy);

#endif /* _WIN32 */
#endif /* IWAN_KDP_WIN_H */
