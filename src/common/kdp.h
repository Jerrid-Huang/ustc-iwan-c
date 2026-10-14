#ifndef IWAN_KDP_H
#define IWAN_KDP_H

/*
 * kdp = kernel data plane。iWAN 客户端的内核数据面监督器（Linux only）。
 *
 * 设计（用户拍板的三步计划第 2 步，详见 docs/kernel-data-plane.md）：
 *   · 握手（OPEN/OPEN_ACK/验签/密钥派生）仍全在用户态 —— 那时还没有内核
 *     会话，钩子不拦，应用自己的 UDP socket 能正常收到 OPEN_ACK；
 *   · 握手完成后才 SESSION_UP 把数据面交给内核：数据帧交换、keepalive
 *     接收、断开接收都由内核负责；
 *   · keepalive 全在用户态：**发送**（沿用 10s 一次的 PT_ECHO_REQ）、应答
 *     （服务端）、失败预算与静默判死都是用户态的事；内核只做数据传输，
 *     外加"收到过闸帧就把当前时间戳写进共享内存"这一件记账 —— 没有定时器、
 *     不发送 keepalive、不判死（见 docs/kernel-data-plane.md）；
 *   · 存活/断开的判据是 /dev/iwan 共享内存里的 last_rx_ms（1s 轮询）：
 *     归零 = 对端 PT_CLOSE / 会话被清，超 IWAN_RX_STALE_MS = 静默丢线；
 *   · 地址/路由/MTU 仍由用户态配置，模块只建卡、置 UP、设 MTU。
 *
 * 返回值与 run_pump() 完全一致，cmd_proxy / oidc 的重连循环不用改语义：
 *   0 = 用户停止（Ctrl-C 等），1 = 会话丢失（应重连），-1 = 启动失败。
 * -1 时 `ns_busy`（可为 NULL）区分两类启动失败：true = 本 netns 已有内核
 * 会话或设备被占（调用者**不要**回退到别的数据面），false = 本机内核面起
 * 不来（调用者若用的是默认的 auto，可以回退 TUN，见 cli_common.h）。
 *
 * 调用契约：
 *   · sockfd 必须是已 connect 到服务器的会话套接字（authenticate() 的产物），
 *     且**仍在握手后的状态**：本函数负责它之上的全部数据面生命周期，但不
 *     关闭它（与 run_pump 相同，调用方负责 port_close）；
 *   · 重连必须先让本函数返回 1（它已经执行 SESSION_DOWN），再重新握手 ——
 *     会话还在时钩子会吞掉 OPEN_ACK，顺序颠倒永远握不上手；
 *   · 绝不能在 init netns 用真实服务器的五元组调用（会吞掉用户真实隧道的
 *     入站包）；验证一律在独立 netns + veth 拓扑里做。
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>   /* struct in6_addr（外层 v6 绑定） */

#include "common.h"   /* slist_t */

#if defined(__linux__)

/* 承载网卡绑定（三种模式，与内核 ABI 一一对应；见 docs/kernel-data-plane.md）：
 *   oif=0, bind_ip=0   什么都不绑：内核按 FIB 解析一次后钉住，路径失效自愈；
 *   oif!=0             绑网卡（"绑网卡"）：严格用这张接口，失败逐包拒绝；
 *   bind_ip!=0         绑出口 IP（"绑 IP"）：内核按地址表解析出持有该地址的
 *                      接口后等价于绑网卡；该地址同时是外层头的源地址。
 * dev 只在绑网卡时有值（日志用），bind_ip 是主机序。
 *
 * 为什么绑定有效性要由用户态判：内核只在**外层查找失败**时反应（正确性
 * 兜底，不是及时性机制）。实测（tests/vm_bind_probe.sh）：
 *   · 承载网卡被置 down / 删除 ⇒ 逐包拒绝（tx_err 增长），数据面不会自己
 *     换卡（显式绑定的语义就是不许漂移）；
 *   · 绑定的出口 IP 被删 ⇒ **内核照发**（合成的 scope link 路由只要求设备
 *     UP，不要求它持有地址；tx_pkts 与对端收包都正常增长）。
 * 所以"绑定失效就停用数据面"只能在这里判。 */
typedef struct {
    uint32_t    oif;
    uint32_t    bind_ip;      /* v4 出口 IP（主机序），0 = 不按 IP 绑 */
    const char *dev;
    /* 外层 v6 的"绑 IP"：语义与 bind_ip 逐条对应（必须等于外层源地址、
     * 必须属于本机接口、与 oif 同时给出时同接口）。bind_v6=true 时只看
     * bind_ip6，bind_ip 必须为 0（两个族不会同时绑）。 */
    bool             bind_v6;
    struct in6_addr  bind_ip6;
    /* 回程路由（conntrack）：让"从隧道进来的连接"的回包按来路回去。对端地址
     * 事先不可知，所以只能用 CONNMARK 把入接口记在连接跟踪表项上，回包再还原
     * 成 fwmark 选一张只有隧道默认路由的表。见 docs/reply-routing.md。
     * 内核面在 SESSION_UP 之后装（承载网卡名那时才知道）；先决检查不满足时
     * **拒绝本次会话**，不做"警告后继续"（那会静默不生效）。 */
    bool             reply_via_tunnel;
} kdp_bind;

/* 绑定当前是否有效（每次都从内核现读 getifaddrs，不缓存"我以为的地址"）。
 * 不绑定时恒为 true。读不到接口状态时返回 true 并把原因写进 why —— 状态
 * 未知时不动作，正确性仍由内核侧兜底。失败时 why 收到中文原因。 */
bool kdp_bind_ok(const kdp_bind *b, char *why, size_t whysz);

/* 等到绑定有效为止（1s 一次，Ctrl-C 可打断）。重连循环在**重新握手之前**
 * 调用它：绑定的出口 IP 回来之前不握手，回来之后才握手并重新打开数据面。 */
void kdp_bind_wait(const kdp_bind *b);

/* 握手前的启动预检（**在 authenticate() 之前调用**）：让"本机内核面起不来"
 * 与"本 netns 已有活会话"这两类失败不必先跟服务器握手、不必先占一条服务端
 * 会话（今天它们都发生在 kdp_run 内部，即握手之后）：
 *   · /dev/iwan 存在且共享内存布局版本匹配；
 *   · 本 netns 没有活会话（enabled=1 且最近 2×keepalive 内还收到过对端帧）；
 *   · iwan0 若已存在，必须由内核模块 iwan 创建。
 * 返回 true = 可以继续；false = 原因写进 err（中文，可直接打印）。
 * *busy = true 表示失败原因是"本 netns 已有活会话"：调用者不要回退到 TUN
 * 面 —— 回退会用同一账号把那会话顶掉（服务端对同源 IP 的第二次 OPEN 按合法
 * 重连处理），比直接失败更糟。
 *
 * 判活窗口是 2×keepalive（10s → 20s），它只能证明"最近有人在用这条会话"：
 * 对端静默（外层链路被黑洞）时 last_rx_ms 同样是旧的，这种会话预检看不出
 * 来，仍由 SESSION_UP 的冲突检查兜底 —— 这也正是 SIGKILL 残留必须能被新客
 * 户端接管的原因（否则一次崩溃之后客户端再也起不来）。
 *
 * 只应在"首次握手之前"调用：重连时本进程自己的会话本来就可能还在，那时
 * 预检会把正常重连误判成冲突。 */
bool kdp_plane_precheck(char *err, size_t errsz, bool *busy);

/* ns_busy 可为 NULL；语义见文件头（-1 时区分"已有会话/设备被占"与"本机
 * 内核面起不来"）。 */
int kdp_run(int sockfd, const uint8_t xor_key[8], uint16_t sid, uint32_t tok,
            uint8_t enc, const char *server, const slist_t *route_targets,
            const slist_t *route_targets6, const char *auth_tun_ip,
            uint16_t auth_mtu, const kdp_bind *bind, bool *ns_busy);

#endif /* __linux__ */

#endif /* IWAN_KDP_H */
