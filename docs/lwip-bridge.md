# lwIP bridge（SOCKS5 模式用户态 TCP 栈）

`src/common/lwip_bridge.c` 用 vendored 的 lwIP 2.2.1 替换了旧的 `netstack.c`，
对 SOCKS 层暴露**完全相同**的 `ns_*` 接口（`src/common/tcpstack.h` 按
`IWAN_TCP_STACK` 二选一分发），所以 `socks.c` / `socks_flow.c` 无需改动。

## 为什么换成 lwIP

旧 `netstack.c`（1458 行）是一个窗口驱动、无拥塞控制的手写栈：发送只受
`in_flight < 对端通告窗口` 约束，没有慢启动/cwnd/拥塞避免。它在 loopback（无丢包、
窗口 autotune 到 MB 级）上秒满速，但在真实 UDP 隧道（丢包、乱序）里不会缩窗、
乱序段直接丢弃逼对端整段重传，吞吐雪崩。lwIP 提供完整 TCP（Reno 拥塞控制、
快速重传、OOS 重组、窗口缩放、RTO、SACK 输出），并在 hev-socks5-tunnel 这类
tun2socks 场景生产验证过。

## 架构

- **`lwip_bridge.h`**：`ns_*` 接口 + 公共类型（`Netstack` / `TcpConn` / `TxItem` /
  `NsState`）。**不包含任何 lwIP 头**——SOCKS 层已经 include 了系统 socket 头
  （`netinet/tcp.h` 定义 `TCP_MSS`、`netinet/in.h` 定义 `BYTE_ORDER`），再拉进
  `lwip/opt.h` + `lwipopts.h` 会宏冲突。lwIP 类型以 opaque 指针（`struct tcp_pcb *`、
  `struct netif *`）出现，由 `lwip_bridge.c` 里 include 真实头做完整类型。
- **`lwipopts.h`**：`NO_SYS=1` raw API、`LWIP_SOCKET=0`、IPv4/TCP only（关掉
  UDP/DNS/ICMP/IGMP/ARP/DHCP/IPv6）、`LWIP_WND_SCALE=1` + `TCP_RCV_SCALE=4`
  （256KB 接收窗口，对齐旧栈 `NS_WINDOW`）、`TCP_QUEUE_OOSEQ=1` +
  `LWIP_TCP_SACK_OUT=1`（乱序重组 + SACK 输出）、软件校验和、`SYS_LIGHTWEIGHT_PROT=0`、
  `LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1`（避免与系统 `htons/htonl` 冲突）、
  `MEM_ALIGNMENT=8`（UBSan 对齐）。内存按 64 并发连接 × 256KB 在飞上限 sizing，
  `tcp_write` 因此保证不因堆耗尽失败。
- **`port/arch/cc.h`**：`BYTE_ORDER` 按编译器宏检测（CI 交叉编译 s390x 是大端）、
  `LWIP_RAND()` 委托项目自己的 `rand_u32()`（全 32 位 ISN，避免可预测 RST 伪造）。

## 数据面

- **上行（本地 fd → 隧道）**：`ns_send_reservev` 返回每连接 4×1460 的 scratch
  iovec（`LOCAL_IOV_MAX` × MSS），`service_local_inputs` 的 `readv` 直接读进去，
  `ns_send_commit` 用 `TCP_WRITE_FLAG_COPY` 喂 `tcp_write`。reserve 前检查
  `pcb->snd_buf >= MSS`，保证 commit 的 `tcp_write` 不失败（不丢数据）。
- **下行（隧道 → 本地 fd）**：`lwip_output_cb`（`netif->output`）把 lwIP 交出的
  完整内层 IP pbuf 套上 `[8B outer][XOR inner]`，拷进 tx 队列；`ns_rx_packet`
  把解出内层段 `pbuf_alloc(PBUF_POOL)` 后喂 `ip4_input`；`tcp_recv` 回调把 pbuf
  拷进 `conn->rxq`。
- **背压**：`recv_cb` 只追加 `rxq` 不调 `tcp_recved`（窗口收缩→对端停发），
  `conn_reconcile_rxq` 在 `ns_tick`/`ns_close` 里对「已被 SOCKS 层排空」的部分
  调 `tcp_recved`。用 `rxq_unrecved = delivered - recved` 精确计数，避免同一轮内
  「收到又排空」的字节漏记（漏记会让 `tcp_close` 误判 `rcv_wnd != max` 而发 RST）。
- **发送队列公平共享**：`bridge_output` 解析内层 TCP 4-tuple 归属到连接，DATA
  段受 `NS_TX_CONN_CAP=16` 上限约束（控制段 SYN/ACK/FIN 豁免）。没有它，一个连接
  的 lwIP 输出会占满整个 128 槽 tx 队列、把其余连接饿到 RTO（真实 bench 里 2/8
  连接上传出现了 55×~575× 的不公平）。`q_used[conn]` 在 enqueue/pop/rearm 三处对账。

## 连接生命周期与关闭

- `tcp_connect` + 回调（`connected`/`recv`/`err`/`poll`）驱动每连接槽位的
  `state`/`term_reason`，`update_tcp_states` 仍按轮询读 `ns_conn(idx)->state`。
- **连接超时**：`ns_tick` 每轮扫描 `SYN_SENT` 槽位，`now - state_ms >
  connect_timeout_ms`（读 `IWAN_NS_CONNECT_TIMEOUT_MS`）就 `tcp_abort`，映射到
  `NS_TERM_TIMEOUT → rep 4`；`bridge_err(ERR_RST)` 映射 `NS_TERM_RST → rep 5`。
- **空闲保活**：lwIP 内置 keepalive（`LWIP_TCP_KEEPALIVE=1` + `SOF_KEEPALIVE`），
  `TCP_KEEPIDLE/INTVL/CNT` 调成 120s/30s/3，对齐旧栈 `NS_IDLE_TIMEOUT` /
  `NS_KEEPALIVE_MS` / `NS_KEEPALIVE_MAX` 语义。
- **优雅关闭**：`ns_close` 先 `conn_reconcile_rxq`（保证 `rcv_wnd` 满，否则
  `tcp_close` 会发 RST 而非 FIN），再用 **`tcp_shutdown(shut_rx=0, shut_tx=1)`**
  半关闭（发 FIN、**保留接收**）。这是关键：本地客户端 EOF 写侧后，对端仍可能
  回响应数据，而全量 `tcp_close()` 会置 `TF_RXCLOSED`，lwIP 对「FIN 之后到达的
  数据」会直接 `tcp_abort`（RST）——那会杀死每一个半关闭的请求/响应流。半关闭后
  两侧 FIN 交换完 `state=NS_CLOSED`。
- **槽位回收**：
  - 异常关闭（RST/超时）：`bridge_err` 置 `NS_CLOSED` + `term_reason` +
    `reap_pending=1`（推迟一轮到 `update_tcp_states` 读完 reason 再复用）。
  - 优雅关闭：pcb 仍活（TIME_WAIT / LAST_ACK），`ns_tick` 等 `tcp_poll` 停跳
    （>1s）后释放槽位——此时 lwIP 不再持有 pcb，`err_cb` 不可能再触发，复用安全。

## 吞吐（验收 ③：环回 ≥ native 80%）

`sudo ./tests/bench.sh`（SOCKS 模式，聚合 Mbit/s，lwIP vs native）：

| 方向 | 连接数 | lwIP | native | 比值 |
|---|---|---|---|---|
| 上行 | 1 | 2561 | 2855 | **90%** |
| | 2 | 2917 | 3302 | **88%** |
| | 4 | 3020 | 3646 | **83%** |
| | 8 | 3271 | 3945 | **83%** |
| 下行 | 1 | 3060 | 2844 | 108% |
| | 2 | 3049 | 2287 | 133% |
| | 4 | 3264 | 1674 | 195% |
| | 8 | 3168 | 2138 | 148% |

**结论**：上行 83~90%、下行 108~195%，验收 ③ 达标（≥80%）。

**关键修复是 `MEM_LIBC_MALLOC=1`**（PBUF_RAM 用 glibc malloc）。lwIP 内置堆是
first-fit 线性扫描，8 连接 ~1400 个 in-flight pbuf 把 free-list 碎片化到 O(n)，
既拖垮上行聚合（508→3271 Mbit/s），又占满单事件循环、连带饿死 8 连接下行
（conn0=0 → 全部 209~293MB）。换 glibc tcache 后两项一起恢复。

**不需零拷贝**：上行 83~90% 已达标，`tcp_write` 无 COPY（PBUF_ROM）是进一步
追平 native 的可选优化，非必需。
