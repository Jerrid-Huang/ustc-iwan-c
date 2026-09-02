# 性能优化台账（吞吐与延迟）

来源：两轮核心代码审查（2025-09）。状态分三类：**已采纳**（提交号）、
**已拒绝**（核实证据）、**暂缓**（条件与理由）。新建议先对照本表，
避免重复提出或回退已否决的方案。

基线：`tests/bench_multi.sh`，loopback TUN，16 recv 线程 × 8 客户端 × 4s，
24 核。各轮聚合吞吐在 10.7–13.8 Gbit/s 噪声带内，0 RcvbufErrors / 0 drops。

## 已采纳

| 项 | 提交 | 内容 |
|---|---|---|
| lwIP tx 空闲槽位图 | `be670f2` | O(128) 扫描 → O(1) ctz |
| lport_map O(1) 出包解析 | `be670f2` | 带 lport/rport/pcb 三重校验兜底 |
| DNS 下行 fast-path | `be670f2` | 原子 pending 计数，无查询时零锁 skip |
| HTTP 握手头续扫 | `be670f2` | 64KB 滴流头 O(n²) → O(n) |
| SO_RCVBUF 截断告警 | `be670f2` | net.core.rmem_max 静默截断时显式提示 |
| rate 表按源 IP 分片 | `e545f23` | 16 shard × 64 桶；per-source 预算语义不变 |
| **下行 sendmmsg 批处理 + per-reader 发送 fd** | `abb2b2e` | 每队列 64 槽批状态，flush 信号/批满时一次 sendmmsg；fd 按 qid % nfds 分摊 |
| https TCP_NODELAY | `abb2b2e` | Nagle 拖慢 TLS 握手 40–200ms/跳 |
| bridge_recv 预分配 | `abb2b2e` | 整链 buf_ensure 后 memcpy |

## 已拒绝（勿回退，证据见下）

| 项 | 拒绝理由 |
|---|---|
| rate 表按 recv 线程分表 | 同一源可开 N 条 flow 散布到 N 线程 → token-mismatch 探测预算放大 N 倍，削弱 F4 防线。已改用按 IP hash 分片（语义不变） |
| A4：TUN reader poll 100ms 加延迟 | **误报**：poll 事件驱动，POLLIN 到达立即返回；100ms 只是空闲超时与 AIMD busy 信号粒度，不给数据包加任何延迟 |
| B3：隧道 socket 无 POLLOUT | **过时**：`socks_send_stall_wait` 已实现 EAGAIN 时有界（1ms/预算）POLLOUT 等待 |
| io_uring SENDMSG | 已实测比 GSO+sendmmsg 慢 ~6%（socks.c 注释记录 617–635 vs 664–688 MB/s），且无 mixed-length 批的 sendmmsg 等价物 |
| SENDMSG_ZC / SO_ZEROCOPY | seg_compact() memmove 重传槽 + 重传原地重封，都与在途 zerocopy 通知冲突（结构性阻塞） |

## 暂缓（含重启条件）

| 项 | 内容 | 暂缓理由 | 重启条件 |
|---|---|---|---|
| B1/C3/#6 | 下行缓冲环形化（`buf_consume`/`rp_flush` 部分 drain 的 O(n) memmove + 倍增 realloc） | 慢读端本身低频且非 CPU 瓶颈；ring 化 buf_t 触及 6+ 调用点（buf_put/ensure/直接读 data+len），漏一处即静默数据错位 | `IWAN_PUMP_PROF` 显示慢客户端 drain 占到可测 CPU |
| B2 | 上行 readv 聚合 4×1460 → 64KB scratch | snd_buf 背压上界已保证不丢；tcp_write len 为 u16_t，扩大 scratch 只省 readv 次数 | 上行 syscall 计数成为 prof 头项 |
| C1 | GSO 迟滞闩锁（MSS 稳定 N 批才切；send_ctrl 后恢复原 MSS 不清零） | 真实但牵动 send_lock 语义与 gso_mss 全局状态机；send_ctrl 清零是"防 lingering segment"的安全设计 | 混合 MTU 流量实测 setsockopt 抖动成为 prof 头项 |
| C2 | TUN 写侧 writev 批量（iovec 直指 recvmmsg arena 零拷贝）+ 重试 5ms 预算 | 零拷贝重构触及 TUN 写重试生命周期；下行逐包 write 是 syscall 大项但重构面大 | 下行 syscall 计数成为 prof 头项（同 C1 一起评估） |
| C4 | prof 计数器门控（env 未设置跳过采集） | 仅 TUN 模式客户端路径（proxy.c），SOCKS 推荐模式不经过；收益可忽略 | 顺手项，与任一 proxy.c 改动搭车 |
| D1/D2 | Windows：pump_win_single 批量 WSASend + SIO_UDP_NETSEGMENT；wintun ReceivePacket 攒批 | Windows 吞吐未实测为瓶颈；IOCP/批处理改动面大 | Windows 实测吞吐成为瓶颈 |
| E1/E2/E4 | 登录路径：async DNS、Happy Eyeballs、SSL_CTX/SESSION 复用 | 非隧道吞吐热点（一次认证多次重建才 10×）；SSL 生命周期与 wincrypt store 枚举牵动安全面 | 登录延迟实测 > 2s 且用户可感知 |
| E5 | gcm.c 每次解密新建 EVP_CIPHER_CTX | 仅登录一次性调用，非性能项 | 顺手项 |
| F | LTO（CMake IPO） | 名义零风险但 mingw/musl 交叉工具链对 LTO 支持参差；需 A/B 与 CI 验证 | Linux A/B 有 ≥3% 收益且 CI 全绿 |
| #5 进阶 | root 时 SO_RCVBUFFORCE 真正生效 | SOCKS 模式定位免 root，force 无效 | 无（保留最低成本版即可） |
| #3/#7 | DNS 线程池/缓存/合并；reservev 尾部小槽 + commitv | 线程创建 ~50µs vs DNS RTT 几十 ms；窗口边缘才见效 | 页面加载场景实测连接建立延迟分布 |

## 基准方法

- 聚合吞吐 / 丢包：`sudo ./tests/bench_multi.sh <threads> "<clients>"`（root，TUN）
- 阶段计数：`IWAN_PROFILE=1`（服务端）、`IWAN_PUMP_PROF=1`（TUN 泵，仅客户端 proxy 模式）
- 单轮噪声带 10.7–13.8 Gbit/s（8 客户端）；结论需多轮或用计数器
- `srv_ticks` 只统计 server 主线程的 /proc/<pid>/stat，**不**含 16 个 recv
  线程；严谨的 server CPU 对比需采样 /proc/<pid>/task/*/stat 或 strace -c
