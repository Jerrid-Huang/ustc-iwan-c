# 性能优化台账（吞吐与延迟）

来源：两轮核心代码审查（2025-09）。状态分三类：**已采纳**（提交号）、
**已拒绝**（核实证据）、**暂缓**（条件与理由）。新建议先对照本表，
避免重复提出或回退已否决的方案。

基线：`tests/bench_multi.sh`，loopback TUN，16 recv 线程 × 8 客户端 × 4s，
24 核。各轮聚合吞吐在 10.7–13.8 Gbit/s 噪声带内，0 RcvbufErrors / 0 drops。

文末"内核数据面（零 TUN）"一节来源不同：它是"客户端去 TUN"这一步的实测记录与
ABI v2 待办，不是代码审查建议表。

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
| C4 prof 计数器门控 | `af7308a` | g_pump_prof_on 一次性解析，add/fetch_add 全部门控 |
| C1 GSO 迟滞闩锁 | `af7308a` | 连续 IWAN_GSO_HYST=8 才重 arm；send_ctrl 清后恢复原 mss |
| C2(有界) TUN 写预算 | `af7308a` | max_ms=0 → PUMP_SEND_RETRY_MS=5ms；writev 批量不可行（TUN 一次一帧） |
| B2 readv 聚合 64KB | `af7308a` | 45×1460，每 256KB 上传轮次 ~45→~4 |
| E2 Happy Eyeballs | `af7308a` | v4/v6 双 lane 并行竞速（简化版） |
| E4 SSL_CTX 缓存 | `af7308a` | 按 CA 模式缓存两枚，登录路径复用 |
| F LTO 选项 | `af7308a` | IWAN_LTO 默认 OFF，-flto=auto 已验证 |

## 已拒绝（勿回退，证据见下）

| 项 | 拒绝理由 |
|---|---|
| rate 表按 recv 线程分表 | 同一源可开 N 条 flow 散布到 N 线程 → token-mismatch 探测预算放大 N 倍，削弱 F4 防线。已改用按 IP hash 分片（语义不变） |
| A4：TUN reader poll 100ms 加延迟 | **误报**：poll 事件驱动，POLLIN 到达立即返回；100ms 只是空闲超时与 AIMD busy 信号粒度，不给数据包加任何延迟 |
| B3：隧道 socket 无 POLLOUT | **过时**：`socks_send_stall_wait` 已实现 EAGAIN 时有界（1ms/预算）POLLOUT 等待 |
| io_uring SENDMSG | 已实测比 GSO+sendmmsg 慢 ~6%（socks.c 注释记录 617–635 vs 664–688 MB/s），且无 mixed-length 批的 sendmmsg 等价物 |
| 出站改用 LWT_XMIT eBPF（同理 XDP/tc-egress） | 位置早于 `validate_xmit_skb()`，内层 L4 校验和仍是 `CHECKSUM_PARTIAL`：出口设备声称支持校验和卸载时（veth 就是）软件根本不算它，连 `enc=0` 都不通；关掉 veth 的 tx 校验和卸载后可通，证明封装/重路由/解封没问题，但只要打开 XOR 就必然覆盖校验和字段 → 对端 `InCsumErrors`（实测 +6，恰等于发出的 6 个加密报文）。A/B 单变量对照见 `kernel/bpf/README.md` |
| SENDMSG_ZC / SO_ZEROCOPY | seg_compact() memmove 重传槽 + 重传原地重封，都与在途 zerocopy 通知冲突（结构性阻塞） |

## 暂缓（含重启条件）

| 项 | 内容 | 暂缓理由 | 重启条件 |
|---|---|---|---|
| B1/C3/#6 | 下行缓冲环形化（`buf_consume`/`rp_flush` 部分 drain 的 O(n) memmove + 倍增 realloc） | 慢读端本身低频且非 CPU 瓶颈；ring 化 buf_t 触及 6+ 调用点（buf_put/ensure/直接读 data+len），漏一处即静默数据错位 | `IWAN_PUMP_PROF` 显示慢客户端 drain 占到可测 CPU |
| C2 批量部分 | writev 批量 TUN 写 | **不可行**：TUN 一次调用一帧，多 iovec 会被内核拼成一帧被 gate 丢弃（已核实 tun_get_user 语义）；有界预算部分已落地（af7308a） | 无（已关闭） |
| E1 | 登录路径 async DNS | getaddrinfo 在同步函数里，真 async 需改调用方框架；收益（一次 DNS ~50ms）与风险不配 | 登录延迟实测 > 2s 且用户可感知 |
| E4 会话复用 | SSL_SESSION 复用 | 牵动会话生命周期与 wincrypt store 枚举；SSL_CTX 缓存已落地（af7308a），session 复用收益递减 | 同上 |
| D1/D2 | Windows：pump_win_single 批量 WSASend + SIO_UDP_NETSEGMENT；wintun ReceivePacket 攒批 | Windows 吞吐未实测为瓶颈；IOCP/批处理改动面大 | Windows 实测吞吐成为瓶颈 |
| E5 | gcm.c 每次解密新建 EVP_CIPHER_CTX | 仅登录一次性调用，非性能项 | 顺手项 |
| #5 进阶 | root 时 SO_RCVBUFFORCE 真正生效 | SOCKS 模式定位免 root，force 无效 | 无（保留最低成本版即可） |
| #3/#7 | DNS 线程池/缓存/合并；reservev 尾部小槽 + commitv | 线程创建 ~50µs vs DNS RTT 几十 ms；窗口边缘才见效 | 页面加载场景实测连接建立延迟分布 |

## 内核数据面（零 TUN，`--data-plane kernel`）

数据面搬到内核模块后，线格与协议开销与 TUN 路径**完全一致**（外层仍是
`[IPv4][UDP][8B 帧头][XOR 内层包]`，36 字节）；差别只在 XOR 的落点：出站由
`ndo_start_xmit` 做（`kernel/iwan_tx.c`），入站由 PREROUTING 钩子（prio −300）
解封后重新注入协议栈。"XOR 只能在 `ndo_start_xmit` 做"这条结论的 A/B 单变量
证据见 `kernel/bpf/README.md`，与本文"已拒绝"表最后一条同源。

### 本机实测（同机 veth 拓扑，**不是**性能基准）

下面这些脚本都以正确性为目的，吞吐只是副产物，因此只能说明"内核数据面在同机
veth 上没有数量级退化"，不能当作链路性能：

| 项 | 实测 | 来源 |
|---|---|---|
| 内层 TCP 64 KiB 双向回显 | 715.8 Mbps，md5 一致 | `tcp_echo_test.sh` T1 |
| 内层 TCP 4 MiB 双向回显 | 2632 Mbps（另一次实测 3051 Mbps） | `tcp_echo_test.sh` T2 |
| TCP 校验和错误 / 重传 | `InCsumErrors +0` / `RetransSegs +0` | 同上 |
| 内层分片 + 内核重组 | 8×3000B UDP 全一致，`rx_delivered` 每包多片 | T3 |
| 外层分片（钩子内联重组） | `rx_reasm 0→32`，回显一致 | T4 |
| 模块出站 ↔ C 侧生产实现 | 60 字节内层包逐字节一致（未豁免任何字段） | `interop_test.sh` A1 |
| C 侧封装 → 模块入站 | 载荷逐字节一致，`rx_bad_hdr` 无增量 | A2 |
| 外层头字段 | 前 26 字节含 TTL/ID/DF/IP 校验和逐字节一致 | A3 |
| XOR 等价性 | 200000 组随机用例 `MISMATCH=0` | `xor_equiv_test.sh` |
| 端到端（真客户端 `--data-plane kernel` 对真服务端 TUN） | 基础 `PASS=28 FAIL=0`，`--extra` `PASS=36 FAIL=0` | `docs/kernel-data-plane-e2e.sh` |
| 退出语义（Ctrl-C） | 客户端 `rc=0` 且打印 `kernel data plane stopped (user stop)`；服务端确认会话关闭 | 同上 C9 / C10c / C10e |

单轮、同机、24 核、未固定时间，仅作量级参考。

### 未测（本机没有真实对端）

真实链路吞吐与 RTT、多会话并发、跨机 MTU/分片组合全部未测。内核数据面也不存在
`IWAN_PUMP_PROF` 那类阶段计数（数据面在内核里，用户态看不到"泵"的阶段），要有
阶段计数得先有 per-CPU 计数器与等价导出（见下表）。

### ABI v2 待办（按价值排序）

| 项 | 现状 | 为什么现在不做 |
|---|---|---|
| 服务端内核数据面 | v1 是"每 netns 单会话 + 设备名固定 `iwan0`"，而服务端要同时服务 256 个会话 ⇒ `iwan-server --data-plane kernel` 是用法错误 | 需要"一个 netns 多会话 + `DEVNAME` 入参 + 按会话分流"的 ABI 变更 |
| 内核侧自主 keepalive 发送 | 发送留在用户态（10s 一次 `PT_ECHO_REQ`）；客户端进程一死（含 SIGKILL）就不再发，对端只能靠自己的空闲超时回收 | 需要内核持有 SID/TOK 并自主发包的语义；当前与 TUN 路径行为一致 |
| 会话空闲自动回收 | 模块侧**没有任何会话超时**：SIGKILL 残留的会话 + `iwan0` + 路由会一直存在、钩子继续吞包，只能手工 `iwan_ctl session-down` 或 `rmmod iwan` | 需要先定义"多久算死"以及是否要通知用户态；宁可先如实文档化（`docs/kernel-data-plane.md`） |
| per-CPU 计数器 | 全是 `atomic64` 单点累加（`iwan_stats`） | 24 核下是否成瓶颈**未实测**（本机数据面只跑到 2.6 Gbps，且是同机 veth）；等有实测拐点再改，避免无证据的复杂度 |
| `IWAN_EV_PEER_SILENT` / `IWAN_PEER_SILENT` | **已清**：编号保留（不动 ABI 号），生产者 `iwan_ev_peer_silent()` 与客户端的解码分支删除；`peer_state` 只会有 `UNKNOWN`/`UP`/`CLOSED` | 静默检测由用户态 1s 轮询 `last_rx_ms` 承担；内核没有定时器，"多久算静默"没有判定点，留着生产者只会让人以为内核会自己判 |
| `IWAN_A_FLAG_ANSWER_PING` | **已清**：bit1 保留但**置位即 `-EINVAL`**；内核会话结构里的 `answer_ping` 字段、`GET_STATS` 回传、客户端开关全部删除 | 与"keepalive/控制帧处理留用户态"的决定一致；宁可拒绝也不假装支持。`iwan_ctl --reserved-flag-bit1` 专门验证拒绝路径 |
| `GET_STATS` 回传 KEY | 会回传（需 `CAP_NET_ADMIN`），文档已警告勿记录输出 | v2 可改为默认不回传 + 显式开关 |
| `ev_dropped` 进客户端诊断 | 只在 `GET_STATS` 可见（`/proc/net/iwan` 列序冻结，不加列） | 客户端诊断目前不需要；改动量一行 |

## 基准方法

- **前置条件（`IWAN_DEBUG_STRIP`，必读）**：`IWAN_DEBUG` / `IWAN_PUMP_PROF` /
  `IWAN_PROFILE` 在 `IWAN_DEBUG_STRIP=ON` 下**完全不被解析**（`src/common/util.c`
  的 `debug_enabled`、`profile.c` 的 `prof_init`、`proxy.c` 的 gate 整段被编译掉），
  而 `CMakeLists.txt:48-58` 对**所有非 Debug 构建类型**（含默认的 Release）把该选项
  默认置为 ON。因此"Release + `export IWAN_PROFILE=1`"这一曾被文档化的组合会**静默
  产出空数据**——实测：真 Release 服务端服务 3 个真实会话，输出中 `^\[prof\]` **0 行**。
  要采集阶段计数必须改用 `-DIWAN_DEBUG_STRIP=OFF`（保留优化）或 `Debug`：
  `cmake -B build -DCMAKE_BUILD_TYPE=Release -DIWAN_DEBUG_STRIP=OFF && cmake --build build -j$(nproc)`。
  `tests/bench.sh` / `tests/bench_multi.sh` 已内置构建类型自检：请求了诊断开关而
  `build/` 是 strip 构建时**直接报错退出并打印重配置命令**，不会静默跑出空结果。
  对照：同为诊断开关的 `IWAN_RXDBG` / `IWAN_FLOWDBG` **不受** strip 影响，Release
  下仍然生效。
- 聚合吞吐 / 丢包：`sudo ./tests/bench_multi.sh <threads> "<clients>"`（root，TUN）
- 阶段计数：`IWAN_PROFILE=1`（服务端）、`IWAN_PUMP_PROF=1`（TUN 泵，仅客户端 proxy 模式）；**需上面的 `IWAN_DEBUG_STRIP=OFF` 构建**
- 单轮噪声带 10.7–13.8 Gbit/s（8 客户端）；结论需多轮或用计数器
- `srv_ticks` 只统计 server 主线程的 /proc/<pid>/stat，**不**含 16 个 recv
  线程；严谨的 server CPU 对比需采样 /proc/<pid>/task/*/stat 或 strace -c


## 同机单向容量基准（lo 裸基线 + veth 外层隧道；用户态 TUN 与内核数据面）

`tests/bench_proto.c` + `tests/bench_proto.sh`：C 发生器覆盖 tcp / udp / 裸 IP
（协议号 253，raw socket）三种内层流量和 c2s / s2c 两个方向。先测**不经隧道**的
裸 lo 基线 —— 它同时标定发生器的上限，避免把"尺子到顶"当成"链路到顶" —— 再用真
`iwan-server` + netns 里的真 TUN 客户端测隧道内数字。

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build -j$(nproc)
./bin/bench_proto selftest                     # 11 项自检，不需要 root
sudo bash tests/bench_proto.sh                 # 默认每档 5s、4 线程（基线 + TUN 档）
sudo insmod kernel/iwan.ko                     # 内核档前置（无参数即可）
sudo env KERNEL=1 bash tests/bench_proto.sh    # 基线 + TUN 档 + 内核档，同一轮
```

口径：内层 1200B UDP / 1220B 裸 IP（负载 1200B）/ TCP 写块 65536B；4 线程；每档
5 秒单向饱和打流；goodput 的 secs 取接收侧"末包 − 首包"，不含建链与启动时间；
发送侧遇内核背压即阻塞，所以丢包 = 发送字节 − 接收字节。槽位名/端口与
`tests/bench.sh` 全部错开，两个脚本可同时运行。

### 实测（2026-10-06，本机，lo 外层为裸基线，隧道档为 veth 外层 + 用户态 TUN）

| 场景 | 协议 | 方向 | 发送 Gbps | 接收 Gbps | 丢包 | 收 pps | 接收/同协议基线 |
|---|---|---|---|---|---|---|---|
| 基线 | tcp | c2s | 144.62 | 144.62 | 0.00% | 420071 | — |
| 基线 | tcp | s2c | 154.67 | 154.64 | 0.00% | 409527 | — |
| 基线 | udp | c2s | 9.19 | 9.19 | 0.00% | 956742 | — |
| 基线 | udp | s2c | 9.09 | 9.09 | 0.00% | 946566 | — |
| 基线 | raw | c2s | 8.25 | 8.25 | 0.00% | 859306 | — |
| 基线 | raw | s2c | 8.39 | 8.39 | 0.00% | 874078 | — |
| 隧道 | tcp | c2s | 3.25 | **3.24** | 0.00% | 197565 | 2.2% |
| 隧道 | tcp | s2c | 5.60 | **5.59** | 0.00% | 304503 | 3.6% |
| 隧道 | udp | c2s | 20.63 | **2.26** | 88.92% | 235419 | 24.6% |
| 隧道 | udp | s2c | 12.84 | **2.86** | 77.60% | 297716 | 31.5% |
| 隧道 | raw | c2s | 15.26 | **1.98** | 86.91% | 206226 | 24.0% |
| 隧道 | raw | s2c | 14.90 | **3.17** | 78.58% | 330415 | 37.8% |

发生器上限（基线接收侧最优值）：tcp 154.6 Gbps（≈41–48 万 pps）、udp 9.19 Gbps
（95.7 万 pps）、raw 8.39 Gbps（87.4 万 pps）。

### 第二轮：三场景同轮对照（`KERNEL=1`，含内核数据面）

同机同参数、同一轮跑完基线 + TUN + 内核三档（2026-10-06，这台机器上模块已 `insmod`）：

| 场景 | 协议 | 方向 | 发送 Gbps | 接收 Gbps | 丢包 | 收 pps |
|---|---|---|---|---|---|---|
| 基线 | tcp | c2s | 122.74 | 122.74 | 0.00% | 420772 |
| 基线 | tcp | s2c | 145.62 | 145.62 | 0.00% | 411791 |
| 基线 | udp | c2s | 8.91 | 8.91 | 0.00% | 928361 |
| 基线 | udp | s2c | 9.36 | 9.36 | 0.00% | 974808 |
| 基线 | raw | c2s | 6.45 | 6.45 | 0.00% | 672354 |
| 基线 | raw | s2c | 5.59 | 5.59 | 0.00% | 581875 |
| 隧道 | tcp | c2s | 1.76 | **1.75** | 0.00% | 69828 |
| 隧道 | tcp | s2c | 2.03 | **2.02** | 0.00% | 53936 |
| 隧道 | udp | c2s | 14.46 | **0.83** | 94.08% | 86792 |
| 隧道 | udp | s2c | 10.18 | **0.69** | 93.16% | 71818 |
| 隧道 | raw | c2s | 13.36 | **0.65** | 95.08% | 67476 |
| 隧道 | raw | s2c | 10.61 | **0.95** | 90.93% | 99081 |
| 内核 | tcp | c2s | 2.00 | **1.99** | 0.00% | 93988 |
| 内核 | tcp | s2c | 2.08 | **2.07** | 0.00% | 69465 |
| 内核 | udp | c2s | 4.45 | **0.47** | 89.13% | 48973 |
| 内核 | udp | s2c | 8.62 | **1.86** | 78.40% | 193888 |
| 内核 | raw | c2s | 6.04 | **0.62** | 89.64% | 64589 |
| 内核 | raw | s2c | 10.09 | **1.51** | 85.04% | 157093 |

只用轮内对照能读出三条：

1. **客户端上行入口翻倍**：客户端设备的 `tx_bytes`（内核档 `iwan0`，TUN 档客户端
   TUN）5 秒内交出 udp 2842.8 / raw 3838.3 MB（4.55 / 6.14 Gbps），而 TUN 档只有
   udp 1373.0 / raw 1418.0 MB（2.20 / 2.27 Gbps）—— 且内核档**被灌入的速率更低**
   （4.45 / 6.04 vs 14.46 / 13.36 Gbps），所以这是入口接受能力的真实差别，不是供给差。
2. **s2c 的外层交付，内核档几乎不丢**：内核档客户端外层 veth 的到达量是服务端发出
   的 1.036–1.041×（即内层包 + 50B 固定开销，见第五组第 6 条），接收侧拿到 93.8%（udp）～96%（raw）；TUN 档同一
   方向服务端发出 2758.8 MB，客户端 TUN 只写出 445.6 MB（**16.2%**）。差别在客户端
   那条「外层 UDP socket → 用户态解密 → 写 TUN」的路径（socket 接收缓冲 + 写 TUN 的
   丢弃策略）；内核档把这条路径换成钩子在 PRE_ROUTING 直接接管（`NF_STOLEN`，不经
   socket 缓冲）。
3. **TCP 行才是容量读数**：内核档 c2s 入口 2.08 / 端到端 1.99 vs TUN 1.76；
   s2c 2.07 vs 2.02 ⇒ 上行 +14%、下行 +2～3%。只有客户端一侧换了数据面（服务端仍是
   TUN 泵），提升有限且方向性明显，符合预期。UDP/raw 的 c2s 行是过载比，**不可比**。

**轮次之间不可比，而且原因不是模块 —— 是"尺子"自己在抖。** 我先前把这一轮偏低归因于
"模块钩子的每包成本"（钩子确实由 `pernet_operations` 的 init 在每个 netns 注册，无会话
时也要过 `pskb_may_pull` + 共享的 `atomic64_inc(&pn->st.rx_pkts)`），并按此做了背靠背
A/B：`sudo rmmod iwan && sudo bash tests/bench_proto.sh`。结果**推翻了这个假设** ——
卸掉模块的那一轮基线是三轮里最低的：

| 轮次 | 模块 | 基线 tcp c2s / s2c | 基线 udp | 基线 raw | 隧道 tcp |
|---|---|---|---|---|---|
| 第一轮 | 未加载 | 144.62 / 154.67 | 9.19 / 9.09 | 8.25 / 8.39 | 3.25 / 5.60 |
| 第二轮 | 已加载 | 122.74 / 145.62 | 8.91 / 9.36 | 6.45 / 5.59 | 1.76 / 2.03 |
| 第三轮（A/B） | 已卸 | 94.74 / 90.31 | 6.73 / 6.50 | 6.49 / 6.54 | 2.44 / 2.95 |

A/B 那一轮跑的时候机器负载 **36.95 / 24 核**、最热 **97°C**、累计降频事件 **108197 次**，
同时有 qemu（占 26.8% 内存）、6 个 `cc1`、`vtpresent-zc` 在吃 CPU。三小时里基线 tcp 从
144.6 掉到 94.7（−35%），**轮间漂移远大于数据面之间的差别**。

由此定下三条读数纪律：

1. **只有行内结构性比值可信**（同一行内两个计数器相比，抗漂移）：内核档客户端入口
   零丢包（`iwan0` 的 `tx_bytes` / 灌入量 = 1220/1200，正好是 IP 头）、外层到达
   1.036–1.041×（内层包 + 50B 固定开销，第五组再复现一次）。**但 TUN 档 s2c 客户端泵的
   保留率不是结构量**（16.2%/17.4%/26.0%/61.3% 都出现过，见第五组的修正）。
2. **速率类结论只作量级参考**：上面第 1、3 条（入口翻倍、TCP +14%）都属此类 ——
   同一轮内 TUN 与内核档相隔约 40 秒，负载在漂移，需要安静机器上复测才能定性。
3. **每轮必须记机器状态**：脚本现在在每个档位开始前打印 `load / 核数 / 最热温度 /
   累计降频 / CPU 前三`，先看这一行再决定这轮数字能不能用。

### 内核数据面对照档（`KERNEL=1`；本轮未跑）

`sudo env KERNEL=1 bash tests/bench_proto.sh` 在**同一条 veth 拓扑**上把客户端换成
`--data-plane kernel`（模块建 `iwan0`、零 TUN；服务端仍是 TUN），基线档与 TUN 档照跑，
所以三个场景是同机同参数、可直接对照。

- 顺序有讲究：TUN 档先跑完**再**切内核档。两者的外层四元组完全相同，而
  `iwan_outer_match` 只比外层地址 —— 同时存在时内核钩子会把 TUN 客户端的下行帧
  截走，量出来的数字必假。
- 证据设备跟着换，而且**两个方向不是同一个设备**：
  - c2s 取客户端 `iwan0` 的 `tx_bytes`：模块在 `ndo_start_xmit` 里显式累加
    `dev->stats.tx_packets/tx_bytes`（`kernel/iwan_tx.c`），可用。
  - s2c **不能**取 `iwan0` 的 `rx_bytes`：模块入站是 `netif_rx`/`netif_receive_skb`
    直接注入协议栈（`kernel/iwan_rx.c`），不经 netdev 的驱动 RX 路径，内核也不会替
    驱动累加 `dev->stats.rx_*` —— 它**恒为 0**。改用客户端 netns 里外层 veth 的到达
    计数（外层 = 内层包 + 50B 固定开销，字节数天然 ≥ payload），与"对端=服务端隧道地址"
    一起判定。
  - 这一条是第一轮真机跑出来的：内核档 s2c 探针被判"`iwan0` 计数不覆盖接收量"，
    而同一份客户端日志里已经写着"内核数据面: 收到对端首个有效帧（/dev/iwan 时间戳
    已非零）"、接收侧也解出了 2.22 Gbps —— 通是通的，是证据取错了设备。
- 安全性（**先前这里写错过，已按源码改正**）：钩子是按 **netns 创建**注册的 ——
  `iwan_net_init` → `iwan_rx_net_init`（`pernet_operations`），模块一加载，init netns
  与此后新建的每个 netns 都有它，**不是**只在本脚本的 netns 里。它不会抢别的隧道的包
  （`iwan_outer_match` 只认本 netns 里 SESSION_UP 过的会话外层地址，没会话就
  `NF_ACCEPT`），代价是每包过一次匹配 + 一个共享原子计数 —— 这正是第二轮被压住的原因。
  `SESSION_DOWN` 或 netns 销毁即回收会话；脚本对客户端先发 SIGINT 再 SIGKILL，就是
  为了走到这条路径。
- 不加 `KERNEL` 时，默认档在模块已加载的情况下**拒绝运行**（理由同第一条）。
- 实测结果见上一节"第二轮"（不再待补）。

### 第四组：另一台机器（安静环境）的尺子对照 —— 证明漂移来自环境

`vlab`（USTC 上的 LXC 容器，Ubuntu 26.04，**2 核**，内核 7.0.14-20-pve）跑
`SKIP_TUNNEL=1 sudo bash tests/bench_proto.sh`（只跑裸 lo 基线，需要 root 只是为了
raw socket；容器里没有 `/dev/net/tun`，见下）：

| 轮次 | 线程 | load（核） | 最热 | 累计降频 | tcp c2s / s2c | udp | raw |
|---|---|---|---|---|---|---|---|
| 1 | 4 | 0.59 / 2 | 41°C | 0 | 64.24 / 65.10 | 2.26 / 2.26 | 2.00 / 1.91 |
| 2 | 4 | 1.24 / 2 | 40°C | 0 | 61.54 / 61.74 | 2.00 / 2.21 | 2.20 / 2.16 |
| 3 | 2 | 3.59 / 2 | 41°C | 0 | 52.16 / 52.33 | 2.57 / 2.19 | 2.05 / 2.06 |

**同参数两次（第 1、2 轮）离散 ≤8%**，而本机（24 核、同一份代码、同一套参数）三轮
基线漂移 35%。⇒ 本机那些漂移来自**环境**（load 37–49/24 核、97°C、累计降频 10 万–33 万），
不是发生器、也不是隧道。同时印证发生器上限**随核数走**：2 核 0.21–0.27 Mpps /
2.0–2.6 Gbps，24 核 0.68–0.98 Mpps / 6.5–9.4 Gbps —— lo 本身远未到顶，量到的始终是尺子。

vlab 上跑不了的两档，以及原因（都是环境限制，不是代码）：

- **TUN 档**：容器里没有 `/dev/net/tun`。`/proc/misc` 里有 `200 tun`（驱动是**内建**的），
  但 LXC 里连 root 都没有 `CAP_MKNOD`（`mknod` 报 `Operation not permitted`），
  `ip tuntap add` 因此打不开设备。要做需在 LXC 宿主侧放行：
  `lxc.cgroup2.devices.allow: c 10:200 rwm` +
  `lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file`。
- **内核档**：该内核（`7.0.14-20-pve`）没有 `/lib/modules/<版本>/` 与内核头文件，
  连 `modprobe tun` 都报 `Module tun not found`，无法构建/加载 `iwan.ko`。

### 第五组：安静机器上的三档同轮 + 模块 A/B（本机，决定性一组）

机器终于空了（`[机器状态]` 显示 load 2.4–7.1 / 24 核、最热 60–79°C，而且**两轮跑完
累计降频一直是 760338 次，一次没涨**），于是把被漂移淹掉的两个问题一次问完：加载模块
后 `KERNEL=1` 跑一轮（基线+TUN+内核），`rmmod` 后紧接着再跑一轮（基线+TUN）。

| 轮次 | 基线 tcp c2s/s2c | 基线 udp | 基线 raw | TUN tcp | 内核 tcp |
|---|---|---|---|---|---|
| ① 带模块（三档） | 156.02 / 178.35 | 10.69 / 10.87 | 9.74 / 9.68 | 4.05 / 4.62 | 4.68 / 4.04 |
| ② 卸模块 | 182.93 / 180.10 | 10.59 / 12.02 | 10.52 / 10.49 | 4.12 / 4.81 | — |

同一份代码、同一套参数，比之前那几轮（基线 tcp 94.7/90.3、udp 6.7、raw 6.5）高
50–97%。**"环境决定一切"到此确证**：本机所有跨轮差异的主因是负载与降频，不是被测对象。

**即便"空闲"也要看误差棒**：这两轮背靠背、参数相同，基线 tcp c2s 却是 156.02 vs
182.93（**+17%**），udp s2c 10.87 vs 12.02（+10%），raw +8%（s2c 基线只差 1%）。也就是
说本机"空闲"时的本底噪声约 **±10%**，下面任何小于这个幅度的速率差都不能当结论。

1. **模块有没有税：没有。** 带模块那轮的 TUN 段 c2s 4.03 / s2c 4.61 Gbps，卸掉模块
   4.11 / 4.81 ⇒ 差 **2.0% / 4.3%**（TCP 是唯一能读容量的行）。先前"未加载那轮更慢"
   纯属环境；钩子那点每包成本在这个量级量不出来。
2. **内核档 vs TUN 档：没有一致优势。** 同一轮内 tcp c2s **+16%**、tcp s2c **−13%**、
   udp s2c +18%、raw s2c −29% —— 方向相反、量级相近，不能宣称内核档更快。
3. **原因由计数钉住：瓶颈在服务端那条用户态 TUN 泵。** 内核档客户端侧两段都是零丢：

| 段 | 内核档实测 | 含义 |
|---|---|---|
| 客户端入口 / 灌入量 | udp 1.0237×、raw 1.0162× | 正是 20B IP 头 ⇒ **入口零丢** |
| s2c 外层到达 / 服务端交出 | tcp 1.0357×、udp 1.0407×、raw 1.0409× | 内层包 + 50B 固定开销 ⇒ **外层零丢** |

   而端到端仍然掉在服务端：内核档 c2s 交付/入口只有 21.5–27.6%、s2c 入口/灌入 12–30%
   （服务端用户态泵写自己 TUN 的那一段）。只换了客户端一侧，瓶颈本来就在另一侧 ——
   这就是第 2 条没有赢面的原因。

**修正一条先前的说法**：我曾把"TUN 档 s2c 客户端泵只保留 16.2%"当作抗漂移的结构性
比值。四轮下来它的值是 16.2% / 17.4% / 26.0% / 61.3%（raw 行还出现过 81.9%、94.7%）
—— **波动极大，不能当结构量**。真正稳的只有内核档那两个比值（三轮复现到四位有效
数字）。正确说法是定性的：**内核档客户端侧零丢，TUN 档同一段会丢，丢多少看当时负载。**

证据列现在还会打印**外层到达计数**（c2s 用宿主侧 `$VETH_H_DEV`、s2c 用客户端 netns 的
`$VETH_N_DEV`；内核档 s2c 本来就用后者，不重复），这样每行都能把"外层根本没到"和
"到了但隧道那一段没跟上"分开。

### 为什么隧道慢在"每包"上（源码 + 实测，四条机制）

1. **包大小决定一切**：裸 lo 的 MTU 是 65536，应用 64 KB 写 ⇒ 栈上一个 GSO 单元最大
   64 KB，180 Gbps 对应约 34–50 万"包事件/秒"；隧道内层被 MTU 1400 截断，每个 64 KB
   写拆成 ~48 个隧道包，实测 30–45 万包/秒 ⇒ **两边包速率同量级，吞吐差 40 倍 ≈ 每包
   字节数差 48 倍**。不是 TCP 不支持大包，是隧道把 1 个大包换成 48 个小包，而每包的
   固定成本不变。两条数据面都拿不到内层 GSO：TUN 只用
   `IFF_TUN|IFF_NO_PI|IFF_MULTI_QUEUE`、**没有 `TUNSETOFFLOAD`**（`src/common/tun.c:52`）；
   内核网卡把 `features/hw_features/vlan_features` 全留 0（`kernel/iwan_tx.c:58-60`），
   原因是 XOR 必须作用在"校验和已算、GSO 已分段"的成品包上
   （`kernel/iwan_tx.c:8-16`、`kernel/iwan_core.c:242`）。
2. **丢包全在用户态泵里，网络上一个字节没丢**：新增的"外层到达"列显示 9 个非基线行的
   外层到达/内层交出是同一个常数 —— tcp **1.0357×**、udp **1.0407×**、raw **1.0410×**
   （就是固定帧头）⇒ 外层 veth 逐字节零丢。丢的是两处：TUN 队列（TUN 档 c2s 灌入
   14862 MB、只有 1774 MB 进设备 ⇒ **88% 丢在这里**）与对端写 TUN（TUN 档 s2c 外层
   到达 5461 MB、注入 2526 MB ⇒ **54% 丢在这里**）。内核档同一段送达 94–98%。
3. **基线"零丢包"是背压，不是链路好**：基线 udp 发送 10.78 = 接收 10.78（发送侧被自己
   的投递速率卡住，接收侧刚好跟得上）；隧道档发送 23.78 vs 接收 2.55，发送侧完全没被
   卡住，中间在**静默丢**（TUN/socket 缓冲满即丢并返回成功，上游收不到背压）。
4. **每包成本**：隧道每包要过两个用户态进程（4 次系统调用 + 2 次拷贝 + 2 次唤醒），
   本轮机器状态行 `iwan-server 94% + iwan-client 92%`（≈1.9 核）对应 26 万 pps ⇒
   **约 7 µs CPU/包**；裸 lo 1.1 Mpps 只用 1–2 核 ⇒ 1–2 µs/包。加解密**不是**瓶颈：
   `enc=1` 是 **XOR**（`iwan_xor()`，64 位字，与用户态 `xor_crypt()` 逐字节等价）。
   客户端自己记录的发送路径上限 617–688 MB/s（`src/common/socks.c:657`）与实测隧道
   3.4–4.8 Gbps 同量级 ⇒ 隧道吞吐就是这条用户态管线的能力上限。
5. **内核档为什么只值 ~2×**：它不是 BPF（是 netfilter 钩子 + 虚拟网卡 `ndo_start_xmit`；
   项目里那点 eBPF 是给 TUN 档做包转向的，本次构建 `IWAN_NO_STEER_BPF` 关掉了），而且
   **注入点与 TUN 完全相同**（`netif_rx`／批处理 `netif_receive_skb`，`kernel/iwan_rx.c:327,418`
   ↔ TUN 的 `tun_get_user`→`netif_rx_ni`）⇒ 二次协议栈遍历、netfilter、XOR、接收侧
   socket 投递都一样，只省掉"用户态那一跳"。另一个用户态泵（服务端）还在 ⇒ 上限≈2×
   （实测 udp s2c pps 33.6 万 → 50.6 万，+51%），而内层包大小限制两边都在 ⇒ TCP 占不到便宜。

6. **内层 MTU 是协商出来的，不是外层网卡给的**（这一条最容易被误解）。链路是：
   客户端 `--mtu`（默认 `IWAN_DEFAULT_MTU = 1400`，`src/common/protocol.h:53`）→ 认证请求
   带上 → 服务端回执 `r->mtu = IWAN_DEFAULT_MTU`（`src/common/auth.c:254`）→ 客户端取
   `min(res.mtu, o.mtu)`（`src/iwan_client.c:1193`）→ 落到设备：TUN 走
   `ip link set dev <tun> mtu`（`src/common/route_linux.c:52`），内核档走 netlink
   `dev->mtu = req_mtu`（`kernel/iwan_netlink.c:290`，范围校验 `IWAN_MIN_MTU..IWAN_MAX_MTU`）。
   外层网卡 MTU 只作为**上界**参与，而且是"一次性假设 + 人工约定"：模块给设备的默认值就是
   按外层 1500 推的 `dev->mtu = 1500 - IWAN_OVERHEAD = 1464`（`kernel/iwan_tx.c:50`，
   `IWAN_OVERHEAD = 8 帧头 + 8 UDP + 20 IP = 36`，`kernel/iwan.h:81`），而模块允许的上限是
   `IWAN_MAX_MTU = 65535 - 36 = 65499`（`kernel/iwan.h:86`）⇒ **内层 MTU 是策略，不是外层
   链路的硬属性**。
   本轮把内层 MTU 直接量了出来（用"外层到达"列反推）：外层 − 内层 = **50B** =
   14（veth 以太头）+ 36（iwan 开销）⇒ TCP 内层 = 50/(1.0357−1) = **1400B（正好 MTU）**、
   udp = **1228B**、raw = **1220B**，与"1200B 负载 + MTU 1400"完全吻合。也就是说 TCP 已经
   吃满 MTU，UDP/raw 反而还留着 ~12% 的每包余量没用。lo 的 65536 只在裸基线里出现
   （两个进程直连 127.0.0.1，没有隧道设备）；隧道档外层是 veth（脚本建 veth 时没写 mtu
   ⇒ 默认 1500），lo 从头到尾没参与。
   注：早先把 1.0357–1.0410 笼统写成"正好是 36B 帧头"不准确 —— veth 的 `rx_bytes` 含
   14B 以太头，所以是 50B；代码里的 `IWAN_OVERHEAD` 36B 不含 L2。两者不矛盾。

7. **不是 syscall 数量的锅**（回应"钩子只做 XOR，凭什么显得拖慢整体"）。先纠正前提：
   **钩子没有拖慢整体** —— 干净 A/B（同轮背靠背、安静机器，带模块 vs 卸模块的 TUN 吞吐）
   只差 **2.0% / 4.3%**，低于 ±10% 本底噪声 ⇒ 无会话时钩子每包那点成本（`pskb_may_pull`
   + `atomic64_inc` + 外层匹配）量不出来。XOR 本身也小：1.2KB 按 64 位字摊开约
   50–100ns，占每包每侧约 3.6µs 的 5% 以下。
   真正"值得省"的是用户态那一跳，而它**已经被批处理摊薄**：客户端用 `recvmmsg`、
   GSO `sendmsg`、`sendmmsg`（`src/common/socks.c:657,708`）。项目自己实测过把这批系统
   调用换成 io_uring —— **TX 反而慢 6%**（617–635 vs 664–688 MB/s）、**RX 慢 15%**
   （1686 vs 1996 MB/s，注释给的原因是"每个 CQE 的处理比它替掉的那次批处理系统调用更贵"）；
   UDP_GRO 也因"8B 外层头没有长度字段 + 内层 IP 头被 XOR"而不可用
   （`src/common/socks.c:1165`）⇒ **减少 syscall 并不能提升这条管线**。
   独立佐证：这两个纯泵的吞吐（TX 664–688、RX 1996 MB/s）与隧道端到端实测
   （3.4–4.8 Gbps ≈ 430–600 MB/s）同量级 ⇒ **隧道就卡在用户态发送路径自己记录的上限
   附近**，而那个上限不由 syscall 数量决定（是每包的拷贝、定帧、记账与协议栈遍历）。
   要把"每包 3.6µs 花在哪"从估算变成实测：`perf record -g -p <iwan-client|iwan-server>`
   （本机 `perf_event_paranoid=4`，需要 root）或 `strace -c -f -p` 看系统调用占比。

**据此可做的优化（按收益排序）**：① **内层开 GSO** —— TUN 侧 `TUNSETOFFLOAD` 加
客户端/服务端支持 GSO 帧（XOR 后分段，或用等长 `UDP_SEGMENT` 一次发出），内核网卡把
features 打开到 GSO/SG/CSUM 并先分段再 XOR；把内层每包从 1.2 KB 提到 ~64 KB 是唯一能
突破"每包成本"上限的路。② **服务端也上内核数据面** —— 现在所有端到端丢包（c2s 交付/
入口 21.5–27.6%、s2c 入口/灌入 12–30%）都在服务端那条用户态 TUN 泵上。③ UDP 过载
测试开 `IWAN_SEND_PACING_PPS`（代码里已有 pace_bucket，默认关闭），把"静默丢包"换成
有意义的节流测定。

### 事故：内核档 + jumbo MTU = kernel panic（2026-10-07）

第一次跑 jumbo 阶梯时，`KERNEL=1` + 内层 MTU 60000 直接把机器打崩（`-b -1` 那段启动
14:11:18 起、14:15:23 止，journald 没来得及落 oops；`/var/log/kern.log` 停在凌晨、
`/sys/fs/pstore` 需要 root）。**根因是模块把上限写成 `65535 - IWAN_OVERHEAD = 65499`，
给了个假绿灯**：内核数据面只在 <=1500 的内层包上验证过，60KB 的 TX/RX 路径（`ndo_start_xmit`
的 60KB skb、`iwan_rx.c:377` 的 `skb_gso_segment` 批处理、以及模块引用的
`__alloc_skb`/`skb_trim`）没有审计过。**这是我放开 MTU 上限时的疏漏**。

止血（已提交）：
- `kernel/iwan.h`：`IWAN_MAX_MTU` 收回 **1500** ⇒ 超限的 SESSION_UP 在
  `iwan_netlink.c:569` 被干净拒绝，而不是 panic。
- `tests/bench_proto.sh`：`CLI_MTU > 1500` 且 `KERNEL=1` 时**默认跳过内核场景**并打印
  原因（要复现才设 `ALLOW_JUMBO_KERNEL=1`）。
- jumbo 度量档暂时**只用于用户态 TUN 档**（那条路不经过模块）。

要做完这个特性还需要：抓到 panic trace（`sudo cat /sys/fs/pstore/*` 或
`sudo journalctl -k -b -1 | tail -100`），然后按 trace 定位 60KB 路径上的缓冲区/长度
截断，再决定 `IWAN_MAX_MTU` 能放到多少。

### 度量档：jumbo MTU —— 不写 GSO 也能把"每包成本"摊销掉

第 1 条说清了 40 倍差距来自"每包固定成本 × MTU 尺寸的内层包"。那么把**每包字节数**
提上去有两条路：GSO（决定谁来分段）或**直接抬 MTU**（决定线上单包多大）。本机隧道的
外层是 veth，MTU 可以设到 65535 ⇒ **抬 MTU 便宜得多**：内层 TCP 的 MSS 自己就变成
MTU−40，栈和泵一次搬 60KB 而不是 1.4KB，**不需要任何 vnet_hdr/分段代码**。GSO 真正
不可替代的场景是外层 MTU 卡在 1500 的真实广域网。

实现（全部默认关闭，正常构建行为不变）：
- `cmake -DIWAN_JUMBO_MTU=60000` 同时放开 `IWAN_MTU_MAX` 与 `IWAN_DEFAULT_MTU`
  （`src/common/protocol.h` 用 `#ifndef` 保护）；两端同版本 ⇒ 协商出 60000。
- `setup_tun()` 现在把服务端 TUN 的 MTU 设成 `IWAN_DEFAULT_MTU`：默认 1500 时是 no-op，
  jumbo 下必需 —— 否则服务端把 60KB 的内层包写进 TUN 会 EMSGSIZE。
- `tests/bench_proto.sh` 新增 `BIN`（二进制目录，可指向独立构建目录而不动 `./bin`）、
  `VETH_MTU`（设两端 veth 的 MTU）、`CLI_MTU`（走客户端 `--mtu`，实际取
  `min(服务端回执, CLI_MTU)` ⇒ 同一个构建里就能做 MTU 阶梯）。

约束：外层帧 = 内层 + 50B（14 以太 + 36 iwan）⇒ 内层 ≤ 65507−36 = 65471，且
veth MTU ≥ 内层+50。客户端 TUN 读缓冲本来就是 64KB（`src/common/tun.c:524`）。
注意 lwip/socks 那条路有写死的 1500 缓冲（`src/common/lwip_bridge.h:44`、`NS_RX_SLOT`）
⇒ **本度量档只用于 TUN/内核数据面的 bench，不要用它跑 socks 路径**。
另外本仓库 `CMAKE_RUNTIME_OUTPUT_DIRECTORY` 默认写死到源码根的 `./bin`，所以度量档
构建要显式 `-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$PWD/build-jumbo/bin`，用完再让脚本重建
`build/`（正常档）覆盖回 `./bin`。

预测（可证伪）：TUN 档会撞到客户端用户态路径的**字节**上限 ≈ 664–688 MB/s
（5.3–5.5 Gbps），不再受约 30 万 pps 的限制；内核档 egress 现在 12.2 Gbps 是被每包
成本卡的，应当明显上升。

### 大 MTU：从静默丢帧到按 MTU 定尺（2026-10-07 修复）

**故障现象**（内层 MTU 60000、承载链路 MTU 65535、不加载模块、整轮无 panic）：
UDP/raw 照跑（应用负载固定 1200B ⇒ 内层分组 1228B），**TCP 两向 100% 收不到**，
而 client.log/server.log 里一条错都没有。端点计数器把范围夹死在客户端中继：

| 方向 | 中继入口 | 承载链路到达 | 中继出口 |
|---|---|---|---|
| c2s tcp | 客户端 tun tx=1.1MB | **0.0MB** | 服务端 tun rx=0.0MB |
| s2c tcp | 承载链路到达 1.1MB | 1.1MB | 客户端 tun rx=**0.0MB** |

**根因**：中继的每报文槽位被写死为 `8 + PUMP_SLOT(2048) = 2056` B，超长分组走
`src/common/proxy.c` 的 `len > PUMP_SLOT` 分支，而该分支只发 `log_debug` ⇒ **静默
丢弃**（原注释的理由是防止越界写入相邻槽位）。60KB 的内层分组因此双向全丢；这也
是"日志干净但 TCP 不通"的原因。

**修复**：槽位按协商出的内层 MTU 动态定尺（`proxy.c` 的 `pump_slot_init`）：
`slot = 8 + max(mtu, PUMP_SLOT)`，批数 `nbatch = min(PUMP_BATCH, 64KiB/slot)`（下限 1），
使每队列缓冲维持 64 KiB 量级而不是随 MTU 线性膨胀。`PUMP_SLOT` 保留为**下限**，
所以 MTU ≤ 2040 时与原实现逐字节一致。协议上限同时从 1500 抬到规范值
`IWAN_MTU_MAX = 65499`（外层 IPv4 总长 65535 − 36B 封装开销 = 20 IP + 8 UDP + 8 定长
首部），与内核模块的 `IWAN_MAX_MTU` 同值；承载链路的三层 MTU 必须 ≥ 内层 + 36，
否则外层会被分片（`tests/bench_proto.sh` 已加检查，`tun.c` 的写缓冲上限 65532 也容得下）。

**验证**：满 MTU 配置（`-DIWAN_JUMBO_MTU=65499`）与正常配置都编译通过。
**尚未验证**：端到端的 60KB TCP —— 等仅计量的接收端点就位后，用客户端单侧测量补上。

**仍受 1500 限制的两处**：① **内核模块**（`IWAN_MAX_MTU` 因 2026-10-07 的 panic 暂收回
1500，>1500 的收发路径待审计后才能放开）；② **lwip/socks 路径**（`lwip_bridge.c:142`、
`:374`、`:616`、`:1058` 硬钳 1500，只影响 SOCKS 本地代理模式，不影响 TUN 数据面）。

### 独立证据：每个隧道数字都验过"真的从隧道设备过线"

隧道档每行同时采两端 TUN 设备的 sysfs 计数（`rx_bytes`/`tx_bytes`），要求**该方向
上的两个计数器都不小于接收侧 payload**：

- TUN 语义：`tx_bytes` = 内核把包交给设备（隧道进程读走），`rx_bytes` = 设备把包
  交给内核（隧道进程注入）。所以 c2s 查「客户端 tx + 服务端 rx」，s2c 查
  「服务端 tx + 客户端 rx」。
- 内核档按方向换设备：c2s 查客户端 `iwan0` 的 `tx_bytes`（模块在 `ndo_start_xmit`
  里累加），s2c 查客户端 netns 里外层 veth 的 `rx_bytes`（模块入站不经 netdev 计数，
  `iwan0` 的 `rx_bytes` 恒为 0，见 `docs/kernel-data-plane.md`）。第二轮实测：内核 tcp
  两行同样逐字节相等（c2s 1300.7/1300.7 MB），s2c 的外层到达/服务端发出 = 1.036×
  （tcp）/ 1.041×（udp、raw）。
- 实测比值：接收侧 1.02–1.04（正是"负载 + 20B IP 头 / +28B UDP 头"该有的量），
  发送侧 1.27–1.89（过载下的供给倍数）。
- TCP 两行两侧计数**逐字节相等**（2108.8/2108.8 MB、3634.4/3634.4 MB）—— 拥塞
  控制下无内层丢包，同时反向校验了计数器读取方向没接反（这一条当初就被接反过，
  探针因此误报过"流量可能没走隧道"，见提交 `905f0a8`）。
- 每行另记收到的**首个远端地址**（`remote=`）：隧道档全部是 `100.64.0.1/.2`。
  内层流量若从 veth 直穿，这里会写成 `172.31.201.x` —— 比只看字节数更直接的绕过
  判据（`tests/bench.sh` 踩过路由没生效、报出同机几十 Gbps 的坑）。

### 读法

- **TCP 行才是诚实的容量数字**：无丢包 ⇒ 拥塞控制已经收敛到隧道能承受的速率。
  安静环境（第五组，本机）用户态 TUN **c2s 4.03 / s2c 4.61 Gbps**、内核档
  4.66 / 4.04；带负载时同一份代码只有 1.76–3.24 / 2.02–5.59 —— **轮次间漂移比数据面
  差别还大**，只能轮内对比，且必须先确认机器状态行。
  跨拓扑量级校验（**不是**同拓扑对照）：`tcp_echo_test.sh` T2 在 veth 拓扑下用
  内核数据面跑内层 TCP 回显是 2632/3051 Mbps，那份脚本自己标注"不是性能基准"，
  两者相差不到一个数量级。本表**不含**内核数据面 —— 见下面的边界。
- **UDP/裸 IP 行是过载法**：把 8–20 Gbps 灌进约 2–3 Gbps 的隧道，77–89% 的"丢包"
  是供给超出容量的比例，不是链路误码。它们的意义在**送达能力**：2.0–3.2 Gbps、
  206–330k pps ⇒ 隧道的 pps 上限约 33 万（1200B 时 ≈3.2 Gbps），而发生器在裸 lo
  上能到 87–96 万 pps，**瓶颈确实在隧道而不是尺子**。
- 方向不对称稳定存在：s2c/c2s = tcp 1.73×、raw 1.60×、udp 1.27×。归因需要
  perf/采样，本轮只给现象。
- 隧道内部丢字节（两端 TUN 计数之差）：udp c2s 25.1%、udp s2c 45.4%、
  raw c2s 32.0%、raw s2c 19.2%；TCP 0%（拥塞控制）。

### 已知边界

- 同机 lo/veth 外层，**不代表**跨主机、真实网卡、真实 MTU 下的数字。
- 本表全部是**用户态 TUN 数据面**。隧道档的外层是 **veth**（netns 里 172.31.201.2
  ↔ 宿主 172.31.201.1），**不是 lo** —— lo 只用在裸基线（两个进程直接对打
  127.0.0.1）。"lo 口径"指的是内层流量与基线，不是隧道的外层链路。
- 内核数据面已在第二轮测过（命令与口径见那节）。两点必须记住：**每个方向只有客户端
  一侧换了数据面**（服务端仍是用户态 TUN 泵），而且第二轮**模块是加载的**，全局钩子税
  同时压低了两档 —— 所以那些绝对值偏保守。
- 已做两次 A/B：第一次在漂移里做，结论被环境淹没；第五组在安静环境下重做，带模块
  4.03/4.61 vs 卸模块 4.11/4.81 ⇒ **差 2.0%/4.3%，模块税量不出来**。速率数字仍必须
  先看机器状态行（load、最热温度、降频增量）。
- 每档单次 5 秒采样，没有重复取中位数；要求更稳的结论请多轮或加长时长。
- 服务端/客户端都用默认参数（未额外指定选项）。
- 发生器自身的两个已知上限：单读线程约 1.1 Mpps 到顶（所以接收侧默认多线程共用
  同一 fd）；UDP 8 线程时接收侧约 6% 的"丢包"同样是尺子而不是链路。

---

## 内核数据面 MTU 阶梯（2026-10-08）

目的：回答"内层 MTU 能不能真正顶到规范上限"，并复现/排除 10-07 那次
"内核档 + 大内层 MTU 直接 panic"。脚本 `tests/mtu_ladder.sh`，逐步
`rmmod` + `insmod kernel/iwan.ko max_mtu=$m`，判定只看 **dmesg 增量**（轮询前记
行号，只取新增部分，不清空 dmesg，尽量保住上一次崩溃的现场）。命令：

```sh
sudo MTS="1600 2048 4096 9000 20000 40000 65499" BIN=$PWD/build-jumbo2/bin \
     bash tests/mtu_ladder.sh 2>&1 | tee /tmp/mtu-ladder.log
```

口径：每档跑 `SINK=1 KERNEL=1`（客户端 `--data-plane kernel`，服务端只计量、
不解封装不注入），**只量 raw 的 c2s**；主指标 = 客户端 `iwan0` 的
`tx_bytes`/`tx_packets` 增量（即模块在 `ndo_start_xmit` 里收下的内层字节与包数），
服务端 SINK 行只作辅助。外层 veth MTU 65535。每档 5 秒、4 线程饱和打流。
同一拓扑另外把客户端换成用户态 TUN 数据面各跑一遍，作为对照。

原始日志：当时在 `/tmp/iwan-mtu-ladder.1079798/mtu-*/`（逐步 `bench.log` 与
`dmesg.new`）。**`/tmp` 是 tmpfs，2026-10-08 15:08 那次 panic 重启把它们连同
tee 日志一起抹掉了** —— 表里的数字是当场抄下来的，逐步日志已不存在。此后跑阶梯
一律把 `OUT=` 与 tee 指向持久路径（见文末"现场保全"）。

| 内层 MTU | 内核档 内层Gbps | 内核档 出站pps | TUN 档 内层Gbps | TUN 档 出站pps | 裸 lo 参考 Gbps | 裸 lo 参考 pps | 计量端点 pps | dmesg |
|---|---|---|---|---|---|---|---|---|
| 1600  | **13.36** | 1,043,945 | 4.33  | 338,503 | 11.93 | 943,863 | 377,311 | 正常 |
| 2048  | **16.92** | 1,032,628 | 5.12  | 312,689 | 14.51 | 894,149 | 346,472 | 正常 |
| 4096  | **24.47** | 746,655   | 9.33  | 284,615 | 28.82 | 883,897 | 357,593 | 正常 |
| 9000  | **35.74** | 496,390   | 16.41 | 227,883 | 56.01 | 779,687 | 284,223 | 正常 |
| 20000 | **28.86** | 180,388   | 24.65 | 154,053 | 58.09 | 363,410 | 273,528 | 正常 |
| 40000 | **28.41** | 88,773    | 28.39 | 88,732  | 81.83 | 255,833 | 213,389 | 正常 |
| 65499 | **25.15** | 48,002    | 31.84 | 60,770  | 83.56 | 159,518 | 225,798 | 正常 |

（"内层Gbps"两列都是客户端隧道设备的出站增量，**同口径**；65499 就是规范上限
65535 − 36。裸 lo 参考 Gbps/pps 是同一台机器上两个 bench_proto 直接在 lo 上对打
的 raw c2s 值，2026-10-08 16:0x 用修好的 bench_proto 重测 —— 见下面"基线列作废"
一节：**这张表里的基线数字是新的，阶梯当时那版基线是截断读出来的假数**。）

### 结论

- **七档全部无内核异常，包括 65499。** dmesg 增量只有常规
  `loaded` / `SESSION_UP .. mtu=N` / `SESSION_DOWN`。10-07 那次"60000 panic"
  在本版代码 + 本拓扑下**不可复现**：本轮 65499 反而压力更大。当时最可疑的
  `ndo_start_xmit` 处理 ~60KB skb 与协议栈对超 4096 单元的软件 GSO，现在被
  实测覆盖。当时没有留下 trace（pstore 空、journald 在不洁关机后轮转了日志），
  所以"已修"只能说是**现象消失**，不是归因。
- **顶满的关键是把它从"每报文成本"换成"每字节成本"。** 1200B 档内核数据面被
  包速率钉死在约 1.04 Mpps（10.4 Gbps，与裸 lo 同量级 ⇒ 当时量到的是发生器/
  协议栈的每包预算）；内层抬到 9000B，同样的包预算换成字节 ⇒ **35.74 Gbps，
  提升 3.4 倍**，而包速率降到 496 kpps。这直接否掉"隧道被 XOR 拖住"的解释：
  XOR 一遍的成本随字节数线性增长，抬 MTU 却让总吞吐涨了 3 倍。
- **收益在约 9000B 之后反转**：20000/40000/65499 分别是 28.86/28.41/25.15 Gbps。
  每报文成本已经不再是瓶颈，剩下的是每字节成本（XOR、两次拷贝、以及外层超
  4096B 单元的软件 GSO 分段：65499 内层要切成约 16 个外层单元）。这与
  `IWAN_GSO_UNIT_SAFE 4096` 的存在一致，但**尚未做分段粒度的 A/B**，所以只报现象。
- **用户态 TUN 档随 MTU 单调上升**（4.33 → 31.84 Gbps），因为它是包速率受限
  （0.06–0.34 Mpps）：包越大越占便宜。于是在 **65499 档出现交叉** ——
  用户态中继 31.84 Gbps 反超内核档 25.15 Gbps。内核数据面在 ≤20000B 全面领先
  （2048 档 3.3 倍、9000 档 2.2 倍），但两端极值不是同一个机制决定的。
- **计量端点的 pps 天花板贯穿全程**（0.21–0.42 Mpps），所以 SINK 行只能看
  客户端出站，不能当链路吞吐。大 MTU 下"计量/出站包比"大于 1
  （20000 档 1.5×、65499 档 4.7×）是"一个内层包被切成 N 个外层单元 × 端点只
  吃下其中一部分"，**不是丢包率**。
- **与真正的裸 lo 尺子比，量级差比我先前说的小得多。** 修好发生器后重测的
  raw 尺子是 11.93 / 14.51 / 28.82 / **56.01** / 58.09 / 81.83 / 83.56 Gbps
  （1600 → 65499）。内核档提交速率 / 尺子 = 1.12 / 1.17 / 0.85 / **0.64** /
  0.50 / 0.35 / 0.30 —— 1600B 档隧道甚至**超过**尺子（因为 SINK 口径量的是
  "已交给模块"，而尺子量的是端到端送达；同口径下 1600B 档发生器被自己的接收
  循环钉在 944 kpps），9000B 档隧道达到尺子的 64%，再往上差距随尺寸单调拉开。
  但注意：SINK=0 的 9000B 档给出**端到端** raw c2s 只有 12.16 Gbps、s2c
  12.88 Gbps —— 那一侧的服务端仍是用户态中继，这个数字被它限住，不是模块的
  能力。**要端到端量模块，必须先有服务端内核数据面。**

### 本轮测量工具的一个真缺陷（已修）

`build-jumbo2/bin/bench_proto` 是 10-07 19:12 构建的，落后于 `tests/bench_proto.c`
在 22:26 的收包缓冲区修复（`MAX_DGRAM 1400` → `DGRAM_BUF 65535`）。后果：
`SIZE_RAW > 1400` 时接收侧 `recvfrom` **静默截断**，每个 65KB 包只记 1380B，
于是基线行的字节列与"丢包%"全是假的（包数有效；隧道行的设备计数不受影响）。
表里那条"裸 lo 参考 pps"能用，字节列已删掉不写。**教训**：产物过期不会报错，
只会让数字悄悄变小。

`tests/mtu_ladder.sh` 已加门禁：`bench_proto`/`iwan-client`/`iwan-server`/
`kernel/iwan.ko` 必须晚于对应源码（按 **mtime** 判，不按提交时间 —— 本仓库先改
代码后提交，提交时间能晚一小时，按它判会把最新产物误判成过期；kbuild 的
`.cmd`/`.o` 不算源码），过期直接停，`ALLOW_STALE_BIN=1` 可放行。

### 已知边界

- 服务端**始终是用户态**：v1 的服务端 `--data-plane` 只接受 `tun`
  （`src/iwan_server.c:308`），所以本阶梯只覆盖模块的**发送路径**。
  模块的接收路径（外层 UDP → 解封 → 注入 `iwan0`）只在非 SINK 的内核档
  **s2c** 方向被覆盖，本阶梯没有覆盖到它 —— 大 MTU 下的接收路径仍是空白，
  尤其是 `kernel/iwan_rx.c` 的批量/`skb_gso_segment` 分支。
- 机器状态在阶梯中持续恶化：load 2.05 → 6.17，最热 66°C → 92°C，累计降频
  22 → 46 次（大 MTU 那几步跑在最热的时候）。所以"9000B 是峰值"这一条可能
  含热漂移，但 3.4 倍的量级差不是漂移能造出来的。
- 每档单次 5 秒，没有重复取中位数。
- 大步长只测了 7 个点，峰值位置（9000B 附近）没有细化。

### 现场保全（2026-10-08 15:08 那次中断之后补）

给阶梯加的 `SINK=0` 档（第一次真正覆盖模块**接收**路径）在 **MTU=20000** 那一步
中断：journal 里最后一条是 `15:08:45 SESSION_UP ... mtu=20000`，之后**一个字都
没有**，机器在 15:08:56 重启（9000 那一步 15:06:40→15:07:22 是完整跑完的）。
五条经验：

- **`panic_on_oops=0`、`panic=0`**（本机实测）：普通 oops 既不会自动重启也不会
  自动停，而且内核还活着时 journald 有时间把 oops 落盘。既然 journal 里连一条
  oops 都没有，那次中断只能是两类：**内核卡死被人手动复位**，或**三重故障级
  硬复位**（这种拿不到任何 printk）。所以"屏幕上的字"和 ramoops 是仅有的两条
  捕获路径 —— 复现时**先别急着复位**，软锁死/RCU stall 报告要等 20 秒以上才打，
  打完再复位。
- **ramoops 会被 efi_pstore 抢掉后端**：pstore 只允许一个后端，systemd 的
  `modprobe@efi_pstore.service` 先注册了它，于是
  `pstore: backend 'efi_pstore' already in use: ignoring 'ramoops'`、
  `ramoops: registering with pstore failed (-16)`。要先用 ramoops 必须让出后端：

  ```sh
  sudo rmmod efi_pstore 2>/dev/null
  sudo sh -c 'R=$(grep -i "Crash kernel" /proc/iomem | head -1 | cut -d- -f1 | tr -d " ")
               modprobe ramoops mem_address=0x$R mem_size=0x100000
               journalctl -k -n 3 --no-pager'   # 应看到 Registered ramoops as persistent store backend
  ```
- **先保全现场，再复现**。`journalctl -k -b -1` 这次还在（上一个启动 14:16 →
  15:08:56），10-07 那次却被轮转掉了 —— 不能指望它。
- **日志不要放 /tmp**：`/tmp` 是 tmpfs，重启即抹。阶梯脚本默认
  `OUT=/tmp/iwan-mtu-ladder.$$`，现在会检测到 tmpfs 并警告；真复盘必须
  `OUT=$HOME/iwan-logs/mtu-ladder`，tee 也要指向持久路径。
- **同机有外来内核态测试在跑**：基准期间 CPU 前三里反复出现 `cavenet_test`、
  `test_malframe`（都不是本仓库的产物）与 200%+ 的 `java`。名字像"另一个内核
  模块的网络/畸形帧测试"，它们与我们的阶梯同时段运行 ⇒ **那次中断不能先入为主
  算在 iwan 头上**，测量数字也要先看机器状态行。

**崩溃靶场（2026-10-08 起的主战法）**：panic 在宿主机上每复现一次就是一次无
trace 的硬重启（屏幕花屏、journald 断在 panic 前、efi_pstore 空）。改用
`tests/vm_crashlab.sh`：guest = 宿主机**同一个内核** vmlinuz + 一个 initramfs
（busybox + 真实 iproute2/iptables + build-jumbo2 产物 + iwan.ko），无盘无
systemd，串口即控制台；guest 内核参数 `oops=panic panic=10` + qemu `-no-reboot`
⇒ 任何 oops/软锁死/hung task 都先打完整 trace 再自动退出，串口日志落
`$HOME/iwan-logs/vm-crashlab/`。配套给 `bench_proto.sh` 加了三个默认值不变的
行过滤开关：`PROTO_LIST`/`DIR_LIST`/`KERNEL_ONLY=1`（跳过 TUN 档只跑内核档），
宿主机上做定向复核也用它们。VM 里的吞吐数字与宿主机不可比，只用于定位。

**归因边界（现有证据允许说的）**：`SINK=1` 阶梯把**发送路径**覆盖到 65499 且
七档全干净；只有 `SINK=0` 会 panic ⇒ 嫌疑集中在 `SINK=1` 根本没走到的部分 ——
模块接收（外层解封 + 注入 iwan0）在大内层 MTU 下，以及服务端用户态 TUN 中继 +
TUN 读写在大内层 MTU 下。下一步应按 **MTU 与方向**逐步二分，并且必须先有 trace。
（2026-10-08 17:0x 的一次更精确定位：内核档两个探针过了，**tcp 行 panic**；
而 SINK=1 阶梯里模块发送路径跑过 20000 的 raw 是干净的，TUN 档的 tcp 也干净 ——
嫌疑收敛到"模块承载 TCP 时才会出现的路径"，等 VM 里的 trace 归因。）

### 根因确认并修复（2026-10-08 22:2x，commit 88458c8）

崩溃靶场把 `VM_CMD` 放宽到完整序列（去掉 `KERNEL_ONLY`、全协议双向）MTU=20000，
**复现了与宿主机 15:08 同样的 panic，并拿到完整 trace**：

```
kernel BUG at include/linux/skbuff.h:2835      ← __skb_pull 的 BUG_ON(skb->len < skb->data_len)
RIP: skb_pull+0x40 ← iwan_decap_one ← iwan_rx_hook ← nf_hook_slow ← ip_rcv   <IRQ> softirq
下半栈（发送方）：iwan-server 的 sendmsg → udp_sendmsg → ip_generic_getfrag ← tun_do_read
寄存器：RAX=20000（skb->len）、RSI=36；线性区仅 28 字节（IP+UDP 头）、data_len=20008
```

机制：用户态服务端发**大 UDP 数据报**时（外层 > ~16KB），内核 UDP 发送路径把
载荷放进 page frags，线性区只留 IP+UDP 头 28 字节。这个非线性 skb 到达模块
RX 钩子后，`iwan_decap_one` 直接 `skb_pull(skb, 36)` 剥外层头 —— 从分页区里
"拉头" ⇒ `BUG_ON` ⇒ softirq 中 Fatal exception ⇒ 整机 panic。

与此前所有方向性观察吻合：只炸 **s2c**（大外层包只有这个方向进模块 RX）；
1200B 探针不炸（小报文线性）；**9000 不炸**（外层 9036 仍在线性分配范围内）、
**20000 必炸**；SINK=1 不炸（服务端无中继，模块 RX 只见小包）。10-07 的
"60000 panic"（外层 60036）是同一 bug。VM 首轮"不复现"只是因为当时跳过了
TUN 档且只跑 tcp c2s —— 恰好绕开了炸点。

修复：`iwan_decap_one` 在解引用外层 UDP 头之前、以及 `skb_pull` 之前各加
`pskb_may_pull`（失败计 rx_nomem）。内层 IP 头原本就有这道（覆盖了内层、
漏了外层）。验证：崩溃靶场 MTU=20000 完整序列 **BENCH DONE** ——
tcp s2c 20.99 Gbps 0% 丢包（原炸点）、tcp c2s 25.44 Gbps、raw 双向正常、
dmesg 无异常。宿主机上的 SINK=0 阶梯（9000/20000/65499）待重跑取正式数字。

顺带发现的两个小账：① 崩溃靶场各档"外层到达"列在 >2GB 流量时出现 -2147.5MB
的负增量 —— bench 的增量算术有 32 位回绕，只影响证据列显示，待修；② VM 与
宿主机重跑 SINK=0 的绝对数字不可直接比（vCPU 数/调度不同），容量结论以宿主机为准。

### 修复后宿主机 SINK=0 阶梯首次跑通（2026-10-09 00:0x，9000/20000/65499）

三档 21 步全部 `正常`，dmesg 增量只有常规行 —— 大 MTU 接收路径第一次量成。
注意：本轮有持续外来负载（`cc1` 100%、`wechat`/`Isolated` ~18%、load 5-8），
基线被压低（raw 基线 9000 档只有 34.22 Gbps，干净时段是 56.01）——**比例与
趋势可用，绝对值建议找干净时段重测**。内核档端到端（接收侧）：

| 内层 MTU | tcp c2s | tcp s2c | raw c2s 收 | raw s2c 收 | 客户端 iwan0 tx pps(raw c2s) |
|---|---|---|---|---|---|
| 9000  | 9.90 Gbps | 8.87 Gbps | 8.81（丢 53.0%） | 7.93（丢 85.1%） | 122,565 |
| 20000 | 16.13 Gbps | 12.64 Gbps | 15.29（丢 11.9%） | 14.00（丢 86.6%） | 95,639 |
| 65499 | 19.00 Gbps | 15.67 Gbps | 13.23（丢 4.3%）  | 12.76（丢 88.1%） | 25,248 |

读法（证据列支持）：
- **外层路径 100% 送达**：三档 `外层到达[宿主vethbp0]` ≈ `客户端[iwan0]tx` ×
  (1+36/MTU)，比率严丝合缝 ⇒ 模块发送 + 外层承载零丢失；raw/udp 行的"丢包"
  全部发生在**服务端用户态**（socket 溢出 / TUN 读环只能拉走 ~8-15 Gbps）。
- **TCP 行 0% 丢包且随 MTU 单调上升**（9.90 → 16.13 → 19.00 c2s）：用户态中继
  是 pps 限的（TCP 收 pps 115k → 96k → 37k），包越大每字节越便宜。
- **MTU 越大服务端越跟得上**：raw c2s 丢包 53% → 11.9% → 4.3%（pps 掉下去，
  中继才吃得动）。
- 端到端数字 = 用户态中继的上限，**不是模块的上限**；模块自身能力仍看 SINK=1
  阶梯（1.04 Mpps / 9000B 35.74 Gbps / 65499B 25.15 Gbps，客户端提交口径）。
- `iwan_rx` 批量/`skb_gso_segment` 分支仍未覆盖（服务端是用户态，不产生 GSO
  超包）——要覆盖得先有服务端内核数据面。

## 内核数据面逐段耗时剖析（2026-10-09，崩溃靶场 guest，ftrace 函数统计器）

方法：guest 内在 `function_profile_enabled` 上挂 `set_ftrace_filter`，只对数据面
节点函数计数与计时（报告的是**含子调用**的时间，配合命中数即得每包成本）。驱
动器 `tests/vm_profile.sh`，四种模式：

- `tx`：SINK=1 + KERNEL_ONLY，raw c2s（对应宿主 SINK=1 阶梯口径）；
- `rx`：SINK=0，raw s2c（模块接收路径）；
- `open`：同 `tx`，但在宿主侧对 `vethbp0` 入向 DROP，切断接收端参与；
- `paged`：SINK=0 只跑 udp c2s。SINK=0 的协议行完全由 `PROTO_LIST` 驱动（SINK=1
  分支固定带一行 raw c2s），而 TUN 档报文不经过模块的 `ndo_start_xmit`，于是
  `iwan_*` 的样本全部来自**套接字发送方（分页 skb）**，是模块发送开销的干净值。

两条口径纪律：① 过滤器必须在 `insmod` **之后**写——模块函数在加载后才进 ftrace
哈希，反序则 `iwan_xmit`/`iwan_xor_*` 一个都不计数；② 把探针行尺寸
（`SIZE_UDP`）也设成 65,459B，统计窗口内只剩一种报文尺寸，平均值即该尺寸的每包
成本，不必跨运行相减。插桩本身有开销，绝对值偏保守；同机内的横向比例可用。

### 发送方向（内层 65,499B，8 vCPU，µs/包，含子调用）

| 段 | 分页发送方（`paged`） | 线性发送方（`tx`，raw/HDRINCL） |
|---|---|---|
| 端到端吞吐（同模块、同会话、同报文尺寸） | **101.3–101.5 Gbps** / 193.5k pps | **26.0–26.7 Gbps** / 49.7–50.9k pps |
| 发送 syscall 每包（推算） | ~20.7（4 线程 ÷ 193.5k pps） | **76.6–78.6**（4 线程 ÷ 50.9k pps = 52.2k pps，与实测吻合） |
| 模块 `iwan_xmit` | **6.18** | ~19（两行混合平均 13.3–14.0，扣除分页分量后推得） |
| — 分页 XOR（`iwan_xor_skb` ⊃ `iwan_xor_paged` ⊃ `iwan_xor`） | **4.61**（占模块 75%） | ~4.6 |
| — 头重分配 `pskb_expand_head` | 0.17 | ~15（线性 65KB 整块拷贝） |
| — 其余簿记（帧头/外层头/校验和/路由/统计） | ~1.4 | ~1.4 |
| 两次出栈遍历 `ip_finish_output` / `__dev_queue_xmit` | 7.50×2 / 7.26×2 | 27.9–29.4×2 / 23.3–24.6×2 |
| 宿主侧接收外层 `udp_rcv` / `udp_queue_rcv_skb` | 1.39 / 1.12 | 1.25–1.35 / 0.99–1.07 |
| 其余（两方向同量级） | `udp_set_csum` 0.05、`ip_send_check` 0.05、`dst_cache_get_ip4` 0.08、`ip_route_output_flow` 0.17、`validate_xmit_skb` 0.07、`veth_xmit` 0.12 | 同左 |

### 接收方向（内层 65,499B，SINK=0 raw s2c，µs/包）

| 段 | 每包 |
|---|---|
| 服务端用户态 TUN 注入 `tun_chr_write_iter` / `tun_get_user` | 9.25 / 9.12 |
| 模块钩子 `iwan_rx_hook` | 2.12 |
| 模块解封装 `iwan_decap_one` | 3.69（其中分页 XOR 3.06–3.17；叶子 `iwan_xor` 0.86/段，约 4–5 段/包） |
| 内层再入栈 `ip_rcv` / `ip_local_deliver` | 5.56 / 2.85 |
| 内层交付 `raw_rcv` | 3.95 |
| 载荷拷贝 `skb_copy_datagram_iter` | 4.00 |
| `nf_hook_slow`（全部钩子调用合计） | 0.26 |

### 结论

1. **XOR 不是主要项**。分页 XOR 4.61 µs/包：占模块 75%，但只占整条发送路径
   ~22%；在 raw 行 76.6 µs 里只占 6%。等价单核有效载荷吞吐 ~14 GB/s（每包 65.5KB
   读+写共 131KB 内存流量）。两种发送方之间相差 56 µs，而 XOR 的量级是几微秒
   ——"多加一次 XOR 就把容量拉低"的推断不成立。
2. **同模块、同会话，换发送方即 26 → 101 Gbps（3.9×）**。差异全在发送方自身每
   包成本：raw/HDRINCL 分配**线性** 65KB skb 并整块拷贝，随后的头重分配再拷一
   次；套接字发送方经 `ip_append_data` 得分页 skb，同一次头重分配只搬 ~20B
   （0.17 µs）。⇒ 基准里 raw 行的容量是**发送方**上限，不是模块上限。
3. **头重分配的成因**：模块 push 36B 后，外层 skb 只剩 12B 头空间，而承载设备
   （veth/以太网）的 `LL_RESERVED_SPACE` = `HH_DATA_ALIGN(ETH_HLEN)` = 16B ⇒
   `ip_finish_output2` 判定头空间不足，调 `skb_realloc_headroom` → 每包一次
   `pskb_expand_head`。线性大 skb 时这一次重分配要整块拷贝 65KB。
4. **不是接收端造成的背压**。`open` 模式把外层包在宿主 `INPUT` 直接丢弃后，吞吐
   与每包成本与闭环完全一致（16,468 vs 16,917 MB/5s；`raw_sendmsg` 75.53 vs
   77.66 µs）⇒ 发送进程既不在等 socket 写内存记账，接收端也不是瓶颈。此前由
   `sock_alloc_send_skb` 平均耗时引出的"反压"推测撤回。
5. **路由缓存每次未命中**：`dst_cache_get_ip4` 与 `ip_route_output_flow` 的命中
   数都等于模块包数 ⇒ 每包都走完整查找。两者之差 0.09 µs/包，量级可忽略，暂不
   为它改动 `/proc/net/iwan` 已冻结的列序。
6. `52c100d` 的分页 XOR + SG 对**分页发送方**成立（头重分配 0.17 µs、无整包线性
   化），但对基准的 raw/HDRINCL 行无效（该路径本就分配线性 skb），故 SINK=1 阶梯
   只观察到 ~4% 漂移，而非预期增益。

### 附：为什么 XOR 与"整包拷贝"同量级（2026-10-09，反汇编 + 同机微基准）

事实核对（同一路径，guest，内层 65,499B）：

| 操作 | µs/包 | 净荷带宽 |
|---|---|---|
| 分页 XOR（TX / RX） | 4.49–4.61 / 3.06–3.17 | 14.2–15.5 GB/s |
| `skb_copy_datagram_iter`（65KB → 用户缓冲区，真正的整包拷贝） | 4.00 | 16.4 GB/s |
| `tun_get_user`（用户 → 内核，含 skb 分配） | 9.12 | 7.2 GB/s |
| `pskb_expand_head` 分页路径 | 0.17 | —— 只搬约 20B 线性头，**不是**整包拷贝 |
| `pskb_expand_head` 线性路径（raw/HDRINCL） | ≈15 | 4.4 GB/s（含 64KB kmalloc） |

⇒ XOR 并非"比整包拷贝慢很多"：比最快的那次拷贝慢 15%，比另两次快 2–3×。分页
路径下 `pskb_expand_head` 的 0.17 µs 容易被误当作整包拷贝的参照，它只搬头部。

成因（`objdump -d kernel/iwan.ko` + 同机微基准，i7-14650HX）：

1. **内核里的 `iwan_xor` 已是 8 字节字**，不是逐字节循环：GCC 先做相位剥离（推进
   到 `(off+i)&7 == 0`），再 `xor %r9,-0x8(%rdi,%rdx,1)` —— `%r9` 由一次
   `mov (%rdx),%r9` 载入 8 字节密钥，尾部逐字节收尾。
2. **模块编译标志是 `-O2 -march=x86-64 -mno-sse -mno-sse2`**，SIMD 不可用，通用
   寄存器的 8 字节就是上限。
3. 同构代码微基准（宿主，64KB，热缓存）：`memcpy` 51.5 GB/s（1.27 µs）、逐字节
   轮转 XOR 3.10 GB/s（21.1 µs）、8 字节字 XOR 29.6 GB/s（2.21 µs）、AVX2 预旋密
   钥 62.0 GB/s（1.06 µs）。逐字节写法确实慢 17×，但内核里没有这样编；8 字节字与
   `memcpy` 的差距来自后者能用 SSE/AVX（用户态）或 ERMS `rep movsb`（内核态），
   而异或没有 `rep` 版本。
4. **冷目标（每次换 1MB 窗口、64MB 工作集）：`memcpy` 15.0 GB/s 对 AVX2 XOR
   16.1 GB/s，持平。** 数据路径上的载荷受访存带宽约束，此时 XOR 的 4.61 µs 与冷
   态 SIMD 的 4.08 µs 同阶 ⇒ 真实路径上它是访存受限，而不是"算得慢"。
5. 组成：每字节一次读 + 一次就地写（写分配还会多一次 DRAM 读）× 访存带宽，加上
   每分段一次 `kmap_local_page`/`kunmap_local` 与函数调用（每包 4–5 段）。

可动空间：把 8 字节字换成 SIMD（AVX2 + `kernel_fpu_begin/end`），热数据 2.21 →
约 1.06 µs（2×），冷数据几乎无收益（4.08 对 4.37 µs）；小分段还要扣掉 FPU 上下文
保存/恢复的固定开销，需按分段长度设阈值。这是可优化项里"分页 XOR 改 SIMD"的定
量依据与收益上限。

### 可优化项（按实测排序，尚未实施）

| 项 | 依据 | 预期 |
|---|---|---|
| 分页 XOR 改 SIMD（AVX2/AVX-512 + `kernel_fpu_begin/end`，密钥按 `off&7` 预旋成向量） | 结论 1：4.61 µs/包，占模块 75% | 乐观 4.6 → ~1.5 µs（整条发送路径约 -15%） |
| 外层出栈改 `dev_queue_xmit` 直连承载设备，跳过 `ip_output`/`ip_finish_output`/LOCAL_OUT | 外层 `ip_local_out` 1.07 µs（分页行）+ 遍历开销 | ~1–2 µs/包，但改变外层包的 netfilter 语义，需权衡 |
| 收敛 `ip_route_output_flow` 每包一次（`dst_cache` 命中数为 0，见下节实测） | `ip_route_output_flow` 0.23 µs × 1 次/包 | ~0.2 µs/包，先查清缓存为何不命中 |

已实施：`needed_headroom` 由 `IWAN_OVERHEAD`(36) 改为按承载网卡的
`LL_RESERVED_SPACE()` 推导（veth ⇒ 52），见下一节「承载网卡绑定」——raw c2s 从
26.05–26.67 Gbps / 49.7–50.9k pps 提到 108.19–115.61 Gbps / 206.5–220.7k pps。

沉淀：`tests/vm_profile.sh`；崩溃靶场打包改为携带 `tests/*.sh`（原先只带
`bench_proto.sh`，guest 内取不到剖析脚本）。

## 承载网卡绑定：一条会话只用一张下游网卡（2026-10-09）

### 改造前

- **出站**：`fl4.flowi4_oif` 从来没被赋值。外层路由每个报文由 FIB 现场决定，只把结果
  缓存在 `dst_cache` 里（键是 daddr/saddr，**不含出口设备**）。于是"这条会话走哪张
  下游网卡"是路由表的隐式副作用：多张等价路由、脚本改路由、策略路由变化都会让同一条
  隧道的报文落到不同网卡上。
- **入站**：`nf_register_net_hook(pn->net, &pn->rx_ops)` 把钩子挂在 netns 上，钩子体
  不看 `state->in`。外层四元组又是可伪造的，于是任意网卡上、四元组匹配的伪包都能进
  解封装流程（凭据闸门在后面才做）。
- **预留**：`needed_headroom` 是设备级常量 `IWAN_OVERHEAD`(36)，与出口网卡的
  `LL_RESERVED_SPACE()` 无关 —— 这就是"raw/HDRINCL 路径每包多一次 65KB 重分配"的根因。

### 语义

一条会话在任一时刻只用一张下游（承载）网卡，来源两种：

1. **显式绑定**：`SESSION_UP` 的 `IWAN_A_OIF`（u32 主机序 ifindex），回落路径
   `/proc/net/iwan` 的 `oif=<ifindex>`；
2. **未绑定**：会话建立时按 FIB 解析一次（`flowi4_oif=0`）并把结果钉住，此后出站查找
   带 `flowi4_oif=<钉住值>`，不再逐包变化。钉住的那张卡失效（设备被删/路由被撤）⇒
   清掉钉住、按 FIB 重解析一次并改钉，仍然只保持一张卡；显式绑定刻意不回落。

钉住结果发布在 `iwan_net.carrier`（0 = 尚未解析），三处使用：出站 `flowi4_oif`、入站
`state->in->ifindex` 比较、`needed_headroom = IWAN_OVERHEAD + LL_RESERVED_SPACE(carrier)`
（只增不减）。会话建立/结束、端点漂移（`SET_PEER`）时清 0，下一次出站重新解析。

`dst_cache` 的键不含 `flowi4_oif`，所以"钉住值变了"必须作废缓存。控制面（进程上下文）
**不**调 `dst_cache_reset`（它要求 BH 关闭），只清 `carrier`；数据面按
`tx_route_dst/src/oif` 三个"建缓存时的参数"记录值发现不一致，在软中断关闭的环境里惰性
作废 —— 避免"进程上下文释放 dst"与数据面取用并发。

### `flowi4_oif` 不是保证：内核会为绑定的设备合成路由

设了 `flowi4_oif` 之后，若 FIB 里没有经该设备的路由，`ip_route_output_flow()` 会为
**这张 UP 的设备**合成一条 scope link 路由（即 `SO_BINDTODEVICE` 语义）。实测：
在 cl netns 里绑 `lo`、或绑一张与 172.31.201.1 完全无关的 `vethb3`，解析都成功，
`rt->dst.dev` 正是绑定的那张，报文也确实从那卡出去（FIB 自己会选的 vethbp1 侧零增长）。
**合成的前提只是设备 UP，不要求它持有 IPv4 地址**：删除 `vethb3` 上唯一的地址
（10.55.0.2/24）后，外层查找仍成功、报文仍从该卡出线（`tx_pkts +5`、对端 RX +6；
见下面的"承载网卡事件语义"表）——这一点与最初的推断相反，是实测纠正过来的。
所以"绑一张卡"是硬语义，**代价是绑到没有回程路由的卡上会静默黑洞**（发包照走、网络侧
丢弃）。模块在解析之后再加一道自查（`rt->dst.dev->ifindex == oif`），用来兜住内核将来
改变这套回落行为；`SESSION_UP` 只做一次解析，不具备"这张卡真能到对端"的判据。

### 实测：raw c2s（崩溃靶场 guest，内层 65,499B，8 vCPU）

| 项 | 改造前 | 改造后 |
|---|---|---|
| 端到端 | 26.05–26.67 Gbps / 49,727–50,908 pps | **108.19–115.61 Gbps / 206,535–220,710 pps**（同配置三次复跑） |
| `pskb_expand_head`（含子调用） | 442,197 次 / 8.92 µs（≈1 次/包） | 48–49 次 / 2.89–4.82 µs（≈0） |
| `iwan_xmit`（含子调用） | 13.3–14.0 µs | **3.17–3.29 µs** |
| `iwan_xor_skb` | 4.6 µs | 1.77–1.84 µs |
| `raw_sendmsg` | 76.6–78.6 µs | 16.30–17.37 µs |
| 钉住日志 | — | `承载网卡 vethbp1 ifindex=2（FIB 解析后钉住）needed_headroom=52` |

约 4.1–4.4×。收益不止那一次 memcpy 的 9 µs：65KB 报文下，每包多出来的约 130KB 内存流量
（重分配的读+写，外加 64KB 头的分配/释放）已经打满内存带宽；去掉之后每包成本降到四分之一，
XOR 也从 4.6 µs 降到 1.77 µs（载荷不再被挤出缓存；65,499B / 1.77 µs ≈ 41 GB/s，接近
8 字节字循环"每周期一字"的上限）。

### 验收（`tests/vm_bind.sh`，只测 raw，判据全部是计数器）

| 用例 | 判据（对端 RX 指 root netns 侧 peer 网卡的 `rx_packets`） |
|---|---|
| ① 不写 oif | `tx_pkts +5`、`tx_err +0`、vethbp0 RX ≥ +5、vethb2 RX ≤ +1；日志记"FIB 解析后钉住 + needed_headroom=52" |
| ② 显式绑 vethbp1 | 同 ①，日志记"显式绑定" |
| ③ 显式绑 lo | 5 个报文都有归宿（`tx_pkts+tx_err=5`）、两张对端卡都不增长、cl 自身 `rx_delivered +5`（入站门限在绑定的卡上放行） |
| ④ 显式绑 vethb3（FIB 不会选它） | vethb2 RX ≥ +5、vethbp0 RX ≤ +1 ⇒ 出站只看绑定卡，完全不管其他网卡 |

对端计数混着 ARP/IPv6 邻居发现，所以判据是单向的（该出线的 ≥ 发送数、不该出线的 ≤ 1），
并在 cl 里关掉 IPv6 压噪声。

### 附带解释一处此前的观测异常

2026-10-09 11:36 那次"内核档 raw c2s 100% 丢包"自洽了：那次外层路由查找全部失败，模块
在每个报文上进 ⑥ 就 `goto drop`（`tx_err` 累加），所以 `tx_pkts/tx_bytes` 停在 0、客户端
出站 0 个报文、`raw_sendmsg` 反而"变快"（12.46 µs，报文实际没有发出）。当时"第二个探针没打印"
是探针自身的观测缺陷：同一函数里两个 `pr_info_ratelimited()` 调用点共享限速状态，前一处
169 万次调用把配额耗尽；`pskb_expand_head` 那栏 48 次命中、无重分配也是同一次失败造成的，
并不是因为路径发生了变化。

## 每包经模块的处理时间（实测汇总，2026-10-09 晚）

### 口径

- 来源：`tests/vm_profile.sh` 的 ftrace 函数统计器，**每调用平均 CPU 时间（含子调用）**，
  8 vCPU guest（同内核 7.0.0-38-generic）、`KERNEL=1`、崩溃靶场最小 VM。
- 统计窗口只放一种分组尺寸：`SIZE_RAW = SIZE_UDP = MTU`（脚本第 3、4 个参数）。默认
  `SIZE_UDP=1200` 会让窗口里混进 1200B 探针行，平均值就不是单一尺寸的每包成本 ——
  下表全部是单尺寸窗口。
- 这些是**处理时间（服务时间）**，不是线上时延/RTT，也不含对端与队列等待；统计器只给
  平均值，没有分位数。

### 出站（`iwan_xmit`，模块 `ndo_start_xmit` 全程，含它调用的外层出栈）

| 统计窗口 | 内层字节 | 每包 µs | 其中 XOR | 其中外层出栈 `ip_local_out` | 其余 |
|---|---|---|---|---|---|
| 改造前 udp 单行 jumbo | 65,459 | 13.29 | 2.83 | 9.81（其中 `pskb_expand_head` 8.92） | 0.65 |
| 改造后 udp 单行 jumbo | 65,499 | **2.91** | 1.53 | 0.79 | 0.59 |
| 改造前 raw+udp 两行 jumbo | 65,499 | 13.97 | 3.18 | 9.21（≈1 次/包） | 0.58 |
| 改造后 raw+udp 两行 jumbo | 65,499 | **3.73** | 2.30 | 0.80 | 0.63 |
| 改造后 raw+udp 两行 9000B | 9,000 | **2.29** | 0.68 | 0.90 | 0.71 |
| 改造后 raw+udp 两行 1200B | 1,200 | 2.13（改造前 1.92） | 0.38 | 0.98 | 0.77 |

"其余"= 两次 `skb_push`、shim/外层头填写、外层校验和（`ip_send_check` 约 0.05 µs × 2）、
路由查找（`ip_route_output_flow` 0.24 + `dst_cache_get_ip4` 0.07）、计数器与 `dev->stats`。
改造后 `pskb_expand_head` 只剩个位到两位数调用（jumbo 档 65 次 / 1,352,807 包，9000B 档
49 次，1200B 档 48 次），即头预留已经足够，逐包不再重分配；改造前 jumbo 档是每包一次、
每次 9.21 µs。

**每包成本模型**（改造后出站）：固定约 2.1 µs + 约 30 ns/KB。
固定部分主要来自外层出栈的栈遍历（约 1 µs/包，1200B 与 9000B 档几乎不随长度变化），
字节相关部分的斜率 30 ns/KB ≈ 33 GB/s，正是 8 字节字 XOR 循环"每周期一字"的实测上限
（XOR 本体占改造后出站的 53–62%）。

### 入站（单帧解封装，jumbo，内层 65,499B）

| 项 | 每帧 µs | 调用数 | 说明 |
|---|---|---|---|
| `iwan_decap_one`（含 XOR） | **2.85** | 348,319 | 这才是"每包经模块入站"的数 |
| `iwan_rx_hook`（钩子总入口） | 1.46 | 753,182 | 平均值含大量不进入解封装的调用；其自身部分约 0.14 µs/次 |
| 改造前同口径 `iwan_decap_one` | 3.69 | 304,044 | 旧路径；两次运行行组成不同，作参考 |
| `pskb_expand_head` | ≈0 | 105 | 入站不做头重分配 |

入站变快（3.69 → 2.85）不是解封装代码改了：出站侧不再每包多搬 65KB，内存带宽与缓存
压力下降，同一颗核上的入站 XOR 跟着受益。

### 换算与边界

- 出站 212,605 pps（raw jumbo，改造后）× 3.73 µs ≈ **0.79 个核**（模块出站部分）；
  改造前 49,727 pps × 13.97 µs ≈ 0.69 个核 —— 每包成本降到 1/3.7，速率提到 4.4 倍。
- 入站 2.85 µs/帧 ⇒ 单核理论上限约 35 万帧/秒（该档实测受服务端 TUN 泵限制）。
- 1200B 档改造后比改造前高 0.21 µs（1.92 → 2.13）：小分组的线性区头长很小，本来不需要整包搬迁；这点差异来自
  多预留 16B 头空间与运行间波动，属噪声量级。
