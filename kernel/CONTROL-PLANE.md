# iWAN 内核数据面控制面 ABI（v1，冻结）

模块、客户端、服务端三边同时改动，因此本文件是唯一的接口约定。任何一方需要
新字段，先改这里再加实现。

## 1. 为什么必须是 netlink，而不是继续扩 /proc

- `/proc/net/iwan` 只能做"配置 + 计数器"，无法**反向**通知用户态。会话超时、
  对端 `PT_CLOSE`、控制帧到达都需要内核主动上报。
- 配置项随会话增多（凭据、隧道参数、对端地址、MTU），逐字段拼字符串很快失控。
- 现有 `/proc` 写路径保留一个版本作为兼容与测试手段，但**新功能只加在 netlink 上**。

## 2. 家族与寻址

| 项 | 值 |
|---|---|
| 家族名 | `"iwan"` |
| 版本 | 1 |
| `netnsok` | true —— 一切状态以**发送 socket 所在的 netns** 为准 |
| 多播组 | `"events"`（内核 → 用户态） |
| `events` 组权限 | 要求 `GENL_MCAST_CAP_NET_ADMIN`（v1 已收紧，见 §4） |

每 netns 一份会话状态。模块参数（`sid/tok/key/enc/dport/...`）降级为**默认值**，
只在该 netns 尚未通过 netlink 建立会话时生效；测试脚本沿用参数即可，不受影响。

## 3. 命令（用户态 → 内核）

### `IWAN_CMD_SESSION_UP`
建立会话，幂等地把该 netns 切到内核数据面。

| 属性 | 说明 |
|---|---|
| `IWAN_A_SID` (u16) | 会话号 |
| `IWAN_A_TOK` (u32) | 凭据 token |
| `IWAN_A_ENC` (u8) | 1 = `PT_DATA_ENC` + XOR，0 = `PT_DATA` 明文 |
| `IWAN_A_KEY` (8B) | 会话密钥 = MD5(user‖pass)[0..8) |
| `IWAN_A_OUTER_SRC` / `IWAN_A_OUTER_DST` (be32) | 本端 / 对端外层地址 |
| `IWAN_A_DPORT` / `IWAN_A_SPORT` (be16) | 外层端口（sport 省略 = 用 dport）。**接收侧只接受目的端口 = SPORT（未给则 DPORT）**；TX 的源端口 = SPORT |
| `IWAN_A_MTU` (u32) | 设备 MTU，缺省 `1500 - IWAN_OVERHEAD` |
| `IWAN_A_FLAGS` (u32) | bit0 建网卡（缺省置位）、bit1 内核代答 `PT_PING_REQ`（**保留未实现**，见 §4） |
| `IWAN_A_OIF` (u32) | 绑定的承载网卡 ifindex（"绑网卡"）；0/省略 = 不绑，由 FIB 解析一次后钉住 |
| `IWAN_A_IP` (be32) | 绑定的**出口 IP**（"绑 IP"）：内核按本机地址表解析出持有该地址的接口并按它钉住承载网卡；该地址同时是外层 IP 头的源地址，故必须等于 `IWAN_A_OUTER_SRC`（不等 = `-EINVAL`）。不属于任何本机接口 = `-EADDRNOTAVAIL`。与 `IWAN_A_OIF` 同时给出时必须指向同一张接口（否则 `-EINVAL`） |
| `IWAN_A_CARRIER` (u32) | **只读**：回执/快照里给出当前实际承载网卡 ifindex（0 = 尚未解析）。写路径忽略 |
| `IWAN_A_OUTER_SRC6` / `IWAN_A_OUTER_DST6` (16B) | 外层 **IPv6** 的本端 / 对端地址（切片 2）。外层版本**不设单独开关**，由"给了哪一对地址"决定：只给 v4 那对 = 外层 v4；只给 v6 这对 = 外层 v6；**两对同时给 = `-EINVAL`**；只给一对里的一半也 = `-EINVAL`。回执只在这条会话是外层 v6 时才发这三个属性（族由"属性在不在"表达） |
| `IWAN_A_IP6` (16B) | 外层 v6 的"绑 IP"（与 `IWAN_A_IP` 逐条同义）：必须等于 `IWAN_A_OUTER_SRC6`、必须属于某张本机接口（`ipv6_chk_addr(strict)`，tentative 不算）、与 `IWAN_A_OIF` 同时给出时必须同接口。给错族（v4 会话带 `IWAN_A_IP6`，或 v6 会话带 `IWAN_A_IP`）= `-EINVAL`，不做隐式转换 |

**外层 v6 的两条硬约束**（都不是实现细节，是语义前提）：

1. **不分片**。IPv6 没有 DF 位，源端分片只会换到对端按"外层 v6 分片"丢弃（记
   `IWAN_S_RX_FRAG6`，包交回协议栈、不按本隧道解封；首片也拒 —— 载荷残缺，而
   RX 的内层判据是宽松口径）。因此 `SESSION_UP` 把
   **内层 MTU + `IWAN_OVERHEAD_V6`(56 = 8B 帧头 + 8B UDP + 40B IPv6) ≤ 承载网卡 MTU** 当作会话能否建立的判据：
   不满足返回 `-EMSGSIZE`（承载网卡 MTU 是本设计唯一已知的路径 MTU 下界，内核
   数据面没有 socket、收不到 ICMPv6 PTB）。出站路径上再兜一次（承载 MTU 中途
   变小），超了就丢弃并计 `tx_err`，绝不悄悄分片。
2. **MTU 硬上限按族不同**：外层 v4 受 16 位总长限制（`IWAN_MTU_HARD_MAX`），
   外层 v6 的载荷长度也是 16 位但基本头多 20 字节，所以是
   `IWAN_MTU_HARD_MAX_V6`（低 20）。绑定与承载解析走各自的族（v6 用
   `iwan_carrier_resolve6`，同一套"显式绑定不许漂移"语义，多一个 `-EMSGSIZE`）。

绑定三模式（互斥、可组合"绑 IP + 绑网卡"作一致性约束）：都不给 = 什么都不绑
（FIB 解析一次后钉住，路径失效时按 FIB 自愈）；只给 `OIF` = 绑网卡；给 `IP` =
绑出口 IP。三者在数据面收敛到同一条路径：`pn->carrier` 记实际用的那张网卡，
出站查找带 `flowi4_oif`、入站按 ifindex 过滤、`needed_headroom` 按它推导。
**显式绑定（OIF 或 IP）失败时绝不漂移到别的网卡**，只计 `tx_err`；只有"什么都
不绑"才自愈重解析。语义与实测（设备 down/删除/删地址）见
`docs/kernel-data-plane.md` 的"承载网卡事件语义"。

行为：按需创建 `iwan0`（`rtnl_link_ops`，进程上下文，无 pernet 顺序问题）→
写入会话状态 → 解析并钉住承载网卡（显式绑定失败即拒绝会话，不留半套状态）→
打开数据面。回执带设备名、实际 MTU 与设备归属 `IWAN_A_DEV_OWNED`。

两道前置闸门（都在建会话之前，失败不会留下半套状态）：

- **RX 钩子闸门**：该 netns 的 `nf_register_net_hook()` 曾经失败（`pn->rx_hooked`
  为 false）时直接回 `-EIO`。否则用户态会拿到"会话成功 + iwan0 已 UP"的回执，
  实际一个入站包都不会被解封 —— 排障时会一路怀疑对端。
- **设备类型闸门**：`iwan0` 这个名字上已经有一张**不是本模块**的设备
  （`dev->rtnl_link_ops != iwan_link_ops`，例如用户自己用 TUN 建的 `iwan0`）
  时回 `-EBUSY`：不复用、不置 UP、**不改它的 MTU**。理由见 §10 第 3 条 ——
  老实现只打印一句警告然后继续复用，会把用户正在跑的隧道改坏。

### `IWAN_CMD_SESSION_DOWN`
关闭数据面 → 清零凭据与 keepalive 时间戳 → 删除由模块创建的那张网卡。
（对应用户态原来的 `tun_close()`。）

删除按**会话认领时记下的 ifindex** 定位，不按名字：设备被改名
（`ip link set iwan0 name ...`）后按名字会"找不到 → 报成功"，而设备其实还在。
删除失败时保留所有权记录，重复 `SESSION_DOWN` 可以接着删。

### `IWAN_CMD_SET_PEER`
只更新 `OUTER_DST` / `SPORT` / `DPORT`，用于对端地址漂移或换线，不必重建会话。

### `IWAN_CMD_SET_ENABLED`
临时停/启数据面而不丢会话状态。

### `IWAN_CMD_GET_STATS`
回执：配置快照 + 全部计数器 + `last_keepalive_ms`（单调时钟毫秒）+ `peer_state`。
支持 `NLM_F_DUMP` 风格逐 netns 枚举（需要时再加）。

两条必须记住的口径：

- **`GET_STATS` 会回传 `IWAN_A_KEY`**（明文 8 字节密钥），与下发值逐字节相同。
  `kernel/iwan_genl.h` 里旧版注释写的"KEY 不回传"与实现相反，**以实现为准**
  （该注释已改）。正因如此：**不要把 `get-stats` 的输出写进日志、工单或上报**
  —— 它包含完整会话凭据（KEY/SID/TOK）。
- 新增计数器 `IWAN_S_EV_DROPPED`（`ev_dropped`）：控制帧事件被限速丢掉的条数，
  见 §4 与 §10 第 9 条。`/proc/net/iwan` 的列序已冻结，这个计数器**只**出现在
  这里。

## 4. 事件（内核 → 用户态，多播组 `events`）

| 事件 | 触发 | 载荷 | 状态 |
|---|---|---|---|
| `IWAN_EV_CTRL_FRAME` | 收到**非数据**帧（`PT_OPEN*`/`PT_ECHO_*`/`PT_PING_*`/`PT_CLOSE`） | 原始帧字节（外层头之后，上限 512B）+ 外层五元组 | 已实现 |
| `IWAN_EV_PEER_CLOSE` | 收到 `PT_CLOSE` | sid | 已实现 |
| `IWAN_EV_PEER_SILENT` | 连续 `silent_ms` 未收到任何有效帧 | 静默时长 | **保留编号，v1 不产生**：内核不做静默判定（无定时器/无 `delayed_work`），生产函数 `iwan_ev_peer_silent()` 已删除 |
| `IWAN_EV_KEEPALIVE` | 收到 `PT_PING_REQ/RSP` | 时间戳（可选订阅，默认只更新状态） | 已实现 |

### 4.1 握手在用户态，内核只接管握手之后的数据面

这一条是理解整份 ABI 的前提，v1 立项时表述得不够清楚：

- 握手（`PT_OPEN`/`PT_OPEN_ACK`/`PT_OPEN_REJECT`）与 **HMAC 验签**都在**用户态**。
  握手期间内核**还没有会话**，RX 钩子只做外层四元组 + 目的端口过滤，然后
  `NF_ACCEPT` 放行 —— 报文照常上到 UDP 层，由**应用自己的 socket** 收到
  `OPEN_ACK`。所以"握手包被钩子吞掉"这件事在 v1 里并不存在。
- 会话建立之后，钩子才开始按凭据闸门接管入站：**数据帧交换、keepalive 接收、
  断线（`PT_CLOSE`）接收**。此时同一个 UDP 端口上的入站控制帧会被吞掉，
  必须靠 `IWAN_EV_CTRL_FRAME` 原样转交给用户态（否则用户态再也看不到
  `PT_ECHO_*`/`PT_PING_*`/`PT_CLOSE`）。
- 因此 **`IWAN_EV_CTRL_FRAME` 只在"已建立会话"的阶段是必需的**，而不是全生命
  周期；说它"架构上不可省"的旧表述只在会话建立后成立。
- 存活依据走共享内存页（§11）：用户态**1s 轮询** `last_rx_ms`（`src/common/kdp.c`
  的 `KDP_POLL_MS`），见到 0 立即判定断线并重连；`events` 组降级为
  **可选/诊断**通道（想更快感知 `PT_CLOSE` 或想看控制帧原文时才订阅）。
- **重连必须先 `SESSION_DOWN` 再重新握手**：换端口/换凭据都要重建会话
  （`SESSION_UP` 与已有会话参数不一致会直接 `-EINVAL`），而只有 `SESSION_DOWN`
  会把留在内核里的会话、设备与共享内存页清干净。反过来（先 `SESSION_UP` 再
  `SESSION_DOWN`）会把刚建好的会话拆掉。
- **内层版本与数据面无关**：`SESSION_UP` 的参数描述的是**外层**（四元组、端口、
  绑定、MTU），内层报文由 TX/RX 按版本各自校验后原样透传 —— 内层 IPv4 与内层
  IPv6（挂在同一个外层 v4 会话里，即 "v6 in v4"）都支持，不需要新属性。
  内层 v6 与外层版本不同，投递时一律 `netif_rx` 重新入栈（`NF_ACCEPT` 那条路
  是按外层版本进来的，版本一变必然误解析）；内层 v4 保持原有投递方式。
  ABI 里**没有**内层地址项，所以模块不做内层地址准入过滤（只有模块参数
  `inner_src` 这个 v4 白名单，不在本 ABI 内）；用户态 TUN 面的会话级准入过滤
  （内层 IP / 派生 ULA）见 `docs/kernel-data-plane.md` 的策略差异一节。

### 4.2 事件通道的限速与权限

- **权限**：`events` 组已加 `GENL_MCAST_CAP_NET_ADMIN`。组内载荷包含控制帧原文、
  对端外层地址与 SID，而 genetlink 的每 netns socket 默认以
  `NL_CFG_F_NONROOT_RECV` 注册 —— 不加这个标志，同 netns 任意本地用户都能订阅，
  属实际权限缺口。
- **限速**：每 netns 一个令牌桶（100 帧/秒、突发 200 帧，见
  `kernel/iwan_netlink.c` 的 `iwan_ev_rate_ok()`）。控制帧路径**没有**可用的
  凭据闸门 —— `PT_OPEN*` 必须放行（见 §10 第 5 条），否则用户态收不到握手；
  没有限速的话，任意源都能用伪造帧把 `genlmsg_new(GFP_ATOMIC)` + 多播打满。
  超限的帧：`genlmsg` 都不分配，直接计入 `IWAN_S_EV_DROPPED`。
- 限速**只**影响多播，不改变数据面看到了什么：`last_rx_ms`/`peer_state` 的记账
  在进桶之前完成，`PT_CLOSE` 的"时间戳置 0"也照旧执行 —— 否则洪水就能顺带把
  断线检测关掉。
- `IWAN_A_FLAG_ANSWER_PING`（bit1，内核代答 `PT_PING_REQ`）**保留、未实现**：
  ABI 里只保留这一个位号，**置位即 `-EINVAL`**（宁可拒绝，也不假装支持）。
  曾经的"把开关记进会话"已删（会话结构里不再有这个字段，`GET_STATS` 也不回传），
  代答本身留到 v2。

## 5. keepalive 与断线（共享内存页 + 用户态轮询）

原设计是"keepalive 写共享内存时间戳、断线清零"。v1 实现**就是**这样落地的，
只是那份内存不是环形区，而是每 netns 一页只读快照（`/dev/iwan`，完整 ABI 见
§11）—— 所以本文件旧版"内核数据面下不再需要共享内存"的结论**已被推翻并删除**，
它当时假设"用户态会被 `IWAN_EV_PEER_SILENT` 唤醒，不需要轮询"，而该事件在 v1
根本不会产生 —— 内核没有定时器，也就没有"多久算静默"的判定点（编号保留，
生产函数已删；判活只有用户态轮询这一条路）。

现在的口径：

1. 内核每收到一个**通过凭据闸门**的帧（数据帧或控制帧）就把当前单调毫秒写进
   该 netns 的共享内存页 `last_rx_ms`；用户态 mmap 之后 **1s 轮询**它。
2. 收到 `PT_CLOSE(0x17)` 时 `last_rx_ms` 立即置 0，`peer_state` 落成
   `IWAN_PEER_CLOSED`；用户态见到 0 即判定断线并退出（**不需要**系统调用）。
3. `IWAN_CMD_GET_STATS` 的 `IWAN_A_LAST_KEEPALIVE_MS` / `IWAN_A_PEER_STATE`
   与共享内存页是**同一个存储**（单一数据源），两条路径读到的值必然一致。
4. keepalive 的**发送**仍在用户态；内核只负责"收到就记时间"。
5. 想更快感知断线可以订阅 `events`，但那是可选/诊断路径，正确性不依赖它。

也就是说：**断线检测 = 用户态轮询共享内存页**，这是 v1 唯一可用的机制；
`IWAN_EV_PEER_SILENT`（内核主动上报静默）留到 v2：真要做就得重新引入一个
生产者（§10 的待定项），v1 的编号保留只是为了让 ABI 不改号。

## 6. 用户态映射

| 现有调用 | 新路径 |
|---|---|
| `open_tun(name)` | `SESSION_UP`（内核建设备），随后沿用现有 `ip addr/route` 配置代码，设备名取回执 |
| `tun_close(fd)` | `SESSION_DOWN` |
| TUN fd 写内层包（服务端 `tun_write_retry`） | 消失：内核解封后直接投递 |
| TUN fd 读内层包 | 消失：本机流量由协议栈直接送给 `iwan0` |
| 用户态 socket 收控制帧 | `IWAN_EV_CTRL_FRAME`（会话建立后必需；握手阶段仍走自身 socket，见 §4.1） |
| 用户态 socket 发控制帧 | 仍用自身 UDP socket（出站不经 `iwan0`，不受影响） |
| 多队列 `tun_attach_many` fan-out | 消失：内核侧天然并行，无需 fd 传递与去特权队列 |
| 用户态"对端还活着吗" | 只读 mmap `/dev/iwan`，1s 轮询 `last_rx_ms`（§5、§11） |

SOCKS 模式（用户态终结 TCP、需要把内层包注入隧道）走裸套接字：`IP_HDRINCL` +
`SO_BINDTODEVICE=iwan0` 发送，等价于原来的"写 TUN fd"。这一条在实现前需要一次
单独验证（内核是否会因 `iwan0` 是 `IFF_POINTOPOINT` 而改写源地址）。

## 7. 迁移与回滚

- 用户态加开关 `--data-plane=kernel|tun`，默认仍是 `tun`，两条路径可同时存在、
  可对照测试；验证完成后再改默认值。
- `/proc/net/iwan` 读路径保留（测试与排障依赖），写路径标记为废弃。
- 模块参数保留，作为 netlink 未配置时的默认值。

## 8. 实施与验收顺序

1. **模块**：netlink 层 + 每 netns 会话状态 + 设备创建/删除 + 事件。
   验收：`kernel/tests/netlink_test.sh`（新）用一个小工具跑通
   `SESSION_UP → 发数据 → 收事件 → GET_STATS → SESSION_DOWN`，
   且既有 `tcp_echo_test.sh` 13 项不受影响。
2. **客户端**：`--data-plane=kernel` 路径打通，控制帧来自事件，
   与 `tun` 路径做同机对照（同一 4 MiB echo、0 校验和错误、0 重传）。
3. **服务端**：去掉 TUN 写路径与多队列 fan-out，实测吞吐对比。
4. **收尾**：per-CPU 计数器、真机 GSO/TSO/多队列与延迟实测，
   补 `docs/perf-plan.md` 的本模块一列。

## 9. 已知风险

- 同一 UDP 端口上"内核拦入站 + 用户态发出站"并存，两侧配置必须一致
  （`sport`/`dport`），否则控制帧与数据帧会走上不同路径；`SESSION_UP` 建立时
  校验一次并拒绝不一致的配置。
- **外层端口口径（v1 最终）**：接收侧**只接受目的端口 = `SPORT`**（未给 `SPORT`
  时 = `DPORT`），TX 的源端口 = `SPORT`。刻意不做"两个端口都接受"：那会把发给
  对端端口的包也吞掉。两端的 `dport`/`sport` 必须**互为对方的 sport/dport**
  （典型配置：`iwc --dport 6100 --sport 6200`、`iws --dport 6200 --sport 6100`）。
  真实客户端的本地端口是临时端口，与对端 `DPORT` 不同 —— 只认 `DPORT` 的实现
  会让入站包永远不匹配（内核数据面等于死的），这正是当初两端同端口测试掩盖的
  缺陷。
- 每 netns 会话状态是新增的数据结构，必须与 pernet 生命周期绑定，
  不能在 `SESSION_UP` 里分配在别的 netns 上（凭发送 socket 的 netns 取）。
- 事件多播在 netns 内投递，订阅 socket 必须在目标 netns 内创建。
- 设备所有权按 `dev_owned && ifindex` 判定，存在一个**很窄**的 ifindex 复用
  误删窗口（见 §10 第 3 条）；比旧的"按名字认领"窄得多。

## 10. v1 实现现状（模块侧已落地）

`kernel/iwan_netlink.c` 已按本文件实现，`make -C kernel` 零告警。落地时确定、
而本文件原先没写死的口径，一并记在这里：

1. **会话路径恒 `any_dir`**：`OUTER_SRC/DST` 是"本端/对端"这一对身份，TX 为
   src→dst，同一会话的入站天然是 dst→src；模块参数的 `any_dir` 只作用于
   无会话的回落路径。
2. **`SESSION_UP` = ensure up**：参数完全一致的重复调用是幂等重放（重新置
   `enabled=true`，不重置 keepalive/peer_state）；任一参数不同则 `-EINVAL`，
   要求先 `SESSION_DOWN`（换线/漂移走 `SET_PEER`）。
3. **设备所有权（v1.1 收紧）**：只删模块创建/认领的那张网卡，用户自建的卡不动。
   具体口径：
   - **类型闸门**：同名设备不是本模块的（`rtnl_link_ops != iwan_link_ops`，例如
     用户用 TUN 建的 `iwan0`）→ `SESSION_UP` 回 `-EBUSY`，不复用、不置 UP、
     不改 MTU。TUN 与 iwan 的 `ARPHRD` 同为 65534，只看名字/链路类型分不出来。
   - **归属判定**：`dev_owned && ifindex` 同时成立才算"我们认领过"。身份用
     `ifindex` 而不是名字：改名（`ip link set iwan0 name x`）后按名字删除会
     "找不到 → 报成功"，设备却还留着。
   - `prev_owned` **不**加 `was_valid` 条件：上一次 `SESSION_DOWN` 删设备失败时
     `valid` 已落而 `dev_owned`/`dev_ifindex` 还留着，下一次 `SESSION_UP` 必须
     接着认领，否则那张设备此后谁也删不掉。
   - 删除失败保留所有权，可重复 `SESSION_DOWN` 重试。
   - 残留窗口：用户删掉我们的设备后又建了一张 **iwan 类型**设备且内核复用了同一
     `ifindex` 时会被误认（要同时满足三个条件，且被删的仍是一张本模块能服务的
     iwan 设备，不是用户的 TUN）。
   - 回执新增 `IWAN_A_DEV_OWNED`（1 = 由会话负责删除），旧客户端忽略即可。
4. **无会话时的行为保证**：`sess.valid == false` 时数据面逐位等于引入控制面
   之前（`cfg.*` + `/proc` 端点 + `cfg.enabled && pn->enabled`），非数据帧仍按
   `rx_bad_hdr` 丢弃。这是既有 13 项验收不回归的依据。
5. **控制帧凭据分类型**：`PT_PING_REQ/RSP`(0x29/0x2A) 接受协议固定凭据
   `0xFFFF/0xFFFFFFFF`（否则 keepalive 永远上不来）；`PT_ECHO_*`/`PT_CLOSE`
   必须等于会话 sid/tok；`PT_OPEN*` 的凭据内核无法预知，只做外层四元组过滤后
   交给用户态验签。
6. **`needs_free_netdev`**：控制面会反复建删设备，必须置该标志，否则每次
   `SESSION_DOWN` 泄漏一个 net_device（已修）。
7. `kernel/iwan_genl.h` 已补三处歧义点：公共 `IWAN_KEY_LEN`、属性字节序约定
   （整数主机序 / 地址端口网络序 / 转换只在 netlink 边界做一次）、`GET_STATS`
   在无会话时的回执契约。
8. **RX 钩子闸门**：`iwan_rx_net_init()` 的返回值在 `iwan_core.c` 里刻意不传播
   （让整个 netns 建不起来代价太大），失败时 `pn->rx_hooked` 保持 false；
   `SESSION_UP` 检查它并回 `-EIO`，避免"会话成功但一个包都收不到"。
9. **事件限速**：每 netns 令牌桶 100 帧/秒、突发 200 帧，纯原子实现（软中断里
   不能睡、不能分配、不能加锁），超限计入 `IWAN_S_EV_DROPPED`。限速只挡多播，
   不挡共享内存记账与 `PT_CLOSE` 语义（§4.2）。
10. **`rtnl_configure_link()` 的返回值必须看**：失败说明设备没完成初始化，
    当场 `rtnl_delete_link()` 并返回错误，不能把半成品留给用户态（旧实现丢弃了
    返回值）。
11. **`dev->mtu` 直接赋值，不调 `dev_set_mtu()`**：后者会发
    `NETDEV_CHANGEMTU` 通知（可观测性更好），但是否内部重取 `rtnl` 随版本而异，
    而调用点已持有 `rtnl_lock()` —— 重入即死锁。取舍：一条通知不值得冒整机僵死
    的风险；设备刚建/还没 UP，没有观察者依赖这次 MTU 变化，范围也已在
    `SESSION_UP` 入口校验（与 `session.mtu` 存**生效值**的口径一致）。

### v2 待定（需拍板才能动）

- **`IWAN_EV_PEER_SILENT` 只是一个保留编号**：v1 没有生产者（判活全在用户态
  轮询 `/dev/iwan`，§5）。要做就得先定义"多少秒算静默"：建议加
  `IWAN_A_SILENT_MS`(u32，0 = 禁用) + per-netns `delayed_work`，并重新引入
  一个多播函数。**`IWAN_A_FLAG_ANSWER_PING` 同样只是保留位**（置位即
  `-EINVAL`，见 §4）。
- `GET_STATS` 只回本 netns，没有 `NLM_F_DUMP`；跨 netns 枚举需要一个 DUMP 命令。
- `LAST_KEEPALIVE_MS` 目前只读；若需要主动复位，加
  `IWAN_A_FLAG_RESET_KEEPALIVE`。
- 设备名恒为 `iwan0`；一命令多卡需要 `SESSION_UP` 允许入参 `IWAN_A_DEVNAME`。
- 同 netns 并发 `SESSION_UP` 未串行化（与既有 `cfg` 约定一致）；需要可加
  per-netns mutex。
- 新代码按 7.0.0-38 的内核头签名书写；更老内核需要 `#if` 分支，本机无法验证。

（已落地、原先列在这里的两项：`events` 组已要求 `GENL_MCAST_CAP_NET_ADMIN`；
`GET_STATS` 的 KEY 回传口径已写清 —— 它**会**回传，见 §3。）

### 已发生的缺陷（必须记住）

1. **`rtnl_create_link()` 不接受 NULL `tb`**（2026-10-06，导致整机卡死）。
   本内核签名是 `(net, ifname, name_assign_type, ops, struct nlattr *tb[], extack)`，
   而它在函数入口就无条件读 `tb[IFLA_NUM_TX_QUEUES]`（反汇编为
   `+0x22: mov 0xf8(%tb),%rax`）。传 NULL 的后果不是返回错误，而是：

   ```
   RIP: rtnl_create_link+0x22
   Call Trace: iwan_genl_session_up+0x513 [iwan]
   note: iwan_ctl exited with irqs disabled
   ```

   由于此处**持有 `rtnl_lock()`**，任务带锁退出 → 路由/网络子系统连同依赖它的
   用户态一起僵死。整机表现：ping（软中断）仍通、SSH 不响应、切不了 TTY、
   鼠标能动；只有硬复位能恢复，且 oops 要重启后从持久化日志里读。
   修法：传全零的 `struct nlattr *tb[IFLA_MAX + 1]`（等价于"不带属性"）。

   教训有两条：**编译零告警不等于 API 用对**，`tb`/`extack` 这类"看起来可以为
   NULL"的参数必须按本机内核实现核对；**在持有 rtnl 锁的路径上新增任何调用，
   都要假设它可能 panic**，先在可承受重启的环境里验证。

2. 事件发送必须用 `GFP_ATOMIC`：RX 路径在 netfilter/软中断上下文，
   `genlmsg_new()` 与 `genlmsg_multicast_netns()` 的 flags 都要是 `GFP_ATOMIC`；
   用 `GFP_KERNEL` 会触发 "sleeping function called from invalid context"。

## 11. 共享内存 ABI（`/dev/iwan`，每 netns 一页，v1 冻结）

本节是 `kernel/iwan_shm.h` 的说明文档；**偏移量以头文件为准**，两边都有
`static_assert` 把结构体布局钉在冻结值上（内核 `iwan_shm.c`、用户态
`kernel/tests/iwan_shm.c` 各一份）。

### 11.1 是什么、为什么需要

- 一片内存 = **一页**（`PAGE_SIZE`）= **一个 netns**；misc 设备 `/dev/iwan`
  （`mode 0444`），用户态 `open(O_RDONLY)` + `mmap()` 后按固定偏移读字段。
- 它存在的唯一理由是 §5：内核每收到一个**通过凭据闸门**的帧就写一次单调
  毫秒，用户态**不需要任何系统调用**就能轮询"对端还活着吗"。keepalive 的发送
  在用户态，所以"存活依据"必须由内核给出。
- 页面里**没有密钥**等敏感数据，因此不加 capability 检查：进程只能看到**自己
  netns** 的那一页（`open()` 时绑定 `current->nsproxy->net_ns`）。

### 11.2 页面布局（偏移 + 大小，全部相对映射起始地址；字段一律主机序）

| 偏移 | 类型 | 字段 | 含义 |
|---|---|---|---|
| `0x00` | u32 | `version` | `IWAN_SHM_VERSION`（当前 1）。**页面身份**，`SESSION_DOWN` 清零时也保留 |
| `0x04` | u32 | `pad` | 对齐填充，恒 0 |
| `0x08` | u64 | `last_rx_ms` | 最近一次有效帧的单调毫秒；**0 = 从未收到 / 已断开** |
| `0x10` | u32 | `peer_state` | `enum iwan_peer_state`（`iwan_genl.h` 复用） |
| `0x14` | u32 | `enabled` | 会话级数据面开关（会话开关 && 模块参数总开关） |
| `0x18` | u64 | `rx_frames` | `pn->st.rx_frames` 的镜像快照（数据帧） |
| `0x20` | u64 | `rx_ctrl_frame` | `pn->st.rx_ctrl_frame` 的镜像快照（**过了凭据闸门**的控制帧） |
| `0x28` | — | 保留区 | 到页尾恒 0（写者只写上面这些字段） |

头部大小 `IWAN_SHM_HDR_SIZE = 0x28`。字段增删必须 `IWAN_SHM_VERSION + 1`，并同步
内核/用户态两处 `static_assert`。

### 11.3 与 netlink 的关系：同一个存储，不是两份

`IWAN_A_LAST_KEEPALIVE_MS` 与 `IWAN_A_PEER_STATE` **就读这一页**，会话结构体
`struct iwan_session` 里不另存一份。所以：

- `GET_STATS` 拿到的时间戳 = mmap 读到的时间戳（同一个 `u64`）；
- 时基统一是 `iwan_now_ms()`（`ktime_get_mono_fast_ns()` 折算的单调毫秒）；
- `SESSION_DOWN` 之后两边同时归零（见 11.5）。

### 11.4 谁写、谁读

| 角色 | 动作 |
|---|---|
| 内核 RX 钩子（软中断） | 每个过闸帧写 `last_rx_ms`（普通 `WRITE_ONCE`，无锁无分配）；`peer_state` 从 UNKNOWN 抬到 UP |
| 内核 `iwan_rx_ctrl()` | `PT_CLOSE` → `last_rx_ms = 0` + `peer_state = CLOSED`；控制帧计数镜像 |
| 内核 netlink（进程上下文） | `SESSION_UP` 重置会话级字段、`SESSION_DOWN` 整页清零、`SET_ENABLED` 写 `enabled` |
| 用户态 | **只读**：轮询 `last_rx_ms`（0 = 断线）、按需读 `peer_state`/计数 |

### 11.5 会话生命周期与清零语义

- `SESSION_UP`（新会话，`valid` 之前为 false）：`version` 写入、`last_rx_ms = 0`、
  `peer_state = UNKNOWN`、两个会话级计数归零；`enabled` **不在这里置位** ——
  等会话真正生效（`valid` 置位）后由调用者写 1，避免用户态先看到 `enabled=1`
  而数据面还没接上。参数完全一致的幂等重放**不重置**这些字段。
- `SESSION_DOWN`：`memset(shm, 0, PAGE_SIZE)` 后只写回 `version`。用户态此刻可能
  正在读，看到的是"清零过程中"的中间态，但每个字段的终态都是"无会话"
  （`enabled = 0`、`last_rx_ms = 0`），语义安全。
- `SET_ENABLED(0/1)`：只动 `enabled`，不丢凭据。
- **`PT_CLOSE` 的处理与限速无关**：即使事件多播被令牌桶限速丢掉（§4.2），
  时间戳置 0 与 `peer_state = CLOSED` 也照旧执行 —— 否则洪水就能顺带把断线
  检测关掉。

### 11.6 引用计数与 netns 生命周期（不能有 use-after-free）

用户态完全可能"先 mmap、再删 netns"，因此页面寿命**不**依赖 netns：

1. `alloc_page()` 拿到的 1 个引用就是 **pernet 引用**；
2. 每次 `open()` 用 `get_page()` 再持 1 个，`release()` 时 `put_page()`；mmap 的
   vma 持有 file 引用 ⇒ 只要映射还在，页面引用就不会提前释放，用户在 netns
   消失后继续读自己的映射是安全的；
3. `open()` 时按打开进程当时的 netns 绑定，之后 `file->private_data` 只认
   `struct page`，不再解引用 `pn` —— 这正是它能安全工作的原因；
4. pernet exit 的顺序是**硬约束**：先摘 netfilter 钩子（`iwan_rx_net_exit()`，
   内含 `synchronize_rcu()`）→ `pn->shm = NULL` → 最后放 pernet 引用；
5. 最后一个引用由 `put_page()` 回收（order 0）。`pn->shm` 的所有访问都用
   `READ_ONCE(pn->shm)` 并容忍 NULL。

### 11.7 为什么用户态只能读

这一页是"内核 → 用户态"的**单向快照**：内核每收一帧就会覆盖 `last_rx_ms`，
用户态写它没有任何语义（写了立刻被覆盖，只会制造"我写了它却不生效"的误解）。
因此把只读做成 ABI 的一部分，而不是口头约定：

- `open()` 拒绝 `FMODE_WRITE`（`-EACCES`）；
- `mmap()` 拒绝偏移非 0、长度超过一页（`-EINVAL`）与 `PROT_WRITE`（`-EPERM`）；
- `mmap()` 清掉 `VM_MAYWRITE`，使随后的 `mprotect(PROT_WRITE)` 也失败；
- 另置 `VM_DONTEXPAND | VM_DONTDUMP`（不许 `mremap` 扩张、不进 core dump）。

### 11.8 为什么摘钩子后必须 `synchronize_rcu()`

`nf_unregister_net_hook()` 只是把钩子从数组里摘掉、把旧数组交给 `call_rcu()`
释放；一次**已经开始**的遍历（`NF_HOOK` 全程在 `rcu_read_lock()` 里）仍可能调用
到本钩子，而本钩子会写这个 netns 的共享内存页。调用者紧接着就要放页面的
pernet 引用，少了这道栅栏就是"钩子还在跑、页面已回收"的 use-after-free。
pernet exit 在进程上下文，`synchronize_rcu()` 可以睡眠，所以放在
`iwan_rx_net_exit()` 里摘钩子之后。

### 11.9 用户态正确用法（v1 唯一口径）

```c
int fd = open("/dev/iwan", O_RDONLY | O_CLOEXEC);   /* 写方式打开会被拒 */
void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
/* 先校验版本，再按固定偏移读；不要 memcpy 整个结构体当 ABI */
uint32_t ver; memcpy(&ver, p + 0x00, 4);            /* 必须 == IWAN_SHM_VERSION */
uint64_t ms;  memcpy(&ms,  p + 0x08, 8);            /* 0 = 断线 */
```

- **1s 轮询**（`src/common/kdp.c` 的 `KDP_POLL_MS = 1000`）足够：keepalive 周期
  远大于 1s，`last_rx_ms == 0` 是精确的断线信号（不是超时推算）。
- 想更快感知 `PT_CLOSE`、或要看控制帧原文，再订阅 `events` 多播组（需要
  `CAP_NET_ADMIN`）；那是可选/诊断路径，正确性不依赖它。
- **重连顺序：先 `SESSION_DOWN` 再重新握手**。只有 `SESSION_DOWN` 会把内核里的
  会话、设备与这一页清干净；换端口/换凭据时 `SESSION_UP` 也会直接 `-EINVAL`
  （见 §4.1）。
- 只读工具：`kernel/tests/iwan_shm.c`（dump/watch，含与内核等价的偏移断言）。
