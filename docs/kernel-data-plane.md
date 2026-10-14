# 客户端内核数据面（`--data-plane kernel`）

客户端可以不再需要 TUN：把数据面交给内核模块 `iwan`（`/dev/iwan` + genetlink
控制面），用户态只负责握手、密钥派生、keepalive 发送和存活判定。

```bash
# 默认行为完全不变（TUN 用户态泵）
sudo iwan-client proxy --server <HOST> --user <U> --pass <P>

# 内核数据面：不建 TUN，设备由模块按需创建
sudo iwan-client proxy --server <HOST> --user <U> --pass <P> --data-plane kernel
```

| 二进制 | 选项 | 取值 | 默认 |
|---|---|---|---|
| `iwan-client proxy` | `--data-plane` | `auto` \| `tun` \| `kernel` | `auto` |
| `iwan-client-oidc` | `--data-plane` | `auto` \| `tun` \| `kernel` | `auto` |
| `iwan-server` | `--data-plane` | 只接受 `tun` | `tun` |

- `kernel` **仅 Linux**：非 Linux 构建显式传 `kernel` 是用法错误（打印
  `error: invalid value 'kernel' for '--data-plane <tun|kernel>': ...` + usage，
  退出码 2），**不会**静默降级成 `tun`。`iwan-winsvc.exe`（Windows）因此永远
  走不到内核数据面代码。
- `auto`（默认）：Linux 上选内核面，内核面在本机不可用时（模块未加载、`/dev/iwan`
  缺失或布局版本不符、`iwan0` 被非 iwan 设备占用）**自动回退 TUN**，两边都起不来
  才退出；非 Linux 上直接是 `tun`。显式 `tun`/`kernel` **不回退**；`auto` 命中
  "本 netns 已有内核会话/设备被占"时也不回退 —— 回退会用同一账号把那条活会话
  顶掉（服务端对同源外层地址的第二次 OPEN 按合法重连处理）。绑定
  （`--bind-dev`/`--bind-ip`）只有内核面能实现，`auto` + 绑定直接选内核面并关掉
  回退；`--listen`/`--socks-*` 是 TUN 面的用户态特性，`auto` + 它们直接选 TUN。
- `--proxy-cidr6`（内层 IPv6）**两个面都支持**，也不再影响选面：
  - 内核面：模块按版本校验内层头（v4 看 `tot_len`、v6 看 `payload_len` + 扩展头
    链），内层 v6 挂在外层 v4 里（`v6 in v4`）时走 `netif_rx` 重新入栈 ——
    `NF_ACCEPT` 是"让当前协议栈路径继续走"，而那条路是按外层 v4 进来的，版本
    一变必然误解析。内层 v4 的投递方式逐位不变。
  - TUN 面：用户态泵把内层分组当载荷透传（本来就支持 v6）。
  - 路由：两个面都由 `route_setup6` 装、退出时回滚。内层地址是**会话派生 ULA**
    （`fd00::/96` + 内层 IPv4 低 32 位，`ip6_derive_ula()`），由
    `route_iface_up()` 的 v6 侧自动配到隧道网卡上，不需要额外配置。
  - 唯一硬门槛是内层 MTU ≥ 1280（RFC 8200 §5）：IPv6 路由器不做分片，链路小于
    1280 时 v6 必然不通。生效 MTU < 1280 且给了 `--proxy-cidr6` 时打警告（不拒绝）。
  - **策略差异**（刻意）：TUN 面的用户态泵按会话内层 IP / 派生 ULA 做准入过滤
    （下行帧必须发往本会话地址、且不得假冒本会话地址为源）；内核面只做内层头
    自洽校验，地址过滤仍只有模块参数 `inner_src` 这个 **v4 白名单**（`__be32`，
    表达不了 v6，也不在 genetlink ABI 里）。要把同样的 v6 准入过滤搬进内核，得
    先给 ABI 加内层地址项。
- `kernel` 与 `--listen` / `--socks-token` / `--socks-no-token` / `--allow-remote`
  （oidc 侧还有 `--socks` / `--socks-listen`）互斥：用户态 SOCKS 代理和内核钩子
  会在同一条外层套接字上抢包。组合使用按用法错误拒绝（退出码 2）。
- `--tun` 在 `kernel` 模式下无效（模块固定 `iwan0`），显式给出别的名字会打一条
  警告后忽略；`--mtu` 仍然生效（下发到 `SESSION_UP`，并决定地址/路由 MTU）。
- 服务端目前不支持内核数据面（`--data-plane kernel` 是用法错误），原因见
  [服务端为什么没有 kernel 数据面](#服务端为什么没有-kernel-数据面)。

## 前提条件

1. 内核模块已加载且与客户端**同批构建**：`sudo insmod kernel/iwan.ko`，加载后
   必须存在 `/dev/iwan`。
2. `iwan0` 没有被别的接口占用（例如真实的 iWAN 隧道正把它当 TUN 用）。
   客户端会先看 `ip -d link show dev iwan0` 的 kind：
   - 不存在 → 放行（`SESSION_UP` 按需创建）；
   - `iwan` → 放行；
   - 其它（`tun` 等）→ 中文硬报错并退出，绝不接管别人的设备；
   - 老 iproute2 不给 kind → 放行并提示，`SESSION_UP` 的 `-EBUSY` 兜底。
3. 需要 root（`SESSION_UP` 会建网卡；地址/路由仍由用户态配置）。
4. 外层地址不能是回环地址：内核数据面用于**同机回环拓扑**（如
   `tests/tun_local_test.sh`）时，回环包会重新进入本机钩子被吞掉。客户端会直接
   拒绝 `127.0.0.0/8` 的任一端并提示改用两个 netns + veth。

量吞吐：`sudo env KERNEL=1 bash tests/bench_proto.sh`（需模块已加载）会在同一条
veth 拓扑上把客户端切到内核数据面，与 TUN 档、裸 lo 基线同参数对照，证据取客户端
`iwan0` 的 sysfs 计数；口径与实测表见 `docs/perf-plan.md`。

## 读数口径：`iwan0` 的 `rx_bytes` 恒为 0

入站是**直接注入协议栈**（`netif_rx` / `netif_receive_skb`，见 `iwan_rx.c`），不经过
netdev 的驱动 RX 路径，而内核不会替驱动累加 `dev->stats.rx_*` —— 所以 `iwan0` 的
sysfs `statistics/rx_bytes` 永远是 0，哪怕下行流量跑满。出站相反：`iwan_tx.c` 在
`ndo_start_xmit` 里显式累加 `dev->stats.tx_packets/tx_bytes`，`tx_bytes` 可用。

要看入站数量就用会话计数（`IWAN_S_TX_BYTES` 一类，genetlink get-stats / `/dev/iwan`），
或者用外层网卡的到达计数。基准脚本就是后者：内核档 s2c 的客户端侧证据取 netns 里
veth 的 `rx_bytes`，而不是 `iwan0` 的。

## 承载网卡绑定：一条会话只用一张下游网卡

会话建立后，这条隧道的**出站与入站都只认一张下游（承载）网卡**，不去"看路由表当下的
心情"：

人的操作界面有三种模式，它们在数据面收敛到同一条路径：

| 模式 | 下发 | 内核行为 |
|---|---|---|
| 什么都不绑 | `IWAN_A_OIF`/`IWAN_A_IP` 都不给 | 建立会话时按 FIB（含策略路由）解析一次并钉住 |
| 绑网卡 | `IWAN_A_OIF`（u32 主机序 ifindex）；回落路径 `/proc/net/iwan oif=<ifindex>` | 严格用这张接口，失败逐包拒绝，绝不漂移 |
| 绑出口 IP | `IWAN_A_IP`（be32）；回落路径 `/proc/net/iwan ip=A.B.C.D` | 按本机地址表解析出持有该地址的接口，等价于绑那张接口；该地址同时写进外层 IP 头的源地址 |

"绑出口 IP"里**是谁决定 IP 属于哪张网卡**：是**接口地址配置**（地址挂在接口上，
内核里 `in_device` 挂在 `net_device`），不是路由表，也不是网卡驱动——驱动只上报
链路状态（carrier / operstate）。所以内核用 `__ip_dev_find()` 查本机地址表来解析，
**刻意不用 FIB 反查**：按路由反查会让"绑 IP"退化成"由 FIB 决定外层路径"，与"什么都
不绑"失去区分。同一 netns 内一个本地地址只能属于一张接口，因此这个解析是函数关系，
没有歧义。两条硬约束：该地址必须属于本机某张接口（否则 `-EADDRNOTAVAIL`）；它必须
等于会话的 `IWAN_A_OUTER_SRC`（否则 `-EINVAL`），因为外层头的源地址就是它，对端按
五元组过滤时两者必须对得上。与 `IWAN_A_OIF` 同时给出时必须指向同一张接口。

客户端参数（`--data-plane kernel` 专用，TUN 路径的等价绑定尚未实现，给了直接报错）：

```
iwan-client proxy ... --data-plane kernel [--bind-dev <NIC>] [--bind-ip <IP>]
```

- `--bind-dev <NIC>`：名字在启动时解析成 ifindex（会话里仍是 ifindex），并校验存在、
  UP、有载波；
- `--bind-ip <IP>`：必须是本机的 IPv4 地址，且（若同时给了 `--bind-dev`）就在那张网卡
  上；下发时同时作为会话的外层源地址；
- 都不给：什么都不绑。

绑定失效时的反应（两侧分工见下节"承载网卡事件语义"）：内核侧只在**外层查找失败**
时反应；绑定的出口 IP 被删不构成查找失败（实测报文照发），所以"绑定失效即停用数据
面"由客户端判——1 秒节拍里从内核现读接口与地址状态（`getifaddrs`，不缓存），失效即
`SESSION_DOWN`（同时让经 `iwan0` 的那条路由失效，内层流量由路由表的下一条目承担），
重连循环在**重新握手之前**等绑定恢复（`kdp_bind_wait`），恢复后再握手并重新打开。

只读状态（对账用）：`GET_STATS`/回执里的 `IWAN_A_OIF`（请求值）、`IWAN_A_IP`
（请求值）、`IWAN_A_CARRIER`（实际生效的承载网卡 ifindex），另有 `IWAN_S_TX_ERR`
（外层查找阶段丢弃的分组数——显式绑定不可用时只会涨这一项）。

- **未绑定**：建立会话时按 FIB（含策略路由）解析一次，把结果钉住，此后不再逐包变化。
  钉住的那张卡失效（设备被删 / 路由被撤）时会重新解析一次并改钉，仍然只保持一张卡。

钉住结果三处生效：出站查找带 `flowi4_oif`（严格绑定语义）、入站钩子比较
`state->in->ifindex`（不匹配的外层包直接放行，不进解封装——顺带收紧了伪造面）、
`needed_headroom` 按该网卡的 `LL_RESERVED_SPACE()` 推导（只增不减，raw/HDRINCL 路径
因此不再每包重分配 64KB 头）。

注意 `flowi4_oif` 的实际语义：若 FIB 里没有经该设备的路由，内核会为这张 UP 的设备
合成一条 scope link 路由（就是 `SO_BINDTODEVICE` 的效果）；合成只要求设备 UP，
不要求它持有 IPv4 地址（实测：删掉绑定网卡上唯一的地址后报文仍从该卡出线）。所以显式绑定是**硬**
的——报文一定从绑定的卡出去，代价是绑到没有回程路由的卡上会静默黑洞（模块自己会复核
解析出的 ifindex 是否等于绑定值，但"这张卡真能到对端"需要数据面探测，控制面判不了）。

### 承载网卡事件语义（实测，`tests/vm_bind_probe.sh`）

靶场 guest 内只跑 raw：经隧道发 5 个内层报文，观察 `tx_pkts`/`tx_err` 与对端
`rx_packets`。`tx_pkts` = 模块接受并交给外层栈；`tx_err` = 模块在外层查找阶段就丢弃。

| 事件 | 实测计数 | 数据面归宿 |
|---|---|---|
| 显式绑定，接口 UP（基线） | `tx_pkts +5`、对端 RX +5 | 接受并出线 |
| 显式绑定，接口被置 down | `tx_pkts +0`、`tx_err +5`（−ENETUNREACH） | 查找失败 ⇒ 逐包拒绝 |
| 显式绑定，接口恢复 UP | `tx_pkts +5`、对端 RX +5 | 自动恢复，无需重新下发 |
| 显式绑定，删除接口唯一 IPv4 地址 | `tx_pkts +5`、对端 RX +6 | **仍接受并出线**（合成不要求地址） |
| 显式绑定，接口被删除 | `tx_pkts +0`、`tx_err +5`（−ENODEV） | 查找失败 ⇒ 逐包拒绝 |
| 自动绑定，接口被置 down | `tx_err +5`，日志"承载网卡 ifindex=2 已不通（−101），按 FIB 重新解析外层路由" | 先清绑定并按 FIB 重新解析；无可用路径时拒绝 |
| 自动绑定，接口恢复 UP | `tx_pkts +5`，日志再次记"（FIB 解析后绑定）" | 自愈完成：重新解析并重新绑定 |
| 按出口 IP 绑定（`ip=`） | 日志"承载网卡 vethb3 ifindex=4（按出口 IP 10.55.0.2 解析）" | 出站恒走该地址所属的接口，与 FIB 的选择无关 |
| 按出口 IP 绑定后地址被删 | 见上行"删除接口唯一 IPv4 地址" | 内核**不**停止发送：钉住仍在，逐包查找与合成路由都不需要该地址 |
| 钉住被清后再发送（`SET_PEER`/改写外层端点/改 `ip=`） | 按出口 IP 惰性重解析该地址所属接口 | 地址已不属于任何本机接口时计 `tx_err` 丢弃；有绑定规格时绝不改走 FIB 选的卡 |

两条结论：① 管理状态（down/UP）与接口删除会让逐包查找失败，显式绑定下这是
**持续拒绝**——控制面若不反应，会话会一直静默失败（只有计数器与限速日志可见）；
② 自动绑定下数据面自己收敛，但仅在存在可用外层路径时才能恢复，且收敛时延等于
一个报文的处理时间。无论哪种，**删除地址既不是充分条件也不是必要条件**：它不影响
模块能否发送。

复现：`VM_CMD="bash /bench/tests/vm_bind_probe.sh 2000" bash tests/vm_crashlab.sh pack 2000`
再 `run 2000`。用 veth 无法复现 carrier off（veth 的 carrier 恒为 up）；那类事件
需要真实网卡，且它产生的正是"设备 UP 但发送即被丢弃"这一分支——模块记 `tx_pkts`，
链路层丢弃不会回传错误。

## 外层 IPv6（切片 2 起）

外层版本由 `--server` 的**字面量地址族**决定，不需要也不提供族开关：

```bash
sudo ip netns exec iwc iwan-client proxy --server 10.100.0.2   --port 16200 ... --data-plane kernel
sudo ip netns exec iwc iwan-client proxy --server '[2001:db8:1ce::2]' --port 16200 ... --data-plane kernel
```

* 服务端同一 `--port` 同时监听 v4/v6（一个端口两组套接字），会话表按**对端
  地址族 + 地址 + 端口**记录，"同源顶替"的判据也按族走；客户端握手本来就与
  族无关（`getaddrinfo`），变的是数据面的外层头。
* 客户端启动时按已连接套接字的两端地址确认外层：本端地址即外层源地址，
  对端地址必须与 `--server` 字面量一致（与 v4 同一条判据）。回环地址不可用；
  **链路本地地址不可用** —— 内核 ABI 的外层 v6 属性只有 16 字节地址、不带
  scope_id，无法保证发到正确接口。
* `--bind-ip` 同时接受 v4 点分地址与 v6 字面量（族必须与会话外层一致，
  否则会话建立时被 `-EINVAL` 拒）。绑定语义逐条与 v4 相同：必须等于外层源
  地址、必须属于本机某张接口、与 `--bind-dev` 同时给出时必须同接口。
* **内层族与外层族无关**，四种组合都成立。版本相同的组合走"原地继续"投递，
  版本不同的组合走 `netif_rx` 重新入栈（`netif_rx` 的代价与它何时发生，见
  `docs/report` 与模块参数 `reinject`）。
* **外层 v6 不分片**：IPv6 没有 DF 位，源端分片会被对端按"外层 v6 分片"丢弃
  （记 `rx_frag6`）。因此内层 MTU 必须满足 `内层 MTU + 56 ≤ 承载网卡 MTU`（56 = `IWAN_OVERHEAD_V6`：8B 帧头 + 8B UDP + 40B IPv6），
  否则 `SESSION_UP` 直接 `-EMSGSIZE` 失败（客户端会打印绑定/MTU 原因）；
  出站路径上承载 MTU 中途变小则丢弃并计 `tx_err`。内层 MTU 别低于 1280
  （IPv6 最小链路 MTU），否则内层 v6 会被自己的协议栈拆掉，白付一次开销。
* 度量口径不受影响：冻结基准（内层 v4 / 外层 v4）走的是"原地继续"那条
  投递路，与切片 1 之前逐位一致。

## 分工

| 环节 | 位置 | 说明 |
|---|---|---|
| `OPEN` / `OPEN_ACK`、验签、密钥派生 | 用户态 | 握手时还没有内核会话，钩子不拦，应用自己的 UDP socket 正常收到 `OPEN_ACK` |
| `SESSION_UP` / `SESSION_DOWN` | 用户态（genetlink） | `src/common/genl_iwan.c`，纯 libc，不依赖 libnl |
| 网卡创建 / UP / MTU | 内核 | 模块按需创建 `iwan0`（`IWAN_A_FLAG_CREATE_DEV`） |
| 地址 / 路由 / 默认路由劫持 / 回滚 | 用户态 | 与 TUN 路径同一套 `route_setup` / `route_iface_up` / `route_teardown`，按回执里的 `DEVNAME` 配置 |
| 数据帧收发（内层包 ↔ 外层加密帧） | 内核 | 钩子在 `LOCAL_IN` 按会话四元组 + 凭据闸门截获下行帧，直接交给 `iwan0` |
| keepalive **接收**、`PT_CLOSE` 接收 | 内核 | 计入 `/dev/iwan` 时间戳 |
| keepalive **发送**（10s `PT_ECHO_REQ`） | 用户态 | 与 TUN 泵同参数（`PUMP_KEEPALIVE_MS` / `PUMP_KA_FAIL_MAX`）；发送失败计入"无人应答"预算，见下 |
| 存活判定（断线检测） | 用户态 | 每 1s 只读 `mmap` 一次 `/dev/iwan` 的 `last_rx_ms`；"收到新帧"既是看门狗的喂狗事件，也是清零失败预算的唯一依据 |
| `events` 多播组 | 用户态（可选） | 拿不到只影响诊断日志，不影响数据面 |

存活判据（与 TUN 泵逐字一致，环境变量语义没有第二份实现）：

- `/dev/iwan` 的 `last_rx_ms == 0`：从未收到（会话刚建立）或已被 `PT_CLOSE`
  置零（对端断开）。收到过又归零 = 会话丢失，立即重连。
- **"无人应答"预算**（`PUMP_KA_FAIL_MAX` = 3，节拍 `PUMP_KEEPALIVE_MS` = 10s）：
  统计**无人应答的失败**，清零条件只有一个 —— 收到过凭据闸门的有效帧。成功的
  `send` 不清零：连通的 UDP 套接字把 ICMP 端口不可达**隔次**上报，中间那次
  `send` 会成功，按"发送成功"清零会让 3 次的预算永远到不了（2026-10-10 实测：
  服务端进程消失后日志反复出现"重试 1/3"，最后只能靠看门狗判死）。计入预算的
  事件按数据面不同：内核数据面是 keepalive 发送失败（每次 `ENETUNREACH` 这类
  硬失败 ⇒ 约 30s 判死；隔次失败 ⇒ 约 60–90s）；默认 TUN 数据面是**接收侧**
  硬错误 `ECONNREFUSED` / `EHOSTUNREACH` / `ENETUNREACH` / `ECONNRESET`
  —— 那里的 ICMP 错误先被 `recvmmsg` 消费，发送侧看不到，所以必须由接收侧计入。
- `IWAN_RX_STALE_MS`（默认 `120000`，`0` 关闭，范围 `30000..86400000`）：
  超过这个时间没有任何通过凭据闸门的帧就判死 —— **外层兜底**，负责预算覆盖不到
  的情形：对端"收得下但一个都不回"（例如端口被黑洞吸收），此时发送全部成功、
  预算恒为 0，只有看门狗会判死。判死阈值由 `proxy.c` 的同一套访问器提供，两条
  数据面不会漂移。

上述两条机制各有独立用例，且每条都断言"是它判的死"并要求另一条**不出现**
（`docs/kernel-data-plane-e2e.sh --life`）：

| 用例 | 场景 | 判死机制 | 关键证据 |
|---|---|---|---|
| L3 | 外层链路 down（无绑定） | 预算（每次 `send` 都 `ENETUNREACH`） | `无下行帧期间 keepalive 失败累计 3 次（最后错误: Network is unreachable）`，全程无看门狗 |
| L4 | 服务端端口换成"只收不回"的黑洞 | 看门狗（`IWAN_RX_STALE_MS=30000`） | `30031 ms 没有收到任何有效帧`，且预算全程为 0 |
| L5 | 服务端消失（默认 TUN 数据面） | 预算（接收侧硬错误） | `[UDP->TUN] 3 unanswered transport failures (last: Connection refused)`，服务端回来后重连、内层 TCP 恢复 |

## 退出与失败路径

返回码与 `run_pump()` 完全一致，调用方的重连循环零改动：
`0` = 用户停止（Ctrl-C），`1` = 会话丢失（触发重连），`-1` = 启动失败（放弃）。

退出顺序（每一路失败都执行相应子集，**绝不留已建立的会话**）：

1. 停止轮询 / 事件排空；
2. 发 `PT_CLOSE`（在关套接字之前，让服务端尽快回收会话）；
3. 拆路由 → `route_teardown` / `route_iface_down`（依赖设备名，必须在删卡之前）；
4. `SESSION_DOWN`（模块删除它创建的 `iwan0`），再用 `GET_STATS` 复核
   `sid==0 && tok==0`；
5. 关 genetlink fd、`munmap` 共享内存、释放列表。

启动顺序（失败即退出，不做任何降级）：

| 顺序 | 检查 | 失败时的行为 |
|---|---|---|
| 1 | 展开 `--proxy-cidr/-ip/-domain/-cidr6` | 中文报错，`-1` |
| 2 | 有路由目标时捕获默认路由 | `cannot detect default route`，`-1` |
| 3 | 会话五元组 = `getsockname`/`getpeername`（拒绝端口 0、`0.0.0.0`、回环、`--server` 与实际对端不一致） | 中文报错，`-1` |
| 4 | 打开并只读 `mmap` `/dev/iwan` + 版本校验 | 设备不存在时明确提示加载模块，`-1`（**不**回落 TUN） |
| 5 | `ip -d link show dev iwan0` 归属预检 | 非 `iwan` 设备：中文报错，`-1` |
| 6 | `SESSION_UP`（`SPORT` 从第一次起显式给出） | `-EBUSY`/`-EINVAL`/`-ENODEV` 各有中文解释，`-1` |
| 7 | 地址 + 路由（与 TUN 路径同序） | 回滚会话后 `-1` |

重连（`rc==1`）时先 `SESSION_DOWN` 再重新握手：新套接字的本地端口几乎必然变化，
而 `SESSION_UP` 的参数漂移是 `-EINVAL`；同时握手必须在**没有**内核会话的状态下
进行，否则钩子会把 `OPEN_ACK` 吞掉。

## 已知回归：`SIGKILL` 会留下会话

TUN 模式下设备是进程私有的非持久 TUN，进程被杀由内核自动回收；内核数据面的
会话与设备属于模块，`SIGKILL` 让客户端来不及 `SESSION_DOWN`：

- `iwan0` 仍在，钩子仍按旧会话吞下行帧 → 这台机器到该服务器的隧道流量会"黑洞"；
- 路由/地址仍在（若用了默认路由劫持，默认路由也仍在）；
- 服务端那边会话要靠它自己的空闲超时回收。

这正是**必须用 Ctrl-C（`SIGINT`/`SIGTERM`）退出**的原因。清理：

```bash
# 推荐：清会话（模块会删掉它创建的 iwan0）
sudo iwan_ctl session-down          # iwan_ctl 来自 kernel/tests/iwan_ctl.c
# 或
sudo rmmod iwan                     # 设备引用会自动释放

# 只删设备是不够的：会话还在，钩子会继续吞包
sudo ip link del iwan0              # 仍需再执行一次 session-down / rmmod

# 用了默认路由劫持时，先恢复默认路由再清会话
ip route show default
```

用了 `--proxy-cidr default` 时还有一条手工维护的服务器 `/32` pin
（`route_setup` 按"先装 pin 再劫持默认路由"的顺序安装，内核数据面外层包靠它
才能从物理网卡出去）。**不要手工删这条 pin**：删掉之后外层包会命中被劫持的
默认路由进入 `iwan0`，形成环路（内核会打 recursive routing 警告），而在内核
数据面下用户态已经没有 TUN 泵可以替你兜住这个错误。

## 服务端为什么没有 kernel 数据面

v1 内核 ABI 是"**每 netns 单会话**、设备名固定 `iwan0`"，而服务端要在同一个
netns 里同时服务最多 256 个客户端会话；并且服务端的状态机整个在
`handle_udp()` 里（OPEN 验签、会话表、`PT_*` 分发、内层包写 TUN），没有可下移的
"每会话数据面"。要支持得先有 v2 ABI（一个 netns 多会话 + `DEVNAME` 入参 + 按会话
分流）。因此 `iwan-server --data-plane kernel` 是用法错误，`--data-plane tun` 是
唯一取值，也是默认值。

## 验证

- 免 root（本项目 CI 可跑）：构造/参数校验、`--help`、`--data-plane` 取值错误与
  互斥、TUN 路径零回归（`tests/socks_handshake.py`、`tests/relay_socks_harness.py`、
  `bin/r55_skspin_harness`、`bin/lwip_data_harness`、`bin/lwip_fairness_harness`），
  以及"模块缺失"路径：用一个 `iwan-server --no-tun` 假服务端完成握手后，客户端
  必须在 `/dev/iwan` 缺失处报中文错误并以非零码退出（不建 TUN、不改路由）。
- 需要 root（模块 + netns + veth + TUN）：`sudo bash docs/kernel-data-plane-e2e.sh`，
  逐项预期输出见脚本头部注释。脚本用**两个 netns + veth**，绝不在 init netns 里下发
  真实外层五元组，也不使用回环地址。
  最近实测（内核 7.0.0-38）：基础 **PASS=28 FAIL=0**，`--extra` **PASS=36 FAIL=0**。
  C1–C10 覆盖：模块加载后无会话、真服务端（用户态 TUN）、真客户端进入内核数据面、
  `iwan0` 归属/UP/MTU/地址、内层 TCP 回显、`/dev/iwan` 共享内存、内核计数器与日志
  一致性、Ctrl-C 三态退出（`rc=0` 且打印 `kernel data plane stopped (user stop)`）、
  退出后设备与会话清理；`--extra` 另加 E1（`iwan0` 被 dummy 占用时拒绝且不动它）、
  E2（SIGKILL 残留与 `session-down` 清理）、E3（运行中被外部删卡后重建）。
  **C10e 是“告别帧真的过线”的证据**：客户端退出后服务端日志出现
  `[peer] session 0x…. (ip …) closed`（`server.c` 的 PT_CLOSE 分支无条件 `srv_log`，
  不受 debug 开关影响），且其中的 `peer` 端口与同轮 `GET_STATS` 的 `sport` 一致。
