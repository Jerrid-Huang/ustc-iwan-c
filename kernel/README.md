# iWAN 内核数据面（零用户态转发）

用一条纯内核路径替换 TUN：**入站**在内核 netfilter 钩子内解封（含外层分片
的内联重组），**出站**由内核虚拟网卡在 `ndo_start_xmit` 内封装。用户态只负责
控制面/信令（OPEN/OPEN_ACK、密钥协商、keepalive 状态），数据面不过用户态。

```
 对端 UDP                ┌─────────────────── 本机内核 ───────────────────┐
 ───────────────────────►│ tc/XDP → ip_rcv → PREROUTING(本模块 prio=-300) │
   IP[DF] / UDP          │   ① 外层分片？内联 ip_defrag（非首片没有端口）  │
   / 8B 帧头             │   ② 校验 sid/tok（解密之前）                     │
   / XOR(内层 IP 包)     │   ③ 剥外层+帧头，按会话密钥 XOR 还原            │
                         │   ④ CHECKSUM_NONE → NF_ACCEPT                   │
                         │ → 路由 → LOCAL_IN → ip_local_deliver（内层分片  │
                         │   在这里由内核重组）→ 本机 socket / 转发         │
                         └────────────────────────────────────────────────┘
 本机应用 → 路由到 iwan0 → 栈完成 GSO 分段与 L4 校验和 →
   ndo_start_xmit：XOR → 8B 帧头 → UDP → 外层 IP → ip_local_out → 物理网卡
```

## 文件

| 文件 | 作用 |
| --- | --- |
| `iwan.h` | 帧常量（镜像 PROTOCOL.md，冻结）、全局配置、每 netns 状态、计数器 |
| `iwan_core.c` | 模块参数、XOR、`/proc/net/iwan`（读统计 + 写每 netns 出站端点）、pernet 生命周期 |
| `iwan_rx.c` | 入站 netfilter 钩子：外层重组、帧头校验、解密、交付（含 GSO 批处理） |
| `iwan_tx.c` | 出站虚拟网卡 `iwan%d`：不变量检查、封装、路由发送 |
| `Makefile` | 树外模块构建：`iwan-objs := iwan_core.o iwan_rx.o iwan_tx.o` |
| `tests/tcp_echo_test.sh` | 本机端到端验收（两 netns + veth，TCP/UDP echo，含两层分片与负向用例） |
| `tests/echo_net.py` | TCP/UDP echo 客户端/服务端（含双向并发读写、逐字节校验） |

## 构建与加载

```bash
make -C kernel                 # 需要当前内核的 headers：/lib/modules/$(uname -r)/build
sudo insmod kernel/iwan.ko \
    enabled=1 any_dir=1 \
    outer_src=10.100.0.2 outer_dst=10.100.0.1 \
    dport=6100 sid=4660 tok=3405691582 key=0011223344556677 enc=1
```

需要的内核配置：`CONFIG_INET`、`CONFIG_NETFILTER`、`CONFIG_NETFILTER_ADVANCED`、
`CONFIG_PROC_FS`、`CONFIG_NET_NS`；用到 `IP_DEFRAG_LOCAL_DELIVER` 与
`ip_defrag()`（`EXPORT_SYMBOL`）、`ip_local_out()`、`ip_route_output_flow()`
（均为 `EXPORT_SYMBOL_GPL`，故本模块 `MODULE_LICENSE("GPL")`）。版本 < 4.18 直接
`#error`（`net_generic`/pernet 与 proc 接口假定）。

### 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | 1 | 总开关 |
| `any_dir` | 0 | 外层 `(src,dst)` 允许反向。对等/本机双向测试用；生产按方向配 |
| `outer_src` / `outer_dst` | 0.0.0.0 | RX 过滤的外层源/目的（服务端 IP / 本机隧道地址） |
| `inner_src` | 0.0.0.0 | 可选：内层源地址白名单，0 = 关闭 |
| `dport` / `sport` | 0 | 隧道 UDP 目的端口（RX 匹配、TX 使用）/ TX 源端口（0 = 用 `dport`） |
| `sid` / `tok` | 0 | 会话 id / token（OPEN_ACK 下发）。数据面唯一凭据，解密前校验 |
| `key` | 全零 | 16 位十六进制 = `MD5(username||password)[0..8)`。全零只用于功能验证 |
| `enc` | 1 | 1 = `PT_DATA_ENC`（XOR），0 = `PT_DATA`（明文会话） |
| `batch` | 1 | 处理 GRO 合并后的 GSO skb（对端用 `UDP_SEGMENT` 批发送时需要） |
| `df` | 1 | 外层置 DF=1。置 0 允许外层分片，供验证钩子内联重组 |
| `hooknum` | 0 | 0 = `PRE_ROUTING`（默认），1 = `LOCAL_IN`（兜底，配 `reinject`） |
| `hookprio` | -300 | 钩子优先级：`nf_defrag_ipv4`(-400) 之后、conntrack(-200) 之前 |
| `reinject` | 0 | 解封后 `netif_rx` 回到 `ip_defrag` 之前（仅 `hooknum=1` 有意义） |

### 每 netns 配置（`/proc/net/iwan` 可写）

一个模块实例服务所有 netns，而两个方向的**出站外层目的地址不同**，所以出站
端点按 netns 配：

```bash
ip netns exec iwc sh -c 'echo "tx_src=10.100.0.1 tx_dst=10.100.0.2" > /proc/net/iwan'
```

`tx_src` 默认取 `iwan0` 的 `dev_addr`（即 `ip link set iwan0 address`）——本实现
用 proc 写口，避免依赖 `ndo_set_mac_address` 的非以太网语义。写口还支持
`enabled=0/1`（每 netns 开关），需要 `CAP_NET_ADMIN`。

`cat /proc/net/iwan` 给出全部配置与计数器（`rx_pkts/rx_outer/rx_reasm/rx_frames/
rx_delivered/rx_batch/rx_batch_skip/rx_bad_hdr/rx_bad_inner/rx_nomem/tx_pkts/
tx_bytes/tx_bad_state/tx_bad_inner/tx_err`）。

## 本机验收测试

六个脚本，从"逐位等价"到"真实流量"再到"控制面"与"共享内存 ABI"：

| 脚本 | 需要 root | 覆盖 | 最近结果（内核 7.0.0-38） |
| --- | --- | --- | --- |
| `xor_equiv_test.sh` | 否 | 从源码抽取 `iwan_xor()`，与生产 `xor_crypt()` 差分 20 万组随机用例 | PASS=2 FAIL=0，`MISMATCH=0` |
| `netlink_test.sh` | 是 | 控制面 T1–T10：按需建卡、配置快照、双向数据面、控制帧事件、keepalive、`SET_PEER` 漂移、`SET_ENABLED`、拆会话清凭据；T1b 设备类型闸门（预置非 iwan 的 `iwan0` ⇒ `SESSION_UP` 必须失败且不动它）、T2e 回执 `DEV_OWNED=1` | PASS=23 FAIL=0（含本轮新增 T1b×3 + T2e×1；T1b 三条闸门断言实测全部命中） |
| `shm_test.sh` | 是 | `/dev/iwan` 共享内存 ABI（CONTROL-PLANE §11）：T1 初始页、T2 按 netns 隔离、T6 时间戳单调、T3 `PT_CLOSE` 置 0 + `peer_state=CLOSED`、T4 `SESSION_DOWN` 整页清零、T5 先 mmap 再删 netns | PASS=24 FAIL=0 |
| `gso_test.sh` | 是 | `UDP_SEGMENT` 批发送（一个 UDP 报文里 N 个等长帧）：`rx_batch` 增长、`rx_delivered`/`rx_frames` 恰好 +N、`rx_bad_hdr` 不增、无 oops；以及**非对称端口**（`sport≠dport`）双向内层 UDP | PASS=12 FAIL=0（`--count 32`：`rx_batch +1`、`rx_frames`/`rx_delivered` 恰好 +32、无 oops） |
| `tcp_echo_test.sh` | 是 | 数据面真实流量 T1–T5：64 KiB 与 4 MiB TCP、内层分片、外层分片重组、负向凭据闸门 | PASS=13 FAIL=0 |
| `interop_test.sh` | 是 | 与 C 侧生产实现字节级对拍 A1–A3（模块出站→C 解封、C 封装→模块入站、外层头字段） | PASS=16 FAIL=0 |

```bash
bash kernel/tests/xor_equiv_test.sh                        # 不需要 root，20 万组
sudo bash kernel/tests/netlink_test.sh --any-dir --extra   # 控制面全量
sudo bash kernel/tests/shm_test.sh                         # /dev/iwan 共享内存 ABI
sudo bash kernel/tests/gso_test.sh --count 32              # UDP_SEGMENT 批发送 + 非对称端口
sudo bash kernel/tests/tcp_echo_test.sh                    # 真实流量（--quick 跳过 4 MiB）
sudo bash kernel/tests/interop_test.sh                     # 跨实现字节级对拍
```

应用侧端到端（真客户端 `--data-plane kernel` 对真服务端 TUN，零 TUN）不在这张表里，由
`docs/kernel-data-plane-e2e.sh` 覆盖：最近实测基础 **PASS=28 FAIL=0**、`--extra`
**PASS=36 FAIL=0**（逐项含义见 `docs/kernel-data-plane.md` 的“验证”一节）。

`netlink_test.sh` 与 `interop_test.sh` 各自建两个 netns（`iwc`/`iws`）用 veth 相连，
配置一律走 genetlink（`SESSION_UP`），不再用 `ip link add type iwan`。

### 已固化的实测结论

- **线格式逐位一致**：模块发出的帧交给 C 侧 `pkt_hdr()`/`xor_crypt()` 逐字节校验后
  解封，解出的内层包与注入包 60 字节全等（id/frag_off/ttl/校验和等一个字段都没
  排除）；外层头前 26 字节（含 TTL/ID/DF/IP 校验和）与期望逐字节一致。
- **反向也一致**：C 侧封的帧按外层五元组发给模块，命中钩子（`rx_outer +1`）、过
  凭据闸门（`rx_frames +1`）、投递协议栈（`rx_delivered +1`，`rx_bad_hdr +0`），
  内层载荷 32 字节全等。
- **XOR 不破坏校验和**：4 MiB TCP 满 MTU 流 `Tcp InCsumErrors +0`、`RetransSegs +0`。
- **外层分片由钩子内联重组**：`df=0` + veth mtu 1000 时 `rx_reasm 0 → 32`。
- **控制帧由内核直送用户态**：`PT_PING_REQ` 事件的 `FRAME_HEX=2900ffffffffffff…`
  （sid/tok 为协议固定通配），`PT_CLOSE` 为 `17011234cafebabe…`（会话凭据）。

### 跑内核测试前建议打开的保护

控制面早期有过一次缺陷：`rtnl_create_link()` 的 `tb` 参数传了 NULL，而本内核在该
函数入口就解引用它（`rtnl_create_link+0x22`），又因为此处持有 `rtnl_lock()`，任务
带锁退出，结果整机僵死、只能硬复位。再跑任何会走到内核新代码路径的测试前：

```bash
sudo sysctl -w kernel.panic_on_oops=1 kernel.panic=15   # 出问题自动重启，而不是僵死
# 重启后取轨迹：journalctl -b -1 -k | grep -B2 -A20 "BUG\|Oops"
```

手动拓扑（等价于脚本做的事，走控制面）：

```bash
ip netns add iwc; ip netns add iws
ip link add veth-c netns iwc type veth peer name veth-s netns iws
ip -n iwc addr add 10.100.0.1/24 dev veth-c; ip -n iwc link set veth-c up
ip -n iws addr add 10.100.0.2/24 dev veth-s; ip -n iws link set veth-s up
ip -n iwc addr add 10.9.0.1/32 dev lo;  ip -n iws addr add 10.9.0.2/32 dev lo
sudo insmod kernel/iwan.ko     # 不传会话参数：配置只能来自 netlink
ip netns exec iwc /tmp/iwan_ctl session-up --sid 4660 --tok 3405691582 --enc 1 \
    --key 0011223344556677 --outer-src 10.100.0.1 --outer-dst 10.100.0.2 --dport 6100 --mtu 1400
ip netns exec iws /tmp/iwan_ctl session-up --sid 4660 --tok 3405691582 --enc 1 \
    --key 0011223344556677 --outer-src 10.100.0.2 --outer-dst 10.100.0.1 --dport 6100 --mtu 1400
# iwan0 由模块按需创建并置 UP；内层地址与路由仍归用户态：
ip -n iwc route add 10.9.0.2/32 dev iwan0
ip -n iws route add 10.9.0.1/32 dev iwan0
```

`/tmp/iwan_ctl` 的构建命令见 `kernel/tests/iwan_ctl.c` 头部注释。

非对称端口（真实客户端的本地端口是临时端口，与对端 `DPORT` 不同）必须显式给
`--sport`，两端的 `sport`/`dport` 互为对方的 `dport`/`sport`：

```bash
ip netns exec iwc /tmp/iwan_ctl session-up ... --dport 6100 --sport 6200
ip netns exec iws /tmp/iwan_ctl session-up ... --dport 6200 --sport 6100
```

接收侧的口径是"**只接受目的端口 = `SPORT`**（未给 `SPORT` 时 = `DPORT`）"。
两端都用同一个 `--dport 6100` 的旧写法只在"两端端口相同"的测试里成立。

`/dev/iwan`（共享内存页，ABI 见 `CONTROL-PLANE.md` §11）——用户态**只读** mmap，
**1s 轮询** `last_rx_ms` 判断对端存活（`0` = 断线）：

```bash
ip netns exec iwc cc -o /tmp/iwan_shm kernel/tests/iwan_shm.c   # 只读 dump/watch 工具
ip netns exec iwc /tmp/iwan_shm dump                            # 打印一次全部字段
ip netns exec iwc /tmp/iwan_shm watch --interval 1000           # 每 1s 一行（默认值）
# 自己写代码时：open("/dev/iwan", O_RDONLY) + mmap(PROT_READ)，偏移见 §11.2
```

写方式 `open()` 会被拒（`-EACCES`），`PROT_WRITE` 的 `mmap()` 会被拒（`-EPERM`），
`mprotect(PROT_WRITE)` 也失败 —— 这一页是"内核 → 用户态"的单向快照。顺序上还有
一条：**重连要先 `SESSION_DOWN` 再重新握手**，否则 `SESSION_UP` 会因参数不一致
直接 `-EINVAL`（见 `CONTROL-PLANE.md` §4.1）。

## 设计要点（为什么必须这样做）

1. **出站必须在内核发送路径的最后一步做**。XOR 覆盖内层 IP 包的**全部字节**，
   包括 TCP/UDP 校验和字段；而 TX 上校验和是延迟计算的（`CHECKSUM_PARTIAL`），
   GSO 超包也是最后才分段。任何 eBPF 钩子（LWT_XMIT / tc egress / XDP）都在
   "校验和没算、GSO 没分"之前，此时 XOR 出来的包到对端必然校验和错误（SYN 都
   过不去）。参考实现没这个问题，是因为它的用户态 daemon 从 TUN 读到的是已经
   算完校验和的成品包。
   本设备把 `features`/`hw_features` 全留 0，于是 `validate_xmit_skb` 会替我们
   做 GSO 分段 + 软件校验和 + 线性化，`ndo_start_xmit` 拿到的就是"单个完整 IP
   报文 + 校验和已就绪"。`tx_bad_state` 计数任何不满足该不变量的可疑包并丢弃。
2. **入站必须在外层重组之后**。非首片没有 UDP/iWAN 头 ⇒ 端口在重组前不可见。
   默认钩子 `PRE_ROUTING` prio=-300（在 `nf_defrag_ipv4`(-400) 之后）：只有
   conntrack/nft 才会去 enable 那个 defrag 钩子，不能依赖；所以在自己的钩子里
   调一次导出的 `ip_defrag()`，返回非 0 = 本片已入队 → `NF_STOLEN`（skb 归重组
   机制），返回 0 = 数据报此刻完整，就在这一次调用里继续解封 —— 与内核
   `nf_ct_ipv4_gather_frags()` 同一套约定。每个到达的包都有立即判决，不存在
   "为了等其余分片而阻塞"。
3. **内层分片交给内核**。模块不建内层重组队列：解出的内层包 `NF_ACCEPT` 之后
   自然落到 `ip_local_deliver` 的 `ip_defrag`（本机）或下一跳（转发）。要不要
   重组内层、按什么身份重组，本来就只有在路由之后才答得出来。
   `hooknum=1`（`LOCAL_IN`）+ `reinject=1` 是等价的兜底路径：那时外层已由内核
   重组完，解封后用 `netif_rx` 把内层包送回 `ip_defrag` 之前。
4. **逐片 XOR 与"整包 XOR"不冲突**。链路上每片各自带 8B 帧头，每片从帧
   payload 偏移 0 开始 XOR；内核在解封后重组，得到的明文与"整包 XOR 后再分片"
   逐字节相同（各片被 XOR 的位置，就是整包里同一偏移的位置）。
5. **策略顺序**：本钩子之后的 netfilter（conntrack -200、filter 0）看到的是
   重组并解密后的**内层明文包**，所以不存在分片逃逸；需要按隧道外层做策略的
   规则必须挂在 prio < -300。

## 已知边界 / 待办

- **端口字节序**：`dport`/`sport` 是 `module_param` 直接落在 `__be16` 字段上的
  **主机序**值，出站写 UDP 头和入站比较都必须 `htons()`。漏掉这一步时模块自打
  自收完全正常（写头和读头用同一个原始值），但线上真实端口是字节交换后的值，
  对端按配置端口发来的报文会被 `rx_bad_hdr` 全部拒掉——这是真实互通缺陷，
  T5 的构造帧用例就是为了钉住它。
- **GSO 批处理**：参考客户端用 `UDP_SEGMENT`（Windows 是
  `SIO_UDP_NETSEGMENT`）把 N 个**等长**帧发进一个 UDP 报文，接收侧 GRO 可能合并
  它们。`batch=1` 时按 `gso_size` 拆回逐帧处理（`skb_gso_segment` + 各自剥头
  解密 + `netif_receive_skb`，`NF_STOLEN`）；拆不了就 `rx_batch_skip++` 并放行
  给内核（会因校验和/端口不符而被丢弃）。本模块自己**发**的是一帧一个 UDP
  报文，不做批处理。
- keepalive 时间戳写共享内存、收到 `PT_CLOSE` 置 0、`SESSION_DOWN` 整页清零都已实现，并被
  `shm_test.sh`（24 条断言）与端到端 C7/C10 实测钉住（ABI 见 CONTROL-PLANE §11）；尚未接的
  是 TunnelType provider 那一层控制面集成。
- **没有会话空闲回收**：模块侧不设超时，会话只由 `SESSION_DOWN` 或 `rmmod` 清除。客户端被
  `SIGKILL` 时会话与 `iwan0` 会留下（钩子继续吞包），见 `docs/kernel-data-plane.md`
  §已知回归（端到端 `--extra` 的 E2 专门钉这条，E2d 验证 `session-down` 能清干净）。
  内核侧空闲回收需要定时器，属 ABI v2 待办。
- 两条错误分支尚无运行时覆盖：`rtnl_configure_link()` 失败、钩子里 `rx_hooked == false`
  返回 `-EIO`（netns 退出竞态）。代码路径已逐行复查，但没有构造出能触发它们的场景。
- 计数器是每 netns 的 `atomic64`，非 per-CPU。生产要做 pps/延迟压测时应改成
  `percpu_counter`/`this_cpu_inc`。
- `verbose` 逐包打印仅用于调试（printk 在 pps 场景下是微秒级开销）。
- SecureBoot 开启的机器需要签名（`scripts/sign-file` 或 DKMS + MOK 注册），
  `insmod` 未签名模块会污染内核（taint）。
- 本机 veth 上的实测已入 `docs/perf-plan.md`（内层 TCP 4 MiB 2632/3051 Mbps、
  `InCsumErrors +0`、`RetransSegs +0`、`rx_reasm 0→32`、端到端 28/0 与 36/0）；
  **真实网卡**上的 GSO/TSO、多队列、高 pps 与延迟仍未量测 —— 本机没有真实对端，用户限定
  只做本机测量，这一列补不了。
