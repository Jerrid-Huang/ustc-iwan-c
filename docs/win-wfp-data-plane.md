# Windows WFP 内核数据面设计（取代 TUN 模式）

目标：Windows 上也做到"报文不进用户态"。Linux 侧的内核模块（`kernel/`）已经做到
这一点，本文件给出 Windows 侧的对应设计，并说明哪些部分能 1:1 照搬、哪一处必须换。

现状：Windows 侧目前只有用户态数据面 —— `src/common/tun_win.c`（wintun.dll 的 TUN
设备）配 `src/common/pump_win_single.c`（单队列泵），每个报文都要过一次
DeviceIoControl 与用户态拷贝。仓库里没有任何内核态 Windows 代码。

## 一、Linux 的形式（要被参考的那一套）

| 角色 | Linux 实现 | 位置 |
|------|-----------|------|
| 内层地址落点 | 模块自建虚拟网卡 `iwan0`，按需创建/销毁 | `kernel/iwan_netlink.c` 的 `rtnl_create_link` + `register_netdevice` |
| 出向封装 | `ndo_start_xmit`：路由到 `iwan0` 的报文就地封装，再交给承载网卡 | `kernel/iwan_tx.c` 的 `iwan_xmit` |
| 入向解封 | netfilter 钩子（PRE_ROUTING，默认 prio -300，即 conntrack 之前）原地解封，`NF_ACCEPT` 让它继续上行 | `kernel/iwan_core.c` 的 `nf_hook_ops` |
| 控制面 | generic netlink 会话 ABI（外层端点、内层 MTU、加密标志、会话 id、开关、统计） | `kernel/iwan_netlink.c` |
| 存活状态 | `/dev/iwan`：每 netns 一页**只读**共享内存，内核每收到一个帧就覆盖时间戳 | `kernel/iwan_shm.c` + `kernel/iwan_shm.h` |
| keepalive | **全部在用户态**；内核没有定时器、没有工作队列 | `src/common/kdp.c` |

两条硬约束沿用：**内核不做定时器与 keepalive**（只负责数据传输与写时间戳）；
**外层 v6 不分片**（会话建立时就校验 `内层 MTU + 封装开销 ≤ 承载网卡 MTU`）。

## 二、Windows 的对应设计

### 2.1 唯一必须换的一处：内层地址落点

Windows 上没有"模块自建 netdev + netfilter 钩子"这样一个包。两条路：

* 写 NDIS 小端口（对应 Linux 的 `ndo_start_xmit`）。问题是：NDIS 小端口在协议栈
  **下方**，它自己**发不出外层 UDP** —— 要把封装后的报文交给承载网卡，只能再配
  WFP 注入（`FwpsInjectNetworkSendAsync`）或 WSK 内核套接字；外层报文的**接收**
  同样要 WFP 才能从承载网卡上截下来。也就是说小端口省不掉 WFP，只是多了一个
  驱动、一份 INF 与一套 NDIS 版本兼容面。
* **推荐**：用系统自带的 KM-TEST 回环适配器（`netloop.inf`，装一个 INF 即可，名字
  可取 `iWAN`）承载内层地址，配合 WFP callout 完成出向拦截/入向注入。改动最小，
  数据同样不进用户态。

取舍：接管"内层地址是否为本机地址"这件事的是回环适配器，而不是我们自己的网卡；
它带来的差别仅在于统计口径（见 2.4），不影响数据面语义。

### 2.2 分层与 callout 选择

| 角色 | Windows 实现 |
|------|-------------|
| 出向拦截 | `FWPS_LAYER_OUTBOUND_IPPACKET_V4` / `_V6` callout：按"被代理目标集合"匹配，命中后**吸收原报文**（不出承载网卡），就地封装成外层 UDP |
| 出向发送 | `FwpsInjectNetworkSendAsync` 把外层 UDP 注入协议栈（外层 IP/UDP 头由驱动构造，校验和交给卸载） |
| 入向拦截 | `FWPS_LAYER_INBOUND_IPPACKET_V4` / `_V6` callout：按外层 UDP 四元组（本机承载地址 + 服务器端点 + 端口）匹配，命中后吸收并解封 |
| 入向交付 | `FwpsInjectTransportReceiveAsync` 把内层报文交给本机协议栈（内层地址已在回环适配器上，所以地址检查通过） |
| 控制面 | 设备 IOCTL（`\Device\iwan` + `\DosDevices\iwan`），会话建立/销毁/查询，语义镜像 genetlink 那组属性 |
| 存活状态 | 命名节对象（section）映射给用户态**只读**，布局与 `kernel/iwan_shm.h` 等价（含版本号与偏移断言） |
| keepalive | 仍在用户态，内核只写时间戳（与 Linux 同一约束） |

不用 ALE 层的原因：ALE 的 connect redirect 面向"连接"而不是"任意 IP 报文"，无法
原样承载内层报文与分片；IP 包层才能做到与 Linux 的 `ndo_start_xmit` 等价。

### 2.3 为什么用"目标集合"匹配而不是"路由到某张网卡"

Linux 靠路由把报文送进 `iwan0` 的 `ndo_start_xmit`；Windows 的 WFP 出向 IP 包层
在路由之后，但拿不到"用户想代理哪些前缀"这件事 —— 而用户态客户端本来就已经算好
了这份集合（`--proxy-cidr`/`--proxy-ip`/`--proxy-domain` 展开后的目标集）。所以
会话建立时把集合下发给驱动，由驱动做最长前缀匹配。这样也顺带解决了 Linux 上
"被服务前缀 vs 更具体的直连 /32"那类边界：集合就是判据，不需要再和路由表比优先级。

### 2.4 回程与连接跟踪：Windows 上反而更简单

Linux 侧为了让"从隧道进来的连接"的回包按来路回去，需要 conntrack 打标记 +
fwmark 策略路由（见 `docs/reply-routing.md`）。Windows 的 WFP **自带流上下文**
（`FwpsFlowAssociateContext0`）：入向解封时把"该连接来自隧道"记在流上，出向时
按流上下文直接判定，不需要额外规则、表或用户态开关。

### 2.5 封装与尺寸口径（与 Linux 一致，直接复用常量）

* `IWAN_HDR_LEN = 8`；`IWAN_OVERHEAD = 8+8+20 = 36`；`IWAN_OVERHEAD_V6 = 8+8+40 = 56`
* 硬上限 `IWAN_MTU_HARD_MAX = 65499`、`IWAN_MTU_HARD_MAX_V6 = 65479`
* 会话建立时校验 `内层 MTU + 开销 ≤ 承载网卡 MTU`；外层 v6 不分片，装不下就拒绝
  会话；运行期每报文再校验一次，装不下就计入丢包统计（与 Linux 同一口径）
* 分段卸载与接收聚合：注入路径要保留/正确设置校验和与分段相关信息，避免把
  Linux 侧已经验证过的"每报文处理开销"重新引入

### 2.6 数据面选面

沿用现有选面机制（`src/common/cli_common.h` 的 `IWAN_DATA_PLANE_*`），Windows 上
`kernel` 的含义就是"内核态数据面"，与 Linux 同名同义，`auto` 的选面规则也一致
（能用就用内核面，起不来才回退 TUN）。是否需要额外别名 `wfp` 由实现时再定。

## 三、IOCTL 契约（草案）

镜像 genetlink 的会话模型，一套 IOCTL 走完：

| IOCTL | 方向 | 内容 |
|-------|------|------|
| `IWAN_IOCTL_SESSION_OPEN` | 入 | 外层端点（v4/v6）、外层源、内层 MTU、加密标志与密钥、目标集合、承载网卡索引（可选绑定） |
| `IWAN_IOCTL_SESSION_CLOSE` | 入 | 会话 id |
| `IWAN_IOCTL_SESSION_GET` | 出 | 会话 id、状态、生效 MTU、实际绑定的承载网卡、统计（tx/rx 报文与字节、各类丢包计数） |
| `IWAN_IOCTL_SHM_MAP` | 出 | 存活共享内存的节对象句柄（只读映射，布局带版本号） |

约束：会话是**每驱动实例一份**（Windows 没有 netns 的对应物，多实例用多个设备
实例或句柄区分，实现时定）；`SESSION_OPEN` 必须幂等，重复打开返回既有会话。

ABI 落在 `src/common/iwan_win_abi.h`（驱动与客户端共用一份头，字段偏移与共享内存
布局在文件末尾用断言冻结）。布局验证不需要 Windows：

```
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -Isrc/common tests/win_abi_layout.c -o /tmp/l64
i686-w64-mingw32-gcc   -std=c11 -Wall -Wextra -Werror -Isrc/common tests/win_abi_layout.c -o /tmp/l32
wine /tmp/l64.exe > a; wine /tmp/l32.exe > b; diff a b   # 除 sizeof(void*) 外必须无差异
```

这一步已在本机跑过：两种目标下逐字段一致（`SESSION_OPEN` 132 字节、
`SESSION_INFO` 192 字节、共享内存页 40 字节且偏移与 Linux 的 `IWAN_SHM_OFF_*`
完全相同），mingw 与 MSVC 对 `__int64` 都是 8 字节对齐，所以"驱动 64 位 + 客户端
32 位"这一组合也成立。

## 四、构建与签名（在 Windows 侧完成）

本机（Linux）没有 WDK/MSVC，驱动的编译与测试只能在 Windows 上做。给出的东西：

* `win-driver/` 下的 WDK 工程（MSBuild `.vcxproj`，KMDF 或 WDM），产出 `iwan.sys`
* `.inf`：设备安装、服务注册；另附 KM-TEST 回环适配器的安装说明
* 安装/卸载脚本：`sc create`/`netcfg`/`devcon` 或 `pnputil` 三条路各给一条
* 测试签名流程：`bcdedit /set testsigning on` + 自签证书（生产签名不在本轮范围）
* 用户态侧接线：`src/common/` 下新增 Windows 内核面的客户端实现，镜像
  `src/common/kdp.c` 的会话建立、统计读取、退出回滚语义

## 五、验证方案

1. **驱动自测**：IOCTL 回路（开会话、查统计、关会话）、共享内存页可读且版本号正确、
   卸载时无残留设备与服务。
2. **单机端到端**：对真实 USTC 服务器建立会话，取校园资源；核对
   * 内层地址出现在回环适配器上；
   * 承载网卡的接收字节增量 ≈ 内层字节 × (1 + 封装开销比)（Linux 侧的口径，见
     `docs/kernel-data-plane.md`）；
   * 退出后适配器地址、会话、统计全部回滚。
3. **对照**：同一台机器上 TUN 面与 WFP 面的吞吐/每报文处理开销对比（应当看到
   用户态拷贝消失带来的差别）。
4. **边界**：外层 v6、装不下的 MTU 被拒、非代理目标不受影响、入向连接的回包按
   来路回去。

## 六、分阶段

* M1：出向 v4（目标集合匹配 + 封装 + 注入）+ IOCTL 会话 + 共享内存页
* M2：入向（解封 + 传输层注入 + 流上下文）
* M3：外层 v6（含不分片约束与 MTU 校验）
* M4：真实服务器端到端与对照测量
