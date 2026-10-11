# Windows 内核数据面（WFP callout 驱动 iwan.sys）

把 iWAN 的数据面从用户态搬进内核，**报文不进用户态**。与 Linux 侧 `kernel/`
（内核模块 `iwan.ko`）是同一件事的两个平台实现，设计对照见
[../docs/win-wfp-data-plane.md](../docs/win-wfp-data-plane.md)。

| Linux | Windows | 说明 |
|---|---|---|
| `iwan.ko` | `iwan.sys`（本目录） | 非 PnP 内核服务，按需启动 |
| `modprobe iwan` | `install.ps1` | 注册服务 + 拷贝 .sys |
| `ndo_start_xmit` 内封装 | 出向 IP 包层 callout + `FwpsInjectNetworkSendAsync` | 按目标集合匹配、就地封装 |
| netfilter 钩子解封 | 入向 IP 包层 callout + `FwpsInjectTransportReceiveAsync` | 按外层 UDP 端口匹配（M2） |
| 模块自建 `iwan0` | 系统自带 KM-TEST 回环适配器承载内层地址 | NDIS 小端口发不出外层 UDP，见设计文档 |
| conntrack + fwmark 策略路由 | WFP 流上下文 | Windows 不需要额外路由规则 |
| `/dev/iwan` 只读一页 | `IOCTL_IWAN_SHM_QUERY` 返回的只读映射 | 页面布局逐字段相同，判活代码两侧共用 |
| genetlink 会话 ABI | 一组 IOCTL | 契约在 `../src/common/iwan_win_abi.h` |

## 目录

| 文件 | 作用 |
|---|---|
| `iwan_win.h` | 驱动内部头：池标签、会话/设备扩展、并发模型 |
| `iwan_win_drv.c` | `DriverEntry`、设备与 IOCTL 分发、加载/卸载顺序 |
| `iwan_win_session.c` | 会话生命周期、目标集合导入、存活共享内存页 |
| `iwan_win_wfp.c` | callout 注册/注销、出向封装与注入、入向匹配/解封/注入（M1–M3，外层 v4/v6 双向） |
| `iwan_win_frame.{h,c}` | 线上格式、XOR、校验和补齐、目标匹配（**不依赖 WDK**，可在 Linux 上对拍） |
| `iwan.inf` | 非 PnP 内核服务安装信息 |
| `iwan.vcxproj` | MSBuild 工程（WDM，非 KMDF） |
| `install.ps1` / `uninstall.ps1` / `testsign.ps1` | 安装、卸载、测试签名 |

## 承载适配器（KM-TEST 环回网卡，必须先建）

内核面把内层地址挂在**本机一张普通网卡**上，报文由驱动在 WFP 里直接注入/截获
（不经过 TUN，也不进用户态）。Linux 侧那张卡是模块自己 `rtnl_create_link` 出来
的 `iwan0`；Windows 侧驱动不是网卡驱动，造不出这样一张卡，所以用系统自带的
**KM-TEST 环回适配器**承担这个角色，名字固定为 `iWAN`。

建法（任选其一，装完把适配器**改名成 `iWAN`**，大小写敏感）：

```powershell
# 图形界面：hdwwiz.exe -> 手动选择硬件 -> 网络适配器 -> Microsoft
#           -> KM-TEST 环回适配器
# 命令行（devcon 随 WDK 提供；老版本 Windows 上 netloop.inf 可用）：
devcon install %WINDIR%\inf\netloop.inf *msloop
Rename-NetAdapter -Name "以太网 2" -NewName "iWAN"     # 或 netsh interface set interface
```

三条注意：

- 不要在它上面配 IP：内层地址由客户端按会话结果自己配（`route_iface_up`，
  与 TUN 面同一套代码）。手工配了会被会话建立时覆盖。
- 不要给它配默认网关：它只承载内层地址，默认路由仍由被代理目标集合与真实
  网卡决定（服务器地址始终钉在真实网卡上，见正文的分离隧道说明）。
- 适配器名写死在 `IWAN_WIN_DEF_DEV`（[kdp_win.h](../src/common/kdp_win.h)），
  两个客户端的调用点传 NULL 取默认值，所以改名成别的会找不到设备。

## 构建（需要 Windows + WDK）

在装了 WDK 的机器上，用管理员权限的 VS 开发者命令提示符：

    msbuild win-driver\iwan.vcxproj /p:Configuration=Release /p:Platform=x64

产物：`build\x64\Release\iwan.sys`（另有 `iwan.inf`、`iwan.cat`）。
链接库：`fwpkclnt.lib`（WFP 内核 API）、`ndis.lib`（NBL 工具）、`wdmsec.lib`（设备 ACL）。

## 签名与安装

    .\win-driver\testsign.ps1      # 首次：bcdedit /set testsigning on（需重启）+ 自签证书 + 签名
    .\win-driver\install.ps1       # 拷到 System32\drivers、建服务、启动、自检
    .\win-driver\uninstall.ps1     # 停服务、删服务、删文件

依赖 Base Filtering Engine（WFP 需要，`install.ps1` 会自动拉起）。
过滤器用 `FWPM_SESSION_FLAG_DYNAMIC` 注册：引擎句柄一关（驱动卸载）规则全清，
不会在系统里留下半套过滤规则。

## 本机（Linux）已经验证的部分

驱动本身**在本机编译不了**（无 WDK/MSVC），但最容易出错的线上格式已经被对拍钉住：

    # 线上格式 / XOR / 校验和 / 目标匹配 与用户态独立实现对拍
    gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -DIWAN_WIN_ABI_BARE -Isrc/common -Iwin-driver \
        tests/win_frame_test.c win-driver/iwan_win_frame.c \
        src/common/protocol.c src/common/crypto.c src/common/util.c \
        -Wl,--gc-sections -lcrypto -o /tmp/win_frame_test && /tmp/win_frame_test
    # => 通过 81 项，失败 0 项

    # ABI 布局在 32/64 位下逐行比对（驱动 64 位 + 客户端 32 位）
    for T in x86_64 i686; do $T-w64-mingw32-gcc -Isrc/common tests/win_abi_layout.c \
        -o /tmp/abi_$T.exe && wine /tmp/abi_$T.exe; done

    # 设备层（用户态打开设备、查会话、映射共享内存）编译与错误路径
    x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -Isrc/common \
        tests/windev_probe.c src/common/windev.c -o /tmp/windev_probe.exe && wine /tmp/windev_probe.exe

## 编译校正清单（第一次在 Windows 上编译时逐条核对）

这些是本机无法编译、按规范写法写但需要编译器确认的点。若报错，按右列改：

| 位置 | 现象 | 改法 |
|---|---|---|
| `FwpsCalloutRegister` / `FwpsFreeNetBufferList` / `FwpsAllocateNetBufferAndNetBufferList` / `FwpsInjectNetworkSendAsync` / `FwpsCalloutUnregisterById` | 提示未声明的标识符 | 这些无版本号的名字是宏，个别 WDK 版本没提供，改成带后缀的 `...0` 版本 |
| `FwpsInjectionHandleCreate(AF_INET, TYPE, &h)` | 参数个数不符 | 某些头文件里的 `...0` 版多一个 `flags` 参数，补 `0` |
| `NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO` 的 `Transmit.TcpChecksum/UdpChecksum` | 成员名不符 | 直接读原始 64 位值的低 3 位（bit0=IP 头、bit1=TCP、bit2=UDP 由网卡补），语义等价 |
| `NET_BUFFER_CURRENT_MDL(...) = ...` 赋值 | 只读 | WFP 官方示例（msnmntr）就是这么写的；若本 WDK 不允许，改用 `NdisAdjustNetBufferCurrentMdl` |
| `IoCreateDeviceSecure` | 未声明 | 需要 `#include <wdmsec.h>`（已包含）并在链接里加 `wdmsec.lib`（已加） |
| `ExAllocatePoolWithTag` 报弃用警告（`TreatWarningAsError` 打开后成错误） | C4996 | 把 `iwan_win.h` 里 `IWAN_ALLOC` 无条件切到 `ExAllocatePool2` |
| `KeStallExecutionProcessor` | 未声明 | 已含 `ntddk.h`；若仍报，改 `#include <wdm.h>` 显式引入 |
| `DriverEntry` 的第二个参数类型 | 警告 | 固定为 `PUNICODE_STRING`（`iwan_win_drv.c` 已如此） |

## Windows 侧验证步骤

前置：`sc.exe query iwan` 显示 RUNNING；`windev_probe.exe` 报告"驱动在位？是"。

1. **M1 出向（当前实现）**
   - 客户端：`iwan-client-oidc --connect --server <线路> --data-plane kernel`
     （`--data-plane` 在 Windows 上现在接受 `kernel`；`auto` 会先试内核面，
     驱动装不上时回退 TUN 面并在日志里说明原因）。
   - 命中目标集合的流量应当从承载网卡以 UDP 外层包出去：
     在该网卡上抓包**只能看到外层 UDP**，看不到明文内层报文。
   - 服务器自身地址不进隧道：`ping <服务器IP>` 抓到的仍是明文 ICMP
     （对应 Linux 侧"服务器 /32 钉在物理网卡"）。
   - 未命中目标集合的流量照常走原路（分流）。
   - 计数口径与 Linux 相同：`IOCTL_IWAN_SESSION_GET` 的 `stats.tx_pkts/tx_bytes`
     （`tx_bytes` 是**外层**字节，含 36 字节封装开销），可与
     `Get-NetAdapterStatistics` 的承载网卡发送计数直接对照。
2. **M2 入向（下一轮）**：下载/HTTP 双向通；`stats.rx_pkts` 增长；
   `stats.ev_dropped` 为 0（凭据不符、装不下等异常都在这里计数）。
3. **M3 外层 v6（下一轮）**：会话外层走 v6；内层 v4/v6 两种都要覆盖。

虚拟机验证建议：在 `testsign.ps1` 打开测试签名并重启后，用现有 Windows 镜像
（`/media/uker/win-e/`）跑 `install.ps1` + `windev_probe.exe`，再用真实服务器
（`202.38.64.106:6001` 四条线路）做端到端；VM 的网络出口与校园网不同，
所以"分流是否正确"要按 VM 自己的路由表核对，不能照搬 Linux 侧的 netns 脚本。

### M2（入向解封）在 Windows 上怎么验

先确认面的选择与驱动在位：客户端启动日志里应当出现
`内核数据面: 会话已建立 dev=iWAN mtu=... sid=... 外层v4 ...`；驱动没装或 ABI
不匹配时会打印原因，`auto` 模式下自动回退 TUN（`busy` 时不回退，避免把已有
会话顶掉）。

| 观测 | 内核面（应当看到） | TUN 面（对照） |
|---|---|---|
| 下载 16MB：真实网卡 RX | 只增长**外层**字节（内层 + 每包 36B 开销） | 同样只增长外层字节 |
| 下载 16MB：`iWAN` 适配器 RX | **0** | 出现内层字节 |
| 客户端退出时的统计行 | `收外层 N 帧（交付 N），发 M 帧 / X 字节` | 无此行 |
| `netstat -ano -p udp` | 只有客户端自己的那个 UDP 套接字 | 同 |

"`iWAN` 适配器 RX 为 0"正是**报文不进用户态**的观测特征：内层包由驱动在 WFP
里直接注入协议栈，不经过任何网卡，也不经过 TUN 适配器。Linux 内核面实测完全
一致（`iwan0` RX 为 0，真实网卡 RX 增长约 +7.8% 开销）。

其余三条：

1. **断线判定**：在服务端侧掐断外层通路（或在网关丢该 UDP 端口），客户端应在
   `IWAN_RX_STALE_MS` 内开始重连 —— 判活只看共享内存页的时间戳，内核没有定时器。
2. **对端 CLOSE**：服务端发 PT_CLOSE 时客户端应立刻重连（驱动把时间戳归零并
   置 peer_state 已关闭，然后才放行该帧）。
3. **旁证（可选）**：`pktmon filter add -p <外层端口>` 后 `pktmon start`，看到的
   应当只有外层 UDP 包 —— 线路上不存在内层包，这是"隧道在核内"的直接证据。

## M1/M2/M3 的边界（都是 fail-closed，绝不把明文放出去）

- **分段卸载的大段**（内层长度超过内层 MTU）：计数后**丢弃**，不做透传。
  软件分段对应 Linux 侧 `ndo_start_xmit` 的 GSO 分支，列为 M1.1。
- **非线性（数据跨多个 MDL）的报文**：不处理也不吸收，计数后放行。
- **入向解封**：M2。当前只匹配外层五元组并计数。
- **外层 v6**：M3。当前两层 v6 callout 只放行。
- 控制帧（`PT_ECHO_REQ/PT_OPEN_ACK/PT_CLOSE` 等）**不进隧道**：和 Linux 一样由
  用户态自己的 UDP 套接字收发，驱动只吞数据帧。所以 ABI 里没有控制帧通道，
  keepalive 也完全留在用户态 —— 内核只把"收到过闸帧"的时间戳写进共享内存。

### M2（入向解封）新增的边界

- **外层分片不重组**：MF 位或分片偏移非 0 一律不解析（首片虽带 UDP 与帧头，
  但内层是残的）。Linux 侧走 `ip_defrag()` 重组，Windows 侧 M2 不做 —— 实践中
  两端外层包都按协商 MTU 发送、客户端置 DF，所以这是异常路径：命中五元组但
  处理不了 ⇒ 计数 + 吞掉，绝不放给本机协议栈。
- **命中五元组就归我们**：解析失败 / 凭据不符 / 未知类型 ⇒ 吞掉（不是放行）。
  否则伪造或残缺的隧道内容会被当成正常入站流量送进协议栈。
- **控制帧的凭据闸门与内核侧逐条一致**：ECHO_REQ/ECHO_RES/CLOSE 必须带会话
  sid/tok；PING 接受协议固定凭据或会话凭据；OPEN/OPEN_ACK/OPEN_REJECT 一律
  放行给用户态（新分配的 sid/tok 内核不可能预先知道，凭据由用户态的 HMAC
  校验）；未建会话时连握手帧都丢。
- **PT_CLOSE 先归零再放行**：时间戳归零 + peer_state 置已关闭之后，才把 CLOSE
  帧交给用户态套接字 —— 用户态无论看哪个信号都能立刻判定断开。
- **注入前有内层自洽性闸门**（版本 + 头长 + 声明总长盖得住整帧），不合法就不
  注入；注入失败也只影响这一个内层包，外层帧同样被吞掉，不会退化成明文放行。
- **批上限 64**：NBL 链超过上限（或出现空 NB）⇒ 整块吞掉并计入 `ev_dropped`，
  不做"吸收一半"。

### M3（外层 v6）说明与新增边界

外层 v4/v6 **双向**都支持，且外层族始终由**会话**决定（驱动按会话里的
`outer_src6/outer_dst6` 是否同时非零判定），与内层版本无关 —— 这一点照 Linux
侧：内层版本由 `iwan_inner_hdr_check()` 判、外层版本由承载网卡决定，所以
v6-in-v4、v6-in-v6、v4-in-v6 三种组合都成立。出向两层 callout 因此都不按
外层族早退，只有入向两层按会话外层族分工（外层是 v4 的会话只可能在 v4 的
入向层收到自己的包）。

与线上格式有关的三条：

- 外层 v6 头逐字段对齐 `iwan_tx_outer6`：traffic class 与 flow label 全 0、
  hop limit 64、nexthdr 直接是 UDP（**不带扩展头**）、payload_len = UDP 头 + 帧。
- 外层 UDP 校验和 v4/v6 都算真的（Linux 侧是 `udp_set_csum` / `udp6_set_csum`）。
  v6 的 UDP 校验和是 RFC 8200 强制的，所以不允许出现 0；v4 有正确值也让中间
  设备和 NAT 省心。
- 外层 v6 **不分片**（v6 没有 DF 位，源端分片会让对端收到碎片）：内层 + 56 超过
  65535 直接丢。会话建立时已校验"内层 MTU + 封装开销 ≤ 承载 MTU"，但**不逐包
  复核承载 MTU 变化** —— 承载网卡 MTU 中途变小这一种情况会表现为发送失败并被
  计入 `tx_err`，不会静默出错。

入向只接受"nexthdr 直接是 UDP"的 v6 外层（与我们的发送侧一致）；带扩展头的
v6 包按"不是我们的包"交回协议栈，不做扩展头链遍历。外层分片仍然不重组
（同 M2 的取舍）。

## 与 Linux 内核面的已知差异（都可解释，且不静默出错）

内核数据面的四条主链路（出向匹配/封装/注入、入向匹配/解封/注入、keepalive 全在
用户态、时间戳只由内核写共享内存）在两端是一致的。以下差异是 Windows 侧目前
**尚未对齐** Linux 的地方，列在这里避免误判：

| 项 | Linux 内核面 | Windows 现状 | 后果 |
|---|---|---|---|
| 回程路径（proxycidr 主动连入的连接） | conntrack 标记 + fwmark 策略路由，回程绕过 iwan | 只按目的地址是否落在目标集合判定 | 从 proxycidr 网段**主动连入**本机的连接，其回程会被封进隧道 —— Windows 的 TUN 面也没有这个能力，所以不是相对 TUN 的退步；要补齐需要 ALE 层的 flow context（`FwpsFlowAssociateContext0`） |
| 外层分片 | `ip_defrag()` 重组后处理 | 不重组，命中五元组但处理不了的直接吞 | 两端外层包都按协商 MTU 发送，属异常路径 |
| 承载 MTU 变化 | 逐包按路由复核 | 会话建立时校验一次 | 承载 MTU 中途变小表现为发送失败 + `tx_err` |
| 分段/校验和卸载的大段 | `skb_gso_segment` 软件切分 | 计数并吞掉（fail-closed） | `FWPS_LAYER_OUTBOUND_IPPACKET_*` 在 NDIS 分段之前，正常路径看不到大段；真遇到只丢这一个包，不发明文 |

前两项与"回程"这项如果要做，建议顺序是：flow context（回程）→ 外层重组 →
大段软件切分。
