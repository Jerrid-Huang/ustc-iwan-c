# Windows NDIS 数据面设计（微型端口 + 协议驱动）

本文件描述 Windows 客户端的**第二条内核数据面**：`iwanmp.sys`，由一对角色组成 ——
一个 NDIS 微型端口（内层虚拟网卡）和一个 NDIS 协议驱动（外层承载收发）。它与
`docs/win-wfp-data-plane.md` 描述的 WFP callout 数据面（`iwan.sys`）并存，用
`--data-plane kernel-mp` 选择，用于 A/B 对照与逐包成本比较。

## 一、为什么要第二条数据面

WFP callout 数据面在客体上实测到的每包成本是它的结构决定的，不是算术决定的：

| 项 | WFP 面（`iwan.sys`） | 本面（`iwanmp.sys`） |
|----|---------------------|---------------------|
| 出向取得内层报文 | `OUTBOUND_IPPACKET` 处**截获**（吸收原包） | 由微型端口**接收**协议栈交下来的报文（路由指向本适配器） |
| 出向交出外层报文 | `FwpsInjectNetworkSendAsync0` 异步注入，缓冲/MDL/NBL 必须活到完成回调 | `NdisSendNetBufferLists` 交给承载微型端口，同步返回 |
| 入向取得外层报文 | `INBOUND_TRANSPORT` 处截获 | 协议驱动在承载网卡上接收 |
| 入向交回内层报文 | `FwpsInjectNetworkReceiveAsync0` 重新入栈 | `NdisMIndicateReceiveNetBufferLists` 指示向上 |
| 每包协议栈往返 | 2 次（吸收 + 注入 × 两个方向） | 0 次（两侧都是驱动自己的出入口） |
| 每包池分配 | 出向 2 次 + 入向 3 次 | 出向 2 次（缓冲 + MDL/NBL）+ 入向 2 次 |
| 在途缓冲 | 有（注入完成前不归还，必须限流） | 出向有上限（`IWAN_MP_MAX_OUTER_INFLIGHT`），入向无 |
| 内层全量拷贝 | 出向 1 次、入向 2 次 | 出向 1 次、入向 1 次 |
| 目标匹配 | 必须（用目标集合代替路由判定） | 不需要（只看路由是否指向本适配器） |

两条数据面复用同一份控制面：IOCTL 契约、会话结构、共享页布局、`iwan_win_frame.c`
的帧格式与校验和逻辑都相同，用户态（`src/common/kdp_win.c`）只换设备名与内层适配器名。

## 二、结构

一个二进制里同时注册两个 NDIS 角色：

* **微型端口**（`win-driver/iwan_win_mp.c`）：`NdisMRegisterMiniportDriver` 注册，
  `NdisMediumIP` + `*IfType=53`（`IF_TYPE_PROP_VIRTUAL`）。它提供内层接口身份：
  地址、路由、MTU 都由 Windows 协议栈按这张适配器来算，因此 TCP 的 MSS 推导、
  `bind()` 到内层地址、路由查找全部自然成立 —— 这一点是 WFP 面靠"预先存在的
  适配器 + 目标集合"凑出来的，本面则是真的有一张网卡。
* **协议驱动**（`win-driver/iwan_win_proto.c`）：`NdisRegisterProtocolDriver` 注册，
  只绑定 `NdisMedium802_3` 的承载网卡，用 `NdisSendNetBufferLists` 发外层帧、
  在 `ReceiveNetBufferListsHandler` 里收外层帧。邻居解析（ARP）由它自己实现
  （约 200 行，用 `iwan_win_now_ms()` 做限速，不引入定时器）。
* **隧道引擎**（`win-driver/iwan_win_mpdata.c`）：与 WFP 面的
  `iwan_win_encap_inject` / `iwan_win_inbound_worker` 逐条对应的封装与解封，
  调用同一批 `iwan_win_frame.c` 函数。
* **共享**：`win-driver/iwan_win_drv.c`（设备与 IOCTL 分发）、
  `win-driver/iwan_win_session.c`（会话与共享页）、`win-driver/iwan_win_frame.c`（纯逻辑）。

编译配置上两个角色不能放在同一个翻译单元里：`ndis.h` 的版本宏族按"微型端口"或
"协议驱动"二选一（`NDIS_MINIPORT_DRIVER` 一旦定义，协议版本宏就不再兜底）。
`win-driver/iwanmp.vcxproj` 因此对 `iwan_win_mp.c` 单独给条目级定义
（`NDIS_MINIPORT_DRIVER;NDIS620_MINIPORT;NDIS683_MINIPORT`），其余文件用 `NDIS630`。
两个翻译单元之间只交换 `PDEVICE_OBJECT` / `NDIS_HANDLE` / `UINT8 *` / `ULONG`，
不传任何与 NDIS 版本相关的结构，所以两种宏配置共存是安全的。

## 三、数据通路

### 3.1 出向（内层 → 外层）

1. 协议栈按路由把内层数据报交给本微型端口的 `MiniportSendNetBufferLists`。
   只有被路由到本适配器的报文会到这里，因此**不需要目标集合匹配**。
2. 引擎按 `[外层 IP][外层 UDP][帧头 8][内层载荷]` 组装：先改内层校验和
   （`iwan_win_inner_fix_csum`），再按会话密钥异或（`iwan_win_xor`），
   再写帧头（`iwan_win_build_frame_hdr`），最后写外层头
   （`iwan_win_outer_hdr4`）。
3. 协议边补以太头（邻居 MAC 已知就直接写，未知就发一个 ARP 请求并丢弃本包），
   然后 `NdisSendNetBufferLists` 交给承载网卡。
4. 发送完成回调里归还缓冲与 MDL、递减在途计数。

与外层 v6 的关系：第一阶段只做 v4。会话是 v6 时引擎直接拒绝并计
`tx_bad_state`（诊断码 `IWAN_WIN_DIAG_TX_V6_NOT_IMPL`），不做任何降级 ——
外层 v6 需要自己实现邻居发现（NS/NA），留到第二阶段。

### 3.2 入向（外层 → 内层）

1. 协议边的 `ReceiveNetBufferListsHandler` 看到承载网卡上的每个帧：先看以太类型，
   ARP 交给邻居学习，IPv4 则用一次 `NdisGetDataBuffer` 读头部（栈缓冲），
   判据是"版本 4 + 协议 UDP + 目的地址等于会话外层源地址 + UDP 目的端口等于会话
   源端口"。
2. 命中的帧取整包连续指针（取不到就分配缓冲让 NDIS 拼进来）交给引擎；引擎按
   端口互换与凭据分类（与 WFP 面 `iwan_win_inbound_kind` 逐条一致）：
   数据帧解封后 `NdisMIndicateReceiveNetBufferLists` 指示向上；控制帧只记账，
   **不**指示向上。
3. 协议边把收到的 NBL 全部归还（`NdisReturnNetBufferLists`），一个都不向上指示 ——
   承载网卡上的常规 TCP/IP 绑定是另一个协议驱动，它自己会收到一份副本，
   所以控制帧（OPEN_ACK / ECHO / CLOSE）照旧到达用户态套接字，控制面代码零改动。

## 四、控制面与 ABI

* 设备名：`\Device\iwanmp` / `\DosDevices\iwanmp`（WFP 面是 `\Device\iwan`）。
  客户端用 `--data-plane kernel-mp` 选择（`src/common/cli_common.c` 的
  `data_plane_is_kernel_mp`），设备路径与内层适配器名都随平面走
  （`src/iwan_client.c` 的 `win_device_path` / `win_inner_dev`）。
* 共享页名不变（`\BaseNamedObjects\iwan_shm`）：同一时刻只应有一个平面的会话。
* **ABI 版本 2**（`src/common/iwan_win_abi.h`）：`IWAN_WIN_SESSION_OPEN` 末尾追加
  `outer_hop`（偏移 136）与 `reserved1`，结构 136 → 144 字节。原因是**内核态没有
  可用的取路由 API**（`GetBestRoute2` 那一族只在用户态 `netioapi.h`），而协议驱动
  必须知道下一跳才能发 ARP。控制面本来就要为承载 MTU 查一次 FIB，顺手取
  `NextHop` 与 `InterfaceIndex`（`src/common/kdp_win.c` 的 `kdp_win_carrier_route`）：
  `outer_hop` 填下一跳（直连路由为 0，表示"对端在链路上"），`oif_index` 填
  承载接口索引。
* 承载选择：`iwan_win_mp_select_carrier` 用 `oif_index` 在协议边的绑定表里查
  恰好一张网卡；查不到就**整个 OPEN 失败**（fail-closed），不静默退化。
  未显式绑定（`--bind-dev`）时，控制面用 `GetBestRoute2` 的结果填 `oif_index`，
  效果同样是恰好一张 —— 与 Linux 侧"一条会话只用一张下游网卡"同语义。
* 内层地址与 MTU 由控制面设置：客户端 `/32` 内层地址挂在承载网卡上（WFP 面），
  本面挂在微型端口适配器上，并把 `route_iface_ensure_name` 的目标名设为
  `iwanmp`（`src/common/route.c`，`src/common/kdp_win.h` 的
  `IWAN_WIN_DEF_DEV_MP` / `IWAN_WIN_MP_ADAPTER_DESC`）。

## 五、安装与卸载

装具在 `tests/win_vm/`（放仓库里，不放 `/tmp` —— `/tmp` 被系统清空过一次，
装具全丢，重新写了一遍）：

```powershell
# 装机：重打 DriverVer、生成并签名 .cat、清掉 DriverStore 里的旧包、
#       合上保险丝（Parameters\Disarm=1）之后再 devcon install
powershell -NoProfile -File C:\iwan\vm-mp-install.ps1
# 放开保险丝并重启设备节点（默认 NoProto=1：只注册小型端口这一半）
powershell -NoProfile -File C:\iwan\vm-mp-arm.ps1 -NoProto 1
# 只读地把现场读全（设备节点、服务、适配器、trace 键、PnP 事件、磁盘）
powershell -NoProfile -File C:\iwan\vm-mp-state.ps1
# 测完回到休眠状态：Disarm=1 + 停设备 + 停服务（重启也安全）
powershell -NoProfile -File C:\iwan\vm-mp-disarm.ps1
```

* **设备实例 ID 是 `ROOT\NET\000x`，不是 `ROOT\IWANMP\0000`**：`devcon install`
  按 INF 的 `Class=Net` 建节点，装具靠 `HardwareID -contains 'iwanmp'` 现查
  （写死实例 ID 的脚本会全程静默地什么都没做 —— 踩过）。
* 客体上的 `.ps1` **必须存成 UTF-8 带 BOM**（仓库里 `vm-rx.ps1`、`vm-load.ps1` 都是）：
  Windows PowerShell 5.1 对没有 BOM 的文件按 ANSI 解码，中文注释的字节会把后面
  的引号吃掉，报 `The string is missing the terminator: '` —— 四个脚本一起"语法错误"，
  看起来像脚本写错了，实际是编码。另一个同族坑：`param(...)` 必须是脚本的第一条
  语句，把 `[Console]::OutputEncoding = ...` 插到它前面会报
  `The assignment expression is not valid`（要放在 `param` 块之后）。
* 上传后先用解析器检查再运行，比跑起来报错便宜：
  `[System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$null,[ref]$e)`
  → 无错打印 `PARSE-OK`。
* **保险丝在安装之前就要合上**：`Disarm` 存在 `Services\iwanmp\Parameters`
  下，`devcon install` 的 AddService 会保留这个子键，所以 PnP 第一次启动设备时
  DriverEntry 就在任何 NDIS 调用之前退出（设备停 Code 10/37），用来证明
  "装载这条路径本身不会把机器弄挂"。

* INF（`win-driver/iwanmp.inf`）：`Class=Net`、`*MediaType=19`（`NdisMediumIP`）、
  `*IfType=53`、`Characteristics=0x1`（`NCF_VIRTUAL`）、`LowerRange="nolower"`、
  硬件 ID 就是 `iwanmp`。文件**刻意全 ASCII**：setupapi 按 ANSI 或 UTF-16LE 解析 INF。
* **包必须带签名的目录文件**：测试签名模式下，只给 `.sys` 签名不够，INF 包里必须有
  有效的 `.cat`（否则 `devcon install` 报 `Driver package does not contain a catalog
  file` → `0xE000022F`）。仓库不提交 `.cat`，安装脚本在客体上用
  `New-FileCatalog` + `Set-AuthenticodeSignature` 现生成。
* **重装必须改 `DriverVer`**：SetupAPI 在 `DriverVer` 相同时不会重新把 `.sys`
  拷进 `System32\drivers`，表现为"装了新构建但跑的还是旧映像"。
* 加载失败时读 `HKLM\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters` 的
  `Stage` / `Status` 与每阶段键 `T<stage>`（`win-driver/iwan_win_session.c` 的
  `iwan_win_mp_trace`）。这张表是排查"设备起不来"的唯一现场依据
  （`sc.exe start` / 事件 219 只会报 `STATUS_FAILED_DRIVER_ENTRY`，看不到具体
  NTSTATUS）。完整键表：

  | 键 | 含义 |
  | --- | --- |
  | T3 / T4 | DriverEntry 总账：3 = 已经走过的步骤、4 = 走到最后一步 |
  | T5 | `NdisRegisterDeviceEx`（控制设备）的 NTSTATUS，成功时不写 |
  | T7 | 注册之前 `DriverObject->DriverUnload` 是否非空（1 = 曾是，已清掉） |
  | T8 / T9 | 保险丝：8 = `Disarm` 的值，9 = 因保险丝放弃 |
  | T10 / T11 | 小型端口注册失败值 / 成功标记 |
  | T12 / T13 | 总账：12 = 协议边结果（`NoProto=1` 时为 `0xC0000001`）、13 = 成功 |
  | T20 / T21 / T22 | `MiniportInitializeEx`：20 = 进入、21 = 失败值（或 0）、22 = 完成 |
  | T30 | 环境：值即 `NdisGetVersion()`（6.89 → `0x00060059`） |
  | T38 / T39 / T40+i | 小型端口候选表：38 = 尝试次数、39 = 命中档（次版本<<8\|revision）、40+i = 第 i 档的 NTSTATUS |
  | T58 / T60+i / T69 | 协议边候选表：58 = 尝试次数、60+i = 第 i 档结果、69 = 命中（值为声明的次版本） |
  | T70 / T71 | 建会话时查绑定表：70 = 1 表示表头指针是 NULL（表没初始化）、71 = 链上节点数（-1 = 表头为空） |
  | T72 / T73 | open_complete 的成败次数：72 = 成功、73 = 失败（绑进表里却打不开的条数） |
  | T74 / T75 | 链上前两个绑定压成的位图：bit0..13 = ifindex（0x3FFF = 没有该节点）、bit14 = opened、bit15 = closed |
  | T76 / T77 | 76 = open_complete 报的 NTSTATUS 原值、77 = bind 里 NdisOpenAdapterEx 当场返回值（都为 0 而 opened 位为 0 ⇒ 打开还在飞） |
  | T78 / T79 | 78 = NDIS 调过几次 BindAdapterEx、79 = 其中被我们按介质/MAC 长度拒掉几次（71=0 时：78=0 ⇒ NDIS 没叫过我们；78>0 且 79=78 ⇒ 叫了全拒） |
  | T80 / T81 / T82 | 建会话的三种结局各写一个键：80 = 按 oif_index 查不到可用绑定、81 = 选中瞬间被解绑、82 = 成功（值为选中绑定的 ifindex） |
  | T83 | 建会话时为"打开还在飞"等了几个 10 ms（0 = 没等；200 = 等满 2 秒仍没等到） |

  两条不变式（都由 0xD1 换来）：

  * 旗子 `g_proto_started` 只在绑定表与锁都初始化、出向池也建好之后才立起来；
    在此之前到达的会话请求一律被 `iwan_win_mp_select_carrier` 拒掉。反向（先立旗
    后初始化）会让查表读到 BSS 里的 16 个零字节，把 `0x30` 当接口索引读 —— 这就
    是 `0xD1 P1=0x30 P2=2 P4=iwanmp+0x30CF` 的成因。
  * 卸载路径只把节点摘链、**不释放**。节点一旦被释放，任何"取到 b 之后放掉
    `g_bind_lock`、再在 `mp->lock` 里复核"的路径就变成读已释放内存；几个几十字节
    的泄漏远便宜于一次 bugcheck。

  教训（冻结）：**读这些键之前必须先把上一轮的值删掉**（`vm-mp-arm.ps1` 会删）。
  曾经因为键没删干净，把"上一轮装机留下的 T10"读成"这一轮的 T10 消失了"，
  于是得出"版本阶梯第一档就命中、卡点不是版本"的错误结论，白绕一轮。

## 六、已知限制

* 外层只支持 v4（`IWAN_WIN_DIAG_TX_V6_NOT_IMPL`）；外层 v6 的 NS/NA 未实现。
* 数据帧仍会到达承载网卡上的 TCP/IP 绑定（本面无法为别的协议驱动吸收），
  客户端控制循环会忽略它们，只是噪声；要彻底消除需要设备通道而不是套接字。
* `--bind-dev` / `--bind-ip` 未在 Windows 侧接线（两个平面都是）：承载由 FIB 决定。
* 不引入定时器、DPC、工作项、线程：ARP 重试与老化都用时间戳比对。
* 入向在途无上限（只有出向有 `IWAN_MP_MAX_OUTER_INFLIGHT`）。

## 七、验证步骤

**装前闸门**（三条，缺一条就停）：

* 判据只看工件：CI 工件里必须同时有 `iwan.sys` 与 `iwanmp.sys`（该 workflow 的历史
  步骤带 `continue-on-error`，"success" 与"编译成功"曾经完全脱钩，已加断言但判据不变）。
* 装机脚本先把 `Services\iwanmp\Parameters\Disarm=1` 写进注册表再装：设备起来时
  `DriverEntry` 在任何 NDIS 调用之前退出，停在 Code 37，稳定且可逆。
* 一次只放开一层：先 `NoProto=1` 只开小型端口，读数正常再放开协议边。放开后若出现
  BugCheck 或整机无响应，立即停手取转储，不要再"再试一次"。

按"能定位"的顺序分阶段，每阶段都有唯一读数，失败时不必猜：

0. **装机**（`vm-mp-install.ps1`）：读数 = `devcon install` 成功、设备节点出现在
   `HardwareID=iwanmp` 下、服务 `iwanmp` 建好、trace 里 `T8=1`、`T9=0xC0000001`
   且**没有任何 T10 之后的键** —— 这正说明保险丝在任何 NDIS 调用之前就生效了。
1. **小型端口这一半**（`vm-mp-arm.ps1 -NoProto 1`）：读数 = `T40=0x00000000`、
   `T39=(运行时次版本<<8)|1`（小型端口是**单次**注册，版本取 `NdisGetVersion()`，
   不再逐档试）、`T11=0`、设备状态从 Code 37 变成 OK、`Get-NetAdapter` 出现
   `iWAN Tunnel Adapter`（本脚本把它改名为 `iwanmp`）。失败读数 = `T10` 里的
   `0xC0010005`（`NDIS_STATUS_BAD_CHARACTERISTICS`），此时看 `T7`（注册前
   `DriverObject->DriverUnload` 是否被占用，是则已清空并记 1）。
   安全不变式：**`NdisMRegisterMiniportDriver` 一旦成功，`DriverEntry` 绝不再返回失败、
   也绝不注销**（历史事故：失败路径注销了已成功的一半，镜像随即卸载而 NDIS 仍持有回调，
   开机蓝屏 + 启动循环）。
2. **地址与 MTU**：`vm-mp-ab.ps1 -PrepareOnly` 会做改名、停用抢网段的 KM-TEST
   `iWAN`、`netsh interface ip set address iwanmp static 10.99.0.1/24`、
   `netsh interface ipv4 set subinterface iwanmp mtu=1400`；读数 = 适配器 `Up`、
   地址与 MTU 就是刚设的值（客户端控制面由 `src/common/route.c` 的
   `route_iface_up` 自动完成，手工步骤用于隔离故障）。
3. **协议边**（`vm-mp-arm.ps1 -NoProto 0`）：读数 = `T12=0`、`T69` 有值（命中档的
   次版本）、`T57` 无值（`tx_pool` 建成了）。协议边保留逐档候选 `T60+i`，全试完
   仍失败时 `T58` = 尝试次数。判别"协议边有没有真的绑上承载网卡"用第 4 步的
   `SESSION_INFO.carrier_index`：非 0 = 绑上了（`iwan_win_proto_bind` 只接 802.3）。
   若为 0（OPEN 直接 `STATUS_DEVICE_NOT_READY`），先给服务键补
   `Services\iwanmp\Ndi\Interfaces`（`UpperRange="ndis5"`、`LowerRange="ethernet"`）
   再重启设备；仍然为 0 就判定为"一个服务担两个角色"在这一层不成立，
   退回拆成两个服务/两个二进制（协议边另用一个服务名与自己的 INF）。
4. **端到端**（宿主 `bash tests/win_vm/mp-ab.sh [秒] [载荷] [线程] [pps]`）：
   宿主先起 `tests/win_blast.py sink 45678`，客体 `vm-mp-ab.ps1` 开会话（`-Device
   \\.\iwanmp -Service iwanmp -OifIndex <Ethernet>`）并后台保持，前台用
   `vm-bench.ps1 gen` 打内层 UDP；读数 = 驱动 17 项计数（尤其 `tx_pkts`、
   `rx_outer`、`rx_delivered`、`tx_bad_state`、`tx_err`）与宿主接收端逐包对账。
5. **A/B 对照**：同承载（slirp）、同发生器，WFP 面用
   `vm-rx.ps1 -Device \\.\iwan -Service iwan -Adapter iWAN`（+ 宿主 sink）跑一遍，
   mp 面用上面第 4 步跑一遍；WFP 面基准是 1/2/4/8 线程
   25.5k/48.2k/74.1k/77.9k pps（客体内部承载），比较外层 pps、内层 Mbps 与
   `tx_bad_state`/`tx_err`。

## 八、静态分析（MSVC /analyze）

`.github/workflows/win-driver.yml` 用三组宏各跑一次 `cl /analyze`（WFP 面、
NDIS 面的协议边、NDIS 面的小型端口 —— 后两者宏族互斥，必须分开编），
每份 XML 落到工件里。判据只有两条：`analysis-*.xml` 存在（不存在说明分析
压根没跑成，`continue-on-error` 会让"success"与"跑过"脱钩），以及 XML 里
我们自己源码的缺陷数。

从 69 条降到 8 条的过程，本身就是一份"哪些是注解、哪些是真缺陷"的清单：

| 轮次 | 我们的缺陷 | 关键动作 |
| --- | --- | --- |
| 起始 | 69 | 8 类：C28023 × 35、C6014 × 11、C6101 × 10、C6385 × 4、C6386 × 3、C6001 × 3、C28125 × 2、C28199 × 1 |
| 一 | 44 | 27 个处理函数补 `_Function_class_`；`_Out_` 结构体参数先清零；所有权转移点置空；`MmMapLockedPagesSpecifyCache` 包 try/except；不再给栈缓冲起别名 |
| 二 | 26 | 声明与定义的注解一致（`DRIVER_DISPATCH` 原型、`MINIPORT_UNLOAD` 前置声明）；`__except` 过滤表达式改成具体异常码；`__drv_freesMem` 标注"交出即撒手"的缓冲参数 |
| 三 | 12 | 六个纯函数的定义侧补齐 `_Success_` / 条件长度注解；L4 校验和写入的边界与下标同源；目标集合按字节偏移遍历 |
| 四 | 10 | C6385 归零；C6386 改用正方向判据（`len < ihl + 18u`） |
| 五 | 8 | C6386 归零：清零校验和字节改用 `iwan_win_wr16()`，下标与判据各只出现一处 |

剩下的 8 条全是 C6014（"Leaking memory"），逐条核对后判定为误报，判读依据
写在代码里（`iwan_win_wfp.c` 的注入段、`iwan_win_drv.c` 的 `DriverEntry`、
`iwan_win_mp.c` 的 `iwan_win_mp_indicate_inner`）：

* `ctx` / `ctx->buf`：交给 `FwpsInject*Async` 的完成回调释放。WFP 的注入接口
  没有 SAL 注解表达这条转移，分析器只看见"分配了、返回前没释放"。
* `nbl`：交给 `NdisMIndicateReceiveNetBufferLists` 之后归 NDIS，归还时由
  `MiniportReturnNetBufferLists` 释放。
* `stor`：循环体内的临时拼接缓冲，三处释放后都已置空。
* `ext` / `devobj`：驱动生命周期资产，跟卸载路径走。

判据：分配点与释放点在同一函数的两条互斥路径上、每条路径恰好释放一次
⇒ 误报。这条判据也写进了代码注释，避免下一轮有人照着告警去"修"一处本来
就正确的所有权转移。

**真正的两处缺陷**（不是注解问题，已修）：

* `iwan_win_shm_map_user` 的 `MmMapLockedPagesSpecifyCache` 原来没有放在
  `__try/__except` 里（KE 要求；异常时 MDL 会漏），现在只吞访问违例与参数
  无效两族，其余异常继续上抛。
* `iwan_win_classify_out6` 的"拼进临时缓冲也失败"分支释放 `stor` 后没有置空，
  下一轮若走零拷贝成功路径，循环末尾的 `if (stor != NULL)` 会把同一块缓冲
  再释放一次 —— 这是池损坏，不是告警噪声。

回归：`tests/win_frame_test.c` 从 394 项扩到 408 项，新增两组用例 ——
`test_parse_failure_clears_out`（失败路径必须把 `out` 的语义字段清成确定值，
负向验证：去掉清零立刻报 2 项失败）与 `test_parse4_vs_dgram_agree`
（两条入向路径的解析器对同一条流必须给出逐项相同的偏移与帧头字段）。
