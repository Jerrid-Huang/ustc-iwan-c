# ustc-iwan-c

USTC iWAN 命令行客户端：通过统一身份认证（OIDC）获取线路配置，以 TUN 隧道或 SOCKS5 代理连接。

| 二进制 | 用途 |
|--------|------|
| `iwan-client-oidc` | 推荐使用。登录、保存配置、选择线路并连接。 |
| `iwan-client` | 手动指定服务器、用户名和密码。 |
| `iwan-server` | 自建兼容测试服务端（仅 Linux）。 |

## 下载

从 [GitHub Releases](https://github.com/Jerrid-Huang/ustc-iwan-c/releases) 下载：

| 平台 | 资产 |
|------|------|
| Linux x86_64（glibc） | `iwan-linux-x86_64.tar.gz` |
| Linux 各架构（静态 musl） | `iwan-linux-<arch>-musl.tar.gz`（x86_64 / i686 / aarch64 / armv7 / riscv64 / ppc64le / s390x） |
| Windows | `iwan-windows-<arch>.zip`（x86_64 / i686 / arm64） |
| macOS | `iwan-macos-<arch>.zip`（x86_64 / arm64） |

权限要求：TUN 模式需要 root / 管理员权限（Windows 还需同目录 `wintun.dll`）；**SOCKS5 模式无需任何权限**。

## iwan-client-oidc（推荐）

登录、保存线路配置并连接。

```
Usage: iwan-client-oidc [OPTIONS] --fetch | --list | --connect | --all
```

| 参数 | 说明 |
|------|------|
| `-f, --fetch` | 登录并抓取线路配置（浏览器认证后粘贴回调 URL），保存到本地 |
| `-l, --list` | 列出本地已保存的线路（离线） |
| `-c, --connect` | 连接（交互选择线路；默认 TUN 模式，root） |
| `-a, --all` | 一次完成 fetch → list → connect |
| `--server <NAME\|HOST:PORT>` | 跳过线路选择，直接连接指定线路（配置名或地址） |
| `--config-dir <DIR>` | 配置目录（默认 `~/.config/iwan`；Windows：`%USERPROFILE%\.config\iwan`） |
| `--tun <TUN>` | TUN 设备名（默认 `iwan0`） |
| `--socks` | 改用纯 SOCKS5 模式（免 root，无需 TUN 设备） |
| `--socks-listen <ADDR:PORT>` | SOCKS 模式默认监听 `127.0.0.1:1080`；**TUN 模式默认关闭 SOCKS 代理**（纯 TUN 网卡），仅在显式指定该选项时启动随 TUN 路由转发的附加 SOCKS5+HTTP 侧车代理。该端口若已被占用，TUN 连接**不会失败**：侧车代理以一条错误日志跳过（继续无本地代理运行，隧道不受影响） |
| `--socks-mtu <MTU>` | SOCKS 模式下内层 TCP 的 MSS/MTU（默认 `1380`） |
| `--socks-token <TOKEN>` | SOCKS5 RFC1929 密码认证（与 `--socks-no-token` 互斥） |
| `--socks-no-token` | 显式允许无密码代理（配合 `--allow-remote`） |
| `--allow-remote` | 允许监听非回环地址（默认仅 127.0.0.1） |
| `--socks-ipv6` | 假设服务器可转发 IPv6：域名解析优先 AAAA 并接受 `ATYP=4` 目标（默认关闭：仅解析 IPv4，IPv6 目标返回 `rep=8`） |
| `--proxy-cidr <CIDR>` | 走隧道的 IPv4 CIDR（可重复，如 `0.0.0.0/0` 全量） |
| `--proxy-ip <IP>` | 走隧道的 IPv4 地址（可重复） |
| `--proxy-domain <DOMAIN>` | 走隧道的域名（可重复，含子域） |
| `--proxy-cidr6 <CIDR6\|IP6\|DOMAIN>` | 走隧道的 IPv6 条目（可重复） |
| `--ustc` | 将全部校园网 CIDR 加入代理路由 |
| `-h, --help` | 帮助 |

配置保存于 `~/.config/iwan/servers.json`，可用 `--config-dir` 修改。

```bash
# 登录获取线路配置（浏览器认证后粘贴回调 URL）
./iwan-client-oidc --fetch

# 列出本地线路（离线）
./iwan-client-oidc --list

# 连接（交互选择线路，TUN 模式）
sudo ./iwan-client-oidc -c --ustc

# 一次完成：--fetch -> --list -> --connect
sudo ./iwan-client-oidc --all

# SOCKS5 模式（免 root）
./iwan-client-oidc --connect --socks --socks-listen 127.0.0.1:1080
```

## iwan-client（手动）

指定服务器、用户名、密码连接。子命令：`ping`、`auth`、`proxy`（TUN 模式）、`socks`（SOCKS5 模式）。

### 公共认证参数（auth / proxy / socks 子命令）

| 参数 | 说明 |
|------|------|
| `--server <SERVER>` | 服务器地址（IP 或域名；`proxy`/`socks` 必填） |
| `--port <PORT>` | 服务器 UDP 端口（默认 `6001`） |
| `--user <USER>` | 用户名（socks 默认 `_rev_m_1`） |
| `--pass <PASS>` | 密码（与 `--pass-file` 二选一） |
| `--pass-file <FILE>` | 从文件读密码（避免命令行泄露） |
| `--ct-pass <PASS>` / `--ct-pass-file <FILE>` | 校内统一认证的"密保口令"（USTC 场景） |
| `--mtu <MTU>` | 内层 TCP 的 MSS/MTU。默认按模式而异：`auth` / `proxy` 为 `1400`（`IWAN_DEFAULT_MTU`），`socks` 为 `1380`；`proxy` 模式还会把它应用到 TUN 设备 MTU |

### proxy（TUN 模式，需要 root）

```
Usage: iwan-client proxy [OPTIONS] --server <SERVER>
```

**默认：纯 TUN 隧道**（本机路由走隧道的流量被转发，不提供任何本地代理端口）。仅当指定 `--listen` 时才**附加**一个 SOCKS5+HTTP 代理。

公共认证参数 +：

| 参数 | 说明 |
|------|------|
| `--tun <TUN>` | TUN 设备名（默认 `iwan0`） |
| `--proxy-cidr <CIDR>` | 走隧道的 IPv4 CIDR（可重复；如 `0.0.0.0/0` 全量） |
| `--proxy-ip <IP>` | 走隧道的 IPv4 地址（可重复） |
| `--proxy-domain <DOMAIN>` | 走隧道的域名（可重复，含子域） |
| `--proxy-cidr6 <CIDR6\|IP6\|DOMAIN>` | 走隧道的 IPv6 条目（可重复） |
| `--listen <ADDR:PORT>` | **可选**：附加本地 SOCKS5 + HTTP 代理（默认不启用；内核栈转发，走 TUN 路由） |
| `--socks-token <TOKEN>` | 代理的 RFC1929 密码认证（与 `--socks-no-token` 互斥） |
| `--socks-no-token` | 显式允许无密码代理（配合 `--allow-remote`） |
| `--allow-remote` | 允许监听非回环地址（默认仅 127.0.0.1） |

> `--listen` 代理的连接走本机内核栈，**与 TUN 路由规则一致**（默认路由全走隧道；`--proxy-cidr` 模式下仅 CIDR 内目标走隧道）。同一端口同时接受 SOCKS5 与 HTTP 握手（设置 `--socks-token` 后 HTTP 代理关闭）。

> **HTTP 代理为单请求语义**：绝对 URI 转发（GET/HEAD/POST … http://…）把一条客户端连接固定到首个请求选定的上游，随后的字节流以透明双工管道直通、不再解析——第二条指向不同 origin 的请求**无法被重新分派**（RFC 7230 §6.3.6 禁止代理跨 authority 复用连接转发）。因此转发时会将原请求里的 `Connection` 头改写为 `Connection: close`：合规上游会以 `Connection: close` 应答并关闭连接，该代理连接在**一次请求/响应后即结束**，合规客户端（浏览器、主流 HTTP 库按 origin 池化）不受影响。**残余（如实声明）**：忽略 `Connection: close` 并坚持在同一连接上复用/管线化的客户端，其第二条请求仍会被送到首个上游（数据面不解析无法感知）；此类客户端必须按 origin 池化连接。`CONNECT` 隧道不受影响（建立后为透明字节流，无逐请求语义）。

> 安全提示：多用户共机时不设 `--socks-token` 意味着本机任何账号都可使用这个无密码代理；`--socks-token` 经命令行传入，本机其他用户可在进程列表中看到明文口令 —— 敏感环境建议改用仅回环监听（默认）并自行评估。

```bash
sudo ./iwan-client proxy --server <IP> --port 6001 --user <USER> \
  --pass '<PASSWORD>' --proxy-ip 1.1.1.1 \
  --listen 127.0.0.1:1080            # 附加本地 SOCKS5+HTTP 代理
```

### socks（SOCKS5 模式，免 root）

```
Usage: iwan-client socks [OPTIONS] --server <SERVER>
```

公共认证参数 +：

| 参数 | 说明 |
|------|------|
| `--listen <ADDR:PORT>` | 本地监听地址（默认 `127.0.0.1:1080`） |
| `--socks-token <TOKEN>` | SOCKS5 RFC1929 密码认证（与 `--socks-no-token` 互斥） |
| `--socks-no-token` | 显式允许无密码代理（配合 `--allow-remote`） |
| `--allow-remote` | 允许监听非回环地址 |
| `--socks-ipv6` | 假设服务器可转发 IPv6：域名解析优先 AAAA 并接受 `ATYP=4` 目标（默认关闭：仅解析 IPv4，IPv6 目标返回 `rep=8`） |

> 同一端口同时接受 HTTP 代理握手（设置 `--socks-token` 后关闭）。默认仅监听回环、无密码；监听非回环地址时必须指定 `--socks-token` 或 `--socks-no-token`（或配合 `--allow-remote`）。

```bash
./iwan-client socks --server <IP> --port 6001 --user <USER> \
  --pass '<PASSWORD>' --listen 127.0.0.1:1080
```

### ping / auth

```bash
./iwan-client ping --server <IP> --port 6001          # 连通性测试
./iwan-client auth --server <IP> --port 6001 --user <USER> --pass '<PASSWORD>'
```

## iwan-server（自建测试服务端，仅 Linux）

用户文件每行 `username:password`，权限必须为 600：

```bash
sudo ./iwan-server --port 6001 --tun iwan-srv \
  --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --dns 114.114.114.114 \
  --users /etc/iwan/users.txt --nat-if eth0
```

| 参数 | 说明 |
|------|------|
| `-p, --port <PORT>` | UDP 端口（默认 `6001`） |
| `-t, --tun <TUN>` | TUN 设备名 |
| `-s, --server-ip <IP>` | 服务器内网 IP（隧道网关地址） |
| `-S, --subnet <CIDR>` | 分配给客户端的子网（如 `198.18.0.0/16`） |
| `-d, --dns <DNS>` | 下发给客户端的 DNS 服务器 |
| `-u, --users <FILE>` | 用户文件（`username:password` 每行，权限 600） |
| `-n, --nat-if <IF>` | 做 NAT 的物理网卡（自动配置 iptables MASQUERADE） |
| `-T, --no-tun` | 测试模式：不开 TUN，把包镜像回客户端（免 root） |
| `--user <NAME>` | setup 完成后降权到该用户（默认 `nobody`）；用户文件仍必需。注意：**没有** `-U` 短选项（仅长选项，`--help` 也只列 `--user`；`iwan-server -U x` 报 invalid option） |
| `-h, --help` | 帮助 |

服务器启动时自动启用 IPv4 转发并配置 iptables MASQUERADE（需要 root，`--no-tun` 测试模式除外）。

> **运行时韧性（R43-C1-L1）**：服务端每秒探测一次 TUN 设备索引（`if_nametoindex`，与客户端 proxy 哨兵同机制）。若 TUN 设备在运行中被外部删除（`ip link del $TUN`、netns 拆除、驱动卸载），服务端会输出 `tun device <name> vanished (deleted externally); tunnel dead — restart to recover` 并以**非零码退出**，交由 systemd/restart 策略恢复，而不是继续在静默死亡的隧道上运行。正常关停（SIGINT/SIGTERM/SIGHUP）不探测、不误报，退出码不受影响。

## 环境变量

三个二进制的 `--help` 末尾各有一段 `Environment:` 清单，与本节下面的三张表是**同一份清单**，共 **4 份文件 / 6 个块**，改动其中一块必须同步其余五块：

- `src/iwan_client.c`、`src/iwan_server.c`、`src/oidc/oidc_cli.c` 各一处 help footer（即 `--help` 末尾的 `Environment:` 段）；
- 本节的三张表：`### iwan-server（仅 Linux）`、`### iwan-client`、`### iwan-client-oidc`。

定位方式：`grep -rn "Environment" src/` 找三个 footer（该命令还会命中 `src/common/port.c` 的 `SetEnvironmentVariableW` 等无关行），本节三张表见下方三个 `###` 标题。每块只列**该二进制真正会读取**的变量。

> **构建条件**：`IWAN_DEBUG`、`IWAN_PROFILE`、`IWAN_PUMP_PROF` 只在**未定义 `IWAN_DEBUG_STRIP`** 的构建里生效。CMake 对非 Debug 构建默认 `IWAN_DEBUG_STRIP=ON`（Release 又是默认构建类型），因此默认产物里这三个变量**完全不会被解析**；现场诊断请用 `-DCMAKE_BUILD_TYPE=Debug`（或显式 `-DIWAN_DEBUG_STRIP=OFF`）构建。**多配置生成器例外**：`-DCMAKE_BUILD_TYPE` 只对单配置生成器（Unix Makefiles / Ninja）有效，Ninja Multi-Config 与 Visual Studio 会忽略它，其非 Debug 配置仍会带上 `-DIWAN_DEBUG_STRIP=1`；请显式加 `-DIWAN_DEBUG_STRIP=OFF`（或在配置阶段 `cmake -B <dir> -DIWAN_DEBUG_STRIP=OFF`）后再 `--config Debug` 构建。`IWAN_RXDBG`/`IWAN_FLOWDBG` 不受该开关影响，Release 下仍可用。
>
> **布尔取值**：`0`/`false`/`no`/`off`（不分大小写）为关闭，其他非空值为开启；未设置与显式空串都取默认值（下面各表中的"默认"列）。例外：`IWAN_RXDBG`/`IWAN_FLOWDBG` 只认**大小写敏感**的精确 `0`/`false`/`off` 为关闭——`no`/`NO`/`No` **不**关闭，`False`/`Off`/`0x`/`00`/`0 ` 一律算**开启**；`IWAN_SRV_TUN_SINGLE` 的关闭拼写区分大小写；`IWAN_PUMP_PROF` 只要**被设置**就是开启（空串、`0` 也算开启，只有完全不设置才是关）；`IWAN_WIN_THREAD_PIN` 的非精确关闭拼写（如 `0 `/`0x`/`00`）按总则算**开启**；两个 `*_ALLOW_LOOPBACK` 安全开关只认精确的 `1`；`IWAN_ALLOW_INSECURE_USERS` 只认 `1`/`true`/`yes`/`on`。数值型变量非法（含上界越界）时回退默认值并打印告警。

### iwan-server（仅 Linux）

| 变量 | 默认 | 说明 |
|------|------|------|
| `IWAN_DEBUG` | 关 | 详细调试日志（`IWAN_DEBUG_STRIP` 构建忽略） |
| `IWAN_PROFILE` | 关 | 退出时打印分阶段吞吐计数（`IWAN_DEBUG_STRIP` 构建忽略） |
| `IWAN_SRV_THREADS` | `4` | 上行 UDP 收包线程数，`1..16`；非法值告警后保持 4 |
| `IWAN_SRV_TUN_SINGLE` | 关 | 只用一个 TUN 队列，替代多队列 fan-out（A/B 基准开关） |
| `IWAN_ALLOW_INSECURE_USERS` | 关 | 允许组/其他可读的用户文件继续启动；仅 `1`/`true`/`yes`/`on` 放行 |
| `IWAN_RATE_OPEN_MAX` | `20` | 每源每秒 OPEN 帧上限，`1..65535` |
| `IWAN_RATE_ECHO_MAX` | `60` | 每源每秒 PING、ECHO 各自上限，`1..65535` |
| `IWAN_RATE_MISS_MAX` | `2000` | 每源每秒**计入慢路径**的未知会话 DATA/CLOSE 帧预算，`1..65535`；超预算后该源本秒内其余未知帧走无锁快路径丢弃（未知 sid 帧无论是否超预算都不投递） |
| `IWAN_RATE_TOKBAD_MAX` | `4096` | 每源每秒**已知会话错 token** 的 DATA 帧预算（bound 类：源与某会话 peer 的 ip:port 逐字节相同），`1..65535`；超预算后该源本秒内其余错 token 帧走无锁快路径丢弃——错 token 帧无论是否超预算都不投递，正确 token 的 DATA 永不触达该预算（预算只省每帧的会话写锁，不 gate 投递） |
| `IWAN_RATE_CLOSE_MAX` | `4096` | 每源每秒**已知会话错 token** 的 CLOSE 帧预算（bound 类），`1..65535`；超预算后该源本秒内其余错 token CLOSE 走无锁快路径丢弃——错 token CLOSE 无论是否超预算都被丢弃，正确 token 的同源 wipe 永不触达该预算（预算只省每帧的会话写锁，不 gate 投递） |
| `IWAN_SRV_THROTTLE_MS` | `2` | 每会话上行节流窗（ms）：该会话自身 TUN 写碰满设备队列后生效，`1..65535`（`0` 非法；一窗一帧地让洪泛者后续帧在到队列前就被丢，把共享设备让给其他会话） |

另读取：`SSL_CERT_FILE`（**唯一**由环境变量指定的 CA 文件来源）、`SSL_CERT_DIR`（**不会**被当作 CA 目录读取——`SSL_CTX_load_verify_locations()` 的第二实参 `CApath` 恒为空，全树也没有调用 `set_default_verify_paths()`；它只在 fork 出的辅助进程 `exec` 前按属主/权限决定保留或清除：非 root 属主、或组/其他可写时被清除）。

`IWAN_RATE_MISS_MAX` 触发的限流丢弃在 stderr 上可观测：只要丢弃计数有增长，服务端就输出一行 `rate: ratedrop=<total> (+<delta>)`（`total` 为累计丢弃数，`delta` 为**自上次报告总数以来的新增量**；Debug 下 `uplink: ... ratedrop=` 统计行报过的数字不会在 `+delta` 里重复计入），**每秒最多一行**；计数不动则一行都不打印。该行**不受 `IWAN_DEBUG_STRIP` 影响，Release 产物同样打印**。

### iwan-client

| 变量 | 默认 | 适用模式 | 说明 |
|------|------|----------|------|
| `IWAN_DEBUG` | 关 | 全部 | 调试日志（`IWAN_DEBUG_STRIP` 构建忽略） |
| `IWAN_PROFILE` | 关 | 全部 | 退出时打印分阶段吞吐（`IWAN_DEBUG_STRIP` 构建忽略） |
| `IWAN_RX_STALE_MS` | `120000` | proxy / socks | 下行静默超过该毫秒数即重新认证；`0` 关闭；`30000..86400000` |
| `IWAN_SEND_PACING_PPS` | `0` | proxy / socks | 聚合发送限速（包/秒），`0` 关闭；有效范围 `1..10000000`，越界/非法告警后关闭 |
| `IWAN_RXDBG` | 关 | socks | 打印每个收到的 VPN 数据报 |
| `IWAN_FLOWDBG` | 关 | socks | 打印 SOCKS 流状态变化与关闭原因 |
| `IWAN_NS_CONNECT_TIMEOUT_MS` | `30000` | socks | 用户态 TCP 连接超时，`1000..300000` |
| `IWAN_SOCKS_ALLOW_LOOPBACK` | 关 | socks | SSRF 开关（只认精确 `1`）：允许非回环对端访问本机回环/链路本地目标 |
| `IWAN_AUTH_FAIL_MAX` | `5` | socks | 每源认证失败达该次数即锁定，`1..100` |
| `IWAN_AUTH_FAIL_WINDOW_MS` | `60000` | socks | 锁定统计窗口，`100..86400000` |
| `IWAN_PUMP_PROF` | 关 | proxy | TUN 泵分阶段剖析；**设置任意值（含空串）即开启**；`IWAN_DEBUG_STRIP` 构建不解析 |
| `IWAN_PUMP_QUEUES` | CPU 数（上限 `8`） | proxy | TUN 读队列数，`1..8`；非法值告警后回到默认；Windows 的 wintun 固定单队列 |
| `IWAN_RELAY_ALLOW_LOOPBACK` | 关 | proxy `--listen` | 中继 SSRF 开关（只认精确 `1`） |
| `IWAN_WIN_THREAD_PIN` | 关 | proxy（Windows） | 实验性：泵线程绑核/提优先级 |
| `IWAN_ELEVATED_RELAUNCH` | — | Windows 内部 | 程序在 UAC 重启前自己设置，请勿手工设置 |

另读取：`SSL_CERT_FILE`（**唯一**由环境变量指定的 CA 文件来源；非 Windows，TUN 模式）、`SSL_CERT_DIR`（**不会**被当作 CA 目录读取；只在进入辅助进程 `exec` 前按属主/权限决定保留或清除）。

### iwan-client-oidc

| 变量 | 默认 | 适用模式 | 说明 |
|------|------|----------|------|
| `IWAN_DEBUG` | 关 | 全部 | 调试日志（`IWAN_DEBUG_STRIP` 构建忽略） |
| `IWAN_RX_STALE_MS` | `120000` | TUN / socks | 下行静默超过该毫秒数即重新认证；`0` 关闭；`30000..86400000` |
| `IWAN_SEND_PACING_PPS` | `0` | TUN / socks | 聚合发送限速（包/秒），`0` 关闭；有效范围 `1..10000000`，越界/非法告警后关闭 |
| `IWAN_RXDBG` | 关 | socks | 打印每个收到的 VPN 数据报 |
| `IWAN_FLOWDBG` | 关 | socks | 打印 SOCKS 流状态变化与关闭原因 |
| `IWAN_NS_CONNECT_TIMEOUT_MS` | `30000` | socks | 用户态 TCP 连接超时，`1000..300000` |
| `IWAN_SOCKS_ALLOW_LOOPBACK` | 关 | socks | SSRF 开关（只认精确 `1`） |
| `IWAN_AUTH_FAIL_MAX` | `5` | socks | 每源认证失败达该次数即锁定，`1..100` |
| `IWAN_AUTH_FAIL_WINDOW_MS` | `60000` | socks | 锁定统计窗口，`100..86400000` |
| `IWAN_PUMP_PROF` | 关 | TUN | TUN 泵分阶段剖析；设置任意值即开启；`IWAN_DEBUG_STRIP` 构建不解析 |
| `IWAN_PUMP_QUEUES` | CPU 数（上限 `8`） | TUN | TUN 读队列数，`1..8`；Windows 的 wintun 固定单队列 |
| `IWAN_RELAY_ALLOW_LOOPBACK` | 关 | TUN `--socks-listen` | 中继 SSRF 开关（只认精确 `1`） |
| `IWAN_WIN_THREAD_PIN` | 关 | TUN（Windows） | 实验性：泵线程绑核/提优先级 |
| `IWAN_ELEVATED_RELAUNCH` | — | Windows 内部 | 程序在 UAC 重启前自己设置，请勿手工设置 |

另读取：`SSL_CERT_FILE`（非 Windows：HTTPS 调用**唯一**由环境变量指定的 CA 文件来源）、`SSL_CERT_DIR`（**不会**被当作 CA 目录读取，辅助进程 `exec` 前只按属主/权限决定保留或清除）、`HOME`、`SUDO_USER`、`SUDO_UID`、`SUDO_GID`、`XDG_RUNTIME_DIR`、`TMPDIR`（Linux）；`USERPROFILE`、`HOMEDRIVE`、`HOMEPATH`、`HOME`、`TEMP`、`TMP`、`USERNAME`（Windows）。

> 注意：`iwan-client-oidc` **不读** `IWAN_PROFILE`（其 `main` 不调用 `prof_init()`）。

### 重复选项

| 二进制 | 重复同一个选项 |
|--------|----------------|
| `iwan-server` | 允许，**取最后一次**的值（裸 `getopt_long`，无重复检测） |
| `iwan-client` | 报错 `cannot be used multiple times`，退出码 2；仅 `proxy` 的列表选项 `--proxy-cidr`/`--proxy-ip`/`--proxy-domain`/`--proxy-cidr6` 可重复并累加 |
| `iwan-client-oidc` | 同上（clap 语义）；列表选项 `--proxy-cidr`/`--proxy-ip`/`--proxy-domain`/`--proxy-cidr6` 可重复并累加 |

`iwan-server` 的机制统一（移植 `cli.c` 的重复检测）仍未实现，当前只在文档层统一措辞。

## 从源码构建

依赖：`cmake`（≥3.16）、C11 编译器、OpenSSL（Debian/Ubuntu：`libssl-dev`；macOS：`brew install openssl@3`）。

```bash
cmake -B build
cmake --build build -j      # 产物在 bin/
```

macOS 需指定 Homebrew OpenSSL：`cmake -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`。

macOS 最低系统版本为 macOS 11（Apple Silicon 与 Intel 均支持）；发布包为 ad-hoc 签名、未公证，首次运行若被 Gatekeeper 拦截需手动放行（`xattr -d com.apple.quarantine iwan-client`，或 系统设置→隐私与安全性）。构建依赖 OpenSSL 3.x（`brew install openssl@3` 或源码静态构建），发布包为源码静态链接，无 Homebrew 运行时依赖。

### Windows 从源码构建

在 Linux 上交叉编译：

```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/windows-x86_64.cmake -DIWAN_OPENSSL_DIR=<mingw-openssl> -DIWAN_STATIC=ON
```

工具链文件提供 `windows-x86_64` / `windows-i686` / `windows-arm64` 三个（arm64 需 llvm-mingw + MSYS2 clangarm64 OpenSSL，见 CI 的 win-arm64 job）。

OpenSSL 需先交叉构建：`ci/build-openssl.sh mingw64 x86_64-w64-mingw32- /path/to/prefix no-asm`（i686 用 `mingw` target + `i686-w64-mingw32-` 前缀；no-asm 必需，PE 汇编器不接受 perlasm 生成的 ELF 指令）。apt 依赖：`gcc-mingw-w64-x86-64`。

`IWAN_STATIC=ON` 使 exe 静态链接 OpenSSL/winpthread，可独立运行；否则需随包附带 DLL。

运行依赖：TUN 模式需要与 exe 同目录的 `wintun.dll`（架构匹配：x86_64→amd64，i686→x86，arm64→arm64，下载 https://www.wintun.net/）；SOCKS5 模式不需要。发布 zip 内已附 README/LICENSE/WINTUN.txt 说明。

> Windows 交付物由 CI 的 `win-cross` 作业（`.github/workflows/build.yml`）持续验证：MinGW-w64 交叉编译（x86_64 + i686，`-DIWAN_WERROR=ON`）、wine 冒烟运行、Windows 客户端 ↔ Linux 服务端的真实线格式测试，以及针对 Windows 构建的 SOCKS5/RFC1929 握手套件（`tests/socks_handshake.py --harness`，在 wine 下执行）。仓库内**没有** PowerShell 测试脚本；真实 Windows TUN 设备（wintun 适配器、netsh 路由、IPv6 ULA）的验证需真机/虚拟机手工完成，CI 不覆盖。

## 致谢

- 基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写与优化。
- SOCKS5 模式使用 [lwIP](third_party/lwip/README.iwan)（BSD-3-Clause），设计参考 [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel)。

## License

[MIT](LICENSE)
