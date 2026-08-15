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
| `--encrypt <0\|1>` | 隧道加密开关（默认 `1`） |
| `--socks` | 改用 SOCKS5 模式（免 root，无需 TUN 设备） |
| `--socks-listen <ADDR:PORT>` | SOCKS5 / HTTP 代理监听地址（SOCKS 模式默认 `127.0.0.1:1080`） |
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
| `--encrypt <0\|1>` | 隧道加密开关（默认 `1`） |
| `--mtu <MTU>` | 内层 TCP 的 MSS/MTU（默认 `1380`；`proxy` 模式使用 TUN 设备 MTU） |

### proxy（TUN 模式，需要 root）

```
Usage: iwan-client proxy [OPTIONS] --server <SERVER>
```

公共认证参数 +：

| 参数 | 说明 |
|------|------|
| `--tun <TUN>` | TUN 设备名（默认 `iwan0`） |
| `--proxy-cidr <CIDR>` | 走隧道的 IPv4 CIDR（可重复；如 `0.0.0.0/0` 全量） |
| `--proxy-ip <IP>` | 走隧道的 IPv4 地址（可重复） |
| `--proxy-domain <DOMAIN>` | 走隧道的域名（可重复，含子域） |
| `--proxy-cidr6 <CIDR6\|IP6\|DOMAIN>` | 走隧道的 IPv6 条目（可重复） |
| `--listen <ADDR:PORT>` | **同时开启本地 SOCKS5 + HTTP 代理**（内核栈转发，走 TUN 路由） |
| `--socks-token <TOKEN>` | 代理的 RFC1929 密码认证（与 `--socks-no-token` 互斥） |
| `--socks-no-token` | 显式允许无密码代理（配合 `--allow-remote`） |
| `--allow-remote` | 允许监听非回环地址（默认仅 127.0.0.1） |

> `--listen` 代理的连接走本机内核栈，**与 TUN 路由规则一致**（默认路由全走隧道；`--proxy-cidr` 模式下仅 CIDR 内目标走隧道）。同一端口同时接受 SOCKS5 与 HTTP 握手（设置 `--socks-token` 后 HTTP 代理关闭）。

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
| `-U, --user <USER>` | 单用户模式（与 `--users` 文件二选一） |
| `-h, --help` | 帮助 |

服务器启动时自动启用 IPv4 转发并配置 iptables MASQUERADE（需要 root，`--no-tun` 测试模式除外）。

## 从源码构建

依赖：`cmake`（≥3.16）、C11 编译器、OpenSSL（Debian/Ubuntu：`libssl-dev`；macOS：`brew install openssl@3`）。

```bash
cmake -B build
cmake --build build -j      # 产物在 bin/
```

macOS 需指定 Homebrew OpenSSL：`cmake -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`。

## 致谢

- 基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写与优化。
- SOCKS5 模式使用 [lwIP](third_party/lwip/README.iwan)（BSD-3-Clause），设计参考 [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel)。

## License

[MIT](LICENSE)
