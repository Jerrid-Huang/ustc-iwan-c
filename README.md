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

## OIDC 使用流程

```bash
# 1. 登录获取线路配置（浏览器认证后粘贴回调 URL）
./iwan-client-oidc --fetch

# 2. 列出本地线路（离线）
./iwan-client-oidc --list

# 3. 连接（交互选择线路，TUN 模式）
sudo ./iwan-client-oidc -c --ustc

# 或一次完成：--fetch -> --list -> --connect
sudo ./iwan-client-oidc --all
```

跳过交互直接连接指定线路：`--server <配置名|host:port>`。

配置保存于 `~/.config/iwan/servers.json`（Windows：`%USERPROFILE%\.config\iwan\servers.json`），可用 `--config-dir` 修改。

### SOCKS5 模式（免 root）

```bash
./iwan-client-oidc --connect --socks \
  --socks-listen 127.0.0.1:1080 --socks-mtu 1380
```

- 默认仅监听回环、无密码；监听非回环地址时必须指定 `--socks-token <PASS>` 或 `--socks-no-token`（互斥），或配合 `--allow-remote`。
- 同一端口同时接受 HTTP 代理握手（设置 `--socks-token` 后禁用）。
- 默认按服务器不支持 IPv6 处理：域名仅解析 IPv4，`ATYP=4`（IPv6 目标）请求返回 `rep=8`。确认服务器可转发 IPv6 时加 `--socks-ipv6`，此时域名解析优先 IPv6（AAAA）并接受 IPv6 目标。

### TUN 模式附加代理

TUN 模式下加 `--socks-listen 127.0.0.1:1080` 即可在同一端口提供 SOCKS5 + HTTP 代理；代理连接走本机内核栈，**与 TUN 路由规则一致**（默认路由全走隧道；`--proxy-cidr` 模式下仅 CIDR 内目标走隧道）。`--socks-token` / `--socks-no-token` / `--allow-remote` 语义与 SOCKS5 模式相同。

### 常用参数

| 参数 | 说明 |
|------|------|
| `--fetch` / `--list` / `--connect` / `--all` | 四个动作，必须指定其一 |
| `--server <NAME\|HOST:PORT>` | 跳过线路选择直接连接 |
| `--proxy-ip` / `--proxy-domain` / `--proxy-cidr` | 指定走隧道的 IPv4 / 域名 / CIDR（可重复） |
| `--proxy-cidr6` | 指定走隧道的 IPv6 CIDR / 地址 / 域名（可重复） |
| `--proxy-cidr 0.0.0.0/0` | 全部 IPv4 流量走隧道 |
| `--tun` / `--encrypt` | TUN 设备名（默认 `iwan0`）/ 加密模式（默认 `1`） |
| `--ustc` | 将全部校园网 CIDR 加入代理路由 |

## 手动客户端

```bash
./iwan-client ping --server <IP> --port 6001
./iwan-client auth --server <IP> --port 6001 --user <USER> --pass '<PASSWORD>'
sudo ./iwan-client proxy --server <IP> --port 6001 --user <USER> --pass '<PASSWORD>' --proxy-ip 1.1.1.1
./iwan-client socks --server <IP> --port 6001 --user <USER> --pass '<PASSWORD>' --listen 127.0.0.1:1080
```

## 服务端（自建测试）

用户文件每行 `username:password`，权限必须为 600：

```bash
sudo ./iwan-server --port 6001 --tun iwan-srv \
  --server-ip 198.18.0.1 --subnet 198.18.0.0/16 --dns 114.114.114.114 \
  --users /etc/iwan/users.txt --nat-if eth0
```

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
