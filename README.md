# ustc-iwan-c

USTC iWAN 校园网 VPN 客户端/服务器，用 C11 从 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化，大幅提升吞吐量并减小延迟。

- **双客户端入口**：
  - `iwan-client` — `ping` / `auth` / `proxy`（TUN 模式）/ `socks`（无 root 的用户态 SOCKS5 代理，同时支持 SOCKS5 与 HTTP 代理握手）
  - `iwan-client-oidc` — OIDC 配置获取与服务器选择（`--fetch` / `--list` / `--connect` / `--all`）
- **`iwan-server`** — 轻量 VPN 服务器（UDP 数据面 ↔ TUN），Linux-only
- 自研用户态 TCP/IP 协议栈（零拷贝段槽、64KB 窗口 + WSCALE、立即 ACK、自适应 RTO、快速重传、keepalive、GSO 批发送）
- 8B 外层头 + XOR 加密内层 IP 包
- **Windows 客户端**（MinGW-w64）：`ping` / `auth` / `socks` / OIDC 全功能；TUN 模式经 wintun 驱动（需管理员）
- **协议已冻结**：线上字节格式与参考实现互操作，完整规范见 [PROTOCOL.md](PROTOCOL.md)

## 快速开始

### 构建（Linux）

依赖：`cmake`（≥3.16）、C11 编译器、OpenSSL 头文件与 `libcrypto`（Debian/Ubuntu 装 `libssl-dev`）。

```sh
cmake -B build
cmake --build build -j      # 产物在 bin/
```

### Windows 安装（免编译）

1. 从 [Releases](https://github.com/Jerrid-Huang/ustc-iwan-c/releases) 下载 `iwan-windows-x86_64.zip`（两个静态 exe，OpenSSL 与运行库已内嵌，无需任何 DLL），解压到 `C:\iwan\`。
2. **TUN 模式**需要 [wintun](https://www.wintun.net/)：下载 `wintun.dll` 放进 exe 同目录，以**管理员**控制台运行（首次自动安装驱动）。`socks` / `ping` / `auth` / OIDC 模式不需要管理员。
3. 使用：

   ```bat
   :: SOCKS5 + HTTP 代理（免管理员），应用设代理 127.0.0.1:1080 即可
   iwan-client.exe socks --server <SERVER> --port 6001 --user <USER> --pass <PASS>

   :: TUN 模式（管理员控制台；需要 wintun）
   iwan-client.exe proxy --server <SERVER> --port 6001 --user <USER> --pass <PASS>

   :: OIDC 登录流程
   iwan-client-oidc.exe --connect
   ```

   密码可从文件读取避免暴露在命令行：`--pass-file <FILE>`（文件保持 0600/私有）。

### 用法示例（Linux）

```sh
# 连通性测试
./bin/iwan-client ping --server <SERVER> --port 6001

# 无 root 的 SOCKS5 代理
./bin/iwan-client socks --server <SERVER> --port 6001 --user <USER> --pass <PASS>

# TUN 模式，代理全部科大校园网（11 条 CIDR）
sudo ./bin/iwan-client-oidc -c --ustc --server <SERVER>

# OIDC：拉取配置 / 列出服务器 / 交互选择连接
./bin/iwan-client-oidc --fetch
./bin/iwan-client-oidc --list
./bin/iwan-client-oidc --connect
```

### 服务器

```sh
# 用户文件：每行 user:pass，必须 chmod 600（否则服务器拒绝启动）
printf 'alice:s3cret-pass\n' | sudo tee /etc/iwan/users.txt
sudo chmod 600 /etc/iwan/users.txt

sudo ./bin/iwan-server --users /etc/iwan/users.txt \
    --port 6001 --tun iwan-srv \
    --server-ip 198.18.0.1 --subnet 198.18.0.0/16 \
    --dns 114.114.114.114 --nat-if eth0
```

需要 root（创建 TUN、写 `ip_forward`、配置 iptables MASQUERADE）。root 启动时自动 fork 并降权到 `--user`（默认 nobody）运行主循环。`--no-tun` 为测试模式（TCP 回显镜像，可无 root 压测隧道吞吐）。

## 安全说明

本项目为与参考实现互操作而复刻其协议，协议层存在固有弱点，部署时须了解：

- **数据面"加密"无机密性**：8 字节静态密钥的重复 XOR，无 IV/无完整性，单包已知明文即可恢复密钥。**不要在隧道内传输高敏感数据**；如需强保密请在承载网层叠加受认证的隧道（如 WireGuard/IPsec）。
- **控制面签名可伪造**：帧签名密钥是源码公开常量；首次连接没有服务器认证，请固定服务器 IP 并在网络层限制 6001/udp 访问。
- **口令可离线爆破**：认证密文为确定性 AES-128-ECB（无盐）。请使用高熵口令，`users.txt` 权限保持 600。
- **会话可被劫持**：sid+token 明文传输。服务端已加固（token 猜测限速、常数时间比较、peer 重绑定门禁、CLOSE 源绑定），但无法防御嗅探者。
- OIDC 路径：登录走标准 OIDC（证书与主机名校验、PKCE、id_token 校验）；`OIDC_APP_SECRET` 为公开常量，`servers.json` 中 passWord 仅为混淆级保护，文件保持 0600。

## 致谢

本项目基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化。

## License

[MIT](LICENSE)
