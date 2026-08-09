# ustc-iwan-c

USTC iWAN 校园网 VPN 客户端,用 C11 从 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化,大幅提升吞吐量并减小延迟。

## 特性

- 双入口:
  - `iwan-client` — `ping` / `auth` / `proxy`(TUN 模式)/ `socks`(无 root 的用户态 SOCKS5 代理)
  - `iwan-client-oidc` — OIDC 配置获取与服务器选择(`--fetch` / `--list` / `--connect` / `--all`)
- `iwan-server` — 参考 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 的 Rust 服务器以 C11 实现的轻量 VPN 服务器(单线程轮询、UDP 数据面 ↔ TUN)
- 自研用户态 TCP/IP 协议栈(零拷贝段槽、64KB 窗口 + WSCALE、delayed ACK、自适应 RTO、快速重传、keepalive 探测、GSO 批发送)
- 8B 外层头 + XOR 加密内层 IP 包(整包加密)
- `--ustc` 快捷路由:一条参数展开为 11 条科大校园网 CIDR,配合 `--server` 直接连接(仅 `iwan-client-oidc`)

## 构建

依赖:`cc`(C11)、OpenSSL 头文件与 `libcrypto`、`clang`(仅用于编译 BPF 转向程序 `src/common/steer_bpf.c`)、Linux 内核头文件(`linux-libc-dev`,提供 `linux/bpf.h` 等)。

```sh
make            # 产物在 bin/
make -B         # 强制全量重建
make clean
```

## 用法

```sh
# 连通性
./bin/iwan-client ping --server <SERVER> --port 6001

# 无 root 的 SOCKS5 代理(用户态 TCP 栈)
./bin/iwan-client socks --server <SERVER> --port 6001 --user <USER> --pass <PASS>

# 同上,但密码从 0600 文件读取(避免口令暴露在 /proc/<pid>/cmdline)
./bin/iwan-client socks --server <SERVER> --port 6001 --user <USER> --pass-file ~/.iwan-pass

# TUN 模式,直连指定服务器并代理全部科大校园网
sudo ./bin/iwan-client-oidc -c --ustc --server <SERVER>
```

OIDC 子命令:

```sh
./bin/iwan-client-oidc --fetch                 # 拉取服务器配置
./bin/iwan-client-oidc --list                  # 列出服务器
./bin/iwan-client-oidc --connect               # 交互选择并连接
./bin/iwan-client-oidc --connect --server <NAME|HOST:PORT>
./bin/iwan-client-oidc --connect --ustc        # 科大校园网路由(11 条 CIDR)
```

`auth`/`proxy`/`socks` 三个子命令均支持 `--pass-file <FILE>` 与 `--ct-pass-file <FILE>`(替代明文 `--pass`/`--ct-pass`;优先级:显式 `--pass` > `--pass-file`)。`socks` 额外支持 `--socks-token <TOKEN>`(对本地 SOCKS5 连接启用 RFC 1929 用户/口令认证,密码须等于该 token,防止同机其他用户借用 VPN 会话)与 `--allow-remote`(允许监听非回环地址,默认拒绝)。

## 服务器

```sh
# 用户文件:每行 user:pass,必须 chmod 600(否则服务器拒绝启动)
printf 'alice:s3cret-pass\n' | sudo tee /etc/iwan/users.txt
sudo chmod 600 /etc/iwan/users.txt

sudo ./bin/iwan-server --users /etc/iwan/users.txt \
    --port 6001 --tun iwan-srv \
    --server-ip 198.18.0.1 --subnet 198.18.0.0/16 \
    --dns 114.114.114.114 --nat-if eth0
```

选项:`--port`(6001)、`--tun`(iwan-srv)、`--server-ip`(198.18.0.1)、`--subnet`(198.18.0.0/16)、`--dns`、`--users`、`--nat-if`(eth0)、`--user`(降权用户,默认 nobody)、`--no-tun`(测试用,跳过 TUN 设备)。

需要 root(创建 TUN、写 `ip_forward`、配置 iptables MASQUERADE;后两项失败仅告警)。**root 启动时,服务器在完成 TUN/NAT/socket 配置后自动 fork 并降权到 `--user` 指定的非特权用户运行主循环**,root 父进程仅保留至退出时恢复 `ip_forward` 与移除 NAT 规则。用户文件若 group/world 可读将拒绝启动(口令明文,设置环境变量 `IWAN_ALLOW_INSECURE_USERS=1` 可显式覆盖)。客户端直接连接:`./bin/iwan-client socks --server <SERVER_IP> --port 6001 --user <USER> --pass <PASS>`。

## 安全说明

本项目为与参考实现互操作而复刻其协议,协议层存在固有弱点,部署时须了解:

- **数据面"加密"无机密性**:载荷为 8 字节静态密钥(派生自 `md5(user+pass)`)的重复 XOR,无 IV/无完整性。单包已知明文即可恢复密钥,任何能嗅探 6001/udp 的人可解密全部隧道流量并可比特翻转篡改。**不要在 VPN 隧道内传输高敏感数据**;如需强保密,请在承载网层叠加受认证的隧道(如 WireGuard/IPsec)。
- **控制面签名可伪造**:帧签名 `md5(8字节头+"mw")` 的"密钥"是源码公开常量,且不覆盖 TLV 载荷。客户端无法认证服务器,在线攻击者可伪造 OPEN_ACK(下发任意 IP/DNS/网关)或伪造 CLOSE 终止会话。**首次连接没有服务器认证**,请固定服务器 IP 并在网络层限制 6001/udp 的访问来源。
- **口令可离线爆破**:认证密文为确定性 AES-128-ECB(无盐),嗅探一次 OPEN 即可离线字典攻击;服务器必须持有明文口令(协议要求)。请使用高熵口令,并确保 `users.txt` 权限为 600。
- **会话可被劫持**:sid+token 以明文传输且是数据面唯一凭据,重放 OPEN 或嗅探 token 可顶替/重绑定会话。CLOSE 已做源地址绑定,但无法防御嗅探者。
- OIDC 路径:登录走标准 OIDC(证书与主机名校验、PKCE、state 比对、id_token 签名与 aud/iss/exp 校验);`OIDC_APP_SECRET` 为公开常量,`servers.json` 中 passWord 字段的加密仅为混淆级保护,请保持该文件 0600。

## 实现说明

目录结构:`src/common/` 为共享核心(协议、加密、用户态 TCP 栈、SOCKS 层、TUN、路由、CLI/JSON/HTTPS 工具,全部打进 `libiwan_core.a`);`src/oidc/` 为 OIDC 登录流(仅 `iwan-client-oidc` 使用,单向依赖 common);三个可执行入口在 `src/` 顶层。构建系统在 `Makefile`(`build/` 下按 `common/`、`oidc/`、`main/` 分桶存放对象;`steer_bpf_data.c` 由 clang 交叉编译的 BPF 目标生成,运行时按 `classifier`/`license` 节名加载)。

- 用户态 TCP 栈支持重传(RTO 自适应 SRTT/RTTVAR)、快速重传(3 个重复 ACK)、delayed ACK(40ms flush)、keepalive(120s 探测)、64KB 窗口 + WSCALE=6、FIN 进重传表。
- 发送路径:等长批走 UDP GSO(单 sendmsg 最多 44 段),混合批走 sendmmsg;接收路径 recvmmsg(64 槽)+ poll 事件驱动。
- 经源码级审查与本地基准验证,io_uring(multishot / SEND_ZC / provided buffers)、UDP_GRO、SO_ZEROCOPY 均不采用(实测更慢或与段槽存活期冲突,决策注释见 `socks.c` 与 `netstack.c`)。
- 消融测试确认所有协议优化均有贡献,无冗余可删。

## 性能基准

4 组合矩阵实测(本机双服务器 + 客户端,单位 Mbit/s;每格为「1 连接 / 16 连接」聚合吞吐)。测试脚本 `/tmp/r16_test.sh`(`SRV=C|R` 参数化)与 `/tmp/updown_multi.py`。

| 客户端 \\ 服务器 | C 服务器 | R 服务器(Rust 原版) |
|---|---|---|
| **C 客户端** | socks5: DL 1798 / 2251, UL 1219 / 142<br>TUN: DL N/A, UL 973 / 1551 | socks5: DL 0.11 / 0.12, UL 7 / 18<br>TUN: DL N/A, UL 920 / 437 |
| **R 客户端** | socks5: DL 77 / 59, UL 12 / 165<br>TUN: DL N/A, UL 46 / 501 | socks5: DL 0.52 / 0.68, UL 8 / 23<br>TUN: DL N/A, UL 22 / 40 |

- 载荷:C 服务器 DL 64MiB/连接,其余 4MiB/连接;R 服务器 DL 1MiB/连接(其单线程瓶颈,大载荷需数小时)。
- TUN DL 单机环境不可测:回程包目标(客户端内网 IP)命中宿主机 local 表本机交付,不穿越隧道(服务器 tun TX 计数为零为证)。
- R 服务器瓶颈为「主循环每轮仅 1 包」:吞吐 ≈ 包大小 × 轮询速率——socks 小包(1470B)7 Mbit/s,TUN 模式 GSO 大包 920 Mbit/s,C 服务器无此限制(多队列)。
- 网络路径:全部流量经真实 TUN/UDP 隧道;UFW INPUT 需放行服务器 tun(`iptables -I INPUT -i iwan-srv-c -j ACCEPT`),转发路径需 `accept_local=1` + fwmark 转向。

## 致谢

本项目基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化。

## License

[MIT](LICENSE)
