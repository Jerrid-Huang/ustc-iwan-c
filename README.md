# ustc-iwan-c

USTC iWAN 校园网 VPN 客户端,用 C11 从 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化,大幅提升吞吐量并减小延迟。

## 特性

- 双入口:
  - `iwan-client` — `ping` / `auth` / `proxy`(TUN 模式)/ `socks`(无 root 的用户态 SOCKS5 代理)
  - `iwan-client-oidc` — OIDC 配置获取与服务器选择(`--fetch` / `--list` / `--connect` / `--all`)
- `iwan-server` — 参考 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 的 Rust 服务器以 C11 实现的轻量 VPN 服务器(单线程轮询、UDP 数据面 ↔ TUN)
- 自研用户态 TCP/IP 协议栈(零拷贝段槽、64KB 窗口 + WSCALE、逐段立即 ACK、自适应 RTO、快速重传、keepalive 探测、GSO 批发送)
- 8B 外层头 + XOR 加密内层 IP 包(整包加密)
- `--ustc` 快捷路由:一条参数展开为 11 条科大校园网 CIDR,配合 `--server` 直接连接(仅 `iwan-client-oidc`)
- **Windows 客户端**(MinGW-w64 交叉编译):`ping` / `auth` / `socks` / OIDC 全功能;`proxy`(TUN)经 wintun 驱动,需管理员 + 安装 [wintun](https://www.wintun.net/);`iwan-server` 保持 Linux-only(依赖 TUN/iptables/BPF)
- **协议已冻结**:线上字节格式(帧布局、帧类型/TLV id、`"mw"` 常量、字节序、vlen+2 怪癖)为与参考实现互操作而固定,完整字节级规范见 [PROTOCOL.md](PROTOCOL.md),`protocol.h` 内有 `_Static_assert` 编译期校验

## 构建

依赖:`cc`(C11)、OpenSSL 头文件与 `libcrypto`、`clang`(仅用于编译 BPF 转向程序 `src/common/steer_bpf.c`)、Linux 内核头文件(`linux-libc-dev`,提供 `linux/bpf.h` 等)。

```sh
make            # 产物在 bin/
make -B         # 强制全量重建
make clean
```

### Windows 交叉编译(Linux 主机)

依赖:`gcc-mingw-w64-x86-64`(posix 线程模型)、`zstd`;OpenSSL 3 使用 MSYS2 ucrt64 开发包(含静态库与头文件),解包到任意目录后用 `OPENSSL_DIR` 指向其 `ucrt64` 根:

```sh
curl -sL https://repo.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-openssl-3.5.1-1-any.pkg.tar.zst -o /tmp/ossl.tar.zst
mkdir -p /tmp/mingw-sysroot && tar --zstd -xf /tmp/ossl.tar.zst -C /tmp/mingw-sysroot

make TARGET=win32 -B CC=x86_64-w64-mingw32-gcc OPENSSL_DIR=/tmp/mingw-sysroot/ucrt64
# 产物:bin/iwan-client.exe、bin/iwan-client-oidc.exe(仅客户端;iwan-server 不构建)
```

MSYS2 的 libcrypto/libssl 是 DLL 导入库:运行时需将 `libcrypto-3-x64.dll`、`libssl-3-x64.dll` 及 mingw 运行库(`libwinpthread-1.dll`、`libssp-0.dll`)与 exe 放在同一目录。TUN 模式还需 `wintun.dll`(与驱动一同安装)并在管理员控制台运行;`socks` / `ping` / `auth` / OIDC 无需管理员。CI(`.github/workflows/build.yml` 的 `win-cross` 任务)自动完成交叉编译 + wine 冒烟 + 与 Linux `iwan-server` 的真实线上握手测试。

### Windows 安装(直接下载,免编译)

1. 从 [Releases](https://github.com/Jerrid-Huang/ustc-iwan-c/releases) 下载 **`iwan-windows-x86_64.zip`**(含两个 exe 与全部运行库 DLL;只下裸 exe 会因缺少 DLL 无法启动)。
2. 解压到任意目录,例如 `C:\iwan`(保持 exe 与 DLL 在同一文件夹):
   ```
   C:\iwan\iwan-client.exe
   C:\iwan\iwan-client-oidc.exe
   C:\iwan\libcrypto-3-x64.dll      (OpenSSL 运行库)
   C:\iwan\libssl-3-x64.dll
   C:\iwan\libwinpthread-1.dll      (mingw 运行库)
   C:\iwan\libssp-0.dll
   ```
3. **TUN 模式需要额外安装 wintun 驱动**(`socks` / `ping` / `auth` / OIDC 模式不需要):
   - 从 [wintun.net](https://www.wintun.net/) 下载安装包(或安装 WireGuard 自带),以管理员运行安装;
   - 把 `wintun.dll` 也放进 `C:\iwan\`(与 exe 同目录)。
4. 使用(在 `C:\iwan` 下打开终端):

   ```bat
   :: 连通性测试(无需管理员)
   iwan-client.exe ping --server <SERVER> --port 6001

   :: SOCKS5 代理,免管理员;应用设置 SOCKS5 127.0.0.1:1080 即可
   iwan-client.exe socks --server <SERVER> --port 6001 --user <USER> --pass <PASS>

   :: 密码从文件读取,避免口令暴露在命令行(文件保持私有)
   iwan-client.exe socks --server <SERVER> --port 6001 --user <USER> --pass-file C:\path\pass.txt

   :: TUN 模式(管理员控制台;需要 wintun)
   iwan-client.exe proxy --server <SERVER> --port 6001 --user <USER> --pass <PASS>

   :: OIDC 登录流程
   iwan-client-oidc.exe --connect
   ```

5. 常见问题:
   - **`wintun.dll not found`**:未安装 wintun 驱动或 DLL 不在 exe 同目录;TUN 模式必须以**管理员**控制台运行。
   - **提示缺少其他 DLL**:确认使用了 zip 包且解压完整,exe 与 4 个运行库 DLL 在同一目录。
   - **防火墙/杀毒提示**:UDP 6001 出站需放行;若拦截请添加允许规则。
   - **64 位**:本项目仅提供 x86_64 构建,不支持 32 位 Windows。

### Windows 原生编译(MSYS2,推荐)

在 Windows 机器上直接用 MSYS2 的 MinGW-w64 工具链编译,无需 Linux:

1. 安装 [MSYS2](https://www.msys2.org/),打开 **UCRT64** 终端;
2. 安装依赖(编译器 + OpenSSL + GNU make 与基础工具):
   ```sh
   pacman -S --needed base-devel mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl make
   ```
3. 编译(在仓库根目录):
   ```sh
   make TARGET=win32 CC=gcc -j8
   # 产物:bin/iwan-client.exe、bin/iwan-client-oidc.exe(iwan-server 不构建)
   ```

要点:

- `CC=gcc` 是必须的:MSYS2 的编译器叫 `gcc`(不是 `cc`,也不是 Linux 交叉场景的 `x86_64-w64-mingw32-gcc`);`cc` 在 MSYS2 中不存在。
- **不需要 `OPENSSL_DIR`**:MSYS2 的 openssl 包装在 gcc 默认搜索路径(`/mingw64/include`、`/mingw64/lib`),`-lssl -lcrypto` 直接命中。
- 必须用 MSYS2 环境自带的 `make`(包名 `make`,GNU make):Makefile 配方使用 `mkdir -p`/`rm -rf`/`od`/`awk` 等 POSIX 工具,`mingw32-make`(cmd shell)无法执行这些配方。
- 在 MSYS2 终端内直接运行产物即可:所有 DLL(`libcrypto-3-x64.dll`、`libssl-3-x64.dll`、`libwinpthread-1.dll`、`libssp-0.dll`)都在 `/mingw64/bin`(已在 PATH)。要脱离 MSYS2 分发/双击运行时,把这些 DLL 拷到 exe 同目录。
- TUN 模式(`proxy`)需安装 [wintun](https://www.wintun.net/) 驱动、`wintun.dll` 放 exe 旁,并在管理员控制台运行;`ping`/`auth`/`socks`/OIDC 无需管理员。
- 也可用 MINGW64 环境(`mingw-w64-x86_64-gcc` + `mingw-w64-x86_64-openssl`),命令不变。
- **不支持 MSVC**:代码使用 GNU 扩展(`__attribute__((may_alias))`)、C11 `stdatomic` 与 GNU make 配方,且依赖 winpthreads;请使用 MinGW-w64 系工具链。

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
- **会话可被劫持**:sid+token 以明文传输且是数据面唯一凭据,重放 OPEN 或嗅探 token 可顶替/重绑定会话。CLOSE 已做源地址绑定,但无法防御嗅探者。**已加固(不改线上格式)**:服务端对 DATA/CLOSE 的 token 猜测按源地址限速(每窗口 4 次,超限静默丢弃)、token 比较改为常数时间(CRYPTO_memcmp)、会话 peer 重绑定要求该源近 1s 内无任何 token 失配(PING/ECHO 的隐式重绑定同样受限);CLOSE 永不重绑定。
- **加固(其余,均不改线上格式)**:客户端对 OPEN_REJECT 也做帧签名校验(原来仅 ACK 路径校验);随机数失败即拒绝启动/连接(不再回退到弱熵混合,弱 nonce/token 即劫持漏洞);客户端在 `socks`/`proxy` 启动时对比服务器下发的网关与所连服务器地址,不一致时告警(可能是伪造 OPEN_ACK,也可能是 NAT 拓扑)。
- OIDC 路径:登录走标准 OIDC(证书与主机名校验、PKCE、state 比对、id_token 签名与 aud/iss/exp 校验);`OIDC_APP_SECRET` 为公开常量,`servers.json` 中 passWord 字段的加密仅为混淆级保护,请保持该文件 0600。HTTPS 传输层已改为进程内 libssl(证书 + 主机名严格校验;Windows 从系统 ROOT 证书库加载信任锚),不再 fork `openssl s_client` 子进程。

## 实现说明

目录结构:`src/common/` 为共享核心(协议、加密、用户态 TCP 栈、SOCKS 层、TUN、路由、CLI/JSON/HTTPS 工具,全部打进 `libiwan_core.a`);`src/oidc/` 为 OIDC 登录流(仅 `iwan-client-oidc` 使用,单向依赖 common);三个可执行入口在 `src/` 顶层。构建系统在 `Makefile`(`build/` 下按 `common/`、`oidc/`、`main/` 分桶存放对象;`steer_bpf_data.c` 由 clang 交叉编译的 BPF 目标生成,运行时按 `classifier`/`license` 节名加载)。

- 用户态 TCP 栈支持重传(RTO 自适应 SRTT/RTTVAR)、快速重传(3 个重复 ACK)、逐段立即 ACK(RFC 1122 的每 2 段 delayed ACK 在 ~2ms RTT 隧道上是纯延迟:重传后 cwnd=1 时每段都要等满窗口,见 netstack.c;早期实现的 delayed-ACK 机制已删除,仅保留立即 ACK)、keepalive(空闲 120s 后开始探测,间隔 30s,连续 3 次无响应即断开;`NS_IDLE_TIMEOUT` / `NS_KEEPALIVE_MS`)、64KB 窗口 + WSCALE=6、FIN 进重传表。
- 发送路径:等长批走 UDP GSO(单 sendmsg 最多 3 段,GSO 单元上限 4096B,见 protocol.h `IWAN_GSO_UNIT_SAFE`),混合批走 sendmmsg;接收路径 recvmmsg(64 槽)+ poll 事件驱动。
- 经源码级审查与本地基准验证,io_uring(multishot / SEND_ZC / provided buffers)、UDP_GRO、SO_ZEROCOPY 均不采用(实测更慢或与段槽存活期冲突,决策注释见 `socks.c` 与 `netstack.c`)。
- 发送限速:客户端 `IWAN_SEND_PACING_PPS` 环境变量控制发送节奏,默认 0 = 关闭(见 util.h);Rust 参考服务器单线程排水有上限,连接它时建议设 300000。
- 服务端对未认证控制面(OPEN/PING/ECHO)按源地址限速,默认 `RATE_OPEN_MAX` 20/s(OPEN)、`RATE_ECHO_MAX` 60/s(PING 与 ECHO 各计各的),可用环境变量 `IWAN_RATE_OPEN_MAX` / `IWAN_RATE_ECHO_MAX` 在启动时覆盖(0-65535,非法值回退默认);超限静默丢弃(仅计数,计入每秒统计行 `ratedrop=`);基准 ping 循环若超过 60/s 会丢包。
- 协议优化均经本地对照基准验证有效(仓库内无消融测试记录,结论来自当时的本地测量,可自行复测)。

## 性能基准

4 组合矩阵实测(本机双服务器 + 客户端,单位 Mbit/s;每格为「1 连接 / 16 连接」聚合吞吐)。测试脚本 `/tmp/r16_test.sh`(`SRV=C|R` 参数化)与 `/tmp/updown_multi.py` 位于 /tmp,属临时文件、不随仓库保存(`updown_multi.py` 已随系统清理丢失,`r16_test.sh` 亦可能随时消失);如需复测请自行重建脚本。

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
