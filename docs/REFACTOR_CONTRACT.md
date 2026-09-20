# ustc-iwan-c 模块化重构规范与接口契约

本文档为本次大规模解耦与重构的唯一权威契约，所有参与子任务的 subagent 必须严格遵守。

---

## 零号红线（不可逾越）
1. **协议线格式绝对冻结 (Wire Protocol Invariant)**：
   - `protocol.h`、`PT_*` 报文头类型、TLV 编码与内存布局 100% 保持原有格式与字段偏移。
2. **密钥与认证策略语义不变**：
   - Windows DPAPI、macOS Keychain、Linux 0600 明文密码存储行为与回退机制保持不变。
3. **构建门禁与测试必须全绿**：
   - gcc C11 strict/Werror (`build/`)
   - clang C11 strict/Werror (`cl/`)
   - MinGW 交叉编译无警告
   - `ctest` 现有全部测试用例 100% PASS。
4. **零抽象性能损耗**：
   - 热点数据面路径（如 `PT_DATA_ENC`、`sendmmsg`）不得引入多级虚函数表或函数指针开销，保持 `static inline` 或直接链接。

---

## 四大模块划分与接口契约约定

### 模块一：平台抽象层 (PAL: Route, Port, Tun)
- **目标**：消除 `src/common/route.c` 和 `src/common/port.c` 内的大量 `#ifdef`。
- **分支规范**：`refactor/pal`
- **文件拆解契约**：
  1. `route.h` 保持统一接口不变：
     - `int route_setup(const char *dev, const char *server, const char *gw, const struct route_list *routes);`
     - `int route_teardown(const char *dev, const char *server, const char *gw, const struct route_list *routes);`
     - `int capture_default(char *gw, size_t gw_sz, char *dev, size_t dev_sz);`
  2. 实现分文件：
     - `src/common/route_linux.c` (纯 Linux netlink/ip route)
     - `src/common/route_win.c` (纯 Windows IP Helper API)
     - `src/common/route_darwin.c` (纯 macOS scutil/route)
     - `src/common/route_common.c` (通用 CIDR 校验与掩码转换)
  3. `port.c` 细分：
     - `src/common/port_clock.c` (纳秒高精时钟)
     - `src/common/port_sock.c` (套接字补丁与 sendmmsg/recvmmsg 跨平台适配)
     - `src/common/port_proc.c` (跨平台子进程与提权)
     - `src/common/port_sys.c` (CPU 拓扑、休眠与崩溃处理)

---

### 模块二：HTTP 协议栈与安全文件存储 (HTTP & Secure FS)
- **目标**：彻底拆解 2352 行的 `src/common/https.c`，并将 `src/oidc/oidc_config.c` 中的安全落盘逻辑剥离。
- **分支规范**：`refactor/http-secfs`
- **文件拆解契约**：
  1. `https.h` 保留 `https_get`, `https_post`, `https_url_split` 接口保持兼容。
  2. 拆解子文件：
     - `src/common/http_parser.c` & `.h`：纯无 I/O 的 Chunk 解码、HTTP Header 解析、定帧状态机、URL 拆解、字符转义。
     - `src/common/tls_pki.c` & `.h`：跨平台 CA 证书库加载、OpenSSL SSL_CTX 缓存与验证。
     - `src/common/tcp_he.c` & `.h`：Happy Eyeballs 双栈非阻塞连接引擎。
     - `src/common/https.c`：串联上述模块，负责 TLS I/O 与重定向。
  3. 抽离安全存储工具：
     - `src/common/fs_secure.c` & `.h`：提供 `fs_normalize_path()`, `fs_dest_verify()`, `fs_atomic_save()` 等防软链接提权的文件原子落盘能力，供 `oidc_config.c` 调用。

---

### 模块三：SOCKS5 与用户态协议栈 (SOCKS & lwIP Bridge)
- **目标**：拆解 2693 行的 `socks_flow.c` 与 1946 行的 `socks.c`，消灭跨文件裸露的全局变量。
- **分支规范**：`refactor/socks-flow`
- **文件拆解契约**：
  1. 剥离 DNS 解析与工作线程池：
     - `src/common/socks_dns.c` & `.h`：管理隧道内 DNS 解析请求与异步响应环形队列。
  2. 剥离握手与鉴权守卫：
     - `src/common/socks_handshake.c` & `.h`：处理 SOCKS5 greeting, RFC1929 鉴权, HTTP 握手。
     - `src/common/socks_auth_guard.c` & `.h`：处理防暴力破解 IP 封禁。
  3. `socks_flow.c` 聚焦流状态机：
     - 拆分 `service_local_inputs` 为三种状态专用泵，隐藏内部 `g_flows` 数组。
  4. `socks.c` 聚焦主调度循环：
     - 提炼 `socks_poll_build_set` 与 `socks_poll_dispatch`。

---

### 模块四：服务端与本地中继数据面 (Server & Relay Data-Plane)
- **目标**：拆解 3219 行的 `relay_proxy.c` 与 3070 行的 `server.c`，分离控制面与高吞吐数据面。
- **分支规范**：`refactor/server-relay`
- **文件拆解契约**：
  1. `server.c` 拆解：
     - `src/common/server_rate.c` & `.h`：Knuth 哈希两级限流引擎。
     - `src/common/server_proto.c` & `.h`：控制面协议状态机（OPEN/CLOSE/PING 握手）。
     - `src/common/server_mirror.c` & `.h`：No-TUN TCP Echo Mirror 仿真测试反射器。
     - `src/common/server.c`：保留核心数据面调度，`handle_udp` 简化为极薄分发器。
  2. `relay_proxy.c` 拆解：
     - `src/common/rp_proto.c` & `.h`：SOCKS/HTTP 纯协议无锁解析器。
     - `src/common/rp_dns.c` & `.h`：并发 DNS 限流与非阻塞连接建立。
     - `src/common/rp_engine.c` & `.h`：双向流转驱动引擎（Up/Down 线程数据流转）。
     - `src/common/relay_proxy.c`：仅保留服务监听、连接配额与启停生命周期。

---
## 集成规范
各 subagent 在自己的 git 工作分支上完成独立重构并通过 `cmake -B build` 验证后，提交 commit，由专门的集成 subagent 依次合入 `refactor/main`，并执行最终的全量回归与三编译器校验。
