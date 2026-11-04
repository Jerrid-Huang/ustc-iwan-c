# Panabit iWAN / SD-WAN 客户端协议（linux_sdwand，2026-10-09 包）逆向规格

对 `iWAN-Linux客户端_20261009.zip` 里 `linux_sdwand_x86` 的静态逆向结果。
文件：ELF x86-64 PIE，**未剥离、带 DWARF**，编译自 `/iWan-test/sdwand.c`（1969 行），
BuildID `3e67c56349ea70b408035b085e6a373b06c48e40`，版本串 `linux_sdwand_x86 2026-10-09`。

证据形式：`函数名 @ 指令地址`，源码行号来自 DWARF 行表。
标「未确定」的没有直接证据，不要当规格用。

---

## 0. 传输、进程模型与配置

- 单进程、单 UDP 套接字（`si_udpsock`，`struct sdwan` 偏移 `0x164`），`connect()` 过对端（`peer_connect` @0x5717）。
- 对端 `si_peerip@0x08` / `si_peerport@0x0c`；本端端口不显式绑定。
- 内层 TUN：`si_tunfd@0x168`，`IFF_TUN | IFF_NO_PI`（`movw $0x1001` @0x5c3c、`TUNSETIFF` @0x5c64），无 4 字节 pi 头。
- 配置 `/etc/sdwan/iwan.conf`；`_sdwclnt`（0x18520，size **0x4a0**）在 .bss，无编译期默认值。
- 定时器：`tm_add("sdwclnt_0", 1, sdwclnt_do_timer, ...)`（@0x9336）⇒ **tick = 1 秒**，按 `os_cursec()` 比较。

**两个方向的硬长度上限**：

| 位置 | 上限 | 证据 |
|---|---|---|
| TUN 读入（上行载荷） | **2040 B** | `tun_recv(fd, buf+8, 0x7f8)` @0x912b/0x9152 |
| UDP 收（下行整帧） | **2048 B**，超出被 `recv()` 静默截断（无 `MSG_TRUNC`） | `peer_recvfrom(fd, buf[0x800], 0x800)` @0x8bad |
| 分片片数据 | 2047 B（`fraglen` 11 bit） | 0x82fe |
| 分片重组缓冲 | 4096 B（`fragContent` @0x17520） | `nm -S` |

---

## 1. 帧格式

```
UDP 载荷 = [ 8 字节帧头 ][ 可选 16 字节签名 ][ 负载 ]

struct sdwan_pkthdr {          // 8 B
    uint8  type;
    uint8  encrypt;
    uint16 sid;
    uint32 token;
};
```

- **字节序**：帧头 `sid`/`token` 是**主机序**（x86 小端），发送端用整字 `mov` 直写、**无 `htons`/`htonl`**（0x923e-0x9265）；
  OPENACK 收到后原样回填（0x7df5-0x7e15 不做 `ntohs`）⇒ 线上字节透明，服务端用什么端序回程就是什么端序。
  控制面 TLV 的数值则是**网络序**。分片头同样是主机序。
- **签名**：`sig[16] = MD5(帧头 8 字节 ‖ "mw")`，写偏移 8..23；校验 `memcmp(pkt+8, d, 16)`。
  `"mw"` 是编译进指令的立即数（`movb $0x6d` / `movb $0x77`，0x6c2f/0x6c33），不是 rodata 字符串、不是密钥。
  **TLV 与负载不参与签名**（`md5update` 只喂 8 字节 + 2 字节）。
- 带签名：0x11/0x12/0x16/0x17，负载从偏移 **24** 起；数据帧（0x14/0x18/0x23）与分片帧（0x22/0x24）**无签名**，负载从偏移 **8** 起。

## 2. 类型码

`sdwan_sock_recv_core` @0x899b：`switch (buf[0] - 0x11)`，24 项跳表 @0xc944。

| type | 名 | 负载起点 | 客户端发送 | 客户端接收处理 |
|---|---|---|---|---|
| 0x11 | OPENREJ | 24 | 否 | `sdwan_onOPENREJ` @0x8026（state4 + 验签） |
| 0x12 | OPENACK | 24 | 否 | `sdwan_onOPENACK` @0x7850（state4 + 验签） |
| 0x13 | OPEN | 24 | **是** | 无分支（default，`panic_pkttype++`） |
| 0x14 | DATA | 8 | 是 | `sdwan_onDATA` @0x7784（校验 token/sid，见 §9.1） |
| 0x15 | ECHOREQ | 24 | 是 | 无分支（default） |
| 0x16 | ECHORESP | 24 | 否 | `sdwan_onECHORESP` @0x80ab（state5 + 验签） |
| 0x17 | CLOSE | 24 | 是 | `sdwan_onCLOSE` @0x8186（state5 + 验签） |
| 0x18 | DATA(XOR) | 8 | 是 | `sdwan_onDATA`（**不校验 token/sid**） |
| 0x22 | IPFRAG | 8（16 B ethpkt） | **否** | `sdwan_onIPFRAG` @0x82ad（`r8=0`，无 SR 头） |
| 0x23 | DATA(v6 明文) | 8 | 是 | `sdwan_onDATA`（不校验 token/sid） |
| 0x24 | IPFRAG | 8（16 B ethpkt） | **否** | 同 0x22（同一跳表目标 0x8b0e） |
| 0x28 | SEGRT | **0**（srhdr 即载荷首字节，无 8+16 前缀） | **否** | `sdwan_onSEGRT` @0x87fe |
| 0x19–0x21、0x25–0x27 | 未用 | — | 否 | default |

全二进制没有任何指令写 `type = 0x22/0x24/0x28` ⇒ **分片与 SR 帧只有 S→C 方向**。
收到 DATA/ECHORESP/IPFRAG/SEGRT 都会刷新 `si_ltime`（0x8a74/0x8ad6/0x8b19/0x8b46）。

## 3. 数据面（0x14 / 0x18 / 0x23）

### 3.1 布局

```
+0  type     0x14 明文 IPv4 / 0x18 XOR 后的 IPv4 / 0x23 明文 IPv6
+1  encrypt  0x14、0x23 恒 0；0x18 时 = si_peerencypt
+2  sid      (2 B 主机序)
+4  token    (4 B 主机序)
+8  内层 IP 报文原文（无内层帧头、无填充）
```

### 3.2 上行 `sdwclnt_tun_recv` @0x90f8（sdwand.c:2383-2487）

```
len = tun_recv(tunfd, buf + 8, 0x7f8);        // ≤ 2040
if (len <= 0) return;
stats.tun_rxpkts++;
if (si_state != 5) return;                    // 未建链不转发、不排队
if (buf[8] >> 4 == 6)        { type = 0x23; enc = 0; }                     // IPv6 恒明文
else if (si_peerencypt != 0) { type = 0x18; enc = si_peerencypt; sdwan_encrypt(&si_key, buf+8, len); }
else                         { type = 0x14; enc = 0; }
sid = si_sid; token = si_token;               // 整字直写
peer_sendto(udpsock, buf, len + 8); stats.sock_txpkts++;
```

IPv6 分支**优先于**加密分支，所以加密会话里 IPv6 也是明文（设计如此）。

### 3.3 下行 `sdwan_onDATA` @0x7784（sdwand.c:1672-1685）

```
data = pkt + 8; dlen = len - 8;
if (hdr->type == 0x18) sdwan_encrypt(&si_key, data, dlen);   // 只按 type 判，忽略 encrypt 字节
tun_send(tunfd, data, dlen);                                  // 忽略 write() 返回值
stats.tun_txpkts++;
```

不检查内层 IP 版本、不检查长度合法性；0x14 与 0x23 走完全相同的路径。

### 3.4 `sdwan_encrypt` @0x37a6：8 字节循环异或（不是 AES）

```c
for (n = len / 8; n > 0; n--) { p[0] ^= key->data32[0]; p[1] ^= key->data32[1]; p += 2; }
for (i = 0; i < (len & 7); i++) b[i] ^= key->data8[i];
```

对称（加密 = 解密），只作用于 `pkt+8` 起；8 字节帧头永远明文。

### 3.5 会话密钥 `sdwan_set_key` @0x6b0b（sdwand.c:1345）

```
snprintf(tmp, 0x80, "%s%s", si_user, si_pass);   // 无分隔符直接拼
sys_md5(tmp, n, digest);
si_key = *(uint64_t*)digest;                     // 只取前 8 字节 → ps+0x48
```

调用点在 `sdwclnt_set_peer` @0x6e78 ⇒ 启动时即算好，与 OPENACK 无关。

## 4. OPEN（0x13）与 OPENACK（0x12）

TLV 编码：`[type:1][len:1][value]`，`len = 值长 + 2`；数值项网络序。

### 4.1 OPEN `sdwan_pktopen` @0x71f5（sdwand.c:1533-1617）

头部 `encrypt = si_encrypt`、`sid = 0`、`token = 0`，TLV 顺序固定：

| # | TLV | len | 值 | 条件 |
|---|---|---|---|---|
| 1 | 0x03 | 4 | `htons(si_cfgmtu@0x2a)` | 恒有 |
| 2 | 0x01 | ulen+2 | 用户名原文（无 NUL） | 恒有 |
| 3 | 0x02 | 0x12 | `AES-128-ECB(MD5("mw"‖user), si_pass[0..15])` | 恒有 |
| 4 | 0x08 | 3 | `si_encrypt` | `si_encrypt != 0` |
| 5 | 0x0a | 4 | `htons((si_pipeidx << 15) \| si_pipeid)` | `si_pipeid != 0` |
| 6 | 0x0a | 6 | `sr_path.links[0]` 的 4 字节原样（已是网络序） | `sr_path.cnt != 0` |

- 口令 TLV：`sys_md5("mw"‖user)` → `AES_set_encrypt_key(..., 0x80, ...)` → `AES_encrypt(si_pass, dst)`，单块 ECB，无 IV、无填充、无 MAC。
  `si_pass` 是 `char[32]` 且 `cfg_load` 用 `strncpy` 零填充 ⇒ **口令 <16 字节时密文后部是零填充；>16 字节时只有前 16 字节被发送**（服务端如何比较未确定）。
- 帧长 `L = 48 + ulen + 可选`（24 头 + 4 MTU + (2+ulen) 用户 + 18 口令）。
- `sdwan_sendOPEN` @0x7588：发包后若 `srcrypt.algo != 0` 调 `set_sr_encrypt`（其第二参数在函数体内从未被读取）。

### 4.2 OPENACK `sdwan_onOPENACK` @0x7850（sdwand.c:1701-1831）

前置：`si_state == 4` 且 `sdwan_pktverify(hdr)` 通过，否则只 `panic_pktverify@0x150++`（无日志、不改状态）。

TLV 循环：`while (remain > 0) { t = p[0]; l = p[1]; switch (t) ... p += l; remain -= l; }`
分派范围硬编码为 `t - 3 <= 10`（0x792e-0x7931）⇒ **只处理 0x03–0x0d**，其余落 default：
`len >= 2` 静默忽略，`len <= 1` 走错误路径。**循环不校验 `l <= remain`**（可越界读栈缓冲）。

| TLV | 要求 len | 写入 | 语义 |
|---|---|---|---|
| 0x03 | ==4 | `si_peermtu@0x28 = ntohs(v)` | 内层 MTU |
| 0x04 | ==6 | `si_ip@0x04 = ntohl(v)` | 内层 IPv4（主机序整数） |
| 0x05 | ==0x0a | `si_dns0@0x14`、`si_dns1@0x18`（v 与 v+4） | **DNS 成对，8 字节值** |
| 0x06 | ==6 | `si_gateway@0x10` | 内层网关 |
| 0x08 | ==3 | `si_peerencypt@0x02 = v[0]` | 对端加密标志 |
| 0x09 | ==3 | `si_peerduppkt@0x03 = v[0]` | **死字段（§9.2）** |
| 0x0b | ==0x12 | 16 B → `ipv6_addr@0x1e4`（全 0 跳过） | 隧道 IPv6 地址 |
| 0x0c | ==0x12 | `inet_ntop` → `ipv6_dns_addr@0x234`(64 B)（全 0 跳过） | IPv6 DNS |
| 0x0d | ==0x12 | `inet_ntop` → `ipv6_gateway_addr@0x1f4`(64 B)（全 0 跳过） | IPv6 网关 |
| 其它（含 0x0a、0x0f） | — | 忽略（len≤1 则错误） | — |

成功收尾（0x7deb 起）：`si_state = 5`；`si_sid = hdr->sid`、`si_token = hdr->token`（**原样，不转序**）；
`si_ltime = now`、`si_lastdial = now`（后者是死字段）；`openackcnt++`；
日志 `using ip %s gateway %s mtu %u encrypt %c`（`Y`/`N`），有 IPv6 时再打 `using ipv6 %s gateway %s DNS %s`；
最后 `sdwclnt_set_iproute` @0x6587 ⇒ **接口 MTU = min(si_cfgmtu, si_peermtu)**（0x65ed-0x6618，`cmovbe` + `tun_set_mtu`），只设一次。

失败路径（长度不符或未知 TLV `len<=1`，统一汇到 0x7fc6）：
`log("Invalid packet format in OPENACK, resetting state")` → `sdwclnt_reset_state` → `panic_open@0x154++`。

**ACL 事实**：客户端**没有** 0x0f AUTH/verify/nonce TLV，也没有 challenge、时间戳或序号；
认证 = 口令 TLV（0x02）+ 服务端回 OPENACK（接受）/ OPENREJ（拒绝）的二值判定。

### 4.3 OPENREJ（0x11）`sdwan_onOPENREJ` @0x8026

`si_state == 4` 且验签通过 ⇒ `log("sdwan peer AUTH REJECTED")` → `reset_state` → `openrejcnt++`；
**`len` 与负载完全未使用**，不解析原因码。无退避、无最大重试（`reset_state` 后 state 归 2/3，下个 tick 重新 OPEN）。

## 5. 保活：ECHOREQ（0x15）与 ECHORESP（0x16）

### 5.1 ECHOREQ 60 字节（`sdwan_pktechoreq` @0x761e，sdwand.c:1633-1668）

```
+0   type=0x15, encrypt=0, sid=si_sid, token=si_token          // 8 B，整字直写
+8   16 B 签名
+24  uint64 tick      = os_curusec()（8 B 原样）
+32  uint32 cur_delay = si_curdelay@0x2c
+36  uint32 min_delay = si_mindelay@0x34      ← 注意线上顺序是 cur/min/max
+40  uint32 max_delay = si_maxdelay@0x30
+44  4 字节        未初始化（栈残留，指令流里没有任何 store：0x76b2 写 max，下一条 0x76b9 直接跳到 +0x18）
+48  char   tag[4]    = "SDRT"
+52  uint32 rtmagic   = htonl(si_rtmagic@0x1d0)   // si_rtmagic 全二进制无写入点 ⇒ 恒 0
+56  uint32 cnt       = 0
```

尾部 12 字节是 `struct sdwan_rtpkt { tag[4]; magic; cnt; entry[] }` 的空表形态（`cnt=0`），
它在缓冲区里从 **+0x18** 开始（`add $0x18,%rax` @0x76b9），因此 +44..+47 是结构体里的 4 字节空洞，
客户端把未初始化的栈内容随包发了出去（服务端不应依赖这 4 字节）。

### 5.2 ECHORESP `sdwan_onECHORESP` @0x80ab（sdwand.c:1848-1885）

前置 `si_state == 5` 且验签通过（否则 `panic_pktverify++`）。取 `p = hdr + 24`：

```
cur_delay = (uint32)os_curusec() - *(uint32*)p;   // 只取 tick 低 32 位，微秒
max_delay = max(max_delay, cur_delay); min_delay = min(min_delay, cur_delay);
echorespcnt++;
```

只做单向延时统计；`p+24` 之后的 `SDRT` 表客户端**不解析**。

## 6. CLOSE（0x17）`sdwan_onCLOSE` @0x8186

`si_state == 5` 且验签通过 ⇒ `log("peer recv CLOSE")`、`si_state = 6`、`closedcnt++`。

## 7. 分片（0x22 / 0x24）

### 7.1 布局（全部主机序）

```
+0   sdwan_pkthdr  hdr      [8 B]
+8   uint32        id       // 分片组标识，整字比较，不做字节序转换
+12  uint32        w        // 位域（小端打包）
+16  uint8         data[fraglen]
```

| bit | 宽度 | 字段 | 单位 | 客户端行为 |
|---|---|---|---|---|
| 0 | 1 | `eop` | — | 0 = 非末片（先存槽）；1 = 末片（拼接并投递） |
| 1 | 1 | `fromin` | — | **从不读取**，语义未确定 |
| 2–14 | 13 | `fragoff` | 字节 | 本片在重组缓冲中的偏移 |
| 15–25 | 11 | `fraglen` | 字节 | 本片长度 |
| 26–31 | 6 | `reserved` | — | **从不校验** |

强校验 `len == fraglen + 16`，否则打印 `Invalid fragment size` 丢弃（0x82f1-0x831a）。

### 7.2 重组（`sdwan_onIPFRAG` @0x82ad，sdwand.c:1954-2030）

- 槽数组 `IPfragsArray` @0x12480：**10 个 × 2064 B**；输出缓冲 `fragContent` @0x17520：**4096 B**；`fragTimeOut` @0x12060 = **10 秒**。
- 槽匹配**只看 `id`**（不看 sid/token）；`id == 0` 表示空槽。
- **只支持两片**：`eop == 0` 的片放 `fragContent` 起点并记槽；`eop == 1` 的片放 `fragContent + fragoff`；
  `total = 已存片长 + 本片长`，**无空洞检测、不校验覆盖区间**。
- 投递 `tun_send(fd, fragContent, total)`，返回等于 `total` 才 `tun_txpkts++`；随后释放槽。无空槽打印 `No space for IP fragment`。
- 0x22 与 0x24 在客户端里**完全等价**（同一跳表目标 0x8b0e，`r8=0` 即无 SR 头）。

## 8. SEGRT（0x28）与源路由

### 8.1 头布局

```
+0  uint8  type          // 客户端不校验
+1  uint8  nextid        // 未读取
+2  uint8  linkcnt       // n
+3  uint8  algo:3 | padlen:5
+4  uint32 links[n]      // 客户端从不读取内容
4+4n  内层帧
```

`srhlen = 4 + 4 * linkcnt`（0x881d），**无长度合法性校验**。

**它与其它类型不同：srhdr 直接占据 UDP 载荷的 0 偏移，没有 8 字节 `sdwan_pkthdr`、也没有 16 字节签名。**
分派靠的正是 `srhdr.type`（=0x28）：`sdwan_sock_recv_core` 读 `buf[0]-0x11` 查跳表，命中 0x28 就把
`buf` 原样交给 `sdwan_onSEGRT`。所以「负载起点」不是 24 而是 0；`nextid` 在偏移 1、`linkcnt` 在偏移 2。

### 8.2 三个分支（`sdwan_onSEGRT` @0x87fe，sdwand.c:2033-2092）

```
p = pkt + srhlen;
if (p->type == 0x22 || p->type == 0x24)  → onIPFRAG(ps, p, len - srhlen, p, srhdr)
else if (srcrypt.algo != 0 && srcrypt.algo == (srhdr->byte3 & 7)) {
    sr_decrypt(ps, pkt + srhlen + 8, len - srhlen - 8);      // 内层 = [8B 明文头][AES 密文]
    dlen = len - srhlen; if (padlen) dlen -= padlen;         // padlen 单位 = 字节
    onDATA(ps, p, dlen, p);
} else {
    onDATA(ps, p, len - srhlen, p);
}
```

两种内层封装**不同**：
- 分片分支：内层即 16 B ethpkt + 片数据，**没有内层 8 字节帧头**；AES 作用于拼接后的整包，再扣 `padlen`。
- 非分片分支：内层是完整帧（8 B 头 + 载荷），AES 只作用于头之后，`onDATA` 再按内层 `type` 决定是否 XOR。

顶层 0x22/0x24（不经 SEGRT）传 `srhdr = NULL`，**永不解密**。

### 8.3 SR 密钥派生（`set_sr_encrypt` @0x7015，sdwand.c:1496-1529）

```
h = sr_path.cnt ? jhash(sr_path.links, cnt*4, 0) + jhash(逆序副本, cnt*4, 0) : 0;   // Jenkins lookup3
kbuf = srpassword ‖ (h 的小端字节重复填充) 直到 32 字节
AES_set_decrypt_key(kbuf, algo == 1 ? 128 : 256, &decrypt_key);   // ps+0x3ac
AES_set_encrypt_key(kbuf, algo == 1 ? 128 : 256, &encrypt_key);   // ps+0x2b8
```

`srlinks` 语法是**十进制 u32**（`strtoul(base 10)` → `htonl`，最多 6 项），不是点分十进制；OPEN 的 0x0a(len 6) 直接拷 `links[0]`，故线上是大端 IPv4。
`srcrypt_t`（ps+0x294，524 B）：`algo:1`、`pass[33]`、对齐洞 2、`AES_KEY encrypt_key`(244)、`AES_KEY decrypt_key`(244)。

### 8.4 `sr_decrypt` @0x8207

```
grp = ((srhdr->byte3 & 7) == 1) ? 16 : 32;
if (len % grp) return;                        // 整包放弃解密
for (cur = data; cur < data + len; cur += grp) AES_decrypt(cur, cur, &decrypt_key);   // 单块 ECB 原地
```

`grp = 32` 时每步只解前 16 字节、后 16 字节原样跳过 —— 与 128 位模式不对称，**疑似源码缺陷**。
`padlen`（5 bit）单位是**字节**，最大 31；`len % grp == 0` 要求明文 + 填充凑成整数块。

## 9. 客户端未实现 / 死代码

1. **数据面 token/sid 校验不可达**：判的是 `ps->si_state != 0x14`（0x89ba-0x89c3），而 `si_state` 只会取 0..6
   ⇒ 校验分支恒被跳过，`panic_token` 永不自增，**收方向没有任何认证**（源码缺陷）。即便 0x14 也一样；0x18/0x23 本来就不校验。
2. **`si_peerduppkt`**（ACK TLV 0x09）写入后全二进制无读取 ⇒ 无去重实现。
3. **`si_lastdial@0x3c`** 只写不读（`set_peer` 与 OPENACK 各写一次）⇒ 死字段，OPEN 重发用的是 `si_lastopen@0x38`。
4. **`mbuf_adjmss` @0x8f7d 无调用者**（`sumd_calc` 只被它调用）⇒ 客户端**不做 TCP MSS 钳位**。
5. **`fromin`、`reserved`、`srhdr.type`、`nextid`、`links[]`** 客户端都不读。
6. **`encrypt` 帧头字节**只回填、不解释。
7. **ECHORESP 的 `SDRT` 表**不解析。
8. **`fragContent` 无越界校验**：`fragoff` 最大 8191 而缓冲 4096 B，缓冲末尾正好接 `_sdwclnt`（0x18520）⇒ 恶意分片可覆写全局状态。
9. **`cfg_valid` 失败但 `cfg_load` 仍返回 0**：配置被 `sdwan_clear_cfg` 清空后，`sdwclnt_init` 用空 `tun_name` 调 `tun_init`，
   正常路径下 `tun_init` 失败 ⇒ `sdwclnt_init` 返回 -1 ⇒ main 打 `sdwan client init failed` 后退出
   （0x930e-0x9317、0x9671-0x967b）。只有在 `tun_init` 能接受空接口名时才会退化成 `sdwclnt_not_ready` 永真空转（该前提未验证）。
   同理 `tm_add` 失败也直接返回 -1（0x933b-0x9355）。

## 10. 状态机与定时器（`sdwclnt_do_timer` @0x8c17，tick = 1 s）

| 状态 | 含义 | 行为 |
|---|---|---|
| 0 | 未就绪 | `sdwclnt_not_ready` 为真则直接 return |
| 1 | 已配置待启动 | `sdwclnt_set_peer` 置 1，末尾 `reset_state` |
| 2 | 域名解析 | 解析节流 2 s（`g_last_resolve`）；成功后 `peer_connect` → 3 |
| 3 | 初始化 | 打 `INIT peer %s:%u`；`ltime = now`、`token = 0`、**`lastopen = 0`**、`peerencypt = 0`、state → 4 |
| 4 | AUTH | `now > ltime + 6` ⇒ `panic_authot++` + `AUTH timeout` + reset；否则 `now > lastopen + 2` ⇒ `lastopen = now` + `AUTH start` + `sendOPEN` |
| 5 | RUNNING | `now > ltime + 15` ⇒ 清 token/sid、`panic_dataot++`、`DATA timeout`、reset；否则 `echotimer++`，**偶数 tick 发 ECHOREQ** |
| 6 | CLOSED | reset、``token = 0``、`closedcnt++`、`peer CLOSED` |

- `lastopen = 0` 使进 4 后的第一个 tick 立刻发 OPEN；`lastopen + 2 >= now` 在 +2/+3 秒成立 ⇒ **实际约每 3 秒重发一次**，AUTH 阶段约 6–7 秒、通常只发 2 个 OPEN。
- ECHOREQ 约每 2 秒一次；只要链路上有包刷新 `si_ltime`，15 秒数据超时不会触发。

## 11. 配置（`/etc/sdwan/iwan.conf`）

`cfg_load` @0x4d95（sdwand.c:584-674）：`key=value` 行，`#` 仅行首算注释，行尾 `\r\n` 只裁 1 字节，值可含 `=`；
**含 `[` 与 `]` 的行表示 TUN 接口名**（`strncpy(tun_name@0x16c, name, 0x20)`），键名部分被忽略。

| 键 | 目标 | 解析 |
|---|---|---|
| `server` | `si_peer@0x50` | `strncpy(...,0x40)` |
| `username` | `si_user@0xd0` | `strncpy(...,0x20)` |
| `password` | `si_pass@0xf0` | `strncpy(...,0x20)` |
| `port` | `si_peerport@0x0c` | `(u16)atoi` |
| `mtu` | `si_cfgmtu@0x2a` | `(u16)atoi`，**合法域 46..1600** |
| `encrypt` | `si_encrypt@0x01` | `atoi != 0` |
| `pipeid` | `si_pipeid@0x1c` | `(u16)atoi` |
| `pipeidx` | `si_pipeidx@0x1e` | `(u16)atoi` |
| `srlinks` | `sr_path.cnt@0x278` | `parse_sr_entry`（十进制 u32，≤6 项） |
| `srpassword` | `srcrypt.pass@0x295` | `strncpy(...,0x20)` + 强制 NUL |
| `srencryptmode` | `srcrypt.algo@0x294` | `(u8)atoi`，1 = AES-128，其它 = AES-256 |
| `ipv6_addr` | `0x1e4` | `inet_pton`，**失败则 cfg_load 返回 -1** |
| `ipv6_gateway_addr` | `0x1f4` | `strncpy(...,0x3f)`（存文本） |
| `ipv6_dns_addr` | `0x234` | `strncpy(...,0x3f)`（存文本） |
| `[name]` | `tun_name@0x16c` | `strncpy(...,0x20)` |

`cfg_valid` @0x4a59：tun/peer/user/pass 非空、`46 <= mtu <= 1600`、`port != 0`、`strlen(peer) <= 63`；
`server` 若不是 IPv4 字面量则试 IPv6 字面量，否则当域名写 `si_peerdomain@0x90`。

## 12. 统计字段（`netif_stats`，ps+0x110，84 B）

```
sock_rxpkts(+0x110) sock_txpkts(+0x114) tun_rxpkts(+0x118) tun_txpkts(+0x11c)
txdnscnt(+0x120) rxdnscnt(+0x124) opencnt(+0x128) openackcnt(+0x12c) openrejcnt(+0x130)
echoreqcnt(+0x134) echorespcnt(+0x138) closedcnt(+0x13c)
panic_txdrop(+0x140) panic_pktdest(+0x144) panic_token(+0x148) panic_dns(+0x14c)
panic_pktverify(+0x150) panic_open(+0x154) panic_dataot(+0x158) panic_authot(+0x15c)
panic_pkttype(+0x160)
```

实际会自增的：`sock_rxpkts`、`sock_txpkts`、`tun_rxpkts`、`tun_txpkts`、`openackcnt`、`openrejcnt`、
`echorespcnt`、`closedcnt`、`panic_pktverify`、`panic_open`、`panic_dataot`、`panic_authot`、`panic_pkttype`。
`panic_txdrop`/`panic_pktdest`/`panic_dns` 无引用；`panic_token` 是死分支。

## 13. 与本仓库（ustc-iwan-c）现有实现的差异

1. ACK 的 DNS TLV 是 **0x05、8 字节成对**；本仓库是 4 字节单值。
2. 缺少 ACK TLV **0x09 / 0x0b / 0x0c / 0x0d**。
3. 缺少 OPEN TLV **0x0a**（pipe 与 srlink 两种长度）。
4. 缺少类型 **0x22 / 0x23 / 0x24 / 0x28**。
5. 数据面密钥来源不同：客户端 `MD5(user‖pass)[0..8]`，本仓库由控制面下发 `key[8]`。
6. 帧头 `sid`/`token` 客户端按主机序直写（字节透明），互通时按「服务端原样回显」处理。
7. ECHOREQ 尾部 12 字节 `SDRT` 块本仓库没有。
8. 本仓库的 AUTH verify（nonce）机制客户端**完全没有**：它只认「口令 TLV + ACK/REJ」。

## 14. 未确定项

- `sr_decrypt` 在 AES-256 下「每 32 B 只解 16 B」是否与服务端同构。
- `fromin` 位、0x22 与 0x24 的语义差别（客户端等价处理）。
- `encrypt` 字节 1 与 2 的差别（客户端不解释）。
- 口令 >16 字节时服务端的比较方式；OPENREJ 是否携带原因码。

已定案（原列于此，现已有证据）：

- `SDRT` 路由表的用法：本构建**未实现**——`si_rtmagic` 无写入点（`magic` 恒 0）、`si_rtcfg`/`si_rtmode` 无引用、无 `entry[]` 的收发代码。
- `si_lastdial`：只在 OPENACK 赋值，无读取点（死字段）。
- CLOSE 原因码：客户端不读负载，线上是否带原因**对客户端无影响**。
- `nextid`/`links[]`：客户端不读，仅端点语义。

---

附：中间产物在 `/home/uker/iwan-sys/proto-re/`（全量反汇编 `/tmp/sdwand_x86.dis`、跳表解码脚本、`pahole` 结构 dump）。

## 15. 互通改造清单（针对本仓库 ustc-iwan-c）

已核对：客户端与本仓库的密码加密、会话密钥**完全同源**——
`src/common/crypto.c:155` 的 `encrypt_password` = `AES-128-ECB(MD5("mw"‖user), 零填充口令前 16 字节)`，
`src/common/crypto.c:213` 的 `session_key` = `MD5(user‖pass)`，`src/iwan_client.c:1321` 取其前 8 字节作 `xor_key`。
所以握手与数据面的密码学**不需要改**，差异集中在 TLV 与类型码：

| 差异 | 本仓库位置 | 影响 | 建议 |
|---|---|---|---|
| ACK 的 DNS 只有 4 字节 | `src/common/server.c:1268` `tlv_put(&b, T_DNS, ctx->dns, 4)` | Panabit 客户端要求 `len == 0x0a`（成对 8 字节），否则走 `Invalid packet format in OPENACK` 并 reset | 改成 8 字节（主 + 备）；本仓库客户端的解析是 `vlen < 4` 才报错（`src/common/auth.c:109`），8 字节可兼容 |
| ACK 带 0x0f AUTH_VERIFY | `src/common/server.c:1270` | Panabit 客户端把它当未知 TLV 静默忽略（`len=4 >= 2`） | 无需改；对端若是本仓库客户端则必须保留 |
| OPEN 带 0x0f nonce | `src/common/auth.c:69` | Panabit 服务端未知，行为未验证 | 对 Panabit 服务端可省略 |
| 无 0x22/0x23/0x24/0x28 | 全仓库 | 收不到 IPv6、分片、SR 承载的数据 | 至少补 0x23（IPv6 明文）与 0x22/0x24（分片重组），SR 视需求 |
| OPEN 无 0x0a | `src/common/auth.c:65-69` | pipe/srlink 语义缺失 | 需要管道或源路由时再补 |
| `sid`/`token` 用网络序构造 | `src/common/protocol.c` `pkt_hdr` | 客户端按主机序直写并原样回显，字节透明 | 无需改，保持服务端自洽即可 |

最小可互通集合（Panabit 客户端 ↔ 本仓库服务端）只需两件：**ACK 的 DNS TLV 改成 8 字节**、**服务端不要假设客户端会发 0x0f**。

## 16. 控制面细节补正（第三路分析，均带指令证据）

**16.1 路由安装（`sdwclnt_set_iproute` @0x6587）**

- 隧道地址：`tun_set_ip(tun, si_ip, 255.255.255.0)`——掩码**硬编码 /24**，不来自 ACK（0x65be-0x65e1）。
- MTU：`tun_set_mtu(tun, min(si_cfgmtu, si_peermtu))`（0x65e6-0x6618）；`si_peermtu==0` 时 MTU 变 0，无校验。
- 默认路由：`route_handle(add=1, dst=0, mask=0, gw=si_gateway, metric=0, dev=tun)`（0x661d-0x664f）⇒
  栈上 `struct rtentry`（`memset` 0x78）三处 `AF_INET`、`rt_flags=3`（RTF_UP|RTF_GATEWAY），走 `ioctl(SIOCADDRT)`；
  删除用 `SIOCDELRT`（`sdwclnt_clear_iproute` @0x67d2）。
- **不检查 ioctl 返回值**（仅 socket<0 返回 -1）；**没有 /32 路由、没有按目的地址的转发/黑洞/重定向**，内层全部走默认路由。
- IPv6：`system("ip -6 addr add %s/64 dev %s")`（0x66ae-0x671a），但**没有** `ip -6 route add default`；清除时却会 `ip -6 route del default`。
- `/etc/resolv.conf` 只在 IPv6 DNS 非 0 时改写，且备份逻辑反了：`access("/etc/resolv.conf",0)!=0`（文件**不存在**）才 `cp -f` 到 `.bak`，恢复时再从 `.bak` 拷回。
- `sdwclnt_load_defroute` @0x63e6 解析 `/proc/net/route`，把原默认路由的 `Iface`/`Gateway` 写进 `si_defifname@0x1b0`、`si_defrtnexthop@0x1ac`，
  **这两个字段之后没有任何读取点** ⇒ 原默认路由只记录、从不恢复（客户端也不删除它，可能共存多条默认路由）。

**16.2 时间基准与状态刷新顺序**

- `recv_core` 在分派 0x14/0x18/0x16/0x22/0x24/0x28 **之前**就写 `si_ltime = os_cursec()`（0x8a69/0x8acb/0x8b0e/0x8b3b）；
  0x14 的 token/sid 校验在刷新之前（0x89c1-0x89ea），0x16 的验签在刷新**之后**，0x28 完全不校验。
  ⇒ 伪造的 0x16/0x28（或 0x18/0x22/0x24）可以无限续命，绕过 15 s DATA 超时。
- `si_lastdial@0x3c` 只在 OPENACK 里赋值，全二进制无读取点（死字段）；OPEN 重发只看 `si_lastopen@0x38`。
- `si_echotimer@0x44` 是 1 s 计数而非时间戳，进 state5 时**不重置** ⇒ 首包 ECHOREQ 在 ACK 后 1–2 s 内。
- `tm_scan` @0x456f：`now >= base + interval` 时触发并把 `base = now`（不累加），存在漂移；主循环 `poll(...,1000 ms)`。
- `os_curusec` @0x4169 用 `gettimeofday`（墙钟，非单调）；RTT 只取低 32 位，`2^32 µs ≈ 71.6 min` 回绕。
- 延时初值：`cur=0`、`max=0`、`min=5,000,000 µs`（5 s 哨兵）；三值跨重连保留（只有 `set_peer` 重置）。

**16.3 CLOSE 与统计**

- `onCLOSE` 要求 state==5 + 验签，成功只做 `state=6`、`closedcnt++`、打 `peer recv CLOSE`；**不回包、不解析原因、不重传**。
- 下一个 tick 的 state6 分支再 `reset_state`、`token=0`、`closedcnt++`、打 `peer CLOSED` ⇒ **每个 CLOSE 计 2 次**。
- `reset_state` 只在 `state==5` 时清路由；收到 CLOSE 时状态已是 6 ⇒ **不清 tun 地址与默认路由**。
- 客户端**从不发送 CLOSE**：`sdwclnt_deinit` @0x93b7 只 `tun_deinit` → `clear_iproute` → 关 socket → `tm_del`。
- panic 计数：`panic_token@0x148`、`panic_pktverify@0x150`、`panic_open@0x154`、`panic_dataot@0x158`、`panic_authot@0x15c`、`panic_pkttype@0x160`，只增计数不改流程。

**16.4 SEGRT 的健壮性事实**

- `srhdrlen = 4 + 4*linkcnt`，`linkcnt` 是 u8 ⇒ 最大 1024，**不与 `blen` 比较**，`blen - srhdrlen` 可为负。
- 加密分支要求 `(srhdr.algo & 7) == srcrypt.algo`，否则直接丢；解密起点是 `payload + 8`（内层 8 B 头不加密），
  padlen 按**字节**从总长里减；**明文分支不减 padlen**（若服务端置了 padlen，填充会被当 IP 数据写进 TUN）。
- 客户端既不发 SEGRT、也不读 `nextid`/`links[]`，逐跳处理在服务端/中间节点，客户端只是端点。

**16.5 更正**

- 本文早期版本把 `SDRT` 写在 ECHOREQ 的 +44，实测是 **+48**（+44..+47 是未初始化的 4 字节空洞，见 §5.1）。
- 早期版本把 0x28 的负载起点写成 24，实测 srhdr **从偏移 0 开始**、无头无签名（见 §2 与 §8.1）。

## 17. 配置面、观测面与随包 GUI（第四路分析）

### 17.1 `/etc/sdwan/iwan.conf` 键表（`cfg_load` @0x4d95，sdwand.c:584-673）

解析规则：`fgets(buf, 0x100)`（**行长上限 255**）；跳过空行、长度为 1 的行、`#` 开头、`\r` 开头；只去掉一个尾部 `\r`/`\n`；
**不做任何 lstrip/rstrip**（`key = val` 会失配）；未知键**静默忽略**（`strcmp` 链尾没有 else，直接下一条 `fgets`）；重复键后者覆盖；
`.bss` 中无任何默认值，故 `[name]` 段头、`server`、`username`、`password`、`port`、`mtu` 实际必填。
**没有 `tun=` 这个键**：网卡名只来自 `[iwan0]` 这样的方括号段头（`strchr('[')`/`strrchr(']')`，`strncpy(…,0x20)`）。
`strings` 里能看到的键名只有：`server`、`username`、`password`、`port`、`encrypt`、`pipeid`、`pipeidx`、`srlinks`、`srpassword`、`srencryptmode`、`ipv6_addr`、`ipv6_gateway_addr`、`ipv6_dns_addr`，以及以 `=mtu` 形式参与比较的 `mtu`。

| 键 | 存储 | 校验 | 长度 |
|---|---|---|---|
| `[name]` | `tun_name` char[32] @+0x16c | 仅非空 | `strncpy(…,0x20)`，**无显式补 NUL** |
| `server` | `si_peer` char[64] @+0x50 | 非空且 `strlen <= 63` | `strncpy(…,0x40)`，**无显式补 NUL** |
| `username` | `si_user` char[32] @+0xd0 | 非空 | 同上 0x20 |
| `password` | `si_pass` char[32] @+0xf0 | 非空 | 同上 0x20 |
| `port` | u16 @+0xc | **仅 `!= 0`**，无 ≤65535 校验 | `atoi` 截断 |
| `mtu` | u16 @+0x2a | **`> 45` 且 `<= 1600`**（`cmp ax,0x2d; jbe fail` / `cmp ax,0x640; jbe ok`）⇒ **[46,1600]** | — |
| `encrypt` | u8 @+0x1 | `atoi != 0` ⇒ 归一化为 **1**，无范围 | — |
| `pipeid` / `pipeidx` | u16 @+0x1c / +0x1e | 无校验 | — |
| `srlinks` | `sr_path.cnt`@+0x278、`links[6]`@+0x27c | **不校验**；逗号分隔十进制，最多 6 项 | 每项 `htonl(strtoul(...,10))` |
| `srpassword` | `srcrypt.pass` char[33] @+0x295 | 无（"srencryptmode≠0 时必须"**未实现**） | `strncpy(…,0x20)` |
| `srencryptmode` | `srcrypt.algo` u8 @+0x294 | 无（0/1/2/255 都收） | — |
| `ipv6_addr` | in6_addr @+0x1e4 | **`inet_pton` 失败 ⇒ `cfg_load` 直接 `return -1`** | — |
| `ipv6_gateway_addr` / `ipv6_dns_addr` | char[64] @+0x1f4 / +0x234 | 无 | `strncpy(…,0x3f)` |

**失败链**：`cfg_valid` @0x4a59 只打一行日志（`… INVALID tun name/peer server/username/password/MTU/port`、`… peer too long (%zu chars)`），
`cfg_load` 仍 `return 0`；随后 `sdwan_clear_cfg` @0x6f5d 把 `tun_name` 清零 ⇒ `tun_init("")` 失败 ⇒ `sdwclnt_init` 返回 -1 ⇒
`main` 打 `"sdwan client init failed\n"`、`"Start quit\n"`、`"EXIT\n"`，**最终 `return 0`（退出码 0）**。全程序只有 `daemonize` 的三处失败 `exit(1)`。

### 17.2 观测面：`netif_stats` 是死计数器

`_sdwclnt+0x110`，84 B = 21×u32：`sock_rxpkts/sock_txpkts/tun_rxpkts/tun_txpkts/txdnscnt/rxdnscnt/opencnt/openackcnt/openrejcnt/`
`echoreqcnt/echorespcnt/closedcnt/panic_txdrop/panic_pktdest/panic_token/panic_dns/panic_pktverify/panic_open/`
`panic_dataot/panic_authot/panic_pkttype`。

- **7 个从未递增**：`txdnscnt`、`rxdnscnt`、`opencnt`、`echoreqcnt`、`panic_txdrop`、`panic_pktdest`、`panic_dns`。
- 其余 14 个的读操作**只有 `++` 的 read-modify-write**；**没有任何 printf/log 格式串引用这段内存**，退出时也无汇总。
- 因此客户端的运行状态只能从 `/tmp/iwan.log` 的文本推断，没有计数器可采。

### 17.3 日志与守护化

- 单一日志等级，**无 level/debug 开关、无环境变量、无配置键、无 syslog**；唯一出口 `/tmp/iwan.log`（`fopen(..., "w+")`，**每次启动截断**），
  每条前缀 `"%d/%d/%d %d:%02d:%02d "`，写后 `fflush` + `fsync`；`-f <conf>`、`-l <log>`、`-h`、`-v` 是全部命令行选项（getopt `"f:l:hv"`）。
- `main` **无条件 `daemonize()`（在 `log_init` 之前）**：双 fork、`setsid`、`umask(0)`、关 0/1/2 并重定向到 `/dev/null`、`chdir("/")`。
  ⇒ 没有前台模式；`puts("SD-WAN client started successfully\n")` 写 stdout，**永远看不到**。
- **无 pid 文件**；`SIGINT/SIGTERM/SIGUSR1/SIGUSR2` 共用一个 handler：写 `received signo %d, start to exit` 后置 `_quit=1`，主循环收敛退出；
  `SIGSEGV` 的 handler（`SA_SIGINFO`）**只置 `_quit=1` 就返回**，不重置信号、不 `_exit` ⇒ 故障指令会被反复触发。

### 17.4 `.deb` 与 GUI（`panabit-iwan-client_1.0_amd64.deb`）

包内仅 5 个文件：`./bin/sdwan`（71,936 B，**BuildID 与 `linux_sdwand_x86` 完全相同** `3e67c563…`，节偏移一致，只删了 DWARF）、
`./usr/bin/iwan`（308,704 B Qt5 GUI）、`.desktop`、`changelog.gz`、`app.png`。**无 systemd unit、无 conffiles、无样例配置**；
`postinst`/`postrm` 只刷图标缓存。

- 启动方式固定：`QProcess::startDetached("sudo /bin/sdwan")`（无附加 argv）⇒ 永远用默认 `/etc/sdwan/iwan.conf` 与 `/tmp/iwan.log`。
- 配置是唯一耦合面：GUI 直接读写 `iwan.conf`（`key=` 行替换、缺失则追加），键名与 `cfg_load` 一致；多服务器用 `/etc/sdwan/<name>.conf`，切换时复制到 `iwan.conf`。
- 观测面与 `netif_stats` 无关：日志页读 `/tmp/iwan.log`；流量读 `/proc/net/dev`；存活判定 `ps -ax | grep sdwan`；启动时间 `ps -p %1 -o lstart=`；
  时延 `ping -c 1 -W 1 %1` 并用正则 `time=([\d\.]+)\s*ms` 解析；停止是 `sudo kill -9` + `pkill -9 -P`。
- GUI **不实现协议**：`objdump -T` 的 UND 符号里没有 socket/sendto/recvfrom/bind/connect、没有 MD5/AES、没有 tun/ioctl，全是 Qt 与 libc 基础符号。
- GUI 侧存在 `routeipver` 字符串，但 `cfg_load` 无此键 ⇒ 写了也被静默忽略（其语义未确定）。

### 17.5 使用说明 docx 与实现不一致（摘要）

| # | 文档 | 实现 |
|---|---|---|
| 1 | mtu "建议 1280–1500" | 硬边界 **[46,1600]**，越界判整份配置非法（不是 clamp） |
| 2 | srlinks "必选，1–65535" | 不校验；逗号分隔、最多 6 项、每项 `htonl` |
| 3 | pipeid "0、1–1024" | `atoi`→u16，无校验 |
| 4 | encrypt "0/1" | 任意非零都等于 1 |
| 5 | srencryptmode "0/1" | 任意 u8 都收；GUI 有 AES128/AES256 两项，文档未提 AES256 |
| 6 | `ipv6=` / `gatewayv6=` / `dnsv6=` | 真名 `ipv6_addr` / `ipv6_gateway_addr` / `ipv6_dns_addr`；按文档写会被静默忽略 |
| 7 | `[name]` 是"配置块"分隔 | 不是块分隔符，只是一行写全局 `tun_name` ⇒ **一份配置只能一条隧道** |
| 8 | "未配置时用系统默认值" | 无任何默认值，`port=0`/`mtu=0` 反而非法 |
| 9 | 前台 `sudo /etc/sdwan/linux_sdwand_x86` | 无条件 daemonize，终端无输出 |
| 10 | sudoers 只需 `/bin/sdwan` 与 `/usr/bin/kill` | 还会调 `pkexec`、`sudo ip route …`、`sudo pkill -9 -P …`、`ps`、`ping` |
| 11 | "ifconfig 可看到 iwan0" | tun 名来自 `[name]`，不必然 `iwan0` |
| 12 | `linux_sdwan_arm`、`panabit_client_1.0_amd64.deb` | 实际是 `linux_sdwand_arm`、`panabit-iwan-client_1.0_amd64.deb` |
| 13 | srpassword "srencryptmode≠0 时必须" | 无联动校验 |

**未确定**：GUI 新建服务器时如何拼出 `[iwan0]` 整行（有 `"["`@0x4302ef、`"]"`@0x4303d5、`"iwan0"`@0x4303cf 三个常量，未逐指令确认拼接点）；docx 内 3 张图片未 OCR。

## 18. 生产服务器实测（2026-11-03，`202.38.64.106:6001`）

用官方 `linux_sdwand_x86`（`-f /tmp/iwan.conf`，`LD_PRELOAD` 假 TUN，`strace -e sendto,recvfrom`）抓到的线上字节。

配置（`tun=` 不存在，网卡名来自段头；`mtu` 必填）：`[iwan0] / server=… / username=_rev_m_2 / password=… / port=6001 / mtu=1400 / encrypt=1`。

**OPEN（59 B）**：`13 01 0000 00000000` + 16 B 签名 +
`03 04 0578`（MTU 1400）`01 0a 5f7265765f6d5f32`（用户名）`02 12 <16 B 口令密文>` `08 03 01`（encrypt=1）。
**没有 0x0F**。

**OPEN_ACK（53 B）**：`12 01 0009 e4977730` + 签名 +
`03 04 0578` `04 06 c61203e9`（198.18.3.233）`06 06 64640101`（100.100.1.1）`05 0a 00000000 00000000`（DNS 成对，8 B）`08 03 01`。
⇒ sid=0x0009、tok=0xe4977730，**无 0x0F 回显**。

**ECHOREQ/ECHORESP（各 60 B）**：帧头 `15/16 00`（encrypt 位 **0**）+ 8..23 签名 + 36 B 载荷：
`tick`(LE u64) `cur`(LE u32=0) `min`(LE u32=5,000,000) `max`(LE u32=0) `+20..23 未初始化残值` `"SDRT"` `magic=0` `cnt=0`；服务端原样回显载荷。

**关键互通结论**
- 带 0x0F 的 OPEN 在**这台**服务器上只换回 40 B「最小 ACK」（`01 0a <用户名>` + `0f 06 <nonce>`，sid=0，无地址 TLV），之后 ECHOREQ/DATA 全部无回包 ⇒ 会话根本没有建立；去掉 0x0F 才是官方行为。
- DNS TLV 必须 8 字节（本节 ACK 实测），与 `src/common/server.c` 的发送格式一致。
- ECHO 帧头的 encrypt 位为 0（只有 OPEN/DATA 带协商位）。

**IPv6 三件套在现网的可见性（2026-11-03 复验）**
- 同一台服务器的 ACK 里只有 `0x03/0x04/0x06/0x05/0x08`，**没有 `0x0b/0x0c/0x0d`**；教育网/联通/移动三条线一致，电信 `218.22.21.19:6002` 当日无回包。
- 因此"内层 v6 是否可用"只看 ACK：有 `0x0b` 才有 v6 地址。本仓库客户端已能解析并显示（`AuthResult.tun6/gw6/dns6` + 连接横幅 `IPv6  tun=… gw=… dns=…`，`IWAN_DEBUG=1` 下还有逐条 TLV dump，需 Debug 构建）。
- 复验方法：`/tmp/fake_ack6.py`（最小 OPEN_ACK 假服务端，`length=0x12` 的 `0x0b/0x0c/0x0d`）验证显示路径；生产服务器验证"不下发时无输出"。
