# 回程路由：让"从隧道进来的连接"按来路回去（设计决定：用 conntrack）

决定（2026-10-11，用户拍板）：**对端地址事先不可知，所以用 conntrack**。

## 问题

被服务地址（`--proxy-cidr` / `--proxy-ip` / `--proxy-domain` / `--proxy-cidr6`
列出的那些）上有连接从隧道进来时，本机回包走哪张网卡？

Linux 对本机发出的包**只按目的地址查 FIB**，入接口不参与决策，也没有"记住来路"
的机制（IPv4 路由缓存 3.6 起删除，IPv6 从来没有）。于是：

* 对端地址落在已装到 `iwan0` 的前缀内 → 目的路由命中，回包自然走隧道；
* 对端是**任意地址**（反向访问、远端从公网侧发起）→ 命中默认路由，回包从**物理
  网卡**出去，源地址还是被服务地址：对端/中间 NAT 基本直接丢，本机严格
  `rp_filter` 下连入包都会被反向丢掉。

源地址那一半不用操心：回包的源地址由连接四元组锁死（`--restore-mark` 不改变它）。

## 为什么只能靠 conntrack

| 机制 | 粒度 | 适不适用 |
|---|---|---|
| 目的地址路由（现状） | 按目的前缀 | 对端可枚举时才够 |
| `ip rule from <被服务地址>` | 按**源地址** | 覆盖"该地址的回包都走隧道"，但同一地址双路径（本机 LAN 直连 + 隧道）分不开 |
| `ip rule iif <口>` | —— | **对本机发出的包无效**（本机发包 iif 是 lo/未设） |
| `MARK`（非 connmark） | —— | 包标记不跨方向，入包的标记不会出现在回包上 |
| **`CONNMARK` + `ip rule fwmark`** | **按连接** | 唯一能做到"逐连接按来路回"，对端地址不需要预知 |

conntrack 表项是**双向**的：回包 tuple 命中同一条表项，因此能把"入接口"这个
信息从入方向带到出方向。

## 配置

```bash
# 入方向：只标记"从隧道进来的、且目的是被服务地址"的连接
iptables -t mangle -A PREROUTING -i "$TUN_IF" -d "$SERVED_SET" \
         -j CONNMARK --set-mark 0x1
# 出方向：本地生成的回包按表项还原成 packet mark
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
# 按标记选表
ip rule add fwmark 0x1 lookup 100 pref 1000
ip route add default dev iwan0 table 100
# 外层端点必须留在 main 表且优先级更高，否则外层包会被自己的规则送进隧道
ip rule add to "$SERVER_IP" lookup main pref 50
```

nftables 等价（优先用它：一个工具、原子替换）：

```nft
table inet iwan_reply {
  chain pre { type filter hook prerouting priority mangle;
              iifname "$TUN_IF" ip daddr $SERVED_SET ct mark set 0x1 }
  chain out { type filter hook output priority mangle;
              ct mark 0x1 meta mark set 0x1 }
}
```

IPv6 同理（`ip6tables` / `ip -6 rule` / `ip -6 route` 或 `table inet` 里的 `ip6 daddr`）。

## 两个数据面的入接口不一样（关键）

| 数据面 | 内层包进入协议栈时的 `skb->dev` | 规则里的 `-i` |
|---|---|---|
| TUN | `iwan0`（用户态把包写进 TUN，内核按"从 iwan0 收到"处理） | `-i iwan0` |
| kernel | **承载网卡**（模块在 PRE_ROUTING 解封后原地 `NF_ACCEPT`，不改 `skb->dev`） | `-i <承载网卡>` |

* kernel 面的承载网卡**客户端自己是知道的**：`SESSION_UP` 回执里的
  `IWAN_A_CARRIER`（`iwan_ctl get-stats` 的 `carrier=`，日志里 "会话已建立" 也会
  打出承载解析结果）。不绑定时承载只解析一次后钉住，运行期不变，所以规则不需要
  跟着漂。
* **不要**为了让 `-i iwan0` 成立去改 `skb->dev`：那会同时改掉 `rp_filter` 的
  iif 语义与 netfilter 的 `-i` 语义，属于 v4 行为变化（冻结口径要求逐位不变）。
* `-d "$SERVED_SET"` 这一半不能省：`-i <承载网卡>` 会把该网卡上**所有**非隧道
  流量也算进来，只按入接口标记会把本机正常业务连接的回包塞进隧道（服务地址集合
  是已知的，对端地址才是未知的那个）。

## kernel 面的硬前提（否则静默失效）

模块默认钩子是 `PRE_ROUTING` + `hookprio=-300`，即 **defrag 之后、conntrack(-200)
之前**。这个位置正好：解封后 `NF_ACCEPT` 继续沿同一条 PRE_ROUTING 路径往下走，
conntrack 在 -200 看到的是**内层**流，表项正常建立（外层 UDP 流不进表，没有额外
开销）。

若改成 `hooknum=1`（LOCAL_IN 兜底）且 `reinject=N`：外层包早已以"外层 UDP"的
身份走过 conntrack，解封后的 `NF_ACCEPT` 不会再进 PRE_ROUTING ⇒ **内层连接没有
表项** ⇒ 回包 `--restore-mark` 得到 0 ⇒ 规则不命中 ⇒ 回包静默走 main 表。

因此启动时必须**先决检查**并在不满足时**拒绝启动**（不是警告）：

* `hooknum == 0` 且 `hookprio < -200`，或
* `reinject == 1`（重新入栈等效于回到 conntrack 之前）。

参数在 `/sys/module/iwan/parameters/{hooknum,hookprio,reinject}`；不满足时给出的
报错要直接写出该把它设成什么，并把"为什么"（上面这段）带上一行。

## 代价与新失败模式（必须进报告）

* 每报文成本：conntrack 哈希查询 + 入方向 `--set-mark`（每连接首包）+ 出方向
  `--restore-mark`。这条路径正是冻结基准量的那条 ⇒ **默认关闭**，基准/报告必须
  写明 conntrack 的开/关状态（模块参数自描述行抓不到 iptables 状态，要单独记）。
* 新失败模式：`nf_conntrack: table full, dropping packet`（容量），UDP 表项超时
  （`nf_conntrack_udp_timeout` 30s / `_stream` 120s；隧道自己的 keepalive 是 10s，
  不受影响）。模块本身没有这类失败，别把它们混进模块的计数器口径。
* 依赖：netns 内需要 `nf_conntrack` + `xt_connmark`（或 nft 的 `ct mark`）。
  conntrack 表是 **per-netns** 的，每个客户端 netns 各自一份成本。

## 清理与回滚

与现有 `route_teardown` 同一口径：**只回滚自己装的东西**。需要记账并在退出时按
逆序删除：`ip rule`（fwmark 与服务端优先规则各一条，按 pref 精确匹配）、
`table 100` 的默认路由、nft 表（`nft delete table inet iwan_reply`，整表原子）
或 iptables 的两条 mangle 规则。被服务地址集合变化时只增删对应的 `-d` 匹配，
不重建整张表。

## 验收（e2e）

1. **前置断言**：kernel 面在 `hooknum=1 && reinject=N` 时拒绝启动并给出可执行的
   修复提示；默认参数下正常启动。
2. **真往返**：对端地址**不在**任何已装前缀内（用一个只在隧道另一侧存在的地址），
   建立连接 → `conntrack -L` 能看到该连接被标记 → `ip route get <对端> from
   <被服务地址>` 指向 `iwan0`（而不是承载网卡）→ 回包真的到对端。
3. **不误伤**：从同一张承载网卡进来的**非**隧道流量（目的地址不在服务地址集合内）
   的连接**不**被标记，回包仍走 main 表。
4. **回滚**：退出后 `ip rule`/表 100/nft 表都消失，`ip route get` 恢复原样。
5. **两个数据面各跑一遍**（`-i iwan0` 与 `-i <承载网卡>` 两条口径）。

## 已定项（落地值）

* 开关：`--reply-via-tunnel`，**默认关**；给了 `--proxy-cidr*` 也不自动开，
  避免改变现网行为。仅内核面可用，TUN 面显式报错（`-i` 口径不同，不静默忽略）。
* 取值：fwmark `0x1`、路由表 `100`、规则 pref `1000`。
* 服务地址集合：`--proxy-cidr*`/`--proxy-ip`/`--proxy-domain` 展开后的前缀，
  复用 `collect_routes` 已经产出的那份；**一个都没有就拒绝启动**（见上："-d 这一半
  不能省"）。
* `had_routes` 的默认路由劫持同时存在时这套规则是冗余的：装不装都不影响正确性，
  退出时按"自己装过的才删"精确回滚，不碰用户已有的 rule/表。

## 口径：冻结基准里 conntrack 是关的

本特性**默认关**，冻结基准（`tests/bench_proto.sh` 的全部档位）一律不带
`--reply-via-tunnel`。因此：

- 不装 `CONNMARK`/`-j MARK` 规则，也不建 fwmark 策略路由表 100 —— 取数里既
  没有 `nf_conntrack` 的查表成本，也没有第二条路由查找；
- 冻结的 pps/Gbps 数字与"回程路由开不开"无关，**不受本特性影响**；
- 基准脚本自己在口径区把这件事打出来（"回程路由/conntrack = 关"），免得后来者
  对着数字猜当时的环境。

开启后的额外成本（用来解释"开了会慢多少"，不是默认口径）：每个首包多一次
`nf_conntrack` 建表；每个后续包在 `PREROUTING` 与 `OUTPUT` 各多一次 mark 读写
与一次 conntrack 查表；回包侧因 fwmark 命中多一次策略路由查找（未命中仍走主表）。
UDP 的 conntrack 表项有超时（`nf_conntrack_udp_timeout`，默认 30s），长闲置的
UDP 流表项过期后回程规则不再命中 —— 这是本方案对 UDP 的固有代价，TCP 不受影响。
