# eBPF 对照路径（只用于验证"eBPF 出站做不到"，不是产品路径）

生产数据面在 `kernel/iwan_rx.c`（入站 netfilter 解封）与 `kernel/iwan_tx.c`
（出站虚拟网卡 `ndo_start_xmit` 内封装）。本目录只有一条**对照实验**路径：
把出站封装搬到 `LWT_XMIT` 的 eBPF 程序里，用同一个开关（`enc`）证明
**XOR 与"校验和延迟计算"的冲突**才是 eBPF 方案失效的原因。

## 为什么它在 XOR 打开时必然失败

```
本机 TCP → ip_finish_output() → __ip_finish_output()
            ├─ GSO 超包先按 MTU 分段（所以"分片之后"这一点 LWT 是满足的）
            └─ ip_finish_output2()  ← LWT_XMIT 钩子在这里
                   ↓
             validate_xmit_skb()  ← 到这一步才 skb_checksum_help() 算 L4 校验和
                   ↓
             dev_hard_start_xmit() / 驱动
```

LWT_XMIT 的位置在"分段之后"但仍在"算校验和之前"。此时 skb 的
`ip_summed == CHECKSUM_PARTIAL`，校验和字段里放的是伪头部的部分和：

- `enc=0`（不 XOR）：只是加头，校验和照旧由后面算 ⇒ 对端一切正常；
- `enc=1`（XOR，协议要求的语义）：XOR 覆盖了校验和字段，之后算出来的是
  **密文的校验和**；对端解出明文再按明文校验 ⇒ `Tcp InCsumErrors` 增长、
  握手建不起来。

内核模块没有这个问题：`ndo_start_xmit` 在 `validate_xmit_skb()` **之后**被调用，
那时报文已经是"单个完整 IP 包 + 校验和已就绪"，XOR 之后依然自洽。
`kernel/tests/ab_lwt_test.sh` 就是跑这两组对照。

## 构建

```bash
make -C kernel/bpf            # 生成 lwt_encap.o（clang -target bpf）
make -C kernel/bpf insns      # 看指令数
```

没有 libbpf-dev 也能构建：本目录 `bpf/bpf_helpers.h` 是最小垫片，iproute2 的
legacy 加载器自己解析 ELF 并重定位 helper，不需要 libbpf。

## 运行对照实验

```bash
sudo bash kernel/tests/ab_lwt_test.sh
```

它建两个 netns（`iwc`/`iws`）+ veth，**入站仍用内核模块**解封，只是把 `iwc`
到对端内层地址的路由换成带 LWT eBPF 程序的路由：

```bash
ip route add 10.9.0.2/32 dev veth-c encap bpf xmit obj kernel/bpf/lwt_encap.o sec lwt_xmit
```

然后两组对照（`enc` 同时改模块与 map，保证两端语义一致）：

| 组 | `enc` | 期望 | 观察点 |
| --- | --- | --- | --- |
| A | 0（明文） | TCP echo **通过** | 说明封装/路由/解封这一半没问题 |
| B | 1（XOR） | TCP echo **失败** | 服务端 `Tcp InCsumErrors` 增长、`lwt_cnt[5]`（加密发出）增长 |

失败原因被唯一地锁定在 XOR 上，而不是"eBPF 写不了隧道"。

## 入站为什么也不能用 eBPF（顺带记录）

- 外层非首片没有 UDP/iWAN 头 ⇒ 不看完整数据报就匹配不了端口/元组；
- tc/XDP 没有 `ip_defrag()` 那样的重组 API 可用（不是 GPL 导出给 BPF 的），
  而 tc 里手工访问变长/可变偏移的载荷会被验证器拒绝；
- 即使只在"外层不分片"的前提下做 tc 解封（实验室里做过，约 4.4k 指令），
  也等于把"外层永不分片"写进协议前提 —— 参考实现并不提供这个保证。

所以入站留在 netfilter 钩子里：`ip_defrag()` 是导出的内核函数，可以像
`nf_ct_ipv4_gather_frags()` 那样在钩子内联完成重组，非首片返回 `NF_STOLEN`
（skb 交给重组机制），数据报完整的那一次调用里继续解封。

## A/B 实测结论（本机 netns，2026-10）

单变量对照：三组只差"XOR 开关"与"出站位置"。

| 组 | 出站路径 | XOR | 结果 |
|---|---|---|---|
| A | `iwan0` 内核模块（`ndo_start_xmit`） | 有 | 通过，64 KiB echo 一致，`Tcp InCsumErrors +0`、重传 0 |
| B | LWT_XMIT eBPF | 有 | 失败；`lwt_cnt[5]=6`（6 个加密报文发出），服务端 `Tcp InCsumErrors +6` |
| B2 | LWT_XMIT eBPF | 无 | 通过（64 KiB echo 一致），服务端 `InCsumErrors` 增量 0 |

B2 是让对照成立的关键一步：**必须先关掉出口 veth 的 tx 校验和卸载**
（`ethtool -K veth-c tx off`）。原因是位置：`LWT_XMIT` 跑在
`ip_finish_output2()` 里、`validate_xmit_skb()` 之前，此刻内层 TCP 校验和还是
`CHECKSUM_PARTIAL`；出口设备若声称支持校验和卸载（`VETH_FEATURES` 含
`NETIF_F_HW_CSUM`），软件就永远不会去算它，于是**不打开 XOR 也一样失败**
（实测 `rx_delivered +6` 与 `InErrs +6` 严格 1:1，`rx_bad_hdr`/`rx_bad_inner` 全 0
——报文完整解封投递，只是校验和从未被算出来）。关掉卸载把"算校验和"推到钩子
之后，B2 立刻恢复正常，XOR 于是成为唯一变量。

结论：**不是"eBPF 写不了隧道"**——B2 证明封装、重路由、对端解封、端口与凭据
闸门全部可用。失效原因是 XOR 与校验和计算时机的冲突：XOR 在校验和算完之前
执行，把校验和字段一起改了，对端解出明文后按明文校验必然失败。内核模块路径
同时避开这两点，靠的是 iwan0 `features=0` 迫使 `validate_xmit_skb()` 在
`ndo_start_xmit` 之前完成 `skb_checksum_help()`，XOR 才落在已经算好的校验和上。

注意 B 组的 `InCsumErrors +6` 本身**不足以单独证明** XOR 时机问题（位置问题会
造成同样的现象），必须与 B2 合起来看才构成单变量证据。
