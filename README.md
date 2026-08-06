# ustc-iwan-c

USTC iWAN 校园网 VPN 客户端,用 C11 从 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化,大幅提升吞吐量并减小延迟。

## 特性

- 双入口:
  - `iwan-client` — `ping` / `auth` / `proxy`(TUN 模式)/ `socks`(无 root 的用户态 SOCKS5 代理)
  - `iwan-client-oidc` — OIDC 配置获取与服务器选择(`--fetch` / `--list` / `--connect` / `--all`)
- 自研用户态 TCP/IP 协议栈(零拷贝段槽、64KB 窗口 + WSCALE、delayed ACK、自适应 RTO、快速重传、keepalive 探测、GSO 批发送)
- 8B 外层头 + XOR 加密内层 IP 包(整包加密)
- `--ustc` 快捷路由:一条参数展开为 11 条科大校园网 CIDR,配合 `--server` 直接连接

## 构建

依赖:`cc`(C11)、OpenSSL 头文件与 `libcrypto`。

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
./bin/iwan-client socks --server <SERVER> --port 6001

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

## 实现说明

- 用户态 TCP 栈支持重传(RTO 自适应 SRTT/RTTVAR)、快速重传(3 个重复 ACK)、delayed ACK(40ms flush)、keepalive(120s 探测)、64KB 窗口 + WSCALE=6、FIN 进重传表。
- 发送路径:等长批走 UDP GSO(单 sendmsg 最多 44 段),混合批走 sendmmsg;接收路径 recvmmsg(64 槽)+ poll 事件驱动。
- 经源码级审查与本地基准验证,io_uring(multishot / SEND_ZC / provided buffers)、UDP_GRO、SO_ZEROCOPY 均不采用(实测更慢或与段槽存活期冲突,决策注释见 `socks.c` 与 `netstack.c`)。
- 消融测试确认所有协议优化均有贡献,无冗余可删。

## 致谢

本项目基于 [yyy1mu/ustc-iwan](https://github.com/yyy1mu/ustc-iwan) 重写并优化。

## License

[MIT](LICENSE)
