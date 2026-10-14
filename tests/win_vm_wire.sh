#!/bin/bash
# Windows 数据面线测（入向：重组后拦截 -> 解封 -> 重组前注入）一键复现。
#
# 用法：tests/win_vm_wire.sh [iwan.sys 路径] [对端窗口秒数] [对端 IP]
#   默认对端 IP = 10.0.2.2（QEMU slirp 网关，见下面的拓扑说明）
#   默认 iwan.sys = /home/uker/iwan-sys/win-driver-x64/build/x64/Release/iwan.sys
#   取件：gh run list --workflow win-driver.yml --branch ci/win-driver-build --limit 1
#         gh run download <id> -D /home/uker/iwan-sys
#         （放在持久路径，别放 /tmp —— 宿主重启会清空）
#   默认窗口 160 s（要大于客体脚本"开会话 + ping + 线测保持"的总时长）
#
# 拓扑（对端用 slirp 网关，不依赖宿主 LAN 地址）：
#   宿主 0.0.0.0:45678（tests/win_wire_peer.py）<- 10.0.2.2 <- QEMU slirp
#        <- 客体 Ethernet 10.0.2.15；客体内 iWAN（KM-TEST 回环）10.99.0.1/24、10.99.0.2/24
#
#   客体发往 10.0.2.2:45678 的 UDP 会被 slirp 直接投给宿主 socket（实测可行），
#   宿主回包的源地址在客体看仍是 10.0.2.2 —— 所以会话 outer_dst 也必须是
#   10.0.2.2，驱动的五元组闸门才对得上。**不要**再用宿主 LAN 地址：宿主一
#   重启，有线网卡地址就没了（enp8s0 DOWN、改走 WiFi），整套线测会静默失效
#   —— 表现是对端 hellos=0（本脚本现在是硬失败，不是警告）。
#
#   客体开一条 iWAN 会话：外层 10.0.2.15:40660 <-> 10.0.2.2:45678，
#   sid 0x1234、tok 0x12345678、key 0102030405060708、enc=1、内层 10.99.0.2/32。
#   客体用户态往对端发 "IWAN-WIRE-HELLO"（不经过驱动，用来让对端知道回谁）；
#   宿主对端 tests/win_wire_peer.py 收到后回灌构造好的外层帧：
#     · 正常帧 ×3/轮  —— 必须被驱动拦下、解封、把内层包重新注入网络层；
#     · 坏凭据帧 ×2    —— 必须被驱动的凭据校验拒绝。
#
# 判据（guest 侧 rx-out.txt 的 STATS 行，全部来自 IOCTL_IWAN_SESSION_GET）：
#   rx_outer     = 命中五元组的外层数据报数（源端口=会话 dport、目的端口=会话 sport）
#   rx_frames    = 其中通过帧头校验（类型/enc/凭据）的数据帧数
#   rx_delivered = 内层包成功注入网络层的次数
#   rx_bad_hdr   = 坏凭据/坏结构样本数 —— 应当恰好等于对端发出的坏样本数（2）
#   通过标准：rx_frames >= 10 且 rx_delivered == rx_frames 且 rx_bad_hdr == 2，
#             且线测结束后 ssh 仍然通（历史上"终止型过滤器写 CONTINUE"就是
#             一建会话全机断网，见 win-driver/iwan_win_wfp.c 的判定注释）。
#
# 踩过的坑（都在这套脚本里被显式处理）：
#   · 必须 -Inject -Wire 同时给：线测整段挂在 if ($Inject) 里面，只给 -Wire 不跑；
#   · 嵌套 ssh -> powershell 会把 -File 脚本参数吃掉，所以客体侧用
#     C:\iwan\vm-wire-run.ps1 这种参数写死的包装脚本；
#   · $-Args 是 PowerShell 自动变量，包装脚本里改名叫 $ScriptArgs；
#   · 客体 C: 曾经 0 字节可用，Add-Type 与 scp 双双静默失败 —— 先看 fsutil；
#   · 串口日志是成串到达的，别拿宿主侧 tail 的时间戳算时序；
#   · 计数器名字必须与所在函数对得上：rx_batch_skip 曾被插进出向 v6 的分类
#     函数里，于是"入向没被调用"这个结论是假的，白绕了一轮；
#   · 注入出来的内层包，在客体防火墙眼里是"凭空出现的入向 UDP"：没有放行
#     规则时会被静默丢掉，而注入 API 仍然返回成功（rx_delivered 照涨）。
#     生产里注入的是被隧道流量的**回应**，状态防火墙会放行；线测里对端灌的
#     是凭空构造的包，所以本脚本临时加一条 UDP 9999 入向放行规则，跑完删掉。
set -u

SYS_PATH="${1:-/home/uker/iwan-sys/win-driver-x64/build/x64/Release/iwan.sys}"
WINDOW="${2:-160}"
PEER_IP="${3:-10.0.2.2}"
PEER_PORT=45678
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/win_vm_wire
mkdir -p "$OUT"

say() { echo "[wire] $*"; }
die() { echo "[wire] 失败：$*" >&2; exit 1; }

[ -f "$SYS_PATH" ] || die "找不到驱动 $SYS_PATH（先 gh run download）"
timeout 15 ssh -o ConnectTimeout=8 -o BatchMode=yes nano11 'echo ok' >/dev/null 2>&1 \
    || die "客体 nano11 不可达（127.0.0.1:2222）"

# 客体侧脚本是这套验证的一半，留在客体上会随环境丢失：顺手归档到 tests/win_vm/
if [ ! -d "$HERE/win_vm" ]; then
    mkdir -p "$HERE/win_vm"
    timeout 120 scp -q 'nano11:C:/iwan/*.ps1' "$HERE/win_vm/" 2>/dev/null \
        && say "已把客体脚本归档到 tests/win_vm/（$(ls -1 "$HERE/win_vm" | wc -l) 个）"
fi

say "换驱动：$SYS_PATH ($(stat -c%s "$SYS_PATH") 字节)"
timeout 60 ssh -o ConnectTimeout=12 nano11 'sc.exe stop iwan' >/dev/null 2>&1
sleep 3
timeout 150 scp -q "$SYS_PATH" 'nano11:C:/iwan/iwan.sys' || die "传驱动失败（客盘满？）"
timeout 200 ssh -o ConnectTimeout=12 nano11 \
    'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-load.ps1 -SysPath C:\iwan\iwan.sys' \
    2>&1 | tr -d '\r' 2>/dev/null | grep -q "State    : Running" || die "驱动没起来（State 不是 Running）"
say "驱动 State: Running"

# 客体侧准备：C: 空间（盘满会让 Add-Type/scp 静默失败）+ 内层包入向放行。
# 这台客体盘一直很紧（16 GB 盘、跑测前约 230 MB 空闲），清理脚本见
# C:\iwan\vm-clean.ps1；再不够就得动 C:\Windows\LiveKernelReports（约 685 MB
# 的内核转储，是之前几次假死留下的证据，删之前先问用户）。
# 只认真实空闲那一行：fsutil 另外还会打总容量、配额空闲、池占用（有 0），
# 按数值大小取最大/最小都会取错（曾经把 16 GB 总容量当空闲放行）。
FREE=$(timeout 60 ssh -o ConnectTimeout=12 nano11 'fsutil volume diskfree C:' 2>/dev/null \
       | tr -d '\r' | grep -iE '^(Total free bytes|总可用字节数)' \
       | grep -oE '[0-9][0-9,]{5,}' | tr -d ',' | head -1)
if [ -n "$FREE" ] && [ "$FREE" -lt 209715200 ]; then
    die "客体 C: 可用空间不足（${FREE} 字节）—— 先清 C:\\Windows\\Temp 等"
fi
say "客体 C: 可用 ${FREE:-未知} 字节"
timeout 60 ssh -o ConnectTimeout=12 nano11 \
    'netsh advfirewall firewall add rule name="iwan-wire-in" dir=in action=allow protocol=UDP localport=9999' \
    >/dev/null 2>&1 && say "已加 UDP 9999 入向放行（跑完删除）"

# 防"空跑"：先把客体上的输出文件删掉，跑完必须重新出现 —— 曾经因为脚本
# 根本没跑（驱动没加载、脚本静默退出）而读到上一次的 rx-out.txt，把陈旧数字
# 当成新结论。
timeout 60 ssh -o ConnectTimeout=12 nano11 \
    'powershell -NoProfile -Command "Remove-Item C:\\iwan\\rx-out.txt -Force -ErrorAction SilentlyContinue"' \
    >/dev/null 2>&1

# 客体包装脚本由本脚本生成并上传：嵌套 ssh -> powershell 会吃掉 -File 脚本的
# 参数，所以参数必须落在客体文件里；而"落在哪里"由这里决定，免得客体上留着
# 上一次的对端 IP（地址变了会变成 hellos=0 的静默空跑）。
# 控制台输出设成 UTF-8：否则宿主抓到的日志里中文全是 '?'（数字与 ASCII 载荷
# 不受影响，但证据可读性差很多）。
printf '\xef\xbb\xbf[Console]::OutputEncoding=[Text.Encoding]::UTF8\r\n& C:\\iwan\\vm-rx.ps1 -Inject -Wire -PeerIp %s -PeerPort %s -PingCount 0 -HoldSeconds 20\r\n' \
    "$PEER_IP" "$PEER_PORT" > "$OUT/vm-wire-run.ps1"
timeout 90 scp -q "$OUT/vm-wire-run.ps1" 'nano11:C:/iwan/vm-wire-run.ps1' \
    || die "上传客体包装脚本失败"
say "客体包装脚本：对端 ${PEER_IP}:${PEER_PORT}"

say "启动宿主对端（窗口 ${WINDOW}s）"
python3 "$HERE/win_wire_peer.py" "$WINDOW" > "$OUT/peer.log" 2>&1 &
PEER=$!
sleep 3

say "运行客体线测（-Inject -Wire，包装脚本见 $OUT/vm-wire-run.ps1）"
timeout $((WINDOW + 60)) ssh -o ConnectTimeout=12 nano11 \
    'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-wire-run.ps1' \
    > "$OUT/guest.log" 2>&1

wait $PEER 2>/dev/null
PEERLINE=$(grep -a "^PEER done" "$OUT/peer.log" || true)
if [ -z "$PEERLINE" ]; then
    die "对端没有打印汇总行（客体脚本很可能根本没跑起来，日志见 $OUT/guest.log）"
fi
say "$PEERLINE"
HELLOS=$(echo "$PEERLINE" | grep -oE 'hellos=[0-9]+' | cut -d= -f2)
[ "${HELLOS:-0}" -gt 0 ] || die "对端一个 HELLO 都没收到：客体侧没发出流量，或对端地址不对（当前 ${PEER_IP}:${PEER_PORT}；客体日志见 $OUT/guest.log）"

# 证据优先取客体落盘的 rx-out.txt；没有就退回控制台日志（内容一样：STATS 行与
# ASCII 载荷都在，中文会因控制台编码丢失，不影响判据）。
EVID="$OUT/rx-out.txt"
timeout 120 scp -q 'nano11:C:/iwan/rx-out.txt' "$EVID" 2>/dev/null || {
    EVID="$OUT/guest.log"
    say "客体没有 rx-out.txt，改从控制台日志取证据（$EVID）"
}

python3 - "$EVID" <<'PY' || exit 1
import re, sys
raw = open(sys.argv[1], 'rb').read()
try:
    txt = raw.decode('utf-8')
except UnicodeDecodeError:
    txt = raw.decode('gbk', 'replace')
txt = txt.replace('\r', '')
stats = {}
for m in re.finditer(r'STATS (\w+) ((?:\w+=\S+ ?)+)', txt):
    tag, body = m.group(1), m.group(2)
    stats[tag] = dict(kv.split('=') for kv in body.split())
final = stats.get('final') or (list(stats.values())[-1] if stats else None)
if not final:
    print('[wire] 失败：rx-out.txt 里没有 STATS 行'); sys.exit(1)
g = lambda k: int(final.get(k, 0))
print('[wire] 最终计数：' + ' '.join('%s=%s' % (k, final[k]) for k in
      ('rx_outer', 'rx_frames', 'rx_delivered', 'rx_batch', 'rx_batch_skip',
       'rx_bad_hdr', 'rx_bad_inner', 'ev_dropped') if k in final))
ok = True
if g('rx_frames') < 10:
    print('[wire] 失败：rx_frames=%d，外层帧没被拦住' % g('rx_frames')); ok = False
if g('rx_delivered') != g('rx_frames'):
    print('[wire] 失败：rx_delivered=%d != rx_frames=%d，有帧没注入成功'
          % (g('rx_delivered'), g('rx_frames'))); ok = False
if g('rx_batch') != 0:
    print('[wire] 失败：rx_batch=%d，有注入在完成回调里被 WFP 退回'
          '（rx_reasm 是失败状态码累加，除以 rx_batch 得原值；'
          '0xC000000D=STATUS_INVALID_PARAMETER 多半是网卡索引/隔离舱给错）' % g('rx_batch'))
    ok = False
if g('rx_bad_hdr') != 2:
    print('[wire] 失败：rx_bad_hdr=%d，坏凭据样本数不对（期望 2）' % g('rx_bad_hdr')); ok = False
if 'IWAN-INNER-OK' in txt or '内层已交付' in txt:
    print('[wire] 附加证据：客体用户态收到了内层载荷 IWAN-INNER-OK')
else:
    print('[wire] 注意：客体用户态没收到内层包。先看 rx_batch/rx_batch_skip/rx_reasm '
          '（注入完成状态诊断：成功/失败各一个计数，失败时 rx_reasm 累加状态码原值）；'
          '若完成是成功的，再排除客体防火墙（本脚本已加 UDP 9999 放行）。')
sys.exit(0 if ok else 1)
PY
RC=$?

timeout 60 ssh -o ConnectTimeout=12 nano11 \
    'netsh advfirewall firewall delete rule name="iwan-wire-in"' >/dev/null 2>&1

timeout 15 ssh -o ConnectTimeout=8 -o BatchMode=yes nano11 'echo ok' >/dev/null 2>&1 \
    && say "线测后网络：通" || { say "线测后网络：不通"; RC=1; }

[ $RC -eq 0 ] && say "通过（证据在 $OUT/）" || say "未通过（证据在 $OUT/）"
exit $RC
