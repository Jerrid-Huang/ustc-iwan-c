# 在 Windows 虚拟机里直接开一个 iWAN 合成会话，用来验证 WFP 数据面。
#
# 为什么要绕过客户端：真正要证的是"内核里封装/解封"这条路径，而不是控制面能跑。
# 这里直接用 IOCTL 开会话，然后做两件事：
#   1) -Inject：从本机构造一个合法的外层 UDP+iWAN 帧，自己发给自己（外层对端就设成
#      本机地址），验证"入向 callout 在协议栈重组之后拦截、解封后注入回网络层"——
#      内层 UDP 载荷能在内层地址的套接字上收到就算走通；反面样本（tok 错）必须收不到。
#      这条测法不依赖宿主：QEMU slirp 不把 guest->host 的 UDP 交给宿主套接字。
#   2) ping：内层 ICMP，需要宿主上有 win_outer_peer.py 回包（那条路依赖 slirp）。
#
# 用法（管理员 PowerShell）：
#   .\vm-rx.ps1 -Inject -PeerIp 10.0.2.15 -PingCount 0
#
# 偏移来自 tests/win_abi_layout.c 的实际输出，不是手算的：
#   SESSION_OPEN 160 字节（ABI 3）：sid@8 tok@12 enc@16 key@17 outer_src@28 outer_dst@32
#     sport@36 dport@38 outer_src6@40 outer_dst6@56 flags@72 oif_index@76
#     bind_ip@80 bind_ip6@84 inner_ip@100 inner_ip6@104 inner_mtu@120
#     carrier_mtu@124 target_offset@128 target_count@132 outer_hop@136
#     outer_if_guid@144（16 字节，全 0 = 按索引挑承载）
#   outer_hop 是外层下一跳（0 = 对端就在链路上）。内核不发路由查询，这一格由
#   控制面在开会话前用 GetBestRoute2 算好；NDIS 平面没有它就发不出外层帧。
#   SESSION_INFO 200 字节：enabled@16 effective_mtu@20 carrier_index@24 dev_owned@28
#     last_rx_ms@40 shm_section_size@48 shm_user_va@56 stats@64（17 个 INT64）
#   TARGET 24 字节：family@0 prefix_len@4 addr@8

param(
    [string]$Adapter  = 'iWAN',
    [string]$InnerIp  = '10.99.0.1',
    [int]   $InnerPfx = 24,
    [string]$Target   = '10.99.0.2',
    [int]   $TargetFamily = 4,
    [string]$PeerIp   = '10.0.2.2',
    [int]   $PeerPort = 45678,
    [string]$Key      = '0102030405060708',
    [int]   $Sid      = 0x1234,
    [long]  $Tok      = 0x12345678,
    [int]   $InnerMtu = 1400,
    [int]   $CarrierMtu = 1500,
    # NDIS 平面（iwanmp.sys）必须显式指定承载网卡索引（不指定就开会话失败），
    # 外层设备名也不同；WFP 平面用默认值。
    [string]$Device   = '\\.\iwan',
    # 两个平面各有自己的服务键（进度标记 RunStage/RunWhat 写在这里）。
    [string]$Service  = 'iwan',
    [int]   $OifIndex = 0,
    [int]   $OuterHop = 0,
    # 承载网卡接口 GUID（如 414E4D50-4957-0000-A456-F83916FBFC14）。
    # 客体实测两套接口索引口径不一致（以太网 netio=7，协议边绑定报 23/26），
    # 按索引挑承载等于猜；给了 GUID 驱动就只按 GUID 匹配。空串 = 退回索引。
    [string]$OuterIfGuid = '',
    [int]   $PingCount = 3,
    [switch]$BindInner,
    [switch]$KeepOpen,
    [switch]$Inject,
# 只开会话、只保持，不跑任何自测。线测/回灌两段默认都挂在 -Inject 下，
# 高速率测量时它们会占住窗口并干扰判定（踩过），所以给一个干净的开关。
[switch]$SkipSelfTest,
# 把驱动的"出向拒绝样本"（共享页 0x100）读出来。计数器只说被拒了几个，
# 说不了为什么 —— 排 UDP 全拒时靠猜浪费过一轮。
[switch]$ShmDump,
    [switch]$Plaintext,
    [string]$InnerDst = '10.99.0.2',
    [int]   $InnerDstPort = 9999,
    [string]$InnerSrc = '10.99.0.1',
    [int]   $InnerSrcPort = 40001,
    [int]   $InjectWaitMs = 1500,
    [int]   $InjectCount = 1,
    [switch]$Wire,
    [int]   $HoldSeconds = 0,
    [switch]$NoInnerIp,
    [switch]$GetOnly
)

$ErrorActionPreference = 'Stop'

# ---------- ABI 常量 ----------
$DevType = 0x8331
function CtlCode([int]$func, [int]$access) {
    # PowerShell 的 -shl 在 Int32 上会溢出成负数：0x83310000 变成 -2093899776，
    # 而 Invoke-Ioctl 的参数是 [uint32]，传参时直接抛“值超出 UInt32”。
    # 全程用 Int64 算完、截断到 32 位再转 UInt32。
    [uint32]((([int64]$DevType -shl 16) -bor ([int64]$access -shl 14) -bor ([int64]$func -shl 2)) -band 0xFFFFFFFFL)
}
$IOCTL_OPEN  = CtlCode 0x800 2      # FILE_WRITE_DATA
$IOCTL_CLOSE = CtlCode 0x801 2
$IOCTL_GET   = CtlCode 0x802 1      # FILE_READ_DATA
$IOCTL_SHM   = CtlCode 0x803 1
$FLAG_BIND_INNER = 0x1

$STAT_NAMES = @('rx_pkts','rx_outer','rx_reasm','rx_frames','rx_delivered','rx_batch',
                'rx_batch_skip','rx_bad_hdr','rx_bad_inner','rx_nomem','rx_ctrl_frame',
                'tx_pkts','tx_bytes','tx_bad_state','tx_bad_inner','tx_err','ev_dropped')

# 进度标记：写进服务注册表键（重启后还在），万一整机卡死，重启后读 RunStage
# 就知道脚本走到哪一步了 —— stdout 会被缓冲，卡死时看不到最后几行。
$RUNKEY = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service"
function Ser([string]$t) {
    # 串口是唯一不经过网络、也不经过本驱动的通道：网络被打死之后，
    # 宿主仍能从串口日志文件看到脚本走到哪一步。任何异常都不许影响主流程。
    try {
        $sp = New-Object System.IO.Ports.SerialPort('COM1', 115200,
            [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One)
        $sp.Open(); $sp.WriteLine($t); $sp.Close()
    } catch { }
}
function Mark([int]$n, [string]$what) {
    Write-Host ("  [mark {0}] {1}" -f $n, $what)
    Ser ("IWAN-MARK {0} {1}" -f $n, $what)
    try {
        New-ItemProperty -Path $RUNKEY -Name RunStage -PropertyType DWord -Value $n -Force | Out-Null
        New-ItemProperty -Path $RUNKEY -Name RunWhat -PropertyType String -Value $what -Force | Out-Null
    } catch { }
}

Add-Type -Namespace IWAN -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share,
    IntPtr sec, uint disp, uint flags, IntPtr templ);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, uint inSize,
    byte[] outBuf, uint outSize, out uint ret, IntPtr ov);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
'@

function Put-Bytes([byte[]]$b, [int]$off, [byte[]]$v) { [Array]::Copy($v, 0, $b, $off, $v.Length) }
function Put-U16([byte[]]$b, [int]$off, [int]$v) {
    $b[$off] = [byte](($v -shr 8) -band 0xFF); $b[$off+1] = [byte]($v -band 0xFF)   # be16
}
function Put-U16Host([byte[]]$b, [int]$off, [int]$v) {
    Put-Bytes $b $off ([BitConverter]::GetBytes([uint16]$v))                        # 主机序
}
function Put-U32Host([byte[]]$b, [int]$off, [long]$v) {
    Put-Bytes $b $off ([BitConverter]::GetBytes([uint32]$v))                        # 主机序
}
function Put-U32Be([byte[]]$b, [int]$off, [long]$v) {
    $b[$off]   = [byte](($v -shr 24) -band 0xFF); $b[$off+1] = [byte](($v -shr 16) -band 0xFF)
    $b[$off+2] = [byte](($v -shr 8) -band 0xFF);  $b[$off+3] = [byte]($v -band 0xFF)  # 大端
}
function Put-Ip4Net([byte[]]$b, [int]$off, [string]$ip) {
    Put-Bytes $b $off ([System.Net.IPAddress]::Parse($ip).GetAddressBytes())         # 网络序
}
function Get-Ip4Net([byte[]]$b, [int]$off) {
    ([System.Net.IPAddress]::new([byte[]]@($b[$off],$b[$off+1],$b[$off+2],$b[$off+3]))).ToString()
}
function Get-I64([byte[]]$b, [int]$off) { [BitConverter]::ToInt64($b, $off) }

function Dump-Stats([byte[]]$info, [string]$tag) {
    # 纯 ASCII 一行，便于宿主侧解析（中文输出经 ssh/重定向会乱码）
    $parts = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $parts += ("{0}={1}" -f $STAT_NAMES[$i], (Get-I64 $info (64 + 8*$i)))
    }
    $line = "STATS {0} {1}" -f $tag, ($parts -join ' ')
    Add-Content -Path C:\iwan\rx-stats.txt -Value $line -Encoding ASCII
    Write-Host $line
}

function Stats-Line([byte[]]$info) {
    $ps = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $v = Get-I64 $info (64 + 8*$i)
        if ($v -ne 0) { $ps += ("{0}={1}" -f $STAT_NAMES[$i], $v) }
    }
    $tail = if ($ps.Count) { $ps -join ' ' } else { '(全 0)' }
    "enabled={0} last_rx_ms={1} {2}" -f [BitConverter]::ToUInt32($info,16), `
        [BitConverter]::ToUInt32($info,40), $tail
}
function Show-Stats([byte[]]$info, [string]$title) {
    Write-Host "`n--- $title ---"
    Write-Host ("enabled={0} effective_mtu={1} carrier_index={2} dev_owned={3} last_rx_ms={4} shm={5}B" -f `
        [BitConverter]::ToUInt32($info,16), [BitConverter]::ToUInt32($info,20), `
        [BitConverter]::ToUInt32($info,24), [BitConverter]::ToUInt32($info,28), `
        [BitConverter]::ToUInt32($info,40), [BitConverter]::ToUInt32($info,48))
    $parts = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $v = Get-I64 $info (64 + 8*$i)
        if ($v -ne 0) { $parts += ("{0}={1}" -f $STAT_NAMES[$i], $v) }
    }
    if ($parts.Count) { Write-Host ("非零计数: " + ($parts -join ' ')) }
    else { Write-Host "非零计数: （全 0）" }
    Ser ("IWAN-STATS[{0}] {1}" -f $title, (Stats-Line $info))
}

function Show-ShmDiag([IntPtr]$h) {
    # 共享页布局见 src/common/iwan_win_abi.h 的 IWAN_WIN_SHM_OFF_DIAG：
    # magic@0 reason@4 len@8 tot@12 pkt0@16 seq@20 first[16]@24
    try {
        $r = Invoke-Ioctl $h $IOCTL_SHM $null 200 'IOCTL_IWAN_SHM_QUERY'
        $va = Get-I64 $r 56
        if ($va -eq 0) { Write-Host 'DIAG 共享页未映射（SHM_QUERY 返回 0）'; return }
        $b = New-Object byte[] 40
        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($va + 0x100), $b, 0, 40)
        $line = ("DIAG magic=0x{0:X8} seq={1} reason={2} len={3} tot={4} pkt0=0x{5:X2} first={6}" -f `
                 [BitConverter]::ToUInt32($b,0), [BitConverter]::ToUInt32($b,20),
                 [BitConverter]::ToUInt32($b,4), [BitConverter]::ToUInt32($b,8),
                 [BitConverter]::ToUInt32($b,12), [BitConverter]::ToUInt32($b,16),
                 [BitConverter]::ToString($b,24,16))
        Write-Host $line
        Ser ("IWAN-" + $line)
    } catch { Write-Host ("DIAG 读取失败: " + $_.Exception.Message) }
}

function Invoke-Ioctl([IntPtr]$h, [uint32]$code, [byte[]]$in, [int]$outSize, [string]$what) {
    $out = New-Object byte[] $outSize
    [uint32]$ret = 0
    $inSize = if ($in) { [uint32]$in.Length } else { [uint32]0 }
    $ok = [IWAN.Native]::DeviceIoControl($h, $code, $in, $inSize, $out, [uint32]$outSize, [ref]$ret, [IntPtr]::Zero)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ("{0} 失败：Win32 错误 {1}（{2}），返回 {3} 字节" -f $what, $err,
               (New-Object System.ComponentModel.Win32Exception($err)).Message, $ret)
    }
    Write-Host ("{0} 成功，返回 {1} 字节" -f $what, $ret)
    return $out
}

# ---------- 造帧：内层 UDP 报文 + 外层 UDP + iWAN 帧头 ----------
# 内层 IPv4/UDP：IP 头校验和算好；UDP 校验和留 0（IPv4 允许不做校验，协议栈照收）。
function Build-InnerUdp([string]$srcIp, [int]$srcPort, [string]$dstIp, [int]$dstPort, [string]$text) {
    $payload = [Text.Encoding]::ASCII.GetBytes($text)
    $len = 20 + 8 + $payload.Length
    $b = New-Object byte[] $len
    $b[0] = 0x45
    $b[2] = [byte](($len -shr 8) -band 0xFF); $b[3] = [byte]($len -band 0xFF)
    $b[8] = 64
    $b[9] = 17
    Put-Ip4Net $b 12 $srcIp
    Put-Ip4Net $b 16 $dstIp
    Put-U16 $b 20 $srcPort
    Put-U16 $b 22 $dstPort
    Put-U16 $b 24 (8 + $payload.Length)
    [Array]::Copy($payload, 0, $b, 28, $payload.Length)
    $sum = 0
    for ($i = 0; $i -lt 20; $i += 2) { $sum += ([int]$b[$i] -shl 8) -bor [int]$b[$i+1] }
    while ($sum -shr 16) { $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
    $sum = (-bnot $sum) -band 0xFFFF
    $b[10] = [byte](($sum -shr 8) -band 0xFF); $b[11] = [byte]($sum -band 0xFF)
    return $b
}

# 外层 = UDP 头 + 8 字节 iWAN 帧头 + [XOR 后的] 内层包。
# 帧头：fh[0]=类型 fh[1]=enc fh[2..3]=sid（大端） fh[4..7]=tok（大端）。
# XOR 只覆盖内层包，从内层偏移 0 起按 key[i & 7] 逐字节异或（与驱动 iwan_win_xor 一致）。
function Build-OuterFrame([byte[]]$inner, [int]$srcPort, [int]$dstPort, [int]$type,
                          [int]$enc, [int]$sid, [long]$tok, [byte[]]$key) {
    $body = New-Object byte[] $inner.Length
    [Array]::Copy($inner, 0, $body, 0, $inner.Length)
    if ($enc) { for ($i = 0; $i -lt $body.Length; $i++) { $body[$i] = $body[$i] -bxor $key[$i % 8] } }
    $fl = 8 + $body.Length          # 帧长（含帧头）
    $total = 8 + $fl                # UDP 头 + 帧
    $f = New-Object byte[] $total
    Put-U16 $f 0 $srcPort
    Put-U16 $f 2 $dstPort
    Put-U16 $f 4 $total
    $f[8] = [byte]$type
    $f[9] = [byte]$enc
    Put-U16 $f 10 $sid
    Put-U32Be $f 12 $tok
    [Array]::Copy($body, 0, $f, 16, $body.Length)
    return $f
}

# 回灌：正面样本（凭据正确）必须让内层载荷出现在 $InnerDst:$InnerDstPort 上；
# 反面样本（tok+1）必须被丢弃 —— 否则说明判定闸门根本没生效。
function Invoke-InjectTest([string]$SrcIp, [int]$SrcPort, [string]$DstIp, [int]$DstPort,
                           [int]$Type, [bool]$Enc, [int]$Sid, [long]$Tok, [byte[]]$Key,
                           [string]$ISrc, [int]$ISrcPort, [string]$IDst, [int]$IDstPort,
                           [int]$WaitMs, [int]$Count = 1) {
    $inner = Build-InnerUdp $ISrc $ISrcPort $IDst $IDstPort 'IWAN-INNER-OK'
    $script:h = $h
    $rx = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $IDstPort))
    $rx.Client.ReceiveTimeout = $WaitMs
    $tx = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($SrcIp), $SrcPort))
    $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($DstIp), $DstPort)
    $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    try {
        $bad = Build-OuterFrame $inner $SrcPort $DstPort $Type $Enc $Sid ($Tok + 1) $Key
        [void]$tx.Send($bad, $bad.Length, $ep)
        Write-Host ("  反面样本已发：{0} 字节（tok+1，应被吞掉）" -f $bad.Length)
        Start-Sleep -Milliseconds 300
        try {
            $d = $rx.Receive([ref]$from)
            Write-Host ("  反面样本竟然交付了内层 {0} 字节 —— 判定闸门失效！" -f $d.Length)
        } catch { Write-Host "  反面样本未交付内层（正确）" }

        $good = Build-OuterFrame $inner $SrcPort $DstPort $Type $Enc $Sid $Tok $Key
        Write-Host ("  正面样本 {0} 字节（{1}:{2} -> {3}:{4}，帧型 0x{5:X2} enc={6}，内层 {7} 字节），发 {8} 次" -f `
            $good.Length, $SrcIp, $SrcPort, $DstIp, $DstPort, $Type, [int]$Enc, $inner.Length, $Count)
        for ($k = 1; $k -le $Count; $k++) {
            [void]$tx.Send($good, $good.Length, $ep)
            if ($k % 5 -eq 0) {
                $st = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(增量)'
                Write-Host ("    已发 {0} 次：rx_reasm={1} rx_batch={2} rx_batch_skip={3} rx_outer={4} rx_delivered={5} rx_bad_hdr={6}" -f `
                    $k, (Get-I64 $st 64+8*2), (Get-I64 $st 64+8*5), (Get-I64 $st 64+8*6), (Get-I64 $st 64+8*1), (Get-I64 $st 64+8*4), (Get-I64 $st 64+8*7))
            }
            Start-Sleep -Milliseconds 60
        }
        try {
            $d = $rx.Receive([ref]$from)
            Write-Host ("  内层已交付：{0} 字节，来自 {1}:{2}，载荷 '{3}'" -f `
                $d.Length, $from.Address, $from.Port, [Text.Encoding]::ASCII.GetString($d))
        } catch { Write-Host "  内层未交付（等超时）—— 入向解封/注入没走通" }
    } finally { $rx.Close(); $tx.Close() }
}

# ---------- 0. 前置检查 ----------
Write-Host "IOCTL: OPEN=$('0x{0:X8}' -f $IOCTL_OPEN) CLOSE=$('0x{0:X8}' -f $IOCTL_CLOSE) GET=$('0x{0:X8}' -f $IOCTL_GET)"

$svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
if (-not $svc) { throw "服务 $Service 不存在：先装载它对应的驱动" }
Write-Host ("服务 {0}: {1}，驱动文件 {2}" -f $Service, $svc.Status, (Get-ItemProperty $RUNKEY -Name ImagePath -ErrorAction SilentlyContinue).ImagePath)

$nic = Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
if (-not $nic) { throw "找不到承载/内层网卡 $Adapter：先跑 vm-net.ps1" }
Write-Host ("网卡 {0}: {1}，ifIndex={2}" -f $Adapter, $nic.Status, $nic.ifIndex)

$have = Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $InnerIp }
if (-not $have) {
    Write-Host "给 $Adapter 配内层地址 $InnerIp/$InnerPfx"
    New-NetIPAddress -InterfaceAlias $Adapter -IPAddress $InnerIp -PrefixLength $InnerPfx | Out-Null
} else { Write-Host "内层地址已存在：$InnerIp/$InnerPfx" }

# 外层源地址：取默认路由那张网卡的地址（对端要能回到它）
$localIp = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 |
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1).IPAddress
if (-not $localIp) { $localIp = (Get-NetIPAddress -AddressFamily IPv4 |
                                Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
                                Select-Object -First 1).IPAddress }
if (-not $localIp) { throw "找不到外层源地址" }
Write-Host "外层源地址：$localIp -> 对端 $PeerIp`:$PeerPort"

# ---------- 1. 拼 SESSION_OPEN + TARGET ----------
$keyBytes = New-Object byte[] 8
for ($i = 0; $i -lt 8; $i++) { $keyBytes[$i] = [Convert]::ToByte($Key.Substring(2*$i, 2), 16) }

$targets = New-Object byte[] 24
Put-U32Host $targets 0 $TargetFamily
Put-U32Host $targets 4 32
Put-Ip4Net  $targets 8 $Target

$req = New-Object byte[] 160
Put-U32Host $req 0  3        # abi_version（ABI 3 起带 outer_if_guid）
Put-U32Host $req 4  160
Put-U16Host $req 8  $Sid    # sid/tok 是主机序字段（地址与端口才是网络序）
Put-U32Host $req 12 $Tok
$req[16] = if ($Plaintext) { 0 } else { 1 }   # enc
Put-Bytes   $req 17 $keyBytes
Put-Ip4Net  $req 28 $localIp                  # outer_src（网络序）
Put-Ip4Net  $req 32 $PeerIp                   # outer_dst
$sportValue = 40000 + ($Sid % 1000)
Put-U16     $req 36 $sportValue               # sport
Put-U16     $req 38 $PeerPort                 # dport
$flags = 0
if ($BindInner) { $flags = $flags -bor $FLAG_BIND_INNER }
Put-U32Host $req 72 $flags
Put-U32Host $req 76 $OifIndex        # oif_index（NDIS 平面必须非 0）
Put-Ip4Net  $req 80 $localIp                  # bind_ip
if ($NoInnerIp) { Write-Host 'inner_ip 留 0（复刻真实客户端内核面：kdp_win 从不填这个字段）' }
else { Put-Ip4Net  $req 100 $InnerIp }          # inner_ip
Put-U32Host $req 120 $InnerMtu
Put-U32Host $req 124 $CarrierMtu
Put-U32Host $req 128 160                      # target_offset
Put-U32Host $req 132 1                        # target_count
Put-U32Host $req 136 $OuterHop                # outer_hop（0 = 对端在链路上）
if ($OuterIfGuid) {
    # .NET 的 Guid.ToByteArray() 就是 Windows 内存里的 GUID 布局
    #（前三段小端、第四段原序），与 ConvertInterfaceLuidToGuid 一致。
    $gb = ([System.Guid]::Parse($OuterIfGuid)).ToByteArray()
    [Array]::Copy($gb, 0, $req, 144, 16)
    Write-Host ("承载 GUID：{0}" -f $OuterIfGuid)
}

$inBuf = New-Object byte[] ($req.Length + $targets.Length)
[Array]::Copy($req, 0, $inBuf, 0, $req.Length)
[Array]::Copy($targets, 0, $inBuf, $req.Length, $targets.Length)
Write-Host ("请求：{0} 字节（结构 160 + 目标 1×24），sid={1} tok={2} 目标 {3}/{4} 外层 {5}:{6}->{7}" -f `
    $inBuf.Length, $Sid, $Tok, $Target, $TargetFamily, $localIp, $sportValue, $PeerPort)

# ---------- 2. 开设备、开会话 ----------
$h = [IWAN.Native]::CreateFileW($Device, [uint32]3221225472, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]::new(-1)) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ("打开 {2} 失败：Win32 错误 {0}（{1}）—— 用管理员身份运行了吗？" -f $err,
           (New-Object System.ComponentModel.Win32Exception($err)).Message, $Device)
}
Write-Host "`n已打开 $Device"

if ($GetOnly) {
    # 只开设备 + 一个无害 IOCTL（GET），绝不走 IOCTL_OPEN：
    # 用来把"CreateFileW/分发"与"wfp_start 注册"分开定位。
    Mark 30 'GetOnly：不建会话，只发 IOCTL_GET'
    $info0 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(无会话)'
    Mark 31 'GetOnly：IOCTL_GET 已返回'
    Write-Host ("无会话时 enabled={0}（预期 0）" -f ([BitConverter]::ToUInt32($info0, 16)))
    Write-Host 'GetOnly 完成，保持设备句柄不关'
    Start-Sleep -Seconds 20
    Write-Host 'GetOnly 结束'
    return
}

try {
    Mark 40 '准备发 IOCTL_IWAN_SESSION_OPEN'
    $null = Invoke-Ioctl $h $IOCTL_OPEN $inBuf 200 'IOCTL_IWAN_SESSION_OPEN'
    Mark 41 'IOCTL_OPEN 已返回'
    Ser 'IWAN-OPEN-RETURNED'
    Mark 42 '准备发 IOCTL_GET'
    $info1 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Mark 43 'IOCTL_GET 已返回'
    Dump-Stats $info1 'after-open'
    Show-Stats $info1 '开会话后'

    if ($Inject -and -not $SkipSelfTest) {
        $encFlag = -not $Plaintext
        $frameType = if ($encFlag) { 0x18 } else { 0x14 }
        Write-Host ("`n--- 入向回灌：本机造帧，{0}:{1} -> {2}:{3}（对端地址 {4}）---" -f `
            $localIp, $PeerPort, $localIp, $sportValue, $PeerIp)
        if ($PeerIp -ne $localIp) {
            Write-Host ("  注意：-PeerIp($PeerIp) 与本机地址($localIp) 不同，帧的源地址不会是会话的外层对端，入向闸门会拒绝它。")
        }
        if (-not $Wire) {
            Mark 44 '准备本机造帧回灌'
            Invoke-InjectTest -SrcIp $localIp -SrcPort $PeerPort -DstIp $localIp -DstPort $sportValue `
                -Type $frameType -Enc $encFlag -Sid $Sid -Tok $Tok -Key $keyBytes `
                -ISrc $InnerSrc -ISrcPort $InnerSrcPort -IDst $InnerDst -IDstPort $InnerDstPort `
                -WaitMs $InjectWaitMs -Count $InjectCount
        }
        if ($Wire) {
            Mark 50 '准备发握手包到宿主'
            # 必须从会话的 sport 发出：slirp 按"宿主侧套接字"记 NAT 映射，
            # 对端把回包发回这个源端口，才会落回本机 40660（= 会话 sport），
            # 否则驱动入向闸门的目的端口对不上。
            $hs = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($localIp), $sportValue))
            $hb = [Text.Encoding]::ASCII.GetBytes('IWAN-HELLO')
            # 先建 NAT 映射：连发几次，确保对端拿到回包地址
            for ($i = 0; $i -lt 3; $i++) {
                [void]$hs.Send($hb, $hb.Length, $PeerIp, $PeerPort)
                Start-Sleep -Milliseconds 200
            }
            Write-Host ("  已从 {0}:{1} 发握手包到 {2}:{3}（对端据此知道回包地址）" -f $localIp, $sportValue, $PeerIp, $PeerPort)
            # 对照：同时从一个临时端口发一个普通 UDP。两者到达情况一比，
            # 就能区分"会话一开、出向 UDP 全废"与"只有外层端口特殊"。
            $ps = New-Object System.Net.Sockets.UdpClient
            $pb = [Text.Encoding]::ASCII.GetBytes('IWAN-PLAIN')
            $pn = $ps.Send($pb, $pb.Length, $PeerIp, $PeerPort)
            Write-Host ("  对照：已从临时端口 {0} 发普通 UDP {1} 字节" -f $ps.Client.LocalEndPoint.Port, $pn)
            $ps.Close()
            # $hs 不能在这里关：下面的重发循环还要用它。关掉的话第一轮 Send 就抛
            # ObjectDisposedException，线测当场中断、线测统计也取不回来（踩过）。
            Mark 51 '握手包已发，等对端回灌'
            # 内层接收端：解封注入的内层包是发往 InnerDst:InnerDstPort 的
            $rxw = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $InnerDstPort))
            $rxw.Client.ReceiveTimeout = 3000
            Write-Host ("  已在内层 {0}:{1} 上监听，等对端回灌..." -f $InnerDst, $InnerDstPort)
            $got = $false
            $fw = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            # 一边继续发 HELLO 保持映射，一边收内层；总窗口 24 秒
            # 同一个套接字（绑在会话 sport 上）既能发也能收：先确认"外层帧到底有没有
            # 到客体"。到不了 -> 线测的通路问题；到得了而内层没交付 -> 驱动入向没拦住。
            $hs.Client.ReceiveTimeout = 1500
            for ($round = 1; $round -le 8 -and -not $got; $round++) {
                try { [void]$hs.Send($hb, $hb.Length, $PeerIp, $PeerPort) } catch { }
                $outer = 0
                $first = '（无）'
                $fwo = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                try {
                    while ($true) {
                        $do = $hs.Receive([ref]$fwo)
                        $outer++
                        if ($outer -eq 1) {
                            $first = ("{0} 字节 来自 {1}:{2}" -f $do.Length, $fwo.Address, $fwo.Port)
                        }
                    }
                } catch { }
                try {
                    $dw = $rxw.Receive([ref]$fw)
                    $got = $true
                    Write-Host ("  内层已交付：{0} 字节，来自 {1}:{2}，载荷 '{3}'" -f `
                        $dw.Length, $fw.Address, $fw.Port, [Text.Encoding]::ASCII.GetString($dw))
                } catch {
                    Write-Host ("  第 {0} 轮：外层到达 {1} 个（首包 {2}）；内层还没到" -f $round, $outer, $first)
                }
            }
            if (-not $got) { Write-Host "  内层始终未交付 —— 入向解封/注入没走通" }
            $rxw.Close()
            $hs.Close()
            Mark 52 '线测等待结束'
            $infoW = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(线测)'
            Mark 53 '线测统计已取回'
            Dump-Stats $infoW 'after-wire'
            Show-Stats $infoW '线测之后'
        }
        Mark 45 '回灌完成，准备取统计'
        $infoI = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
        Mark 46 '统计已取回'
        Show-Stats $infoI '回灌之后'
    }

    if ($PingCount -gt 0) {
        Write-Host "`n--- ping $Target（内层 ICMP，应该被封装后由宿主对端回包）---"
        & ping.exe -4 -n $PingCount -w 2000 $Target
        Write-Host ("ping 退出码 {0}" -f $LASTEXITCODE)
    }

    $info2 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Dump-Stats $info2 'final'
    Show-Stats $info2 '回灌/ping 之后'
    if ($ShmDump) { Show-ShmDiag $h }

    if ($HoldSeconds -gt 0) {
        Mark 60 ("会话保持 {0} 秒（判定：这期间网络是否断、断了之后能否自己恢复）" -f $HoldSeconds)
        $left = $HoldSeconds
        while ($left -gt 0) {
            Start-Sleep -Seconds 5
            $left -= 5
            try {
                $inf = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(保持中)'
                Ser ("IWAN-LIVE t={0}s {1}" -f ($HoldSeconds - $left), (Stats-Line $inf))
            } catch {
                Ser ("IWAN-LIVE IOCTL_GET 失败: " + $_.Exception.Message)
            }
        }
        Mark 61 '保持结束'
        # 保持段里通常才是打流窗口（探针/对端灌帧都在此时发生），必须在它
        # 结束之后再取一次：final 那一行是**流量之前**的快照，拿它当结论会
        # 得出"计数器全零 = 驱动没干活"的错误判断（已经踩过一次）。
        $info3 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
        Dump-Stats $info3 'after-hold'
        Show-Stats $info3 '保持结束之后'
        if ($ShmDump) { Show-ShmDiag $h }
    }
    if (-not $KeepOpen) {
        Mark 47 '准备 CLOSE'
        $null = Invoke-Ioctl $h $IOCTL_CLOSE $null 0 'IOCTL_IWAN_SESSION_CLOSE'
        Mark 48 'CLOSE 已返回'
    } else { Write-Host "`n保持会话打开（-KeepOpen）" }
} finally {
    [void][IWAN.Native]::CloseHandle($h)
    Write-Host "已关闭设备句柄"
}
