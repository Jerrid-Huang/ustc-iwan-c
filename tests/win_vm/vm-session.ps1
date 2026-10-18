# 在 Windows 虚拟机里直接开一个 iWAN 合成会话，用来验证 WFP 数据面。
#
# 为什么要绕过客户端：真正要证的是"内核里封装/解封"这条路径，而不是控制面能跑。
# 这里直接用 IOCTL 开会话（外层对端指向宿主上的 win_outer_peer.py），然后在虚拟机
# 里 ping 一个被代理目标 —— 如果驱动的出向 callout 吸收了内层包、宿主收到合法的
# 外层包并回包、驱动的入向 callout 解封后注入协议栈，ping 就会通。
#
# 用法（管理员 PowerShell）：
#   .\vm-session.ps1 -PeerIp 10.0.2.2 -PeerPort 45678 -Target 10.99.0.2
#
# 偏移来自 tests/win_abi_layout.c 的实际输出，不是手算的：
#   SESSION_OPEN 136 字节：sid@8 tok@12 enc@16 key@17 outer_src@28 outer_dst@32
#     sport@36 dport@38 outer_src6@40 outer_dst6@56 flags@72 oif_index@76
#     bind_ip@80 bind_ip6@84 inner_ip@100 inner_ip6@104 inner_mtu@120
#     carrier_mtu@124 target_offset@128 target_count@132
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
    [int]   $PingCount = 3,
    [switch]$BindInner,
    [switch]$KeepOpen
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
function Put-U32Host([byte[]]$b, [int]$off, [long]$v) {
    Put-Bytes $b $off ([BitConverter]::GetBytes([uint32]$v))                        # 主机序
}
function Put-Ip4Net([byte[]]$b, [int]$off, [string]$ip) {
    Put-Bytes $b $off ([System.Net.IPAddress]::Parse($ip).GetAddressBytes())         # 网络序
}
function Get-Ip4Net([byte[]]$b, [int]$off) {
    ([System.Net.IPAddress]::new([byte[]]@($b[$off],$b[$off+1],$b[$off+2],$b[$off+3]))).ToString()
}
function Get-I64([byte[]]$b, [int]$off) { [BitConverter]::ToInt64($b, $off) }

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

# ---------- 0. 前置检查 ----------
Write-Host "IOCTL: OPEN=$('0x{0:X8}' -f $IOCTL_OPEN) CLOSE=$('0x{0:X8}' -f $IOCTL_CLOSE) GET=$('0x{0:X8}' -f $IOCTL_GET)"

$svc = Get-Service -Name iwan -ErrorAction SilentlyContinue
if (-not $svc) { throw "服务 iwan 不存在：先用 vm-load.ps1 装载驱动" }
Write-Host ("服务 iwan: {0}，驱动文件 {1}" -f $svc.Status, (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath)

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

$req = New-Object byte[] 136
Put-U32Host $req 0  1
Put-U32Host $req 4  136
Put-U16     $req 8  $Sid
Put-U32Host $req 12 $Tok
$req[16] = 1                                  # enc
Put-Bytes   $req 17 $keyBytes
Put-Ip4Net  $req 28 $localIp                  # outer_src（网络序）
Put-Ip4Net  $req 32 $PeerIp                   # outer_dst
Put-U16     $req 36 (40000 + ($Sid % 1000))   # sport
Put-U16     $req 38 $PeerPort                 # dport
$flags = 0
if ($BindInner) { $flags = $flags -bor $FLAG_BIND_INNER }
Put-U32Host $req 72 $flags
Put-U32Host $req 76 0
Put-Ip4Net  $req 80 $localIp                  # bind_ip
Put-Ip4Net  $req 100 $InnerIp                 # inner_ip
Put-U32Host $req 120 $InnerMtu
Put-U32Host $req 124 $CarrierMtu
Put-U32Host $req 128 136                      # target_offset
Put-U32Host $req 132 1                        # target_count

$inBuf = New-Object byte[] ($req.Length + $targets.Length)
[Array]::Copy($req, 0, $inBuf, 0, $req.Length)
[Array]::Copy($targets, 0, $inBuf, $req.Length, $targets.Length)
Write-Host ("请求：{0} 字节（结构 136 + 目标 1×24），sid={1} tok={2} 目标 {3}/{4} 外层 {5}:{6}" -f `
    $inBuf.Length, $Sid, $Tok, $Target, $TargetFamily, $PeerIp, $PeerPort)

# ---------- 2. 开设备、开会话 ----------
$h = [IWAN.Native]::CreateFileW("\\.\iwan", [uint32]3221225472, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]::new(-1)) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ("打开 \\.\iwan 失败：Win32 错误 {0}（{1}）—— 用管理员身份运行了吗？" -f $err,
           (New-Object System.ComponentModel.Win32Exception($err)).Message)
}
Write-Host "`n已打开 \\.\iwan"

try {
    $null = Invoke-Ioctl $h $IOCTL_OPEN $inBuf 200 'IOCTL_IWAN_SESSION_OPEN'
    $info1 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Show-Stats $info1 '开会话后'

    if ($PingCount -gt 0) {
        Write-Host "`n--- ping $Target（内层 ICMP，应该被封装后由宿主对端回包）---"
        & ping.exe -4 -n $PingCount -w 2000 $Target
        Write-Host ("ping 退出码 {0}" -f $LASTEXITCODE)
    }

    $info2 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Show-Stats $info2 'ping 之后'

    if (-not $KeepOpen) {
        $null = Invoke-Ioctl $h $IOCTL_CLOSE $null 0 'IOCTL_IWAN_SESSION_CLOSE'
    } else { Write-Host "`n保持会话打开（-KeepOpen）" }
} finally {
    [void][IWAN.Native]::CloseHandle($h)
    Write-Host "已关闭设备句柄"
}
