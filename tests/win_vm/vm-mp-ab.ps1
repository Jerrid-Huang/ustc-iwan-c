# iwanmp（NDIS 微型端口 + 协议驱动）端到端装具：准备内层适配器 → 后台保持会话
# → 前台打内层流 → 收回两侧计数。
#
# 与 WFP 平面的 vm-rx.ps1 是同一套 IOCTL/ABI 2 装具，只有三个参数不同：
#   -Adapter iwanmp -Device \\.\iwanmp -Service iwanmp，并且必须给 -OifIndex（承载网卡）。
#
# 用法（客体，管理员）：
#   powershell -NoProfile -File C:\iwan\vm-mp-ab.ps1 -PrepareOnly
#   powershell -NoProfile -File C:\iwan\vm-mp-ab.ps1 -Seconds 10 -Bytes 1200 -Pps 20000
#
# 宿主侧先用 tests/win_blast.py sink 45678 起计数端（外层对端 = 10.0.2.2:45678）。
param(
    [string]$TunnelDesc  = 'iWAN Tunnel Adapter',
    [string]$Adapter     = 'iwanmp',
    [string]$KillAdapter = 'iWAN',      # KM-TEST 回环，占着同一个 10.99.0.0/24
    [string]$Carrier     = 'Ethernet',
    [string]$Device      = '\\.\iwanmp',
    [string]$Service     = 'iwanmp',
    [string]$InnerIp     = '10.99.0.1',
    [int]   $InnerPfx    = 24,
    [int]   $InnerMtu    = 1400,
    [string]$InnerDst    = '10.99.0.2',
    [int]   $InnerDport  = 40001,
    [string]$PeerIp      = '10.0.2.2',
    [int]   $PeerPort    = 45678,
    [int]   $Seconds     = 10,
    [int]   $Bytes       = 1200,
    [int]   $Threads     = 1,
    [int]   $Pps         = 20000,
    [int]   $HoldSeconds = 0,           # 0 = 自动取 Seconds + 25
    [switch]$PrepareOnly,
    [switch]$SkipBench
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }

if ($HoldSeconds -le 0) { $HoldSeconds = $Seconds + 25 }

# ---- 1. 内层适配器就位 -------------------------------------------------
Sec '内层适配器'
$tun = Get-NetAdapter -ErrorAction SilentlyContinue |
       Where-Object { $_.InterfaceDescription -eq $TunnelDesc } |
       Select-Object -First 1
if (-not $tun) {
    '找不到隧道适配器（InterfaceDescription = ' + $TunnelDesc + '）—— 先确认 iwanmp 已装载且设备已启动'
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, ifIndex | Format-Table -AutoSize
    exit 2
}
"  当前名字 = $($tun.Name)，状态 = $($tun.Status)，ifIndex = $($tun.ifIndex)"
if ($tun.Name -ne $Adapter) {
    Rename-NetAdapter -Name $tun.Name -NewName $Adapter -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    "  已改名为 $Adapter"
}
# 同一网段的另一张网卡必须先停用：两张都持有 10.99.0.0/24 时，路由选谁看度量，
# 内层流量可能根本不经过隧道（这是 WFP 平面 A/B 时踩过的坑）。
if ($KillAdapter) {
    $kill = Get-NetAdapter -Name $KillAdapter -ErrorAction SilentlyContinue
    if ($kill -and $kill.Status -ne 'Disabled') {
        Disable-NetAdapter -Name $KillAdapter -Confirm:$false -ErrorAction SilentlyContinue
        "  已停用 $KillAdapter（它与 $Adapter 抢同一个网段）"
        Start-Sleep -Seconds 2
    }
}

Sec '地址与 MTU'
& netsh.exe interface ip set address name="$Adapter" static "$InnerIp/$InnerPfx" | Out-String
& netsh.exe interface ipv4 set subinterface "$Adapter" mtu=$InnerMtu store=persistent | Out-String
Start-Sleep -Seconds 2
Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object IPAddress, PrefixLength, InterfaceAlias | Format-Table -AutoSize
"  链路状态 = $((Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue).Status)"

Sec '承载网卡'
$oif = (Get-NetAdapter -Name $Carrier -ErrorAction SilentlyContinue).ifIndex
"  $Carrier ifIndex = $oif"
& netsh.exe interface ipv4 show route | Select-String -Pattern '0.0.0.0/0' | Select-Object -First 3

if ($PrepareOnly) { Sec '只做准备（-PrepareOnly）'; exit 0 }

# ---- 2. 后台开会话并保持 ------------------------------------------------
Sec '会话（后台）'
$rxArgs = @{
    Adapter = $Adapter; Device = $Device; Service = $Service
    InnerIp = $InnerIp; Target = $InnerDst; InnerMtu = $InnerMtu
    CarrierMtu = 1500; OifIndex = $oif; OuterHop = 0
    PeerIp = $PeerIp; PeerPort = $PeerPort; PingCount = 0
    Inject = $true; SkipSelfTest = $true; ShmDump = $true
    HoldSeconds = $HoldSeconds
}
$rx = Start-Job -ScriptBlock {
    param($a)
    & C:\iwan\vm-rx.ps1 @a *>&1
} -ArgumentList $rxArgs

$opened = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    $out = (Receive-Job -Job $rx -Keep 2>&1 | Out-String)
    if ($out -match 'Mark 60|IWAN-LIVE') { $opened = $true; break }
    if ($out -match 'IOCTL_OPEN 失败|失败') { break }
}
"  会话就绪 = $opened（等了 $i 秒）"

# ---- 3. 打流 -----------------------------------------------------------
if (-not $SkipBench -and $opened) {
    Sec "内层打流（$Seconds 秒，$Bytes 字节，$Threads 线程，$Pps pps）"
    & C:\iwan\vm-bench.ps1 -Mode gen -Bind $InnerIp -Dst $InnerDst -Dport $InnerDport `
        -Sport 40001 -Seconds $Seconds -Bytes $Bytes -Threads $Threads -Pps $Pps
    Start-Sleep -Seconds 2
}

# ---- 4. 收计数 ---------------------------------------------------------
Sec '等会话保持结束'
for ($i = 0; $i -lt ($HoldSeconds + 30); $i++) {
    Start-Sleep -Seconds 1
    $out = (Receive-Job -Job $rx -Keep 2>&1 | Out-String)
    if ($out -match 'Mark 61') { break }
}
"  等待 $i 秒"

Sec '客体侧完整日志'
Receive-Job -Job $rx -Keep 2>&1 | ForEach-Object { $_ }
Stop-Job -Job $rx -ErrorAction SilentlyContinue
Remove-Job -Job $rx -Force -ErrorAction SilentlyContinue

Sec '收尾'
'驱动统计见上面 after-hold 段；宿主接收端累计由宿主侧 tests/win_blast.py 打印。'
