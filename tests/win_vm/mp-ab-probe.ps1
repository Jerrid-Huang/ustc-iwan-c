# 内层适配器 OPEN 探针：把 vm-rx.ps1 包一层，只测会话建立与保持。
#
# 单独成文件而不是内联在 vm-mp-full.ps1 里，是因为它要用不同的命令行参数
# 反复跑（媒介形状、承载 GUID、保持秒数），内联的 here-string 一旦有引号
# 就会在 ssh -> cmd -> powershell 三层转义里变形（踩过多次）。
param(
    [switch]$GetOnly,
    [int]$HoldSeconds = 0,
    [int]$OifIndex = 0,
    [string]$OuterIfGuid = '',
    # 内层 ping 次数。扫媒介形状时它是"这个形状能不能发出去"的唯一判据：
    # 能发时 tx_pkts 才会动（会话已开、包已进封装）。
    [int]$PingCount = 0
)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ad = Get-NetAdapter -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceDescription -like 'iWAN Tunnel Adapter*' -and $_.Status -ne 'Not Present' } |
      Select-Object -First 1
if (-not $ad) { 'PROBE no-adapter'; exit 2 }
$oif = $OifIndex
if ($oif -le 0) { $oif = (Get-NetAdapter -Name 'Ethernet' -ErrorAction SilentlyContinue).ifIndex }
if (-not $OuterIfGuid -and $oif -gt 0) {
    $c = Get-NetAdapter -InterfaceIndex $oif -ErrorAction SilentlyContinue
    if ($c) { $OuterIfGuid = $c.InterfaceGuid.ToString() }
}
"PROBE adapter=$($ad.Name) ifIndex=$($ad.ifIndex) carrier=$oif guid=$OuterIfGuid"

$rxArgs = @{
    Adapter = $ad.Name; Device = '\\.\iwanmp'; Service = 'iwanmp'
    InnerIp = '10.99.0.1'; Target = '10.99.0.2'; InnerMtu = 1400
    CarrierMtu = 1500; OifIndex = $oif; OuterHop = 0
    OuterIfGuid = $OuterIfGuid
    PeerIp = '10.0.2.2'; PeerPort = 45678; PingCount = $PingCount
    Inject = (-not $GetOnly); SkipSelfTest = $true; ShmDump = $true
    HoldSeconds = $HoldSeconds
}
if ($GetOnly) { $rxArgs['GetOnly'] = $true }
& C:\iwan\vm-rx.ps1 @rxArgs *>&1 | ForEach-Object { $_ }
