# 内层媒介形状扫描：一个映像 + 若干注册表档位，找出 Windows 认的那一种。
#
# 背景：内层适配器声明 NdisMediumIP + AccessType=广播 + 无链路地址时，
# TCP/IP 仍会给对端建邻居项并索要 6 字节链路地址，拿不到就在 send 处失败
# （ping 报 General failure，UDP 报 WSAEINVAL），连 NDIS 都到不了 ——
# 现象是驱动 tx_pkts 恒 0。哪种形状是 Windows 认的无法从代码推出，所以
# 把三种维度都做成 Parameters 下的 DWORD，每轮 restart-device 试一档：
#   MpAccess 0=广播 1=点对点 2=环回
#   MpMacLen 0=无链路地址 6=给一个假 MAC
#   MpIfType 0=PROP_VIRTUAL 6=ETHERNET_CSMACD 131=TUNNEL
#
# 每档判据：内层 ping 能不能发出去（tx_pkts 动不动）。tx_pkts>0 才算这一档
# 可用；只看"ping 通不通"会漏判（对端没人回包时也能发出去）。
#
# 用法（客体，管理员）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-sweep.ps1 -Carrier 7
param(
    [int]$Carrier = 0,
    [string[]]$Shapes = @('0-0-0', '1-0-0', '0-6-0', '1-6-0', '0-6-6', '1-6-6', '0-0-6', '2-0-0', '2-6-6'),
    [int]$WaitSeconds = 8,
    [int]$PingCount = 2,
    [int]$HoldSeconds = 2
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'

function Set-Param([string]$n, [int]$v) {
    if (-not (Test-Path $pkey)) { New-Item -Path $pkey -Force | Out-Null }
    New-ItemProperty -Path $pkey -Name $n -PropertyType DWord -Value $v -Force | Out-Null
}

function Get-TunnelAdapter {
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like 'iWAN Tunnel Adapter*' -and $_.Status -ne 'Not Present' } |
        Select-Object -First 1
}

function Ensure-Name($ad) {
    # 每次 restart-device 后迷你端口可能以新实例回来，别名变成
    # "本地连接* N"；名字不是 iwanmp 时后续 netsh/Get-NetIPAddress 全落空。
    if ($ad -and $ad.Name -ne 'iwanmp') {
        & netsh.exe interface set interface name="$($ad.Name)" newname="iwanmp" 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
}

function Ensure-InnerIp {
    $have = @(Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -eq '10.99.0.1' })
    if ($have.Count -eq 0) {
        & netsh.exe interface ipv4 add address name="iwanmp" 10.99.0.1 255.255.255.0 store=persistent 2>&1 |
            Out-String | ForEach-Object { "  $_" }
        Start-Sleep -Seconds 1
    }
    & netsh.exe interface ipv4 set subinterface "iwanmp" mtu=1400 store=persistent 2>&1 | Out-Null
}

$node = (Get-PnpDevice -ErrorAction SilentlyContinue |
         Where-Object { $_.InstanceId -like 'ROOT\NET\*' -and $_.FriendlyName -like 'iWAN*' } |
         Select-Object -First 1).InstanceId
if (-not $node) { 'SWEEP fatal: 找不到 iwanmp 设备节点'; exit 2 }
"SWEEP node=$node"

if ($Carrier -le 0) { $Carrier = (Get-NetAdapter -Name 'Ethernet' -ErrorAction SilentlyContinue).ifIndex }
$cguid = (Get-NetAdapter -InterfaceIndex $Carrier -ErrorAction SilentlyContinue).InterfaceGuid
if ($cguid) { $cguid = $cguid.ToString() } else { $cguid = '' }
"SWEEP carrier=$Carrier guid=$cguid"

$rows = @()
foreach ($sh in $Shapes) {
    $p = $sh.Split('-')
    if ($p.Count -ne 3) { "SWEEP skip bad shape $sh"; continue }
    $a = [int]$p[0]; $m = [int]$p[1]; $t = [int]$p[2]
    Set-Param 'MpAccess' $a
    Set-Param 'MpMacLen' $m
    Set-Param 'MpIfType' $t
    Set-Param 'Disarm' 0
    Set-Param 'NoProto' 0
    & pnputil.exe /restart-device $node 2>&1 | Out-Null
    Start-Sleep -Seconds $WaitSeconds

    $ad = Get-TunnelAdapter
    if (-not $ad) { $rows += "SWEEP shape=$sh adapter=NONE"; continue }
    Ensure-Name $ad
    $ad = Get-TunnelAdapter
    Ensure-InnerIp
    $mac = $ad.MacAddress
    if (-not $mac) { $mac = '-' }
    $st = $ad.Status

    # 先试 ping：能不能把内层报文交给驱动。
    $ping = (ping -n $PingCount -w 300 10.99.0.2 2>&1 | Out-String)
    $sent = 0; $recv = 0
    $mm = [regex]::Match($ping, 'Sent = (\d+), Received = (\d+)')
    if ($mm.Success) { $sent = [int]$mm.Groups[1].Value; $recv = [int]$mm.Groups[2].Value }

    # 再开会话并把 ping 放在会话里再打一次，读驱动的 tx_pkts。
    $out = (& cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\mp-ab-probe.ps1 -HoldSeconds $HoldSeconds -OifIndex $Carrier -OuterIfGuid $cguid -PingCount $PingCount" 2>&1 | Out-String)
    $tx = '-'; $txbad = '-'; $open = '-'
    $ms = [regex]::Matches($out, 'STATS (\S+) ([^\r\n]*)')
    if ($ms.Count -gt 0) {
        $last = $ms[$ms.Count - 1].Value
        $m2 = [regex]::Match($last, 'tx_pkts=(-?\d+)')
        if ($m2.Success) { $tx = $m2.Groups[1].Value }
        $m3 = [regex]::Match($last, 'tx_bad_state=(-?\d+)')
        if ($m3.Success) { $txbad = $m3.Groups[1].Value }
    }
    if ($out -match 'Open 失败|OPEN 失败|Win32 错误') { $open = 'FAIL' } else { $open = 'OK' }
    $rows += ("SWEEP shape={0} adapter={1} mac={2} ping={3}/{4} open={5} tx_pkts={6} tx_bad_state={7}" -f `
              $sh, $st, $mac, $sent, $recv, $open, $tx, $txbad)
    "  " + $rows[$rows.Count - 1]
}

''
'=== 汇总 ==='
$rows | ForEach-Object { $_ }
''
'判读：tx_pkts>0 的形状才是 Windows 认的媒介形状；ping=2/0 但 tx_pkts=0 说明报文连驱动都没到。'
