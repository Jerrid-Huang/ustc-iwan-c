# Inner medium shape sweep: one image + several registry settings, find the one Windows accepts.
#
# Background: when the inner adapter declares NdisMediumIP + AccessType=broadcast + no link address,
# TCP/IP still creates a neighbor entry for the peer and asks for a 6-byte link address; without it send fails
# (ping reports General failure, UDP reports WSAEINVAL) and packets never even reach NDIS --
# the symptom is driver tx_pkts always 0. Which shape Windows accepts cannot be derived from code, so
# all three dimensions are DWORDs under Parameters; restart-device tries one setting per round:
#   MpAccess 0=broadcast 1=point-to-point 2=loopback
#   MpMacLen 0=no link address 6=give a fake MAC
#   MpIfType 0=PROP_VIRTUAL 6=ETHERNET_CSMACD 131=TUNNEL
#
# Criterion per setting: can the inner ping be sent (does tx_pkts move). Only tx_pkts>0 makes the setting
# usable; checking only "does ping work" misses cases (sending works even when no peer replies).
#
# Usage (guest, administrator):
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
    # After each restart-device the miniport may come back as a new instance with alias
    # "Local Area Connection* N"; if the name is not iwanmp, later netsh/Get-NetIPAddress all miss.
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
if (-not $node) { 'SWEEP fatal: no iwanmp device node found'; exit 2 }
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

    # Try ping first: can inner packets be handed to the driver.
    $ping = (ping -n $PingCount -w 300 10.99.0.2 2>&1 | Out-String)
    $sent = 0; $recv = 0
    $mm = [regex]::Match($ping, 'Sent = (\d+), Received = (\d+)')
    if ($mm.Success) { $sent = [int]$mm.Groups[1].Value; $recv = [int]$mm.Groups[2].Value }

    # Then open a session and ping again inside it, to read the driver's tx_pkts.
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
    if ($out -match 'Open failed|OPEN failed|Win32 error') { $open = 'FAIL' } else { $open = 'OK' }
    $rows += ("SWEEP shape={0} adapter={1} mac={2} ping={3}/{4} open={5} tx_pkts={6} tx_bad_state={7}" -f `
              $sh, $st, $mac, $sent, $recv, $open, $tx, $txbad)
    "  " + $rows[$rows.Count - 1]
}

''
'=== summary ==='
$rows | ForEach-Object { $_ }
''
'Interpretation: only a shape with tx_pkts>0 is a medium shape Windows accepts; ping=2/0 but tx_pkts=0 means packets never even reached the driver.'
