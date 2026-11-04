# iwanmp (NDIS miniport + protocol driver) end-to-end harness: prepare inner adapter -> keep session in background
# -> blast inner traffic in the foreground -> collect counters from both sides.
#
# Same IOCTL/ABI 2 harness as vm-rx.ps1 for the WFP plane; only three parameters differ:
#   -Adapter iwanmp -Device \\.\iwanmp -Service iwanmp, and -OifIndex (carrier NIC) is mandatory.
#
# Usage (guest, administrator):
#   powershell -NoProfile -File C:\iwan\vm-mp-ab.ps1 -PrepareOnly
#   powershell -NoProfile -File C:\iwan\vm-mp-ab.ps1 -Seconds 10 -Bytes 1200 -Pps 20000
#
# Start tests/win_blast.py sink 45678 on the host first (outer peer = 10.0.2.2:45678).
param(
    [string]$TunnelDesc  = 'iWAN Tunnel Adapter',
    [string]$Adapter     = 'iwanmp',
    [string]$KillAdapter = 'iWAN',      # KM-TEST loopback, occupies the same 10.99.0.0/24
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
    [int]   $HoldSeconds = 0,           # 0 = automatically use Seconds + 25
    [switch]$PrepareOnly,
    [switch]$SkipBench
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }

if ($HoldSeconds -le 0) { $HoldSeconds = $Seconds + 25 }

# ---- 1. inner adapter ready --------------------------------------------
Sec 'inner adapter'
$tun = Get-NetAdapter -ErrorAction SilentlyContinue |
       Where-Object { $_.InterfaceDescription -eq $TunnelDesc } |
       Select-Object -First 1
if (-not $tun) {
    'cannot find tunnel adapter (InterfaceDescription = ' + $TunnelDesc + ') -- first confirm iwanmp is loaded and the device is started'
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, ifIndex | Format-Table -AutoSize
    exit 2
}
"  current name = $($tun.Name), status = $($tun.Status), ifIndex = $($tun.ifIndex)"
if ($tun.Name -ne $Adapter) {
    Rename-NetAdapter -Name $tun.Name -NewName $Adapter -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    "  renamed to $Adapter"
}
# Another NIC on the same subnet must be disabled first: when both hold 10.99.0.0/24, route choice follows the metric,
# and inner traffic may not go through the tunnel at all (this pitfall was hit during WFP-plane A/B).
if ($KillAdapter) {
    $kill = Get-NetAdapter -Name $KillAdapter -ErrorAction SilentlyContinue
    if ($kill -and $kill.Status -ne 'Disabled') {
        Disable-NetAdapter -Name $KillAdapter -Confirm:$false -ErrorAction SilentlyContinue
        "  disabled $KillAdapter (it competes with $Adapter for the same subnet)"
        Start-Sleep -Seconds 2
    }
}

Sec 'address and MTU'
& netsh.exe interface ip set address name="$Adapter" static "$InnerIp/$InnerPfx" | Out-String
& netsh.exe interface ipv4 set subinterface "$Adapter" mtu=$InnerMtu store=persistent | Out-String
Start-Sleep -Seconds 2
Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object IPAddress, PrefixLength, InterfaceAlias | Format-Table -AutoSize
"  link status = $((Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue).Status)"

Sec 'carrier NIC'
$oif = (Get-NetAdapter -Name $Carrier -ErrorAction SilentlyContinue).ifIndex
"  $Carrier ifIndex = $oif"
& netsh.exe interface ipv4 show route | Select-String -Pattern '0.0.0.0/0' | Select-Object -First 3

if ($PrepareOnly) { Sec 'prepare only (-PrepareOnly)'; exit 0 }

# ---- 2. open session in background and keep it --------------------------
Sec 'session (background)'
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
    if ($out -match 'IOCTL_OPEN failed|failed') { break }
}
"  session ready = $opened (waited $i seconds)"

# ---- 3. blast ----------------------------------------------------------
if (-not $SkipBench -and $opened) {
    Sec "inner blast ($Seconds seconds, $Bytes bytes, $Threads threads, $Pps pps)"
    & C:\iwan\vm-bench.ps1 -Mode gen -Bind $InnerIp -Dst $InnerDst -Dport $InnerDport `
        -Sport 40001 -Seconds $Seconds -Bytes $Bytes -Threads $Threads -Pps $Pps
    Start-Sleep -Seconds 2
}

# ---- 4. collect counters -----------------------------------------------
Sec 'wait for session keepalive to end'
for ($i = 0; $i -lt ($HoldSeconds + 30); $i++) {
    Start-Sleep -Seconds 1
    $out = (Receive-Job -Job $rx -Keep 2>&1 | Out-String)
    if ($out -match 'Mark 61') { break }
}
"  waited $i seconds"

Sec 'guest-side full log'
Receive-Job -Job $rx -Keep 2>&1 | ForEach-Object { $_ }
Stop-Job -Job $rx -ErrorAction SilentlyContinue
Remove-Job -Job $rx -Force -ErrorAction SilentlyContinue

Sec 'cleanup'
'Driver stats are in the after-hold section above; host receiver totals are printed by host-side tests/win_blast.py.'
