# Inner adapter OPEN probe: wraps vm-rx.ps1, only tests session setup and keepalive.
#
# Separate file instead of inline in vm-mp-full.ps1 because it is run repeatedly with different
# command-line arguments (medium shape, carrier GUID, hold seconds); an inline here-string with quotes
# gets mangled through ssh -> cmd -> powershell triple escaping (hit this several times).
param(
    [switch]$GetOnly,
    [int]$HoldSeconds = 0,
    [int]$OifIndex = 0,
    [string]$OuterIfGuid = '',
    # Inner ping count. When sweeping medium shapes it is the only criterion for "can this shape send at all":
    # tx_pkts moves only when sending works (session open, packets encapsulated).
    [int]$PingCount = 0,
    # Outer peer. Default goes through slirp to the host (10.0.2.2); using the guest's own address becomes "guest-internal carrier",
    # used to measure the driver's own ceiling (not limited by slirp's ~286 Mbps single-flow ceiling).
    [string]$PeerIp = '10.0.2.2',
    [string]$LocalIp = '',
    [int]$PeerPort = 45678
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
    PeerIp = $PeerIp; PeerPort = $PeerPort; PingCount = $PingCount; LocalIp = $LocalIp
    Inject = (-not $GetOnly); SkipSelfTest = $true; ShmDump = $true
    HoldSeconds = $HoldSeconds
}
if ($GetOnly) { $rxArgs['GetOnly'] = $true }
& C:\iwan\vm-rx.ps1 @rxArgs *>&1 | ForEach-Object { $_ }
