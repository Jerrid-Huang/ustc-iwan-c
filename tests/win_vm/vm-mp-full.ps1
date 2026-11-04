# iwanmp all-in-one on-machine harness: inspect -> clean -> install -> open fuse -> adapter/address/MTU -> OPEN probe -> full trace read
#
# The only reason this script exists: which build is running used to be guessed from disassembly snapshots -- on the guest,
# when the .sys is pinned by a loaded driver Copy-Item reports Access denied, sc delete only marks it
# for deletion, and pnputil /delete-driver needs a reboot to take effect -- file mtime is completely untrustworthy.
# So everything is chained through the PE TimeDateStamp:
#   stamp of source .sys  ==  stamp of System32\drivers\iwanmp.sys (installed the right one)
#   the driver reads it into T31 (see iwan_win_mp_build_stamp in win-driver/iwan_win_mp.c)
# If they differ, fail immediately instead of guessing from trace keys.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-full.ps1 `
#       -Sys C:\iwan\iwanmp.sys -Inf C:\iwan\iwanmp.inf -Carrier 7
#   inspect only: -InspectOnly
#   harness already installed, probe only: -SkipInstall
param(
    [string]$Sys = 'C:\iwan\iwanmp.sys',
    [string]$Inf = 'C:\iwan\iwanmp.inf',
    [string]$Hwid = 'iwanmp',
    [int]$Carrier = 0,
    [int]$HoldSeconds = 4,
    [int]$WaitSeconds = 8,
    # Media shape of the inner adapter. On the guest with NdisMediumIP + broadcast + no link address,
    # TCP/IP still creates a neighbor entry for the peer and asks for a 6-byte link address; without it send
    # fails outright (ping reports General failure, UDP reports WSAEINVAL) and never even reaches NDIS.
    # Registry + restart-device switches the tier without rebooting the whole machine with a new image.
    #   MpAccess 0=broadcast 1=point-to-point 2=loopback
    #   MpMacLen 0=no link address 6=fake MAC
    #   MpIfType 0=PROP_VIRTUAL 6=ETHERNET_CSMACD 131=TUNNEL
    [int]$MpAccess = 0,
    [int]$MpMacLen = 0,
    [int]$MpIfType = 0,
    # Ping count inside the session: only together with MpAccess does it prove the inner side can hand packets to the driver.
    [int]$PingCount = 0,
    [switch]$InspectOnly,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }
function PeStamp([string]$p) {
    if (-not (Test-Path $p)) { return [uint32]0 }
    $b = [System.IO.File]::ReadAllBytes($p)
    if ($b.Length -lt 0x40) { return [uint32]0 }
    if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return [uint32]0 }
    $lf = [BitConverter]::ToInt32($b, 0x3C)
    if ($lf -le 0 -or ($lf + 12) -gt $b.Length) { return [uint32]0 }
    return [BitConverter]::ToUInt32($b, $lf + 8)
}

$drv = 'C:\Windows\System32\drivers\iwanmp.sys'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
$traceKeys = '^(T\d+|Stage|Status)$'

function Get-IwanmpNodes {
    @(Get-PnpDevice -ErrorAction SilentlyContinue |
      Where-Object { $_.HardwareID -contains $Hwid })
}
function Show-Trace {
    if (-not (Test-Path $pkey)) { '  (no Parameters key)'; return }
    $p = Get-ItemProperty $pkey
    foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match $traceKeys } | Sort-Object)) {
        "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
    }
}
function Clear-Trace {
    if (-not (Test-Path $pkey)) { return }
    $p = Get-ItemProperty $pkey
    foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match $traceKeys })) {
        Remove-ItemProperty -Path $pkey -Name $n -ErrorAction SilentlyContinue
    }
}
function Set-Param([string]$n, [int]$v) {
    if (-not (Test-Path $pkey)) { New-Item -Path $pkey -Force | Out-Null }
    New-ItemProperty -Path $pkey -Name $n -PropertyType DWord -Value $v -Force | Out-Null
}

Sec '0 inspect'
$srcStamp = PeStamp $Sys
$dstStamp = PeStamp $drv
"  src     $Sys  len=" + (Get-Item $Sys -ErrorAction SilentlyContinue).Length + " stamp=0x{0:X8}" -f $srcStamp
"  installed $drv  len=" + (Get-Item $drv -ErrorAction SilentlyContinue).Length + " stamp=0x{0:X8}" -f $dstStamp
"  service " + ((Get-Service -Name 'iwanmp' -ErrorAction SilentlyContinue).Status)
"  nodes   " + (Get-IwanmpNodes).Count
Show-Trace
if ($InspectOnly) { return }

if (-not $SkipInstall) {
    Sec '1 clean up'
    # Orphan nodes show up one after another (failed devcon installs leave empty shells with no Service value),
    # so delete in a loop until none remain, not once and assume it is clean.
    for ($round = 0; $round -lt 6; $round++) {
        $nodes = Get-IwanmpNodes
        if ($nodes.Count -eq 0) { break }
        foreach ($d in $nodes) {
            "  remove-device $($d.InstanceId)"
            & pnputil.exe /remove-device $d.InstanceId 2>&1 | Out-String | ForEach-Object { "    $_" }
        }
    }
    "  nodes after cleanup " + (Get-IwanmpNodes).Count

    & sc.exe query iwanmp 2>&1 | Out-String | ForEach-Object { "  $_" }
    & sc.exe delete iwanmp 2>&1 | Out-String | ForEach-Object { "  $_" }

    foreach ($o in (& pnputil.exe /enum-drivers | Out-String) -split "`r`n`r`n") {
        if ($o -match ([regex]::Escape($Hwid) + '\.inf')) {
            $m = [regex]::Match($o, 'Published Name:\s*(\S+)')
            if ($m.Success) {
                "  delete-driver $($m.Groups[1].Value)"
                & pnputil.exe /delete-driver $m.Groups[1].Value /uninstall /force 2>&1 |
                    Out-String | ForEach-Object { "    $_" }
            }
        }
    }
    if (Test-Path $drv) {
        Remove-Item $drv -Force -ErrorAction SilentlyContinue
        "  delete $drv -> exists=" + (Test-Path $drv)
    }

    Sec '2 install (fuse closed first)'
    Set-Param 'Disarm' 1
    Set-Param 'NoProto' 1
    & cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-install.ps1 -SysPath $Sys -InfPath $Inf" 2>&1 |
        Out-String | ForEach-Object { "  $_" }
    $dstStamp = PeStamp $drv
    "  stamp after install=0x{0:X8}" -f $dstStamp
    if ($dstStamp -ne $srcStamp -or $srcStamp -eq 0) {
        "  FATAL: installed image is not this build (src 0x{0:X8} / installed 0x{1:X8}) -- stopping" -f $srcStamp, $dstStamp
        return
    }
}

Sec '2.5 protocol component registration (NetTrans)'
# The protocol edge needs a binding; a service alone is not enough: NDIS must see it as a NetTrans component.
# Step 1 deleted the driver package, so the component registration may point at a service that no longer exists;
# without this fix T71 stays 0 and the whole round of readings is wasted (this happened once).
# Position matters too: install too early and DriverEntry is pulled up early (fuse still closed, burning
# one DriverEntry for nothing); install too late and this round of readings is void as well.
& cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-proto.ps1 -SysSrc $drv" 2>&1 |
    Out-String | ForEach-Object { "  $_" }
$comp = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}' -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -match '^\{' } |
          Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ComponentId -eq 'iwanmp' })
"  component instances " + $comp.Count
if ($comp.Count -eq 0) {
    # When leftover components make netcfg -l spin, uninstall first then install; retry only once to avoid an endless loop.
    "  not installed, run netcfg -u then install again"
    & cmd.exe /c "C:\Windows\System32\netcfg.exe -u iwanmp" 2>&1 | Out-String | ForEach-Object { "  $_" }
    & cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-mp-proto.ps1 -SysSrc $drv" 2>&1 |
        Out-String | ForEach-Object { "  $_" }
    $comp = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}' -ErrorAction SilentlyContinue |
              Where-Object { $_.PSChildName -match '^\{' } |
              Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ComponentId -eq 'iwanmp' })
    "  component instances after retry " + $comp.Count
}
if ($comp.Count -eq 0) { throw 'NetTrans component not installed: the protocol edge cannot bind' }
# Ndi\Interfaces on the service key is written by both INFs: the miniport package and the protocol component package
# both write into Services\iwanmp\Ndi\Interfaces, and the later install overwrites value by value.
# Measured: the miniport package changed it to upper=ndis5 / lower=ethernet; both shapes work,
# but the real values of this round must be recorded, otherwise when a binding appears and then
# cannot be opened, the interface shape cannot be ruled out.
$ik = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Ndi\Interfaces'
if (Test-Path $ik) {
    $q = Get-ItemProperty $ik
    "  service Ndi: upper=" + ($q.UpperRange -join ',') + " lower=" + ($q.LowerRange -join ',')
} else { '  service Ndi\Interfaces: missing' }

Sec '3 open fuse (protocol edge starts too)'
$node = (Get-IwanmpNodes | Select-Object -First 1).InstanceId
if (-not $node) { throw 'no device node with HardwareID=iwanmp' }
Clear-Trace
Set-Param 'MpAccess' $MpAccess
Set-Param 'MpMacLen' $MpMacLen
Set-Param 'MpIfType' $MpIfType
Set-Param 'Disarm' 0
Set-Param 'NoProto' 0
"  media shape: MpAccess=$MpAccess MpMacLen=$MpMacLen MpIfType=$MpIfType"
& pnputil.exe /restart-device $node 2>&1 | Out-String | ForEach-Object { "  $_" }
Start-Sleep -Seconds $WaitSeconds
"  device: " + ((Get-IwanmpNodes | Select-Object -First 1).Status)
$t31 = 0
if (Test-Path $pkey) { $t31 = [uint32](Get-ItemProperty $pkey).T31 }
"  running image T31=0x{0:X8} (src 0x{1:X8})" -f $t31, $srcStamp
if ($t31 -ne $srcStamp) { "  WARNING: not running this build, later readings are unreliable" }

Sec '4 adapter / address / MTU'
$ad = Get-NetAdapter -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceDescription -like 'iWAN Tunnel Adapter*' -and $_.Status -ne 'Not Present' } |
      Select-Object -First 1
if (-not $ad) { '  no tunnel adapter (MiniportInitializeEx failed, check T20/T21/T22)'; Show-Trace; return }
"  adapter $($ad.Name) ifIndex=$($ad.ifIndex) status=$($ad.Status)"
if ($ad.Name -ne 'iwanmp') {
    & netsh.exe interface set interface name="$($ad.Name)" newname="iwanmp" 2>&1 | Out-String | ForEach-Object { "  $_" }
    Start-Sleep -Seconds 2
    $ad = Get-NetAdapter -Name 'iwanmp' -ErrorAction SilentlyContinue
    "  renamed $($ad.Name) ifIndex=$($ad.ifIndex)"
}
# netsh set address on an existing address reports "The object already exists." and has no effect,
# only add address actually adds it.
# The test must be whether this address exists, not whether any address exists: the adapter comes up
# with a 169.254.x.x autoconfig address, so the latter test silently skips add -- and then ping hits
# that nonexistent inner address, looking like the data plane is broken (this happened).
$have = @(Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -eq '10.99.0.1' })
if ($have.Count -eq 0) {
    & netsh.exe interface ipv4 add address name="iwanmp" 10.99.0.1 255.255.255.0 2>&1 | Out-String | ForEach-Object { "  $_" }
    Start-Sleep -Seconds 1
}
$have = @(Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -eq '10.99.0.1' })
if ($have.Count -eq 0) { '  WARNING: 10.99.0.1 was not added, inner traffic will fail' }
& netsh.exe interface ipv4 set subinterface "iwanmp" mtu=1400 store=persistent 2>&1 | Out-String | ForEach-Object { "  $_" }
Get-NetIPAddress -InterfaceAlias 'iwanmp' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object IPAddress, PrefixLength | Format-Table -AutoSize | Out-String -Width 200

Sec '5 OPEN probe'
if ($Carrier -le 0) { $Carrier = (Get-NetAdapter -Name 'Ethernet' -ErrorAction SilentlyContinue).ifIndex }
"  carrier ifIndex=$Carrier hold ${HoldSeconds}s"
# Two numbering schemes are printed side by side: the driver binding table stores NDIS values, the control plane uses netio values,
# and the probe uses Get-NetAdapter ifIndex. When the three differ, symptoms are identical to not bound at all.
foreach ($c in (Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID })) {
    $ni = Get-NetAdapter -Name $c.NetConnectionID -ErrorAction SilentlyContinue
    "  index map name=$($c.NetConnectionID) miniport=$($c.Index) netio=$(if ($ni) { $ni.ifIndex } else { '?' })"
}
Clear-Trace
# Carrier NIC interface GUID: on the guest the two interface index schemes measurably disagree (Ethernet
# netio=7 while the protocol edge binding reports 23/26), so picking the carrier by index is a guess. The real
# control-plane path uses ConvertInterfaceLuidToGuid for the same GUID; copy that scheme here.
$cguid = (Get-NetAdapter -InterfaceIndex $Carrier -ErrorAction SilentlyContinue).InterfaceGuid
if ($cguid) { $cguid = $cguid.ToString() } else { $cguid = '' }
"  carrier GUID=$cguid"
& cmd.exe /c "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File C:\iwan\mp-ab-probe.ps1 -HoldSeconds $HoldSeconds -OifIndex $Carrier -OuterIfGuid $cguid -PingCount $PingCount" 2>&1 |
    Out-String | ForEach-Object { "  $_" }

Sec '6 trace table'
Show-Trace
''
'  how to read:'
'   T31 = running image timestamp (match with step 3 source means this build is running)'
'   T69 = declared minor version hit by protocol edge registration; T78/T79 = NDIS BindAdapterEx calls/rejections'
'   T71 = link bindings; T72/T73 = open_complete success/failure counts; T74/T75 = first two bindings ifindex|opened|closed'
'   T76/T77 = NTSTATUS of failed open / NdisOpenAdapterEx immediate return; T83 > 0 means it waited for an in-flight open'
'   T80 = no usable binding found; T81 = unbound at selection instant; T82 = success, value is selected ifindex'
'   T87 = session carries carrier GUID (1=yes, lookup by GUID only); T88 = hits<<8 | parse_ok'
'   T90/T91/T92 = AccessType/MacAddressLength/IfType tier used by this miniport instance'
'   T93/T94/T95/T96 = ARP requests sent / ARP frames received / neighbors learned / peer_mac_valid'
