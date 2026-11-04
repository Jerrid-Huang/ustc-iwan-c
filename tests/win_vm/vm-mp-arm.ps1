# Release the iwanmp fuse and restart the device node -- this is the step that really "starts loading".
#
# Two levels; by default only half is released (-NoProto 1):
#   Level 1 (script default): register the miniport only, not the protocol side. Used to verify
#     "adapter appears + address and MTU settable + control device usable + no hang";
#   Level 2: -NoProto 0, the protocol side also comes up (outer carrier send/receive), only then is end-to-end possible.
# At either level, DriverEntry does not return failure after the miniport registers successfully.
#
# Usage: powershell -NoProfile -File vm-mp-arm.ps1 -NoProto 1
param(
    [string]$InstanceId = '',
    [int]$Disarm = 0,
    [int]$NoProto = 1,
    [int]$WaitSeconds = 6
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Sec($t) { "`n=== $t ===" }

# Device instance ID is not fixed: devcon install creates the node per the INF Class, so it lands in
# ROOT\NET\000x (early scripts hardcoded ROOT\IWANMP\0000 as a guess, which never took effect).
function Get-IwanmpInstanceId {
    $d = Get-PnpDevice -ErrorAction SilentlyContinue |
         Where-Object { $_.HardwareID -contains 'iwanmp' } |
         Select-Object -First 1
    if ($d) { return $d.InstanceId }
    return ''
}
if (-not $InstanceId) { $InstanceId = Get-IwanmpInstanceId }

$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
if (-not (Test-Path $pkey)) { throw "no $pkey (driver package not installed yet?)" }

Sec 'clear old trace keys (otherwise values from the previous round are read)'
$p = Get-ItemProperty $pkey
foreach ($n in @($p.PSObject.Properties.Name | Where-Object { $_ -match '^(T\d+|Stage|Status)$' })) {
    Remove-ItemProperty -Path $pkey -Name $n -ErrorAction SilentlyContinue
    "  delete $n"
}

Sec 'set gates'
New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value $Disarm -Force | Out-Null
New-ItemProperty -Path $pkey -Name 'NoProto' -PropertyType DWord -Value $NoProto -Force | Out-Null
"  Disarm=$Disarm NoProto=$NoProto"

Sec 'restart device node'
& pnputil.exe /restart-device "$InstanceId" 2>&1 | Out-String
Start-Sleep -Seconds $WaitSeconds

Sec 'device status'
if (-not $InstanceId) { throw 'no device node with HardwareID=iwanmp' }
Get-PnpDevice | Where-Object { $_.HardwareID -contains 'iwanmp' } |
    Select-Object Status, FriendlyName, InstanceId, Problem, ProblemDescription | Format-List
foreach ($k in 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service') {
    $v = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $k -ErrorAction SilentlyContinue).Data
    if ($null -ne $v) { "  $k = $v" }
}

Sec 'inner adapter'
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'iWAN' -or $_.Name -match 'iwanmp' } |
    Select-Object Name, InterfaceDescription, Status, ifIndex, LinkSpeed | Format-Table -AutoSize

Sec 'trace keys'
$p = Get-ItemProperty $pkey
foreach ($n in 'Stage', 'Status') {
    if ($p.PSObject.Properties.Name -contains $n) { "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
}
$tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
    "  {0,-8} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
}

Sec 'criteria hints'
'T11/T13 = 0x00000000 means registered successfully; T30 is NdisGetVersion() (6.89 -> 0x00060059);'
'T40/T39 are the miniport half, T60/T69 are the protocol half (T60=0xC0000001 when NoProto=1).'
