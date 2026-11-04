# Close the safety fuse and stop the device node -- the "dormant state" of iwanmp.
#
# Target state (return here after every test):
#   * Parameters\Disarm=1 (DriverEntry exits before any NDIS call)
#   * device node Disabled (PnP does not start it at all, even after reboot)
#   * service stopped (sc.exe stop only unloads the loaded image; the service type is demand)
# Thus even if the driver still hides a defect that can hang the machine, a reboot is always safe.
#
# Usage: powershell -NoProfile -File vm-mp-disarm.ps1
param(
    [string]$InstanceId = ''
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
if (Test-Path $pkey) {
    Sec 'close the fuse'
    New-ItemProperty -Path $pkey -Name 'Disarm' -PropertyType DWord -Value 1 -Force | Out-Null
    Get-ItemProperty $pkey | Select-Object Disarm, NoProto | Format-List
} else {
    "no $pkey"
}

Sec 'stop service'
& sc.exe stop iwanmp 2>&1 | Out-String
Start-Sleep -Seconds 2

Sec 'stop device node'
if (-not $InstanceId) { 'device node not found, skipping' }
else { & pnputil.exe /disable-device "$InstanceId" 2>&1 | Out-String }
Start-Sleep -Seconds 3

Sec 'final state'
Get-PnpDevice | Where-Object { $_.HardwareID -contains 'iwanmp' } |
    Select-Object Status, FriendlyName, InstanceId, Problem, ProblemDescription | Format-List
Get-Service -Name iwanmp -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-List
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match 'iWAN' } |
    Select-Object Name, Status, ifIndex | Format-Table -AutoSize

Sec 'criteria'
'device Status=Disabled/Error and service Stopped -> reboot is safe.'
