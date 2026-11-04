# Read-only: dump the iwanmp state in one pass (device node, service, inner adapter, trace keys, PnP events).
#
# Usage: powershell -NoProfile -File vm-mp-state.ps1
param(
    [string]$InstanceId = '',
    [int]$EventMinutes = 10
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

Sec 'device node'
$devs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
          Where-Object { $_.HardwareID -contains 'iwanmp' })
if ($devs.Count -gt 0) {
    $devs | Select-Object Status, Class, FriendlyName, InstanceId, Problem, ProblemDescription |
        Format-List
} else {
    'no device node with HardwareID=iwanmp'
}

Sec 'device properties'
foreach ($k in 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_Service',
               'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverProvider') {
    if (-not $InstanceId) { break }
    $v = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $k -ErrorAction SilentlyContinue).Data
    if ($null -ne $v) { "  $k = $v" }
}

Sec 'service'
Get-Service -Name iwanmp -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType, StartType | Format-List
if (-not (Get-Service -Name iwanmp -ErrorAction SilentlyContinue)) { 'no iwanmp service' }

Sec 'inner adapter'
Get-NetAdapter -ErrorAction SilentlyContinue |
    Select-Object Name, InterfaceDescription, Status, ifIndex, LinkSpeed, MacAddress |
    Format-Table -AutoSize
foreach ($n in (Get-NetAdapter -ErrorAction SilentlyContinue).Name) {
    $mtu = (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu
    $ips = (Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ','
    "  {0,-24} ifIndex={1,-4} mtu={2,-6} ipv4={3}" -f $n,
        (Get-NetAdapter -Name $n).ifIndex, $mtu, $ips
}

Sec 'disk'
Get-PSDrive C | Select-Object @{n='FreeMB';e={[int]($_.Free/1MB)}}, @{n='UsedMB';e={[int]($_.Used/1MB)}} | Format-Table -AutoSize

Sec 'staged trace keys'
$pkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwanmp\Parameters'
$p = Get-ItemProperty $pkey -ErrorAction SilentlyContinue
if ($p) {
    foreach ($n in 'Stage', 'Status', 'Disarm', 'NoProto') {
        if ($p.PSObject.Properties.Name -contains $n) { "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n }
    }
    $tkeys = @($p.PSObject.Properties.Name | Where-Object { $_ -match '^T\d+$' })
    foreach ($n in ($tkeys | Sort-Object { [int]($_.Substring(1)) })) {
        "  {0,-10} = 0x{1:X8} ({1})" -f $n, [uint32]$p.$n
    }
    if ($tkeys.Count -eq 0) { '  (no T keys at all: the driver has never been loaded)' }
} else {
    "no $pkey"
}

Sec 'iwanmp package in DriverStore'
(& pnputil.exe /enum-drivers | Out-String) -split "`r?`n`r?`n" |
    Where-Object { $_ -match 'iwanmp\.inf' } |
    ForEach-Object { ($_ -replace '\s+', ' ').Trim() }

Sec "Kernel-PnP events of the last $EventMinutes minutes"
Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-$EventMinutes) } `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Kernel-PnP' } |
    Select-Object -First 8 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }
