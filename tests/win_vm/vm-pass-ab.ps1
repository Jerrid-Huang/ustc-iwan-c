# PassThrough A/B on the guest: same generated load, two driver settings.
#
# Why: Parameters\PassThrough (bit1=TX, bit2=RX) makes the driver skip the tunnel work and just
# count the packet. Running the same inner UDP load with 0 and with 1 answers two questions:
#   (a) does the switch actually take effect end to end (frames must stop reaching the host peer),
#   (b) how much per-packet work does encapsulation cost (tx_pkts rate at an identical generator
#       setting; a rate-limited generator cannot show this, an unlimited one is limited by the ruler).
#
# Structure: vm-rx.ps1 holds a real session open (-HoldSeconds) and prints all 17 counters when it
# ends; vm-bench.ps1 runs the generator meanwhile. The session is opened AFTER the registry value is
# written, because the driver reads PassThrough when the session is opened.
param(
    [int]    $PassThrough = 0,
    [int]    $HoldSeconds = 24,
    [int]    $GenSeconds  = 8,
    [string] $Dst         = '8.8.8.8',
    [int]    $Dport       = 9999,
    [int]    $Threads     = 1,
    [int]    $Bytes       = 1200,
    [string] $Target      = '8.8.8.8',
    [int]    $WarmupSec   = 8,
    [string] $RxScript    = 'C:\iwan\vm-rx.ps1',
    [string] $GenScript   = 'C:\iwan\vm-bench.ps1'
)

$ErrorActionPreference = 'Stop'

$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan\Parameters'
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
New-ItemProperty -Path $key -Name PassThrough -Value $PassThrough -PropertyType DWord -Force | Out-Null
$readBack = (Get-ItemProperty -Path $key -Name PassThrough).PassThrough
Write-Host ("PASSAB set PassThrough={0} (read back {1})" -f $PassThrough, $readBack)

$holdOut = 'C:\iwan\ab-hold.txt'
$genOut = 'C:\iwan\ab-gen.txt'
Remove-Item $holdOut, $genOut -ErrorAction SilentlyContinue

$hold = Start-Process powershell -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RxScript,
    '-HoldSeconds', "$HoldSeconds", '-KeepOpen', '-Target', $Target, '-PingCount', '0'
) -RedirectStandardOutput $holdOut -PassThru -WindowStyle Hidden

Start-Sleep -Seconds $WarmupSec

$gen = Start-Process powershell -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $GenScript,
    '-Mode', 'gen', '-Dst', $Dst, '-Dport', "$Dport",
    '-Seconds', "$GenSeconds", '-Threads', "$Threads", '-Bytes', "$Bytes"
) -RedirectStandardOutput $genOut -PassThru -WindowStyle Hidden

[void]$gen.WaitForExit(180000)
[void]$hold.WaitForExit(180000)

Write-Host 'PASSAB gen:'
Get-Content $genOut -ErrorAction SilentlyContinue | Select-String -Pattern 'BENCH' | ForEach-Object { $_.Line }

Write-Host 'PASSAB live:'
Get-Content $holdOut -ErrorAction SilentlyContinue |
    Select-String -Pattern 'IWAN-LIVE|^STATS ' | ForEach-Object { $_.Line }

Write-Host ("PASSAB done PassThrough={0}" -f $PassThrough)
