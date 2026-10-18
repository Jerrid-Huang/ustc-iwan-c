# 遥测版测试启动器：显式参数，避免 ssh 多层引号把参数搞坏（上一轮就是这么坏的）。
#
# 做的事：把 vm-rx.ps1 的输出实时通过 UDP 发到宿主，宿主按到达时间落盘 ——
# 虚拟机一旦卡死，ssh 和 guest 磁盘日志都可能丢，"什么时候断流"只有宿主看得到。
param(
    [string]$PeerIp = '10.0.2.2',
    [int]   $PeerPort = 45678,
    [int]   $HoldSeconds = 0,
    [switch]$Wire,
    [switch]$Inject,
    [switch]$NoInnerIp,
    [switch]$GetOnly,
    [string]$HostIp = '114.214.185.234',
    [int]   $Port = 45679
)
$ErrorActionPreference = 'Continue'
$u = New-Object System.Net.Sockets.UdpClient
$ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($HostIp), $Port)
function Tel([string]$msg) {
    $line = "GUEST {0} {1}" -f (Get-Date).ToString('HH:mm:ss.fff'), $msg
    try { $b = [Text.Encoding]::UTF8.GetBytes($line); [void]$u.Send($b, $b.Length, $ep) } catch { }
    Write-Host $line
}

# 组装 vm-rx.ps1 的参数（在这里拼，避免 ssh 层引号）
$argList = @('-PeerIp', $PeerIp, '-PeerPort', "$PeerPort", '-PingCount', '0')
if ($HoldSeconds -gt 0) { $argList += @('-HoldSeconds', "$HoldSeconds") }
if ($Wire)   { $argList += '-Wire' }
if ($Inject) { $argList += '-Inject' }
if ($NoInnerIp) { $argList += '-NoInnerIp' }
if ($GetOnly) { $argList += '-GetOnly' }

Tel ("=== 遥测启动：PeerIp={0} Hold={1}s Wire={2} Inject={3} ===" -f $PeerIp, $HoldSeconds, [bool]$Wire, [bool]$Inject)
Tel ("服务状态 = {0}" -f (Get-Service iwan -ErrorAction SilentlyContinue).Status)

$hb = Start-Job -ScriptBlock {
    param($ip, $p)
    $c = New-Object System.Net.Sockets.UdpClient
    $e = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($ip), $p)
    while ($true) {
        try { $b = [Text.Encoding]::UTF8.GetBytes('HB'); [void]$c.Send($b, $b.Length, $e) } catch { }
        Start-Sleep -Milliseconds 300
    }
} -ArgumentList $HostIp, $Port

try {
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\iwan\vm-rx.ps1') + $argList
    Tel ("启动 vm-rx.ps1 " + ($argList -join ' '))
    $p = Start-Process powershell -ArgumentList $a -RedirectStandardOutput C:\iwan\rx-out.txt -RedirectStandardError C:\iwan\rx-err.txt -PassThru -WindowStyle Hidden
    $seen = 0
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 400
        if (Test-Path C:\iwan\rx-out.txt) {
            $lines = @(Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -ErrorAction SilentlyContinue)
            while ($seen -lt $lines.Count) { Tel ("OUT " + $lines[$seen]); $seen++ }
        }
        $p.Refresh()
    }
    Tel ("vm-rx.ps1 已退出（代码 {0}）" -f $p.ExitCode)
    if (Test-Path C:\iwan\rx-out.txt) {
        $lines = @(Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -ErrorAction SilentlyContinue)
        while ($seen -lt $lines.Count) { Tel ("OUT " + $lines[$seen]); $seen++ }
    }
    if (Test-Path C:\iwan\rx-err.txt) {
        $errs = @(Get-Content C:\iwan\rx-err.txt -Encoding UTF8 -ErrorAction SilentlyContinue)
        foreach ($e in $errs) { Tel ("ERR " + $e) }
    }
} finally {
    Tel "遥测结束"
    Stop-Job $hb -ErrorAction SilentlyContinue
    Remove-Job $hb -Force -ErrorAction SilentlyContinue
    $u.Close()
}
