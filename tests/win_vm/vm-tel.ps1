# 把测试过程实时发到宿主（UDP 45679）：虚拟机一旦卡死，ssh 和 guest 磁盘日志都可能丢，
# 但"什么时候断流"这件事只有宿主能看到。
param(
    [string]$TestArgs = '-PeerIp 10.0.2.15 -PingCount 0',
    [string]$HostIp   = '114.214.185.234',
    [int]   $Port     = 45679
)
$ErrorActionPreference = 'Continue'
$u = New-Object System.Net.Sockets.UdpClient
$ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($HostIp), $Port)
function Tel([string]$msg) {
    $line = "GUEST {0} {1}" -f (Get-Date).ToString('HH:mm:ss.fff'), $msg
    try { $b = [Text.Encoding]::UTF8.GetBytes($line); [void]$u.Send($b, $b.Length, $ep) } catch { }
    Write-Host $line
}
Tel "=== 遥测启动，测试参数：$TestArgs ==="
Tel ("服务状态 = {0}" -f (Get-Service iwan -ErrorAction SilentlyContinue).Status)

# 心跳：后台任务每 300ms 发一次，卡死时宿主立刻能看到断流
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
    Tel "启动 vm-rx.ps1 ..."
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\iwan\vm-rx.ps1') + ($TestArgs -split ' ')
    $p = Start-Process powershell -ArgumentList $a -RedirectStandardOutput C:\iwan\rx-out.txt -RedirectStandardError C:\iwan\rx-err.txt -PassThru -WindowStyle Hidden
    # 轮询输出文件，把新增行实时转发给宿主
    $seen = 0
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 400
        if (Test-Path C:\iwan\rx-out.txt) {
            $lines = @(Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -ErrorAction SilentlyContinue)
            while ($seen -lt $lines.Count) {
                Tel ("OUT " + $lines[$seen])
                $seen++
            }
        }
        $p.Refresh()
    }
    Tel ("vm-rx.ps1 退出，代码 = {0}" -f $p.ExitCode)
    if (Test-Path C:\iwan\rx-out.txt) {
        $lines = @(Get-Content C:\iwan\rx-out.txt -Encoding UTF8 -ErrorAction SilentlyContinue)
        while ($seen -lt $lines.Count) { Tel ("OUT " + $lines[$seen]); $seen++ }
    }
} finally {
    Tel "遥测结束"
    Stop-Job $hb -ErrorAction SilentlyContinue
    Remove-Job $hb -Force -ErrorAction SilentlyContinue
    $u.Close()
}
