# 会话开着期间，客体到底还能不能通网：ICMP / TCP / UDP 三条路分别试，
# 结果写 COM1（宿主直接读串口日志，不依赖 ssh，也不依赖本驱动）。
param([int]$Seconds = 90, [string]$HostIp = '114.214.185.234',
      [int]$TcpPort = 45677, [int]$UdpPort = 45680)
function Ser([string]$t) {
    try {
        $sp = New-Object System.IO.Ports.SerialPort('COM1', 115200,
            [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One)
        $sp.Open(); $sp.WriteLine($t); $sp.Close()
    } catch { }
}
$end = (Get-Date).AddSeconds($Seconds)
Ser 'NETCHECK start'
while ((Get-Date) -lt $end) {
    $icmp = 'ERR'
    try { if (Test-Connection -ComputerName $HostIp -Count 1 -Quiet -ErrorAction Stop) { $icmp = 'OK' } else { $icmp = 'NO' } } catch { }
    $tcp = 'ERR'
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $ar = $c.BeginConnect($HostIp, $TcpPort, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(1500) -and $c.Connected) { $tcp = 'OK' } else { $tcp = 'NO' }
        $c.Close()
    } catch { }
    $udp = 'ERR'
    try {
        $u = New-Object System.Net.Sockets.UdpClient
        $b = [Text.Encoding]::ASCII.GetBytes('NETCHECK')
        [void]$u.Send($b, $b.Length, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($HostIp), $UdpPort)))
        $udp = 'SENT'; $u.Close()
    } catch { }
    Ser ("NETCHECK icmp={0} tcp={1} udp={2}" -f $icmp, $tcp, $udp)
    Start-Sleep -Seconds 3
}
Ser 'NETCHECK end'
