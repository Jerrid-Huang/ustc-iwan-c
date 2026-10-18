# 线测的"发信器"：从客体 10.0.2.15:40660 往宿主对端 45678 每 2 秒发一个报文。
# 目的只有一个 —— 在 slirp 里建立映射，好让对端把构造好的外层帧回灌到客体；
# 内容对驱动不重要，重要的是源端口 40660 与外层对端 114.214.185.234 匹配得上。
param([string]$LocalIp = '10.0.2.15', [int]$LocalPort = 40660,
      [string]$PeerIp = '114.214.185.234', [int]$PeerPort = 45678, [int]$Seconds = 60)
$u = New-Object System.Net.Sockets.UdpClient
$u.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIp), $LocalPort)))
$ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($PeerIp), $PeerPort)
$b = [Text.Encoding]::ASCII.GetBytes('IWAN-WIRE-HELLO')
$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $end) {
    try { [void]$u.Send($b, $b.Length, $ep) } catch { }
    Start-Sleep -Seconds 2
}
$u.Close()
