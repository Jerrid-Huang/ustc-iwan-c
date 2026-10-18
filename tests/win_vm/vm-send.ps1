# 从虚拟机往宿主真实地址发一个普通 UDP，验证 slirp 是否把 guest->host 的 UDP 交给宿主套接字。
param([string]$Dst = '114.214.185.234', [int]$Port = 45678, [string]$Text = 'hello-from-guest')
$u = New-Object System.Net.Sockets.UdpClient
$b = [Text.Encoding]::ASCII.GetBytes($Text)
$n = $u.Send($b, $b.Length, $Dst, $Port)
"sent=$n to ${Dst}:${Port}"
$u.Close()
