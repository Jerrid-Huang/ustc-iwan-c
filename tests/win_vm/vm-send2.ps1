# 从指定源端口往宿主真实地址发 UDP —— 用来验证 slirp 的 NAT 映射与端口选择。
param([string]$Dst='114.214.185.234', [int]$Port=45678, [int]$SrcPort=40660, [string]$Text='probe')
$ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $SrcPort)
$u = [System.Net.Sockets.UdpClient]::new($ep)
$b = [Text.Encoding]::ASCII.GetBytes($Text)
$n = $u.Send($b, $b.Length, $Dst, $Port)
"sent=$n from port $SrcPort to ${Dst}:${Port}"
$u.Close()
