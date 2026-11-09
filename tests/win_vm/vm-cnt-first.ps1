# Exercise the first UDP datagram of fresh flows in both bridge directions.
# Both endpoints are explicit: an unbound sender could pass via local loopback.
param(
    [Parameter(Mandatory=$true)][string]$Src,
    [Parameter(Mandatory=$true)][string]$Dst,
    [ValidateRange(1,1000)][int]$Count = 20,
    [ValidateRange(1,1400)][int]$Bytes = 1200,
    [ValidateRange(100,10000)][int]$TimeoutMs = 1500,
    [ValidateRange(1024,65535)][int]$Port = 45679
)
$ErrorActionPreference = 'Stop'
$srcIp = [Net.IPAddress]::Parse($Src)
$dstIp = [Net.IPAddress]::Parse($Dst)
if ($srcIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $dstIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $Src -eq $Dst -or $Src -eq '0.0.0.0' -or $Dst -eq '0.0.0.0') {
    throw 'Use two distinct, explicit IPv4 addresses on separate adapters.'
}
$a = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Src)
$b = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Dst)
if ($a.Count -ne 1 -or $b.Count -ne 1 -or
    $a[0].InterfaceIndex -eq $b[0].InterfaceIndex) {
    throw 'The two endpoints must belong to different adapters.'
}
"FIRSTPATH src=$Src if=$($a[0].InterfaceIndex) dst=$Dst if=$($b[0].InterfaceIndex)"
$ok = 0
for ($i = 1; $i -le $Count; $i++) {
    $tx = New-Object Net.Sockets.UdpClient
    $rx = New-Object Net.Sockets.UdpClient
    try {
        $rx.Client.Bind([Net.IPEndPoint]::new($dstIp,$Port))
        $tx.Client.Bind([Net.IPEndPoint]::new($srcIp,0))
        $tx.Client.ReceiveTimeout = $TimeoutMs
        $rx.Client.ReceiveTimeout = $TimeoutMs
        $data = New-Object byte[] $Bytes
        for ($j = 0; $j -lt $Bytes; $j++) { $data[$j] = ($j + $i) -band 255 }
        [void]$tx.Send($data,$data.Length,$Dst,$Port)
        $peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $received = $rx.Receive([ref]$peer)
        if ($peer.Address.ToString() -ne $Src -or $received.Length -ne $Bytes -or
            [Convert]::ToBase64String($received) -ne [Convert]::ToBase64String($data)) {
            throw "Bad forward payload or source: $peer"
        }
        [void]$rx.Send($received,$received.Length,$peer)
        $reply = $tx.Receive([ref]$peer)
        if ($peer.Address.ToString() -ne $Dst -or $reply.Length -ne $Bytes -or
            [Convert]::ToBase64String($reply) -ne [Convert]::ToBase64String($data)) {
            throw "Bad reverse payload or source: $peer"
        }
        $ok++
        "FIRST trial=$i forward=1 reverse=1 bytes=$Bytes"
    } finally {
        $tx.Close()
        $rx.Close()
    }
}
"FIRSTRESULT fresh_flows=$Count forward=$ok reverse=$ok bytes=$Bytes"
