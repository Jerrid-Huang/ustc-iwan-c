# Open an iWAN synthetic session directly inside a Windows VM to validate the WFP data plane.
#
# Why bypass the client: what really needs proof is the kernel encapsulation/decapsulation path, not the control plane.
# Here we open the session directly via IOCTL, then do two things:
#   1) -Inject: build a valid outer UDP+iWAN frame locally and send it to ourselves (outer peer set to
#      the local address), verifying that the inbound callout intercepts after stack reassembly and injects after decap --
#      success means the inner UDP payload arrives on a socket bound to the inner address; the negative sample (bad tok) must not.
#      This test does not depend on the host: QEMU slirp does not deliver guest->host UDP to host sockets.
#   2) ping: inner ICMP, needs win_outer_peer.py on the host to reply (that path depends on slirp).
#
# Usage (administrator PowerShell):
#   .\vm-rx.ps1 -Inject -PeerIp 10.0.2.15 -PingCount 0
#
# Offsets come from the actual output of tests/win_abi_layout.c, not from hand calculation:
#   SESSION_OPEN 160 bytes (ABI 3): sid@8 tok@12 enc@16 key@17 outer_src@28 outer_dst@32
#     sport@36 dport@38 outer_src6@40 outer_dst6@56 flags@72 oif_index@76
#     bind_ip@80 bind_ip6@84 inner_ip@100 inner_ip6@104 inner_mtu@120
#     carrier_mtu@124 target_offset@128 target_count@132 outer_hop@136
#     outer_if_guid@144 (16 bytes, all 0 = pick carrier by index)
#   outer_hop is the outer next hop (0 = peer on link). The kernel does not do route lookup; this cell is
#   computed by the control plane with GetBestRoute2 before opening the session; the NDIS plane cannot send outer frames without it.
#   SESSION_INFO 200 bytes: enabled@16 effective_mtu@20 carrier_index@24 dev_owned@28
#     last_rx_ms@40 shm_section_size@48 shm_user_va@56 stats@64 (17 INT64s)
#   TARGET 24 bytes: family@0 prefix_len@4 addr@8

param(
    [string]$Adapter  = 'iWAN',
    [string]$InnerIp  = '10.99.0.1',
    [int]   $InnerPfx = 24,
    [string]$Target   = '10.99.0.2',
    [int]   $TargetFamily = 4,
    [string]$PeerIp   = '10.0.2.2',
    [string]$LocalIp  = '',
    [int]   $PeerPort = 45678,
    [string]$Key      = '0102030405060708',
    [int]   $Sid      = 0x1234,
    [long]  $Tok      = 0x12345678,
    [int]   $InnerMtu = 1400,
    [int]   $CarrierMtu = 1500,
    # The NDIS plane (iwanmp.sys) must explicitly specify the carrier NIC index (session open fails without it),
    # and the outer device name differs; the WFP plane uses the defaults.
    [string]$Device   = '\\.\iwan',
    # Each plane has its own service key (progress markers RunStage/RunWhat are written here).
    [string]$Service  = 'iwan',
    [int]   $OifIndex = 0,
    [int]   $OuterHop = 0,
    # Carrier NIC interface GUID (e.g. 414E4D50-4957-0000-A456-F83916FBFC14).
    # On the guest the two interface index schemes measurably disagree (Ethernet netio=7, protocol edge binding reports 23/26),
    # so picking the carrier by index is a guess; with a GUID the driver matches by GUID only. Empty string = fall back to index.
    [string]$OuterIfGuid = '',
    [int]   $PingCount = 3,
    [switch]$BindInner,
    [switch]$KeepOpen,
    [switch]$Inject,
# Open and hold a session only, run no self-tests. Wire test / replay both default under -Inject;
# at high rates they occupy the window and disturb the verdict (this happened), so give a clean switch.
[switch]$SkipSelfTest,
# Read the driver outbound-reject sample (shared page 0x100). The counter only says how many were rejected,
# not why -- when debugging all-UDP-rejected, guessing wasted a whole round.
[switch]$ShmDump,
    [switch]$Plaintext,
    [string]$InnerDst = '10.99.0.2',
    [int]   $InnerDstPort = 9999,
    [string]$InnerSrc = '10.99.0.1',
    [int]   $InnerSrcPort = 40001,
    [int]   $InjectWaitMs = 1500,
    [int]   $InjectCount = 1,
    [switch]$Wire,
    [int]   $HoldSeconds = 0,
    [switch]$NoInnerIp,
    [switch]$GetOnly
)

$ErrorActionPreference = 'Stop'

# ---------- ABI constants ----------
$DevType = 0x8331
function CtlCode([int]$func, [int]$access) {
    # PowerShell -shl overflows to negative on Int32: 0x83310000 becomes -2093899776,
    # and Invoke-Ioctl parameters are [uint32], so passing it throws a value-out-of-range UInt32 error.
    # Do all math in Int64, truncate to 32 bits, then cast to UInt32.
    [uint32]((([int64]$DevType -shl 16) -bor ([int64]$access -shl 14) -bor ([int64]$func -shl 2)) -band 0xFFFFFFFFL)
}
$IOCTL_OPEN  = CtlCode 0x800 2      # FILE_WRITE_DATA
$IOCTL_CLOSE = CtlCode 0x801 2
$IOCTL_GET   = CtlCode 0x802 1      # FILE_READ_DATA
$IOCTL_SHM   = CtlCode 0x803 1
$FLAG_BIND_INNER = 0x1

$STAT_NAMES = @('rx_pkts','rx_outer','rx_reasm','rx_frames','rx_delivered','rx_batch',
                'rx_batch_skip','rx_bad_hdr','rx_bad_inner','rx_nomem','rx_ctrl_frame',
                'tx_pkts','tx_bytes','tx_bad_state','tx_bad_inner','tx_err','ev_dropped')

# Progress markers: written to the service registry key (survives reboot); if the whole machine hangs, after reboot read RunStage
# to know how far the script got -- stdout is buffered, so the last lines are invisible when hung.
$RUNKEY = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service"
function Ser([string]$t) {
    # Serial is the only channel that goes through neither the network nor this driver: after the network is dead,
    # the host can still see from the serial log how far the script got. No exception may affect the main flow.
    try {
        $sp = New-Object System.IO.Ports.SerialPort('COM1', 115200,
            [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One)
        $sp.Open(); $sp.WriteLine($t); $sp.Close()
    } catch { }
}
function Mark([int]$n, [string]$what) {
    Write-Host ("  [mark {0}] {1}" -f $n, $what)
    Ser ("IWAN-MARK {0} {1}" -f $n, $what)
    try {
        New-ItemProperty -Path $RUNKEY -Name RunStage -PropertyType DWord -Value $n -Force | Out-Null
        New-ItemProperty -Path $RUNKEY -Name RunWhat -PropertyType String -Value $what -Force | Out-Null
    } catch { }
}

Add-Type -Namespace IWAN -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share,
    IntPtr sec, uint disp, uint flags, IntPtr templ);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, uint inSize,
    byte[] outBuf, uint outSize, out uint ret, IntPtr ov);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
'@

function Put-Bytes([byte[]]$b, [int]$off, [byte[]]$v) { [Array]::Copy($v, 0, $b, $off, $v.Length) }
function Put-U16([byte[]]$b, [int]$off, [int]$v) {
    $b[$off] = [byte](($v -shr 8) -band 0xFF); $b[$off+1] = [byte]($v -band 0xFF)   # be16
}
function Put-U16Host([byte[]]$b, [int]$off, [int]$v) {
    Put-Bytes $b $off ([BitConverter]::GetBytes([uint16]$v))                        # host byte order
}
function Put-U32Host([byte[]]$b, [int]$off, [long]$v) {
    Put-Bytes $b $off ([BitConverter]::GetBytes([uint32]$v))                        # host byte order
}
function Put-U32Be([byte[]]$b, [int]$off, [long]$v) {
    $b[$off]   = [byte](($v -shr 24) -band 0xFF); $b[$off+1] = [byte](($v -shr 16) -band 0xFF)
    $b[$off+2] = [byte](($v -shr 8) -band 0xFF);  $b[$off+3] = [byte]($v -band 0xFF)  # big endian
}
function Put-Ip4Net([byte[]]$b, [int]$off, [string]$ip) {
    Put-Bytes $b $off ([System.Net.IPAddress]::Parse($ip).GetAddressBytes())         # network byte order
}
function Get-Ip4Net([byte[]]$b, [int]$off) {
    ([System.Net.IPAddress]::new([byte[]]@($b[$off],$b[$off+1],$b[$off+2],$b[$off+3]))).ToString()
}
function Get-I64([byte[]]$b, [int]$off) { [BitConverter]::ToInt64($b, $off) }

function Dump-Stats([byte[]]$info, [string]$tag) {
    # Pure ASCII one-liner, easy for the host to parse (Chinese output garbles over ssh/redirection)
    $parts = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $parts += ("{0}={1}" -f $STAT_NAMES[$i], (Get-I64 $info (64 + 8*$i)))
    }
    $line = "STATS {0} {1}" -f $tag, ($parts -join ' ')
    Add-Content -Path C:\iwan\rx-stats.txt -Value $line -Encoding ASCII
    Write-Host $line
}

function Stats-Line([byte[]]$info) {
    $ps = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $v = Get-I64 $info (64 + 8*$i)
        if ($v -ne 0) { $ps += ("{0}={1}" -f $STAT_NAMES[$i], $v) }
    }
    $tail = if ($ps.Count) { $ps -join ' ' } else { '(all 0)' }
    "enabled={0} last_rx_ms={1} {2}" -f [BitConverter]::ToUInt32($info,16), `
        [BitConverter]::ToUInt32($info,40), $tail
}
function Show-Stats([byte[]]$info, [string]$title) {
    Write-Host "`n--- $title ---"
    Write-Host ("enabled={0} effective_mtu={1} carrier_index={2} dev_owned={3} last_rx_ms={4} shm={5}B" -f `
        [BitConverter]::ToUInt32($info,16), [BitConverter]::ToUInt32($info,20), `
        [BitConverter]::ToUInt32($info,24), [BitConverter]::ToUInt32($info,28), `
        [BitConverter]::ToUInt32($info,40), [BitConverter]::ToUInt32($info,48))
    $parts = @()
    for ($i = 0; $i -lt $STAT_NAMES.Count; $i++) {
        $v = Get-I64 $info (64 + 8*$i)
        if ($v -ne 0) { $parts += ("{0}={1}" -f $STAT_NAMES[$i], $v) }
    }
    if ($parts.Count) { Write-Host ("non-zero counts: " + ($parts -join ' ')) }
    else { Write-Host "non-zero counts: (all 0)" }
    Ser ("IWAN-STATS[{0}] {1}" -f $title, (Stats-Line $info))
}

function Show-ShmDiag([IntPtr]$h) {
    # Shared page layout: IWAN_WIN_SHM_OFF_DIAG in src/common/iwan_win_abi.h:
    # magic@0 reason@4 len@8 tot@12 pkt0@16 seq@20 first[16]@24
    try {
        $r = Invoke-Ioctl $h $IOCTL_SHM $null 200 'IOCTL_IWAN_SHM_QUERY'
        $va = Get-I64 $r 56
        if ($va -eq 0) { Write-Host 'DIAG shared page not mapped (SHM_QUERY returned 0)'; return }
        $b = New-Object byte[] 40
        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($va + 0x100), $b, 0, 40)
        $line = ("DIAG magic=0x{0:X8} seq={1} reason={2} len={3} tot={4} pkt0=0x{5:X2} first={6}" -f `
                 [BitConverter]::ToUInt32($b,0), [BitConverter]::ToUInt32($b,20),
                 [BitConverter]::ToUInt32($b,4), [BitConverter]::ToUInt32($b,8),
                 [BitConverter]::ToUInt32($b,12), [BitConverter]::ToUInt32($b,16),
                 [BitConverter]::ToString($b,24,16))
        Write-Host $line
        Ser ("IWAN-" + $line)
    } catch { Write-Host ("DIAG read failed: " + $_.Exception.Message) }
}

function Invoke-Ioctl([IntPtr]$h, [uint32]$code, [byte[]]$in, [int]$outSize, [string]$what) {
    $out = New-Object byte[] $outSize
    [uint32]$ret = 0
    $inSize = if ($in) { [uint32]$in.Length } else { [uint32]0 }
    $ok = [IWAN.Native]::DeviceIoControl($h, $code, $in, $inSize, $out, [uint32]$outSize, [ref]$ret, [IntPtr]::Zero)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ("{0} failed: Win32 error {1} ({2}), returned {3} bytes" -f $what, $err,
               (New-Object System.ComponentModel.Win32Exception($err)).Message, $ret)
    }
    Write-Host ("{0} succeeded, returned {1} bytes" -f $what, $ret)
    return $out
}

# ---------- Frame building: inner UDP datagram + outer UDP + iWAN header ----------
# Inner IPv4/UDP: IP header checksum computed; UDP checksum left 0 (IPv4 allows no checksum, the stack accepts it).
function Build-InnerUdp([string]$srcIp, [int]$srcPort, [string]$dstIp, [int]$dstPort, [string]$text) {
    $payload = [Text.Encoding]::ASCII.GetBytes($text)
    $len = 20 + 8 + $payload.Length
    $b = New-Object byte[] $len
    $b[0] = 0x45
    $b[2] = [byte](($len -shr 8) -band 0xFF); $b[3] = [byte]($len -band 0xFF)
    $b[8] = 64
    $b[9] = 17
    Put-Ip4Net $b 12 $srcIp
    Put-Ip4Net $b 16 $dstIp
    Put-U16 $b 20 $srcPort
    Put-U16 $b 22 $dstPort
    Put-U16 $b 24 (8 + $payload.Length)
    [Array]::Copy($payload, 0, $b, 28, $payload.Length)
    $sum = 0
    for ($i = 0; $i -lt 20; $i += 2) { $sum += ([int]$b[$i] -shl 8) -bor [int]$b[$i+1] }
    while ($sum -shr 16) { $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
    $sum = (-bnot $sum) -band 0xFFFF
    $b[10] = [byte](($sum -shr 8) -band 0xFF); $b[11] = [byte]($sum -band 0xFF)
    return $b
}

# Outer = UDP header + 8-byte iWAN frame header + [XORed] inner packet.
# Frame header: fh[0]=type fh[1]=enc fh[2..3]=sid (big endian) fh[4..7]=tok (big endian).
# XOR covers only the inner packet, from inner offset 0, byte by byte with key[i & 7] (same as driver iwan_win_xor).
function Build-OuterFrame([byte[]]$inner, [int]$srcPort, [int]$dstPort, [int]$type,
                          [int]$enc, [int]$sid, [long]$tok, [byte[]]$key) {
    $body = New-Object byte[] $inner.Length
    [Array]::Copy($inner, 0, $body, 0, $inner.Length)
    if ($enc) { for ($i = 0; $i -lt $body.Length; $i++) { $body[$i] = $body[$i] -bxor $key[$i % 8] } }
    $fl = 8 + $body.Length          # frame length (including header)
    $total = 8 + $fl                # UDP header + frame
    $f = New-Object byte[] $total
    Put-U16 $f 0 $srcPort
    Put-U16 $f 2 $dstPort
    Put-U16 $f 4 $total
    $f[8] = [byte]$type
    $f[9] = [byte]$enc
    Put-U16 $f 10 $sid
    Put-U32Be $f 12 $tok
    [Array]::Copy($body, 0, $f, 16, $body.Length)
    return $f
}

# Replay: the positive sample (correct credentials) must make the inner payload appear on $InnerDst:$InnerDstPort;
# the negative sample (tok+1) must be dropped -- otherwise the verdict gate never worked.
function Invoke-InjectTest([string]$SrcIp, [int]$SrcPort, [string]$DstIp, [int]$DstPort,
                           [int]$Type, [bool]$Enc, [int]$Sid, [long]$Tok, [byte[]]$Key,
                           [string]$ISrc, [int]$ISrcPort, [string]$IDst, [int]$IDstPort,
                           [int]$WaitMs, [int]$Count = 1) {
    $inner = Build-InnerUdp $ISrc $ISrcPort $IDst $IDstPort 'IWAN-INNER-OK'
    $script:h = $h
    $rx = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $IDstPort))
    $rx.Client.ReceiveTimeout = $WaitMs
    $tx = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($SrcIp), $SrcPort))
    $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($DstIp), $DstPort)
    $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    try {
        $bad = Build-OuterFrame $inner $SrcPort $DstPort $Type $Enc $Sid ($Tok + 1) $Key
        [void]$tx.Send($bad, $bad.Length, $ep)
        Write-Host ("  negative sample sent: {0} bytes (tok+1, should be swallowed)" -f $bad.Length)
        Start-Sleep -Milliseconds 300
        try {
            $d = $rx.Receive([ref]$from)
            Write-Host ("  negative sample unexpectedly delivered inner {0} bytes -- verdict gate failed!" -f $d.Length)
        } catch { Write-Host "  negative sample delivered no inner packet (correct)" }

        $good = Build-OuterFrame $inner $SrcPort $DstPort $Type $Enc $Sid $Tok $Key
        Write-Host ("  positive sample {0} bytes ({1}:{2} -> {3}:{4}, frame type 0x{5:X2} enc={6}, inner {7} bytes), sending {8} times" -f `
            $good.Length, $SrcIp, $SrcPort, $DstIp, $DstPort, $Type, [int]$Enc, $inner.Length, $Count)
        for ($k = 1; $k -le $Count; $k++) {
            [void]$tx.Send($good, $good.Length, $ep)
            if ($k % 5 -eq 0) {
                $st = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(delta)'
                Write-Host ("    sent {0} times: rx_reasm={1} rx_batch={2} rx_batch_skip={3} rx_outer={4} rx_delivered={5} rx_bad_hdr={6}" -f `
                    $k, (Get-I64 $st 64+8*2), (Get-I64 $st 64+8*5), (Get-I64 $st 64+8*6), (Get-I64 $st 64+8*1), (Get-I64 $st 64+8*4), (Get-I64 $st 64+8*7))
            }
            Start-Sleep -Milliseconds 60
        }
        try {
            $d = $rx.Receive([ref]$from)
            Write-Host ("  inner delivered: {0} bytes, from {1}:{2}, payload '{3}'" -f `
                $d.Length, $from.Address, $from.Port, [Text.Encoding]::ASCII.GetString($d))
        } catch { Write-Host "  inner not delivered (timeout) -- inbound decap/inject failed" }
    } finally { $rx.Close(); $tx.Close() }
}

# ---------- 0. Preflight checks ----------
Write-Host "IOCTL: OPEN=$('0x{0:X8}' -f $IOCTL_OPEN) CLOSE=$('0x{0:X8}' -f $IOCTL_CLOSE) GET=$('0x{0:X8}' -f $IOCTL_GET)"

$svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
if (-not $svc) { throw "service $Service not found: load its driver first" }
Write-Host ("service {0}: {1}, driver file {2}" -f $Service, $svc.Status, (Get-ItemProperty $RUNKEY -Name ImagePath -ErrorAction SilentlyContinue).ImagePath)

$nic = Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
if (-not $nic) { throw "carrier/inner NIC $Adapter not found: run vm-net.ps1 first" }
Write-Host ("NIC {0}: {1}, ifIndex={2}" -f $Adapter, $nic.Status, $nic.ifIndex)

$have = Get-NetIPAddress -InterfaceAlias $Adapter -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $InnerIp }
if (-not $have) {
    Write-Host "assigning inner address $InnerIp/$InnerPfx to $Adapter"
    New-NetIPAddress -InterfaceAlias $Adapter -IPAddress $InnerIp -PrefixLength $InnerPfx | Out-Null
} else { Write-Host "inner address already exists: $InnerIp/$InnerPfx" }

# Outer source address: defaults to the address of the NIC with the default route; -LocalIp overrides it.
# Must override for guest-internal loopback carrier: the outer destination is the carrier NIC own address, so if the source
# is taken from the default-route NIC (10.0.2.15), ARP becomes a cross-subnet question to our own address, and Windows
# does not answer such ARP (measured T93=13 requests, T94=0 replies).
$localIp = $LocalIp
if (-not $localIp) { $localIp = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 |
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1).IPAddress
}
if (-not $localIp) { $localIp = (Get-NetIPAddress -AddressFamily IPv4 |
                                Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
                                Select-Object -First 1).IPAddress }
if (-not $localIp) { throw "outer source address not found" }
Write-Host "outer source address: $localIp -> peer $PeerIp`:$PeerPort"

# ---------- 1. Build SESSION_OPEN + TARGET ----------
$keyBytes = New-Object byte[] 8
for ($i = 0; $i -lt 8; $i++) { $keyBytes[$i] = [Convert]::ToByte($Key.Substring(2*$i, 2), 16) }

$targets = New-Object byte[] 24
Put-U32Host $targets 0 $TargetFamily
Put-U32Host $targets 4 32
Put-Ip4Net  $targets 8 $Target

$req = New-Object byte[] 160
Put-U32Host $req 0  3        # abi_version (ABI 3 and later carries outer_if_guid)
Put-U32Host $req 4  160
Put-U16Host $req 8  $Sid    # sid/tok are host-order fields (addresses and ports are network order)
Put-U32Host $req 12 $Tok
$req[16] = if ($Plaintext) { 0 } else { 1 }   # enc
Put-Bytes   $req 17 $keyBytes
Put-Ip4Net  $req 28 $localIp                  # outer_src (network byte order)
Put-Ip4Net  $req 32 $PeerIp                   # outer_dst
$sportValue = 40000 + ($Sid % 1000)
Put-U16     $req 36 $sportValue               # sport
Put-U16     $req 38 $PeerPort                 # dport
$flags = 0
if ($BindInner) { $flags = $flags -bor $FLAG_BIND_INNER }
Put-U32Host $req 72 $flags
Put-U32Host $req 76 $OifIndex        # oif_index (must be non-zero for the NDIS plane)
Put-Ip4Net  $req 80 $localIp                  # bind_ip
if ($NoInnerIp) { Write-Host 'inner_ip left 0 (mirrors the real client kernel plane: kdp_win never fills this field)' }
else { Put-Ip4Net  $req 100 $InnerIp }          # inner_ip
Put-U32Host $req 120 $InnerMtu
Put-U32Host $req 124 $CarrierMtu
Put-U32Host $req 128 160                      # target_offset
Put-U32Host $req 132 1                        # target_count
Put-U32Host $req 136 $OuterHop                # outer_hop (0 = peer on link)
if ($OuterIfGuid) {
    # .NET Guid.ToByteArray() is exactly the Windows in-memory GUID layout
    # (first three parts little endian, fourth part original order), same as ConvertInterfaceLuidToGuid.
    $gb = ([System.Guid]::Parse($OuterIfGuid)).ToByteArray()
    [Array]::Copy($gb, 0, $req, 144, 16)
    Write-Host ("carrier GUID: {0}" -f $OuterIfGuid)
}

$inBuf = New-Object byte[] ($req.Length + $targets.Length)
[Array]::Copy($req, 0, $inBuf, 0, $req.Length)
[Array]::Copy($targets, 0, $inBuf, $req.Length, $targets.Length)
Write-Host ("request: {0} bytes (struct 160 + target 1x24), sid={1} tok={2} target {3}/{4} outer {5}:{6}->{7}" -f `
    $inBuf.Length, $Sid, $Tok, $Target, $TargetFamily, $localIp, $sportValue, $PeerPort)

# ---------- 2. Open device, open session ----------
$h = [IWAN.Native]::CreateFileW($Device, [uint32]3221225472, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]::new(-1)) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ("open {2} failed: Win32 error {0} ({1}) -- are you running as administrator?" -f $err,
           (New-Object System.ComponentModel.Win32Exception($err)).Message, $Device)
}
Write-Host "`nopened $Device"

if ($GetOnly) {
    # Open device + one harmless IOCTL (GET), never IOCTL_OPEN:
    # used to separate CreateFileW/dispatch from wfp_start registration.
    Mark 30 'GetOnly: no session, just IOCTL_GET'
    $info0 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(no session)'
    Mark 31 'GetOnly: IOCTL_GET returned'
    Write-Host ("enabled={0} effective_mtu={1} carrier_index={2} last_rx_ms={3}" -f `
        ([BitConverter]::ToUInt32($info0, 16)), ([BitConverter]::ToUInt32($info0, 20)),
        ([BitConverter]::ToUInt32($info0, 24)), ([BitConverter]::ToUInt32($info0, 40)))
    # 17 INT64 counters (ABI 3: STATS at SESSION_INFO offset 64, 136 bytes total)
    $names = @('rx_pkts','rx_outer','rx_reasm','rx_frames','rx_delivered',
               'rx_batch','rx_batch_skip','rx_bad_hdr','rx_bad_inner','rx_nomem',
               'rx_ctrl_frame','tx_pkts','tx_bytes','tx_bad_state','tx_bad_inner',
               'tx_err','ev_dropped')
    $parts = @()
    for ($i = 0; $i -lt $names.Count; $i++) {
        $parts += ('{0}={1}' -f $names[$i], [BitConverter]::ToInt64($info0, 64 + 8 * $i))
    }
    Write-Host ("STATS " + ($parts -join ' '))
    Write-Host 'GetOnly done'
    return
}

try {
    Mark 40 'about to send IOCTL_IWAN_SESSION_OPEN'
    $null = Invoke-Ioctl $h $IOCTL_OPEN $inBuf 200 'IOCTL_IWAN_SESSION_OPEN'
    Mark 41 'IOCTL_OPEN returned'
    Ser 'IWAN-OPEN-RETURNED'
    Mark 42 'about to send IOCTL_GET'
    $info1 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Mark 43 'IOCTL_GET returned'
    Dump-Stats $info1 'after-open'
    Show-Stats $info1 'after open'

    if ($Inject -and -not $SkipSelfTest) {
        $encFlag = -not $Plaintext
        $frameType = if ($encFlag) { 0x18 } else { 0x14 }
        Write-Host ("`n--- inbound replay: local frames, {0}:{1} -> {2}:{3} (peer address {4}) ---" -f `
            $localIp, $PeerPort, $localIp, $sportValue, $PeerIp)
        if ($PeerIp -ne $localIp) {
            Write-Host ("  NOTE: -PeerIp($PeerIp) differs from local address ($localIp), the frame source will not be the session outer peer and the inbound gate will reject it.")
        }
        if (-not $Wire) {
            Mark 44 'about to replay local frames'
            Invoke-InjectTest -SrcIp $localIp -SrcPort $PeerPort -DstIp $localIp -DstPort $sportValue `
                -Type $frameType -Enc $encFlag -Sid $Sid -Tok $Tok -Key $keyBytes `
                -ISrc $InnerSrc -ISrcPort $InnerSrcPort -IDst $InnerDst -IDstPort $InnerDstPort `
                -WaitMs $InjectWaitMs -Count $InjectCount
        }
        if ($Wire) {
            Mark 50 'about to send handshake to host'
            # Must send from the session sport: slirp records NAT mappings per host-side socket,
            # and the peer replies to this source port, so replies land back on local 40660 (= session sport),
            # otherwise the driver inbound gate destination port does not match.
            $hs = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($localIp), $sportValue))
            $hb = [Text.Encoding]::ASCII.GetBytes('IWAN-HELLO')
            # Build the NAT mapping first: send a few times so the peer learns the reply address
            for ($i = 0; $i -lt 3; $i++) {
                [void]$hs.Send($hb, $hb.Length, $PeerIp, $PeerPort)
                Start-Sleep -Milliseconds 200
            }
            Write-Host ("  handshake sent from {0}:{1} to {2}:{3} (peer now knows the reply address)" -f $localIp, $sportValue, $PeerIp, $PeerPort)
            # Control: also send a plain UDP datagram from an ephemeral port. Comparing arrival tells
            # "all outbound UDP is dead once the session opens" apart from "only the outer port is special".
            $ps = New-Object System.Net.Sockets.UdpClient
            $pb = [Text.Encoding]::ASCII.GetBytes('IWAN-PLAIN')
            $pn = $ps.Send($pb, $pb.Length, $PeerIp, $PeerPort)
            Write-Host ("  control: sent plain UDP {1} bytes from ephemeral port {0}" -f $ps.Client.LocalEndPoint.Port, $pn)
            $ps.Close()
            # $hs must not be closed here: the retry loop below still needs it. If closed, the first Send throws
            # ObjectDisposedException, the wire test aborts, and its stats cannot be collected (this happened).
            Mark 51 'handshake sent, waiting for peer replay'
            # Inner receiver: decapped/injected inner packets are sent to InnerDst:InnerDstPort
            $rxw = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $InnerDstPort))
            $rxw.Client.ReceiveTimeout = 3000
            Write-Host ("  listening on inner {0}:{1}, waiting for peer replay..." -f $InnerDst, $InnerDstPort)
            $got = $false
            $fw = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            # Keep sending HELLO to hold the mapping while receiving inner; total window 24 seconds
            # The same socket (bound to the session sport) can both send and receive: first confirm whether outer frames
            # reach the guest at all. If not -> wire path problem; if yes but no inner delivery -> driver inbound did not intercept.
            $hs.Client.ReceiveTimeout = 1500
            for ($round = 1; $round -le 8 -and -not $got; $round++) {
                try { [void]$hs.Send($hb, $hb.Length, $PeerIp, $PeerPort) } catch { }
                $outer = 0
                $first = '(none)'
                $fwo = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                try {
                    while ($true) {
                        $do = $hs.Receive([ref]$fwo)
                        $outer++
                        if ($outer -eq 1) {
                            $first = ("{0} bytes from {1}:{2}" -f $do.Length, $fwo.Address, $fwo.Port)
                        }
                    }
                } catch { }
                try {
                    $dw = $rxw.Receive([ref]$fw)
                    $got = $true
                    Write-Host ("  inner delivered: {0} bytes, from {1}:{2}, payload '{3}'" -f `
                        $dw.Length, $fw.Address, $fw.Port, [Text.Encoding]::ASCII.GetString($dw))
                } catch {
                    Write-Host ("  round {0}: {1} outer arrived (first {2}); inner not yet" -f $round, $outer, $first)
                }
            }
            if (-not $got) { Write-Host "  inner never delivered -- inbound decap/inject failed" }
            $rxw.Close()
            $hs.Close()
            Mark 52 'wire wait finished'
            $infoW = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(wire)'
            Mark 53 'wire stats collected'
            Dump-Stats $infoW 'after-wire'
            Show-Stats $infoW 'after wire test'
        }
        Mark 45 'replay done, about to collect stats'
        $infoI = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
        Mark 46 'stats collected'
        Show-Stats $infoI 'after replay'
    }

    if ($PingCount -gt 0) {
        Write-Host "`n--- ping $Target (inner ICMP, should be encapsulated and replied by the host peer) ---"
        & ping.exe -4 -n $PingCount -w 2000 $Target
        Write-Host ("ping exit code {0}" -f $LASTEXITCODE)
    }

    $info2 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
    Dump-Stats $info2 'final'
    Show-Stats $info2 'after replay/ping'
    if ($ShmDump) { Show-ShmDiag $h }

    if ($HoldSeconds -gt 0) {
        Mark 60 ("session held {0} seconds (checks: does the network break during this time, and does it recover)" -f $HoldSeconds)
        $left = $HoldSeconds
        while ($left -gt 0) {
            Start-Sleep -Seconds 5
            $left -= 5
            try {
                $inf = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET(holding)'
                Ser ("IWAN-LIVE t={0}s {1}" -f ($HoldSeconds - $left), (Stats-Line $inf))
            } catch {
                Ser ("IWAN-LIVE IOCTL_GET failed: " + $_.Exception.Message)
            }
        }
        Mark 61 'hold finished'
        # The hold window is usually when traffic runs (probes/peer replays happen then), so take another reading
        # after it ends: the final line is a snapshot **before traffic**, and using it as the conclusion gives
        # the wrong verdict "all counters zero = driver did nothing" (this happened once).
        $info3 = Invoke-Ioctl $h $IOCTL_GET $null 200 'IOCTL_IWAN_SESSION_GET'
        Dump-Stats $info3 'after-hold'
        Show-Stats $info3 'after hold ended'
        if ($ShmDump) { Show-ShmDiag $h }
    }
    if (-not $KeepOpen) {
        Mark 47 'about to CLOSE'
        $null = Invoke-Ioctl $h $IOCTL_CLOSE $null 0 'IOCTL_IWAN_SESSION_CLOSE'
        Mark 48 'CLOSE returned'
    } else { Write-Host "`nkeeping session open (-KeepOpen)" }
} finally {
    [void][IWAN.Native]::CloseHandle($h)
    Write-Host "closed device handle"
}
