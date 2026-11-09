# Count complete native / WFP encapsulation / pass-through runs on one guest.
# Use after vm-cnt-first.ps1 proves the explicitly bound bridge path.
# No client process or keepalive is used: IOCTL establishes a data-plane session.
param(
    [Parameter(Mandatory=$true)][string]$CarrierIp,
    [Parameter(Mandatory=$true)][string]$PeerIp,
    [string]$InnerIp='198.18.0.2',
    [Parameter(Mandatory=$true)][string]$GenIp,
    [string]$Target='8.8.8.8',
    [string]$InnerAdapter='iWAN',
    [string]$DriverService='iwan',
    [ValidateRange(32,1300)][int]$Bytes=1200,
    [ValidateRange(1,16)][int]$Threads=1,
    [ValidateRange(1,30)][int]$Seconds=4,
    [ValidateRange(0,1000000)][int]$Pps=10000,
    [string]$Root='C:\iwan'
)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class IwanTaxIo {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr h,uint code,IntPtr ib,uint il,byte[] ob,uint ol,out uint n,IntPtr ov);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    static byte[] Call(uint code,int size) {
        IntPtr h=CreateFileW(@"\\.\iwan",0xC0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
        if(h==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            byte[] b=new byte[size]; uint n;
            if(!DeviceIoControl(h,code,IntPtr.Zero,0,b,(uint)size,out n,IntPtr.Zero)) {
                int error=Marshal.GetLastWin32Error();
                // SESSION_GET returns STATUS_INVALID_DEVICE_STATE (Win32 22)
                // when no session exists. This is the native-baseline state.
                if(code==0x83316008 && error==22) return b;
                throw new Win32Exception(error);
            }
            if(size>0 && n!=size) throw new Exception("short SESSION_GET");
            return b;
        } finally { CloseHandle(h); }
    }
    public static byte[] Get() { return Call(0x83316008,200); }
    public static void Close() { Call(0x8331A004,0); }
}
'@
function Stats {
    $b=[IwanTaxIo]::Get()
    return @{ Enabled=[BitConverter]::ToUInt32($b,16); Tx=[BitConverter]::ToInt64($b,152);
              Busy=[BitConverter]::ToInt64($b,168); Bad=[BitConverter]::ToInt64($b,176);
              Err=[BitConverter]::ToInt64($b,184) }
}
function Wait-Ready($p,[string]$file,[string]$pattern) {
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        $p.Refresh()
        if ($p.HasExited) { throw "Process exited before ready: $file" }
        if ((Test-Path $file) -and (Select-String -Path $file -Pattern $pattern -Quiet)) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Readiness timeout: $file"
}
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$dir=Join-Path $Root ('cnt-ab-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
"TAXLOGS path=$dir"
$ca=Get-NetIPAddress -AddressFamily IPv4 -IPAddress $CarrierIp
$pa=Get-NetIPAddress -AddressFamily IPv4 -IPAddress $PeerIp
if ($ca.InterfaceIndex -eq $pa.InterfaceIndex) { throw 'Carrier and peer must be on separate adapters' }
$key='HKLM:\SYSTEM\CurrentControlSet\Services\iwan\Parameters'
$prior=Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
$hadPass=$prior -and ($prior.PSObject.Properties.Name -contains 'PassThrough')
$oldPass=if($hadPass){$prior.PassThrough}else{0}
$svc=Get-Service $DriverService
$started=$svc.Status -ne 'Running'
$owned=$false
$rule='IwanCntAb-'+[Guid]::NewGuid().ToString('N')
$peer=$null
try {
    if ($started) { Start-Service $DriverService }
    if ((Stats).Enabled -ne 0) { throw 'An existing WFP session is active; refusing to replace it' }
    New-Item -Path $key -Force | Out-Null
    New-NetFirewallRule -Name $rule -DisplayName 'iWAN isolated bridge measurement' -Direction Inbound -Action Allow -Protocol UDP -LocalAddress $CarrierIp,$PeerIp -RemoteAddress $CarrierIp,$PeerIp -InterfaceAlias $ca.InterfaceAlias,$pa.InterfaceAlias -Profile Any | Out-Null
    foreach ($mode in 'native','encap','pass') {
        if ($mode -ne 'native') {
            $pass=if($mode -eq 'pass'){1}else{0}
            New-ItemProperty -Path $key -Name PassThrough -PropertyType DWord -Value $pass -Force | Out-Null
            $openArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $Root 'vm-rx.ps1'),'-Service',$DriverService,'-Adapter',$InnerAdapter,'-InnerIp',$InnerIp,'-LocalIp',$CarrierIp,'-PeerIp',$PeerIp,'-Target',$Target,'-PingCount','0','-SkipSelfTest','-KeepOpen')
            $op=Start-Process powershell.exe -ArgumentList $openArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir "$mode.open.out") -RedirectStandardError (Join-Path $dir "$mode.open.err")
            $null=$op.Handle
            if (-not $op.WaitForExit(20000)) { Stop-Process -Id $op.Id; throw 'Session setup timeout' }
            if ($op.ExitCode -ne 0) { throw "Session setup failed: $dir" }
            $owned=$true
            if ((Stats).Enabled -ne 1) { throw 'Session not enabled' }
        }
        $so=Join-Path $dir "$mode.sink.out"
        $go=Join-Path $dir "$mode.gen.out"
        $peer=Start-Process (Join-Path $Root 'win_sink.exe') -ArgumentList @('-B',$PeerIp,'-p','45678','-S',($Seconds+5)) -PassThru -WindowStyle Hidden -RedirectStandardOutput $so -RedirectStandardError (Join-Path $dir "$mode.sink.err")
        $null=$peer.Handle
        Wait-Ready $peer $so '^SINK ready'
        $dst=if($mode -eq 'native'){$PeerIp}else{$Target}
        $src=if($mode -eq 'native'){$CarrierIp}else{$GenIp}
        $size=if($mode -eq 'native'){$Bytes+36}else{$Bytes}
        $port=if($mode -eq 'native'){45678}else{9999}
        $gen=Start-Process (Join-Path $Root 'win_gen.exe') -ArgumentList @('-B',$src,'-d',$dst,'-p',$port,'-b',$size,'-t',$Threads,'-S',$Seconds,'-r',$Pps) -PassThru -WindowStyle Hidden -RedirectStandardOutput $go -RedirectStandardError (Join-Path $dir "$mode.gen.err")
        $null=$gen.Handle
        if (-not $gen.WaitForExit(($Seconds+10)*1000)) { Stop-Process -Id $gen.Id; throw 'Generator timeout' }
        if ($gen.ExitCode -ne 0) { throw 'Generator failed' }
        if (-not $peer.WaitForExit(10000)) { throw 'Sink did not produce final counters' }
        if ($peer.ExitCode -ne 0) { throw 'Sink failed' }
        $peer=$null
        $g=(Select-String -Path $go -Pattern '^GEN pkts=' | Select-Object -Last 1).Line
        $s=(Select-String -Path $so -Pattern '^SINK pkts=' | Select-Object -Last 1).Line
        if (-not $g -or -not $s) { throw "Missing final counters: $dir" }
        if ($g -notmatch ' err=0$' -or $s -notmatch ' err=0$') { throw "Traffic tool reported an error: $dir" }
        $st=if($owned){Stats}else{@{Tx=0;Busy=0;Bad=0;Err=0}}
        if ($owned -and $st.Enabled -ne 1) { throw 'Session disappeared during traffic' }
        "TAX mode=$mode payload=$Bytes threads=$Threads pps_target=$Pps tx=$($st.Tx) busy=$($st.Busy) bad=$($st.Bad) err=$($st.Err)"
        $g
        $s
        if ($g -notmatch 'pkts=(\d+)') { throw 'No generator packet count' }
        $sent=[long]$Matches[1]
        if ($s -notmatch 'pkts=(\d+)') { throw 'No sink packet count' }
        $received=[long]$Matches[1]
        if ($sent -eq 0) { throw 'Generator sent no packets' }
        if ($mode -eq 'native' -and $received -eq 0) { throw 'Native bridge delivered no packets' }
        if ($mode -eq 'encap' -and $st.Tx -eq 0) { throw 'No packet entered encapsulation' }
        if ($mode -eq 'pass' -and ($st.Tx -ne $sent -or $received -ne 0)) { throw 'Pass-through count mismatch' }
        if ($owned) { [IwanTaxIo]::Close(); $owned=$false }
    }
    if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime -ne $boot) { throw 'Guest restarted during measurement' }
    "TAXRESULT logs=$dir boot=$($boot.ToString('s'))"
} finally {
    if ($peer -and -not $peer.HasExited) { Stop-Process -Id $peer.Id }
    if ($owned) { [IwanTaxIo]::Close() }
    Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
    if ($hadPass) { New-ItemProperty -Path $key -Name PassThrough -PropertyType DWord -Value $oldPass -Force | Out-Null }
    else { Remove-ItemProperty -Path $key -Name PassThrough -ErrorAction SilentlyContinue }
    if ($started) { Stop-Service $DriverService }
}
