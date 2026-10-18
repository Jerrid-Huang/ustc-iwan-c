# 在 nano11 虚拟机里签名并加载 iwan.sys —— 只做"能不能装上、能不能起来"的判定。
#
# 前提：testsigning 已经是 Yes（虚拟机已具备），Administrator 已提权。
# 这个脚本不装任何工具链，只用系统自带能力：
#   New-SelfSignedCertificate  造一张代码签名证书
#   Set-AuthenticodeSignature  给 .sys 做内嵌 Authenticode 签名
#   sc.exe                     以"内核服务"方式创建并启动（非 PnP，不需要 INF）
#
# 用法：powershell -NoProfile -File vm-load.ps1 -SysPath C:\iwan\iwan.sys
param(
    [string]$SysPath = 'C:\iwan\iwan.sys',
    [string]$ServiceName = 'iwan',
    [string]$CertSubject = 'CN=iwan win-driver test'
)

$ErrorActionPreference = 'Stop'

function Sec($t) { "`n=== $t ===" }

if (-not (Test-Path $SysPath)) { throw "找不到 $SysPath" }
$sys = (Resolve-Path $SysPath).Path
Sec "驱动文件"
Get-Item $sys | Select-Object FullName, Length, LastWriteTime | Format-List

# 1) 证书：自签一张代码签名证书，公钥进 Root + TrustedPublisher（测试签名的要求）
Sec '证书'
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CertSubject `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
            -KeyLength 2048 -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(3)
    '新建证书'
} else {
    '复用已有证书'
}
$cert | Select-Object Subject, Thumbprint, NotAfter | Format-List
foreach ($store in 'Root', 'TrustedPublisher') {
    $path = "Cert:\LocalMachine\$store"
    if (-not (Test-Path (Join-Path $path $cert.Thumbprint))) {
        $pub = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
        $storeObj = [System.Security.Cryptography.X509Certificates.X509Store]::new($store, 'LocalMachine')
        $storeObj.Open('ReadWrite')
        $storeObj.Add($pub)
        $storeObj.Close()
        "已把公钥加入 $store"
    } else {
        "$store 里已有"
    }
}

# 2) 内嵌签名
Sec '签名'
$res = Set-AuthenticodeSignature -FilePath $sys -Certificate $cert -HashAlgorithm SHA256
$res | Select-Object Status, StatusMessage | Format-List
Get-AuthenticodeSignature $sys | Select-Object Status, SignerCertificate | Format-List

# 3) 以内核服务方式创建并启动（WDM 驱动，demand start）
Sec '服务'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    "已存在服务 $ServiceName（状态 $($existing.Status)），先停掉再删"
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
sc.exe create $ServiceName type= kernel start= demand error= normal binPath= $sys | Out-String
sc.exe start $ServiceName | Out-String
Start-Sleep -Seconds 2

Sec '服务状态'
sc.exe query $ServiceName | Out-String
Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
    Select-Object Name, Status, ServiceType | Format-List

# 4) 失败时把 SCM 的记录挖出来（加载失败的原因都在这里：NTSTATUS）
Sec '最近的 SCM / 内核加载记录'
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    StartTime = (Get-Date).AddMinutes(-5)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Service Control Manager|Kernel-PnP|Kernel-Plugin' } |
    Select-Object -First 8 |
    ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.ProviderName, ($_.Message -replace '\s+', ' ') }

# 5) 驱动是否真的在跑：设备对象、WFP callout
Sec '设备对象与服务进程'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($svc) { $svc | Select-Object Name, State, Started, PathName | Format-List }
}

Sec 'WFP 里有没有我们的 callout'
$wfp = Join-Path $env:TEMP 'wfp-state.xml'
netsh wfp show state file="$wfp" | Out-Null
if (Test-Path $wfp) {
    $txt = Get-Content $wfp -Raw
    "state 文件大小 $((Get-Item $wfp).Length) 字节"
    foreach ($kw in 'iwan', 'IWAN', 'Iwan') {
        $n = ([regex]::Matches($txt, $kw)).Count
        if ($n -gt 0) { "包含 '$kw' $n 次" }
    }
    Remove-Item $wfp -Force
} else {
    'netsh wfp show state 没产出文件'
}

Sec '结论提示'
'服务 State=Running 且 SCM 无错误 -> 驱动加载成功；否则看上面 SCM 记录里的 NTSTATUS。'
