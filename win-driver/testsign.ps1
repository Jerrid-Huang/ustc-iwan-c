<#
  testsign.ps1 — 为驱动做测试签名（需要管理员，通常要重启一次）。

  生产签名（EV 证书 + 微软硬件开发者门户）不在本轮范围；测试签名足够在
  自己的机器/虚拟机上加载 iwan.sys。

  步骤与原因：
    1) bcdedit /set testsigning on —— 允许加载测试签名驱动，需重启生效；
    2) 自签一张代码签名证书，并把它装进“受信任的根”和“受信任的发布者”，
       否则内核会拒绝加载；
    3) signtool 给 iwan.sys 签名（sha256），再 signtool verify 复核。
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Sys = "$PSScriptRoot\build\x64\Release\iwan.sys",
    [string]$Subject = 'CN=iWAN Test Signing'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Sys)) { throw "找不到驱动文件：$Sys" }

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    $cand = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse `
        -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
    if (-not $cand) { throw "找不到 signtool.exe（装 Windows SDK 后重试）" }
    $signtool = $cand.FullName
} else {
    $signtool = $signtool.Source
}

Write-Host "1/3 打开测试签名（需重启后生效）"
& bcdedit /set testsigning on | Out-Null

Write-Host "2/3 准备自签名证书"
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
        -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature -KeyLength 2048
}
foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher') {
    $found = Get-ChildItem $store | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $found) {
        Write-Host "  安装证书到 $store"
        Export-Certificate -Cert $cert -FilePath "$env:TEMP\iwan-testsign.cer" | Out-Null
        Import-Certificate -FilePath "$env:TEMP\iwan-testsign.cer" -CertStoreLocation $store | Out-Null
    }
}

Write-Host "3/3 签名并复核"
& $signtool sign /v /fd sha256 /s My /n $Subject $Sys
& $signtool verify /v /pa $Sys

Write-Host ""
Write-Host "若这是第一次打开 testsigning，请重启后再 install.ps1。"
