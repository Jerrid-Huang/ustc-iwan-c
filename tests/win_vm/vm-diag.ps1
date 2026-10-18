$ErrorActionPreference='Continue'
"=== 启动时间 / 系统版本 ==="
$os = Get-CimInstance Win32_OperatingSystem
"{0}  启动于 {1}" -f $os.Caption, $os.LastBootUpTime
"=== 服务 iwan ==="
sc.exe query iwan
"=== 驱动文件 ==="
Get-Item C:\iwan\iwan.sys -ErrorAction SilentlyContinue | Select-Object Length,LastWriteTime | Format-List
"=== 最近的关机/蓝屏事件（新到旧）==="
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001,41,6008,6005,6006,1074} -MaxEvents 14 -ErrorAction SilentlyContinue |
  Sort-Object TimeCreated -Descending |
  ForEach-Object { "{0} [{1}] Id={2} {3}" -f $_.TimeCreated.ToString('MM-dd HH:mm:ss'), $_.ProviderName, $_.Id, (($_.Message -replace '\s+',' ')) }
"=== 转储文件 ==="
Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize | Out-String
Get-Item C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue | Select-Object Length,LastWriteTime | Format-List
"=== WFP 状态里有没有我们的 callout ==="
$f = Join-Path $env:TEMP 'wfp2.xml'
netsh wfp show state file="$f" | Out-Null
if (Test-Path $f) { $t = Get-Content $f -Raw; "文件 {0} 字节，'iwan' 出现 {1} 次" -f (Get-Item $f).Length, ([regex]::Matches($t,'iwan')).Count; Remove-Item $f -Force } else { '没产出 state 文件' }
"=== 网卡 ==="
Get-NetAdapter | Format-Table Name,InterfaceDescription,ifIndex,Status -AutoSize | Out-String -Width 160
