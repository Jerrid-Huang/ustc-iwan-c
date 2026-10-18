# 取最近的蓝屏记录、转储文件与 Driver Verifier 状态 —— 用来判定上一轮是不是 iwan.sys 崩的。
$ErrorActionPreference = 'Continue'
"=== 当前时间 / 引导时间 ==="
(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime

"=== BugCheck 事件（Id=1001）==="
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 4 -ErrorAction SilentlyContinue |
    ForEach-Object { "{0}  {1}" -f $_.TimeCreated, (($_.Message -replace "`r`n", ' ') -replace '\s+', ' ') }

"=== 转储文件 ==="
Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name, Length, LastWriteTime | Format-Table -AutoSize
Get-Item C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue | Select-Object Length, LastWriteTime | Format-List

"=== 转储配置 ==="
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue |
    Select-Object CrashDumpEnabled, AutoReboot, DumpFile, MinidumpDir | Format-List

"=== Driver Verifier ==="
(& verifier /query) 2>&1 | Select-Object -First 20

"=== 服务与驱动文件 ==="
Get-Service iwan -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-Table -AutoSize
Get-Item C:\iwan\iwan.sys | Select-Object Length, LastWriteTime | Format-List

"=== 上一次开机的系统日志里有没有测试签名/加载失败 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7026} -MaxEvents 2 -ErrorAction SilentlyContinue |
    ForEach-Object { "{0}  {1}" -f $_.TimeCreated, (($_.Message -replace "`r`n", ' ') -replace '\s+', ' ') }
