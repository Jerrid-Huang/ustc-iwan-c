# 在虚拟机里跑测试，进程由 WMI 创建（不属于 ssh 会话，ssh 断了也不会被杀），
# 输出重定向到文件。这样 ssh 通道挂住/断开都不会影响测试，也不会被误判成"整机卡死"。
param([string]$TestArgs = '-Inject -PeerIp 10.0.2.15 -PingCount 0')
$ErrorActionPreference = 'Stop'
Remove-Item C:\iwan\rx-out.txt,C:\iwan\rx-err.txt -ErrorAction SilentlyContinue
Remove-Item C:\iwan\rx-stats.txt -ErrorAction SilentlyContinue
$inner = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-rx.ps1 ' + $TestArgs
$cmd = 'cmd.exe /c "' + $inner + ' > C:\iwan\rx-out.txt 2> C:\iwan\rx-err.txt"'
$r = ([wmiclass]'Win32_Process').Create($cmd)
"已启动：ReturnValue={0} pid={1}" -f $r.ReturnValue, $r.ProcessId
