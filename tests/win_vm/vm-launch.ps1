# 用 WMI 在客体里起一个脱离 ssh 会话的进程，输出重定向到文件。
param([string]$Script, [string]$ScriptArgs = '', [string]$Out = 'C:\iwan\nc-out.txt')
$inner = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' + $Script + ' ' + $ScriptArgs
$cmd = 'cmd.exe /c "' + $inner + ' > ' + $Out + ' 2>&1"'
$r = ([wmiclass]'Win32_Process').Create($cmd)
"已起：pid={0} rc={1}" -f $r.ProcessId, $r.ReturnValue
