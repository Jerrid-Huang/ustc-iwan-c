# 开会话 → 从会话 sport 发 HELLO 到宿主 → 读统计。用来判断"会话开着时普通 UDP 还能不能出去"。
param([string]$PeerIp='114.214.185.234', [int]$PeerPort=45678)
$ErrorActionPreference = 'Stop'
$req = New-Object byte[] 160
# 复用 vm-rx.ps1 的 IOCTL 逻辑太绕：这里直接调用 vm-rx.ps1 的 -KeepOpen 会话，
# 但把 HELLO 放到一个独立步骤里做（-KeepOpen 的会话在脚本退出后仍由设备句柄持有，
# 句柄随进程退出而关闭，所以这里用 vm-rx.ps1 -Wire 的方式：开会话 + 发 HELLO）。
& C:\iwan\vm-rx.ps1 -Inject -Wire -PeerIp $PeerIp -PeerPort $PeerPort -PingCount 0
