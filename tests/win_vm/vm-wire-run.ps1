# 线测固定入口：参数写死在这里，避免多层 PowerShell/ssh 引号把参数吃掉
# （已经两次出现"跑的是默认参数"：PingCount 默认 3、-Inject -Wire 完全没生效）。
& powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-rx.ps1 `
    -PeerIp 114.214.185.234 -PeerPort 45678 -Inject -Wire -PingCount 0 -HoldSeconds 20
