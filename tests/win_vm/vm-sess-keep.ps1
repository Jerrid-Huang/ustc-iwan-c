# 固定入口：只开会话、保持不放（参数写死，避免多层引号吃掉 -KeepOpen）。
& powershell -NoProfile -ExecutionPolicy Bypass -File C:\iwan\vm-rx.ps1 `
    -PeerIp 114.214.185.234 -PeerPort 45678 -PingCount 0 -HoldSeconds 0 -KeepOpen
