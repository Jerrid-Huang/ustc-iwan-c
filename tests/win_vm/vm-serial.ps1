# 往 COM1 写一行：宿主直接读串口日志文件，不依赖客体网络。
# 用途：网络被打死之后，仍然能看到测试脚本走到哪一步。
param([string]$Text = 'MARK', [string]$Port = 'COM1')
try {
    $sp = New-Object System.IO.Ports.SerialPort($Port, 115200,
        [System.IO.Ports.Parity]::None, 8, [System.IO.Ports.StopBits]::One)
    $sp.Open()
    $sp.WriteLine($Text)
    $sp.Close()
    Write-Host "串口已写：$Text"
} catch {
    Write-Host ("串口写失败：" + $_.Exception.Message)
}
