$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\iwan'
"TestFlags = {0}" -f (Get-ItemProperty $k -Name TestFlags -ErrorAction SilentlyContinue).TestFlags
"WfpStage  = {0}" -f (Get-ItemProperty $k -Name WfpStage -ErrorAction SilentlyContinue).WfpStage
"RunStage  = {0}" -f (Get-ItemProperty $k -Name RunStage -ErrorAction SilentlyContinue).RunStage
"RunWhat   = {0}" -f (Get-ItemProperty $k -Name RunWhat -ErrorAction SilentlyContinue).RunWhat
"服务状态  = {0}" -f (Get-Service iwan -ErrorAction SilentlyContinue).Status
