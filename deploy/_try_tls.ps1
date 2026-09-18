# ASCII only (PowerShell 5.1 reads BOM-less .ps1 as the OEM code page).
# Try frpc_force_tls to get past a middlebox that kills plaintext frp traffic.
$ErrorActionPreference = 'Continue'
$cfg = 'C:\ProgramData\SakuraFrpService\config.json'
$bak = "$cfg.bak-before-tls"
Copy-Item $cfg $bak -Force
Write-Output "backup -> $bak"

$t = [IO.File]::ReadAllText($cfg, [Text.Encoding]::UTF8)
$n = $t -replace '"frpc_force_tls":\s*false', '"frpc_force_tls": true'
if ($n -eq $t) { Write-Output 'WARN: frpc_force_tls not flipped (already true?)' }
else {
  [IO.File]::WriteAllText($cfg, $n, (New-Object Text.UTF8Encoding($false)))
  Write-Output 'frpc_force_tls set to true'
}
(Select-String -Path $cfg -Pattern 'frpc_force_tls').Line

Write-Output '--- stopping daemon ---'
Get-Process SakuraFrpService, frpc, SakuraFrpLauncher -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Output "  kill $($_.Id) $($_.Name)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 4
Write-Output '--- starting daemon ---'
$svc = 'C:\Program Files\SakuraFrpLauncher\SakuraFrpService.exe'
Start-Process -FilePath $svc -ArgumentList '--daemon' -WorkingDirectory 'C:\Program Files\SakuraFrpLauncher' -WindowStyle Hidden
Start-Sleep -Seconds 45

Write-Output '--- processes ---'
Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'frpc|SakuraFrp' } |
  Select-Object ProcessId, Name | Format-Table -AutoSize | Out-String
$fp = (Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'frpc.exe' }).ProcessId
if ($fp) {
  Write-Output '--- frpc connections ---'
  Get-NetTCPConnection -OwningProcess $fp -ErrorAction SilentlyContinue |
    Select-Object State, RemoteAddress, RemotePort | Format-Table -AutoSize | Out-String
}
Write-Output '--- log tail ---'
$l = Get-ChildItem 'C:\ProgramData\SakuraFrpService\Logs' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $l.FullName -Tail 20
