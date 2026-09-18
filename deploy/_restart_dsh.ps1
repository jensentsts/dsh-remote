# ASCII only (Windows PowerShell 5.1 reads BOM-less .ps1 as the OEM code page).
# Restart the remote dsh web so it picks up the freshly written server.ts.
$ErrorActionPreference = 'Continue'
$log = 'E:\__ai__\usbctl-远端部署\_dsh-web.log'
$errlog = 'E:\__ai__\usbctl-远端部署\_dsh-web.err.log'

Write-Output '--- before: dsh processes ---'
$procs = Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and ($_.CommandLine -match 'bin\.ts\s+"?web"?' -or $_.CommandLine -match 'pnpm\.cjs\s+dsh\s+web')
}
foreach ($p in $procs) { Write-Output ("  {0}  {1}" -f $p.ProcessId, $p.Name) }

Write-Output '--- killing them ---'
foreach ($p in $procs) {
  Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 3
$still = (Get-NetTCPConnection -State Listen -LocalPort 11325 -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "listeners on 11325 after kill: $still"

Write-Output '--- restarting ---'
$node = 'E:\__path__\nodejs\node.exe'
$pnpm = 'C:\Users\thinkpad\AppData\Roaming\npm\node_modules\pnpm\bin\pnpm.cjs'
$work = 'E:\__ai__\dsh\deepseek-harness'
if (-not (Test-Path $node)) { Write-Output "node not found: $node"; exit 1 }
if (-not (Test-Path $pnpm)) { Write-Output "pnpm not found: $pnpm"; exit 1 }
Start-Process -FilePath $node -ArgumentList $pnpm, 'dsh', 'web' `
  -WorkingDirectory $work -WindowStyle Hidden `
  -RedirectStandardOutput $log -RedirectStandardError $errlog
Start-Sleep -Seconds 18

Write-Output '--- after: listeners ---'
Get-NetTCPConnection -State Listen -LocalPort 11325 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-String
Write-Output '--- after: dsh processes ---'
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine -match 'bin\.ts\s+"?web"?'
} | Select-Object ProcessId, Name | Format-Table -AutoSize | Out-String
Write-Output '--- stdout tail ---'
Get-Content $log -Tail 20 -ErrorAction SilentlyContinue
Write-Output '--- stderr tail ---'
Get-Content $errlog -Tail 20 -ErrorAction SilentlyContinue
