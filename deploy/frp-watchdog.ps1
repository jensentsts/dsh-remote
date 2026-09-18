# ASCII only.
#
# Non-destructive frp watchdog (v3).
#
# The failure this exists for: frpc loses its node connection and then cannot
# re-establish it, retrying forever. Restarting the daemon fixes it instantly.
#
# v1 called the link healthy whenever frpc held ANY established connection
# (established -gt 0). While frpc is stuck retrying its node login it repeatedly
# obtains a single half-open socket, so v1 logged "ok" on the very check that
# should have counted as a failure, reset its counter, and never restarted
# anything: the tunnel stayed down until a human intervened.
#
# v2 raised the threshold to two, but measured it per process. Process
# enumeration returns empty on this machine intermittently, so v2 concluded frpc
# was gone and killed a healthy tunnel - a watchdog causing the outage it exists
# to prevent.
#
# v3 counts established connections to the node from the SOCKET TABLE, the one
# signal that has never lied here, and never acts on a single reading: every
# restart needs two consecutive unhealthy checks, a missing process must be
# confirmed by two independent APIs, and a restart is polled for up to 150
# seconds before it is called verified. A healthy frpc holds 3-5 node
# connections; a stuck one holds 0-1.
#
# Deliberately narrow, because an earlier, cleverer watchdog caused an outage:
#   * it judges only by LOCAL evidence, never by probing the tunnel from outside;
#   * it never kills anything unless it is about to restart;
#   * a kill-switch file disables it entirely;
#   * it embeds no path with non-ASCII characters, so the file parses the same
#     whatever code page PowerShell reads it with.
$ErrorActionPreference = 'Continue'
$HEALTHY_MIN = 2
$NODE_PORT = 8088   # the frp node's control port; healthy means >= 2 connections to it
$dir = $PSScriptRoot
$log = Join-Path $dir 'frp-watchdog.log'
$state = Join-Path $dir 'frp-watchdog.state'
$off = Join-Path $dir 'frp-watchdog.disabled'
$svcDir = 'C:\Program Files\SakuraFrpLauncher'
$svc = Join-Path $svcDir 'SakuraFrpService.exe'

function Write-Log([string]$message) {
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $message" + [Environment]::NewLine
  [System.IO.File]::AppendAllText($log, $line, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-Frpc {
  # Two independent APIs, unioned. Either one can fail transiently on this box,
  # and a single empty reading must never be taken as proof that frpc is gone.
  # Absence is used for the log line only; the health decision never depends on
  # it.
  $ids = @()
  foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'frpc.exe' })) { $ids += $p.ProcessId }
  foreach ($p in @(Get-Process -Name frpc -ErrorAction SilentlyContinue)) { $ids += $p.Id }
  @(@($ids | Sort-Object -Unique) | ForEach-Object { [pscustomobject]@{ ProcessId = $_ } })
}

function Measure-Established($processId) {
  # Count established connections to the frp node from the socket table rather
  # than from a process. Process enumeration needs a PID, and both enumeration
  # APIs have returned empty at once on this machine.
  return @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
           Where-Object { $_.RemotePort -eq $NODE_PORT }).Count
}

if (Test-Path $off) { Write-Log 'disabled by kill switch'; exit 0 }

$procs = Get-Frpc
$fp = if ($procs.Count -gt 0) { $procs[0].ProcessId } else { $null }
$established = Measure-Established $fp

if ($established -ge $HEALTHY_MIN) {
  if (Test-Path $state) { Remove-Item $state -Force -ErrorAction SilentlyContinue }
  Write-Log "ok: frpc pid=$fp established=$established"
  exit 0
}

$missing = -not $fp
$fails = 0
if (Test-Path $state) { $fails = [int](Get-Content $state -Raw) }
$fails++
[System.IO.File]::WriteAllText($state, [string]$fails, (New-Object System.Text.UTF8Encoding($false)))
Write-Log "unhealthy: consecutive=$fails frpc_pid=$fp established=$established healthy_min=$HEALTHY_MIN"

if ($fails -lt 2) { exit 0 }
if ($missing) { Write-Log 'frpc.exe is absent (both process APIs agree)' }

Write-Log "restarting frp daemon after $fails unhealthy check(s)"
Get-Process SakuraFrpService, frpc -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Log "  stop $($_.Id) $($_.Name)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 5
Start-Process -FilePath $svc -ArgumentList '--daemon' -WorkingDirectory $svcDir -WindowStyle Hidden
Remove-Item $state -Force -ErrorAction SilentlyContinue

# Prove the restart worked instead of assuming it: a restart that silently fails
# is exactly how a watchdog becomes the thing that itself needs watching.
$deadline = (Get-Date).AddSeconds(150)
$best = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 6
  $p = Get-Frpc
  $id = if ($p.Count -gt 0) { $p[0].ProcessId } else { $null }
  $n = Measure-Established $id
  if ($n -gt $best) { $best = $n }
  if ($n -ge $HEALTHY_MIN) { Write-Log "restart verified: frpc pid=$id established=$n"; exit 0 }
}
Write-Log "restart did NOT recover within 150s (best established=$best); next check retries"
exit 0