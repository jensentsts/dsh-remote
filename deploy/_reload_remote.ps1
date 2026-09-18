# ASCII only: Windows PowerShell 5.1 reads BOM-less .ps1 as the OEM code page,
# so non-ASCII text here breaks the parser. Keep this script English-only.
$ErrorActionPreference = 'Stop'
$p = "$env:USERPROFILE\.dsh\profiles\web\cordis.patch.yml"
if (-not (Test-Path $p)) { Write-Output "patch not found: $p"; exit 1 }
Copy-Item $p "$p.bak-before-v2" -Force
$t = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$n = $t -replace 'dsh-remote-plugin/src/server\.ts(?!\?)', 'dsh-remote-plugin/src/server.ts?v=2'
if ($n -eq $t) {
  Write-Output "no replacement made (already versioned?)"
} else {
  [IO.File]::WriteAllText($p, $n, (New-Object Text.UTF8Encoding($false)))
  Write-Output "replaced; backup at $p.bak-before-v2"
}
Write-Output "--- matching lines ---"
Select-String -Path $p -Pattern 'dsh-remote|server\.ts' | ForEach-Object { "$($_.LineNumber): $($_.Line)" }
