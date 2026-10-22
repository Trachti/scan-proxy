# Enable Windows success auditing needed for the 5145/5140 attribution fallback.
# Run deliberately from an elevated Windows PowerShell session; this changes host audit policy.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Helper = Join-Path $PSScriptRoot 'scan-proxy-smb.ps1'
if (-not (Test-Path $Helper)) { throw "SMB helper not found: $Helper" }
Write-Host 'Enabling success auditing for Detailed File Share (5145) and File Share (5140).'
Write-Host 'Administrative rights and authorization to modify audit policy are required.'
& $Helper -Mode Setup
if ($LASTEXITCODE -ne 0) { throw "Audit setup failed with exit code $LASTEXITCODE" }
