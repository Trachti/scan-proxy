[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Helper = Join-Path $PSScriptRoot 'scan-proxy-smb.ps1'
if (-not (Test-Path $Helper)) {
    throw "SMB helper not found: $Helper"
}
Write-Host 'Enabling Windows Detailed File Share success auditing (requires elevation).'
& $Helper -Mode Setup
exit $LASTEXITCODE
