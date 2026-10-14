[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot '.venv'
$Python = Join-Path $VirtualEnvironment 'Scripts\python.exe'

if (-not (Test-Path $Python)) {
    py -m venv $VirtualEnvironment
}
& $Python -m pip install -r (Join-Path $RepositoryRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
Write-Host 'Installation complete. Copy and edit the example configuration files before running.'
