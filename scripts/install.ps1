[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot '.venv'
$Python = Join-Path $VirtualEnvironment 'Scripts\python.exe'

if (-not (Test-Path $Python)) {
    py -m venv $VirtualEnvironment
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $RepositoryRoot 'requirements.txt')

Write-Host 'Installation complete.'
Write-Host 'Copy config\scan-proxy-config.example.xlsx to config\scan-proxy-config.xlsx and edit it.'
Write-Host 'Copy config\environment.example.ps1 to config\environment.local.ps1 and edit it.'
