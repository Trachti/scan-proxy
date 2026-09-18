[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot '.venv'
$Python = Join-Path $VirtualEnvironment 'Scripts\python.exe'
$Application = Join-Path $RepositoryRoot 'src\scan_proxy.py'
$BuildRoot = Join-Path $RepositoryRoot 'build'
$DistributionRoot = Join-Path $RepositoryRoot 'dist\scan-proxy'

if (-not (Test-Path $Python)) {
    py -m venv $VirtualEnvironment
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $RepositoryRoot 'requirements-dev.txt')

Remove-Item $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $DistributionRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $DistributionRoot | Out-Null

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name 'scan-proxy' `
    --distpath $DistributionRoot `
    --workpath (Join-Path $BuildRoot 'work') `
    --specpath $BuildRoot `
    $Application

New-Item -ItemType Directory -Force -Path (Join-Path $DistributionRoot 'scripts') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DistributionRoot 'config') | Out-Null

Copy-Item `
    (Join-Path $RepositoryRoot 'scripts\scan-proxy-smb.ps1') `
    (Join-Path $DistributionRoot 'scripts\scan-proxy-smb.ps1')

Copy-Item `
    (Join-Path $RepositoryRoot 'config\scan-proxy-config.example.xlsx') `
    (Join-Path $DistributionRoot 'config\scan-proxy-config.example.xlsx')

Copy-Item `
    (Join-Path $RepositoryRoot 'config\environment.example.ps1') `
    (Join-Path $DistributionRoot 'config\environment.example.ps1')

Write-Host "Build complete: $DistributionRoot"
