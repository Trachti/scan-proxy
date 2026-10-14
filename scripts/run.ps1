[CmdletBinding()]
param([switch]$UsePython)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$LocalEnvironment = Join-Path $RepositoryRoot 'config\environment.local.ps1'
if (Test-Path $LocalEnvironment) {
    . $LocalEnvironment
}
if (-not $env:SCAN_PROXY_CONFIG) {
    $env:SCAN_PROXY_CONFIG = Join-Path $RepositoryRoot 'config\scan-proxy-config.xlsx'
}

$Executable = Join-Path $RepositoryRoot 'dist\scan-proxy\scan-proxy.exe'
if (-not $UsePython -and (Test-Path $Executable)) {
    & $Executable
    exit $LASTEXITCODE
}

$Python = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    throw "Python virtual environment not found: $Python. Run .\scripts\install.ps1 first."
}
& $Python (Join-Path $RepositoryRoot 'src\scan_proxy.py')
exit $LASTEXITCODE
