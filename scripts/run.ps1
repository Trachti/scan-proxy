[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentFile = Join-Path $RepositoryRoot 'config\environment.local.ps1'
$Python = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'
$Application = Join-Path $RepositoryRoot 'src\scan_proxy.py'

if (Test-Path $EnvironmentFile) {
    . $EnvironmentFile
}

if (-not (Test-Path $Python)) {
    throw 'Virtual environment not found. Run scripts\install.ps1 first.'
}

& $Python $Application
