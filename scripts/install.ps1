# Install Python dependencies in a local virtual environment.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironment = Join-Path $RepositoryRoot '.venv'
$Python = Join-Path $VirtualEnvironment 'Scripts\python.exe'

if (-not (Test-Path $Python)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv $VirtualEnvironment
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv $VirtualEnvironment
    } else {
        throw 'Python 3.10+ was not found. Install Python, then rerun this script.'
    }
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}

& $Python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed.' }
& $Python -m pip install -r (Join-Path $RepositoryRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
Write-Host 'Installation finished.'
Write-Host 'Next: copy config example files into their local, git-ignored equivalents.'
