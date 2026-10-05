[CmdletBinding()]
param(
    [switch]$UsePython
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$LocalEnvironment = Join-Path $RepoRoot 'config\environment.local.ps1'

if (Test-Path $LocalEnvironment) {
    . $LocalEnvironment
}

if ($UsePython) {
    $Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path $Python)) {
        throw "Python virtual environment not found: $Python"
    }
    & $Python (Join-Path $RepoRoot 'src\scan_proxy.py')
    exit $LASTEXITCODE
}

$Executable = Join-Path $RepoRoot 'dist\scan-proxy\scan-proxy.exe'
if (-not (Test-Path $Executable)) {
    throw "Built executable not found: $Executable. Run .\scripts\build.ps1 first."
}

& $Executable
exit $LASTEXITCODE
