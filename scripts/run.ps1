# Load private local settings, then run Python or a compiled executable.
[CmdletBinding()]
param([switch]$UsePython)

$ErrorActionPreference = 'Stop'
$ApplicationRoot = Split-Path -Parent $PSScriptRoot
$LocalEnvironment = Join-Path $ApplicationRoot 'config\environment.local.ps1'
if (-not (Test-Path $LocalEnvironment)) {
    throw "Missing local settings: $LocalEnvironment. Copy config\environment.example.ps1 first."
}
. $LocalEnvironment

if ($UsePython) {
    $Python = Join-Path $ApplicationRoot '.venv\Scripts\python.exe'
    $Script = Join-Path $ApplicationRoot 'src\scan_proxy.py'
    if (-not (Test-Path $Python)) { throw "Python virtual environment not found: $Python" }
    if (-not (Test-Path $Script)) { throw "Python entry point not found: $Script" }
    & $Python $Script
    exit $LASTEXITCODE
}

# Support both a repo-root launcher and the self-contained distribution launcher.
$Executable = Join-Path $ApplicationRoot 'scan-proxy.exe'
if (-not (Test-Path $Executable)) {
    $Executable = Join-Path $ApplicationRoot 'dist\scan-proxy\scan-proxy.exe'
}
if (-not (Test-Path $Executable)) {
    throw "Executable not found: $Executable. Run .\scripts\build.ps1 or pass -UsePython."
}
& $Executable
exit $LASTEXITCODE
