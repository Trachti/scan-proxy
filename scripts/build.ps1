# Build a self-contained Windows executable without bundling local settings.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'
$Application = Join-Path $RepositoryRoot 'src\scan_proxy.py'
$BuildRoot = Join-Path $RepositoryRoot 'build'
$DistributionRoot = Join-Path $RepositoryRoot 'dist\scan-proxy'

if (-not (Test-Path $Python)) { & (Join-Path $PSScriptRoot 'install.ps1') }
& $Python -m pip install -r (Join-Path $RepositoryRoot 'requirements-dev.txt')
if ($LASTEXITCODE -ne 0) { throw 'Build dependency installation failed.' }

Remove-Item $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $DistributionRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $DistributionRoot | Out-Null
& $Python -m PyInstaller `
    --noconfirm --clean --onefile --console `
    --name 'scan-proxy' `
    --distpath $DistributionRoot `
    --workpath (Join-Path $BuildRoot 'work') `
    --specpath $BuildRoot `
    $Application
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }

foreach ($Subdirectory in @('scripts', 'config')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $DistributionRoot $Subdirectory) | Out-Null
}
foreach ($Name in @('scan-proxy-smb.ps1', 'run.ps1', 'setup-smb-auditing.ps1')) {
    Copy-Item (Join-Path $RepositoryRoot "scripts\$Name") (Join-Path $DistributionRoot "scripts\$Name")
}
Copy-Item (Join-Path $RepositoryRoot 'config\scan-proxy-config.example.xlsx') (Join-Path $DistributionRoot 'config\scan-proxy-config.example.xlsx')
Copy-Item (Join-Path $RepositoryRoot 'config\environment.example.ps1') (Join-Path $DistributionRoot 'config\environment.example.ps1')
Write-Host "Build ready: $DistributionRoot"
Write-Host 'No local production settings, databases or scanned documents were included.'
