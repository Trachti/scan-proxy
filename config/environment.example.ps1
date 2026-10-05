# Copy this file to environment.local.ps1 and adjust the values for your environment.
# environment.local.ps1 is ignored by Git.

$env:SCAN_PROXY_ROOT = 'E:\scan'
$env:SCAN_PROXY_SMB_USER = 'scanner-service'
$env:SCAN_PROXY_IGNORED_NETWORKS = '10.0.0.0/24;10.0.1.0/24'

# Optional overrides:
# $env:SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS = '5'
# $env:SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS = '600'
# $env:SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS = '60'
# $env:SCAN_PROXY_PENDING_BATCH_SIZE = '8'
# $env:SCAN_PROXY_SMB_LIVE_LOOKBACK_MINUTES = '2'
# $env:SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES = '10'
# $env:SCAN_PROXY_SMB_TIMEOUT_SECONDS = '5'
# $env:SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS = '20'
# $env:SCAN_PROXY_PENDING_MAX_HOURS = '48'
# $env:SCAN_PROXY_CONFIG = 'C:\scan-proxy\config\scan-proxy-config.xlsx'
# $env:SCAN_PROXY_SMB_HELPER = 'C:\scan-proxy\scripts\scan-proxy-smb.ps1'
