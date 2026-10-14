# Copy this file to environment.local.ps1. Never commit the local file.
# Replace these generic defaults with deployment-specific settings on the host.

$env:SCAN_PROXY_ROOT = 'C:\scan'
$env:SCAN_PROXY_SMB_USER = ''
$env:SCAN_PROXY_IGNORED_NETWORKS = ''
$env:SCAN_PROXY_ENABLE_HOSTNAME_LOOKUP = 'false'

# Optional settings:
# $env:SCAN_PROXY_CONFIG = 'C:\scan-proxy\config\scan-proxy-config.xlsx'
# $env:SCAN_PROXY_SMB_HELPER = 'C:\scan-proxy\scripts\scan-proxy-smb.ps1'
# $env:SCAN_PROXY_LOCAL_SERVER_ALIASES = ''
# $env:SCAN_PROXY_LOCAL_SHARE = 'scan'
# $env:SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS = '5'
# $env:SCAN_PROXY_MIN_FILE_AGE_SECONDS = '3'
# $env:SCAN_PROXY_SMB_SNAPSHOT_TTL_SECONDS = '8'
# $env:SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES = '10'
# $env:SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS = '60'
# $env:SCAN_PROXY_PENDING_BATCH_SIZE = '8'
# $env:SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS = '600'
# $env:SCAN_PROXY_DAILY_RETENTION_DAYS = '90'
