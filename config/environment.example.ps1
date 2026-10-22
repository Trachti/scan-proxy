# Copy to config/environment.local.ps1 and change the private values locally.
# DO NOT commit environment.local.ps1 or paste real accounts, hosts or CIDRs into this example.

# Base directory for relative Source and Destination workbook paths.
$env:SCAN_PROXY_ROOT = 'C:\ScanData'

# Empty user disables SMB client-IP attribution. For production use, specify the
# actual SMB account in environment.local.ps1 only, e.g. 'DOMAIN\<account>'.
$env:SCAN_PROXY_SMB_USER = ''

# Optional networks excluded from SMB attribution; keep empty unless needed.
# Use a semicolon-separated list of private deployment-specific CIDRs.
$env:SCAN_PROXY_IGNORED_NETWORKS = ''

# Optional: Reverse-DNS is disabled by default because hostnames can be sensitive.
$env:SCAN_PROXY_ENABLE_HOSTNAME_LOOKUPS = 'false'

# Optional: optimize UNC-to-local routing ONLY for your actual local SMB share.
# Leave empty to disable local UNC remapping.
$env:SCAN_PROXY_LOCAL_SHARE = ''
$env:SCAN_PROXY_LOCAL_SERVER_ALIASES = ''

# Optional scheduling and SMB attribution settings:
# $env:SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS = '5'
# $env:SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS = '600'
# $env:SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS = '60'
# $env:SCAN_PROXY_PENDING_BATCH_SIZE = '8'
# $env:SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES = '10'
# $env:SCAN_PROXY_SMB_SHARE_FALLBACK_MAX_AGE_SECONDS = '30'
# $env:SCAN_PROXY_SMB_SNAPSHOT_TIMEOUT_SECONDS = '4'
# $env:SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS = '20'
# $env:SCAN_PROXY_PENDING_MAX_HOURS = '48'
# $env:SCAN_PROXY_DAILY_RETENTION_DAYS = '90'
# $env:SCAN_PROXY_CONFIG = 'C:\ScanProxy\config\scan-proxy-config.xlsx'
# $env:SCAN_PROXY_SMB_HELPER = 'C:\ScanProxy\scripts\scan-proxy-smb.ps1'
