# Configuration

Deployment values are provided through environment variables (for example, in `config/environment.local.ps1`). Production values do not belong in Git.

## Settings

| Variable | Default | Description |
| --- | --- | --- |
| `SCAN_PROXY_ROOT` | `C:\scan` | Base directory for relative Excel paths |
| `SCAN_PROXY_CONFIG` | `config/scan-proxy-config.xlsx` | Workbook location |
| `SCAN_PROXY_SMB_HELPER` | `scripts/scan-proxy-smb.ps1` | PowerShell helper |
| `SCAN_PROXY_SMB_USER` | empty | SMB account filter; empty disables attribution |
| `SCAN_PROXY_IGNORED_NETWORKS` | empty | Optional semicolon-separated CIDRs; IPv4 and IPv6 supported |
| `SCAN_PROXY_LOCAL_SERVER_ALIASES` | empty | Optional additional aliases for the local SMB server |
| `SCAN_PROXY_LOCAL_SHARE` | scan root folder name | SMB share mapped to the local scan root |
| `SCAN_PROXY_ENABLE_HOSTNAME_LOOKUP` | `false` | Enable PTR lookup and hostname analytics |
| `SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS` | `5` | Seconds between rule/file scans |
| `SCAN_PROXY_MIN_FILE_AGE_SECONDS` | `3` | Minimum unchanged-file age before transfer |
| `SCAN_PROXY_SMB_SNAPSHOT_TTL_SECONDS` | `8` | Cache duration for live SMB open-file snapshot |
| `SCAN_PROXY_SMB_SNAPSHOT_TIMEOUT_SECONDS` | `4` | Live SMB subprocess timeout |
| `SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS` | `20` | Historical batch subprocess timeout |
| `SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES` | `10` | Event 5145 lookback |
| `SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS` | `60` | Pending attribution retry interval |
| `SCAN_PROXY_PENDING_BATCH_SIZE` | `8` | Pending items per SMB batch |
| `SCAN_PROXY_PENDING_MAX_HOURS` | `48` | Time to retry before marking unresolved |
| `SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS` | `600` | Analytics regeneration interval |
| `SCAN_PROXY_DAILY_RETENTION_DAYS` | `90` | Daily CSV retention period |

All integer settings must be at least 1. Set CIDRs and account names only on the deployment host.

## Workbook format

The preferred worksheet name is `Rules`. Required English columns: `Identifier`, `Source`, `Destination`, `Mode`, and `Enabled` (or `Status`). `Action` is optional and defaults to `move`. Use only generic identifiers; the `Scanner` column from older workbooks is ignored in this sanitized version.

- `identifier`: only top-level files match an exact filename stem or an `identifier-` filename prefix.
- `subfolder` / `subfolders`: recursively route files while preserving their relative paths.
- `move`: copy atomically and then delete the source; a source-delete failure is recorded for a later retry.
- `copy`: copy atomically; do not overwrite an existing destination.

The daemon reloads the workbook when it changes. Avoid pointing recursive destinations into their own source trees.

## SMB helper modes

- `OpenSnapshot`: output a compact JSON list of currently open files, once per file scan cycle.
- `ResolveBatch`: read pending items from standard input as JSON and correlate their file paths with open files or event 5145 data.
- `Resolve`: resolve one file, including a short recent-session fallback.
- `Status`: show diagnostic SMB and event data for the configured account.
- `Setup`: enable Windows Detailed File Share success auditing (admin rights required).

For the historical lookup, Windows Event ID **5145** is matched against file paths and the explicitly selected account. Ambiguous candidates remain unresolved rather than being assigned a guessed client IP.

## Analytics

Reports and the SQLite state file are written under `analytics/` next to the application. HTML shows aggregate totals, attribution state, and (if enabled) scanner IP breakdowns. CSV output is written for resolved scanner IPs. No SMB account is required for the core routing engine.

Reverse-DNS is opt-in. Reports and operational state are private runtime data even when the source repository is public.
