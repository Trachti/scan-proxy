# Configuration reference

Source code and examples are generic. Apply real deployment values **only** to private local configuration. The `scripts/run.ps1` launcher dot-sources `config/environment.local.ps1` before starting Python or the `.exe`.

## Private files

```powershell
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
Copy-Item .\config\scan-proxy-config.example.xlsx .\config\scan-proxy-config.xlsx
```

Do not commit either local output file. The filenames and locations are expected by the launcher and Python service unless `SCAN_PROXY_CONFIG` overrides the workbook path.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `SCAN_PROXY_ROOT` | `incoming/` beside app | Base directory for relative Excel source/destination paths. Set explicitly for Windows deployment. |
| `SCAN_PROXY_CONFIG` | `config/scan-proxy-config.xlsx` | Absolute path to the local workbook (optional override). |
| `SCAN_PROXY_SMB_HELPER` | `scripts/scan-proxy-smb.ps1` | Absolute path to the helper (optional override). |
| `SCAN_PROXY_SMB_USER` | empty | SMB account filter. **Empty disables SMB attribution**. |
| `SCAN_PROXY_IGNORED_NETWORKS` | empty | Semicolon- or comma-separated CIDRs excluded from attribution. |
| `SCAN_PROXY_ENABLE_HOSTNAME_LOOKUPS` | `false` | Enable reverse DNS in local reports; potentially identifying. |
| `SCAN_PROXY_LOCAL_SHARE` | empty | Share name for safe local UNC-to-`SCAN_PROXY_ROOT` mapping. Empty disables optimization. |
| `SCAN_PROXY_LOCAL_SERVER_ALIASES` | empty | Additional semicolon-separated aliases of the local SMB server. |
| `SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS` | `5` | File scan and workbook re-check period. |
| `SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS` | `600` | Reports refresh schedule (seconds). |
| `SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS` | `60` | Pending attribution sweep period (seconds). |
| `SCAN_PROXY_PENDING_BATCH_SIZE` | `8` | Number of pending records per PowerShell batch. |
| `SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES` | `10` | Lookback for Windows Security events during historical resolution. |
| `SCAN_PROXY_SMB_SHARE_FALLBACK_MAX_AGE_SECONDS` | `30` | Maximum distance between file time and 5140 event for share fallback. |
| `SCAN_PROXY_SMB_SNAPSHOT_TIMEOUT_SECONDS` | `4` | Runtime limit of an open-file snapshot helper call. |
| `SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS` | `20` | Runtime limit of a pending-resolution helper call. |
| `SCAN_PROXY_PENDING_MAX_HOURS` | `48` | Pending retry deadline. |
| `SCAN_PROXY_DAILY_RETENTION_DAYS` | `90` | Daily CSV retention (not SQLite history). |

Other tuning constants remain in `src/scan_proxy.py`; do not change them without testing.

## Workbook `Rules` schema

| Column | Required | Meaning |
| --- | --- | --- |
| `Identifier` | yes | File prefix used in `identifier` mode; blank in recursive mode. |
| `Source` | yes | Path to watch, absolute or relative to `SCAN_PROXY_ROOT`. |
| `Destination` | yes | Path to deliver files, absolute or relative to `SCAN_PROXY_ROOT`. |
| `Mode` | yes | `identifier`, `subfolder` or `subfolders`. |
| `Enabled` or `Status` | yes | `TRUE`, `true`, `1`, `yes`, `on`, `enabled` or `x`. |
| `Action` | optional | `move` (default) or `copy`. |
| `Scanner` | optional | Administrative note; not used for client attribution or stored in completed-scan analytics. |

Identifier matching applies to files **directly in the configured source folder**. A row `DOC / incoming / routed / identifier / TRUE / move` matches `DOC.pdf` and `DOC-123.pdf`, but not `DOCUMENT.pdf`. Identifiers are compared case-insensitively.

`subfolder` and `subfolders` recurse through `Source` and preserve each file's relative directory structure under `Destination`. `copy` skips existing destinations; `move` generates a unique target filename if the original name is already present. The service processes only source files older than 3 seconds and revalidates source metadata before transfer.

For a clean installation, use the English sample workbook. Older deployments with localized header names or action values must migrate their workbook; localized aliases are not guaranteed.

## SMB evidence priority

1. Shared `Get-SmbOpenFile` snapshot during active scanning. A file reported as currently open is not transferred while it is still open.
2. Historical `ResolveBatch` evaluation with exact matching Windows Event 5145 evidence preferred.
3. Restricted Windows Event 5140 fallback only if an appropriate share, account, sufficiently recent access and **one single client IP** are established. Share-level attribution is inherently less precise than 5145. For a UNC source, Event 5140 share-only fallback also requires the source server name to identify the local Windows host or a configured `SCAN_PROXY_LOCAL_SERVER_ALIASES` entry (the local share name alone is insufficient).

The application deliberately does **not** guess an IP for ambiguous activity. Unresolved records are retried with increasing delays and stop after the configured deadline.

## Local share optimization

Normally, `Source` may contain a UNC path. When this is **the same machine** and you deliberately configure both `SCAN_PROXY_LOCAL_SHARE` and the local server's alias(es), a matching UNC source can be read as a local path beneath `SCAN_PROXY_ROOT`, reducing local SMB overhead. This optimization does not modify the Excel workbook and does not apply to arbitrary remote servers. Use it only when the share maps **exactly** to the specified root.

## Privacy and operational data

Production settings, SQLite files, local logs, HTML reports, CSV files and scanned documents can contain identifying information and must never be committed. Changing code does not redact already-generated state. Historical data retained in SQLite may outlive the 90-day retention of daily CSVs; establish a local retention policy.
