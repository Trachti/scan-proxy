# Configuration

scan-proxy separates public code from deployment-specific settings. Keep production values in `config/environment.local.ps1` or another local environment mechanism and never commit them.

## Environment file

Start with:

```powershell
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
```

Then edit the local file.

### Core paths

- `SCAN_PROXY_ROOT`: base path for relative routing paths.
- `SCAN_PROXY_CONFIG`: routing workbook path.
- `SCAN_PROXY_SMB_HELPER`: PowerShell SMB helper path.

### SMB attribution

- `SCAN_PROXY_SMB_USER`: SMB account to correlate with scanner access.
- `SCAN_PROXY_IGNORED_NETWORKS`: semicolon-separated CIDRs that are never accepted as scanner clients.
- `SCAN_PROXY_SMB_LIVE_LOOKBACK_MINUTES`: short live attribution window.
- `SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES`: wider history window for pending records.
- `SCAN_PROXY_SMB_TIMEOUT_SECONDS`: timeout for one live helper call.
- `SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS`: timeout for one pending batch.

### Scheduling

- `SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS`: routing scan interval.
- `SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS`: pending attribution sweep interval.
- `SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS`: CSV/HTML refresh interval.
- `SCAN_PROXY_PENDING_BATCH_SIZE`: rows sent to one PowerShell batch.
- `SCAN_PROXY_PENDING_MAX_HOURS`: maximum retry age before an item becomes unresolved.

## Workbook schema

The preferred worksheet name is `Rules`.

Required columns:

- `Identifier`
- `Source`
- `Destination`
- `Mode`
- `Enabled` or `Status`

Optional columns:

- `Action`
- `Scanner`

Supported modes:

- `identifier`: route files whose stem equals the identifier or whose file name starts with `identifier-`.
- `subfolder` / `subfolders`: recursively preserve the source-relative folder structure.

Supported actions:

- `move`
- `copy`

## Security Event 5145

The SMB helper uses the Detailed File Share audit category and Security Event 5145 for historical attribution. Enable it once from an elevated shell:

```powershell
.\scripts\scan-proxy-smb.ps1 -Mode Setup
```

Use `-Mode Status` to inspect currently open SMB files, active SMB sessions, and recent matching Event 5145 entries.
