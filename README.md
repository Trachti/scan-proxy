# scan-proxy

`scan-proxy` is a Windows-oriented scan-file routing service written in Python with a small PowerShell SMB helper. It watches configured source folders, routes completed scan files according to Excel rules, attributes files to scanner clients when Windows SMB evidence is unambiguous, and produces local SQLite/CSV/HTML analytics.

The public repository intentionally contains no organization-specific usernames, network ranges, server names, or administrative identifiers. Deployment-specific values belong in local configuration only.

## Highlights in v2.12.0

- Low-CPU batch processing for pending SMB attribution.
- Grouped Windows Security Event 5145 queries instead of one expensive lookup per pending file.
- Exact `Get-SmbOpenFile` attribution caching.
- Retry backoff for unresolved scanner IP addresses.
- Persistent reverse-DNS cache and hostname-aware analytics.
- Change-only report writes to reduce unnecessary disk I/O.
- Separate intervals for file scanning, pending SMB resolution, and report refresh.
- Completed-period weekly, monthly, and yearly CSV reports.
- English source comments, public logs, status output, configuration examples, and analytics UI.

## How it works

1. `scan_proxy.py` loads routing rules from an Excel workbook.
2. Source folders are scanned on a configurable interval.
3. The SMB helper checks currently open files and, when needed, Windows Security Event 5145 history.
4. Files are copied atomically through a temporary `.part` file.
5. Move operations delete the source only after the destination has been committed.
6. Successful transfers are stored in SQLite.
7. Unresolved SMB attribution is retried with backoff for a limited period.
8. CSV and HTML analytics are refreshed only when required.

## Repository layout

```text
scan-proxy/
├─ src/
│  └─ scan_proxy.py
├─ scripts/
│  ├─ scan-proxy-smb.ps1
│  ├─ build.ps1
│  └─ run.ps1
├─ config/
│  ├─ environment.example.ps1
│  └─ scan-proxy-config.example.xlsx
├─ tests/
│  └─ test_scan_proxy.py
├─ docs/
│  ├─ CONFIGURATION.md
│  └─ UPGRADE-v2.12.0.md
├─ .gitignore
├─ CHANGELOG.md
├─ RELEASE_NOTES_v2.12.0.md
├─ requirements.txt
├─ requirements-dev.txt
└─ README.md
```

Keep an existing `LICENSE` file unchanged unless you intentionally want to change the project's license.

## Requirements

- Windows 10/11 or Windows Server with SMB server cmdlets available.
- Windows PowerShell 5.1 or compatible PowerShell for the SMB helper.
- Python 3.10+ when running from source.
- Administrator rights for enabling or reading the required Windows Security auditing configuration.
- An Excel workbook with the routing-rule schema described below.

Python dependencies:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Configuration

Copy the example environment file and keep the local copy out of Git:

```powershell
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
```

Edit `config\environment.local.ps1` for your environment. Important settings include:

| Variable | Purpose |
| --- | --- |
| `SCAN_PROXY_ROOT` | Base path used for relative source/destination paths |
| `SCAN_PROXY_CONFIG` | Path to the routing workbook |
| `SCAN_PROXY_SMB_HELPER` | Path to `scan-proxy-smb.ps1` |
| `SCAN_PROXY_SMB_USER` | SMB service account whose file activity is attributed |
| `SCAN_PROXY_IGNORED_NETWORKS` | Semicolon-separated CIDR ranges never treated as scanners |
| `SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS` | File/rule scan interval |
| `SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS` | Pending SMB attribution sweep interval |
| `SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS` | Analytics refresh interval |
| `SCAN_PROXY_PENDING_BATCH_SIZE` | Maximum pending rows resolved in one batch |
| `SCAN_PROXY_SMB_LIVE_LOOKBACK_MINUTES` | Short lookback used for live resolution |
| `SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES` | Event 5145 history window for pending resolution |
| `SCAN_PROXY_PENDING_MAX_HOURS` | Maximum time to retry unresolved attribution |

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for details.

## Excel routing workbook

The public workbook schema uses an English worksheet named `Rules` and these columns:

| Column | Required | Values / purpose |
| --- | --- | --- |
| `Identifier` | Yes | File identifier used by `identifier` mode |
| `Source` | Yes | Source folder |
| `Destination` | Yes | Destination folder |
| `Mode` | Yes | `identifier`, `subfolder`, or `subfolders` |
| `Enabled` | Yes* | `true`, `on`, `1`, `enabled`, `yes`, or `x` |
| `Status` | Alternative | May be used instead of `Enabled` |
| `Action` | No | `move` (default) or `copy` |
| `Scanner` | No | Optional analytics label |

Relative paths are resolved below `SCAN_PROXY_ROOT`; absolute paths remain absolute.

An example workbook is included as `config\scan-proxy-config.example.xlsx`. Copy it to the configured live path and add your own routing data. Do not publish the production workbook if it contains internal paths, labels, or infrastructure information.

## Enable SMB auditing

Run PowerShell as Administrator:

```powershell
.\scripts\scan-proxy-smb.ps1 -Mode Setup
```

Check the current helper status with your local values:

```powershell
. .\config\environment.local.ps1

.\scripts\scan-proxy-smb.ps1 `
    -Mode Status `
    -UserName $env:SCAN_PROXY_SMB_USER `
    -IgnoredNetworks $env:SCAN_PROXY_IGNORED_NETWORKS
```

The resolver only accepts unambiguous evidence. A client is not guessed when multiple SMB clients remain plausible.

## Run from source

Load your local environment and start the service:

```powershell
. .\config\environment.local.ps1
.\.venv\Scripts\python.exe .\src\scan_proxy.py
```

Or use the wrapper:

```powershell
.\scripts\run.ps1 -UsePython
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Build a Windows package

```powershell
.\scripts\build.ps1
```

The build is written to:

```text
dist\scan-proxy\
```

The build folder includes the executable plus the SMB helper and public configuration example. Keep your real `environment.local.ps1` and production workbook outside the public repository/release asset unless you explicitly intend to distribute them.

To create a release archive:

```powershell
Compress-Archive `
    -Path .\dist\scan-proxy\* `
    -DestinationPath .\dist\scan-proxy-v2.12.0-windows.zip `
    -Force
```

## Analytics

Runtime analytics are written below the application base directory:

```text
analytics/
├─ _state/
├─ daily/
├─ weekly/
├─ monthly/
├─ yearly/
└─ analytics.html
```

The HTML report is serverless and contains embedded report data. Daily CSV retention is configurable in source. Weekly, monthly, and yearly CSV reports are generated only for completed periods.

## Security and privacy

Do not commit or publish:

- `config/environment.local.ps1`
- the production routing workbook
- SMB usernames specific to your organization
- internal network ranges
- internal hostnames or server names
- logs
- SQLite databases
- analytics exports containing internal scanner IPs or hostnames

The included `.gitignore` excludes the main local/runtime files, but review every release before publishing it.

## Release

Current version: **v2.12.0**

Release notes: [`RELEASE_NOTES_v2.12.0.md`](RELEASE_NOTES_v2.12.0.md)

Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## Author

Maintained by **Trachti**.
