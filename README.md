# Scan Proxy

**Maintainer: Trachti**  
**Version: 2.13.0**

Scan Proxy is a small Windows-oriented service that routes completed scanned files according to Excel rules. It can correlate scanner clients with open SMB files and Windows Security event 5145 data. Local SQLite state supports interrupted move recovery and optional per-scanner reports.

This repository contains only generic source code, documentation, tests, and example configuration. No organization-specific names, accounts, IP ranges, scanner documents, or production configuration are included.

## Core functionality

- Read and hot-reload routing rules from an Excel workbook.
- Match files by identifier or source subfolder; copy or move them to the configured destination.
- Avoid processing files that are still changing; also detect open SMB files when attribution is configured.
- Publish files through a temporary `.part` file and an atomic rename.
- Recover from source-deletion failures after a destination has been committed.
- Resolve scanner IPs efficiently: one shared `Get-SmbOpenFile` snapshot per scan cycle and one PowerShell process for each batch of pending records.
- Generate local HTML and CSV analytics; daily reports are retained for a configurable number of days, while weekly/monthly/yearly CSV files are finalized after each period closes.

## Requirements

- Windows 10/11 or Windows Server with PowerShell 5.1 or newer for SMB resolution. Python routing tests can also run on other platforms.
- Python 3.10 or newer for source execution.
- Read access to scan sources and write access to destinations.
- The `openpyxl` and `pypdf` packages (installed by the setup script).
- An explicitly configured SMB account and suitable Windows permissions if SMB attribution is required.

## Quick start (PowerShell)

```powershell
.\scripts\install.ps1
Copy-Item .\config\scan-proxy-config.example.xlsx .\config\scan-proxy-config.xlsx
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
```

Edit the two local configuration files. Run the service in Python mode:

```powershell
.\scripts\run.ps1 -UsePython
```

Or build a Windows executable and launch it:

```powershell
.\scripts\build.ps1
.\scripts\run.ps1
```

For historical SMB attribution, enable *Detailed File Share* success auditing **once** from an elevated session:

```powershell
.\scripts\setup-smb-auditing.ps1
```

The helper also supports `-Mode Status -UserName <account>` for diagnostics. It does not accept all SMB users implicitly when an account is not configured.

## Excel rules

Create a worksheet called `Rules` with these columns:

| Column | Example | Purpose |
| --- | --- | --- |
| `Identifier` | `DOC` | File identifier for `identifier` mode |
| `Source` | `incoming` | Source directory relative to `SCAN_PROXY_ROOT` or an absolute path |
| `Destination` | `routed` | Destination directory |
| `Mode` | `identifier` | `identifier`, `subfolder`, or `subfolders` |
| `Enabled` | `true` | `true`, `1`, `yes`, `on`, or `x` |
| `Action` | `move` | `move` or `copy` (default: `move`) |

For `identifier` mode, a file matches if its filename stem equals the identifier or its name starts with `identifier-`. Subfolder mode copies the source-relative tree. The sample workbook contains only generic file identifiers.

## Privacy and configuration

SMB attribution is **disabled by default** unless `SCAN_PROXY_SMB_USER` is set locally. Reverse-DNS/hostname lookups are also **off by default**. Routine completed scan entries do not retain their source or destination paths; pending attribution and interrupted moves temporarily need those paths to recover correctly. Enabling attribution stores scanner IPs in local SQLite data and reports, which can be personal data in some environments.

Do not commit local configuration, logs, reports, databases, or documents. See [Security](SECURITY.md), [Configuration](docs/CONFIGURATION.md), and [Deployment](docs/DEPLOYMENT.md).

## Testing

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

SMB PowerShell cmdlets and event log access require a Windows host. The cross-platform tests verify the rule engine, routing, reports, privacy defaults, and the Python-side SMB snapshot logic.

## Project layout

```text
config/            Sanitized workbook and environment examples
src/scan_proxy.py  Python routing daemon and local reports
scripts/           Windows launcher, installer, builder, SMB helper, audit setup
tests/             Unit and file-transfer integration tests
docs/              Configuration and deployment guidance
```
