# scan-proxy

`scan-proxy` is a Windows-oriented scan routing service. It watches configured scan sources, safely copies or moves completed files to their destinations, resolves scanner client IP addresses from SMB state and Windows Security event 5145 data, and generates SQLite-backed CSV/HTML analytics.

The repository contains only source code, examples, documentation, tests, and build/setup scripts. Production scans, logs, analytics state, internal paths, service account values, and live configuration are intentionally excluded.

## Repository layout

```text
scan-proxy/
├── .github/
│   └── workflows/
│       └── ci.yml
├── config/
│   ├── environment.example.ps1
│   └── scan-proxy-config.example.xlsx
├── docs/
│   ├── CONFIGURATION.md
│   └── DEPLOYMENT.md
├── scripts/
│   ├── build.ps1
│   ├── install.ps1
│   ├── run.ps1
│   ├── scan-proxy-smb.ps1
│   └── setup-smb-auditing.ps1
├── src/
│   └── scan_proxy.py
├── tests/
│   └── test_scan_proxy.py
├── .gitattributes
├── .gitignore
├── README.md
├── SECURITY.md
├── requirements-dev.txt
└── requirements.txt
```

## Requirements

- Windows for SMB attribution and the production runtime.
- Python 3.10 or newer for source-based execution.
- Access to the configured source and destination paths.
- Windows Detailed File Share auditing when event 5145 attribution is required.

## Quick start

Open PowerShell in the repository root and run:

```powershell
.\scripts\install.ps1
Copy-Item .\config\scan-proxy-config.example.xlsx .\config\scan-proxy-config.xlsx
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
```

Edit the two local configuration files, then run:

```powershell
.\scripts\run.ps1
```

To enable the required Windows auditing from an elevated PowerShell session:

```powershell
.\scripts\setup-smb-auditing.ps1
```

## Excel rule schema

The `Rules` worksheet uses the following English columns:

| Column | Example | Meaning |
| --- | --- | --- |
| `Identifier` | `FINANCE` | Identifier used for file-name matching. |
| `Source` | `\\SCAN-SERVER\scan` | Source directory. |
| `Destination` | `\\FILE-SERVER\departments\finance\scan` | Destination directory. |
| `Mode` | `identifier` | `identifier`, `subfolder`, or `subfolders`. |
| `Enabled` | `true` | Enables or disables the rule. |
| `Action` | `move` | `move` or `copy`. |
| `Scanner` | `FrontDesk` | Optional analytics label. |

See `docs/CONFIGURATION.md` for the full behavior.

## Host-specific settings

Use environment variables instead of hard-coding internal values into source control. `config/environment.example.ps1` documents all supported settings.

The most important settings are:

```powershell
$env:SCAN_PROXY_ROOT = 'E:\scan'
$env:SCAN_PROXY_SMB_USER = 'scanner-service'
$env:SCAN_PROXY_IGNORED_NETWORKS = '10.0.0.0/24;10.0.1.0/24'
```

## Build an executable

Run:

```powershell
.\scripts\build.ps1
```

The deployable output is created in `dist\scan-proxy`. The build includes the executable and copies the SMB helper plus safe configuration examples into the expected deployment structure.

## Runtime data

At runtime, the application creates:

- `logs\scan-proxy\` for routing logs.
- `logs\analytics\` for analytics logs.
- `analytics\_state\scan-proxy.db` for SQLite state.
- `analytics\daily\`, `weekly\`, `monthly\`, and `yearly\` for CSV reports.
- `analytics\analytics.html` for the browser-readable report.

These paths are ignored by Git.

## Testing

Run the unit tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

GitHub Actions runs the same core tests on Windows.

## Production note

Do not commit a live `config/scan-proxy-config.xlsx`, `config/environment.local.ps1`, scanned documents, logs, analytics databases, internal hostnames, service account names, or network ranges. See `SECURITY.md`.
