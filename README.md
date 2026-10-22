# Scan Proxy

**Maintainer:** Trachti  
**Version:** 2.13.1 (source update; Windows deployment validation required)  
**Platform:** Windows 10/11 or Windows Server, Windows PowerShell 5.1, Python 3.10+

Scan Proxy routes completed scan files according to an Excel workbook and produces local SQLite/CSV/HTML analytics. It can optionally attribute transfers to scanner IPs through Windows SMB open-file information and Security events **5145** and **5140**, without running a PowerShell process for every file.

> **Privacy first:** This public project contains no live organization names, internal hosts, credentials, production CIDRs, scanner documents or operational reports. Provide deployment-specific values only in `config/environment.local.ps1` and `config/scan-proxy-config.xlsx`, both excluded from Git. IP attribution and reverse DNS are disabled until explicitly configured.

## 1. What is new in 2.13.1?

- Keep the optimized 2.13.0 file scan, cached rules, per-scan SMB `OpenSnapshot`, grouped `ResolveBatch` and low-CPU retry mechanism.
- Prefer **exact file evidence from Security event 5145**. Use Security event **5140 only as a restricted fallback** when the account, share, short time window and exactly one client IP match. Event 5140 identifies a *share*, not a specific file: this is weaker evidence and must not be treated as exact file identification.
- Enable success auditing for both **Detailed File Share (5145)** and **File Share (5140)** when expressly requested by an administrator.
- Keep copy/move recovery, local analytics, optional hostname resolution and completed-period CSV reports.
- Use generic environment variables, English workbook columns, comments, logs and dashboard. No deployment-specific data is distributed.
- Minimize stored file paths: paths for pending SMB resolution remain temporary; resolved/expired records have path fields cleared. Local logs can still contain source/destination paths and must remain private.

## 2. Folder and file layout

```text
scan-proxy/
├── README.md                          # Start here
├── CHANGELOG.md                       # Trachti release notes
├── SECURITY.md                        # Data protection and deployment warnings
├── .gitignore                         # Prevent accidental publication of private files
├── requirements.txt                   # Runtime dependencies
├── requirements-dev.txt               # Optional executable builder
├── src/
│   └── scan_proxy.py                  # Routing service + analytics
├── scripts/
│   ├── scan-proxy-smb.ps1              # SMB snapshot, event 5145/5140, status
│   ├── install.ps1                     # Python environment setup
│   ├── run.ps1                         # Loads private settings, starts the service
│   ├── build.ps1                       # Optional Windows executable
│   └── setup-smb-auditing.ps1          # Optional administrator-only audit setup
├── config/
│   ├── environment.example.ps1         # Safe public example
│   └── scan-proxy-config.example.xlsx  # Safe public Excel example
├── docs/
│   ├── CONFIGURATION.md                # All options and Excel rule examples
│   ├── DEPLOYMENT.md                   # Windows installation and scheduled tasks
│   └── GITHUB-UPLOAD.md                # GitHub website click-by-click update
└── tests/
    └── test_scan_proxy.py             # Automated cross-platform tests
```

**Created locally, never uploaded:** `.venv/`, `config/environment.local.ps1`, `config/scan-proxy-config.xlsx`, `logs/`, `analytics/`, `build/`, `dist/`, scans and other runtime files. Existing `LICENSE` and any unrelated repository files should remain unchanged.

## 3. Requirements and permissions

1. A Windows host with file-sharing support. `Get-SmbOpenFile`/`Get-SmbSession` require SMB server functionality on the host where files are served. For historical attribution, the service must be able to read Windows Security events on that host.
2. **Python 3.10 or newer**, preferably installed with the `py` launcher. [Download Python](https://www.python.org/downloads/windows/).
3. **Windows PowerShell 5.1** and an account with read access to source folders, write access to destination folders and permission to remove source files when using `move`.
4. A local Excel editor (Microsoft Excel or another XLSX-compatible editor) for the routing configuration.
5. Administrative permissions **only for the optional one-time audit policy setup**. Do not normally run the service as Administrator. Check organizational auditing policies before enabling events 5145/5140; event volume and security-log storage may increase.

An SMB username, server names, share names and network ranges vary by installation; **none are provided or inferred by the project**.

## 4. Install from scratch: Windows PowerShell

### Step 1 — Download the repository

Open <https://github.com/Trachti/scan-proxy>, choose **Code → Download ZIP** and extract it to a working folder, for example `C:\ScanProxy`. Alternatively, if Git is installed:

```powershell
git clone https://github.com/Trachti/scan-proxy.git C:\ScanProxy
Set-Location C:\ScanProxy
```

If you obtained the **2.13.1 update ZIP** separately, extract it into the repository folder, replacing the files with the same relative paths (see [GitHub update guide](docs/GITHUB-UPLOAD.md)). Do not extract everything into a second nested `scan-proxy` folder.

### Step 2 — Install the Python dependencies

Open **Windows PowerShell** (not necessarily as Administrator) and run:

```powershell
Set-Location C:\ScanProxy
.\scripts\install.ps1
```

The installer creates `.venv/` and installs `openpyxl` and `pypdf`. If Windows refuses to run scripts, use an execution policy approved by your administrator; for example, in a process where local scripts are allowed:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

This changes only the current PowerShell process, not the machine's permanent policy.

### Step 3 — Create **local**, private configuration files

```powershell
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
Copy-Item .\config\scan-proxy-config.example.xlsx .\config\scan-proxy-config.xlsx
notepad .\config\environment.local.ps1
```

Inside `environment.local.ps1`, set your own base directory, for example:

```powershell
$env:SCAN_PROXY_ROOT = 'C:\ScanData'
$env:SCAN_PROXY_SMB_USER = ''  # Leave empty while testing basic routing
$env:SCAN_PROXY_IGNORED_NETWORKS = ''
$env:SCAN_PROXY_ENABLE_HOSTNAME_LOOKUPS = 'false'
```

Create these folders in Explorer or PowerShell:

```powershell
New-Item -ItemType Directory -Force C:\ScanData\incoming,C:\ScanData\routed
```

All environment-specific values stay in `environment.local.ps1`; **never edit `environment.example.ps1` with real internal data**.

### Step 4 — Edit and enable one Excel rule

1. Open `C:\ScanProxy\config\scan-proxy-config.xlsx` in Excel.
2. Open the worksheet **Rules**.
3. Keep the existing header row exactly as shown below.
4. The example rules start with **Enabled = FALSE** on purpose. In row 2, set `Enabled` to **TRUE** after verifying `Source` and `Destination`.
5. Save and close Excel.

| Identifier | Source | Destination | Mode | Enabled | Action | Scanner |
| --- | --- | --- | --- | --- | --- | --- |
| `DOC` | `incoming` | `routed` | `identifier` | `TRUE` | `move` | *(empty)* |

A file named `DOC.pdf` or `DOC-0001.pdf` inside `C:\ScanData\incoming` is moved to `C:\ScanData\routed`. Files with other names are not routed by this identifier rule. Set `Action` to `copy` to keep the original. With `subfolder`/`subfolders`, the relative directory tree is preserved instead of matching identifiers. See [Configuration](docs/CONFIGURATION.md).

### Step 5 — Start the program in Python mode

```powershell
Set-Location C:\ScanProxy
.\scripts\run.ps1 -UsePython
```

A line like `Scanproxy 2.13.1 running. Press Ctrl+C to stop.` indicates the process started. Put a **test** file named `DOC-test.txt` in `C:\ScanData\incoming`, then check `C:\ScanData\routed\DOC-test.txt` after a few seconds. **Use synthetic data first**; `move` deletes its source after successfully committing the destination.

Use **Ctrl+C** to stop. The program rereads the Excel workbook when its modification time changes, so editing the workbook normally does not require a restart.

### Step 6 — Inspect logs and analytics

The service creates these paths automatically:

```text
C:\ScanProxy\logs\scan-proxy\              File routing logs
C:\ScanProxy\logs\analytics\               Analytics and pending-resolution logs
C:\ScanProxy\analytics\analytics.html      Local browser dashboard
C:\ScanProxy\analytics\daily\             Daily CSV reports (90-day file retention by default)
C:\ScanProxy\analytics\weekly\            Completed ISO-week reports
C:\ScanProxy\analytics\monthly\           Completed month reports
C:\ScanProxy\analytics\yearly\            Completed year reports
C:\ScanProxy\analytics\_state\scan-proxy.db  Private local SQLite database
```

Double-click `analytics\analytics.html` to view it **without a web server**. With SMB attribution disabled during initial testing, the totals still count transfers, but scanner-specific rows/CSV files remain absent and the attribution counter shows unresolved entries. The initial report is generated during initialization; later updates follow `SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS` (default **600 seconds**, 10 minutes), and only changed reports are rewritten.

## 5. Optional: enable SMB scanner-IP attribution

**Skip this section until basic copy/move routing works.** Attribution only works on a suitable Windows SMB file-server host with the required permissions and logs. It is off by default; no personal IP/host data is collected by the resolver in the default configuration.

1. In your **local** `config/environment.local.ps1`, set `$env:SCAN_PROXY_SMB_USER` to the actual SMB account used for scanner file uploads. Keep that value private. Optionally set `$env:SCAN_PROXY_IGNORED_NETWORKS` to the specific CIDR ranges that are not scanner clients. If your source workbook contains the local SMB UNC share and you want local file I/O optimization, set `$env:SCAN_PROXY_LOCAL_SHARE` and, if necessary, `$env:SCAN_PROXY_LOCAL_SERVER_ALIASES`.
2. From an **elevated** Windows PowerShell window, enable the necessary **success** audit categories once (if approved by your security policy):

   ```powershell
   Set-Location C:\ScanProxy
   .\scripts\setup-smb-auditing.ps1
   ```

3. Open an ordinary PowerShell window, load the *local* account, and inspect SMB status:

   ```powershell
   Set-Location C:\ScanProxy
   . .\config\environment.local.ps1
   .\scripts\scan-proxy-smb.ps1 -Mode Status `
     -UserName $env:SCAN_PROXY_SMB_USER `
     -IgnoredNetworks $env:SCAN_PROXY_IGNORED_NETWORKS
   ```

4. Restart the service via `run.ps1 -UsePython`. The main file loop uses a shared `OpenSnapshot`, not a separate PowerShell call for each candidate. If attribution is unresolved, `ResolveBatch` checks historical Events 5145 and (only under strict conditions) 5140.

**What to expect:** Unambiguous scanner IPs become `resolved`. Unmatched or ambiguous files remain `pending` until the retry deadline (default **48 hours**), then `unresolved`; **no IP is guessed**. Event 5140 represents access to a *share* and never proves which file was written. Prefer event 5145 for file-level auditing. Setting `SCAN_PROXY_ENABLE_HOSTNAME_LOOKUPS = 'true'` enables reverse DNS; this exposes potentially personal scanner hostnames in local analytics.

## 6. Optional: build an executable (.exe)

```powershell
Set-Location C:\ScanProxy
.\scripts\build.ps1
```

The executable bundle is under `C:\ScanProxy\dist\scan-proxy\` and contains `scan-proxy.exe`, a `scripts/` folder, plus generic configuration examples. Create `dist\scan-proxy\config\environment.local.ps1` and `dist\scan-proxy\config\scan-proxy-config.xlsx` by copying the bundled examples and filling in **private** settings; do **not** publish these local files. Start the executable using:

```powershell
Set-Location C:\ScanProxy\dist\scan-proxy
.\scripts\run.ps1
```

The packaged `run.ps1` loads the local environment; running `scan-proxy.exe` directly does **not** read PowerShell `.ps1` configuration files, so an executable launched directly must receive equivalent environment variables from its process/service context.

## 7. Automatic startup (optional)

In **Task Scheduler** choose **Create Task… → General** (use a dedicated low-privilege runtime account) → **Triggers → New… → At startup** → **Actions → New…**:

- **Program/script:** `powershell.exe`
- **Add arguments:** `-NoProfile -ExecutionPolicy RemoteSigned -File "C:\ScanProxy\scripts\run.ps1" -UsePython`
- **Start in:** `C:\ScanProxy`

Save, use **Run** for a test, and verify logs and actual file permissions. Avoid multiple concurrent instances: the application uses a Windows named mutex. For an executable distribution, use its own `scripts\run.ps1` and omit `-UsePython`. See [Deployment](docs/DEPLOYMENT.md) for checks and upgrades.

## 8. Tests

```powershell
Set-Location C:\ScanProxy
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

These verify rules, routing, path privacy, pending behavior and report generation. Windows-specific SMB cmdlets, Event Log access, task scheduling and executable packaging require **validation on the actual Windows host**; automated Linux tests do not prove live SMB correctness.

## 9. Troubleshooting

| Symptom | Check |
| --- | --- |
| PowerShell script blocked | Use an approved execution policy for the current session, or sign scripts according to your policy. |
| `config/...xlsx` not found | Copy the `.example.xlsx` file to `scan-proxy-config.xlsx` and save it. |
| Nothing is moved | Is `Enabled` TRUE? Does the filename match `Identifier`? Does the source exist? Is the file at least 3 seconds old? |
| Permission denied | Check the runtime account's access to source, destination, SQLite and log directories. |
| Scanner IP pending | Ensure the correct SMB account is set, audit categories are enabled, the Security log retains events, and you are on the SMB file server. |
| Event 5140 never resolves | 5140 is share-level and is accepted only with a matching share, narrow window and one unambiguous client. |
| Dashboard seems stale | Wait for the report refresh period or restart in a test environment. |
| Source duplicated | When action is `copy`, unchanged destinations are intentionally not overwritten. When action is `move`, collisions receive a distinct name. |

## 10. Upgrade an existing installation

**Back up private files and state first:** `config/environment.local.ps1`, `config/scan-proxy-config.xlsx`, and the local `analytics/_state` database. Stop the running service. Replace **only repository code, scripts, public examples and documentation**, leaving production settings untouched. The source schema is **English** (`Identifier`, `Source`, `Destination`, `Mode`, `Enabled`, `Action`): if an old workbook uses localized headers/values, migrate it by using the new example XLSX rather than assuming compatibility.

State tables are retained across source updates, but do not make the first upgrade directly on production. Verify routes and permissions on a test host. Legacy analytics databases may contain older stored paths and hostnames; existing data is **not automatically anonymized**. Keep old state private and review retention. If starting over intentionally, stop the service, back up and remove the generated `analytics/` folder before restarting (this discards historical analytics and pending recovery records).

## 11. Publish this update to GitHub

See [GITHUB-UPLOAD.md](docs/GITHUB-UPLOAD.md) for every folder, filename and exact GitHub website click. The 2.13.1 update archive is an **overlay** for the existing repository: it does not rewrite `LICENSE` or unrelated files, and it does **not** automatically commit or push to GitHub.

## License and security

Keep the existing repository [LICENSE](LICENSE) unchanged. Please read [SECURITY.md](SECURITY.md) before making changes public. Any real scanner IP, hostname, filename, log, database or document produced at runtime can be sensitive even when the application code is generic.
