# Deployment

## From source

1. Clone or extract Scan Proxy onto the Windows host.
2. Run `scripts\install.ps1` to create the virtual environment.
3. Copy `config\scan-proxy-config.example.xlsx` to `config\scan-proxy-config.xlsx`.
4. Copy `config\environment.example.ps1` to `config\environment.local.ps1` and adjust local values.
5. Configure the Excel rules using neutral paths that exist on the host.
6. Optionally enable Windows Detailed File Share auditing through `scripts\setup-smb-auditing.ps1` in an elevated shell.
7. Start the service using `scripts\run.ps1 -UsePython`.

## Bundled executable

Run `scripts\build.ps1`. The deployable folder is `dist\scan-proxy\` and includes:

```text
scan-proxy.exe
scripts/scan-proxy-smb.ps1
config/scan-proxy-config.example.xlsx
config/environment.example.ps1
```

Add local configuration next to the executable and launch it from a process that has the required `SCAN_PROXY_*` environment variables. `scripts\run.ps1` loads `config\environment.local.ps1` when started from the repository; launching `scan-proxy.exe` directly does **not** automatically execute a PowerShell environment file.

## Operations

- Routing logs: `logs\scan-proxy\`
- Analytics logs: `logs\analytics\`
- Local SQLite database: `analytics\_state\scan-proxy.db`
- HTML report: `analytics\analytics.html`
- CSV reports: `analytics\daily\`, `weekly\`, `monthly\`, `yearly\`

Never commit the runtime directories or production configuration. Back up an existing `analytics/` directory before upgrading; old databases or reports may contain historical account, path, scanner IP, or hostname information and may not have a compatible schema. Start with a fresh `analytics/` directory if a clean deployment is required. Run on a Windows host with enough permissions to read sources, create destinations, and remove source files when using `move`. Historical SMB resolution additionally requires Windows Security log access and appropriate auditing policy.

## Tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Test on Windows with a real SMB share and event 5145 auditing before using the service on production scan folders. The continuous-integration tests do not exercise live Windows SMB cmdlets.
