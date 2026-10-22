# Windows deployment and upgrade

This guide supplements [README.md](../README.md). Test basic file routing on synthetic files first, then enable optional SMB attribution.

## Source-mode installation

1. Copy the source tree to an access-controlled path such as `C:\ScanProxy`.
2. Run `scripts\install.ps1` from a Windows PowerShell prompt.
3. Copy the public configuration examples to private `environment.local.ps1` and `scan-proxy-config.xlsx`.
4. Configure a safe root directory and verify actual permissions. Excel rules are disabled by default.
5. Enable one rule and run `scripts\run.ps1 -UsePython`.
6. Test both matching and non-matching synthetic files; check logs and destination contents.
7. Only then decide whether SMB IP attribution is needed. If approved, configure `SCAN_PROXY_SMB_USER` and enable 5145/5140 success auditing from an administrator shell.

## Building and running a `.exe`

```powershell
Set-Location C:\ScanProxy
.\scripts\build.ps1
Set-Location .\dist\scan-proxy
Copy-Item .\config\environment.example.ps1 .\config\environment.local.ps1
Copy-Item .\config\scan-proxy-config.example.xlsx .\config\scan-proxy-config.xlsx
notepad .\config\environment.local.ps1
.\scripts\run.ps1
```

The executable distribution must retain these relative files: `scan-proxy.exe`, `scripts/run.ps1`, `scripts/scan-proxy-smb.ps1`, `scripts/setup-smb-auditing.ps1`, `config/environment.local.ps1` and `config/scan-proxy-config.xlsx`. **Never distribute configured local files publicly.**

## Task Scheduler

Use a dedicated task account and **Create Task…** in Windows Task Scheduler. On **General**, select the correct account and make sure it has adequate folder permissions. On **Triggers**, choose **New… → At startup**. On **Actions**, choose **New…**:

```text
Program/script:    powershell.exe
Add arguments:     -NoProfile -ExecutionPolicy RemoteSigned -File "C:\ScanProxy\scripts\run.ps1" -UsePython
Start in:          C:\ScanProxy
```

For a compiled distribution change `-File` to the `dist\scan-proxy\scripts\run.ps1` path and omit `-UsePython`. Test with **Run**, then confirm the Task History, `logs/scan-proxy/` and output files. The application uses a Windows mutex to reject simultaneous instances. Avoid setting the task to start a second concurrent run.

Choose a script execution policy appropriate to the host. Some enterprises block local PowerShell scripts or enforce signed script requirements; do not bypass organization policy.

## Updating to 2.14.0

1. Stop the scheduled task or interactive process. Check the process has exited.
2. Back up private Excel rules, local environment settings, `analytics/_state/`, logs and current state under restricted storage.
3. Replace the public code and documentation files in the matching repository paths. Do not overwrite local config or existing `LICENSE`.
4. Run the tests and inspect the local SMB configuration. The new version expects English workbook columns and action/mode values; migrate old localized rules.
5. Verify the generic example files have not gained private usernames/hostnames/CIDRs. Keep deployment-specific values local.
6. Test a known `copy` rule first; then verify `move` and pending recovery. Check analytics and SMB attribution with synthetic events or a permitted controlled scanner test.
7. Restart the task after validation.

**Existing state warning:** Previous SQLite data may contain source/destination paths or scanner hostnames. Deploying new code does not scrub old SQLite rows or historical Git commits. If replacing the database is intentional, archive it privately and delete the generated `analytics/` directory **only while stopped**, understanding that pending move recovery and prior reports will be lost.

## SMB diagnosis and event setup

From elevated PowerShell, if authorized:

```powershell
.\scripts\setup-smb-auditing.ps1
```

For status (requires a locally configured SMB account):

```powershell
. .\config\environment.local.ps1
.\scripts\scan-proxy-smb.ps1 -Mode Status -UserName $env:SCAN_PROXY_SMB_USER
```

Verify the host is the SMB file server. `Get-SmbOpenFile`/`Get-SmbSession` return relevant records only there. Event 5145 provides file-relative details; Event 5140 provides share-level details and is intentionally a weaker, narrow-window fallback.
