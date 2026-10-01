# Deployment

## Source-based deployment

For SMB client attribution, deploy the application on the Windows SMB server that hosts the monitored source share. The SMB cmdlets and Security event 5145 expose activity observed by the local server.

1. Clone the repository to the Windows host.
2. Run `scripts\install.ps1`.
3. Copy `config\scan-proxy-config.example.xlsx` to `config\scan-proxy-config.xlsx` and configure the rules.
4. Copy `config\environment.example.ps1` to `config\environment.local.ps1` and configure the host-specific values.
5. From an elevated PowerShell session, run `scripts\setup-smb-auditing.ps1` if Windows Detailed File Share auditing is not already enabled.
6. Run `scripts\run.ps1`.

## Executable deployment

Run `scripts\build.ps1`. The deployable directory is created under `dist\scan-proxy` and contains the executable plus the helper/config examples.

For the deployed build, create these local files/directories next to the executable:

```text
scan-proxy\
├── scan-proxy.exe
├── config\
│   ├── scan-proxy-config.xlsx
│   └── environment.local.ps1
└── scripts\
    └── scan-proxy-smb.ps1
```

If the executable is launched by a service or scheduled task, set the required `SCAN_PROXY_*` environment variables in that execution context. `environment.local.ps1` is loaded by `scripts\run.ps1`; the standalone executable does not automatically execute PowerShell configuration files.

## Runtime output

The application creates `logs\` and `analytics\` beside the source repository or executable. Those directories contain operational data and are intentionally ignored by Git.
