# Security and privacy

This public repository must not contain production document scans, organization identifiers, device names, personal names, account names, real IP ranges, credentials, internal paths, logs, or analytics databases. The only tracked configuration is the generic example workbook and environment template.

The runtime processes document filenames and filesystem paths. With SMB attribution enabled, it also processes client IP addresses and, if explicitly enabled, DNS hostnames. **IP addresses and filenames can be personal data.** Consult your organization's retention and privacy requirements before enabling attribution or collecting reports.

## Safe defaults

- SMB client attribution requires a locally configured `SCAN_PROXY_SMB_USER` and is otherwise disabled.
- Hostname lookup is opt-in through `SCAN_PROXY_ENABLE_HOSTNAME_LOOKUP`.
- Completed scan records do not retain source/destination paths once attribution is resolved or disabled.
- Paths are temporarily retained for pending attribution or incomplete moves because retry/recovery needs them.
- Runtime logs, reports, local configuration, and SQLite state are ignored by Git.
- The PowerShell helper does not enumerate arbitrary SMB users if no account is configured.

Run the auditing setup script only from an elevated PowerShell session after reviewing its consequences. Grant the runtime account only the necessary share, filesystem, SMB, and event-log access.

Removing information from the current repository files does **not** erase it from existing Git history or published release assets. Review those separately before publishing a new version; use a history-rewrite procedure only if previous commits or assets exposed sensitive information.
