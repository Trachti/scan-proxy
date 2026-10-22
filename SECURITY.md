# Security and privacy

The repository MUST contain generic code and examples only. Never publish production usernames, service accounts, passwords, domain names, hostnames, UNC shares, internal CIDRs, client IP addresses, scanned documents, actual filenames or analytics data.

## Local-only configuration and data

- Keep `config/environment.local.ps1` and `config/scan-proxy-config.xlsx` on the deployment host. They are excluded by `.gitignore`. Public `*.example.*` files must remain generic.
- Keep `logs/`, `analytics/`, SQLite database, CSV reports, HTML reports, `.part` transfer files and actual scanned documents outside source control. Reports and logs may disclose scanner IPs, internal hostnames, filenames and paths.
- Do not share operational logs or databases for troubleshooting without review and redaction. The default source configuration has SMB and reverse DNS disabled.
- Pending attribution requires temporary original file paths to check SMB history. The application clears path fields when pending attribution becomes resolved or permanently unresolved. Interrupted moves may temporarily retain source/destination paths until recovery completes.
- Updating the program does not sanitize **existing** database rows, Git history or already published releases. Review them separately before publishing the repository.

## Least privilege and Windows auditing

- Use a dedicated runtime identity with only the required read/write/delete permissions.
- `scripts/setup-smb-auditing.ps1` modifies Windows auditing. Only run with explicit approval as an administrator; it enables success auditing for Detailed File Share (5145) and File Share (5140) and may generate high event volume.
- Access to Windows Security Event logs and SMB administrative cmdlets should be limited to accounts permitted by your security policy. Do not grant broad privileges merely to make attribution work.
- File-level evidence from 5145 is preferred. Event 5140 is share-level only; it cannot prove individual file ownership, even when its restricted fallback uniquely attributes a client in a narrow time window.
- Download dependencies through your organization's approved Python package processes. Review and sign scripts according to your code execution policy.

## Publication checklist

Check Git status and the full Git history before making anything public. `.gitignore` prevents new untracked files from being added accidentally but does **not** remove secrets already committed. Rotate compromised credentials and use a coordinated history-rewrite process if sensitive data was previously published.
