# Security Notes

Do not commit production scanner documents, logs, analytics databases, live Excel configuration files, service account details, or internal network ranges to the repository.

The repository intentionally tracks only `config/scan-proxy-config.example.xlsx` and `config/environment.example.ps1`. Keep the production files `config/scan-proxy-config.xlsx` and `config/environment.local.ps1` local to the deployment host.

The SMB resolver reads Windows SMB state and Security event 5145 data. Run the auditing setup script only with an account authorized to change local audit policy, and grant the runtime account only the permissions it actually needs.

Before making the repository public, review Git history as well as the current working tree for internal hostnames, UNC paths, usernames, IP ranges, and scanned documents.
