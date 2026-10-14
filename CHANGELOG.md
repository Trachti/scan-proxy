# Changelog

## 2.13.0 — Trachti

- Incorporated the optimized scan cycle from the supplied 2.13.0 scripts into the public repository layout.
- Kept Excel rule routing, atomic copy/move, recovery of incomplete moves, and optional SQLite-backed analytics.
- Replaced per-file PowerShell calls with a cached `OpenSnapshot` and retained batched `ResolveBatch` lookups for historical event 5145 correlation.
- Removed hard-coded organization-specific settings, account names, network ranges, and local server aliases.
- Standardized source comments, functions, variable names, logs, workbook fields, output files, and the HTML interface in English.
- Used `Trachti` as the project maintainer identifier.
- Removed the workbook's optional person-identifying scanner label from runtime rule handling.
- Disabled SMB attribution and hostname lookups by default until explicitly configured.
- Minimized retention of resolved document paths in the local scans table; paths required for pending recovery are retained temporarily.
- Added cross-platform routing tests and Windows PowerShell syntax validation in CI.

This is an update bundle based on the two supplied scripts, not a verified GitHub release. The existing repository and previous release assets must be reviewed separately. Deployments should review environment variables and test on Windows before replacing a production instance.
