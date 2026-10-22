# Changelog

## 2.13.1 — Trachti (2026-10-22 public integration)

- Integrated the supplied 2.13.1 Python service and PowerShell SMB resolver into the existing public `src/`, `scripts/`, `config/` layout.
- Added an Event 5140 share-access fallback **only when** there is no stronger Event 5145 match, the SMB account/share match, access is within the narrow configured time window, and exactly one client IP is observed.
- Maintained the optimized `OpenSnapshot` hot path, grouped `ResolveBatch`, file-scan interval, pending-IP backoff, SQLite caching, dirty-report writes and daily/weekly/monthly/yearly analytics.
- Standardized public comments, runtime messages, workbook columns, log filenames, report filenames and HTML interface in English.
- Removed hard-coded environment identifiers, local server names, production accounts, production subnets and vendor/organization references; public examples use neutral values.
- Changed author attribution in source change entries to **Trachti**.
- Defaulted SMB attribution and reverse-DNS lookups to **off** until local configuration is supplied. Cleared routine path fields when an attribution resolves or expires; unresolved pending records temporarily require original paths.
- Added updated Windows setup/build/run scripts, an example workbook, tests, installation documentation and a GitHub upload guide.

### Compatibility and validation notes

- Preferred workbook schema is English: `Rules` with `Identifier`, `Source`, `Destination`, `Mode`, `Enabled`/`Status`, and optional `Action`, `Scanner`.
- Supported actions: `move`, `copy`; modes: `identifier`, `subfolder`, `subfolders`.
- This is a **source-code update bundle**, not an automatically published GitHub release. No live Windows SMB, Event Log or executable integration test was performed in the creation environment. Test on a controlled Windows host before production rollout.

## Previous public revisions — Trachti

- **2.13.0:** Cached SMB open-file snapshot, shared pending-resolution PowerShell process and updated public installation layout.
- **2.12.0:** Low-CPU historical Event 5145 correlation, reverse-DNS caching, English documentation, change-only reports and improved path privacy.
