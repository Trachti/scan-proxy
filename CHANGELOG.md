# Changelog

All notable changes to scan-proxy are documented here.

The project follows semantic versioning for public releases.

## [2.12.0] - 2026-10-05

### Added

- Low-CPU batch resolution for pending SMB client attribution.
- Grouped Windows Security Event 5145 lookups.
- Persistent reverse-DNS cache with hostnames in analytics.
- Separate pending-resolution and report-refresh schedules.
- Exact open-file attribution cache to preserve high-confidence SMB matches.
- Staggered retry backoff for unresolved client IP addresses.

### Changed

- Reduced PowerShell process creation during pending attribution.
- Reduced SQLite write overhead and improved report indexes.
- CSV and HTML reports are only rewritten when their content changes.
- Weekly, monthly, and yearly CSV files are generated only for completed periods.
- Public configuration uses environment variables instead of organization-specific defaults.
- Source comments, public logs, status text, analytics UI, and example configuration are English.
- Public runtime version is now reported as `2.12.0`.

### Removed

- Organization-specific usernames, network ranges, abbreviations, and administrative references from public defaults.

## [2.11.0]

Previous public release. See the repository history for the exact changes in that version.
