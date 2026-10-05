# Upgrade to v2.12.0

## Replace these existing files

- `src/scan_proxy.py`
- `scripts/scan-proxy-smb.ps1`
- `config/environment.example.ps1`
- `tests/test_scan_proxy.py`
- `README.md`

## Add these files if they do not already exist

- `CHANGELOG.md`
- `RELEASE_NOTES_v2.12.0.md`
- `docs/CONFIGURATION.md`
- `docs/UPGRADE-v2.12.0.md`
- `scripts/run.ps1`
- `.gitignore`
- `requirements.txt`
- `requirements-dev.txt`
- `config/scan-proxy-config.example.xlsx`

`build.ps1` is included as a self-contained build script. If your repository already has a working build script with deployment-specific behavior, compare it before replacing it.

## Do not replace or publish

- `config/environment.local.ps1`
- your production routing workbook
- logs
- analytics output
- SQLite databases
- internal hostnames, accounts, network ranges, or scanner inventory

## Compatibility notes

Existing SQLite state is reused. v2.12.0 adds indexes/tables with `CREATE ... IF NOT EXISTS`, so an existing analytics database can remain in place.

The public workbook schema uses English column names. If your production workbook still uses an older localized schema, migrate it separately before replacing a production installation.

## Release tag

Use `v2.12.0` for the public GitHub tag and `scan-proxy v2.12.0` for the GitHub release title.
