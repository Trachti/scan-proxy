# Apply this update to the existing repository

This archive is an **overlay**, not a clone or a Git commit. It contains replacements for the source scripts and the related examples, launchers, documentation, and tests. It intentionally does **not** contain `.git/`, `LICENSE`, local configuration, existing scans, or analytics state.

1. Make a local backup or work on a new Git branch.
2. Extract this ZIP **into the root of your existing `scan-proxy` checkout**, allowing the listed files to be replaced.
3. Keep your existing `LICENSE` and Git metadata. Explicitly inspect and remove **obsolete tracked files** from the previous version; an overlay cannot automatically know which additional files must be deleted. Do not leave old versions of the scripts in other paths.
4. Review `git status`, `git diff`, tracked local configuration, past release assets, and any information in Git history. Deleting a file in a new commit does not delete earlier published copies.
5. Run `python -m unittest discover -s tests -v` and test Windows SMB functionality on the intended server before committing or publishing.

For PowerShell:

```powershell
# Start from the root of the existing checkout.
Expand-Archive -Path 'scan-proxy-v2.13.0-Trachti-overlay.zip' -DestinationPath '.' -Force
python -m unittest discover -s tests -v
git status
```

Existing local configuration and runtime data are not part of the overlay. The updated example workbook has English column names. Existing production workbooks must also use those column names. Do not blindly overwrite a production configuration with the sample workbook.

**Important:** This overlay does not remove sensitive information from existing Git commits, release archives, or production logs. Those require separate, deliberate cleanup.
