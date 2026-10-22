# Upload the 2.13.1 update to the existing GitHub repository

Target repository: <https://github.com/Trachti/scan-proxy>. The update bundle is an **overlay**: replace matching paths, keep the existing `LICENSE` and all unrelated files. It is not itself a Git commit or a replacement of private configuration.

## Option A — GitHub website: precise clicks

1. Sign in to GitHub with an account permitted to write to `Trachti/scan-proxy`.
2. Open the repository and select the **Code** tab.
3. Switch the branch selector from `main` to a new branch such as `update-v2.13.1`, if you want a review before merging.
4. Open the repository **root**, click **Add file → Upload files**, and drag in the files from the update archive's root: `README.md`, `CHANGELOG.md`, `SECURITY.md`, `.gitignore`, `requirements.txt`, `requirements-dev.txt`. Replace matching files when GitHub presents the diff/commit view.
5. Click the **src** folder, then **Add file → Upload files**, and upload `src/scan_proxy.py` from your extracted bundle (the file itself, not a second `src` folder).
6. Click the **scripts** folder, then **Add file → Upload files**, and upload `scan-proxy-smb.ps1`, `install.ps1`, `run.ps1`, `build.ps1`, `setup-smb-auditing.ps1` from the update's `scripts` folder.
7. Click the **config** folder, then **Add file → Upload files**, and upload **only** `environment.example.ps1` and `scan-proxy-config.example.xlsx`. Do **not** upload `environment.local.ps1` or `scan-proxy-config.xlsx`.
8. Click the **docs** folder, then **Add file → Upload files**, and upload `CONFIGURATION.md`, `DEPLOYMENT.md`, `GITHUB-UPLOAD.md`.
9. Click the **tests** folder, then **Add file → Upload files**, and upload `test_scan_proxy.py`.
10. Review **Files changed**: paths should be `src/scan_proxy.py`, `scripts/scan-proxy-smb.ps1` etc. Ensure **no** `src/src/`, `scripts/scripts/`, configuration secrets, documents, log files, actual scanner IPs or server names were uploaded.
11. Enter a commit message such as **`Trachti: integrate scan proxy 2.13.1 with safe 5140 fallback`**, choose **Commit changes** (to the new branch if you created one), then open a **Pull request → Compare & pull request → Create pull request** and merge after review.

GitHub website labels can change slightly; all upload destinations above refer to **existing folders** at the repository root. For files already present in a folder, GitHub may offer an update/replacement confirmation rather than a new-file dialog. If the website refuses to replace an existing file via upload, open that file and choose the **pencil/Edit this file** icon for text files, paste the replacement contents and commit. Use upload for the XLSX workbook.

## Option B — Recommended when Git is available

This is safer and faster when multiple files need replacing because the directory structure is copied exactly:

```powershell
git clone https://github.com/Trachti/scan-proxy.git C:\ScanProxy
Expand-Archive -Path C:\Downloads\scan-proxy-v2.13.1-trachti-update.zip -DestinationPath C:\ScanProxy -Force
Set-Location C:\ScanProxy
git switch -c update-v2.13.1
git status --short
git diff --check
git add README.md CHANGELOG.md SECURITY.md .gitignore requirements.txt requirements-dev.txt src scripts config/environment.example.ps1 config/scan-proxy-config.example.xlsx docs/CONFIGURATION.md docs/DEPLOYMENT.md docs/GITHUB-UPLOAD.md tests/test_scan_proxy.py
git diff --cached --stat
git commit -m "Trachti: integrate scan proxy 2.13.1 with safe 5140 fallback"
git push -u origin update-v2.13.1
```

Open the GitHub URL displayed after `git push` and create a pull request for review. The ZIP is assumed to contain files at their relative paths (`src/`, `scripts/` etc.) without another enclosing directory.

## Publication checks

- `config/environment.local.ps1` and `config/scan-proxy-config.xlsx` are absent from the commit.
- `analytics/`, `.venv/`, `logs/`, scanned files and compiled executables are absent.
- Source comments and runtime messages are English; change entries say `Trachti`.
- The workbook example uses fictitious identifiers and starts with rules **disabled**.
- Any previously committed private data remains in Git history; review history separately.
