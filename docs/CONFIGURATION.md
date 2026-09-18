# Configuration

## Excel configuration

The runtime configuration file is `config/scan-proxy-config.xlsx`. A safe example is stored as `config/scan-proxy-config.example.xlsx`.

The `Rules` worksheet uses these columns:

| Column | Required | Description |
| --- | --- | --- |
| `Identifier` | Yes | File identifier used by `identifier` mode. |
| `Source` | Yes | Source directory or UNC path. Relative paths are resolved below `SCAN_PROXY_ROOT`. |
| `Destination` | Yes | Destination directory or UNC path. Relative paths are resolved below `SCAN_PROXY_ROOT`. |
| `Mode` | Yes | `identifier`, `subfolder`, or `subfolders`. |
| `Enabled` | Yes | `true`, `1`, `yes`, `on`, or `x` enables the rule. |
| `Action` | No | `move` or `copy`. Defaults to `move`. |
| `Scanner` | No | Optional analytics label. |

### Identifier mode

A rule with `Mode=identifier` matches files whose base name equals the configured identifier or whose file name starts with `<identifier>-`.

### Subfolder mode

A rule with `Mode=subfolder` or `Mode=subfolders` recursively processes files below the configured source and preserves the relative path below the destination.

## Environment configuration

Copy `config/environment.example.ps1` to `config/environment.local.ps1`. The local file is ignored by Git.

Required environment-specific settings normally include:

- `SCAN_PROXY_ROOT`: base directory used for relative paths.
- `SCAN_PROXY_SMB_USER`: Windows/SMB account whose SMB activity should be attributed.
- `SCAN_PROXY_IGNORED_NETWORKS`: semicolon- or comma-separated CIDR ranges that must never be treated as scanner clients.

Optional settings control the file scan interval, SMB query interval, SMB event lookback, configuration path, and SMB helper path.
