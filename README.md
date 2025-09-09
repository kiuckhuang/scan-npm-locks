# scan-npm-locks

A security scanner for npm/yarn/pnpm lockfiles that detects compromised package versions. This tool helps identify known vulnerable packages in your dependency tree and provides remediation options.

[Vulnerability source](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)

## Features

- 🔍 Scans `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files
- 🚨 Detects exact compromised package versions
- ⚠️ Warns when packages are present at different (potentially unsafe) versions
- 🛠️ Automatic remediation with `--fix` flag
- 📎 Generates package manager override blocks to prevent installation of compromised versions
- 🔎 Optional heuristic scan of built JavaScript bundles for malicious code patterns
- 💻 Works with npm, yarn, and pnpm projects

## Compromised Packages

This tool checks for the following compromised package versions:

```
ansi-regex@6.2.1
ansi-styles@6.2.2
backslash@0.2.1
chalk@5.6.1
chalk-template@1.1.1
color-convert@3.1.1
color-name@2.0.1
color-string@2.1.1
debug@4.4.2
error-ex@1.3.3
has-ansi@6.0.1
is-arrayish@0.3.3
simple-swizzle@0.2.3
slice-ansi@7.1.1
strip-ansi@7.1.1
supports-color@10.2.1
supports-hyperlinks@4.1.1
wrap-ansi@9.0.1
```

## Installation

Download the script directly:

```bash
curl -O https://raw.githubusercontent.com/kiuckhuang/scan-npm-locks/main/scan-npm-locks.sh
chmod +x scan-npm-locks.sh
```

Or clone the repository:

```bash
git clone https://github.com/kiuckhuang/scan-npm-locks.git
cd scan-npm-locks
```

## Usage

Basic scan of current directory:
```bash
./scan-npm-locks.sh
```

Scan specific directory:
```bash
./scan-npm-locks.sh /path/to/project
```

Automatic remediation (removes compromised packages and reinstalls safely):
```bash
./scan-npm-locks.sh --fix
```

Generate package.json override blocks to prevent future installation:
```bash
./scan-npm-locks.sh --print-overrides
```

Scan built JavaScript bundles for malicious patterns:
```bash
./scan-npm-locks.sh --scan-dist
```

Use custom list of compromised packages:
```bash
./scan-npm-locks.sh --list my-vulnerable-packages.txt
```

## Exit Codes

- `0` - No compromised versions found and no warnings
- `8` - Warnings only (package present at different version)
- `10` - Exact compromised version(s) found
- `2` - Bad usage

## How It Works

The scanner recursively searches for lockfiles in the specified directory and checks them against a list of known compromised package versions. For each lockfile found:

1. **npm (package-lock.json)**: Uses `jq` to parse the dependency tree and check versions
2. **Yarn (yarn.lock)**: Parses the YAML-like format to extract package versions
3. **PNPM (pnpm-lock.yaml)**: Extracts versions from the YAML structure
4. **Unknown formats**: Performs basic string matching

When a compromised version is detected, the tool can automatically clean the `node_modules` directory and lockfiles, then reinstall dependencies with lifecycle scripts disabled to prevent malicious code execution.

## Requirements

- POSIX-compatible shell (sh/bash)
- `find`, `awk`, `grep`, `sort`, `sed`
- `jq` (recommended, required for package-lock.json parsing)

## Security Recommendations

If compromised packages are found:

1. Use `--fix` to automatically clean and reinstall dependencies safely
2. Add the generated override blocks to your `package.json`
3. Rebuild your applications and redeploy
4. Purge CDN/service worker caches if shipping frontend bundles
5. Rotate CI/registry tokens and enable 2FA/U2F for package publishing

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

To update the list of compromised packages, modify `affected_versions.txt` or use the `--list` option with your own file.

## License

MIT
