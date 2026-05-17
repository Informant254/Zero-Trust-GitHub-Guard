# 🛡️ Zero-Trust GitHub Guard

[![Stars](https://img.shields.io/github/stars/Informant254/Zero-Trust-GitHub-Guard?style=social)](https://github.com/Informant254/Zero-Trust-GitHub-Guard/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Defensive Excellence](https://img.shields.io/badge/Defensive%20Excellence-dry--run%20fixes%20%7C%20line%20evidence-green)](https://github.com/Informant254/Zero-Trust-GitHub-Guard)

**A defensive secret scanner for developers who want fast local evidence, dry-run remediation, and safer credential cleanup before code reaches GitHub.**

## 🚀 Quick Start

Install directly from GitHub:
```bash
pip install git+https://github.com/Informant254/Zero-Trust-GitHub-Guard.git
```

Initialize the guard:
```bash
zero-trust-guard init
```

Scan your current directory for secrets:
```bash
zero-trust-guard scan
```

Scan a specific path:
```bash
zero-trust-guard scan path/to/project
```

Emit JSON for CI or scripts:
```bash
zero-trust-guard scan --format json --fail-on-findings .
```

Preview remediation actions:
```bash
zero-trust-guard fix
```

Apply an interactive remediation:
```bash
zero-trust-guard fix --apply
```

## ✨ Features

- **Multi-Provider Scanning**: Detects common tokens for Google, AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, and more.
- **Dry-Run Fix Mode**: Shows remediation options first and requires `--apply` before changing files.
- **Line-Level Evidence**: Reports file paths, secret types, counts, and line numbers without printing secret values.
- **Safe Redaction**: Replaces detected values with `[REDACTED]`.
- **Quarantine Workflow**: Moves risky files into `.quarantine/` with collision-safe names.
- **Small Runtime Footprint**: Uses a minimal dependency set for local and mobile-friendly scanning.
- **CI-Friendly Output**: JSON output and `--fail-on-findings` support automation without exposing secret values.

## 🔐 Defensive Defaults

- Skips `.git`, dependency folders, caches, build outputs, and symlinked files.
- Limits scanned files to 1 MB by default to keep scans fast and predictable.
- Redacts matched secrets as `[REDACTED]` instead of exposing values in output.
- Keeps quarantine output in `.quarantine/`, which is ignored by Git.
- Documents assumptions and limits in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## ⚠️ Secret Handling

If a real key was committed, redaction is not enough. Rotate or revoke the key with the provider, then remove it from Git history if required by your incident process.

## 🤝 Contributing

If you find this tool useful, please **give it a ⭐ Star**! Contributions are welcome.

---
Built with ❤️ by [Informant254](https://github.com/Informant254)
