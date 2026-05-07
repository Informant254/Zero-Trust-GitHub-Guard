# Security Policy

## Supported Versions

This repository is maintained on the `main` branch.

## Reporting a Vulnerability

Please do not open public issues containing live secrets, exploit payloads, or sensitive logs.

Report security issues privately to the repository owner with:

1. Affected version or commit.
2. Clear reproduction steps using dummy secrets only.
3. Expected and actual behavior.
4. Suggested remediation if known.

## Safe Usage

- Run `zero-trust-guard scan` before committing code.
- Use `zero-trust-guard fix` first as a dry run.
- Use `zero-trust-guard fix --apply` only after reviewing the findings.
- Rotate any secret that was committed, even if it was later redacted.
