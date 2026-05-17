# Threat Model

Zero-Trust GitHub Guard is a local defensive scanner for catching secrets before they reach remote repositories.

## Assets

- API keys and personal access tokens
- Webhook URLs
- Repository source code
- Developer workstation trust boundary

## Threats

- Accidental secret commits
- Secrets hidden in generated files or examples
- Remediation workflows that expose secret values in logs
- Scans that unexpectedly traverse outside the intended workspace

## Controls

- Findings report type, count, and line numbers without printing secret values.
- Symlinks are skipped by default to keep scans inside the intended tree.
- `.git`, dependency folders, caches, and build outputs are skipped.
- `fix` is dry-run by default and requires `--apply` before modifying files.
- Quarantine output is ignored by Git.
- JSON output is available for CI and downstream tooling.

## Limitations

- Regex scanning can produce false positives and false negatives.
- Redaction does not revoke a leaked credential.
- Git history cleanup is outside the current scope.
- Binary files and files larger than the configured size limit are skipped.

## Incident Guidance

If a real secret was committed:

1. Revoke or rotate it with the provider.
2. Confirm no unauthorized use occurred.
3. Remove it from current files.
4. Decide whether Git history cleanup is required.
5. Add a regression test or fixture to prevent repeat leaks.
