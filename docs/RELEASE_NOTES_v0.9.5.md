# ThreatForge Community v0.9.5 — Security Hardening

ThreatForge Community v0.9.5 is a focused security-hardening release following the v0.9.4 Operational Dashboard release.

This release does not introduce new product workflows. It strengthens repository security, tenant API key storage, and local evidence storage path handling.

## What changed

### GitHub Actions hardening

The CI workflow now explicitly restricts the default `GITHUB_TOKEN` permissions to read-only repository contents.

This addresses CodeQL's `actions/missing-workflow-permissions` finding and reduces unnecessary token privileges during CI execution.

### Tenant API key hardening

Tenant API keys are now stored using a slow hash and verified by prefix + hash verification.

Previous behavior used deterministic SHA-256-style lookup. The new flow avoids direct deterministic hashing of sensitive tenant API keys and aligns the storage model with stronger secret-handling practices.

Operational impact:

- Existing tenant API keys generated before this release must be regenerated.
- Login with user/password is not affected.
- UI usage is not affected.
- No database migration is required.

### Evidence storage path hardening

Evidence storage now applies stricter path handling:

- server-generated storage keys are validated with a strict pattern;
- tenant_id and case_id must be positive integers;
- storage paths are resolved with Path.resolve();
- final paths must remain inside the configured evidence storage directory;
- cleanup and file operations use pathlib.

This addresses CodeQL `py/path-injection` alerts in the evidence storage flow.

## Validation

Validated before release:

- python -m app.selftest_isolation: ALL TESTS PASSED
- python -m pytest -q: 71 passed, 1 warning
- GitHub Actions CI: passed on main
- GitHub CodeQL: passed on main
- CodeQL open alerts: none

## Upgrade notes

After upgrading to v0.9.5:

1. Regenerate tenant API keys if you use X-API-Key authentication.
2. Keep the existing evidence storage directory configured as before.
3. No database migration is required.

## Release type

Security hardening release.
