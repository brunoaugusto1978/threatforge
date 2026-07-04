# Pull Request

## Summary

<!-- What does this PR change and why? Link related issues (Closes #123). -->

## Type of change

- [ ] Bug fix
- [ ] Feature (Community)
- [ ] Feature (Enterprise-gated seam in Community)
- [ ] Documentation
- [ ] Security hardening (non-vulnerability)
- [ ] Chore / build / CI

## Checklist

- [ ] **Selftest run** — the relevant selftest(s) / CI selftest pass locally
      (e.g. `docker compose ... selftest`).
- [ ] **No plaintext secrets** — no passwords/cookies/tokens/session values are
      stored, logged or exported; only hashes + masks + non-sensitive metadata.
- [ ] **No licensing change without approval** — LICENSE / NOTICE / COMMERCIAL /
      dual-licensing text unchanged unless explicitly approved by the maintainer.
- [ ] **Tenant isolation preserved** — all new queries are `tenant_id`-scoped;
      cross-tenant access returns 404.
- [ ] **RBAC validated** — role checks applied (viewer/analyst/admin; operator
      roles where relevant); support operators cannot manage secrets/connectors.
- [ ] **Feature gates respected** — premium paths go through
      `features.ensure_enabled(...)` and return HTTP 402 when unlicensed; no
      ad-hoc license checks.
- [ ] **Docs updated** — README/CHANGELOG/relevant docs updated; user-facing
      changes documented.
- [ ] **Audit** — sensitive actions are audited with secret redaction where
      applicable.

## Notes for reviewers

<!-- Anything reviewers should focus on, migration/deploy notes, screenshots. -->
