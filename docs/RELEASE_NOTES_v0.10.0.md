# ThreatForge Community v0.10.0 — Operational Review Workflow

ThreatForge Community v0.10.0 introduces the first backend slice of the operational review workflow for investigation cases.

## Added

- Append-only operational review history for investigation cases.
- New `case_reviews` persistence model.
- New Alembic migration for `case_reviews`.
- `GET /cases/{case_id}/reviews` for viewer+ users.
- `POST /cases/{case_id}/reviews` for analyst+ users.
- Audit event `case.review_added`.
- Focused test coverage for review creation, read permissions, RBAC, tenant isolation and audit.

## Security and isolation

- Review history is tenant-scoped.
- Cross-tenant access returns 404 without leaking case existence.
- Viewers can read review history but cannot create reviews.
- Analysts/admins can append review entries.
- Review entries are append-only in this first backend slice.

## Validation

- `python -m pytest -q` — 74 passed, 1 warning.
- `python -m app.selftest_isolation` — ALL TESTS PASSED.
