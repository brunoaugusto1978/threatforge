# ThreatForge Community v0.10.1 — Case Reviews Migration Hotfix

ThreatForge Community v0.10.1 is a maintenance hotfix for the v0.10 operational review workflow.

## Fixed

- Hardened the `20260711_01_case_reviews` Alembic migration to be idempotent.
- Prevents `DuplicateTable` failures when an existing POC database already has the `case_reviews` table but Alembic has not been stamped to the new head.
- Avoids creating duplicate indexes when equivalent model-created indexes already exist.
- Keeps new installs and existing POC upgrades aligned on Alembic head `20260711_01_case_reviews`.

## Validation

- `python -m pytest tests/test_case_reviews_migration.py tests/test_case_reviews.py -q`
- `python -m pytest -q`
- `python -m app.selftest_isolation`

## Notes

This release does not add new product features. It improves upgrade and clean-install reliability for the v0.10.0 case review workflow.
