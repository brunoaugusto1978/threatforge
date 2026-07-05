"""Shared pytest fixtures for the ThreatForge Community test suite.

The core problem these fixtures solve: `app.main`, `app.config`,
`app.database` (with `engine = create_engine(config.DATABASE_URL, ...)`) and
`app.routers.*` are cached in `sys.modules` on first import. Setting
`DATABASE_URL` via `os.environ` / `monkeypatch.setenv` in a later test does
nothing to those cached modules — the SQLAlchemy engine is already bound to
whatever DB the first test imported against. That is what made the previous
run report `1 passed, 6 errors` with `POST /setup/operator → 409 Conflict`:
tests after the first were hitting the first test's DB (already had a
platform operator).

Approach (Option A from the release checklist): each test that needs the
FastAPI app gets a fixture that (1) purges any cached `app.*` module before
setting env, (2) uses a `tmp_path`-scoped SQLite file (unique per test),
(3) re-imports `app.main` under the new env, and (4) builds a fresh
`TestClient` on top.

Purge happens only on setup, not teardown. Other test files
(e.g. `test_enterprise_adapter.py`) may have already bound their own
top-level references to `app.*` modules at collection time; blowing those
references away on teardown would leave those tests holding dead handles.
Leaving the freshly-imported modules in `sys.modules` after our tests is
harmless — the next `fresh_app` will purge them again on its own setup.
"""
from __future__ import annotations

import sys

import pytest


def _pw(label: str) -> str:
    """Deterministic synthetic password meeting the app's complexity policy.

    Kept identical to the helper used by `app.selftest_isolation` so tests
    read the same way as the multi-tenant selftest.
    """
    return f"{label}Aa12345!"


def _purge_app_modules() -> None:
    """Drop every `app` / `app.*` module from `sys.modules` so the next
    `import app.main` re-executes module bodies against the current env.
    """
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)


@pytest.fixture()
def fresh_app(monkeypatch, tmp_path):
    """Fresh FastAPI app + fresh empty SQLite DB, isolated per test.

    Yields a `TestClient` pointing at a brand-new app instance. Nothing has
    been created inside it yet — no operator, no tenants — so tests can
    exercise `/setup/operator` directly if they need to.
    """
    _purge_app_modules()

    db_path = tmp_path / "threatforge_test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET", _pw("JwtSecret"))
    monkeypatch.setenv("API_KEY", "")
    monkeypatch.setenv("BOOTSTRAP_OPERATOR_EMAIL", "")
    monkeypatch.setenv("BOOTSTRAP_OPERATOR_PASSWORD", "")
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "local")
    monkeypatch.setenv("EVIDENCE_STORAGE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("EVIDENCE_MAX_BYTES", "2048")

    # Import order matters: TestClient is safe to import ahead of time, but
    # `app.main` must be imported *after* the env vars are in place so its
    # module body picks up the tmp DATABASE_URL when it constructs `engine`.
    from fastapi.testclient import TestClient
    from app.main import app

    yield TestClient(app)


@pytest.fixture()
def tenant_admin_client(fresh_app):
    """Fresh app with one platform operator, one tenant and a logged-in
    tenant admin. Yields the admin's authenticated `TestClient`.
    """
    op = fresh_app
    r = op.post(
        "/setup/operator",
        json={"email": "op@plat.com", "password": _pw("Operator")},
    )
    assert r.status_code == 201, r.text

    rt = op.post(
        "/tenants",
        json={
            "name": "Tenant Test",
            "admin_email": "admin@test.com",
            "admin_password": _pw("TenantAdmin"),
        },
    )
    assert rt.status_code == 201, rt.text

    # Reuse the freshly-imported `app` from `fresh_app` — same module in
    # `sys.modules`, so this returns the same FastAPI instance / engine /
    # session. A separate `TestClient` gives the admin its own cookie jar.
    from fastapi.testclient import TestClient
    from app.main import app

    admin = TestClient(app)
    rl = admin.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": _pw("TenantAdmin")},
    )
    assert rl.status_code == 200, rl.text
    return admin
