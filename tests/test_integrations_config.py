"""ThreatForge Community v0.9.2 — Enterprise integration configuration.

Covers the release contract for
:mod:`app.routers.integrations_routes` and :class:`app.models.IntegrationConnection`:

* Community without an entitlement keeps returning **402** and audit
  ``integration.*_denied`` — the Enterprise/licence overlay is respected.
* With the descriptor's ``Feature`` granted (simulated by monkeypatching
  :func:`app.features.entitlements` after the app is imported), the three
  endpoints stop returning 501:

  - ``POST /integrations/{name}/connections`` persists a minimal, non-secret
    connection row for MISP, OpenCTI and Generic/Webhook.
  - ``POST /integrations/{name}/test`` returns ``configured/status/message``.
  - ``POST /integrations/{name}/sync`` returns ``accepted/status/message``.

* Secret fields (``api_key``, ``api_token``, ``token``, ``secret``, ``password``,
  ``client_secret``, ``auth_key``, ``private_key``) are stripped before
  persistence and only their masked presence flag is echoed back.

* Tenant isolation: tenant A cannot see or overwrite tenant B's connection.

Isolation: uses ``fresh_app`` / ``tenant_admin_client`` from :mod:`conftest`
(sys.modules purge + tmp_path SQLite) so each test starts from a clean DB.
"""
from __future__ import annotations

import pytest


def _pw(label: str) -> str:
    """Match the deterministic synthetic password helper used in conftest."""
    return f"{label}Aa12345!"


def _enable(monkeypatch, *feature_names: str) -> None:
    """Grant the listed canonical Feature keys via the licence stub.

    We monkeypatch :func:`app.features.entitlements` after ``fresh_app`` has
    imported ``app.main`` — this bypasses the real Enterprise adapter without
    needing a licence file, private key or Enterprise package installed.
    """
    from app import features as feats
    from app.features import Feature

    wanted = {Feature(name) for name in feature_names}
    monkeypatch.setattr(feats, "entitlements", lambda: wanted)


def _create_tenant_admin(op_client, tenant_name: str, admin_email: str):
    """Create a tenant + admin via the platform-operator client, return admin TestClient."""
    from fastapi.testclient import TestClient
    from app.main import app

    r = op_client.post("/tenants", json={
        "name": tenant_name,
        "admin_email": admin_email,
        "admin_password": _pw("TenantAdmin"),
    })
    assert r.status_code == 201, r.text
    admin = TestClient(app)
    rl = admin.post("/auth/login", json={
        "email": admin_email, "password": _pw("TenantAdmin"),
    })
    assert rl.status_code == 200, rl.text
    return admin


# ---------------------------------------------------------------------------
# Community (no entitlement): 402 must remain
# ---------------------------------------------------------------------------
def test_community_without_entitlement_returns_402_on_configure(tenant_admin_client):
    r = tenant_admin_client.post("/integrations/misp/connections",
                                 json={"base_url": "https://misp.example.org"})
    assert r.status_code == 402, r.text
    body = r.json()
    assert body.get("feature") == "integration.misp"
    assert (body.get("upgrade") or {}).get("email")


def test_community_without_entitlement_returns_402_on_test_and_sync(tenant_admin_client):
    rt = tenant_admin_client.post("/integrations/misp/test", json={})
    rs = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert rt.status_code == 402, rt.text
    assert rs.status_code == 402, rs.text


def test_community_denied_actions_are_audited(tenant_admin_client):
    tenant_admin_client.post("/integrations/generic/connections", json={})
    tenant_admin_client.post("/integrations/generic/test", json={})
    tenant_admin_client.post("/integrations/generic/sync", json={})
    audit = tenant_admin_client.get("/audit").json()
    actions = {a.get("action") for a in audit}
    assert "integration.config_denied" in actions
    assert "integration.test_denied" in actions
    assert "integration.sync_denied" in actions


# ---------------------------------------------------------------------------
# Enterprise licence unlocks — MISP / OpenCTI / Generic
# ---------------------------------------------------------------------------
def test_enterprise_misp_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp.example.org",
        "verify_tls": True,
        "direction": "pull",
        "tags": ["tlp:white"],
        "sync_interval_minutes": 30,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "misp"
    assert body["enabled"] is True
    assert body["config"]["base_url"] == "https://misp.example.org"
    assert body["config"]["direction"] == "pull"
    assert body["config"]["tags"] == ["tlp:white"]
    assert body["secrets_metadata"] == {}
    assert body["id"] and body["tenant_id"] and body["created_at"]


def test_enterprise_opencti_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    r = tenant_admin_client.post("/integrations/opencti/connections", json={
        "base_url": "https://opencti.example.org",
        "verify_tls": False,
        "direction": "both",
        "sync_interval_minutes": 60,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "opencti"
    assert body["config"]["base_url"] == "https://opencti.example.org"
    assert body["config"]["verify_tls"] is False
    assert body["config"]["direction"] == "both"


def test_enterprise_generic_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.generic")
    r = tenant_admin_client.post("/integrations/generic/connections", json={
        "endpoint_url": "https://sink.example.org/ingest",
        "format": "stix2",
        "direction": "push",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "generic"
    assert body["config"]["endpoint_url"] == "https://sink.example.org/ingest"
    assert body["config"]["format"] == "stix2"


def test_enterprise_configure_accepts_minimal_payload(tenant_admin_client, monkeypatch):
    """v0.9.2 accepts an empty body as a valid minimal configuration.

    The Enterprise connector will enforce full-schema validation on real
    push/pull. Community's job here is only to unblock the UI: the front-end
    posts ``{}`` when the user clicks Configure, and that must succeed.
    """
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["config"] == {}
    assert body["secrets_metadata"] == {}


def test_enterprise_configure_upsert_updates_existing_row(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r1 = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp-a.example.org", "direction": "pull"})
    assert r1.status_code == 200
    r2 = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp-b.example.org", "direction": "push"})
    assert r2.status_code == 200
    # Same row (unique on tenant_id+name), config replaced with the newest payload.
    assert r2.json()["id"] == r1.json()["id"]
    assert r2.json()["config"]["base_url"] == "https://misp-b.example.org"
    assert r2.json()["config"]["direction"] == "push"


# ---------------------------------------------------------------------------
# Secret masking
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("secret_field", [
    "api_key", "api_token", "token", "secret", "password",
    "client_secret", "auth_key", "private_key",
])
def test_secrets_are_stripped_from_response_and_persistence(
    tenant_admin_client, monkeypatch, secret_field,
):
    """Every documented secret key is redacted before persistence and response."""
    _enable(monkeypatch, "integration.misp")
    plain = "s3cret-value-that-must-never-leak"
    r = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp.example.org",
        secret_field: plain,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    # Response never carries the plaintext.
    assert secret_field not in body["config"]
    assert plain not in r.text
    # But we record that a secret was received.
    assert secret_field in body["secrets_metadata"]
    assert body["secrets_metadata"][secret_field] == {"present": True, "masked": "***"}

    # Direct DB read: the row stores neither the plaintext value nor the raw key.
    from app.database import SessionLocal
    from app.models import IntegrationConnection
    with SessionLocal() as db:
        row = db.query(IntegrationConnection).first()
        assert row is not None
        assert secret_field not in (row.config_json or {})
        assert plain not in str(row.config_json or {})


def test_secret_field_names_are_case_insensitive(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp.example.org",
        "API_KEY": "leaky",
        "Token": "leaky-2",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "API_KEY" not in body["config"]
    assert "Token" not in body["config"]
    assert "leaky" not in r.text
    assert set(body["secrets_metadata"].keys()) == {"API_KEY", "Token"}


# ---------------------------------------------------------------------------
# /test and /sync no longer return 501 when licensed
# ---------------------------------------------------------------------------
def test_enterprise_test_returns_not_configured_before_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/test", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is False
    assert body["status"] == "not_configured"
    assert "message" in body


def test_enterprise_test_returns_ready_after_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections",
                             json={"base_url": "https://misp.example.org"})
    r = tenant_admin_client.post("/integrations/misp/test", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True
    assert body["status"] == "ready"


def test_enterprise_sync_returns_not_configured_before_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    r = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is False
    assert body["status"] == "not_configured"


def test_enterprise_sync_returns_queued_after_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    tenant_admin_client.post("/integrations/opencti/connections",
                             json={"base_url": "https://opencti.example.org"})
    r = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is True
    assert body["status"] == "queued"


def test_enterprise_endpoints_never_return_501(tenant_admin_client, monkeypatch):
    """Regression guard for the v0.9.1 behaviour where all three endpoints 501'd.

    Once the feature is unlocked, none of the three endpoints may respond with
    Not Implemented — that was the bug the release was cut to fix.
    """
    _enable(monkeypatch, "integration.generic",
            "integration.misp", "integration.opencti")
    for name in ("misp", "opencti", "generic"):
        assert tenant_admin_client.post(
            f"/integrations/{name}/connections", json={}).status_code != 501
        assert tenant_admin_client.post(
            f"/integrations/{name}/test", json={}).status_code != 501
        assert tenant_admin_client.post(
            f"/integrations/{name}/sync", json={}).status_code != 501


# ---------------------------------------------------------------------------
# Audit trail for the licensed path
# ---------------------------------------------------------------------------
def test_enterprise_audit_logs_config_test_and_sync_requested(
    tenant_admin_client, monkeypatch,
):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections",
                             json={"base_url": "https://misp.example.org",
                                   "api_key": "wont-be-stored"})
    tenant_admin_client.post("/integrations/misp/test", json={})
    tenant_admin_client.post("/integrations/misp/sync", json={})

    audit = tenant_admin_client.get("/audit").json()
    actions = [a.get("action") for a in audit]
    assert "integration.config_saved" in actions
    assert "integration.test_requested" in actions
    assert "integration.sync_requested" in actions
    # And crucially: no *_denied for these three, and no secret value in detail.
    denied = {"integration.config_denied", "integration.test_denied",
              "integration.sync_denied"}
    assert not denied.intersection(actions)
    for entry in audit:
        assert "wont-be-stored" not in str(entry)


# ---------------------------------------------------------------------------
# Unknown integration name still 404 (feature gate must not swallow 404)
# ---------------------------------------------------------------------------
def test_unknown_integration_returns_404_even_with_all_entitlements(
    tenant_admin_client, monkeypatch,
):
    _enable(monkeypatch, "integration.misp",
            "integration.opencti", "integration.generic")
    r = tenant_admin_client.post("/integrations/does-not-exist/connections", json={})
    assert r.status_code == 404, r.text


# ---------------------------------------------------------------------------
# RBAC: non-admin still blocked before the gate applies
# ---------------------------------------------------------------------------
def test_viewer_cannot_configure_even_when_licensed(fresh_app, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    op = fresh_app
    assert op.post("/setup/operator",
                   json={"email": "op@plat.com",
                         "password": _pw("Operator")}).status_code == 201
    assert op.post("/tenants", json={
        "name": "Tenant Test",
        "admin_email": "admin@test.com",
        "admin_password": _pw("TenantAdmin"),
    }).status_code == 201

    from fastapi.testclient import TestClient
    from app.main import app
    admin = TestClient(app)
    assert admin.post("/auth/login", json={
        "email": "admin@test.com", "password": _pw("TenantAdmin"),
    }).status_code == 200

    # Tenant admin adds a viewer directly via POST /users — same path the
    # multi-tenant selftest exercises when it wants a read-only account.
    r_create = admin.post("/users", json={
        "email": "viewer@test.com",
        "password": _pw("Viewer"),
        "role": "viewer",
    })
    assert r_create.status_code in (200, 201), r_create.text

    viewer = TestClient(app)
    assert viewer.post("/auth/login", json={
        "email": "viewer@test.com", "password": _pw("Viewer"),
    }).status_code == 200

    r = viewer.post("/integrations/misp/connections", json={})
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------
def test_tenant_isolation_a_cannot_see_or_overwrite_b(fresh_app, monkeypatch):
    """Two tenants each configure ``misp``; each keeps its own row untouched."""
    _enable(monkeypatch, "integration.misp")
    op = fresh_app
    assert op.post("/setup/operator", json={
        "email": "op@plat.com", "password": _pw("Operator"),
    }).status_code == 201

    admin_a = _create_tenant_admin(op, "Tenant A", "admin-a@test.com")
    admin_b = _create_tenant_admin(op, "Tenant B", "admin-b@test.com")

    ra = admin_a.post("/integrations/misp/connections",
                      json={"base_url": "https://misp-a.example.org"})
    rb = admin_b.post("/integrations/misp/connections",
                      json={"base_url": "https://misp-b.example.org"})
    assert ra.status_code == 200, ra.text
    assert rb.status_code == 200, rb.text
    row_a, row_b = ra.json(), rb.json()

    # Two distinct rows for two distinct tenants (unique constraint is per tenant).
    assert row_a["id"] != row_b["id"]
    assert row_a["tenant_id"] != row_b["tenant_id"]
    assert row_a["config"]["base_url"] == "https://misp-a.example.org"
    assert row_b["config"]["base_url"] == "https://misp-b.example.org"

    # After A saves again, B's stored row is untouched — no cross-tenant write.
    admin_a.post("/integrations/misp/connections",
                 json={"base_url": "https://misp-a-updated.example.org"})
    rb_test = admin_b.post("/integrations/misp/test", json={})
    assert rb_test.status_code == 200
    assert rb_test.json()["configured"] is True

    # Direct DB introspection: exactly two rows, one per tenant, values intact.
    from app.database import SessionLocal
    from app.models import IntegrationConnection
    with SessionLocal() as db:
        rows = db.query(IntegrationConnection).order_by(
            IntegrationConnection.tenant_id).all()
        assert len(rows) == 2
        by_tenant = {r.tenant_id: r for r in rows}
        assert by_tenant[row_a["tenant_id"]].config_json["base_url"] == (
            "https://misp-a-updated.example.org")
        assert by_tenant[row_b["tenant_id"]].config_json["base_url"] == (
            "https://misp-b.example.org")


def test_tenant_isolation_test_endpoint_only_sees_own_row(fresh_app, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    op = fresh_app
    assert op.post("/setup/operator", json={
        "email": "op@plat.com", "password": _pw("Operator"),
    }).status_code == 201

    admin_a = _create_tenant_admin(op, "Tenant A", "admin-a@test.com")
    admin_b = _create_tenant_admin(op, "Tenant B", "admin-b@test.com")

    # Only A configures. B must report not_configured — never A's row.
    admin_a.post("/integrations/opencti/connections",
                 json={"base_url": "https://opencti-a.example.org"})
    rb = admin_b.post("/integrations/opencti/test", json={})
    assert rb.status_code == 200
    body = rb.json()
    assert body["configured"] is False
    assert body["status"] == "not_configured"
