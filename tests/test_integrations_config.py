"""ThreatForge Community v0.9.2 — Enterprise integration configuration.

Extended for v0.9.3 with required-fields enforcement:
* ``POST /integrations/{name}/connections`` returns **422** with a
  ``missing_fields`` breakdown whenever a required config or secret name is
  absent; nothing is persisted and the router audits
  ``integration.config_rejected``.
* ``/test`` and ``/sync`` only report ``ready``/``queued`` once the stored row
  satisfies :func:`_is_ready` — a row with ``base_url`` but no ``api_key``
  marker is *persisted*-nothing (rejected) or, on partial upgrade paths, still
  reports ``not_configured``.
* A new ``GET /integrations/{name}/connections`` endpoint returns the current
  row (masked) so the UI can prefill the modal on subsequent opens.
* ``GET /integrations/{name}`` now also returns ``secrets_schema`` describing
  the required/optional secret names for the connector.

Covers the release contract for :mod:`app.routers.integrations_routes` and
:class:`app.models.IntegrationConnection`. Community without an entitlement
keeps returning **402** and audit ``integration.*_denied`` — the Enterprise/
licence overlay is respected. Secrets remain stripped from persistence and
response bodies.

Isolation: uses ``fresh_app`` / ``tenant_admin_client`` from :mod:`conftest`
(sys.modules purge + tmp_path SQLite) so each test starts from a clean DB.
"""
from __future__ import annotations

import pytest


def _pw(label: str) -> str:
    """Match the deterministic synthetic password helper used in conftest."""
    return f"{label}Aa12345!"


def _enable(monkeypatch, *feature_names: str) -> None:
    """Grant the listed canonical Feature keys via the licence stub."""
    from app import features as feats
    from app.features import Feature

    wanted = {Feature(name) for name in feature_names}
    monkeypatch.setattr(feats, "entitlements", lambda: wanted)


def _create_tenant_admin(op_client, tenant_name: str, admin_email: str):
    """Create a tenant + admin via the platform-operator client."""
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


# Minimal payloads that satisfy each connector's required contract.
_MISP_OK = {"base_url": "https://misp.example.org", "api_key": "misp-plain-secret"}
_OPENCTI_OK = {"base_url": "https://opencti.example.org", "api_token": "opencti-plain-token"}
_GENERIC_OK = {"endpoint_url": "https://sink.example.org/ingest"}


# ---------------------------------------------------------------------------
# Community (no entitlement): 402 must remain
# ---------------------------------------------------------------------------
def test_community_without_entitlement_returns_402_on_configure(tenant_admin_client):
    r = tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    assert r.status_code == 402, r.text
    body = r.json()
    assert body.get("feature") == "integration.misp"
    assert (body.get("upgrade") or {}).get("email")


def test_community_without_entitlement_returns_402_on_test_and_sync(tenant_admin_client):
    rt = tenant_admin_client.post("/integrations/misp/test", json={})
    rs = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert rt.status_code == 402, rt.text
    assert rs.status_code == 402, rs.text


def test_community_without_entitlement_returns_402_on_read(tenant_admin_client):
    r = tenant_admin_client.get("/integrations/misp/connections")
    assert r.status_code == 402, r.text


def test_community_denied_actions_are_audited(tenant_admin_client):
    tenant_admin_client.post("/integrations/generic/connections", json={})
    tenant_admin_client.post("/integrations/generic/test", json={})
    tenant_admin_client.post("/integrations/generic/sync", json={})
    tenant_admin_client.get("/integrations/generic/connections")
    audit = tenant_admin_client.get("/audit").json()
    actions = {a.get("action") for a in audit}
    assert "integration.config_denied" in actions
    assert "integration.test_denied" in actions
    assert "integration.sync_denied" in actions
    assert "integration.read_denied" in actions


# ---------------------------------------------------------------------------
# Descriptor GET exposes secrets_schema (used by the UI modal)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name, req, opt", [
    ("misp", ["api_key"], []),
    ("opencti", ["api_token"], []),
    ("generic", [], ["token", "secret"]),
])
def test_get_integration_exposes_secrets_schema(tenant_admin_client, name, req, opt):
    r = tenant_admin_client.get(f"/integrations/{name}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "config_schema" in body
    assert body["config_schema"].get("properties")
    assert "secrets_schema" in body
    assert body["secrets_schema"]["required"] == req
    assert body["secrets_schema"]["optional"] == opt


def test_get_integration_unknown_name_returns_404(tenant_admin_client):
    r = tenant_admin_client.get("/integrations/does-not-exist")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Enterprise licence unlocks — MISP / OpenCTI / Generic with required fields
# ---------------------------------------------------------------------------
def test_enterprise_misp_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={
        **_MISP_OK,
        "verify_tls": True,
        "direction": "pull",
        "tags": ["tlp:white"],
        "sync_interval_minutes": 30,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "misp"
    assert body["enabled"] is True
    assert body["ready"] is True
    assert body["config"]["base_url"] == "https://misp.example.org"
    assert body["config"]["direction"] == "pull"
    assert body["config"]["tags"] == ["tlp:white"]
    # api_key stripped from config, recorded as present in secrets_metadata.
    assert "api_key" not in body["config"]
    assert body["secrets_metadata"]["api_key"] == {"present": True, "masked": "***"}
    assert "misp-plain-secret" not in r.text
    assert body["id"] and body["tenant_id"] and body["created_at"]


def test_enterprise_opencti_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    r = tenant_admin_client.post("/integrations/opencti/connections", json={
        **_OPENCTI_OK,
        "verify_tls": False,
        "direction": "both",
        "sync_interval_minutes": 60,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "opencti"
    assert body["ready"] is True
    assert body["config"]["base_url"] == "https://opencti.example.org"
    assert body["config"]["verify_tls"] is False
    assert body["config"]["direction"] == "both"
    assert "api_token" not in body["config"]
    assert body["secrets_metadata"]["api_token"] == {"present": True, "masked": "***"}
    assert "opencti-plain-token" not in r.text


def test_enterprise_generic_configure_persists_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.generic")
    r = tenant_admin_client.post("/integrations/generic/connections", json={
        **_GENERIC_OK,
        "format": "stix2",
        "direction": "push",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "generic"
    assert body["ready"] is True
    assert body["config"]["endpoint_url"] == "https://sink.example.org/ingest"
    assert body["config"]["format"] == "stix2"
    # Generic has no required secrets: an empty secrets_metadata is still ready.
    assert body["secrets_metadata"] == {}


def test_enterprise_generic_accepts_optional_secret_masked(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.generic")
    r = tenant_admin_client.post("/integrations/generic/connections", json={
        **_GENERIC_OK, "token": "webhook-shared-secret",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ready"] is True
    assert "token" not in body["config"]
    assert body["secrets_metadata"]["token"] == {"present": True, "masked": "***"}
    assert "webhook-shared-secret" not in r.text


# ---------------------------------------------------------------------------
# v0.9.3: required-fields validation — empty and partial payloads rejected
# ---------------------------------------------------------------------------
def test_enterprise_configure_rejects_empty_payload_with_422(tenant_admin_client, monkeypatch):
    """v0.9.3 replaces the v0.9.2 'accept empty body' behaviour.

    The Integrations UI now opens a modal and collects real fields; a payload
    of ``{}`` means the operator submitted nothing, and the router must refuse
    rather than persist an incomplete row that ``/test`` would later report as
    not_configured — the v0.9.2 UX said 'Integration configured' after that
    call, which was misleading. The user preference for that flow was fixed.
    """
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert set(detail["missing_fields"]) == {"base_url", "api_key"}
    assert detail["missing_config_fields"] == ["base_url"]
    assert detail["missing_required_secrets"] == ["api_key"]

    # And crucially: nothing was persisted.
    from app.database import SessionLocal
    from app.models import IntegrationConnection
    with SessionLocal() as db:
        assert db.query(IntegrationConnection).count() == 0


def test_enterprise_configure_rejects_missing_required_secret(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections",
                                 json={"base_url": "https://misp.example.org"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_fields"] == ["api_key"]
    assert detail["missing_config_fields"] == []
    assert detail["missing_required_secrets"] == ["api_key"]


def test_enterprise_configure_rejects_missing_required_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections",
                                 json={"api_key": "just-the-secret"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_fields"] == ["base_url"]
    assert detail["missing_config_fields"] == ["base_url"]


def test_enterprise_configure_rejected_is_audited_without_secret_value(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json={
        "api_key": "this-must-not-appear-in-audit",
    })
    audit = tenant_admin_client.get("/audit").json()
    actions = [a.get("action") for a in audit]
    assert "integration.config_rejected" in actions
    # Secret value never lands in audit detail.
    for entry in audit:
        assert "this-must-not-appear-in-audit" not in str(entry)


def test_enterprise_generic_accepts_only_endpoint_url(tenant_admin_client, monkeypatch):
    """Generic has no required secret — endpoint_url alone is a valid row."""
    _enable(monkeypatch, "integration.generic")
    r = tenant_admin_client.post("/integrations/generic/connections", json=_GENERIC_OK)
    assert r.status_code == 200, r.text
    assert r.json()["ready"] is True


def test_enterprise_generic_rejects_empty(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.generic")
    r = tenant_admin_client.post("/integrations/generic/connections", json={})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_fields"] == ["endpoint_url"]


# ---------------------------------------------------------------------------
# Upsert / prefill via GET
# ---------------------------------------------------------------------------
def test_enterprise_configure_upsert_updates_existing_row(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r1 = tenant_admin_client.post("/integrations/misp/connections", json={
        **_MISP_OK, "direction": "pull"})
    assert r1.status_code == 200
    r2 = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp-b.example.org", "api_key": "rotated-secret",
        "direction": "push"})
    assert r2.status_code == 200
    # Same row (unique on tenant_id+name), config replaced with the newest payload.
    assert r2.json()["id"] == r1.json()["id"]
    assert r2.json()["config"]["base_url"] == "https://misp-b.example.org"
    assert r2.json()["config"]["direction"] == "push"
    # And the rotated secret is still just a masked marker.
    assert r2.json()["secrets_metadata"]["api_key"]["present"] is True


def test_enterprise_reupsert_without_secret_keeps_marker(tenant_admin_client, monkeypatch):
    """Editing non-secret fields with a blank credential input must succeed.

    The modal leaves the password input blank on re-open (the value never
    leaves the server), so a config-only edit sends no ``api_key``. The
    router must:

      1. Load the existing row *before* running required-secret validation.
      2. Treat the required secret as satisfied because the on-file marker
         says ``present=True``.
      3. Merge markers instead of overwriting, so ``/test`` still says
         ``ready`` afterwards.

    This is the exact bug that was caught in code review before applying
    v0.9.3: previously the validator only looked at the payload and
    422'd on a legitimate re-save.
    """
    _enable(monkeypatch, "integration.misp")

    # First configuration: full payload -> 200 ready.
    r1 = tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    assert r1.status_code == 200, r1.text
    assert r1.json()["ready"] is True

    # Second configuration: only the non-secret change; input for api_key was blank.
    r2 = tenant_admin_client.post("/integrations/misp/connections", json={
        "base_url": "https://misp-new.example.org",
    })
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["ready"] is True
    assert body["config"]["base_url"] == "https://misp-new.example.org"
    assert body["secrets_metadata"]["api_key"]["present"] is True

    # GET /connections keeps reporting the marker.
    rg = tenant_admin_client.get("/integrations/misp/connections")
    assert rg.status_code == 200
    assert rg.json()["secrets_metadata"]["api_key"]["present"] is True
    assert rg.json()["ready"] is True

    # /test still ready after the config-only edit.
    rt = tenant_admin_client.post("/integrations/misp/test", json={})
    assert rt.status_code == 200 and rt.json()["status"] == "ready"


def test_enterprise_reupsert_without_secret_keeps_marker_opencti(
    tenant_admin_client, monkeypatch,
):
    """Same guarantee for OpenCTI / ``api_token``.

    Mirrors the MISP flow. Included explicitly so a future change that
    silently regresses only one connector fails visibly.
    """
    _enable(monkeypatch, "integration.opencti")

    r1 = tenant_admin_client.post("/integrations/opencti/connections", json=_OPENCTI_OK)
    assert r1.status_code == 200, r1.text
    assert r1.json()["ready"] is True

    r2 = tenant_admin_client.post("/integrations/opencti/connections", json={
        "base_url": "https://opencti-new.example.org",
    })
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["ready"] is True
    assert body["config"]["base_url"] == "https://opencti-new.example.org"
    assert body["secrets_metadata"]["api_token"]["present"] is True

    rg = tenant_admin_client.get("/integrations/opencti/connections")
    assert rg.status_code == 200
    assert rg.json()["secrets_metadata"]["api_token"]["present"] is True

    rt = tenant_admin_client.post("/integrations/opencti/test", json={})
    assert rt.status_code == 200 and rt.json()["status"] == "ready"


def test_first_configuration_still_requires_secret_misp(tenant_admin_client, monkeypatch):
    """No existing row => the required-secret exemption must NOT apply.

    Sending only ``base_url`` on the very first configuration is a real
    missing-field, not a re-save; the router must still 422.
    """
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections",
                                 json={"base_url": "https://misp.example.org"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_required_secrets"] == ["api_key"]
    assert detail["missing_config_fields"] == []


def test_first_configuration_still_requires_secret_opencti(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    r = tenant_admin_client.post("/integrations/opencti/connections",
                                 json={"base_url": "https://opencti.example.org"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_required_secrets"] == ["api_token"]


def test_first_configuration_empty_payload_still_422(tenant_admin_client, monkeypatch):
    """The re-save exemption must not turn empty-payload into success."""
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/connections", json={})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert set(detail["missing_fields"]) == {"base_url", "api_key"}


def test_reupsert_still_requires_config_fields_even_with_marker(
    tenant_admin_client, monkeypatch,
):
    """The on-file exemption covers only *secrets*, never config fields.

    If the operator clears a required non-secret field (e.g. ``base_url``)
    the router must still 422 — the modal prefills those fields for a
    reason, and an explicit blank is a real error, not an intended
    inheritance.
    """
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    r = tenant_admin_client.post("/integrations/misp/connections",
                                 json={"api_key": "rotated"})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["missing_config_fields"] == ["base_url"]
    assert detail["missing_required_secrets"] == []


def test_reupsert_with_new_secret_replaces_marker(tenant_admin_client, monkeypatch):
    """A payload that DOES carry a new secret replaces the on-file marker.

    The marker's ``present`` stays True either way, but the newest value is
    what the (future) Enterprise vault would encrypt. Community can't verify
    this from the marker alone, so we check that ``config_saved`` audits the
    key was received this turn.
    """
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    r = tenant_admin_client.post("/integrations/misp/connections", json={
        **_MISP_OK, "api_key": "rotated-value",
    })
    assert r.status_code == 200, r.text
    assert r.json()["secrets_metadata"]["api_key"]["present"] is True
    assert "rotated-value" not in r.text

    audit = tenant_admin_client.get("/audit").json()
    saved = [a for a in audit if a.get("action") == "integration.config_saved"]
    # We made two saves; at least one config_saved must show api_key received.
    assert saved
    with_key = [a for a in saved
                if "api_key" in ((a.get("detail") or {}).get("secrets_present") or [])]
    assert with_key, saved


def test_get_connections_returns_null_before_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.get("/integrations/misp/connections")
    assert r.status_code == 200, r.text
    assert r.json() is None


def test_get_connections_returns_masked_row_after_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    r = tenant_admin_client.get("/integrations/misp/connections")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "misp"
    assert body["config"]["base_url"] == "https://misp.example.org"
    assert body["ready"] is True
    # The plaintext secret is never returned by the GET either.
    assert "misp-plain-secret" not in r.text
    assert body["secrets_metadata"]["api_key"] == {"present": True, "masked": "***"}


# ---------------------------------------------------------------------------
# Secret masking — parametric across every documented key
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("secret_field", [
    "api_key", "api_token", "token", "secret", "password",
    "client_secret", "auth_key", "private_key",
])
def test_secrets_are_stripped_from_response_and_persistence(
    tenant_admin_client, monkeypatch, secret_field,
):
    """Every documented secret key is redacted before persistence and response.

    Uses the ``generic`` connector because it has no required secret, so we
    can exercise the strip pass with any single secret key without also
    needing to send an unrelated required credential to satisfy validation.
    """
    _enable(monkeypatch, "integration.generic")
    plain = "s3cret-value-that-must-never-leak"
    r = tenant_admin_client.post("/integrations/generic/connections", json={
        **_GENERIC_OK, secret_field: plain,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert secret_field not in body["config"]
    assert plain not in r.text
    assert secret_field in body["secrets_metadata"]
    assert body["secrets_metadata"][secret_field] == {"present": True, "masked": "***"}

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
        "API_KEY": "leaky",  # required (case-insensitive)
        "Token": "leaky-2",  # extra
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "API_KEY" not in body["config"]
    assert "Token" not in body["config"]
    assert "leaky" not in r.text
    assert set(body["secrets_metadata"].keys()) == {"API_KEY", "Token"}


# ---------------------------------------------------------------------------
# /test and /sync — ready only when the row satisfies the required-fields
# predicate; not_configured otherwise
# ---------------------------------------------------------------------------
def test_test_returns_not_configured_before_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    r = tenant_admin_client.post("/integrations/misp/test", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is False
    assert body["status"] == "not_configured"


def test_test_returns_ready_after_valid_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    r = tenant_admin_client.post("/integrations/misp/test", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True
    assert body["status"] == "ready"


def test_sync_returns_not_configured_before_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    r = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is False
    assert body["status"] == "not_configured"


def test_sync_returns_queued_after_valid_save(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.opencti")
    tenant_admin_client.post("/integrations/opencti/connections", json=_OPENCTI_OK)
    r = tenant_admin_client.post("/integrations/opencti/sync", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is True
    assert body["status"] == "queued"


def test_endpoints_never_return_501_when_licensed(tenant_admin_client, monkeypatch):
    """Regression guard for the v0.9.1 bug where all three endpoints 501'd."""
    _enable(monkeypatch, "integration.generic",
            "integration.misp", "integration.opencti")
    # POST /connections may 422 for empty bodies now — that's still not 501.
    for name in ("misp", "opencti", "generic"):
        assert tenant_admin_client.post(
            f"/integrations/{name}/connections", json={}).status_code != 501
        assert tenant_admin_client.post(
            f"/integrations/{name}/test", json={}).status_code != 501
        assert tenant_admin_client.post(
            f"/integrations/{name}/sync", json={}).status_code != 501
        assert tenant_admin_client.get(
            f"/integrations/{name}/connections").status_code != 501


# ---------------------------------------------------------------------------
# Audit trail for the licensed path
# ---------------------------------------------------------------------------
def test_audit_logs_config_saved_test_and_sync_requested(
    tenant_admin_client, monkeypatch,
):
    _enable(monkeypatch, "integration.misp")
    tenant_admin_client.post("/integrations/misp/connections", json=_MISP_OK)
    tenant_admin_client.post("/integrations/misp/test", json={})
    tenant_admin_client.post("/integrations/misp/sync", json={})

    audit = tenant_admin_client.get("/audit").json()
    actions = [a.get("action") for a in audit]
    assert "integration.config_saved" in actions
    assert "integration.test_requested" in actions
    assert "integration.sync_requested" in actions
    denied = {"integration.config_denied", "integration.test_denied",
              "integration.sync_denied", "integration.config_rejected"}
    assert not denied.intersection(actions)
    # And the secret value never appears anywhere in the audit trail.
    for entry in audit:
        assert "misp-plain-secret" not in str(entry)


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

    r = viewer.post("/integrations/misp/connections", json=_MISP_OK)
    assert r.status_code == 403, r.text
    # But viewer can still READ the stored row (masked) once one exists —
    # write-side actions require admin, read is viewer+.
    admin.post("/integrations/misp/connections", json=_MISP_OK)
    r_read = viewer.get("/integrations/misp/connections")
    assert r_read.status_code == 200
    assert r_read.json()["ready"] is True
    assert "misp-plain-secret" not in r_read.text


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

    ra = admin_a.post("/integrations/misp/connections", json={
        "base_url": "https://misp-a.example.org", "api_key": "key-a"})
    rb = admin_b.post("/integrations/misp/connections", json={
        "base_url": "https://misp-b.example.org", "api_key": "key-b"})
    assert ra.status_code == 200, ra.text
    assert rb.status_code == 200, rb.text
    row_a, row_b = ra.json(), rb.json()

    assert row_a["id"] != row_b["id"]
    assert row_a["tenant_id"] != row_b["tenant_id"]
    assert row_a["config"]["base_url"] == "https://misp-a.example.org"
    assert row_b["config"]["base_url"] == "https://misp-b.example.org"

    # A saving again leaves B's row untouched — no cross-tenant write.
    admin_a.post("/integrations/misp/connections", json={
        "base_url": "https://misp-a-updated.example.org", "api_key": "key-a-2"})
    rb_test = admin_b.post("/integrations/misp/test", json={})
    assert rb_test.status_code == 200
    assert rb_test.json()["configured"] is True

    # And B's stored row seen via GET is still the original.
    rb_read = admin_b.get("/integrations/misp/connections")
    assert rb_read.status_code == 200
    assert rb_read.json()["config"]["base_url"] == "https://misp-b.example.org"

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

    admin_a.post("/integrations/opencti/connections", json={
        "base_url": "https://opencti-a.example.org", "api_token": "tok-a"})
    rb = admin_b.post("/integrations/opencti/test", json={})
    assert rb.status_code == 200
    body = rb.json()
    assert body["configured"] is False
    assert body["status"] == "not_configured"

    rb_read = admin_b.get("/integrations/opencti/connections")
    assert rb_read.status_code == 200
    assert rb_read.json() is None
