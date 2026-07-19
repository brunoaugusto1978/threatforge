"""GET /dashboard/overview — v0.11.0 real-data operational dashboard.

Covers the release contract for :mod:`app.routers.dashboard_routes`:

* Tenant-scoped, viewer+ (mirrors ``GET /stats``): unauthenticated -> 401,
  a plain viewer can read it, two tenants never see each other's numbers.
* Every number is derived from real rows created through the normal API
  (no mock/sample data ever appears when a tenant is empty — the aggregate
  is just 0/[] for everything).
* The response never carries secrets/tokens/api_key/hashed_password/
  config_json/secrets_metadata, even when a licensed Enterprise integration
  connection has been configured with a real secret value.
* "Top exposed assets" never leaks the raw ``MonitoredAsset.value`` (which
  can hold PII such as an e-mail), only the operator-facing label/type/
  criticality plus aggregated counts.
* Ranking/ordering behaves as documented (most exposed asset first).

Isolation: uses ``fresh_app`` / ``tenant_admin_client`` from ``conftest.py``
(sys.modules purge + tmp_path SQLite per test) — same pattern as the rest of
the suite.
"""
from __future__ import annotations


def _pw(label: str) -> str:
    """Match the deterministic synthetic password helper used in conftest."""
    return f"{label}Aa12345!"


def _create_tenant_admin(op_client, tenant_name: str, admin_email: str):
    """Create a tenant + admin via the platform-operator client (mirrors the
    helper in test_integrations_config.py)."""
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


def _enable(monkeypatch, *feature_names: str) -> None:
    """Grant the listed canonical Feature keys via the license stub."""
    from app import features as feats
    from app.features import Feature

    wanted = {Feature(name) for name in feature_names}
    monkeypatch.setattr(feats, "entitlements", lambda: wanted)


def _create_asset(client, label, value, criticality="medium", asset_type="domain"):
    r = client.post("/exposure/assets", json={
        "asset_type": asset_type, "label": label, "value": value, "criticality": criticality,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _intake(client, exposure_type, detail, *, asset_id=None, severity=None, title=None):
    payload = {"exposure_type": exposure_type, "source": "manual_intake", "detail": detail}
    if asset_id is not None:
        payload["asset_id"] = asset_id
    if severity is not None:
        payload["severity"] = severity
    if title is not None:
        payload["title"] = title
    r = client.post("/exposure/findings/intake", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


def _create_case(client, title, severity="alto"):
    r = client.post("/cases", json={"title": title, "severity": severity})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _all_strings(obj):
    """Flatten every string value/key found anywhere in a JSON-like structure."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(_all_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_all_strings(v))
    elif obj is not None:
        out.append(str(obj))
    return out


# ---------------------------------------------------------------------------
# Shape + real aggregation
# ---------------------------------------------------------------------------
def test_overview_reflects_real_data_no_mocking(tenant_admin_client):
    client = tenant_admin_client

    # empty tenant first: every counter must be a real 0, not fabricated data.
    r0 = client.get("/dashboard/overview")
    assert r0.status_code == 200, r0.text
    empty = r0.json()
    assert empty["summary"]["iocs_total"] == 0
    assert empty["summary"]["cases_total"] == 0
    assert empty["recent_cases"] == []
    assert empty["recent_exposure_findings"] == []
    assert empty["top_exposed_assets"] == []
    assert empty["summary"]["telegram_sources_active"] == 0
    assert empty["summary"]["telegram_events_total"] == 0
    telegram_empty = next(it for it in empty["integrations"] if it["name"] == "telegram-intelligence")
    assert telegram_empty["surface"] == "collection"
    assert telegram_empty["connected"] is False
    assert telegram_empty["collector_state"] == "not_configured"

    # IOC
    ro = client.post("/observables", json={"type": "ip", "value": "203.0.113.10"})
    assert ro.status_code == 201, ro.text
    from app.database import SessionLocal
    from app.models import Observable
    with SessionLocal() as db:
        obs = db.query(Observable).first()
        obs.verdict = "malicious"
        db.commit()

    # Brand (BrandCreate.official_domains is list[str], not a comma string)
    rb = client.post("/brands", json={"name": "Acme Corp", "official_domains": ["acme.example"]})
    assert rb.status_code == 201, rb.text

    # Case
    case_id = _create_case(client, "Suspicious login pattern", severity="critico")

    # Monitored asset + linked exposure finding (identity_exposure)
    asset_id = _create_asset(client, "CEO identity", "ceo@acme.example", criticality="critical",
                             asset_type="identity")
    finding = _intake(client, "identity_exposure", {"email": "ceo@acme.example",
                                                    "person_label": "CEO"},
                      asset_id=asset_id, severity="high")

    # Credential exposure -> materializes a CredentialIdentity dossier
    _intake(client, "credential_exposure",
           {"email": "user@acme.example", "password": "S3nhaForte!"},
           severity="medium")

    r = client.get("/dashboard/overview")
    assert r.status_code == 200, r.text
    body = r.json()

    s = body["summary"]
    assert s["iocs_total"] == 1
    assert s["iocs_malicious"] == 1
    assert s["brands_total"] == 1
    assert s["brands_active"] == 1
    assert s["cases_total"] == 1
    assert s["cases_open"] == 1
    assert s["exposure_findings_total"] == 2
    assert s["exposure_findings_open"] >= 1
    assert s["monitored_assets_total"] == 1
    assert s["monitored_assets_active"] == 1
    assert s["credential_identities_total"] == 1

    # distributions add up to the real totals — no invented buckets/rows
    assert sum(body["cases_by_severity"].values()) == s["cases_total"]
    assert sum(body["cases_by_status"].values()) == s["cases_total"]
    assert sum(body["exposure_by_severity"].values()) == s["exposure_findings_total"]
    assert sum(body["exposure_by_status"].values()) == s["exposure_findings_total"]

    recent_ids = {c["id"] for c in body["recent_cases"]}
    assert recent_ids == {case_id}
    assert body["recent_cases"][0]["severity"] == "critico"

    finding_ids = {f["id"] for f in body["recent_exposure_findings"]}
    assert finding["id"] in finding_ids

    # top exposed assets: our asset shows up with exactly 1 linked finding,
    # and never leaks the raw (PII-bearing) monitored-asset value.
    assert len(body["top_exposed_assets"]) == 1
    top = body["top_exposed_assets"][0]
    assert top["id"] == asset_id
    assert top["finding_count"] == 1
    assert "value" not in top
    assert "ceo@acme.example" not in r.text


def test_credential_identity_high_risk_counter_is_real(tenant_admin_client):
    """The high-risk counter reuses app.risk.band_of thresholds; forcing a
    known max_risk via direct DB write (same pattern used across the suite
    for deterministic setup) confirms the dashboard reads the real column
    rather than recomputing/guessing a number."""
    client = tenant_admin_client
    _intake(client, "credential_exposure",
           {"email": "vip@acme.example", "password": "Xyz123!!"}, severity="critical")

    from app.database import SessionLocal
    from app.models import CredentialIdentity
    with SessionLocal() as db:
        ci = db.query(CredentialIdentity).first()
        ci.max_risk = 92
        db.commit()

    r = client.get("/dashboard/overview")
    assert r.status_code == 200, r.text
    assert r.json()["summary"]["credential_identities_high_risk"] == 1


# ---------------------------------------------------------------------------
# Ordering of "top exposed assets"
# ---------------------------------------------------------------------------
def test_top_exposed_assets_ordered_by_finding_count(tenant_admin_client):
    client = tenant_admin_client
    busy_id = _create_asset(client, "Busy asset", "busy.acme.example", asset_type="domain")
    quiet_id = _create_asset(client, "Quiet asset", "quiet.acme.example", asset_type="domain")

    # Distinct email/person_label per finding: app.exposure_ingest.dedup_key()
    # for identity_exposure hashes (email or person_label, exposure_kind, url) —
    # NOT the "domain" field — so findings must differ on one of those to avoid
    # deduping into a single row (which would silently collapse this test).
    _intake(client, "identity_exposure", {"person_label": "Busy Person A", "domain": "busy.acme.example"},
           asset_id=busy_id)
    _intake(client, "identity_exposure", {"person_label": "Busy Person B", "domain": "busy.acme.example"},
           asset_id=busy_id)
    _intake(client, "identity_exposure", {"person_label": "Quiet Person", "domain": "quiet.acme.example"},
           asset_id=quiet_id)

    body = client.get("/dashboard/overview").json()
    top = body["top_exposed_assets"]
    assert len(top) == 2
    assert top[0]["id"] == busy_id
    assert top[0]["finding_count"] == 2
    assert top[1]["id"] == quiet_id
    assert top[1]["finding_count"] == 1


# ---------------------------------------------------------------------------
# Recent imports (ExposureIngestBatch) — real provenance, not a promise left
# unimplemented
# ---------------------------------------------------------------------------
def test_recent_ingests_reflects_real_import_batches(tenant_admin_client):
    client = tenant_admin_client
    csv_content = "email,password\nalice@acme.example,Passw0rd!\n"
    r = client.post(
        "/exposure/import",
        files={"file": ("leak.csv", csv_content, "text/csv")},
        data={"parser": "csv_generic"},
    )
    assert r.status_code == 201, r.text
    batch = r.json()

    body = client.get("/dashboard/overview").json()
    assert body["summary"]["exposure_ingests_total"] == 1
    ids = {b["id"] for b in body["recent_ingests"]}
    assert batch["id"] in ids
    entry = next(b for b in body["recent_ingests"] if b["id"] == batch["id"])
    assert entry["parser"] == "csv_generic"
    assert entry["created_count"] == batch["created_count"]
    assert entry["status"] == "completed"


# ---------------------------------------------------------------------------
# recent_exposure_findings.title masking — app.exposure_ingest.parse_csv_generic
# titles credential_exposure records "Credential exposure <email>"; the
# dashboard must mask that embedded e-mail under EXPOSURE_PII_MASKING=by_role
# for non-admin callers, exactly like app.exposure_ingest.mask_detail already
# does for the `detail` dict on GET /exposure/findings.
# ---------------------------------------------------------------------------
def test_recent_findings_title_masks_email_for_viewer_under_by_role_policy(
    tenant_admin_client, monkeypatch,
):
    from app import config as app_config
    monkeypatch.setattr(app_config, "EXPOSURE_PII_MASKING", "by_role")

    admin = tenant_admin_client
    csv_content = "email,password\nvictim@acme.example,Pass1234!\n"
    r = admin.post(
        "/exposure/import",
        files={"file": ("leak.csv", csv_content, "text/csv")},
        data={"parser": "csv_generic"},
    )
    assert r.status_code == 201, r.text

    r_create = admin.post("/users", json={
        "email": "viewer2@test.com", "password": _pw("Viewer2"), "role": "viewer",
    })
    assert r_create.status_code in (200, 201), r_create.text

    from fastapi.testclient import TestClient
    from app.main import app
    viewer = TestClient(app)
    assert viewer.post("/auth/login", json={
        "email": "viewer2@test.com", "password": _pw("Viewer2"),
    }).status_code == 200

    viewer_body = viewer.get("/dashboard/overview").json()
    viewer_titles = " ".join((f["title"] or "") for f in viewer_body["recent_exposure_findings"])
    assert "victim@acme.example" not in viewer_titles

    # Admin is exempt from by_role masking (same rule as the rest of Exposure
    # Monitoring) — confirms this is role-driven masking, not a blanket
    # redaction that would make the title useless for everyone.
    admin_body = admin.get("/dashboard/overview").json()
    admin_titles = " ".join((f["title"] or "") for f in admin_body["recent_exposure_findings"])
    assert "victim@acme.example" in admin_titles


# ---------------------------------------------------------------------------
# Never exposes secrets/tokens/api_key/config_json/secrets_metadata
# ---------------------------------------------------------------------------
def test_overview_never_exposes_integration_secrets_or_raw_config(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "integration.generic")
    plain_secret = "s3cret-generic-token-must-never-leak"
    rc = tenant_admin_client.post("/integrations/generic/connections", json={
        "endpoint_url": "https://sink.example.org/ingest", "token": plain_secret,
    })
    assert rc.status_code == 200, rc.text

    r = tenant_admin_client.get("/dashboard/overview")
    assert r.status_code == 200, r.text
    body = r.json()

    # The plaintext secret never appears anywhere in the payload.
    assert plain_secret not in r.text

    # Never surfaces the raw config_json / secrets_metadata columns, nor any
    # of the disallowed key/field names, anywhere in the response.
    banned_substrings = ("config_json", "secrets_metadata", "api_key",
                        "hashed_password", "password_hash")
    flat = " ".join(_all_strings(body)).lower()
    for banned in banned_substrings:
        assert banned not in flat, banned

    integrations = {it["name"]: it for it in body["integrations"]}
    assert set(integrations) == {"misp", "opencti", "generic", "telegram-intelligence"}
    assert integrations["generic"]["connected"] is True
    assert integrations["generic"]["connection_enabled"] is True
    assert integrations["generic"]["license_enabled"] is True
    # Locked/unconfigured connectors correctly report as such — real state,
    # not fabricated "connected" flags.
    assert integrations["misp"]["connected"] is False
    assert integrations["misp"]["license_enabled"] is False
    # Only the reduced, safe fields are present per integration/collection surface.
    safe_fields = {
        "name", "title", "premium", "license_enabled", "connected",
        "connection_enabled", "surface", "connection_count",
        "enabled_connection_count", "source_count", "active_source_count",
        "event_count", "collector_state", "last_success_at", "last_event_at",
    }
    for it in body["integrations"]:
        assert set(it) == safe_fields

    assert body["summary"]["integrations_connected"] == 1
    assert body["summary"]["integrations_catalog_total"] == 4


# ---------------------------------------------------------------------------
# Telegram Intelligence is a first-class dashboard surface
# ---------------------------------------------------------------------------
def test_overview_includes_telegram_collection_health_sources_and_events(
    tenant_admin_client, monkeypatch,
):
    _enable(monkeypatch, "collection.telegram")

    from app.database import SessionLocal
    from app.models import (CollectionConnection, CollectionEvent,
                            CollectionSource, Tenant, utcnow)

    now = utcnow().isoformat()
    with SessionLocal() as db:
        tid = db.query(Tenant).first().id
        conn = CollectionConnection(
            tenant_id=tid, provider="telegram", name="CBG Telegram POC",
            enabled=True, status="active", provider_account_ref="8770625350",
            cursor="110122819",
            config_json={
                "poll_timeout_seconds": 20,
                "_health": {
                    "state": "healthy", "checked_at": now,
                    "last_success_at": now, "last_event_at": now,
                },
            },
            secret_refs={"bot_token": "secretref://file/redacted"},
            secrets_metadata={"bot_token": {"configured": True}},
        )
        db.add(conn)
        db.flush()
        source = CollectionSource(
            tenant_id=tid, connection_id=conn.id, provider="telegram",
            source_ref="-5107651859", kind="group", name="Sala de Conteúdo",
            enabled=True, status="active",
        )
        db.add(source)
        db.flush()
        db.add(CollectionEvent(
            tenant_id=tid, source_id=source.id, provider="telegram",
            external_id_hash="a" * 64, processing_state="normalized",
            redacted_text="safe redacted text", occurred_at=utcnow(),
        ))
        db.commit()

    response = tenant_admin_client.get("/dashboard/overview")
    assert response.status_code == 200, response.text
    body = response.json()
    telegram = next(it for it in body["integrations"] if it["name"] == "telegram-intelligence")

    assert telegram["license_enabled"] is True
    assert telegram["connected"] is True
    assert telegram["connection_enabled"] is True
    assert telegram["connection_count"] == 1
    assert telegram["active_source_count"] == 1
    assert telegram["source_count"] == 1
    assert telegram["event_count"] == 1
    assert telegram["collector_state"] == "healthy"
    assert telegram["last_success_at"] == now
    assert telegram["last_event_at"] == now

    assert body["summary"]["telegram_connections_total"] == 1
    assert body["summary"]["telegram_sources_active"] == 1
    assert body["summary"]["telegram_events_total"] == 1
    assert body["summary"]["integrations_connected"] == 1

    # Secret references and chat IDs are never exposed by the dashboard.
    assert "secretref://" not in response.text
    assert "-5107651859" not in response.text


def test_overview_marks_stale_telegram_health_offline(tenant_admin_client, monkeypatch):
    _enable(monkeypatch, "collection.telegram")

    from datetime import timedelta
    from app.database import SessionLocal
    from app.models import CollectionConnection, Tenant, utcnow

    stale = (utcnow() - timedelta(minutes=10)).isoformat()
    with SessionLocal() as db:
        tid = db.query(Tenant).first().id
        db.add(CollectionConnection(
            tenant_id=tid, provider="telegram", name="stale",
            enabled=True, status="active", provider_account_ref="bot-stale",
            config_json={"_health": {"state": "healthy", "checked_at": stale}},
            secret_refs={}, secrets_metadata={},
        ))
        db.commit()

    body = tenant_admin_client.get("/dashboard/overview").json()
    telegram = next(it for it in body["integrations"] if it["name"] == "telegram-intelligence")
    assert telegram["collector_state"] == "offline"


# ---------------------------------------------------------------------------
# RBAC: viewer+ ; unauthenticated blocked
# ---------------------------------------------------------------------------
def test_overview_requires_authentication(tenant_admin_client):
    from fastapi.testclient import TestClient
    from app.main import app

    anon = TestClient(app)
    r = anon.get("/dashboard/overview")
    assert r.status_code == 401, r.text


def test_overview_viewer_role_can_read(fresh_app):
    op = fresh_app
    assert op.post("/setup/operator", json={
        "email": "op@plat.com", "password": _pw("Operator"),
    }).status_code == 201
    assert op.post("/tenants", json={
        "name": "Tenant Test", "admin_email": "admin@test.com",
        "admin_password": _pw("TenantAdmin"),
    }).status_code == 201

    from fastapi.testclient import TestClient
    from app.main import app

    admin = TestClient(app)
    assert admin.post("/auth/login", json={
        "email": "admin@test.com", "password": _pw("TenantAdmin"),
    }).status_code == 200

    r_create = admin.post("/users", json={
        "email": "viewer@test.com", "password": _pw("Viewer"), "role": "viewer",
    })
    assert r_create.status_code in (200, 201), r_create.text

    viewer = TestClient(app)
    assert viewer.post("/auth/login", json={
        "email": "viewer@test.com", "password": _pw("Viewer"),
    }).status_code == 200

    r = viewer.get("/dashboard/overview")
    assert r.status_code == 200, r.text
    assert "summary" in r.json()


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------
def test_overview_is_tenant_scoped(fresh_app):
    op = fresh_app
    assert op.post("/setup/operator", json={
        "email": "op@plat.com", "password": _pw("Operator"),
    }).status_code == 201

    admin_a = _create_tenant_admin(op, "Tenant A", "admin-a@test.com")
    admin_b = _create_tenant_admin(op, "Tenant B", "admin-b@test.com")

    case_a = _create_case(admin_a, "Tenant A incident", severity="alto")
    case_b1 = _create_case(admin_b, "Tenant B incident 1", severity="baixo")
    case_b2 = _create_case(admin_b, "Tenant B incident 2", severity="baixo")

    body_a = admin_a.get("/dashboard/overview").json()
    body_b = admin_b.get("/dashboard/overview").json()

    assert body_a["summary"]["cases_total"] == 1
    assert {c["id"] for c in body_a["recent_cases"]} == {case_a}

    assert body_b["summary"]["cases_total"] == 2
    assert {c["id"] for c in body_b["recent_cases"]} == {case_b1, case_b2}

    # No cross-tenant leakage in either direction.
    assert case_a not in {c["id"] for c in body_b["recent_cases"]}
    assert case_b1 not in {c["id"] for c in body_a["recent_cases"]}
