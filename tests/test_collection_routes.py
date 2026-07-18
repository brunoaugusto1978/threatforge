from __future__ import annotations

from types import SimpleNamespace

from app.collection.contracts import (
    ConnectionTestResult,
    ProviderHealth,
    ProviderIdentity,
)


def _pw(label: str) -> str:
    return f"{label}Aa12345!"


def _enable(monkeypatch):
    from app import features
    from app.features import Feature

    monkeypatch.setattr(features, "entitlements", lambda: {Feature.COLLECTION_TELEGRAM})


class _FakeProvider:
    name = "telegram"

    def test_connection(self, secret_ref, config=None):
        assert secret_ref.startswith("secretref://")
        return ConnectionTestResult(
            ok=True,
            identity=ProviderIdentity(
                provider="telegram",
                account_ref="777000",
                display_name="ThreatForge",
                username="tf_poc_bot",
            ),
            health=ProviderHealth(
                state="healthy",
                checked_at="2026-07-18T00:00:00+00:00",
                last_success_at="2026-07-18T00:00:00+00:00",
            ),
        )


def _register_fake():
    from app.collection import registry

    registry.providers.register("telegram", _FakeProvider(), replace=True)


def _create_admin(op_client, name, email):
    from fastapi.testclient import TestClient
    from app.main import app

    r = op_client.post(
        "/tenants",
        json={
            "name": name,
            "admin_email": email,
            "admin_password": _pw("TenantAdmin"),
        },
    )
    assert r.status_code == 201, r.text
    client = TestClient(app)
    login = client.post(
        "/auth/login",
        json={"email": email, "password": _pw("TenantAdmin")},
    )
    assert login.status_code == 200, login.text
    return client


def test_catalog_is_visible_and_locked_without_license(tenant_admin_client):
    r = tenant_admin_client.get("/collection/catalog")
    assert r.status_code == 200
    item = r.json()[0]
    assert item["name"] == "telegram-intelligence"
    assert item["feature"] == "collection.telegram"
    assert item["enabled"] is False
    assert item["upgrade"]["email"]


def test_locked_collection_actions_return_standard_402(tenant_admin_client):
    r = tenant_admin_client.get("/collection/connections")
    assert r.status_code == 402
    assert r.json()["error"] == "enterprise_feature_required"
    assert r.json()["feature"] == "collection.telegram"


def test_authorized_connection_source_and_health_flow(
    tenant_admin_client, monkeypatch
):
    _enable(monkeypatch)
    _register_fake()

    created = tenant_admin_client.post(
        "/collection/connections",
        json={
            "name": "CBG controlled bot",
            "provider": "telegram",
            "bot_token_ref": "secretref://file/telegram-collection-bot-token",
            "poll_timeout_seconds": 10,
        },
    )
    assert created.status_code == 201, created.text
    connection = created.json()
    assert connection["enabled"] is False
    assert connection["credential_configured"] is True
    assert "secretref" not in created.text
    assert "bot_token" not in created.text

    tested = tenant_admin_client.post(
        f"/collection/connections/{connection['id']}/test",
        json={"activate": True},
    )
    assert tested.status_code == 200, tested.text
    assert tested.json()["ok"] is True
    assert tested.json()["connection"]["enabled"] is True
    assert tested.json()["connection"]["bot_username"] == "tf_poc_bot"

    source = tenant_admin_client.post(
        f"/collection/connections/{connection['id']}/sources",
        json={
            "source_ref": "-1001234567890",
            "name": "CBG authorized group",
            "kind": "supergroup",
            "enabled": True,
        },
    )
    assert source.status_code == 201, source.text
    assert source.json()["enabled"] is True

    rows = tenant_admin_client.get("/collection/sources").json()
    assert len(rows) == 1
    assert rows[0]["source_ref"] == "-1001234567890"

    paused = tenant_admin_client.patch(
        f"/collection/sources/{rows[0]['id']}", json={"enabled": False}
    )
    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"

    health = tenant_admin_client.get(
        f"/collection/connections/{connection['id']}/health"
    )
    assert health.status_code == 200
    assert health.json()["state"] == "healthy"


def test_invalid_secret_reference_is_rejected_without_persistence(
    tenant_admin_client, monkeypatch
):
    _enable(monkeypatch)
    _register_fake()
    r = tenant_admin_client.post(
        "/collection/connections",
        json={
            "name": "bad",
            "provider": "telegram",
            "bot_token_ref": "123456:raw-token-must-not-be-accepted",
        },
    )
    assert r.status_code == 422
    assert tenant_admin_client.get("/collection/connections").json() == []


def test_direct_id_access_is_tenant_scoped(fresh_app, monkeypatch):
    _enable(monkeypatch)
    _register_fake()
    op = fresh_app
    assert op.post(
        "/setup/operator",
        json={"email": "op@plat.com", "password": _pw("Operator")},
    ).status_code == 201
    a = _create_admin(op, "Tenant A", "a@test.com")
    b = _create_admin(op, "Tenant B", "b@test.com")

    created = a.post(
        "/collection/connections",
        json={
            "name": "tenant-a-bot",
            "provider": "telegram",
            "bot_token_ref": "secretref://env/THREATFORGE_TEST_BOT_TOKEN",
        },
    )
    assert created.status_code == 201, created.text
    connection_id = created.json()["id"]
    assert b.get(f"/collection/connections/{connection_id}/health").status_code == 404
    assert b.patch(
        f"/collection/connections/{connection_id}", json={"enabled": False}
    ).status_code == 404

class _FailedProviderWithoutDiagnostic:
    name = "telegram"

    def test_connection(self, secret_ref, config=None):
        return ConnectionTestResult(
            ok=False,
            identity=None,
            health=ProviderHealth(
                state="degraded",
                checked_at="2026-07-18T00:00:00+00:00",
                error_code="provider_unavailable",
                retry_after_seconds=30,
            ),
            diagnostic=None,
        )


def test_failed_connection_without_explicit_diagnostic_is_sanitized(
    tenant_admin_client, monkeypatch
):
    from app.collection import registry

    _enable(monkeypatch)
    registry.providers.register(
        "telegram", _FailedProviderWithoutDiagnostic(), replace=True
    )
    created = tenant_admin_client.post(
        "/collection/connections",
        json={
            "name": "CBG unavailable bot",
            "provider": "telegram",
            "bot_token_ref": "secretref://file/telegram-collection-bot-token",
        },
    )
    assert created.status_code == 201, created.text

    tested = tenant_admin_client.post(
        f"/collection/connections/{created.json()['id']}/test",
        json={"activate": False},
    )
    assert tested.status_code == 200, tested.text
    body = tested.json()
    assert body["ok"] is False
    assert body["diagnostic"] == {
        "code": "provider_unavailable",
        "state": "degraded",
        "retry_after_seconds": 30,
    }
    assert "secretref" not in tested.text
