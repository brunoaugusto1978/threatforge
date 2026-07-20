from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _enable(monkeypatch):
    from app import features
    from app.features import Feature

    monkeypatch.setattr(features, "entitlements", lambda: {Feature.COLLECTION_TELEGRAM})


def _register_provider():
    from app.collection import registry
    from app.collection.contracts import (
        ConnectionTestResult,
        ProviderHealth,
        ProviderIdentity,
    )

    class Provider:
        name = "telegram"

        def test_connection(self, secret_ref, config=None):
            return ConnectionTestResult(
                ok=True,
                identity=ProviderIdentity(
                    provider="telegram",
                    account_ref="777000",
                    username="tf_poc_bot",
                ),
                health=ProviderHealth(
                    state="healthy",
                    checked_at="2026-07-18T20:00:00+00:00",
                    last_success_at="2026-07-18T20:00:00+00:00",
                ),
            )

    registry.providers.register("telegram", Provider(), replace=True)


def _create_source(client) -> int:
    connection = client.post(
        "/collection/connections",
        json={
            "name": "CBG Telegram POC",
            "provider": "telegram",
            "bot_token_ref": "secretref://file/telegram-collection-bot-token",
        },
    )
    assert connection.status_code == 201, connection.text
    tested = client.post(
        f"/collection/connections/{connection.json()['id']}/test",
        json={"activate": True},
    )
    assert tested.status_code == 200, tested.text
    source = client.post(
        f"/collection/connections/{connection.json()['id']}/sources",
        json={
            "source_ref": "-1001234567890",
            "name": "Authorized test group",
            "kind": "group",
            "enabled": True,
        },
    )
    assert source.status_code == 201, source.text
    return int(source.json()["id"])


def test_events_are_tenant_scoped_redacted_paginated_and_audited(
    tenant_admin_client, monkeypatch
):
    _enable(monkeypatch)
    _register_provider()
    source_id = _create_source(tenant_admin_client)

    from app.database import SessionLocal
    from app.models import AuditLog, CollectionEvent

    with SessionLocal() as db:
        for index in range(1, 28):
            db.add(
                CollectionEvent(
                    tenant_id=1,
                    source_id=source_id,
                    provider="telegram",
                    external_id_hash=f"{index:064x}",
                    processing_state="normalized",
                    redacted_text=("<script>alert(1)</script> " + "x" * 4100)
                    if index == 27
                    else f"Mensagem autorizada {index}",
                    context_json={
                        "chat_type": "group",
                        "update_kind": "message",
                        "forwarded": False,
                        "has_attachment": False,
                        "entity_count": 0,
                        "secret": "must-not-leak",
                        "raw_payload": {"token": "must-not-leak"},
                    },
                    occurred_at=datetime(2026, 7, 18, 20, index % 60, tzinfo=timezone.utc),
                )
            )
        db.commit()

    first = tenant_admin_client.get("/collection/events?limit=25")
    assert first.status_code == 200, first.text
    rows = first.json()
    assert len(rows) == 25
    assert rows[0]["id"] > rows[-1]["id"]
    assert rows[0]["text_truncated"] is True
    assert len(rows[0]["redacted_text"]) <= 4020
    assert rows[0]["context"] == {
        "chat_type": "group",
        "update_kind": "message",
        "forwarded": False,
        "has_attachment": False,
        "entity_count": 0,
    }
    assert "must-not-leak" not in first.text
    assert "external_id_hash" not in first.text

    older = tenant_admin_client.get(
        f"/collection/events?limit=25&before_id={rows[-1]['id']}"
    )
    assert older.status_code == 200, older.text
    assert len(older.json()) == 2

    filtered = tenant_admin_client.get(
        f"/collection/events?source_id={source_id}&state=normalized&limit=5"
    )
    assert filtered.status_code == 200
    assert len(filtered.json()) == 5

    with SessionLocal() as db:
        audit = db.query(AuditLog).filter(
            AuditLog.action == "collection.events_viewed",
            AuditLog.tenant_id == 1,
        ).all()
        assert len(audit) == 3
        assert audit[-1].detail["rows"] == 5


def test_event_source_filter_rejects_cross_tenant_source(
    tenant_admin_client, monkeypatch
):
    _enable(monkeypatch)
    _register_provider()
    _create_source(tenant_admin_client)

    from app.database import SessionLocal
    from app.models import CollectionConnection, CollectionSource, Tenant

    with SessionLocal() as db:
        db.add(Tenant(id=2, name="Other tenant", slug="other-tenant"))
        db.flush()
        connection = CollectionConnection(
            tenant_id=2,
            provider="telegram",
            name="other",
            enabled=False,
            status="pending",
        )
        db.add(connection)
        db.flush()
        source = CollectionSource(
            tenant_id=2,
            connection_id=connection.id,
            provider="telegram",
            source_ref="-999",
            kind="group",
            name="Other source",
            enabled=True,
            status="active",
        )
        db.add(source)
        db.commit()
        other_source_id = source.id

    response = tenant_admin_client.get(
        f"/collection/events?source_id={other_source_id}"
    )
    assert response.status_code == 404


def test_collector_compose_overrides_api_http_healthcheck():
    compose = Path("docker-compose.enterprise.yml").read_text(encoding="utf-8")
    collector = compose.split("  collector:", 1)[1]
    assert 'test: ["CMD", "python", "-m", "app.collection.healthcheck"]' in collector
    assert "THREATFORGE_COLLECTION_HEARTBEAT_MAX_AGE" in collector
    assert "127.0.0.1:8000/health" not in collector


def test_static_ui_moves_redacted_events_to_intelligence_workspace():
    source = Path("app/static/app.js").read_text(encoding="utf-8")
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    assert 'data-view="intelligence"' in html
    assert "Intelligence Feed" in source
    assert 'api("GET", `/intelligence/events?${params.toString()}`)' in source
    assert "${esc(event.redacted_text)}" in source
    assert "Load older events" in source
    assert "Redacted evidence only" in source
    assert 'id="telegramEvents"' not in source
    assert "telegramLoadEvents" not in source
