from __future__ import annotations

from sqlalchemy import func, select

from app.collection import registry, service, worker
from app.collection.contracts import (
    CollectionBatch,
    NormalizedUpdate,
    ProviderHealth,
    ProviderIdentity,
)
from app.models import CollectionEvent
from tests._tg import make_session, make_tenant


class _FakeProvider:
    name = "telegram"

    def __init__(self, updates=None, fail=None):
        self.updates = list(updates or [])
        self.fail = fail

    def poll(self, secret_ref, cursor, config=None):
        if self.fail:
            raise self.fail
        return CollectionBatch(
            updates=tuple(self.updates),
            next_cursor=str(self.updates[-1]["update_id"]) if self.updates else cursor,
            health=ProviderHealth(
                state="healthy",
                checked_at="2026-07-18T00:00:00+00:00",
                last_success_at="2026-07-18T00:00:00+00:00",
            ),
        )

    def source_ref(self, raw):
        return str(raw["message"]["chat"]["id"])

    def normalize(self, raw):
        return NormalizedUpdate(
            provider="telegram",
            external_id=str(raw["update_id"]),
            kind="message",
            occurred_at="2026-07-18T00:00:00+00:00",
            normalized={"chat_type": "group", "safe": True},
            redacted_text="inert text",
            raw_fingerprint="a" * 64,
        )


class _ProviderFailure(RuntimeError):
    code = "rate_limited"
    state = "degraded"
    retry_after_seconds = 7
    http_status = 429

    def __str__(self):
        return "must-not-be-returned"


def _setup(db, provider, *, source_enabled=True):
    registry.providers.register("telegram", provider, replace=True)
    make_tenant(db, 1)
    conn = service.create_connection(
        db,
        tenant_id=1,
        provider="telegram",
        name="poc",
        secret_refs={"bot_token": "secretref://env/THREATFORGE_TEST_BOT_TOKEN"},
    )
    service.bind_bot_identity(
        db,
        tenant_id=1,
        connection_id=conn.id,
        identity=ProviderIdentity(provider="telegram", account_ref="777"),
        enable=True,
    )
    src = service.create_source(
        db,
        tenant_id=1,
        connection_id=conn.id,
        source_ref="-1005",
        kind="group",
    )
    if source_enabled:
        service.enable_source(db, tenant_id=1, source_id=src.id)
    db.commit()
    return conn, src


def _update(update_id=5, chat_id=-1005):
    return {
        "update_id": update_id,
        "message": {
            "message_id": update_id,
            "date": 1_700_000_000,
            "chat": {"id": chat_id, "type": "group"},
            "text": "test",
        },
    }


def test_worker_ingests_and_advances_connection_cursor_once():
    db = make_session()
    conn, _ = _setup(db, _FakeProvider([_update()]))
    first = worker.run_connection_once(db, tenant_id=1, connection_id=conn.id)
    second = worker.run_connection_once(db, tenant_id=1, connection_id=conn.id)
    assert first.status == "ok" and first.processed == 1 and first.cursor == "5"
    assert second.deduplicated == 1
    count = db.scalar(select(func.count()).select_from(CollectionEvent))
    assert count == 1
    current = service.get_connection(db, tenant_id=1, connection_id=conn.id)
    assert service.connection_health(current)["state"] == "healthy"


def test_disabled_source_stops_ingestion_but_consumes_unrelated_update():
    db = make_session()
    conn, _ = _setup(db, _FakeProvider([_update()]), source_enabled=False)
    result = worker.run_connection_once(db, tenant_id=1, connection_id=conn.id)
    assert result.status == "ok"
    assert result.ignored == 1
    assert result.cursor == "5"
    assert db.scalar(select(func.count()).select_from(CollectionEvent)) == 0


def test_provider_outage_does_not_advance_cursor_or_leak_error():
    db = make_session()
    conn, _ = _setup(db, _FakeProvider(fail=_ProviderFailure()))
    result = worker.run_connection_once(db, tenant_id=1, connection_id=conn.id)
    assert result.status == "failed"
    assert result.error_code == "rate_limited"
    current = service.get_connection(db, tenant_id=1, connection_id=conn.id)
    assert current.cursor is None
    health = service.connection_health(current)
    assert health["error_code"] == "rate_limited"
    assert "must-not-be-returned" not in repr(health)


def test_disabled_connection_is_not_polled():
    db = make_session()
    provider = _FakeProvider([_update()])
    conn, _ = _setup(db, provider)
    service.set_connection_enabled(
        db, tenant_id=1, connection_id=conn.id, enabled=False
    )
    db.commit()
    result = worker.run_connection_once(db, tenant_id=1, connection_id=conn.id)
    assert result.status == "disabled"
    assert db.scalar(select(func.count()).select_from(CollectionEvent)) == 0
