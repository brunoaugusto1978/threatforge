from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.collection import retention, service
from app.models import AuditLog, CollectionEvent
from tests._tg import make_session, make_tenant


def _event(db, tenant_id, legal_hold=False):
    conn = service.create_connection(db, tenant_id=tenant_id, provider="telegram", name="c")
    src = service.create_source(db, tenant_id=tenant_id, connection_id=conn.id,
                                source_ref="s")
    ev = CollectionEvent(
        tenant_id=tenant_id, source_id=src.id, provider="telegram",
        processing_state="analyzed", normalized_fingerprint="a" * 64,
        raw_fingerprint="b" * 64, external_id_hash="e" * 64,
        redacted_text="secret text", context_json={"handle": "@x"},
        control_nonce_hash="c" * 64, analysis_json={"intent": "x"},
        legal_hold=legal_hold,
        created_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    db.add(ev); db.commit()
    return ev


def test_purge_clears_only_authorized_fields_req11_c10():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db, 1)
    report = retention.purge_expired_events(
        db, tenant_id=1, policy="std-30d", older_than=datetime.now(timezone.utc))
    assert report.purged == 1
    db.refresh(ev)
    # PURGED_FIELDS cleared
    assert ev.redacted_text is None
    assert ev.context_json == {}
    assert ev.control_nonce_hash is None
    assert ev.analysis_json == {}
    # PRESERVED_FIELDS intact
    assert ev.normalized_fingerprint == "a" * 64
    assert ev.raw_fingerprint == "b" * 64
    assert ev.external_id_hash == "e" * 64
    assert ev.provider == "telegram"
    # bookkeeping
    assert ev.purged_at is not None and ev.retention_policy == "std-30d"
    # the contract lists stay consistent with the model
    for f in retention.PURGED_FIELDS + retention.PRESERVED_FIELDS:
        assert hasattr(ev, f), f


def test_purge_is_audited_c10():
    db = make_session(); make_tenant(db, 1)
    _event(db, 1)
    retention.purge_expired_events(
        db, tenant_id=1, policy="std-30d", older_than=datetime.now(timezone.utc))
    entries = db.execute(
        select(AuditLog).where(AuditLog.action == "collection.retention_purged")
    ).scalars().all()
    assert len(entries) == 1
    detail = entries[0].detail or {}
    assert detail.get("policy") == "std-30d" and detail.get("purged") == 1
    # never content in the audit log
    assert "secret text" not in str(detail)


def test_legal_hold_is_respected_req11():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db, 1, legal_hold=True)
    report = retention.purge_expired_events(
        db, tenant_id=1, policy="std-30d", older_than=datetime.now(timezone.utc))
    assert report.purged == 0 and report.skipped_legal_hold == 1
    db.refresh(ev)
    assert ev.redacted_text == "secret text" and ev.purged_at is None
