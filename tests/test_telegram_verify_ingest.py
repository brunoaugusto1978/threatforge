from __future__ import annotations

import pytest
from unittest import mock

from sqlalchemy.exc import OperationalError

from app.collection import ingest, service, verify
from app.collection.contracts import NormalizedUpdate
from app.models import CollectionConnection, CollectionEvent, CollectionSourceTestRequest
from tests._tg import make_session, make_tenant


def _conn_and_source(db, tenant_id=1, enable=True):
    conn = service.create_connection(db, tenant_id=tenant_id, provider="telegram", name="c")
    src = service.create_source(db, tenant_id=tenant_id, connection_id=conn.id,
                                source_ref="chan-1")
    if enable:
        conn.enabled = True
        conn.status = "active"
        service.enable_source(db, tenant_id=tenant_id, source_id=src.id)
    db.commit()
    return conn, src


def _normalizer(raw):
    return NormalizedUpdate(
        provider="telegram", external_id=str(raw.get("update_id")), kind="channel",
        occurred_at="2026-07-18T12:00:00+00:00",
        normalized={"has_text": True}, redacted_text="[redacted]",
        raw_fingerprint="f" * 64, content_version=1)


def test_verify_parse_hash_redact_req6():
    assert verify.parse_verify_nonce("TF-VERIFY-abc12345") == "abc12345"
    assert verify.parse_verify_nonce("nope") is None
    assert len(verify.nonce_hash("abc12345")) == 64
    log = verify.redact_for_log("got TF-VERIFY-abc12345 now")
    assert "abc12345" not in log and "TF-VERIFY-<nonce:" in log


def test_control_requires_matching_pending_request_c5():
    """Mandatory test #5: TF-VERIFY without a pending request follows NORMAL flow."""
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    res = ingest.ingest_update(
        db, source=src, raw={"update_id": 1, "text": "TF-VERIFY-Zz9_abc123"},
        normalizer=_normalizer)
    assert res.outcome == "normalized"          # NOT control
    ev = db.get(CollectionEvent, res.event_id)
    assert ev.is_control is False


def test_valid_verify_confirms_exactly_one_request_c5():
    """Mandatory test #6: a valid TF-VERIFY confirms exactly one request."""
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    issued = service.request_source_test(db, tenant_id=1, connection_id=conn.id,
                                         source_id=src.id)
    db.commit()
    res = ingest.ingest_update(
        db, source=src, raw={"update_id": 2, "text": f"TF-VERIFY-{issued.nonce}"},
        normalizer=_normalizer)
    assert res.outcome == "control"
    ev = db.get(CollectionEvent, res.event_id)
    assert ev.is_control is True and ev.processing_state == "control"
    assert ev.redacted_text is None and ev.finding_id is None and ev.case_id is None
    req = db.get(CollectionSourceTestRequest, issued.request_id)
    assert req.status == "verified" and req.verified_at is not None
    assert req.telemetry_json.get("confirmed_via") == "ingest"
    # replay of the same nonce: request no longer pending → normal flow
    res2 = ingest.ingest_update(
        db, source=src, raw={"update_id": 3, "text": f"TF-VERIFY-{issued.nonce}"},
        normalizer=_normalizer)
    assert res2.outcome == "normalized"
    verified = db.query(CollectionSourceTestRequest).filter_by(status="verified").count()
    assert verified == 1


def test_expired_request_not_confirmed_c5():
    from datetime import datetime, timedelta, timezone
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    issued = service.request_source_test(db, tenant_id=1, connection_id=conn.id,
                                         source_id=src.id)
    req = db.get(CollectionSourceTestRequest, issued.request_id)
    req.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    res = ingest.ingest_update(
        db, source=src, raw={"update_id": 4, "text": f"TF-VERIFY-{issued.nonce}"},
        normalizer=_normalizer)
    assert res.outcome == "normalized"
    assert db.get(CollectionSourceTestRequest, issued.request_id).status == "expired"


def test_normalized_update_advances_connection_cursor_c1():
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    res = ingest.ingest_update(
        db, source=src, raw={"update_id": 42, "text": "hello"}, normalizer=_normalizer)
    assert res.outcome == "normalized"
    ev = db.get(CollectionEvent, res.event_id)
    assert ev.normalized_fingerprint and ev.occurred_at is not None  # C10
    assert db.get(CollectionConnection, conn.id).cursor == "42"      # C1
    assert res.envelope is not None and res.envelope.original_custody is False


def test_two_sources_share_one_cursor_c1():
    """Mandatory test #1: two sources of the same connection share the cursor."""
    db = make_session(); make_tenant(db, 1)
    conn, src1 = _conn_and_source(db)
    src2 = service.create_source(db, tenant_id=1, connection_id=conn.id,
                                 source_ref="chan-2")
    service.enable_source(db, tenant_id=1, source_id=src2.id)
    db.commit()
    ingest.ingest_update(db, source=src1, raw={"update_id": 10, "text": "a"},
                         normalizer=_normalizer)
    ingest.ingest_update(db, source=src2, raw={"update_id": 11, "text": "b"},
                         normalizer=_normalizer)
    conn = db.get(CollectionConnection, conn.id)
    assert conn.cursor == "11"           # single shared cursor on the connection
    from app.models import CollectionSource
    assert not hasattr(CollectionSource, "cursor")  # cursor no longer on source


def test_replay_returns_dedup_not_rejection_c4():
    """Mandatory test #3: replay → deduplicated with the existing event."""
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    r1 = ingest.ingest_update(db, source=src, raw={"update_id": 7, "text": "x"},
                              normalizer=_normalizer)
    r2 = ingest.ingest_update(db, source=src, raw={"update_id": 7, "text": "x"},
                              normalizer=_normalizer)
    assert r1.outcome == "normalized"
    assert r2.outcome == "deduplicated"
    assert r2.event_id == r1.event_id
    rejected = db.query(CollectionEvent).filter_by(processing_state="rejected").count()
    assert rejected == 0


def test_validation_error_dead_letters_and_advances_c4():
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)

    def _boom(raw):
        raise ValueError("bad update")

    res = ingest.ingest_update(db, source=src, raw={"update_id": 8, "text": "x"},
                               normalizer=_boom)
    assert res.outcome == "rejected"
    ev = db.get(CollectionEvent, res.event_id)
    assert ev.processing_state == "rejected" and ev.rejection_reason == "ValueError"
    assert ev.redacted_text is None
    assert db.get(CollectionConnection, conn.id).cursor == "8"


def test_db_error_rolls_back_without_cursor_advance_c4():
    """Mandatory test #4: infrastructure error → no cursor advance, no dead letter."""
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    with mock.patch.object(db, "flush",
                           side_effect=OperationalError("stmt", {}, Exception("down"))):
        with pytest.raises(ingest.IngestInfrastructureError):
            ingest.ingest_update(db, source=src, raw={"update_id": 9, "text": "x"},
                                 normalizer=_normalizer)
    assert db.get(CollectionConnection, conn.id).cursor is None   # not advanced
    assert db.query(CollectionEvent).count() == 0                  # no dead letter


def test_revoked_or_disabled_refuses_ingestion_c10():
    """Mandatory test #9: revoked source/connection does not accept ingestion."""
    db = make_session(); make_tenant(db, 1)
    conn, src = _conn_and_source(db)
    service.revoke_connection(db, tenant_id=1, connection_id=conn.id)
    db.commit()
    with pytest.raises(ingest.IngestNotAllowed):
        ingest.ingest_update(db, source=src, raw={"update_id": 12, "text": "x"},
                             normalizer=_normalizer)
    # re-enable connection but disable source
    conn.enabled = True; conn.status = "active"; db.commit()
    src.enabled = False; db.commit()
    with pytest.raises(ingest.IngestNotAllowed):
        ingest.ingest_update(db, source=src, raw={"update_id": 13, "text": "x"},
                             normalizer=_normalizer)
    assert db.get(CollectionConnection, conn.id).cursor is None
