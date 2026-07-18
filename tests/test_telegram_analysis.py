"""Analysis state machine (corrective C8): transitions, retry, expired lock."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.collection import analysis, service
from app.models import CollectionEvent
from tests._tg import make_session, make_tenant


def _event(db, state="normalized", **kw):
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name=f"c{db.query(CollectionEvent).count()}")
    src = service.create_source(db, tenant_id=1, connection_id=conn.id, source_ref="s")
    ev = CollectionEvent(tenant_id=1, source_id=src.id, provider="telegram",
                         processing_state=state, **kw)
    db.add(ev); db.commit()
    return ev


def test_lock_complete_transition():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db)
    analysis.acquire(db, event=ev, worker="w1")
    assert ev.processing_state == "analyzing" and ev.locked_by == "w1"
    analysis.complete(db, event=ev, worker="w1",
                      analysis_version="clf-1", analysis={"intent": "sale"})
    assert ev.processing_state == "analyzed"
    assert ev.processed_at is not None
    assert ev.analysis_version == "clf-1" and ev.analysis_json == {"intent": "sale"}
    assert ev.locked_by is None and ev.locked_at is None


def test_fail_sets_retry_and_backoff():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db)
    analysis.acquire(db, event=ev, worker="w1")
    analysis.fail(db, event=ev, worker="w1", error_code="classifier_timeout")
    assert ev.processing_state == "failed"
    assert ev.attempts == 1 and ev.error_code == "classifier_timeout"
    assert ev.next_attempt_at is not None


def test_retry_only_after_next_attempt_at():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db)
    analysis.acquire(db, event=ev, worker="w1")
    analysis.fail(db, event=ev, worker="w1", error_code="x")
    with pytest.raises(analysis.NotLockable):
        analysis.acquire(db, event=ev, worker="w2")     # retry not due yet
    ev.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    analysis.acquire(db, event=ev, worker="w2")          # now allowed
    assert ev.processing_state == "analyzing" and ev.locked_by == "w2"


def test_exhausted_attempts_dead_letter():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db)
    for n in range(analysis.DEFAULT_MAX_ATTEMPTS):
        ev.next_attempt_at = None
        analysis.acquire(db, event=ev, worker="w1")
        analysis.fail(db, event=ev, worker="w1", error_code=f"e{n}")
    assert ev.processing_state == "dead_letter"
    assert ev.attempts == analysis.DEFAULT_MAX_ATTEMPTS
    with pytest.raises(analysis.NotLockable):
        analysis.acquire(db, event=ev, worker="w1")


def test_active_lock_blocks_expired_lock_allows():
    db = make_session(); make_tenant(db, 1)
    ev = _event(db)
    analysis.acquire(db, event=ev, worker="w1")
    with pytest.raises(analysis.LockHeld):
        analysis.acquire(db, event=ev, worker="w2")      # active lock
    ev.locked_at = datetime.now(timezone.utc) - timedelta(seconds=999)
    db.commit()
    analysis.acquire(db, event=ev, worker="w2")           # expired lock taken over
    assert ev.locked_by == "w2"
    with pytest.raises(analysis.LockHeld):
        analysis.complete(db, event=ev, worker="w1",      # old holder rejected
                          analysis_version="v", analysis={})


def test_control_and_rejected_never_lockable():
    db = make_session(); make_tenant(db, 1)
    ctl = _event(db, state="control", is_control=True)
    with pytest.raises(analysis.NotLockable):
        analysis.acquire(db, event=ctl, worker="w1")
    rej = _event(db, state="rejected")
    with pytest.raises(analysis.NotLockable):
        analysis.acquire(db, event=rej, worker="w1")


def test_atomic_acquire_rejects_stale_second_session(tmp_path):
    """Two workers that loaded the same row cannot both acquire it."""
    from sqlalchemy import create_engine, event as sqla_event
    from sqlalchemy.orm import sessionmaker
    import app.models  # noqa: F401
    from app.database import Base
    from app.models import Tenant

    engine = create_engine(f"sqlite:///{tmp_path / 'locks.db'}")
    @sqla_event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    setup = S(); setup.add(Tenant(id=1, name="T1", slug="t1")); setup.commit()
    conn = service.create_connection(setup, tenant_id=1, provider="telegram", name="c")
    src = service.create_source(setup, tenant_id=1, connection_id=conn.id, source_ref="s")
    ev = CollectionEvent(tenant_id=1, source_id=src.id, provider="telegram",
                         processing_state="normalized")
    setup.add(ev); setup.commit(); event_id = ev.id; setup.close()

    s1, s2 = S(), S()
    e1, e2 = s1.get(CollectionEvent, event_id), s2.get(CollectionEvent, event_id)
    analysis.acquire(s1, event=e1, worker="w1"); s1.commit()
    with pytest.raises(analysis.LockHeld):
        analysis.acquire(s2, event=e2, worker="w2")
    s1.close(); s2.close()
