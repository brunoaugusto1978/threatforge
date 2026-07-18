"""PostgreSQL-only concurrency proof for SKIP LOCKED/atomic analysis acquisition."""
from __future__ import annotations

import os
import threading

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.collection import analysis, service
from app.database import Base
from app.models import CollectionEvent, Tenant

PG_URL = os.getenv("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="set TEST_POSTGRES_URL for PostgreSQL concurrency test")


def test_postgres_two_workers_acquire_exactly_once():
    engine = create_engine(PG_URL)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db = S(); db.add(Tenant(id=1, name="T1", slug="t1")); db.flush()
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name="c")
    src = service.create_source(db, tenant_id=1, connection_id=conn.id, source_ref="s")
    ev = CollectionEvent(tenant_id=1, source_id=src.id, provider="telegram",
                         processing_state="normalized")
    db.add(ev); db.commit(); db.close()

    barrier = threading.Barrier(2)
    winners: list[str] = []
    errors: list[Exception] = []

    def worker(name: str):
        session = S()
        try:
            barrier.wait()
            row = analysis.acquire_next(session, tenant_id=1, worker=name)
            if row is not None:
                winners.append(name)
            session.commit()
        except Exception as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc); session.rollback()
        finally:
            session.close()

    threads = [threading.Thread(target=worker, args=("w1",)),
               threading.Thread(target=worker, args=("w2",))]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    assert len(winners) == 1
