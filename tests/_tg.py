"""Helpers for the Telegram-intelligence tests: isolated in-memory DB session,
synthetic tenants/findings and a registered dummy provider (services validate
the provider against the registry — corrective C10)."""
from __future__ import annotations

import hashlib

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401  (register all tables on Base.metadata)
from app.collection import registry
from app.database import Base
from app.models import ExposureFinding, Tenant


class DummyProvider:
    """Minimal registered provider so service-level registry validation passes."""
    name = "telegram"

    def fetch_identity(self, secret_ref):  # pragma: no cover
        raise NotImplementedError

    def normalize(self, raw):  # pragma: no cover
        raise NotImplementedError


def ensure_provider(name: str = "telegram") -> None:
    if name not in registry.providers:
        registry.providers.register(name, DummyProvider())


def make_session() -> Session:
    ensure_provider()
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _rec):  # pragma: no cover
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def make_tenant(db: Session, tid: int) -> None:
    db.add(Tenant(id=tid, name=f"T{tid}", slug=f"t{tid}"))
    db.flush()


def make_finding(db: Session, tenant_id: int, key: str = "k") -> ExposureFinding:
    """Valid synthetic finding for outbox tests (corrective C7)."""
    f = ExposureFinding(
        tenant_id=tenant_id,
        exposure_type="credential_exposure",
        title=f"synthetic finding {key}",
        source="test",
        dedup_key=hashlib.sha256(f"{tenant_id}:{key}".encode()).hexdigest(),
    )
    db.add(f)
    db.flush()
    return f
