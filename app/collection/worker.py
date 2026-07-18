"""Isolated collection worker for provider-neutral inbound intelligence.

The worker is a separate process from FastAPI.  It polls only enabled
connections, dispatches transient updates to enabled tenant-scoped sources and
uses :func:`app.collection.ingest.ingest_update`, which persists each event and
advances the connection cursor in the same transaction.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import features
from app.collection import ingest, registry, runtime, service
from app.database import SessionLocal
from app.models import CollectionConnection, CollectionSource, utcnow

LOG = logging.getLogger("threatforge.collection.worker")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cursor(raw: dict[str, Any]) -> str | None:
    value = raw.get("update_id")
    return str(value) if value is not None else None


@dataclass(frozen=True)
class WorkerOutcome:
    connection_id: int
    status: str
    processed: int = 0
    deduplicated: int = 0
    rejected: int = 0
    ignored: int = 0
    cursor: str | None = None
    error_code: str = ""


def _health_dict(health: Any) -> dict[str, Any]:
    if health is None:
        return {"state": "pending", "checked_at": _iso_now()}
    if hasattr(health, "__dataclass_fields__"):
        return asdict(health)
    if isinstance(health, dict):
        return dict(health)
    return {"state": "degraded", "checked_at": _iso_now(), "error_code": "provider_error"}


def _advance_ignored(
    db: Session, *, tenant_id: int, connection_id: int, cursor: str | None
) -> None:
    if cursor is None:
        return
    conn = service.get_connection(
        db, tenant_id=tenant_id, connection_id=connection_id
    )
    conn.cursor = cursor
    conn.updated_at = utcnow()
    db.commit()


def run_connection_once(
    db: Session, *, tenant_id: int, connection_id: int
) -> WorkerOutcome:
    """Poll and process one bounded batch for one connection."""
    conn = service.get_connection(
        db, tenant_id=tenant_id, connection_id=connection_id
    )
    if conn.deleted_at is not None or not conn.enabled or conn.status != "active":
        return WorkerOutcome(connection_id, "disabled", cursor=conn.cursor)

    provider = registry.providers.get(conn.provider)
    if provider is None:
        service.set_connection_health(
            db,
            tenant_id=tenant_id,
            connection_id=connection_id,
            health={
                "state": "offline",
                "checked_at": _iso_now(),
                "error_code": "provider_unavailable",
            },
        )
        db.commit()
        return WorkerOutcome(
            connection_id, "failed", cursor=conn.cursor, error_code="provider_unavailable"
        )

    secret_ref = (conn.secret_refs or {}).get("bot_token")
    if not secret_ref:
        service.set_connection_health(
            db,
            tenant_id=tenant_id,
            connection_id=connection_id,
            health={
                "state": "unauthorized",
                "checked_at": _iso_now(),
                "error_code": "credential_unavailable",
            },
        )
        db.commit()
        return WorkerOutcome(
            connection_id, "failed", cursor=conn.cursor, error_code="credential_unavailable"
        )

    try:
        batch = provider.poll(secret_ref, conn.cursor, conn.config_json or {})
    except Exception as exc:  # provider boundary: sanitize, never log str(exc)
        diagnostic = runtime.provider_diagnostic(exc)
        service.set_connection_health(
            db,
            tenant_id=tenant_id,
            connection_id=connection_id,
            health={
                "state": diagnostic["state"],
                "checked_at": _iso_now(),
                "error_code": diagnostic["code"],
                "retry_after_seconds": diagnostic["retry_after_seconds"],
            },
        )
        db.commit()
        LOG.warning(
            "collection poll failed provider=%s connection_id=%s code=%s",
            conn.provider,
            conn.id,
            diagnostic["code"],
        )
        return WorkerOutcome(
            connection_id,
            "failed",
            cursor=conn.cursor,
            error_code=diagnostic["code"],
        )

    sources = service.list_sources(
        db, tenant_id=tenant_id, connection_id=connection_id
    )
    active_by_ref = {
        src.source_ref: src
        for src in sources
        if src.enabled and src.status == "active" and src.deleted_at is None
    }

    processed = dedup = rejected = ignored = 0
    for raw in tuple(batch.updates or ()):
        ref = str(provider.source_ref(raw) or "")
        source = active_by_ref.get(ref)
        if source is None:
            ignored += 1
            _advance_ignored(
                db,
                tenant_id=tenant_id,
                connection_id=connection_id,
                cursor=_cursor(raw),
            )
            continue
        try:
            result = ingest.ingest_update(
                db, source=source, raw=raw, normalizer=provider.normalize
            )
        except ingest.IngestInfrastructureError:
            service.set_connection_health(
                db,
                tenant_id=tenant_id,
                connection_id=connection_id,
                health={
                    "state": "degraded",
                    "checked_at": _iso_now(),
                    "error_code": "ingest_infrastructure_error",
                    "processed_updates": processed,
                    "ignored_updates": ignored,
                },
            )
            db.commit()
            return WorkerOutcome(
                connection_id,
                "failed",
                processed=processed,
                deduplicated=dedup,
                rejected=rejected,
                ignored=ignored,
                cursor=service.get_connection(
                    db, tenant_id=tenant_id, connection_id=connection_id
                ).cursor,
                error_code="ingest_infrastructure_error",
            )
        if result.outcome == "deduplicated":
            dedup += 1
        elif result.outcome == "rejected":
            rejected += 1
        else:
            processed += 1

    health = _health_dict(batch.health)
    health.update({"processed_updates": processed, "ignored_updates": ignored})
    service.set_connection_health(
        db,
        tenant_id=tenant_id,
        connection_id=connection_id,
        health=health,
    )
    db.commit()
    current = service.get_connection(
        db, tenant_id=tenant_id, connection_id=connection_id
    )
    return WorkerOutcome(
        connection_id,
        "ok",
        processed=processed,
        deduplicated=dedup,
        rejected=rejected,
        ignored=ignored,
        cursor=current.cursor,
    )


def run_all_once(db: Session) -> list[WorkerOutcome]:
    rows = list(
        db.scalars(
            select(CollectionConnection).where(
                CollectionConnection.enabled.is_(True),
                CollectionConnection.status == "active",
                CollectionConnection.deleted_at.is_(None),
            ).order_by(CollectionConnection.id)
        )
    )
    outcomes: list[WorkerOutcome] = []
    for row in rows:
        outcomes.append(
            run_connection_once(
                db, tenant_id=row.tenant_id, connection_id=row.id
            )
        )
    return outcomes


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    runtime.bootstrap_enterprise_extensions(replace=True)
    if not features.is_enabled(features.Feature.COLLECTION_TELEGRAM):
        LOG.error("collection.telegram is not licensed; worker will not start")
        return 2
    enabled = os.getenv("THREATFORGE_COLLECTION_WORKER_ENABLED", "false").lower()
    if enabled not in {"1", "true", "yes", "on"}:
        LOG.info("collection worker disabled by configuration")
        return 0
    interval = max(5, min(int(os.getenv("THREATFORGE_COLLECTION_POLL_INTERVAL", "15")), 300))
    while True:
        with SessionLocal() as db:
            outcomes = run_all_once(db)
            LOG.info("collection cycle connections=%s", len(outcomes))
        time.sleep(interval)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
