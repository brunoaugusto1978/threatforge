"""Atomic analysis queue state machine for ``collection_event``.

The actual classifier remains Enterprise. Community owns durable queue state and
must guarantee that two workers cannot acquire the same event. ``acquire`` uses
an atomic conditional UPDATE (compare-and-set), which is safe across PostgreSQL
workers and also works in single-process SQLite development. ``acquire_next``
uses PostgreSQL ``FOR UPDATE SKIP LOCKED`` when available.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from app.collection.outbox import next_backoff
from app.models import CollectionEvent, utcnow

DEFAULT_LOCK_TTL_SECONDS = 300
DEFAULT_MAX_ATTEMPTS = 5


class AnalysisError(Exception):
    """Controlled state-machine error."""


class NotLockable(AnalysisError):
    pass


class LockHeld(AnalysisError):
    pass


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _ready_predicate(now: datetime, lock_cutoff: datetime, max_attempts: int):
    return and_(
        CollectionEvent.is_control.is_(False),
        CollectionEvent.purged_at.is_(None),
        CollectionEvent.attempts < max_attempts,
        or_(
            CollectionEvent.processing_state == "normalized",
            and_(
                CollectionEvent.processing_state == "failed",
                or_(CollectionEvent.next_attempt_at.is_(None),
                    CollectionEvent.next_attempt_at <= now),
            ),
            and_(
                CollectionEvent.processing_state == "analyzing",
                or_(CollectionEvent.locked_at.is_(None),
                    CollectionEvent.locked_at < lock_cutoff),
            ),
        ),
    )


def acquire(
    db: Session, *, event: CollectionEvent, worker: str,
    lock_ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> CollectionEvent:
    """Atomically acquire one known event by compare-and-set.

    A stale ORM object is safe: eligibility is evaluated by the database in the
    UPDATE predicate. Exactly one concurrent worker receives ``rowcount == 1``.
    """
    # Persist explicit caller changes (e.g. clearing next_attempt_at in an
    # operator-approved retry) before the database evaluates the CAS predicate.
    db.flush()
    now = utcnow()
    cutoff = now - timedelta(seconds=lock_ttl_seconds)
    stmt = (
        update(CollectionEvent)
        .where(CollectionEvent.id == event.id, _ready_predicate(now, cutoff, max_attempts))
        .values(processing_state="analyzing", locked_by=worker, locked_at=now)
        .execution_options(synchronize_session=False)
    )
    result = db.execute(stmt)
    if result.rowcount != 1:
        # The caller may hold a stale ORM instance loaded before another worker
        # acquired the row. Force a database refresh before classifying failure.
        db.expire_all()
        current = db.execute(
            select(CollectionEvent).where(CollectionEvent.id == event.id)
        ).scalar_one_or_none()
        if current is None:
            raise NotLockable("event not found")
        locked_at = _aware(current.locked_at)
        if current.processing_state == "analyzing" and locked_at is not None and locked_at >= cutoff:
            raise LockHeld(f"locked by {current.locked_by!r}")
        if current.processing_state == "failed":
            if current.attempts >= max_attempts:
                raise NotLockable("max attempts reached")
            nxt = _aware(current.next_attempt_at)
            if nxt is not None and nxt > now:
                raise NotLockable("retry not due yet")
        raise NotLockable(f"state {current.processing_state!r} is not analysable")
    db.expire(event)
    db.refresh(event)
    return event


def acquire_next(
    db: Session, *, tenant_id: int, worker: str,
    lock_ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> CollectionEvent | None:
    """Acquire the next ready event.

    PostgreSQL uses row locking with ``SKIP LOCKED``. SQLite is explicitly a
    single-worker development path and falls back to select + atomic CAS.
    """
    now = utcnow()
    cutoff = now - timedelta(seconds=lock_ttl_seconds)
    dialect = db.get_bind().dialect.name
    stmt = (
        select(CollectionEvent)
        .where(CollectionEvent.tenant_id == tenant_id,
               _ready_predicate(now, cutoff, max_attempts))
        .order_by(CollectionEvent.created_at, CollectionEvent.id)
        .limit(1)
    )
    if dialect == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
        event = db.execute(stmt).scalar_one_or_none()
        if event is None:
            return None
        event.processing_state = "analyzing"
        event.locked_by = worker
        event.locked_at = now
        db.flush()
        return event
    event = db.execute(stmt).scalar_one_or_none()
    if event is None:
        return None
    return acquire(db, event=event, worker=worker,
                   lock_ttl_seconds=lock_ttl_seconds,
                   max_attempts=max_attempts)


def complete(
    db: Session, *, event: CollectionEvent, worker: str,
    analysis_version: str, analysis: dict,
) -> CollectionEvent:
    """analyzing → analyzed. Records analysis output + processed_at."""
    _require_holder(event, worker)
    event.processing_state = "analyzed"
    event.processed_at = utcnow()
    event.analysis_version = analysis_version
    event.analysis_json = dict(analysis or {})
    event.error_code = None
    event.locked_by = None
    event.locked_at = None
    db.flush()
    return event


def fail(
    db: Session, *, event: CollectionEvent, worker: str, error_code: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> CollectionEvent:
    """analyzing → failed (retryable) or dead_letter when attempts exhausted."""
    _require_holder(event, worker)
    event.attempts = (event.attempts or 0) + 1
    event.error_code = str(error_code)[:60]
    event.locked_by = None
    event.locked_at = None
    if event.attempts >= max_attempts:
        event.processing_state = "dead_letter"
        event.next_attempt_at = None
    else:
        event.processing_state = "failed"
        event.next_attempt_at = next_backoff(event.attempts)
    db.flush()
    return event


def _require_holder(event: CollectionEvent, worker: str) -> None:
    if event.processing_state != "analyzing":
        raise AnalysisError(f"event is not analyzing (state={event.processing_state!r})")
    if event.locked_by != worker:
        raise LockHeld(f"lock held by {event.locked_by!r}, not {worker!r}")


@dataclass(frozen=True)
class QueueStats:
    ready: int
    analyzing: int
    failed: int
    dead_letter: int


def queue_stats(db: Session, *, tenant_id: int) -> QueueStats:
    def _count(state: str) -> int:
        from sqlalchemy import func
        return int(db.execute(
            select(func.count()).select_from(CollectionEvent).where(
                CollectionEvent.tenant_id == tenant_id,
                CollectionEvent.processing_state == state)
        ).scalar_one())
    return QueueStats(ready=_count("normalized"), analyzing=_count("analyzing"),
                      failed=_count("failed"), dead_letter=_count("dead_letter"))
