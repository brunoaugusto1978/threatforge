"""Single-update ingestion with the same-transaction cursor advance (req #8).

For each update the flow is strictly:

    1. validate
    2. normalize
    3. persist event OR controlled rejection (sanitised dead-letter)
    4. advance the CONNECTION cursor (corrective C1 — the Bot API update stream
       belongs to the bot/connection; all sources of a connection share it)
    5. commit the transaction

Corrective audit findings addressed here:

  C1 — the cursor is resolved and advanced on ``CollectionConnection`` in the
       same transaction that persists the update's outcome.
  C4 — exception taxonomy. A replay is answered with the EXISTING event
       (``deduplicated``), never a rejection. Only validation/normalisation
       errors (:class:`ValidationRejected` or ``ValueError``/``TypeError``/
       ``KeyError`` from the provider callbacks) produce the sanitised
       dead-letter. Database/infrastructure errors roll back WITHOUT advancing
       the cursor and WITHOUT a provider dead-letter — they surface as
       :class:`IngestInfrastructureError`. No blanket ``except Exception``.
  C5 — TF-VERIFY is only treated as control when a pending, unexpired test
       request matches tenant + connection + source + nonce hash. On match the
       request is confirmed (``verified``/``verified_at``/telemetry) and no
       classification/correlation/alerting happens. Without a match the
       message follows the NORMAL flow.
  C10 — ingestion is refused (controlled error, no cursor movement) when the
       connection or the source is disabled, revoked or soft-deleted; the
       update's ``occurred_at`` is persisted on the event.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.collection import service as _service
from app.collection import verify
from app.collection.contracts import NormalizedUpdate, RejectionRecord
from app.collection.envelope import EvidenceEnvelope
from app.models import CollectionConnection, CollectionEvent, CollectionSource, utcnow


class IngestError(Exception):
    """Base controlled ingestion error."""


class IngestNotAllowed(IngestError):
    """Connection/source disabled, revoked or soft-deleted (C10)."""


class ValidationRejected(IngestError):
    """Raise from a validator/normalizer to signal a controlled rejection."""


class IngestInfrastructureError(IngestError):
    """Database/infrastructure failure: rolled back, cursor NOT advanced (C4)."""


# Exception types from provider callbacks treated as validation failures (C4).
_VALIDATION_ERRORS = (ValidationRejected, ValueError, TypeError, KeyError)


@dataclass(frozen=True)
class IngestResult:
    outcome: str            # 'normalized' | 'control' | 'rejected' | 'deduplicated'
    event_id: int | None
    cursor: str | None
    envelope: EvidenceEnvelope | None = None


def _hash(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _extract_cursor(raw: dict[str, Any]) -> str | None:
    for key in ("update_id", "cursor", "offset", "id"):
        if raw.get(key) is not None:
            return str(raw[key])
    return None


def _extract_text(raw: dict[str, Any]) -> str | None:
    if isinstance(raw.get("text"), str):
        return raw["text"]
    msg = raw.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("text"), str):
        return msg["text"]
    return None


def _parse_occurred_at(value: Any) -> datetime | None:
    """Persistable ``occurred_at`` from ISO-8601 or unix epoch (C10)."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        parsed = datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _resolve_active_pair(
    db: Session, source: CollectionSource,
) -> CollectionConnection:
    """Return the source's connection; refuse ingestion if either is inactive."""
    conn = db.execute(
        select(CollectionConnection).where(
            CollectionConnection.id == source.connection_id,
            CollectionConnection.tenant_id == source.tenant_id,
        )
    ).scalar_one_or_none()
    if conn is None:
        raise IngestNotAllowed("connection not found for source")
    if conn.deleted_at is not None or not conn.enabled or conn.status == "revoked":
        raise IngestNotAllowed("connection is disabled, revoked or deleted")
    if source.deleted_at is not None or not source.enabled or source.status == "revoked":
        raise IngestNotAllowed("source is disabled, revoked or deleted")
    return conn


def _find_existing_event(db: Session, source: CollectionSource,
                         external_id_hash: str) -> CollectionEvent | None:
    if not external_id_hash:
        return None
    return db.execute(
        select(CollectionEvent).where(
            CollectionEvent.tenant_id == source.tenant_id,
            CollectionEvent.source_id == source.id,
            CollectionEvent.external_id_hash == external_id_hash,
            CollectionEvent.processing_state != "rejected",
        )
    ).scalar_one_or_none()


def ingest_update(
    db: Session,
    *,
    source: CollectionSource,
    raw: dict[str, Any],
    normalizer: Callable[[dict[str, Any]], NormalizedUpdate],
    validator: Callable[[dict[str, Any]], None] | None = None,
) -> IngestResult:
    """Process one raw update inside a single transaction (validate→…→commit)."""
    # C10 — activation gate (controlled error; no cursor movement, no dead letter)
    conn = _resolve_active_pair(db, source)

    tenant_id = source.tenant_id
    provider = source.provider
    cursor_val = _extract_cursor(raw)
    text = _extract_text(raw)

    # ---- C4: replay short-circuit — return the existing event, not a rejection.
    ext_hash = _hash(cursor_val) if cursor_val is not None else ""
    existing = _find_existing_event(db, source, ext_hash)
    if existing is not None:
        return IngestResult("deduplicated", existing.id, conn.cursor)

    # ---- C5: TF-VERIFY is control ONLY with a matching pending request.
    nonce = verify.parse_verify_nonce(text)
    if nonce is not None:
        request = _service.find_matching_test_request(
            db, tenant_id=tenant_id, connection_id=conn.id,
            source_id=source.id, nonce_hash=verify.nonce_hash(nonce))
        if request is not None:
            try:
                ev = CollectionEvent(
                    tenant_id=tenant_id, source_id=source.id, provider=provider,
                    external_id_hash=ext_hash,
                    processing_state="control", is_control=True,
                    control_nonce_hash=verify.nonce_hash(nonce),
                    occurred_at=_parse_occurred_at(_raw_date(raw)),
                    redacted_text=None, context_json={"kind": "tf_verify"},
                )
                db.add(ev)
                _service.confirm_test_request(
                    db, request=request,
                    telemetry={"confirmed_via": "ingest",
                               "nonce_hash_prefix": verify.nonce_hash(nonce)[:12]})
                _advance_cursor(conn, cursor_val)
                db.flush()
                db.commit()
            except SQLAlchemyError as exc:
                db.rollback()
                raise IngestInfrastructureError(str(exc)[:200]) from exc
            return IngestResult("control", ev.id, conn.cursor)
        # no matching pending request → NORMAL flow (fall through)

    # ---- 1. validate / 2. normalize (validation errors → sanitised rejection)
    try:
        if validator is not None:
            validator(raw)
        nu = normalizer(raw)
    except _VALIDATION_ERRORS as exc:
        return _record_rejection(db, conn, source, cursor_val, exc)

    # ---- 3. persist event / 4. advance cursor / 5. commit — same transaction
    envelope = EvidenceEnvelope.from_normalized(
        provider=provider, tenant_id=tenant_id, source_ref=source.source_ref,
        normalized=nu.normalized, redacted_text=nu.redacted_text,
        content_version=nu.content_version, redaction_profile=nu.redaction_profile,
        occurred_at=nu.occurred_at, raw_fingerprint=nu.raw_fingerprint,
    )
    ev = CollectionEvent(
        tenant_id=tenant_id, source_id=source.id, provider=provider,
        external_id_hash=_hash(nu.external_id) if nu.external_id else ext_hash,
        processing_state="normalized",
        normalized_fingerprint=envelope.normalized_fingerprint,
        raw_fingerprint=nu.raw_fingerprint,
        content_version=nu.content_version,
        redaction_profile=nu.redaction_profile,
        redacted_text=nu.redacted_text,
        context_json=dict(nu.normalized),
        occurred_at=_parse_occurred_at(nu.occurred_at),
    )
    try:
        db.add(ev)
        _advance_cursor(conn, cursor_val)
        db.flush()
        db.commit()
    except IntegrityError:
        # C4 — concurrent replay raced us to the unique index: dedup, not reject.
        db.rollback()
        existing = _find_existing_event(db, source, ev.external_id_hash)
        if existing is not None:
            return IngestResult("deduplicated", existing.id, conn.cursor)
        raise IngestInfrastructureError("integrity error without existing event")
    except SQLAlchemyError as exc:
        # C4 — infrastructure error: rolled back, cursor NOT advanced, no dead letter.
        db.rollback()
        raise IngestInfrastructureError(str(exc)[:200]) from exc
    return IngestResult("normalized", ev.id, conn.cursor, envelope)


def _raw_date(raw: dict[str, Any]) -> Any:
    msg = raw.get("message")
    if isinstance(msg, dict) and msg.get("date") is not None:
        return msg.get("date")
    return raw.get("date")


def _advance_cursor(conn: CollectionConnection, cursor_val: str | None) -> None:
    """C1 — the cursor lives on the connection (shared by all its sources)."""
    if cursor_val is not None:
        conn.cursor = cursor_val
    conn.updated_at = utcnow()


def _record_rejection(db: Session, conn: CollectionConnection,
                      source: CollectionSource, cursor_val: str | None,
                      exc: Exception) -> IngestResult:
    """Persist a sanitised dead-letter and still advance the cursor (req #8).

    Only reached for validation/normalisation failures (C4). No sensitive
    content is stored: a short reason code and a hashed id only.
    """
    reason = type(exc).__name__[:60]
    rec = RejectionRecord(
        provider=source.provider,
        reason_code=reason,
        external_id_hash=_hash(cursor_val) if cursor_val is not None else "",
        sanitized_detail="update rejected during validation/normalization",
    )
    try:
        ev = CollectionEvent(
            tenant_id=source.tenant_id, source_id=source.id, provider=source.provider,
            external_id_hash=rec.external_id_hash,
            processing_state="rejected",
            rejection_reason=rec.reason_code,
            context_json={"detail": rec.sanitized_detail},
        )
        db.add(ev)
        _advance_cursor(conn, cursor_val)
        db.flush()
        db.commit()
    except SQLAlchemyError as db_exc:
        db.rollback()
        raise IngestInfrastructureError(str(db_exc)[:200]) from db_exc
    return IngestResult("rejected", ev.id, conn.cursor)
