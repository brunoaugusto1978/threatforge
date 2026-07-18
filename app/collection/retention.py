"""Retention purge for normalised collection content (req #11, corrective C10).

When the retention window on the normalised content expires, we:

  * clear ``redacted_text``;
  * clear context and policy-bound identifiers (``context_json``,
    ``control_nonce_hash``, ``analysis_json``);
  * PRESERVE ONLY the authorised fields: fingerprints
    (``normalized_fingerprint``/``raw_fingerprint``), minimal metadata
    (provider, timestamps, states, ``external_id_hash``) and the provenance
    links (``finding_id``/``case_id``);
  * record ``purged_at`` and the applied policy (``retention_policy``);
  * respect ``legal_hold`` (rows under legal hold are skipped);
  * write an audit entry for the purge run (C10).

``PURGED_FIELDS`` / ``PRESERVED_FIELDS`` are the machine-readable contract of
what the purge touches; the tests assert against them so any drift fails loudly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CollectionEvent, utcnow

# Contract: what the purge clears vs preserves (authorised fields only).
PURGED_FIELDS: tuple[str, ...] = (
    "redacted_text", "context_json", "control_nonce_hash", "analysis_json",
)
PRESERVED_FIELDS: tuple[str, ...] = (
    "normalized_fingerprint", "raw_fingerprint", "external_id_hash",
    "provider", "processing_state", "content_version", "redaction_profile",
    "occurred_at", "created_at", "finding_id", "case_id", "legal_hold",
)


@dataclass(frozen=True)
class PurgeReport:
    purged: int
    skipped_legal_hold: int
    policy: str


def purge_expired_events(
    db: Session, *, tenant_id: int, policy: str, older_than: datetime,
    actor: str = "retention-job", commit: bool = True,
) -> PurgeReport:
    """Purge policy-bound content from events created before ``older_than``.

    Only rows not already purged and not under legal hold are affected. The run
    is audited (action ``collection.retention_purged``) with counts only — no
    content ever enters the audit log.
    """
    rows = db.execute(
        select(CollectionEvent).where(
            CollectionEvent.tenant_id == tenant_id,
            CollectionEvent.created_at < older_than,
            CollectionEvent.purged_at.is_(None),
        )
    ).scalars().all()

    purged = 0
    skipped = 0
    purged_ids: list[int] = []
    for ev in rows:
        if ev.legal_hold:
            skipped += 1
            continue
        # clear exactly the policy-bound fields (PURGED_FIELDS)
        ev.redacted_text = None
        ev.context_json = {}
        ev.control_nonce_hash = None
        ev.analysis_json = {}
        # bookkeeping
        ev.purged_at = utcnow()
        ev.retention_policy = policy
        purged += 1
        purged_ids.append(ev.id)

    _audit_purge(db, tenant_id=tenant_id, policy=policy, actor=actor,
                 purged=purged, skipped=skipped)

    if commit:
        db.commit()
    else:
        db.flush()
    return PurgeReport(purged=purged, skipped_legal_hold=skipped, policy=policy)


def _audit_purge(db: Session, *, tenant_id: int, policy: str, actor: str,
                 purged: int, skipped: int) -> None:
    """Audit the purge run (C10). Counts + policy only; never content."""
    try:
        from app import audit
        audit.record(
            db, actor=actor, actor_role="system", tenant_id=tenant_id,
            action="collection.retention_purged", target_type="collection_event",
            target_id=None, request=None, commit=False,
            detail={"policy": policy, "purged": purged,
                    "skipped_legal_hold": skipped},
        )
    except Exception:  # audit failure must not break the purge (same as app.audit)
        pass
