"""Alert outbox helpers — idempotency (req #5) and state (req #4).

Residual requirement #5: every enqueue derives a ``dedup_key`` from at least
tenant, finding, channel, template and template version. A UNIQUE constraint on
``dedup_key`` guarantees the same notification cannot be enqueued twice by a
replay or reprocessing.

Residual requirement #4: delivery state (``status``, ``attempts``,
``next_attempt_at``, ``delivered_at``, ``error_code``) lives ONLY in outbox
columns, never inside ``payload_json``. This module never writes those into the
payload.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.collection.states import OUTBOX_STATUS

# Keys that must never appear inside payload_json (they are columns; req #4).
FORBIDDEN_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "status", "attempts", "next_attempt_at", "delivered_at", "error_code",
    "delivery_state",
})

# Closed, redacted delivery payload. State remains in table columns.
ALLOWED_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "finding_ref", "severity", "redacted_title", "redacted_summary",
    "asset_ref", "category", "confidence", "ioc_summary",
    "occurred_at", "source_ref",
})

_DEDUP_VERSION = "v1"


def compute_dedup_key(
    tenant_id: int,
    finding_id: int | str,
    alert_channel_id: int,
    template: str,
    template_version: str | int,
) -> str:
    """Deterministic idempotency key (SHA-256 hex).

    Derived from tenant, finding, channel, template and template version — the
    minimum mandated by residual requirement #5. Stable across processes so a
    replay recomputes the same key and hits the UNIQUE constraint.
    """
    material = "|".join([
        _DEDUP_VERSION,
        str(int(tenant_id)),
        str(finding_id),
        str(int(alert_channel_id)),
        str(template or ""),
        str(template_version if template_version is not None else ""),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def assert_payload_clean(payload: dict) -> None:
    """Validate the closed, already-redacted outbox payload contract.

    Arbitrary dictionaries are rejected so raw conversations, credentials or
    original evidence cannot be persisted accidentally in the durable outbox.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload_json must be an object")
    keys = {str(k).lower() for k in payload}
    bad = FORBIDDEN_PAYLOAD_KEYS & keys
    if bad:
        raise ValueError(
            f"payload_json must not carry delivery-state keys: {sorted(bad)}"
        )
    unknown = keys - ALLOWED_PAYLOAD_KEYS
    if unknown:
        raise ValueError(f"payload_json contains unapproved keys: {sorted(unknown)}")
    for key, value in payload.items():
        if isinstance(value, dict):
            raise ValueError(f"payload_json field {key!r} must be pre-rendered/redacted")
        if isinstance(value, (list, tuple)):
            if any(isinstance(item, (dict, list, tuple, set)) for item in value):
                raise ValueError(f"payload_json field {key!r} contains nested data")
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"payload_json field {key!r} has unsupported type")


def next_backoff(attempts: int, *, base_seconds: int = 30, cap_seconds: int = 3600,
                 now: datetime | None = None) -> datetime:
    """Exponential backoff timestamp for the next attempt."""
    now = now or datetime.now(timezone.utc)
    delay = min(cap_seconds, base_seconds * (2 ** max(0, int(attempts) - 1)))
    return now + timedelta(seconds=delay)


@dataclass(frozen=True)
class EnqueueResult:
    created: bool          # True if a new row was inserted, False if deduped
    dedup_key: str
    outbox_id: int | None = None
    status: str = "pending"


def is_terminal(status: str) -> bool:
    return status in ("delivered", "dead_letter")


VALID_STATUS = set(OUTBOX_STATUS)
