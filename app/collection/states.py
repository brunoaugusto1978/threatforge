"""Canonical state vocabularies for the collection/alerting subsystem.

Single source of truth for the string enums stored in the ``status`` / state
columns. Kept as plain string tuples (not Python ``Enum``) so they serialise
directly into JSON/SQL and can be reused verbatim in ``CheckConstraint`` SQL by
both the ORM models and the Alembic migration.
"""
from __future__ import annotations


# collection_connection.status — lifecycle of a provider connection.
# NOTE (residual req #1): activation is driven by the boolean ``enabled`` column,
# NOT by textual interpretation of ``status``. ``status`` is descriptive.
CONNECTION_STATUS = ("pending", "active", "revoked")

# collection_source.status — a monitored source (channel/group/DM) under a conn.
SOURCE_STATUS = ("pending", "active", "paused", "revoked")

# collection_event.processing_state — per-update lifecycle inside ingestion.
# ``control`` = TF-VERIFY handshake (never classified/correlated; req #6).
# ``rejected`` = validation/normalisation failed → sanitised dead-letter (req #8).
# C8: analysis lifecycle appended — normalized -> analyzing -> analyzed|failed
EVENT_STATE = ("received", "normalized", "control", "rejected", "dead_letter",
               "analyzing", "analyzed", "failed")

# collection_source_test_request.status — TF-VERIFY test handshake lifecycle.
TEST_REQUEST_STATUS = ("pending", "awaiting", "verified", "failed", "expired")

# alert_outbox.status — delivery lifecycle. State lives ONLY in columns
# (residual req #4): never inside ``payload_json``.
OUTBOX_STATUS = ("pending", "sending", "delivered", "failed", "dead_letter")

# tenant_alert_channel.channel_type — supported alert transports.
CHANNEL_TYPE = ("telegram", "webhook", "email", "smtp")


def _sql_in(column: str, values: tuple[str, ...]) -> str:
    """Render a portable ``col IN ('a','b',...)`` fragment for CheckConstraints."""
    joined = ",".join(f"'{v}'" for v in values)
    return f"{column} IN ({joined})"
