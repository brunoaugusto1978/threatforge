"""Public collection/alerting services (v0.11.0, Phase 1 — corrective).

Implemented to the level needed to validate contracts, persistence, tenant
isolation, secret handling and the outbox/idempotency invariants. The real Bot
API I/O and intent classifier remain in the private Enterprise package.

Every function takes an explicit ``tenant_id`` and filters by it.

Corrective audit findings addressed here:
  C3 — opaque Secret Resolver refs are persisted (``secret_refs``) and can be
       resolved later via :func:`resolve_connection_secret` /
       :func:`resolve_channel_secret`; classification is fail-closed.
  C6 — ``enqueue_alert`` verifies the finding belongs to the same tenant as
       the outbox and the channel.
  C10 — provider validated against the registry; identity provider validated
       against the connection provider.
"""
from __future__ import annotations

import hashlib
import secrets as _pysecrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.collection import outbox as outbox_helpers
from app.collection import registry as _registry
from app.collection import secrets as secret_resolver
from app.collection.contracts import ProviderIdentity
from app.models import (
    AlertOutbox,
    CollectionConnection,
    CollectionSource,
    CollectionSourceTestRequest,
    ExposureFinding,
    TenantAlertChannel,
    utcnow,
)


class ServiceError(Exception):
    """Base for controlled service errors (never leak a stack trace)."""


class TenantMismatch(ServiceError):
    pass


class NotFound(ServiceError):
    pass


class IdentityConflict(ServiceError):
    """A bot identity already has an active connection in another tenant (#7)."""


class ProviderMismatch(ServiceError):
    """Identity/source provider differs from the connection provider (C10)."""


class UnknownProvider(ServiceError):
    """Provider is not registered in the collection provider registry (C10)."""


class UnknownChannelType(ServiceError):
    """Alert channel type is not registered."""


class ChannelNotReady(ServiceError):
    """Alert channel is disabled, deleted, or lacks required configuration."""


def _require_registered_provider(provider: str) -> str:
    key = str(provider).strip().lower()
    if key not in _registry.providers:
        raise UnknownProvider(
            f"collection provider {provider!r} is not registered")
    return key


def _require_registered_alert_channel(channel_type: str) -> str:
    key = str(channel_type).strip().lower()
    if key not in _registry.alert_channels:
        raise UnknownChannelType(f"alert channel {channel_type!r} is not registered")
    return key


# --------------------------------------------------------------------------- #
# Connections
# --------------------------------------------------------------------------- #
def create_connection(
    db: Session, *, tenant_id: int, provider: str, name: str,
    payload: dict | None = None, secret_refs: dict[str, str] | None = None,
    actor: str | None = None,
) -> CollectionConnection:
    """Create a disabled connection without persisting cleartext secrets.

    ``payload`` is fail-closed through the provider schema.  ``secret_refs`` is
    the preferred Phase 2A path: callers submit only validated opaque Secret
    Resolver references such as ``secretref://env/THREATFORGE_...``.
    """
    provider = _require_registered_provider(provider)
    split = secret_resolver.classify_payload(payload or {}, provider=provider)
    refs = secret_resolver.persist_secrets(tenant_id, f"connection:{name}", split)
    metadata = dict(split.secrets_metadata)
    for raw_name, raw_ref in (secret_refs or {}).items():
        key = str(raw_name).strip().lower()
        ref = secret_resolver.validate_opaque_ref(raw_ref)
        refs[key] = ref
        metadata[key] = {"present": True, "kind": "opaque_ref", "masked": "***"}
    conn = CollectionConnection(
        tenant_id=tenant_id, provider=provider, name=name,
        enabled=False, status="pending",
        config_json=split.config_json,
        secret_refs=refs,
        secrets_metadata=metadata,
        created_by=actor,
    )
    db.add(conn)
    db.flush()
    return conn


def resolve_connection_secret(conn: CollectionConnection, name: str) -> str | None:
    """Authorised path for a provider to resolve a connection secret (C3)."""
    return secret_resolver.resolve_secret(conn.secret_refs or {}, name)


def bind_bot_identity(
    db: Session, *, tenant_id: int, connection_id: int, identity: ProviderIdentity,
    enable: bool = True,
) -> CollectionConnection:
    """Persist the non-secret bot identity (getMe) and optionally enable (#7).

    Validates that the identity's provider matches the connection's provider
    (C10) and enforces cross-tenant exclusivity of the active identity.
    """
    conn = _get_connection(db, tenant_id, connection_id)
    if str(identity.provider).strip().lower() != conn.provider:
        raise ProviderMismatch(
            f"identity provider {identity.provider!r} does not match "
            f"connection provider {conn.provider!r}")
    if enable:
        clash = db.execute(
            select(CollectionConnection.id).where(
                CollectionConnection.provider == identity.provider,
                CollectionConnection.provider_account_ref == identity.account_ref,
                CollectionConnection.enabled.is_(True),
                CollectionConnection.deleted_at.is_(None),
                CollectionConnection.id != connection_id,
            )
        ).first()
        if clash is not None:
            raise IdentityConflict(
                f"bot identity {identity.account_ref!r} already active in another connection")
    conn.provider_account_ref = identity.account_ref
    if identity.username:
        conn.config_json = {**(conn.config_json or {}), "bot_username": identity.username}
    if enable:
        conn.enabled = True
        conn.status = "active"
    conn.updated_at = utcnow()
    db.flush()
    return conn


def revoke_connection(db: Session, *, tenant_id: int, connection_id: int,
                      actor: str | None = None) -> CollectionConnection:
    conn = _get_connection(db, tenant_id, connection_id)
    conn.enabled = False
    conn.status = "revoked"
    conn.revoked_at = utcnow()
    conn.revoked_by = actor
    db.flush()
    return conn


def soft_delete_connection(db: Session, *, tenant_id: int, connection_id: int,
                           actor: str | None = None) -> CollectionConnection:
    conn = _get_connection(db, tenant_id, connection_id)
    now = utcnow()
    conn.enabled = False
    conn.status = "revoked"
    conn.revoked_at = conn.revoked_at or now
    conn.revoked_by = actor
    conn.deleted_at = now
    conn.deleted_by = actor
    db.flush()
    return conn


def get_connection(db: Session, *, tenant_id: int, connection_id: int) -> CollectionConnection:
    return _get_connection(db, tenant_id, connection_id)


def list_connections(db: Session, *, tenant_id: int, provider: str | None = None) -> list[CollectionConnection]:
    stmt = select(CollectionConnection).where(
        CollectionConnection.tenant_id == tenant_id,
        CollectionConnection.deleted_at.is_(None),
    )
    if provider:
        stmt = stmt.where(CollectionConnection.provider == str(provider).lower())
    return list(db.scalars(stmt.order_by(CollectionConnection.id)))


def set_connection_enabled(
    db: Session, *, tenant_id: int, connection_id: int, enabled: bool
) -> CollectionConnection:
    conn = _get_connection(db, tenant_id, connection_id)
    if enabled and not conn.provider_account_ref:
        raise ChannelNotReady("connection identity must be verified before enabling")
    conn.enabled = bool(enabled)
    conn.status = "active" if enabled else "pending"
    conn.updated_at = utcnow()
    db.flush()
    return conn


def set_connection_health(
    db: Session, *, tenant_id: int, connection_id: int, health: dict
) -> CollectionConnection:
    """Merge sanitized operational telemetry into ``config_json._health``.

    Empty polling cycles must not erase the last observed event timestamp or
    cumulative counters.  Provider failures likewise preserve the last known
    success/event metadata while replacing the current state and diagnostic.
    """
    conn = _get_connection(db, tenant_id, connection_id)
    allowed = {
        "state", "checked_at", "last_success_at", "last_event_at",
        "lag_seconds", "error_code", "retry_after_seconds",
        "processed_updates", "deduplicated_updates", "rejected_updates",
        "ignored_updates", "persisted_events",
        "last_cycle_processed", "last_cycle_deduplicated",
        "last_cycle_rejected", "last_cycle_ignored",
    }
    incoming = {k: v for k, v in dict(health or {}).items() if k in allowed}
    current = connection_health(conn)
    merged = dict(current)
    for key, value in incoming.items():
        # An empty provider value means "no new event in this cycle", not that
        # the historical timestamp disappeared.
        if key in {"last_success_at", "last_event_at"} and value in (None, ""):
            continue
        merged[key] = value
    conn.config_json = {**(conn.config_json or {}), "_health": merged}
    conn.updated_at = utcnow()
    db.flush()
    return conn


def connection_health(conn: CollectionConnection) -> dict:
    health = (conn.config_json or {}).get("_health")
    return dict(health) if isinstance(health, dict) else {"state": "pending"}


def _get_connection(db: Session, tenant_id: int, connection_id: int) -> CollectionConnection:
    conn = db.execute(
        select(CollectionConnection).where(
            CollectionConnection.id == connection_id,
            CollectionConnection.tenant_id == tenant_id,
            CollectionConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise NotFound("connection not found")
    return conn


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
def create_source(
    db: Session, *, tenant_id: int, connection_id: int, source_ref: str,
    kind: str = "channel", name: str | None = None, actor: str | None = None,
) -> CollectionSource:
    """Create a source under a connection of the SAME tenant. Starts disabled."""
    conn = _get_connection(db, tenant_id, connection_id)
    src = CollectionSource(
        tenant_id=tenant_id, connection_id=conn.id, provider=conn.provider,
        source_ref=source_ref, kind=kind, name=name,
        enabled=False, status="pending", created_by=actor,
    )
    db.add(src)
    db.flush()
    return src


def enable_source(db: Session, *, tenant_id: int, source_id: int) -> CollectionSource:
    return set_source_enabled(db, tenant_id=tenant_id, source_id=source_id, enabled=True)


def set_source_enabled(
    db: Session, *, tenant_id: int, source_id: int, enabled: bool
) -> CollectionSource:
    src = _get_source(db, tenant_id, source_id)
    src.enabled = bool(enabled)
    src.status = "active" if enabled else "paused"
    src.updated_at = utcnow()
    db.flush()
    return src


def get_source(db: Session, *, tenant_id: int, source_id: int) -> CollectionSource:
    return _get_source(db, tenant_id, source_id)


def list_sources(
    db: Session, *, tenant_id: int, connection_id: int | None = None
) -> list[CollectionSource]:
    stmt = select(CollectionSource).where(
        CollectionSource.tenant_id == tenant_id,
        CollectionSource.deleted_at.is_(None),
    )
    if connection_id is not None:
        stmt = stmt.where(CollectionSource.connection_id == connection_id)
    return list(db.scalars(stmt.order_by(CollectionSource.id)))


def soft_delete_source(db: Session, *, tenant_id: int, source_id: int,
                       actor: str | None = None) -> CollectionSource:
    src = _get_source(db, tenant_id, source_id)
    src.enabled = False
    src.status = "revoked"
    src.deleted_at = utcnow()
    src.deleted_by = actor
    db.flush()
    return src


def _get_source(db: Session, tenant_id: int, source_id: int) -> CollectionSource:
    src = db.execute(
        select(CollectionSource).where(
            CollectionSource.id == source_id,
            CollectionSource.tenant_id == tenant_id,
            CollectionSource.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if src is None:
        raise NotFound("source not found")
    return src


# --------------------------------------------------------------------------- #
# TF-VERIFY test requests (req #6)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TestRequestIssued:
    request_id: int
    nonce: str          # returned ONCE to the operator; only its hash is stored
    expires_at: datetime


def request_source_test(
    db: Session, *, tenant_id: int, connection_id: int,
    source_id: int | None = None, ttl_minutes: int = 30,
    actor: str | None = None,
) -> TestRequestIssued:
    """Open a TF-VERIFY handshake. Stores the nonce HASH only (#6)."""
    conn = _get_connection(db, tenant_id, connection_id)
    source: CollectionSource | None = None
    if source_id is not None:
        source = _get_source(db, tenant_id, source_id)
        if source.connection_id != conn.id:
            raise TenantMismatch("source belongs to a different connection")
        if source.provider != conn.provider:
            raise ProviderMismatch("source provider differs from connection provider")
    nonce = _pysecrets.token_urlsafe(24)
    expires = utcnow() + timedelta(minutes=ttl_minutes)
    row = CollectionSourceTestRequest(
        tenant_id=tenant_id, connection_id=conn.id,
        source_id=source.id if source is not None else None,
        provider=conn.provider,
        nonce_hash=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        status="awaiting", requested_by=actor, expires_at=expires,
    )
    db.add(row)
    db.flush()
    return TestRequestIssued(request_id=row.id, nonce=nonce, expires_at=expires)


def find_matching_test_request(
    db: Session, *, tenant_id: int, connection_id: int,
    source_id: int | None, nonce_hash: str,
) -> CollectionSourceTestRequest | None:
    """Locate the pending, unexpired handshake matching tenant/conn/source/nonce.

    Returns None when there is no match — in that case the message must follow
    the NORMAL flow (corrective C5), not be treated as control.
    """
    row = db.execute(
        select(CollectionSourceTestRequest).where(
            CollectionSourceTestRequest.tenant_id == tenant_id,
            CollectionSourceTestRequest.connection_id == connection_id,
            CollectionSourceTestRequest.nonce_hash == nonce_hash,
            CollectionSourceTestRequest.status.in_(("pending", "awaiting")),
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    if row.source_id is not None and source_id is not None and row.source_id != source_id:
        return None
    if row.expires_at is not None:
        now = utcnow()
        exp = row.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            row.status = "expired"
            db.flush()
            return None
    return row


def confirm_test_request(
    db: Session, *, request: CollectionSourceTestRequest,
    telemetry: dict | None = None,
) -> CollectionSourceTestRequest:
    """Mark the handshake verified; telemetry only — no finding/case/alert (#6)."""
    request.status = "verified"
    request.verified_at = utcnow()
    request.telemetry_json = {**(request.telemetry_json or {}), **(telemetry or {})}
    db.flush()
    return request


# --------------------------------------------------------------------------- #
# Alert channels + outbox
# --------------------------------------------------------------------------- #
def create_alert_channel(
    db: Session, *, tenant_id: int, name: str, channel_type: str,
    payload: dict | None = None, actor: str | None = None,
) -> TenantAlertChannel:
    """Create an alert channel; secrets → resolver, refs persisted (C3)."""
    channel_type = _require_registered_alert_channel(channel_type)
    split = secret_resolver.classify_payload(payload or {}, channel_type=channel_type)
    refs = secret_resolver.persist_secrets(tenant_id, f"channel:{name}", split)
    ch = TenantAlertChannel(
        tenant_id=tenant_id, name=name, channel_type=channel_type,
        enabled=False,
        config_json=split.config_json,
        secret_refs=refs,
        secrets_metadata=split.secrets_metadata,
        created_by=actor,
    )
    db.add(ch)
    db.flush()
    return ch


def resolve_channel_secret(channel: TenantAlertChannel, name: str) -> str | None:
    """Authorised path to resolve a channel secret via its stored ref (C3)."""
    return secret_resolver.resolve_secret(channel.secret_refs or {}, name)


_REQUIRED_CHANNEL_CONFIG = {
    "telegram": ({"chat_id"}, {"bot_token"}),
    "webhook": (set(), {"webhook_url"}),
    "email": ({"smtp_host", "smtp_from", "smtp_to"}, set()),
    "smtp": ({"smtp_host", "smtp_from", "smtp_to"}, set()),
}


def _assert_channel_ready(channel: TenantAlertChannel) -> None:
    if channel.deleted_at is not None or not channel.enabled:
        raise ChannelNotReady("alert channel is disabled or deleted")
    req_config, req_secrets = _REQUIRED_CHANNEL_CONFIG.get(
        channel.channel_type, (set(), set()))
    missing_config = req_config - set((channel.config_json or {}).keys())
    missing_secrets = req_secrets - set((channel.secret_refs or {}).keys())
    if missing_config or missing_secrets:
        raise ChannelNotReady(
            f"alert channel is incomplete: config={sorted(missing_config)}, "
            f"secrets={sorted(missing_secrets)}")


def enable_alert_channel(db: Session, *, tenant_id: int, channel_id: int) -> TenantAlertChannel:
    channel = db.execute(select(TenantAlertChannel).where(
        TenantAlertChannel.id == channel_id,
        TenantAlertChannel.tenant_id == tenant_id,
        TenantAlertChannel.deleted_at.is_(None),
    )).scalar_one_or_none()
    if channel is None:
        raise NotFound("alert channel not found")
    # Validate configuration before activation; temporarily evaluate as enabled.
    channel.enabled = True
    try:
        _assert_channel_ready(channel)
    except Exception:
        channel.enabled = False
        raise
    channel.updated_at = utcnow()
    db.flush()
    return channel


def soft_delete_alert_channel(db: Session, *, tenant_id: int, channel_id: int,
                              actor: str | None = None) -> TenantAlertChannel:
    channel = db.execute(select(TenantAlertChannel).where(
        TenantAlertChannel.id == channel_id,
        TenantAlertChannel.tenant_id == tenant_id,
        TenantAlertChannel.deleted_at.is_(None),
    )).scalar_one_or_none()
    if channel is None:
        raise NotFound("alert channel not found")
    channel.enabled = False
    channel.deleted_at = utcnow()
    channel.deleted_by = actor
    db.flush()
    return channel


@dataclass(frozen=True)
class EnqueueOutcome:
    created: bool
    outbox_id: int
    dedup_key: str
    status: str


def enqueue_alert(
    db: Session, *, tenant_id: int, alert_channel_id: int, finding_id: int,
    template: str, template_version: str = "1",
    payload: dict | None = None, external_channel_ref: str | None = None,
) -> EnqueueOutcome:
    """Idempotently enqueue one notification.

    * Confirms the channel exists **and belongs to the same tenant** (#2).
    * Confirms the finding exists **and belongs to the same tenant** (C6).
    * Rejects a ``payload_json`` carrying delivery-state keys (#4).
    * Derives ``dedup_key`` and returns the existing row on replay (#5).
    """
    payload = payload or {}
    outbox_helpers.assert_payload_clean(payload)

    channel = db.execute(
        select(TenantAlertChannel).where(
            TenantAlertChannel.id == alert_channel_id,
            TenantAlertChannel.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if channel is None:
        raise NotFound("alert channel not found")
    if channel.tenant_id != tenant_id:
        raise TenantMismatch("alert channel belongs to a different tenant")
    _assert_channel_ready(channel)

    # C6 — the finding must exist and belong to the same tenant.
    finding = db.execute(
        select(ExposureFinding.id, ExposureFinding.tenant_id).where(
            ExposureFinding.id == finding_id)
    ).first()
    if finding is None:
        raise NotFound("finding not found")
    if finding.tenant_id != tenant_id:
        raise TenantMismatch("finding belongs to a different tenant")

    dedup_key = outbox_helpers.compute_dedup_key(
        tenant_id, finding_id, alert_channel_id, template, template_version)

    existing = db.execute(
        select(AlertOutbox).where(AlertOutbox.dedup_key == dedup_key)
    ).scalar_one_or_none()
    if existing is not None:
        return EnqueueOutcome(False, existing.id, dedup_key, existing.status)

    row = AlertOutbox(
        tenant_id=tenant_id, alert_channel_id=alert_channel_id, finding_id=finding_id,
        external_channel_ref=external_channel_ref, template=template,
        template_version=str(template_version), dedup_key=dedup_key,
        status="pending", attempts=0, payload_json=payload,
    )
    try:
        # Savepoint keeps the caller's outer transaction usable if a concurrent
        # worker wins the UNIQUE(dedup_key) race.
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        existing = db.execute(
            select(AlertOutbox).where(AlertOutbox.dedup_key == dedup_key)
        ).scalar_one_or_none()
        if existing is None:
            raise
        return EnqueueOutcome(False, existing.id, dedup_key, existing.status)
    return EnqueueOutcome(True, row.id, dedup_key, row.status)


def mark_delivered(db: Session, *, tenant_id: int, outbox_id: int) -> AlertOutbox:
    row = _get_outbox(db, tenant_id, outbox_id)
    row.status = "delivered"
    row.delivered_at = utcnow()
    row.error_code = None
    db.flush()
    return row


def mark_failed(db: Session, *, tenant_id: int, outbox_id: int, error_code: str,
                dead_letter: bool = False) -> AlertOutbox:
    row = _get_outbox(db, tenant_id, outbox_id)
    row.attempts = (row.attempts or 0) + 1
    row.error_code = error_code[:60]
    if dead_letter:
        row.status = "dead_letter"
    else:
        row.status = "failed"
        row.next_attempt_at = outbox_helpers.next_backoff(row.attempts)
    db.flush()
    return row


def _get_outbox(db: Session, tenant_id: int, outbox_id: int) -> AlertOutbox:
    row = db.execute(
        select(AlertOutbox).where(
            AlertOutbox.id == outbox_id, AlertOutbox.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if row is None:
        raise NotFound("outbox row not found")
    return row
