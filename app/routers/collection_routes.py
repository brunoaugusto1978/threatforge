"""Provider-neutral Telegram Intelligence catalog and source-management API.

No live provider code is present here.  Every operational endpoint is gated by
``collection.telegram`` and dispatches through the public collection registry.
Community without the package/license continues to expose only a locked catalog
card and returns the standard HTTP 402 body for actions.
"""
from __future__ import annotations

from datetime import timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, features
from app.auth import (
    Principal, current_tenant_id, require_admin, require_analyst, require_viewer,
)
from app.collection import registry, runtime, service
from app.database import get_db
from app.models import (
    CollectionEvent, CollectionSource, CollectionSourceTestRequest, utcnow,
)

router = APIRouter(
    prefix="/collection",
    tags=["collection"],
    dependencies=[Depends(require_viewer)],
)


class ConnectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    provider: Literal["telegram"] = "telegram"
    bot_token_ref: str = Field(
        description="Opaque secret reference; never a Telegram token value."
    )
    poll_timeout_seconds: int = Field(default=20, ge=1, le=50)
    allowed_updates: list[str] = Field(
        default_factory=lambda: [
            "message",
            "edited_message",
            "channel_post",
            "edited_channel_post",
        ]
    )

    @field_validator("name", "bot_token_ref")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be blank")
        return value


class ConnectionStateUpdate(BaseModel):
    enabled: bool


class ConnectionTestRequest(BaseModel):
    activate: bool = True


class SourceCreate(BaseModel):
    source_ref: str = Field(min_length=1, max_length=160)
    name: str | None = Field(default=None, max_length=120)
    kind: Literal["group", "supergroup", "channel", "private", "test"] = "group"
    enabled: bool = True

    @field_validator("source_ref")
    @classmethod
    def _source_ref(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("source_ref must be a non-empty provider identifier")
        return value


class SourceStateUpdate(BaseModel):
    enabled: bool


class SourceVerificationRequest(BaseModel):
    ttl_minutes: int = Field(default=30, ge=5, le=120)


_EVENT_CONTEXT_FIELDS = {
    "chat_type",
    "update_kind",
    "forwarded",
    "has_text",
    "entity_count",
    "has_attachment",
}
_EVENT_TEXT_LIMIT = 4000


def _safe_event_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in _EVENT_CONTEXT_FIELDS if key in value}


def _event_text(value: Any) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ""
    if len(text) <= _EVENT_TEXT_LIMIT:
        return text, False
    return text[:_EVENT_TEXT_LIMIT] + "…[truncated]", True


def _audit(
    db: Session,
    principal: Principal,
    tid: int,
    request: Request,
    action: str,
    target_type: str,
    target_id: int | None,
    detail: dict[str, Any] | None = None,
) -> None:
    audit.record(
        db,
        actor=principal.subject,
        actor_role=principal.role,
        tenant_id=tid,
        operator_user_id=principal.user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        request=request,
        detail=detail,
    )


def _gate() -> None:
    features.ensure_enabled(features.Feature.COLLECTION_TELEGRAM)


def _bootstrap_provider() -> Any:
    provider = registry.providers.get("telegram")
    if provider is None:
        runtime.bootstrap_enterprise_extensions(replace=False)
        provider = registry.providers.get("telegram")
    if provider is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "provider_unavailable", "provider": "telegram"},
        )
    return provider


def _connection_view(row) -> dict[str, Any]:
    config_json = dict(row.config_json or {})
    config_json.pop("_health", None)
    return {
        "id": row.id,
        "provider": row.provider,
        "name": row.name,
        "enabled": bool(row.enabled),
        "status": row.status,
        "provider_account_ref": row.provider_account_ref or "",
        "bot_username": config_json.get("bot_username") or "",
        "config": config_json,
        "credential_configured": bool((row.secret_refs or {}).get("bot_token")),
        "health": service.connection_health(row),
        "cursor_configured": row.cursor is not None,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _source_view(row: CollectionSource) -> dict[str, Any]:
    return {
        "id": row.id,
        "connection_id": row.connection_id,
        "provider": row.provider,
        "source_ref": row.source_ref,
        "kind": row.kind,
        "name": row.name or "",
        "enabled": bool(row.enabled),
        "status": row.status,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("/catalog")
def collection_catalog():
    enabled = features.is_enabled(features.Feature.COLLECTION_TELEGRAM)
    item: dict[str, Any] = {
        "name": "telegram-intelligence",
        "title": "Telegram Intelligence",
        "feature": features.Feature.COLLECTION_TELEGRAM.value,
        "analysis_feature": features.Feature.ANALYSIS_TELEGRAM.value,
        "premium": True,
        "enabled": enabled,
        "description": (
            "Authorized inbound collection from a controlled Telegram group. "
            "Separate from outbound Telegram alert notifications."
        ),
        "capabilities": [
            "authorized Bot API collection",
            "tenant-isolated sources",
            "replay-safe cursor",
            "sanitized health",
        ],
    }
    if not enabled:
        item["upgrade"] = features.upgrade_block()
    return [item]


@router.get("/connections")
def list_connections(
    db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)
):
    _gate()
    _bootstrap_provider()
    return [
        _connection_view(row)
        for row in service.list_connections(db, tenant_id=tid, provider="telegram")
    ]


@router.post("/connections", status_code=201)
def create_connection(
    payload: ConnectionCreate,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    _gate()
    _bootstrap_provider()
    try:
        row = service.create_connection(
            db,
            tenant_id=tid,
            provider=payload.provider,
            name=payload.name,
            payload={
                "poll_timeout_seconds": payload.poll_timeout_seconds,
                "allowed_updates": payload.allowed_updates,
            },
            secret_refs={"bot_token": payload.bot_token_ref},
            actor=principal.subject,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_secret_reference", "code": str(exc)},
        ) from None
    except service.ServiceError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from None
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.connection_created",
        "collection_connection",
        row.id,
        {"provider": row.provider},
    )
    return _connection_view(row)


@router.patch("/connections/{connection_id}")
def update_connection_state(
    connection_id: int,
    payload: ConnectionStateUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    _gate()
    try:
        row = service.set_connection_enabled(
            db,
            tenant_id=tid,
            connection_id=connection_id,
            enabled=payload.enabled,
        )
        db.commit()
    except service.NotFound:
        raise HTTPException(status_code=404, detail="Connection not found.") from None
    except service.ChannelNotReady as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from None
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.connection_enabled" if payload.enabled else "collection.connection_disabled",
        "collection_connection",
        row.id,
    )
    return _connection_view(row)


@router.post("/connections/{connection_id}/test")
def test_connection(
    connection_id: int,
    payload: ConnectionTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    _gate()
    provider = _bootstrap_provider()
    try:
        row = service.get_connection(
            db, tenant_id=tid, connection_id=connection_id
        )
    except service.NotFound:
        raise HTTPException(status_code=404, detail="Connection not found.") from None
    secret_ref = (row.secret_refs or {}).get("bot_token")
    if not secret_ref:
        raise HTTPException(status_code=409, detail="Credential reference is missing.")
    try:
        result = provider.test_connection(secret_ref, row.config_json or {})
    except Exception as exc:
        diagnostic = runtime.provider_diagnostic(exc)
        result = None
    else:
        diagnostic = (
            {
                "code": result.diagnostic.code,
                "state": result.diagnostic.state,
                "retry_after_seconds": result.diagnostic.retry_after_seconds,
            }
            if result.diagnostic is not None
            else None
        )
    if not diagnostic and (result is None or not result.ok):
        health = result.health if result is not None else None
        diagnostic = {
            "code": getattr(health, "error_code", None) or "provider_error",
            "state": getattr(health, "state", None) or "degraded",
            "retry_after_seconds": getattr(health, "retry_after_seconds", None),
        }

    if result is not None and result.ok and result.identity is not None:
        try:
            row = service.bind_bot_identity(
                db,
                tenant_id=tid,
                connection_id=connection_id,
                identity=result.identity,
                enable=payload.activate,
            )
            service.set_connection_health(
                db,
                tenant_id=tid,
                connection_id=connection_id,
                health={
                    "state": result.health.state,
                    "checked_at": result.health.checked_at,
                    "last_success_at": result.health.last_success_at,
                    "error_code": "",
                },
            )
            db.commit()
        except service.IdentityConflict as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from None
        ok = True
    else:
        health = result.health if result is not None else None
        service.set_connection_health(
            db,
            tenant_id=tid,
            connection_id=connection_id,
            health={
                "state": getattr(health, "state", None) or diagnostic["state"],
                "checked_at": getattr(health, "checked_at", None) or "",
                "error_code": getattr(health, "error_code", None) or diagnostic["code"],
                "retry_after_seconds": getattr(health, "retry_after_seconds", None)
                if health is not None
                else diagnostic.get("retry_after_seconds"),
            },
        )
        db.commit()
        ok = False
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.connection_tested",
        "collection_connection",
        connection_id,
        {"ok": ok, "error_code": "" if ok else (diagnostic or {}).get("code", "provider_error")},
    )
    current = service.get_connection(
        db, tenant_id=tid, connection_id=connection_id
    )
    return {
        "ok": ok,
        "connection": _connection_view(current),
        "diagnostic": None if ok else diagnostic,
    }


@router.get("/connections/{connection_id}/health")
def get_connection_health(
    connection_id: int,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
):
    _gate()
    try:
        row = service.get_connection(
            db, tenant_id=tid, connection_id=connection_id
        )
    except service.NotFound:
        raise HTTPException(status_code=404, detail="Connection not found.") from None
    return service.connection_health(row)


@router.get("/sources")
def list_sources(
    connection_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
):
    _gate()
    if connection_id is not None:
        try:
            service.get_connection(db, tenant_id=tid, connection_id=connection_id)
        except service.NotFound:
            raise HTTPException(status_code=404, detail="Connection not found.") from None
    return [
        _source_view(row)
        for row in service.list_sources(
            db, tenant_id=tid, connection_id=connection_id
        )
    ]


@router.post("/connections/{connection_id}/sources", status_code=201)
def create_source(
    connection_id: int,
    payload: SourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    _gate()
    try:
        row = service.create_source(
            db,
            tenant_id=tid,
            connection_id=connection_id,
            source_ref=payload.source_ref,
            kind=payload.kind,
            name=payload.name,
            actor=principal.subject,
        )
        if payload.enabled:
            row = service.enable_source(db, tenant_id=tid, source_id=row.id)
        db.commit()
    except service.NotFound:
        db.rollback()
        raise HTTPException(status_code=404, detail="Connection not found.") from None
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.source_created",
        "collection_source",
        row.id,
        {"connection_id": connection_id, "provider": row.provider},
    )
    return _source_view(row)


@router.post(
    "/connections/{connection_id}/sources/{source_id}/verify-request",
    status_code=201,
)
def request_source_verification(
    connection_id: int,
    source_id: int,
    payload: SourceVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    """Issue a one-time TF-VERIFY message for an authorized source.

    Only the nonce hash is persisted. The plaintext control message is returned
    once to the authenticated tenant administrator and is never included in
    the audit detail.
    """
    _gate()
    try:
        connection = service.get_connection(
            db, tenant_id=tid, connection_id=connection_id
        )
        source = service.get_source(db, tenant_id=tid, source_id=source_id)
        if source.connection_id != connection.id:
            raise HTTPException(
                status_code=404, detail="Source not found for connection."
            )
        if source.provider != connection.provider:
            raise HTTPException(
                status_code=409, detail="Source provider differs from connection."
            )
        issued = service.request_source_test(
            db,
            tenant_id=tid,
            connection_id=connection.id,
            source_id=source.id,
            ttl_minutes=payload.ttl_minutes,
            actor=principal.subject,
        )
        db.commit()
    except service.NotFound:
        db.rollback()
        raise HTTPException(
            status_code=404, detail="Connection or source not found."
        ) from None
    except (service.TenantMismatch, service.ProviderMismatch) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from None

    _audit(
        db,
        principal,
        tid,
        request,
        "collection.source_verification_requested",
        "collection_source_test_request",
        issued.request_id,
        {
            "connection_id": connection.id,
            "source_id": source.id,
            "provider": source.provider,
            "ttl_minutes": payload.ttl_minutes,
        },
    )
    return {
        "request_id": issued.request_id,
        "connection_id": connection.id,
        "source_id": source.id,
        "provider": source.provider,
        "status": "awaiting",
        "message": f"TF-VERIFY-{issued.nonce}",
        "expires_at": issued.expires_at,
    }


@router.get("/source-tests/{request_id}")
def get_source_verification_status(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_viewer),
):
    """Return tenant-scoped verification status without nonce material."""
    _gate()
    row = db.execute(
        select(CollectionSourceTestRequest).where(
            CollectionSourceTestRequest.id == request_id,
            CollectionSourceTestRequest.tenant_id == tid,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404, detail="Source verification request not found."
        )

    if row.status in {"pending", "awaiting"} and row.expires_at is not None:
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < utcnow():
            row.status = "expired"
            db.commit()

    _audit(
        db,
        principal,
        tid,
        request,
        "collection.source_verification_status_viewed",
        "collection_source_test_request",
        row.id,
        {
            "connection_id": row.connection_id,
            "source_id": row.source_id,
            "provider": row.provider,
            "status": row.status,
        },
    )
    return {
        "request_id": row.id,
        "connection_id": row.connection_id,
        "source_id": row.source_id,
        "provider": row.provider,
        "status": row.status,
        "requested_at": row.requested_at,
        "verified_at": row.verified_at,
        "expires_at": row.expires_at,
    }


@router.patch("/sources/{source_id}")
def update_source_state(
    source_id: int,
    payload: SourceStateUpdate,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_admin),
):
    _gate()
    try:
        row = service.set_source_enabled(
            db, tenant_id=tid, source_id=source_id, enabled=payload.enabled
        )
        db.commit()
    except service.NotFound:
        raise HTTPException(status_code=404, detail="Source not found.") from None
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.source_enabled" if payload.enabled else "collection.source_disabled",
        "collection_source",
        row.id,
    )
    return _source_view(row)


@router.get("/events")
def list_events(
    request: Request,
    source_id: int | None = Query(default=None),
    before_id: int | None = Query(default=None, ge=1),
    state: Literal[
        "received", "normalized", "control", "rejected", "dead_letter",
        "analyzing", "analyzed", "failed"
    ] | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_analyst),
):
    """List tenant-scoped, redacted collection evidence.

    The route never returns raw provider payloads, secret references, external
    identifiers or unrestricted context. Pagination uses the stable event id.
    """
    _gate()
    if source_id is not None:
        try:
            service.get_source(db, tenant_id=tid, source_id=source_id)
        except service.NotFound:
            raise HTTPException(status_code=404, detail="Source not found.") from None
    stmt = (
        select(CollectionEvent, CollectionSource)
        .join(
            CollectionSource,
            (CollectionSource.id == CollectionEvent.source_id)
            & (CollectionSource.tenant_id == CollectionEvent.tenant_id),
        )
        .where(
            CollectionEvent.tenant_id == tid,
            CollectionEvent.purged_at.is_(None),
        )
    )
    if source_id is not None:
        stmt = stmt.where(CollectionEvent.source_id == source_id)
    if before_id is not None:
        stmt = stmt.where(CollectionEvent.id < before_id)
    if state is not None:
        stmt = stmt.where(CollectionEvent.processing_state == state)
    rows = db.execute(
        stmt.order_by(CollectionEvent.id.desc()).limit(limit)
    ).all()
    result = []
    for event, source in rows:
        text, truncated = _event_text(event.redacted_text)
        result.append(
            {
                "id": event.id,
                "source_id": event.source_id,
                "source_name": source.name or source.source_ref,
                "provider": event.provider,
                "state": event.processing_state,
                "occurred_at": event.occurred_at,
                "created_at": event.created_at,
                "redacted_text": text,
                "text_truncated": truncated,
                "context": _safe_event_context(event.context_json),
                "finding_id": event.finding_id,
                "case_id": event.case_id,
            }
        )
    _audit(
        db,
        principal,
        tid,
        request,
        "collection.events_viewed",
        "collection_event",
        source_id,
        {
            "rows": len(result),
            "source_id": source_id,
            "before_id": before_id,
            "state": state,
        },
    )
    return result
