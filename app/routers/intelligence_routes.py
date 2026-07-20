"""Provider-neutral Intelligence Workspace API (v0.11.0, Phase 2C).

The workspace is a read-only operational surface over the existing collection
schema.  It introduces no migration and never returns provider payloads,
secret references, external identifiers, fingerprints, or unrestricted
context.  Every query is tenant-scoped.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, features
from app.auth import Principal, current_tenant_id, require_analyst, require_viewer
from app.collection import service
from app.database import get_db
from app.models import CollectionConnection, CollectionEvent, CollectionSource, utcnow

router = APIRouter(
    prefix="/intelligence",
    tags=["intelligence"],
    dependencies=[Depends(require_viewer)],
)

_EVENT_CONTEXT_FIELDS = {
    "chat_type",
    "update_kind",
    "forwarded",
    "has_text",
    "entity_count",
    "has_attachment",
    "email_detected",
    "email_domains",
    "actor_ref",
    "actor_kind",
    "actor_username_present",
}
_EVENT_TEXT_LIMIT = 4000
_EVENT_STATES = (
    "received",
    "normalized",
    "control",
    "rejected",
    "dead_letter",
    "analyzing",
    "analyzed",
    "failed",
)
_PENDING_STATES = ("received", "normalized", "analyzing", "failed")
_COLLECTOR_PRIORITY = ("unauthorized", "offline", "degraded", "pending", "healthy")
_STALE_AFTER_SECONDS = 120

def _safe_string_list(value: Any, *, limit: int = 20, max_length: int = 120) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:max_length] for item in value[:limit]]


_ANALYSIS_FACTOR_CODES = {
    "protected_target_match",
    "threat_term_match",
    "explicit_intent",
    "authorized_source",
    "critical_target",
    "negation_detected",
    "authorized_testing_context",
    "informational_context",
    "contextual_target_match",
    "credential_artifact",
    "credential_email_domain_match",
    "claimed_access_signal",
    "credential_market_signal",
    "conversation_continuity",
    "unverified_control_literal",
}


def _safe_analysis(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    target = value.get("matched_target")
    promotion = value.get("promotion")
    factors = []
    for item in value.get("factors") or []:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "")
        if code not in _ANALYSIS_FACTOR_CODES:
            continue
        factors.append({
            "code": code,
            "weight": int(item.get("weight") or 0),
            "matched": bool(item.get("matched")),
            "detail": str(item.get("detail") or "")[:200],
        })
    safe_target = None
    if isinstance(target, dict):
        safe_target = {
            "kind": str(target.get("kind") or "")[:30],
            "label": str(target.get("label") or "")[:200],
            "criticality": str(target.get("criticality") or "")[:20],
        }
    safe_promotion = None
    if isinstance(promotion, dict):
        safe_promotion = {
            "finding_id": promotion.get("finding_id"),
            "case_id": promotion.get("case_id"),
            "finding_created": bool(promotion.get("finding_created")),
            "case_created": bool(promotion.get("case_created")),
            "linked_from_context": bool(promotion.get("linked_from_context")),
            "context_linked_event_count": max(
                0, min(int(promotion.get("context_linked_event_count") or 0), 50)
            ),
        }
    return {
        "decision": str(value.get("decision") or "")[:60],
        "score": max(0, min(int(value.get("score") or 0), 100)),
        "confidence": str(value.get("confidence") or "")[:20],
        "severity": str(value.get("severity") or "")[:20],
        "threat_category": str(value.get("threat_category") or "")[:60],
        "correlation_family": str(
            value.get("correlation_family")
            or value.get("threat_category")
            or ""
        )[:60],
        "matched_email_domains": _safe_string_list(
            value.get("matched_email_domains"), max_length=253
        ),
        "contextual_match": bool(value.get("contextual_match")),
        "conversation_followup": bool(value.get("conversation_followup")),
        "context_event_count": max(
            0, min(int(value.get("context_event_count") or 0), 50)
        ),
        "matched_target": safe_target,
        "matched_target_terms": _safe_string_list(value.get("matched_target_terms")),
        "matched_threat_terms": _safe_string_list(value.get("matched_threat_terms")),
        "matched_intent_terms": _safe_string_list(value.get("matched_intent_terms")),
        "negation": bool(value.get("negation")),
        "authorized_context": bool(value.get("authorized_context")),
        "informational_context": bool(value.get("informational_context")),
        "factors": factors,
        "promotion": safe_promotion,
    }


def _safe_event_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result = {
        key: value[key]
        for key in _EVENT_CONTEXT_FIELDS
        if key in value
        and key not in {"email_domains", "actor_ref", "actor_kind"}
    }
    email_domains = _safe_string_list(
        value.get("email_domains"), max_length=253
    )
    if email_domains:
        result["email_domains"] = email_domains
    actor_ref = str(value.get("actor_ref") or "")
    if len(actor_ref) == 64 and all(ch in "0123456789abcdef" for ch in actor_ref):
        result["actor_ref"] = actor_ref
    actor_kind = str(value.get("actor_kind") or "")[:30]
    if actor_kind in {"user", "sender_chat"}:
        result["actor_kind"] = actor_kind
    return result


def _event_text(value: Any) -> tuple[str, bool]:
    text = value if isinstance(value, str) else ""
    if len(text) <= _EVENT_TEXT_LIMIT:
        return text, False
    return text[:_EVENT_TEXT_LIMIT] + "…[truncated]", True


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        parsed = _parse_iso(value)
        return parsed.isoformat() if parsed is not None else None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _collector_state(connection: CollectionConnection, now: datetime) -> tuple[str, dict[str, Any]]:
    if not connection.enabled:
        return "paused", {}
    health = service.connection_health(connection)
    raw_state = str(health.get("state") or "pending").lower()
    state = raw_state if raw_state in {*_COLLECTOR_PRIORITY, "paused"} else "degraded"
    checked_at = _parse_iso(health.get("checked_at"))
    if checked_at is None:
        state = "pending"
    elif (now - checked_at).total_seconds() > _STALE_AFTER_SECONDS:
        state = "offline"
    return state, health


def _audit(
    db: Session,
    principal: Principal,
    tid: int,
    request: Request,
    action: str,
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
        target_type="collection_event",
        target_id=target_id,
        request=request,
        detail=detail,
    )


def _base_event_query(tid: int):
    return (
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


def _event_view(event: CollectionEvent, source: CollectionSource, *, detail: bool = False) -> dict[str, Any]:
    text, truncated = _event_text(event.redacted_text)
    result: dict[str, Any] = {
        "id": event.id,
        "source_id": event.source_id,
        "source_name": source.name or f"Source #{source.id}",
        "source_kind": source.kind,
        "provider": event.provider,
        "state": event.processing_state,
        "occurred_at": _iso(event.occurred_at),
        "created_at": _iso(event.created_at),
        "redacted_text": text,
        "text_truncated": truncated,
        "context": _safe_event_context(event.context_json),
        "analysis": _safe_analysis(event.analysis_json),
        "analysis_version": event.analysis_version,
        "finding_id": event.finding_id,
        "case_id": event.case_id,
        "has_finding": event.finding_id is not None,
        "has_case": event.case_id is not None,
    }
    if detail:
        result.update(
            {
                "content_version": event.content_version,
                "redaction_profile": event.redaction_profile,
                "is_control": bool(event.is_control),
                "rejection_reason": event.rejection_reason,
                "attempts": event.attempts,
                "next_attempt_at": _iso(event.next_attempt_at),
            }
        )
    return result


@router.get("/overview")
def intelligence_overview(
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
):
    """Return a fast, provider-neutral operational overview for viewer+."""
    collection_enabled = features.is_enabled(features.Feature.COLLECTION_TELEGRAM)
    analysis_enabled = features.is_enabled(features.Feature.ANALYSIS_TELEGRAM)
    now = utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    event_filter = (
        CollectionEvent.tenant_id == tid,
        CollectionEvent.purged_at.is_(None),
    )
    events_total = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(*event_filter)
    ) or 0
    events_24h = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            *event_filter, CollectionEvent.created_at >= day_ago
        )
    ) or 0
    events_7d = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            *event_filter, CollectionEvent.created_at >= week_ago
        )
    ) or 0
    pending_analysis = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            *event_filter, CollectionEvent.processing_state.in_(_PENDING_STATES)
        )
    ) or 0
    linked_findings = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            *event_filter, CollectionEvent.finding_id.is_not(None)
        )
    ) or 0
    linked_cases = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            *event_filter, CollectionEvent.case_id.is_not(None)
        )
    ) or 0
    last_event_at = db.scalar(
        select(func.max(func.coalesce(CollectionEvent.occurred_at, CollectionEvent.created_at)))
        .where(*event_filter)
    )

    connection_rows = list(
        db.scalars(
            select(CollectionConnection)
            .where(
                CollectionConnection.tenant_id == tid,
                CollectionConnection.deleted_at.is_(None),
            )
            .order_by(CollectionConnection.id)
        )
    )
    source_rows = list(
        db.scalars(
            select(CollectionSource)
            .where(
                CollectionSource.tenant_id == tid,
                CollectionSource.deleted_at.is_(None),
            )
            .order_by(CollectionSource.provider, CollectionSource.name, CollectionSource.id)
        )
    )

    collectors = []
    collector_states = []
    for connection in connection_rows:
        state, health = _collector_state(connection, now)
        collector_states.append(state)
        collectors.append(
            {
                "id": connection.id,
                "name": connection.name,
                "provider": connection.provider,
                "enabled": bool(connection.enabled),
                "status": connection.status,
                "state": state,
                "last_success_at": health.get("last_success_at"),
                "last_event_at": health.get("last_event_at"),
                "persisted_events": int(health.get("persisted_events") or 0),
                "deduplicated_updates": int(health.get("deduplicated_updates") or 0),
                "ignored_updates": int(health.get("ignored_updates") or 0),
                "error_code": health.get("error_code") or None,
            }
        )

    enabled_states = [state for connection, state in zip(connection_rows, collector_states) if connection.enabled]
    if not connection_rows:
        overall_collector_state = "not_configured"
    elif not enabled_states:
        overall_collector_state = "paused"
    else:
        overall_collector_state = next(
            (state for state in _COLLECTOR_PRIORITY if state in enabled_states),
            "pending",
        )

    provider_counts = {
        str(provider): int(count)
        for provider, count in db.execute(
            select(CollectionEvent.provider, func.count())
            .where(*event_filter)
            .group_by(CollectionEvent.provider)
            .order_by(CollectionEvent.provider)
        ).all()
    }
    state_counts = {state: 0 for state in _EVENT_STATES}
    for state, count in db.execute(
        select(CollectionEvent.processing_state, func.count())
        .where(*event_filter)
        .group_by(CollectionEvent.processing_state)
    ).all():
        state_counts[str(state)] = int(count)

    source_metrics = {
        int(source_id): (int(count), _iso(last_seen))
        for source_id, count, last_seen in db.execute(
            select(
                CollectionEvent.source_id,
                func.count(),
                func.max(func.coalesce(CollectionEvent.occurred_at, CollectionEvent.created_at)),
            )
            .where(*event_filter)
            .group_by(CollectionEvent.source_id)
        ).all()
    }
    sources = []
    for source in source_rows:
        count, last_seen = source_metrics.get(source.id, (0, None))
        sources.append(
            {
                "id": source.id,
                "provider": source.provider,
                "name": source.name or f"Source #{source.id}",
                "kind": source.kind,
                "enabled": bool(source.enabled),
                "status": source.status,
                "event_count": count,
                "last_event_at": last_seen,
            }
        )

    response = {
        "generated_at": _iso(now),
        "tenant_id": tid,
        "license_enabled": collection_enabled,
        "analysis_enabled": analysis_enabled,
        "summary": {
            "events_total": int(events_total),
            "events_24h": int(events_24h),
            "events_7d": int(events_7d),
            "pending_analysis": int(pending_analysis),
            "linked_findings": int(linked_findings),
            "linked_cases": int(linked_cases),
            "connections_total": len(connection_rows),
            "connections_enabled": sum(1 for row in connection_rows if row.enabled),
            "sources_total": len(source_rows),
            "sources_active": sum(1 for row in source_rows if row.enabled),
            "collector_state": overall_collector_state,
            "last_event_at": _iso(last_event_at),
        },
        "providers": provider_counts,
        "states": state_counts,
        "collectors": collectors,
        "sources": sources,
    }
    if not collection_enabled:
        response["upgrade"] = features.upgrade_block()
    return response


@router.get("/events")
def intelligence_events(
    request: Request,
    provider: str | None = Query(default=None, min_length=1, max_length=40),
    source_id: int | None = Query(default=None, ge=1),
    state: Literal[
        "received", "normalized", "control", "rejected", "dead_letter",
        "analyzing", "analyzed", "failed"
    ] | None = Query(default=None),
    query: str | None = Query(default=None, max_length=200),
    has_finding: bool | None = Query(default=None),
    has_case: bool | None = Query(default=None),
    pending_analysis: bool | None = Query(default=None),
    occurred_from: datetime | None = Query(default=None),
    occurred_to: datetime | None = Query(default=None),
    before_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_analyst),
):
    """List redacted intelligence events with stable cursor pagination."""
    features.ensure_enabled(features.Feature.COLLECTION_TELEGRAM)
    if source_id is not None:
        try:
            service.get_source(db, tenant_id=tid, source_id=source_id)
        except service.NotFound:
            raise HTTPException(status_code=404, detail="Source not found.") from None

    stmt = _base_event_query(tid)
    if provider:
        stmt = stmt.where(CollectionEvent.provider == provider.strip().lower())
    if source_id is not None:
        stmt = stmt.where(CollectionEvent.source_id == source_id)
    if state is not None:
        stmt = stmt.where(CollectionEvent.processing_state == state)
    if query and query.strip():
        pattern = f"%{query.strip()}%"
        stmt = stmt.where(CollectionEvent.redacted_text.ilike(pattern))
    if has_finding is True:
        stmt = stmt.where(CollectionEvent.finding_id.is_not(None))
    elif has_finding is False:
        stmt = stmt.where(CollectionEvent.finding_id.is_(None))
    if has_case is True:
        stmt = stmt.where(CollectionEvent.case_id.is_not(None))
    elif has_case is False:
        stmt = stmt.where(CollectionEvent.case_id.is_(None))
    if pending_analysis is True:
        stmt = stmt.where(CollectionEvent.processing_state.in_(_PENDING_STATES))
    if occurred_from is not None:
        stmt = stmt.where(
            func.coalesce(CollectionEvent.occurred_at, CollectionEvent.created_at) >= occurred_from
        )
    if occurred_to is not None:
        stmt = stmt.where(
            func.coalesce(CollectionEvent.occurred_at, CollectionEvent.created_at) <= occurred_to
        )
    if before_id is not None:
        stmt = stmt.where(CollectionEvent.id < before_id)

    rows = db.execute(stmt.order_by(CollectionEvent.id.desc()).limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [_event_view(event, source) for event, source in rows]
    next_before_id = items[-1]["id"] if has_more and items else None
    _audit(
        db,
        principal,
        tid,
        request,
        "intelligence.events_viewed",
        source_id,
        {
            "rows": len(items),
            "provider": provider,
            "source_id": source_id,
            "state": state,
            "has_finding": has_finding,
            "has_case": has_case,
            "pending_analysis": pending_analysis,
        },
    )
    return {
        "items": items,
        "has_more": has_more,
        "next_before_id": next_before_id,
    }


@router.get("/events/{event_id}")
def intelligence_event_detail(
    event_id: int,
    request: Request,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
    principal: Principal = Depends(require_analyst),
):
    """Return one redacted event detail, never the provider payload."""
    features.ensure_enabled(features.Feature.COLLECTION_TELEGRAM)
    row = db.execute(
        _base_event_query(tid).where(CollectionEvent.id == event_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Intelligence event not found.")
    event, source = row
    result = _event_view(event, source, detail=True)
    _audit(
        db,
        principal,
        tid,
        request,
        "intelligence.event_viewed",
        event_id,
        {"provider": event.provider, "source_id": event.source_id},
    )
    return result
