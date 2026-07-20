"""Tenant-scoped intelligence analysis and automatic promotion.

Community owns durable state, tenant data and promotion into the shared schema.
Provider-specific classification remains in the Enterprise package and is invoked
through the host-owned classifier/correlator registries.  Only redacted text and
an allowlisted target catalogue cross that seam.

The processor is deliberately idempotent:

* the analysis state machine atomically acquires each event;
* findings use a tenant-scoped deterministic daily correlation key;
* an existing finding/case is reused on replay or repeated same-day evidence;
* raw provider payloads, external IDs, secrets and message text are never copied
  into findings, cases or audit detail.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, features
from app.collection import analysis, registry
from app.models import (
    Brand,
    CollectionEvent,
    CollectionSource,
    ExposureFinding,
    InvestigationCase,
    MonitoredAsset,
    Tenant,
    utcnow,
)

LOG = logging.getLogger("threatforge.collection.intelligence_analysis")

ANALYSIS_VERSION = "telegram-conversation-v2"
WORKER_NAME = "intelligence-analysis"
_DEFAULT_FINDING_THRESHOLD = 60
_DEFAULT_CASE_THRESHOLD = 80
_DEFAULT_BATCH_SIZE = 25
_DEFAULT_CONTEXT_WINDOW_SECONDS = 900
_DEFAULT_CONTEXT_MAX_EVENTS = 10
_MAX_EVENT_IDS = 50

_CASE_SEVERITY = {
    "low": "baixo",
    "medium": "medio",
    "high": "alto",
    "critical": "critico",
}


@dataclass(frozen=True)
class AnalysisPolicy:
    auto_finding: bool
    auto_case: bool
    finding_threshold: int
    case_threshold: int
    batch_size: int
    context_window_seconds: int = _DEFAULT_CONTEXT_WINDOW_SECONDS
    context_max_events: int = _DEFAULT_CONTEXT_MAX_EVENTS


@dataclass(frozen=True)
class AnalysisOutcome:
    event_id: int
    status: str
    score: int = 0
    decision: str = ""
    finding_id: int | None = None
    case_id: int | None = None
    error_code: str = ""


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def policy_from_env() -> AnalysisPolicy:
    finding_threshold = _env_int(
        "THREATFORGE_INTELLIGENCE_FINDING_THRESHOLD",
        _DEFAULT_FINDING_THRESHOLD,
        1,
        100,
    )
    case_threshold = _env_int(
        "THREATFORGE_INTELLIGENCE_CASE_THRESHOLD",
        _DEFAULT_CASE_THRESHOLD,
        finding_threshold,
        100,
    )
    return AnalysisPolicy(
        auto_finding=_env_bool("THREATFORGE_INTELLIGENCE_AUTO_FINDING", False),
        auto_case=_env_bool("THREATFORGE_INTELLIGENCE_AUTO_CASE", False),
        finding_threshold=finding_threshold,
        case_threshold=case_threshold,
        batch_size=_env_int(
            "THREATFORGE_INTELLIGENCE_ANALYSIS_BATCH_SIZE",
            _DEFAULT_BATCH_SIZE,
            1,
            100,
        ),
        context_window_seconds=_env_int(
            "THREATFORGE_INTELLIGENCE_CONTEXT_WINDOW_SECONDS",
            _DEFAULT_CONTEXT_WINDOW_SECONDS,
            60,
            3600,
        ),
        context_max_events=_env_int(
            "THREATFORGE_INTELLIGENCE_CONTEXT_MAX_EVENTS",
            _DEFAULT_CONTEXT_MAX_EVENTS,
            1,
            50,
        ),
    )


def _split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                yield item


def _meaningful_terms(label: str, values: Iterable[str]) -> list[str]:
    """Return stable target terms without broad generic single tokens.

    Full labels/domains are retained.  Short individual tokens are added only
    when they look like an explicit acronym (e.g. ``ACME``), which lets the POC
    match the protected organization without turning generic words such as
    ``security`` into standalone targets.
    """
    collected: list[str] = []

    def add(raw: str) -> None:
        term = re.sub(r"\s+", " ", str(raw or "").strip())
        if len(term) < 3:
            return
        lowered = term.casefold()
        if lowered not in {item.casefold() for item in collected}:
            collected.append(term[:255])

    add(label)
    for value in values:
        add(value)
    for token in re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ0-9_-]+", label):
        if len(token) >= 3 and (token.isupper() or any(ch.isdigit() for ch in token)):
            add(token)
    return collected


def _brand_target(brand: Brand) -> dict[str, Any]:
    values: list[str] = []
    values.extend(_split_csv(brand.official_domains))
    values.extend(_split_csv(brand.keywords))
    for field in (brand.aliases, brand.variations, brand.products, brand.subdomains):
        values.extend(_iter_strings(field))
    return {
        "ref": f"brand:{brand.id}",
        "kind": "brand",
        "label": brand.name,
        "brand_id": brand.id,
        "asset_id": None,
        "asset_type": "brand",
        "criticality": "high",
        "terms": _meaningful_terms(brand.name, values),
    }


def _asset_target(asset: MonitoredAsset) -> dict[str, Any]:
    return {
        "ref": f"asset:{asset.id}",
        "kind": "asset",
        "label": asset.label,
        "brand_id": None,
        "asset_id": asset.id,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "terms": _meaningful_terms(asset.label, [asset.value]),
    }


def _tenant_target(tenant: Tenant) -> dict[str, Any]:
    return {
        "ref": f"tenant:{tenant.id}",
        "kind": "tenant",
        "label": tenant.name,
        "brand_id": None,
        "asset_id": None,
        "asset_type": "organization",
        "criticality": "high",
        "terms": _meaningful_terms(tenant.name, [tenant.slug]),
    }



def _event_time(event: CollectionEvent) -> datetime:
    value = event.occurred_at or event.created_at or utcnow()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def recent_context_events(
    db: Session,
    *,
    event: CollectionEvent,
    policy: AnalysisPolicy,
) -> list[CollectionEvent]:
    """Return a bounded, same-source context window preceding ``event``.

    Control/rejected/dead-letter evidence is excluded.  The query is scoped by
    tenant and source; no event from another customer can enter the envelope.
    """
    current_time = _event_time(event)
    cutoff = current_time - timedelta(seconds=policy.context_window_seconds)
    event_time_expr = func.coalesce(
        CollectionEvent.occurred_at, CollectionEvent.created_at
    )
    rows = list(
        db.scalars(
            select(CollectionEvent)
            .where(
                CollectionEvent.tenant_id == event.tenant_id,
                CollectionEvent.source_id == event.source_id,
                CollectionEvent.provider == event.provider,
                CollectionEvent.id < event.id,
                CollectionEvent.purged_at.is_(None),
                CollectionEvent.is_control.is_(False),
                CollectionEvent.processing_state.notin_(
                    ("control", "rejected", "dead_letter")
                ),
                event_time_expr >= cutoff,
                event_time_expr <= current_time,
            )
            .order_by(event_time_expr.desc(), CollectionEvent.id.desc())
            .limit(policy.context_max_events)
        )
    )
    rows.reverse()
    return rows


def _safe_context_analysis(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    target = value.get("matched_target")
    return {
        "decision": str(value.get("decision") or "")[:60],
        "threat_category": str(value.get("threat_category") or "")[:60],
        "correlation_family": str(value.get("correlation_family") or "")[:60],
        "matched_target_ref": (
            str(target.get("ref") or "")[:100]
            if isinstance(target, dict)
            else ""
        ),
    }


def _context_payload(events: list[CollectionEvent]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for row in events:
        ctx = row.context_json or {}
        payload.append(
            {
                "redacted_text": str(row.redacted_text or "")[:4000],
                "occurred_at": _event_time(row).isoformat(),
                "context": {
                    key: ctx.get(key)
                    for key in (
                        "chat_type",
                        "thread_ref",
                        "reply_to_ref",
                        "actor_ref",
                        "actor_kind",
                        "email_detected",
                        "email_domains",
                    )
                    if key in ctx
                },
                "analysis": _safe_context_analysis(row.analysis_json),
                "linked": bool(row.finding_id or row.case_id),
            }
        )
    return payload


def build_envelope(
    db: Session,
    *,
    event: CollectionEvent,
    source: CollectionSource,
    policy: AnalysisPolicy,
    context_events: list[CollectionEvent] | None = None,
) -> dict[str, Any]:
    tenant = db.get(Tenant, event.tenant_id)
    targets: list[dict[str, Any]] = []
    tenant_terms: list[str] = []
    if tenant is not None:
        tenant_target = _tenant_target(tenant)
        targets.append(tenant_target)
        tenant_terms.extend(tenant_target["terms"])

    brands = list(
        db.scalars(
            select(Brand)
            .where(Brand.tenant_id == event.tenant_id, Brand.status == "active")
            .order_by(Brand.id)
        )
    )
    threat_terms: list[str] = []
    for brand in brands:
        target = _brand_target(brand)
        targets.append(target)
        threat_terms.extend(_iter_strings(brand.sensitive_terms))

    assets = list(
        db.scalars(
            select(MonitoredAsset)
            .where(
                MonitoredAsset.tenant_id == event.tenant_id,
                MonitoredAsset.active.is_(True),
                MonitoredAsset.asset_type.in_(("domain", "keyword", "repo", "ip_range")),
            )
            .order_by(MonitoredAsset.id)
        )
    )
    targets.extend(_asset_target(asset) for asset in assets)

    return {
        "schema": "threatforge.intelligence.envelope.v1",
        "provider": event.provider,
        "redacted_text": event.redacted_text or "",
        "context": {
            key: (event.context_json or {}).get(key)
            for key in (
                "chat_type",
                "update_kind",
                "forwarded",
                "has_text",
                "entity_count",
                "has_attachment",
                "thread_ref",
                "reply_to_ref",
                "actor_ref",
                "actor_kind",
                "actor_username_present",
                "email_detected",
                "email_domains",
            )
            if key in (event.context_json or {})
        },
        "source": {
            "provider": source.provider,
            "kind": source.kind,
            "authorized": bool(source.enabled and source.status == "active"),
        },
        "targets": targets,
        "tenant_terms": tenant_terms,
        "threat_terms": threat_terms,
        "conversation": _context_payload(context_events or []),
        "policy": {
            "auto_finding": policy.auto_finding,
            "auto_case": policy.auto_case,
            "finding_threshold": policy.finding_threshold,
            "case_threshold": policy.case_threshold,
            "context_window_seconds": policy.context_window_seconds,
            "context_max_events": policy.context_max_events,
        },
    }


def _safe_list(value: Any, *, limit: int = 20) -> list[Any]:
    return list(value[:limit]) if isinstance(value, list) else []


def _safe_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("classifier result must be an object")
    target = value.get("matched_target")
    if target is not None and not isinstance(target, dict):
        raise ValueError("matched_target must be an object")
    promotion = value.get("promotion")
    if promotion is not None and not isinstance(promotion, dict):
        raise ValueError("promotion must be an object")
    score = max(0, min(int(value.get("score") or 0), 100))
    return {
        "schema": "threatforge.intelligence.analysis.v1",
        "decision": str(value.get("decision") or "informational")[:60],
        "score": score,
        "confidence": str(value.get("confidence") or "low")[:20],
        "severity": str(value.get("severity") or "low")[:20],
        "threat_category": str(value.get("threat_category") or "none")[:60],
        "correlation_family": str(
            value.get("correlation_family")
            or value.get("threat_category")
            or "none"
        )[:60],
        "matched_email_domains": [
            str(item)[:253]
            for item in _safe_list(value.get("matched_email_domains"))
        ],
        "contextual_match": bool(value.get("contextual_match")),
        "conversation_followup": bool(value.get("conversation_followup")),
        "context_event_count": max(
            0, min(int(value.get("context_event_count") or 0), 50)
        ),
        "matched_target": {
            "ref": str((target or {}).get("ref") or "")[:100],
            "kind": str((target or {}).get("kind") or "")[:30],
            "label": str((target or {}).get("label") or "")[:200],
            "brand_id": (target or {}).get("brand_id"),
            "asset_id": (target or {}).get("asset_id"),
            "asset_type": str((target or {}).get("asset_type") or "")[:30],
            "criticality": str((target or {}).get("criticality") or "")[:20],
        } if target else None,
        "matched_target_terms": [str(item)[:120] for item in _safe_list(value.get("matched_target_terms"))],
        "matched_threat_terms": [str(item)[:120] for item in _safe_list(value.get("matched_threat_terms"))],
        "matched_intent_terms": [str(item)[:120] for item in _safe_list(value.get("matched_intent_terms"))],
        "negation": bool(value.get("negation")),
        "authorized_context": bool(value.get("authorized_context")),
        "informational_context": bool(value.get("informational_context")),
        "factors": [
            {
                "code": str(item.get("code") or "")[:60],
                "weight": int(item.get("weight") or 0),
                "matched": bool(item.get("matched")),
                "detail": str(item.get("detail") or "")[:200],
            }
            for item in _safe_list(value.get("factors"))
            if isinstance(item, dict)
        ],
        "promotion": {
            "create_finding": bool((promotion or {}).get("create_finding")),
            "create_case": bool((promotion or {}).get("create_case")),
            "finding_threshold": int((promotion or {}).get("finding_threshold") or 0),
            "case_threshold": int((promotion or {}).get("case_threshold") or 0),
        },
    }


def _bind_approved_target(
    result: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    """Replace classifier target metadata with the host-approved tenant target.

    Enterprise output is never trusted to introduce a database identifier. The
    returned ``ref`` must exist in the exact tenant-scoped catalogue supplied by
    Community, and matched terms are reduced to that target's approved terms.
    """
    target = result.get("matched_target")
    if not isinstance(target, dict):
        return result
    ref = str(target.get("ref") or "")
    approved = next(
        (
            item
            for item in envelope.get("targets") or []
            if isinstance(item, dict) and str(item.get("ref") or "") == ref
        ),
        None,
    )
    if approved is None:
        result["matched_target"] = None
        result["matched_target_terms"] = []
        result["promotion"]["create_finding"] = False
        result["promotion"]["create_case"] = False
        return result
    result["matched_target"] = {
        "ref": str(approved.get("ref") or "")[:100],
        "kind": str(approved.get("kind") or "")[:30],
        "label": str(approved.get("label") or "")[:200],
        "brand_id": approved.get("brand_id"),
        "asset_id": approved.get("asset_id"),
        "asset_type": str(approved.get("asset_type") or "")[:30],
        "criticality": str(approved.get("criticality") or "")[:20],
    }
    approved_terms = {
        str(item).casefold(): str(item)[:120]
        for item in approved.get("terms") or []
        if isinstance(item, str)
    }
    result["matched_target_terms"] = [
        approved_terms[str(item).casefold()]
        for item in result.get("matched_target_terms") or []
        if str(item).casefold() in approved_terms
    ][:20]
    return result


def _dedup_key(event: CollectionEvent, result: dict[str, Any]) -> str:
    target = result.get("matched_target") or {}
    occurred = event.occurred_at or event.created_at or utcnow()
    if occurred.tzinfo is None:
        occurred = occurred.replace(tzinfo=timezone.utc)
    material = "|".join(
        (
            "intelligence-v1",
            str(event.tenant_id),
            str(target.get("ref") or "unmatched"),
            str(
                result.get("correlation_family")
                or result.get("threat_category")
                or "none"
            ),
            occurred.astimezone(timezone.utc).date().isoformat(),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _exposure_type(
    target: dict[str, Any] | None, result: dict[str, Any]
) -> str:
    if str(result.get("correlation_family") or "") == "credential_exposure":
        return "credential_exposure"
    if not target:
        return "brand_exposure"
    asset_type = str(target.get("asset_type") or "")
    if target.get("kind") in {"brand", "tenant"}:
        return "brand_exposure"
    if asset_type in {"identity", "email"}:
        return "identity_exposure"
    if asset_type in {"domain", "ip_range"}:
        return "infrastructure_exposure"
    if asset_type == "repo":
        return "source_code_exposure"
    if asset_type == "secret_pattern":
        return "secret_exposure"
    return "brand_exposure"


def _finding_title(result: dict[str, Any], label: str) -> str:
    if str(result.get("correlation_family") or "") == "credential_exposure":
        return f"Potential credential exposure involving {label}"[:300]
    return f"Potential targeted threat against {label}"[:300]


def _case_title(result: dict[str, Any], label: str) -> str:
    if str(result.get("correlation_family") or "") == "credential_exposure":
        return f"Potential credential exposure involving {label}"[:255]
    return f"Potential targeted threat against {label}"[:255]


def _finding_detail(
    event: CollectionEvent,
    result: dict[str, Any],
    *,
    event_ids: list[int] | None = None,
    case_id: int | None = None,
    previous_detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = result.get("matched_target") or {}
    previous = previous_detail or {}
    ids = list(dict.fromkeys([*(event_ids or []), event.id]))[-_MAX_EVENT_IDS:]
    email_domains = list(
        dict.fromkeys(
            [
                *[str(item) for item in previous.get("matched_email_domains") or []],
                *[str(item) for item in result.get("matched_email_domains") or []],
            ]
        )
    )[:20]
    decisions = list(
        dict.fromkeys(
            [
                *[str(item) for item in previous.get("decisions") or []],
                str(result.get("decision") or ""),
            ]
        )
    )[-20:]
    return {
        "origin": "intelligence_analysis",
        "provider": event.provider,
        "analysis_version": ANALYSIS_VERSION,
        "decision": result.get("decision"),
        "confidence": result.get("confidence"),
        "confidence_score": result.get("score"),
        "threat_category": result.get("threat_category"),
        "correlation_family": result.get("correlation_family"),
        "matched_email_domains": email_domains,
        "decisions": [item for item in decisions if item],
        "contextual_match": bool(result.get("contextual_match")),
        "conversation_followup": bool(result.get("conversation_followup")),
        "context_event_count": int(result.get("context_event_count") or 0),
        "target_ref": target.get("ref"),
        "target_kind": target.get("kind"),
        "target_label": target.get("label"),
        "matched_target_terms": result.get("matched_target_terms") or [],
        "matched_threat_terms": result.get("matched_threat_terms") or [],
        "matched_intent_terms": result.get("matched_intent_terms") or [],
        "factors": result.get("factors") or [],
        "event_ids": ids,
        "event_count": len(ids),
        "case_id": case_id,
        "human_review_required": True,
    }


def _find_case_for_exposure(db: Session, *, tenant_id: int, finding_id: int) -> InvestigationCase | None:
    rows = db.scalars(
        select(InvestigationCase)
        .where(InvestigationCase.tenant_id == tenant_id)
        .order_by(InvestigationCase.id)
    )
    for case in rows:
        snapshot = case.finding_snapshot or {}
        if int(snapshot.get("exposure_finding_id") or 0) == finding_id:
            return case
    return None



_LINKABLE_CONTEXT_DECISIONS = {
    "monitored_target_mention",
    "claimed_access",
    "credential_market_activity",
}


def _link_context_events(
    *,
    context_events: list[CollectionEvent],
    result: dict[str, Any],
    finding: ExposureFinding,
    case: InvestigationCase | None,
) -> list[int]:
    """Attach bounded prior brand context to the same finding/case.

    Only already-analyzed events with the exact host-approved target reference
    are eligible.  Generic noise and cross-target events are never linked.
    """
    if str(result.get("correlation_family") or "") != "credential_exposure":
        return []
    target_ref = str((result.get("matched_target") or {}).get("ref") or "")
    if not target_ref:
        return []
    linked: list[int] = []
    for row in context_events:
        analysis_json = dict(row.analysis_json or {})
        decision = str(analysis_json.get("decision") or "")
        row_target = analysis_json.get("matched_target")
        row_target_ref = (
            str(row_target.get("ref") or "")
            if isinstance(row_target, dict)
            else ""
        )
        if decision not in _LINKABLE_CONTEXT_DECISIONS or row_target_ref != target_ref:
            continue
        if row.finding_id not in (None, finding.id):
            continue
        if case is not None and row.case_id not in (None, case.id):
            continue
        row.finding_id = finding.id
        row.case_id = case.id if case else None
        promotion = dict(analysis_json.get("promotion") or {})
        promotion.update(
            {
                "finding_id": finding.id,
                "case_id": case.id if case else None,
                "finding_created": False,
                "case_created": False,
                "linked_from_context": True,
            }
        )
        analysis_json["promotion"] = promotion
        row.analysis_json = analysis_json
        linked.append(row.id)
    return linked


def _promote(
    db: Session,
    *,
    event: CollectionEvent,
    result: dict[str, Any],
    context_events: list[CollectionEvent] | None = None,
) -> tuple[ExposureFinding | None, InvestigationCase | None, bool, bool]:
    promotion = result.get("promotion") or {}
    if not promotion.get("create_finding"):
        return None, None, False, False

    target = result.get("matched_target") or {}
    dkey = _dedup_key(event, result)
    finding = db.scalar(
        select(ExposureFinding).where(
            ExposureFinding.tenant_id == event.tenant_id,
            ExposureFinding.dedup_key == dkey,
        )
    )
    finding_created = finding is None
    now = utcnow()
    if finding is None:
        label = str(target.get("label") or "monitored target")[:180]
        finding = ExposureFinding(
            tenant_id=event.tenant_id,
            exposure_type=_exposure_type(target, result),
            asset_id=target.get("asset_id"),
            title=_finding_title(result, label),
            source=f"{event.provider}_intelligence"[:60],
            source_reliability="B",
            info_credibility="2",
            severity=str(result.get("severity") or "medium"),
            status="new",
            observed_at=event.occurred_at or event.created_at,
            first_seen=now,
            last_seen=now,
            dedup_key=dkey,
            detail={},
            redacted=True,
            risk_score=int(result.get("score") or 0),
            parser_version=ANALYSIS_VERSION[:20],
        )
        db.add(finding)
        db.flush()
    else:
        finding.last_seen = now
        finding.risk_score = max(finding.risk_score or 0, int(result.get("score") or 0))
        if finding.status == "duplicate":
            finding.status = "new"

    previous_detail = dict(finding.detail or {})
    previous_ids = list(previous_detail.get("event_ids") or [])
    finding.detail = _finding_detail(
        event,
        result,
        event_ids=previous_ids,
        previous_detail=previous_detail,
    )

    case = _find_case_for_exposure(
        db, tenant_id=event.tenant_id, finding_id=finding.id
    )
    case_created = False
    if promotion.get("create_case") and case is None:
        label = str(target.get("label") or "monitored target")[:180]
        snapshot = {
            "exposure_finding_id": finding.id,
            "exposure_type": finding.exposure_type,
            "source": finding.source,
            "dedup_key": finding.dedup_key,
            "intelligence": {
                "analysis_version": ANALYSIS_VERSION,
                "decision": result.get("decision"),
                "confidence_score": result.get("score"),
                "threat_category": result.get("threat_category"),
                "correlation_family": result.get("correlation_family"),
                "target_ref": target.get("ref"),
                "target_label": target.get("label"),
            },
        }
        case = InvestigationCase(
            tenant_id=event.tenant_id,
            brand_id=target.get("brand_id"),
            finding_snapshot=snapshot,
            title=_case_title(result, label),
            description=(
                "Automatically opened from authorized inbound intelligence.\n"
                f"Provider: {event.provider}\n"
                f"Target: {label}\n"
                f"Decision: {result.get('decision')}\n"
                f"Confidence: {result.get('score')}/100\n"
                f"Threat category: {result.get('threat_category')}\n"
                f"Correlation family: {result.get('correlation_family')}\n"
                f"Evidence event: #{event.id}\n"
                "Human review is required before escalation or response."
            ),
            severity=_CASE_SEVERITY.get(str(result.get("severity")), "medio"),
            status="open",
            created_by_user_id=None,
            assignee_user_id=None,
        )
        db.add(case)
        db.flush()
        case_created = True

    linked_context_ids = _link_context_events(
        context_events=context_events or [],
        result=result,
        finding=finding,
        case=case,
    )
    previous_detail = dict(finding.detail or {})
    existing_ids = list(previous_detail.get("event_ids") or [])
    finding.detail = _finding_detail(
        event,
        result,
        event_ids=[*existing_ids, *linked_context_ids],
        case_id=case.id if case else None,
        previous_detail=previous_detail,
    )
    if case is not None:
        snapshot = dict(case.finding_snapshot or {})
        intel = dict(snapshot.get("intelligence") or {})
        intel["event_count"] = int((finding.detail or {}).get("event_count") or 0)
        intel["latest_decision"] = result.get("decision")
        snapshot["intelligence"] = intel
        case.finding_snapshot = snapshot
    result.setdefault("promotion", {})["context_linked_event_count"] = len(
        linked_context_ids
    )
    event.finding_id = finding.id
    event.case_id = case.id if case else None
    return finding, case, finding_created, case_created


def _record_audit(
    db: Session,
    *,
    event: CollectionEvent,
    result: dict[str, Any],
    finding: ExposureFinding | None,
    case: InvestigationCase | None,
    finding_created: bool,
    case_created: bool,
) -> None:
    detail = {
        "provider": event.provider,
        "decision": result.get("decision"),
        "score": result.get("score"),
        "severity": result.get("severity"),
        "finding_id": finding.id if finding else None,
        "case_id": case.id if case else None,
        "finding_created": finding_created,
        "case_created": case_created,
    }
    audit.record(
        db,
        actor="system:intelligence-worker",
        actor_role="service",
        tenant_id=event.tenant_id,
        action="intelligence.analysis_completed",
        target_type="collection_event",
        target_id=event.id,
        detail=detail
    )
    if finding_created and finding is not None:
        audit.record(
            db,
            actor="system:intelligence-worker",
            actor_role="service",
            tenant_id=event.tenant_id,
            action="intelligence.finding_created",
            target_type="exposure",
            target_id=finding.id,
            detail={"event_id": event.id, "case_id": case.id if case else None},
        )
    if case_created and case is not None:
        audit.record(
            db,
            actor="system:intelligence-worker",
            actor_role="service",
            tenant_id=event.tenant_id,
            action="intelligence.case_created",
            target_type="case",
            target_id=case.id,
            detail={"event_id": event.id, "finding_id": finding.id if finding else None},
        )


def analyze_event(
    db: Session,
    *,
    event: CollectionEvent,
    source: CollectionSource,
    policy: AnalysisPolicy,
    worker_name: str = WORKER_NAME,
    already_acquired: bool = False,
) -> AnalysisOutcome:
    classifier = registry.classifiers.get(event.provider)
    correlator = registry.correlators.get(event.provider)
    if classifier is None or correlator is None:
        if already_acquired:
            db.rollback()
        return AnalysisOutcome(
            event.id,
            "skipped",
            error_code="analysis_extension_unavailable",
        )

    if not already_acquired:
        analysis.acquire(db, event=event, worker=worker_name)
    elif event.processing_state != "analyzing" or event.locked_by != worker_name:
        raise analysis.LockHeld("event is not held by this analysis worker")
    try:
        context_events = recent_context_events(
            db, event=event, policy=policy
        )
        envelope = build_envelope(
            db,
            event=event,
            source=source,
            policy=policy,
            context_events=context_events,
        )
        classified = classifier.classify(envelope)
        correlated = correlator.correlate(
            {
                "schema": "threatforge.intelligence.correlation.v1",
                "analysis": classified,
                "policy": envelope["policy"],
            }
        )
        result = _bind_approved_target(_safe_result(correlated), envelope)
        finding, case, finding_created, case_created = _promote(
            db,
            event=event,
            result=result,
            context_events=context_events,
        )
        result["promotion"].update(
            {
                "finding_id": finding.id if finding else None,
                "case_id": case.id if case else None,
                "finding_created": finding_created,
                "case_created": case_created,
            }
        )
        analysis.complete(
            db,
            event=event,
            worker=worker_name,
            analysis_version=ANALYSIS_VERSION,
            analysis=result,
        )
        db.commit()
        _record_audit(
            db,
            event=event,
            result=result,
            finding=finding,
            case=case,
            finding_created=finding_created,
            case_created=case_created,
        )
        return AnalysisOutcome(
            event.id,
            "analyzed",
            score=int(result.get("score") or 0),
            decision=str(result.get("decision") or ""),
            finding_id=finding.id if finding else None,
            case_id=case.id if case else None,
        )
    except Exception as exc:
        LOG.warning(
            "intelligence analysis failed event_id=%s error_type=%s",
            event.id,
            type(exc).__name__,
        )
        db.rollback()
        return AnalysisOutcome(
            event.id,
            "failed",
            error_code="analysis_processing_error",
        )


def run_analysis_once(
    db: Session,
    *,
    policy: AnalysisPolicy | None = None,
    worker_name: str = WORKER_NAME,
) -> list[AnalysisOutcome]:
    if not features.is_enabled(features.Feature.ANALYSIS_TELEGRAM):
        return []
    policy = policy or policy_from_env()
    tenant_ids = list(
        db.scalars(
            select(CollectionEvent.tenant_id)
            .where(
                CollectionEvent.processing_state.in_(
                    ("normalized", "failed", "analyzing")
                ),
                CollectionEvent.purged_at.is_(None),
                CollectionEvent.is_control.is_(False),
            )
            .distinct()
            .order_by(CollectionEvent.tenant_id)
        )
    )
    outcomes: list[AnalysisOutcome] = []
    remaining = policy.batch_size
    while remaining > 0:
        progressed = False
        for tenant_id in tenant_ids:
            if remaining <= 0:
                break
            event = analysis.acquire_next(
                db,
                tenant_id=int(tenant_id),
                worker=worker_name,
            )
            if event is None:
                continue
            source = db.get(CollectionSource, event.source_id)
            if source is None or source.tenant_id != event.tenant_id:
                db.rollback()
                outcomes.append(
                    AnalysisOutcome(
                        event.id,
                        "failed",
                        error_code="source_unavailable",
                    )
                )
                continue
            outcomes.append(
                analyze_event(
                    db,
                    event=event,
                    source=source,
                    policy=policy,
                    worker_name=worker_name,
                    already_acquired=True,
                )
            )
            remaining -= 1
            progressed = True
        if not progressed:
            break
    return outcomes
