"""Safe, tenant-scoped intelligence correlation summaries for cases.

This module deliberately selects only linkage and operational metadata from
``collection_event`` and ``exposure_finding``. It never reads message text,
provider payloads, actor identifiers, chat identifiers or secret material.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CollectionEvent, ExposureFinding, InvestigationCase, Tenant


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _event_time(occurred_at: datetime | None, created_at: datetime | None) -> datetime | None:
    return occurred_at or created_at


def _exposure_finding_id(case: InvestigationCase) -> int | None:
    snapshot = case.finding_snapshot if isinstance(case.finding_snapshot, dict) else {}
    value = snapshot.get("exposure_finding_id")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def case_intelligence_summaries(
    db: Session,
    *,
    tenant_id: int,
    cases: Iterable[InvestigationCase],
    include_event_ids: bool = False,
) -> dict[int, dict | None]:
    """Return safe correlation metadata keyed by case id.

    All queries are constrained by ``tenant_id``. The event query is
    column-scoped and intentionally excludes ``redacted_text``, ``context_json``
    and provider identifiers. ``event_ids`` are returned only for a single-case
    detail response; list/dashboard responses receive aggregate metadata only.
    """
    case_rows = list(cases)
    case_ids = [case.id for case in case_rows]
    if not case_ids:
        return {}

    events_by_case: dict[int, list[dict]] = defaultdict(list)
    event_rows = db.execute(
        select(
            CollectionEvent.id,
            CollectionEvent.case_id,
            CollectionEvent.provider,
            CollectionEvent.occurred_at,
            CollectionEvent.created_at,
        ).where(
            CollectionEvent.tenant_id == tenant_id,
            CollectionEvent.case_id.in_(case_ids),
        ).order_by(CollectionEvent.case_id, CollectionEvent.id)
    ).all()
    for row in event_rows:
        if row.case_id is None:
            continue
        events_by_case[int(row.case_id)].append({
            "id": int(row.id),
            "provider": str(row.provider or ""),
            "activity_at": _event_time(row.occurred_at, row.created_at),
        })

    exposure_ids = {
        finding_id
        for finding_id in (_exposure_finding_id(case) for case in case_rows)
        if finding_id is not None
    }
    findings: dict[int, dict] = {}
    if exposure_ids:
        finding_rows = db.execute(
            select(
                ExposureFinding.id,
                ExposureFinding.source,
                ExposureFinding.exposure_type,
                ExposureFinding.detail,
            ).where(
                ExposureFinding.tenant_id == tenant_id,
                ExposureFinding.id.in_(exposure_ids),
            )
        ).all()
        findings = {
            int(row.id): {
                "source": str(row.source or ""),
                "exposure_type": str(row.exposure_type or ""),
                "detail": row.detail if isinstance(row.detail, dict) else {},
            }
            for row in finding_rows
        }

    output: dict[int, dict | None] = {}
    for case in case_rows:
        snapshot = case.finding_snapshot if isinstance(case.finding_snapshot, dict) else {}
        intel = snapshot.get("intelligence") if isinstance(snapshot.get("intelligence"), dict) else {}
        finding_id = _exposure_finding_id(case)
        finding = findings.get(finding_id or 0, {})
        detail = finding.get("detail") if isinstance(finding.get("detail"), dict) else {}
        linked_events = events_by_case.get(case.id, [])

        source = str(finding.get("source") or snapshot.get("source") or "")
        providers = sorted({str(item.get("provider") or "") for item in linked_events if item.get("provider")})
        if not source and len(providers) == 1:
            source = f"{providers[0]}_intelligence"

        is_intelligence_case = bool(
            linked_events
            or finding_id is not None
            or source.endswith("_intelligence")
            or intel
        )
        if not is_intelligence_case:
            output[case.id] = None
            continue

        activity_values = [item["activity_at"] for item in linked_events if item.get("activity_at") is not None]
        event_ids = [int(item["id"]) for item in linked_events]
        decision = str(
            intel.get("latest_decision")
            or intel.get("decision")
            or detail.get("decision")
            or ""
        )
        confidence = intel.get("confidence_score")
        if confidence in (None, ""):
            confidence = detail.get("confidence_score")
        try:
            confidence_score = int(confidence) if confidence not in (None, "") else None
        except (TypeError, ValueError):
            confidence_score = None

        summary = {
            "source": source or None,
            "finding_id": finding_id,
            "exposure_type": str(finding.get("exposure_type") or snapshot.get("exposure_type") or "") or None,
            "decision": decision or None,
            "confidence_score": confidence_score,
            "correlation_family": str(
                intel.get("correlation_family")
                or detail.get("correlation_family")
                or ""
            ) or None,
            "correlated_event_count": len(event_ids),
            "first_event_at": _iso(min(activity_values)) if activity_values else None,
            "last_activity_at": _iso(max(activity_values)) if activity_values else None,
            "human_review_required": bool(detail.get("human_review_required", True)),
        }
        if include_event_ids:
            summary["event_ids"] = event_ids
        output[case.id] = summary

    return output



def case_pdf_report_context(
    db: Session,
    *,
    tenant_id: int,
    case: InvestigationCase,
) -> dict:
    """Build a safe, tenant-scoped context for one case PDF report.

    The returned structure contains only operator-visible linkage metadata. It
    never returns provider message text, actor/chat identifiers, raw payloads,
    fingerprints, storage paths, secrets or license material.
    """
    tenant_name = db.scalar(
        select(Tenant.name).where(Tenant.id == tenant_id)
    ) or f"Tenant {tenant_id}"

    intelligence = case_intelligence_summaries(
        db,
        tenant_id=tenant_id,
        cases=[case],
        include_event_ids=True,
    ).get(case.id)

    finding_id = None
    if isinstance(intelligence, dict):
        finding_id = intelligence.get("finding_id")
    if finding_id is None:
        finding_id = _exposure_finding_id(case)

    finding: dict | None = None
    if finding_id is not None:
        row = db.execute(
            select(
                ExposureFinding.id,
                ExposureFinding.title,
                ExposureFinding.source,
                ExposureFinding.exposure_type,
                ExposureFinding.severity,
                ExposureFinding.status,
                ExposureFinding.risk_score,
                ExposureFinding.detail,
            ).where(
                ExposureFinding.tenant_id == tenant_id,
                ExposureFinding.id == finding_id,
            )
        ).one_or_none()
        if row is not None:
            detail = row.detail if isinstance(row.detail, dict) else {}
            finding = {
                "id": int(row.id),
                "title": str(row.title or ""),
                "source": str(row.source or ""),
                "exposure_type": str(row.exposure_type or ""),
                "severity": str(row.severity or ""),
                "status": str(row.status or ""),
                "risk_score": int(row.risk_score or 0),
                "target_label": str(detail.get("target_label") or ""),
            }

    return {
        "tenant_name": str(tenant_name),
        "intelligence": intelligence,
        "exposure_finding": finding,
    }
