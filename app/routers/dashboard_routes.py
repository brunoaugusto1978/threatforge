"""Operational Dashboard Overview (v0.11.0) — tenant-scoped, viewer+.

Replaces the old "just /stats" Overview with a single aggregation endpoint
that gives an operator a real, at-a-glance read of CTI/DRP/Exposure Monitoring
state: IOCs, brands/brand findings, investigation cases, exposure findings,
monitored assets, credential identities and integration connection status.

Design constraints (unchanged from the rest of the Community codebase):
  - No new migration: every value is derived with plain SELECT/COUNT/GROUP BY
    over existing tables (``app/models.py``). Nothing new is persisted.
  - No mock/fictitious data: every number comes from a real query scoped to
    the caller's tenant (``current_tenant_id``); there is no fallback/sample
    payload when a tenant has zero rows — the counters are just 0.
  - RBAC: viewer+ (read-only), same as ``GET /stats``. No audit log entry is
    written — this mirrors ``/stats`` (a read-only, frequently-polled
    aggregate) rather than the audited write endpoints.
  - Tenant isolation: every query is filtered by ``tenant_id == tid``; nothing
    here ever crosses tenants (an operator still resolves ``tid`` through the
    same ``current_tenant_id`` dependency used everywhere else).
  - Never exposes secrets/tokens/api_key/hashed_password/config_json/
    secrets_metadata. Integration status is reduced to
    ``{name, title, premium, license_enabled, connected, connection_enabled}``
    — the stored ``config_json``/``secrets_metadata`` columns are never read
    into the response, only whether a row exists and its ``enabled`` flag.
  - "Top exposed assets" never returns ``MonitoredAsset.value`` (can hold PII
    such as an e-mail/identity) — only the operator-assigned ``label``,
    ``asset_type`` and ``criticality``, plus the aggregated finding count/risk.
  - Integration connection rows are read with a column-scoped SELECT
    (``IntegrationConnection.name``, ``.enabled`` only) — ``config_json`` and
    ``secrets_metadata`` are never fetched from the database into this
    process at all, not just excluded from the response.
  - ``ExposureFinding.title`` can carry an e-mail address (some
    identity_exposure/credential_exposure records are titled
    ``"Credential exposure <email>"`` at ingestion time — see
    ``app/exposure_ingest.py``). ``recent_exposure_findings`` runs titles
    through the same PII masking used everywhere else in Exposure Monitoring
    (``app.exposure_ingest.mask_value`` + ``config.EXPOSURE_PII_MASKING`` +
    the caller's effective role) instead of returning the raw string.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config, exposure_ingest as ing, features, integrations, risk
from app.auth import Principal, current_tenant_id, require_viewer
from app.database import get_db
from app.models import (Brand, BrandFinding, CollectionConnection,
                        CollectionEvent, CollectionSource, CredentialIdentity,
                        ExposureFinding, ExposureIngestBatch, IntegrationConnection,
                        InvestigationCase, MonitoredAsset, Observable, utcnow)

router = APIRouter(prefix="/dashboard", tags=["dashboard"],
                   dependencies=[Depends(require_viewer)])

# Matches the same shape used to detect/mask e-mails elsewhere in Exposure
# Monitoring (app/schemas.py's observable "email" pattern, relaxed for
# embedded matches inside a larger title string rather than a whole-value
# match).
_EMAIL_IN_TEXT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}")

# Fixed vocabularies mirrored from the CheckConstraints in app/models.py — kept
# local (not imported from other routers) so this module has no coupling to
# other routers' internals, only to the shared model layer.
CASE_SEVERITIES = ("baixo", "medio", "alto", "critico")
CASE_STATUSES = ("open", "triage", "investigating", "contained", "closed", "false_positive")
CASE_ACTIVE_STATUSES = {"open", "triage", "investigating", "contained"}

EXPOSURE_SEVERITIES = ("low", "medium", "high", "critical")
EXPOSURE_STATUSES = ("new", "triaging", "confirmed", "mitigated", "closed",
                    "false_positive", "duplicate")
EXPOSURE_OPEN_STATUSES = {"new", "triaging", "confirmed"}

BRAND_FINDING_PRIORITY_VERDICTS = {"malicious", "suspicious"}

_COLLECTION_HEALTH_STATES = {"healthy", "degraded", "unauthorized", "offline", "pending"}
_COLLECTION_STATE_PRIORITY = ("unauthorized", "offline", "degraded", "pending", "healthy")
_COLLECTION_STALE_AFTER_SECONDS = 120


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _latest_iso(values: list[str | None]) -> str | None:
    parsed = [(_parse_iso(value), value) for value in values]
    valid = [(dt, value) for dt, value in parsed if dt is not None]
    if not valid:
        return None
    return str(max(valid, key=lambda item: item[0])[1])


def _telegram_collection_status(db: Session, tid: int) -> dict:
    """Return a reduced, tenant-scoped Telegram Intelligence dashboard row.

    Only operational columns and ``config_json._health`` are consumed. Opaque
    secret references and secret metadata are not selected from the database.
    """
    rows = db.execute(
        select(
            CollectionConnection.id,
            CollectionConnection.enabled,
            CollectionConnection.status,
            CollectionConnection.provider_account_ref,
            CollectionConnection.cursor,
            CollectionConnection.config_json,
        ).where(
            CollectionConnection.tenant_id == tid,
            CollectionConnection.provider == "telegram",
            CollectionConnection.deleted_at.is_(None),
        )
    ).all()

    source_total = db.scalar(
        select(func.count()).select_from(CollectionSource).where(
            CollectionSource.tenant_id == tid,
            CollectionSource.provider == "telegram",
            CollectionSource.deleted_at.is_(None),
        )
    ) or 0
    source_active = db.scalar(
        select(func.count()).select_from(CollectionSource).where(
            CollectionSource.tenant_id == tid,
            CollectionSource.provider == "telegram",
            CollectionSource.deleted_at.is_(None),
            CollectionSource.enabled == True,  # noqa: E712
        )
    ) or 0
    event_total = db.scalar(
        select(func.count()).select_from(CollectionEvent).where(
            CollectionEvent.tenant_id == tid,
            CollectionEvent.provider == "telegram",
        )
    ) or 0

    enabled_rows = [row for row in rows if bool(row.enabled)]
    verified = any(bool(row.provider_account_ref) for row in rows)
    health_rows: list[dict] = []
    for row in enabled_rows:
        config_json = row.config_json if isinstance(row.config_json, dict) else {}
        health = config_json.get("_health")
        health_rows.append(dict(health) if isinstance(health, dict) else {"state": "pending"})

    if not rows:
        collector_state = "not_configured"
    elif not enabled_rows:
        collector_state = "paused"
    else:
        states: list[str] = []
        now = utcnow()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        for health in health_rows:
            state = str(health.get("state") or "pending")
            if state not in _COLLECTION_HEALTH_STATES:
                state = "degraded"
            checked_at = _parse_iso(health.get("checked_at"))
            if checked_at is None:
                state = "pending"
            elif (now - checked_at).total_seconds() > _COLLECTION_STALE_AFTER_SECONDS:
                state = "offline"
            states.append(state)
        collector_state = next(
            (state for state in _COLLECTION_STATE_PRIORITY if state in states),
            "pending",
        )

    return {
        "name": "telegram-intelligence",
        "title": "Telegram Intelligence",
        "premium": True,
        "license_enabled": features.is_enabled(features.Feature.COLLECTION_TELEGRAM),
        "connected": verified,
        "connection_enabled": bool(enabled_rows),
        "surface": "collection",
        "connection_count": len(rows),
        "enabled_connection_count": len(enabled_rows),
        "source_count": int(source_total),
        "active_source_count": int(source_active),
        "event_count": int(event_total),
        "collector_state": collector_state,
        "last_success_at": _latest_iso([h.get("last_success_at") for h in health_rows]),
        "last_event_at": _latest_iso([h.get("last_event_at") for h in health_rows]),
    }


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _count(db: Session, model, tid: int, *extra) -> int:
    stmt = select(func.count()).select_from(model).where(model.tenant_id == tid, *extra)
    return db.scalar(stmt) or 0


def _distribution(db: Session, model, column, tid: int, buckets: tuple[str, ...]) -> dict[str, int]:
    """GROUP BY count for one column, pre-seeded with every known bucket at 0
    so the UI always gets a stable shape (no missing keys for zero-count
    values) — real values only, never fabricated totals.
    """
    out = {b: 0 for b in buckets}
    rows = db.execute(
        select(column, func.count()).where(model.tenant_id == tid).group_by(column)
    ).all()
    for value, n in rows:
        key = value if value is not None else "unknown"
        out[key] = out.get(key, 0) + int(n)
    return out


def _safe_title(title: str | None, role: str, policy: str) -> str | None:
    """Mask any e-mail address embedded in a free-text title.

    ``ExposureFinding.title`` is not itself PII/PUBLIC-classified the way
    ``detail`` fields are (see ``app.exposure_ingest.classify``) — it's a
    human-readable string that some ingestion paths build as e.g.
    ``f"Credential exposure {email}"``. Rather than dropping the title
    entirely (which would make the "recent findings" list useless — an
    operator needs *some* label), every embedded e-mail match is masked
    through the exact same ``mask_value``/``EXPOSURE_PII_MASKING`` policy
    used for `detail` elsewhere, so behaviour stays consistent with the rest
    of Exposure Monitoring: masked only when the tenant has opted into
    ``by_role`` masking and the caller isn't admin.
    """
    if not title:
        return title
    return _EMAIL_IN_TEXT_RE.sub(
        lambda m: ing.mask_value(m.group(0), ing.PII, role, policy), title)


@router.get("/overview")
def dashboard_overview(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_viewer),
    tid: int = Depends(current_tenant_id),
    recent_limit: int = Query(5, ge=1, le=20),
    top_assets_limit: int = Query(5, ge=1, le=20),
):
    """Real-data operational overview for the tenant (viewer+).

    Every field below is computed live from this tenant's rows — nothing is
    mocked or backfilled with sample data.
    """
    # ---------------- summary counters ----------------
    iocs_total = _count(db, Observable, tid)
    iocs_malicious = _count(db, Observable, tid, Observable.verdict == "malicious")

    brands_total = _count(db, Brand, tid)
    brands_active = _count(db, Brand, tid, Brand.status == "active")

    brand_findings_total = _count(db, BrandFinding, tid)
    brand_findings_priority = _count(
        db, BrandFinding, tid, BrandFinding.verdict.in_(tuple(BRAND_FINDING_PRIORITY_VERDICTS)))

    cases_total = _count(db, InvestigationCase, tid)
    cases_open = _count(db, InvestigationCase, tid,
                       InvestigationCase.status.in_(tuple(CASE_ACTIVE_STATUSES)))

    exposure_total = _count(db, ExposureFinding, tid)
    exposure_open = _count(db, ExposureFinding, tid,
                          ExposureFinding.status.in_(tuple(EXPOSURE_OPEN_STATUSES)))
    exposure_ingests_total = _count(db, ExposureIngestBatch, tid)

    assets_total = _count(db, MonitoredAsset, tid)
    assets_active = _count(db, MonitoredAsset, tid, MonitoredAsset.active == True)  # noqa: E712

    identities_total = _count(db, CredentialIdentity, tid)
    identities_active = _count(
        db, CredentialIdentity, tid, CredentialIdentity.status.in_(("new", "reviewing")))
    # "high risk" reuses the same band_of() thresholds as the exposure finding
    # risk score — no new/ad-hoc cutoff invented for the dashboard.
    identities_high_risk = _count(
        db, CredentialIdentity, tid, CredentialIdentity.max_risk >= 70)

    descriptors = integrations.list_descriptors()
    # Column-scoped SELECT: only `name`/`enabled` ever leave the database for
    # this request. `config_json`/`secrets_metadata` are not fetched at all —
    # not just excluded from the response — so there is no code path here
    # that could accidentally leak them later (e.g. a future `.model_dump()`
    # on the ORM row).
    connected_rows = {
        name: enabled
        for name, enabled in db.execute(
            select(IntegrationConnection.name, IntegrationConnection.enabled)
            .where(IntegrationConnection.tenant_id == tid)
        ).all()
    }
    telegram_status = _telegram_collection_status(db, tid)
    integrations_connected = (
        sum(1 for d in descriptors if d.name in connected_rows)
        + (1 if telegram_status["connected"] else 0)
    )

    summary = {
        "iocs_total": iocs_total,
        "iocs_malicious": iocs_malicious,
        "brands_total": brands_total,
        "brands_active": brands_active,
        "brand_findings_total": brand_findings_total,
        "brand_findings_priority": brand_findings_priority,
        "cases_total": cases_total,
        "cases_open": cases_open,
        "exposure_findings_total": exposure_total,
        "exposure_findings_open": exposure_open,
        "exposure_ingests_total": exposure_ingests_total,
        "monitored_assets_total": assets_total,
        "monitored_assets_active": assets_active,
        "credential_identities_total": identities_total,
        "credential_identities_active": identities_active,
        "credential_identities_high_risk": identities_high_risk,
        "integrations_catalog_total": len(descriptors) + 1,
        "integrations_connected": integrations_connected,
        "telegram_connections_total": telegram_status["connection_count"],
        "telegram_connections_enabled": telegram_status["enabled_connection_count"],
        "telegram_sources_total": telegram_status["source_count"],
        "telegram_sources_active": telegram_status["active_source_count"],
        "telegram_events_total": telegram_status["event_count"],
    }

    # ---------------- distributions ----------------
    cases_by_severity = _distribution(db, InvestigationCase, InvestigationCase.severity, tid, CASE_SEVERITIES)
    cases_by_status = _distribution(db, InvestigationCase, InvestigationCase.status, tid, CASE_STATUSES)
    exposure_by_severity = _distribution(db, ExposureFinding, ExposureFinding.severity, tid, EXPOSURE_SEVERITIES)
    exposure_by_status = _distribution(db, ExposureFinding, ExposureFinding.status, tid, EXPOSURE_STATUSES)

    # ---------------- recent cases ----------------
    recent_cases = []
    case_rows = db.scalars(
        select(InvestigationCase).where(InvestigationCase.tenant_id == tid)
        .order_by(InvestigationCase.created_at.desc(), InvestigationCase.id.desc())
        .limit(recent_limit)
    )
    for c in case_rows:
        recent_cases.append({
            "id": c.id,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "brand_id": c.brand_id,
            "assignee_user_id": c.assignee_user_id,
            "created_at": _iso(c.created_at),
        })

    # ---------------- recent exposure findings ----------------
    role = principal.effective_role()
    policy = config.EXPOSURE_PII_MASKING
    recent_findings = []
    finding_rows = db.scalars(
        select(ExposureFinding).where(ExposureFinding.tenant_id == tid)
        .order_by(ExposureFinding.created_at.desc(), ExposureFinding.id.desc())
        .limit(recent_limit)
    )
    for f in finding_rows:
        recent_findings.append({
            "id": f.id,
            "exposure_type": f.exposure_type,
            "title": _safe_title(f.title, role, policy),
            "severity": f.severity,
            "status": f.status,
            "source": f.source,
            "risk_score": f.risk_score,
            "risk_band": risk.band_of(f.risk_score),
            "created_at": _iso(f.created_at),
        })

    # ---------------- recent imports (exposure ingest batches) ----------------
    recent_ingests = []
    ingest_rows = db.scalars(
        select(ExposureIngestBatch).where(ExposureIngestBatch.tenant_id == tid)
        .order_by(ExposureIngestBatch.created_at.desc(), ExposureIngestBatch.id.desc())
        .limit(recent_limit)
    )
    for b in ingest_rows:
        recent_ingests.append({
            "id": b.id,
            "source": b.source,
            "parser": b.parser,
            "original_filename": b.original_filename,
            "record_count": b.record_count,
            "created_count": b.created_count,
            "deduped_count": b.deduped_count,
            "error_count": b.error_count,
            "status": b.status,
            "created_at": _iso(b.created_at),
        })

    # ---------------- top exposed assets ----------------
    # Ranked by how many exposure findings point at the asset, then by the
    # highest risk score among those findings. Only assets with >=1 linked
    # finding are "exposed" — an asset with zero findings has nothing to show.
    top_rows = db.execute(
        select(
            MonitoredAsset.id, MonitoredAsset.label, MonitoredAsset.asset_type,
            MonitoredAsset.criticality, MonitoredAsset.active,
            func.count(ExposureFinding.id).label("finding_count"),
            func.max(ExposureFinding.risk_score).label("max_risk"),
        )
        .join(ExposureFinding, ExposureFinding.asset_id == MonitoredAsset.id)
        .where(MonitoredAsset.tenant_id == tid, ExposureFinding.tenant_id == tid)
        .group_by(MonitoredAsset.id, MonitoredAsset.label, MonitoredAsset.asset_type,
                 MonitoredAsset.criticality, MonitoredAsset.active)
        .order_by(func.count(ExposureFinding.id).desc(), func.max(ExposureFinding.risk_score).desc())
        .limit(top_assets_limit)
    ).all()
    top_exposed_assets = [{
        "id": row.id,
        "label": row.label,
        "asset_type": row.asset_type,
        "criticality": row.criticality,
        "active": bool(row.active),
        "finding_count": int(row.finding_count),
        "max_risk_score": int(row.max_risk or 0),
        "max_risk_band": risk.band_of(int(row.max_risk or 0)),
    } for row in top_rows]

    # ---------------- integrations status (simple) ----------------
    # Never reads config_json/secrets_metadata — connected_rows above was
    # already fetched with a column-scoped SELECT (name/enabled only).
    integrations_status = []
    for d in descriptors:
        enabled_flag = connected_rows.get(d.name)
        integrations_status.append({
            "name": d.name,
            "title": d.title,
            "premium": d.premium,
            "license_enabled": features.is_enabled(d.feature),
            "connected": d.name in connected_rows,
            "connection_enabled": bool(enabled_flag) if enabled_flag is not None else False,
            "surface": "integration",
            "connection_count": 1 if d.name in connected_rows else 0,
            "enabled_connection_count": 1 if bool(enabled_flag) else 0,
            "source_count": None,
            "active_source_count": None,
            "event_count": None,
            "collector_state": "not_applicable",
            "last_success_at": None,
            "last_event_at": None,
        })
    integrations_status.append(telegram_status)

    return {
        "generated_at": _iso(utcnow()),
        "tenant_id": tid,
        "summary": summary,
        "cases_by_severity": cases_by_severity,
        "cases_by_status": cases_by_status,
        "exposure_by_severity": exposure_by_severity,
        "exposure_by_status": exposure_by_status,
        "recent_cases": recent_cases,
        "recent_exposure_findings": recent_findings,
        "recent_ingests": recent_ingests,
        "top_exposed_assets": top_exposed_assets,
        "integrations": integrations_status,
    }
