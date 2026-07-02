"""Timeline — aggregation over pluggable event sources (read-only, no new table).

Each TimelineSource normalizes its own domain data into a common event shape.
Community sources: exposure, cases, audit. Enterprise can register more sources
(feeds/monitors) via register_source without touching this module. A future
append-only `timeline_event` table can back the same interface for realtime.
"""
from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from sqlalchemy import select

from app.models import (AuditLog, ExposureFinding, ExposureIngestBatch,
                        InvestigationCase)

# scope = (kind, id): ("tenant", None) | ("case", <id>) | ("finding", <id>)


def _ev(ts, source, type_, title, actor, severity, icon, ref_kind, ref_id) -> dict:
    return {"ts": ts, "source": source, "type": type_, "title": title,
            "actor": actor or "system", "severity": severity, "icon": icon,
            "ref": {"kind": ref_kind, "id": ref_id}}


_ACTION_LABEL = {
    "exposure.intake": "Exposure intake", "exposure.import": "Exposure import",
    "exposure.import_rollback": "Import rolled back",
    "exposure.finding_triage": "Finding triaged", "exposure.case_opened": "Case opened from finding",
    "exposure.asset_create": "Monitored asset created", "exposure.asset_update": "Asset updated",
    "exposure.asset_delete": "Asset deleted",
    "case.create": "Case created", "case.status_change": "Case status changed",
    "case.close": "Case closed", "case.reopen": "Case reopened", "case.assign": "Case assigned",
    "case.note_added": "Note added", "evidence.add": "Evidence attached",
    "evidence.download": "Evidence downloaded",
}


def _humanize(action: str) -> str:
    return _ACTION_LABEL.get(action, action.replace(".", " ").replace("_", " "))


@runtime_checkable
class TimelineSource(Protocol):
    name: str

    def events(self, db, tid: int, scope) -> Iterable[dict]: ...


class ExposureTimelineSource:
    name = "exposure"

    def events(self, db, tid, scope):
        kind, sid = scope
        out = []
        if kind == "finding":
            f = db.get(ExposureFinding, sid)
            if f and f.tenant_id == tid:
                out.append(_ev(f.created_at, self.name, "exposure.finding_created",
                               f.title, "system", f.severity, "key", "exposure_finding", f.id))
                sightings = int((f.detail or {}).get("sightings", 1))
                if f.last_seen and f.created_at and f.last_seen > f.created_at:
                    out.append(_ev(f.last_seen, self.name, "exposure.finding_seen",
                                   f"Seen again ({sightings}x)", "system", f.severity,
                                   "eye", "exposure_finding", f.id))
        elif kind == "tenant":
            for f in db.scalars(select(ExposureFinding).where(ExposureFinding.tenant_id == tid)
                                .order_by(ExposureFinding.created_at.desc()).limit(100)):
                out.append(_ev(f.created_at, self.name, "exposure.finding_created",
                               f.title, "system", f.severity, "key", "exposure_finding", f.id))
            for b in db.scalars(select(ExposureIngestBatch).where(ExposureIngestBatch.tenant_id == tid)
                                .order_by(ExposureIngestBatch.created_at.desc()).limit(50)):
                out.append(_ev(b.created_at, self.name, "exposure.import",
                               f"Import #{b.id}: {b.created_count} created, {b.deduped_count} deduped",
                               "system", None, "list", "exposure_ingest", b.id))
        return out


class CaseTimelineSource:
    name = "case"

    def events(self, db, tid, scope):
        kind, sid = scope
        cases = []
        if kind == "case":
            c = db.get(InvestigationCase, sid)
            if c and c.tenant_id == tid:
                cases = [c]
        elif kind == "tenant":
            cases = list(db.scalars(select(InvestigationCase).where(InvestigationCase.tenant_id == tid)
                                    .order_by(InvestigationCase.created_at.desc()).limit(100)))
        out = []
        for c in cases:
            out.append(_ev(c.created_at, self.name, "case.created",
                           f"Case #{c.id}: {c.title}", None, c.severity, "folder", "case", c.id))
            if c.closed_at:
                out.append(_ev(c.closed_at, self.name, "case.closed",
                               f"Case #{c.id} closed", None, c.severity, "folder", "case", c.id))
        return out


class AuditTimelineSource:
    name = "audit"

    def events(self, db, tid, scope):
        kind, sid = scope
        stmt = select(AuditLog).where(AuditLog.tenant_id == tid)
        if kind == "finding":
            stmt = stmt.where(AuditLog.target_type == "exposure", AuditLog.target_id == str(sid))
        elif kind == "case":
            stmt = stmt.where(AuditLog.target_type == "case", AuditLog.target_id == str(sid))
        limit = 100 if kind == "tenant" else 200
        rows = db.scalars(stmt.order_by(AuditLog.ts.desc()).limit(limit))
        out = []
        for a in rows:
            actor = a.actor if not a.operator_user_id else f"{a.actor} (operator)"
            out.append(_ev(a.ts, self.name, a.action, _humanize(a.action), actor,
                           None, "list", (a.target_type or "audit"), a.target_id))
        return out


_SOURCES: list[TimelineSource] = []


def register_source(source: TimelineSource) -> None:
    _SOURCES.append(source)


def sources() -> list[str]:
    return [s.name for s in _SOURCES]


def _sortkey(e) -> float:
    ts = e.get("ts")
    if ts is None:
        return float("-inf")
    try:
        return ts.timestamp()  # robusto a naive/aware (SQLite x Postgres)
    except Exception:
        return float("-inf")


def collect(db, tid: int, scope, limit: int = 100) -> list[dict]:
    events: list[dict] = []
    for s in _SOURCES:
        try:
            events.extend(s.events(db, tid, scope))
        except Exception:  # uma fonte não pode derrubar a timeline inteira
            continue
    events.sort(key=_sortkey, reverse=True)
    return events[:limit]


# built-in Community sources
register_source(ExposureTimelineSource())
register_source(CaseTimelineSource())
register_source(AuditTimelineSource())
