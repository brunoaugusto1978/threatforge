"""Timeline API — aggregated, read-only, tenant-scoped.

GET /timeline?scope=tenant|case:{id}|finding:{id}  -> merged events (desc)
GET /timeline/sources                              -> registered source names
Cross-tenant referenced resource -> 404. Secrets never appear (upstream redaction).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import timeline
from app.auth import current_tenant_id, require_viewer
from app.database import get_db
from app.models import ExposureFinding, InvestigationCase

router = APIRouter(prefix="/timeline", tags=["timeline"],
                   dependencies=[Depends(require_viewer)])


def _parse_scope(scope: str, db: Session, tid: int):
    if not scope or scope == "tenant":
        return ("tenant", None)
    kind, sep, sid_raw = scope.partition(":")
    if not sep:
        raise HTTPException(status_code=422, detail="invalid scope.")
    try:
        sid = int(sid_raw)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid scope id.")
    if kind == "case":
        c = db.get(InvestigationCase, sid)
        if c is None or c.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Case not found.")
        return ("case", sid)
    if kind == "finding":
        f = db.get(ExposureFinding, sid)
        if f is None or f.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Exposure finding not found.")
        return ("finding", sid)
    raise HTTPException(status_code=422, detail="unknown scope kind.")


@router.get("")
def get_timeline(scope: str = Query("tenant"), limit: int = Query(100, ge=1, le=500),
                 db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    sc = _parse_scope(scope, db, tid)
    events = timeline.collect(db, tid, sc, limit)
    out = []
    for e in events:
        ts = e.get("ts")
        out.append({**e, "ts": ts.isoformat() if hasattr(ts, "isoformat") else ts})
    return out


@router.get("/sources")
def list_sources():
    return timeline.sources()
