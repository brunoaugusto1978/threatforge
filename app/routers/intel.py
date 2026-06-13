from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.auth import require_analyst, require_viewer
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.mitre_attack import MitreAttackConnector
from app.database import get_db
from app.models import AttackTechnique, KEVEntry, SyncState
from app.schemas import SyncResult

router = APIRouter(tags=["intel"], dependencies=[Depends(require_viewer)])


def _record_sync(db: Session, source: str, items: int) -> None:
    from app.models import utcnow

    state = db.get(SyncState, source) or SyncState(source=source)
    state.last_sync_at = utcnow()
    state.items = items
    db.merge(state)
    db.commit()


@router.post("/sync/kev", response_model=SyncResult, dependencies=[Depends(require_analyst)])
def sync_kev(db: Session = Depends(get_db)):
    try:
        items = CisaKevConnector().sync(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Falha ao sincronizar KEV: {type(exc).__name__}")
    _record_sync(db, "cisa_kev", items)
    return SyncResult(source="cisa_kev", items=items, status="ok")


@router.post("/sync/mitre", response_model=SyncResult, dependencies=[Depends(require_analyst)])
def sync_mitre(db: Session = Depends(get_db)):
    try:
        items = MitreAttackConnector().sync(db)
    except Exception as exc:
        raise HTTPException(
            status_code=502, detail=f"Falha ao sincronizar ATT&CK: {type(exc).__name__}"
        )
    _record_sync(db, "mitre_attack", items)
    return SyncResult(source="mitre_attack", items=items, status="ok")


@router.get("/intel/kev/{cve_id}")
def get_kev(cve_id: str, db: Session = Depends(get_db)):
    entry = db.get(KEVEntry, cve_id.upper())
    if entry is None:
        raise HTTPException(status_code=404, detail="CVE is not listed in the local KEV dataset. Run /sync/kev.")
    return {
        "cve_id": entry.cve_id,
        "vendor": entry.vendor,
        "product": entry.product,
        "name": entry.name,
        "description": entry.description,
        "date_added": entry.date_added,
        "due_date": entry.due_date,
        "known_ransomware": entry.known_ransomware,
    }


@router.get("/intel/attack/{technique_id}")
def get_technique(technique_id: str, db: Session = Depends(get_db)):
    tech = db.get(AttackTechnique, technique_id.upper())
    if tech is None:
        raise HTTPException(
            status_code=404, detail="Technique not found. Run /sync/mitre."
        )
    return {
        "technique_id": tech.technique_id,
        "name": tech.name,
        "tactics": (tech.tactics or "").split(",") if tech.tactics else [],
        "description": tech.description,
        "url": tech.url,
    }


@router.get("/intel/attack")
def search_techniques(q: str, limit: int = 20, db: Session = Depends(get_db)):
    if len(q) < 2:
        raise HTTPException(status_code=422, detail="Busca exige ao menos 2 caracteres.")
    pattern = f"%{q.lower()}%"
    stmt = (
        select(AttackTechnique)
        .where(
            or_(
                func.lower(AttackTechnique.name).like(pattern),
                func.lower(AttackTechnique.technique_id).like(pattern),
            )
        )
        .limit(min(limit, 100))
    )
    return [
        {"technique_id": t.technique_id, "name": t.name, "tactics": t.tactics, "url": t.url}
        for t in db.scalars(stmt)
    ]


@router.get("/sync/status")
def sync_status(db: Session = Depends(get_db)):
    return [
        {"source": s.source, "last_sync_at": s.last_sync_at, "items": s.items}
        for s in db.scalars(select(SyncState))
    ]
