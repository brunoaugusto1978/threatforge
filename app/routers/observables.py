from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.epss import EpssConnector
from app.connectors.urlhaus import UrlhausConnector
from app.database import get_db
from app.models import Enrichment, Observable
from app.schemas import ObservableCreate, ObservableDetail, ObservableOut, validate_observable
from app.scoring import compute_score

router = APIRouter(
    prefix="/observables", tags=["observables"], dependencies=[Depends(require_api_key)]
)

CONNECTORS = [CisaKevConnector(), EpssConnector(), UrlhausConnector()]


@router.post("", response_model=ObservableOut, status_code=201)
def create_observable(payload: ObservableCreate, db: Session = Depends(get_db)):
    try:
        value = validate_observable(payload.type, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    existing = db.scalar(
        select(Observable).where(Observable.type == payload.type, Observable.value == value)
    )
    if existing:
        return existing

    obs = Observable(type=payload.type, value=value)
    db.add(obs)
    db.commit()
    db.refresh(obs)
    return obs


@router.get("", response_model=list[ObservableOut])
def list_observables(
    type: str | None = None,
    verdict: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    stmt = select(Observable).order_by(Observable.id.desc())
    if type:
        stmt = stmt.where(Observable.type == type)
    if verdict:
        stmt = stmt.where(Observable.verdict == verdict)
    stmt = stmt.limit(min(limit, 500)).offset(max(offset, 0))
    return list(db.scalars(stmt))


@router.get("/{observable_id}", response_model=ObservableDetail)
def get_observable(observable_id: int, db: Session = Depends(get_db)):
    obs = db.get(Observable, observable_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Observável não encontrado.")
    return obs


@router.post("/{observable_id}/enrich", response_model=ObservableDetail)
def enrich_observable(observable_id: int, db: Session = Depends(get_db)):
    obs = db.get(Observable, observable_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Observável não encontrado.")

    results: dict[str, dict | None] = {}
    errors: list[str] = []
    for connector in CONNECTORS:
        if not connector.supports(obs.type):
            continue
        try:
            data = connector.enrich(obs.type, obs.value, db)
        except Exception as exc:  # fonte fora do ar não derruba o enriquecimento
            errors.append(f"{connector.name}: {type(exc).__name__}")
            continue
        results[connector.name] = data
        db.add(Enrichment(observable_id=obs.id, source=connector.name, data=data))

    score, verdict, factors = compute_score(results)
    obs.score = score
    obs.verdict = verdict
    obs.score_factors = factors
    obs.last_enriched_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(obs)

    if errors and not results:
        raise HTTPException(
            status_code=502, detail=f"Todas as fontes falharam: {'; '.join(errors)}"
        )
    return obs
