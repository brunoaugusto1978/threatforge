import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth import current_tenant_id, require_analyst, require_viewer
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.epss import EpssConnector
from app.connectors.urlhaus import UrlhausConnector
from app.database import get_db
from app.models import Enrichment, Observable
from app.schemas import ObservableCreate, ObservableDetail, ObservableOut, validate_observable
from app.scoring import compute_score

logger = logging.getLogger(__name__)

# Friendly, source-specific messages shown to the end user when an external
# enrichment source fails. Never surface the raw exception class or HTTP
# status text (e.g. "HTTPStatusError") in the UI — that belongs in logs/audit only.
_SOURCE_LABELS = {
    "urlhaus": "URLhaus",
    "cisa_kev": "CISA KEV",
    "epss": "EPSS",
}


def _friendly_source_failure(source: str) -> str:
    label = _SOURCE_LABELS.get(source, source)
    return f"Não foi possível consultar a fonte {label} no momento."


def _status_code_from(exc: Exception) -> int | None:
    """Best-effort extraction of an HTTP status code from a connector error
    (e.g. httpx.HTTPStatusError), without hard-depending on httpx types."""
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None) if response is not None else None

router = APIRouter(
    prefix="/observables", tags=["observables"], dependencies=[Depends(require_viewer)]
)

CONNECTORS = [CisaKevConnector(), EpssConnector(), UrlhausConnector()]


@router.post("", response_model=ObservableOut, status_code=201,
             dependencies=[Depends(require_analyst)])
def create_observable(payload: ObservableCreate, db: Session = Depends(get_db),
                      tid: int = Depends(current_tenant_id)):
    try:
        value = validate_observable(payload.type, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    existing = db.scalar(
        select(Observable).where(Observable.tenant_id == tid,
                                 Observable.type == payload.type, Observable.value == value)
    )
    if existing:
        return existing

    obs = Observable(tenant_id=tid, type=payload.type, value=value)
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
    tid: int = Depends(current_tenant_id),
):
    stmt = select(Observable).where(Observable.tenant_id == tid).order_by(Observable.id.desc())
    if type:
        stmt = stmt.where(Observable.type == type)
    if verdict:
        stmt = stmt.where(Observable.verdict == verdict)
    stmt = stmt.limit(min(limit, 500)).offset(max(offset, 0))
    return list(db.scalars(stmt))


def _get_owned(db: Session, observable_id: int, tid: int) -> Observable:
    obs = db.get(Observable, observable_id)
    # isolation: 404, not 403, to avoid revealing existence in another tenant
    if obs is None or obs.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Observable not found.")
    return obs


@router.get("/{observable_id}", response_model=ObservableDetail)
def get_observable(observable_id: int, db: Session = Depends(get_db),
                   tid: int = Depends(current_tenant_id)):
    return _get_owned(db, observable_id, tid)


@router.post("/{observable_id}/enrich", response_model=ObservableDetail,
             dependencies=[Depends(require_analyst)])
def enrich_observable(observable_id: int, request: Request, db: Session = Depends(get_db),
                      tid: int = Depends(current_tenant_id),
                      principal=Depends(require_analyst)):
    obs = _get_owned(db, observable_id, tid)
    already_enriched = obs.last_enriched_at is not None

    results: dict[str, dict | None] = {}
    warnings: list[str] = []
    for connector in CONNECTORS:
        if not connector.supports(obs.type):
            continue
        try:
            data = connector.enrich(obs.type, obs.value, db)
        except Exception as exc:
            # An external source being unavailable is an *external* failure, not an
            # internal platform error: never let the raw exception (e.g.
            # "HTTPStatusError") reach the client. Log the technical detail for
            # troubleshooting/audit, and surface only a friendly message.
            status_code = _status_code_from(exc)
            logger.warning(
                "Enrichment source failed: source=%s observable_id=%s status_code=%s error=%s",
                connector.name, obs.id, status_code, type(exc).__name__,
            )
            audit.record(
                db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                action="enrichment.source_failed", target_type="observable",
                target_id=obs.id, request=request,
                detail={
                    "source": connector.name,
                    "status_code": status_code,
                    "error_type": type(exc).__name__,
                },
                commit=False,
            )
            warnings.append(_friendly_source_failure(connector.name))
            continue
        results[connector.name] = data
        db.add(Enrichment(observable_id=obs.id, source=connector.name, data=data))

    if results:
        score, verdict, factors = compute_score(results)
        obs.score = score
        obs.verdict = verdict
        obs.score_factors = factors
    elif warnings and not already_enriched:
        # Every applicable source failed on the first enrichment attempt: there is
        # no signal at all, so the IOC must stay UNKNOWN rather than being scored
        # as "no known threat" (which would misrepresent an absent check as a
        # clean result). The IOC itself is never removed or corrupted.
        obs.verdict = "unknown"
        obs.score = 0
        obs.score_factors = []
    # else: all sources failed on a re-enrich of an already-enriched observable —
    # treat it as a transient external failure and keep the previous, valid
    # score/verdict/factors untouched instead of discarding real prior signal.

    obs.last_enriched_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(obs)

    if warnings and not results:
        warnings.append(f"O IOC foi mantido como {obs.verdict.upper()}.")
    obs.enrichment_warnings = warnings or None
    return obs
