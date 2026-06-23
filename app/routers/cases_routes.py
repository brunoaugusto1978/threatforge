"""Investigation Cases — tenant-scoped.

RBAC: viewer lê; analyst cria/edita campos e move entre estados ATIVOS;
assign/close/reopen são admin-only. Cross-tenant -> 404.
O case sobrevive a archive/delete/clear de brand/finding (FK SET NULL + snapshot).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth import Principal, current_tenant_id, require_analyst, require_viewer
from app.database import get_db
from app.models import Brand, BrandFinding, InvestigationCase, User, utcnow
from app.schemas import CaseCreate, CaseOut, CaseUpdate

router = APIRouter(prefix="/cases", tags=["cases"], dependencies=[Depends(require_viewer)])

ACTIVE = {"open", "triage", "investigating", "contained"}
TERMINAL = {"closed", "false_positive"}
_VERDICT_SEVERITY = {"malicious": "alto", "suspicious": "medio",
                     "low": "baixo", "no_known_threat": "baixo", "info": "baixo"}


def _owned_case(db: Session, case_id: int, tid: int) -> InvestigationCase:
    c = db.get(InvestigationCase, case_id)
    if c is None or c.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Case not found.")
    return c


def _is_admin(principal: Principal) -> bool:
    return principal.effective_role() == "admin"


def _validate_assignee(db: Session, tid: int, uid: int | None) -> None:
    if uid is None:
        return
    u = db.get(User, uid)
    if u is None or u.tenant_id != tid:
        raise HTTPException(status_code=422, detail="assignee_user_id must be a user of this tenant.")


def _snapshot(f: BrandFinding, brand: Brand | None) -> dict:
    return {
        "finding_id": f.id, "brand_id": f.brand_id,
        "brand_name": brand.name if brand else None,
        "domain": f.domain, "score": f.score, "verdict": f.verdict,
        "similarity": f.similarity, "source": f.source, "status": f.status,
        "captured_at": utcnow().isoformat(),
    }


def _active_case_for_finding(db: Session, tid: int, finding_id: int) -> InvestigationCase | None:
    return db.scalar(select(InvestigationCase).where(
        InvestigationCase.tenant_id == tid, InvestigationCase.finding_id == finding_id,
        InvestigationCase.status.in_(tuple(ACTIVE))))


def _audit(db, principal, tid, request, action, case_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="case", target_id=case_id, request=request, detail=detail)


@router.post("", status_code=201, dependencies=[Depends(require_analyst)])
def create_case(payload: CaseCreate, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(require_analyst),
                tid: int = Depends(current_tenant_id)):
    brand = None
    if payload.brand_id is not None:
        brand = db.get(Brand, payload.brand_id)
        if brand is None or brand.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Brand not found.")
    snapshot = None
    if payload.finding_id is not None:
        f = db.get(BrandFinding, payload.finding_id)
        if f is None or f.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Finding not found.")
        # consistência: finding deve pertencer à brand informada
        if brand is not None and f.brand_id != brand.id:
            raise HTTPException(status_code=422,
                                detail="finding_id does not belong to the given brand_id.")
        # duplicidade: já existe case ativo para o finding
        existing = _active_case_for_finding(db, tid, payload.finding_id)
        if existing is not None:
            raise HTTPException(status_code=409, detail={
                "message": "An active investigation already exists for this finding.",
                "existing_case_id": existing.id})
        snapshot = _snapshot(f, brand or db.get(Brand, f.brand_id))
        if brand is None:
            payload.brand_id = f.brand_id
    if payload.assignee_user_id is not None and not _is_admin(principal):
        raise HTTPException(status_code=403, detail="Assigning a case requires admin.")
    _validate_assignee(db, tid, payload.assignee_user_id)

    case = InvestigationCase(
        tenant_id=tid, brand_id=payload.brand_id, finding_id=payload.finding_id,
        finding_snapshot=snapshot, title=payload.title, description=payload.description,
        severity=payload.severity, status="open",
        assignee_user_id=payload.assignee_user_id, created_by_user_id=principal.user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "case.create", case.id,
           {"title": case.title, "severity": case.severity, "brand_id": case.brand_id,
            "finding_id": case.finding_id, "from_finding": False})
    return CaseOut.model_validate(case).model_dump()


@router.get("", dependencies=[Depends(require_viewer)])
def list_cases(status: str | None = None, severity: str | None = None,
               assignee_user_id: int | None = None, brand_id: int | None = None,
               q: str | None = None, limit: int = 100, offset: int = 0,
               db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    stmt = select(InvestigationCase).where(InvestigationCase.tenant_id == tid)
    if status:
        stmt = stmt.where(InvestigationCase.status == status)
    if severity:
        stmt = stmt.where(InvestigationCase.severity == severity)
    if assignee_user_id is not None:
        stmt = stmt.where(InvestigationCase.assignee_user_id == assignee_user_id)
    if brand_id is not None:
        stmt = stmt.where(InvestigationCase.brand_id == brand_id)
    if q:
        stmt = stmt.where(InvestigationCase.title.ilike(f"%{q}%"))
    stmt = stmt.order_by(InvestigationCase.created_at.desc()).limit(max(1, min(limit, 500))).offset(max(offset, 0))
    return [CaseOut.model_validate(c).model_dump() for c in db.scalars(stmt)]


@router.get("/{case_id}", dependencies=[Depends(require_viewer)])
def get_case(case_id: int, db: Session = Depends(get_db),
             tid: int = Depends(current_tenant_id)):
    return CaseOut.model_validate(_owned_case(db, case_id, tid)).model_dump()


@router.patch("/{case_id}", dependencies=[Depends(require_analyst)])
def update_case(case_id: int, payload: CaseUpdate, request: Request,
                db: Session = Depends(get_db),
                principal: Principal = Depends(require_analyst),
                tid: int = Depends(current_tenant_id)):
    case = _owned_case(db, case_id, tid)
    provided = payload.model_dump(exclude_unset=True)
    admin = _is_admin(principal)

    # assignee (admin-only)
    if "assignee_user_id" in provided:
        if not admin:
            raise HTTPException(status_code=403, detail="Assigning a case requires admin.")
        new_assignee = provided["assignee_user_id"]
        _validate_assignee(db, tid, new_assignee)
        if new_assignee != case.assignee_user_id:
            old = case.assignee_user_id
            case.assignee_user_id = new_assignee
            _audit(db, principal, tid, request, "case.assign", case.id,
                   {"assignee": {"from": old, "to": new_assignee}})

    # status transitions
    if "status" in provided and provided["status"] != case.status:
        old, new = case.status, provided["status"]
        if old in ACTIVE and new in ACTIVE:
            case.status = new
            _audit(db, principal, tid, request, "case.status_change", case.id,
                   {"status": {"from": old, "to": new}})
        elif old in ACTIVE and new in TERMINAL:
            if not admin:
                raise HTTPException(status_code=403, detail="Closing a case requires admin.")
            case.status = new
            case.closed_at = utcnow()
            _audit(db, principal, tid, request, "case.close", case.id,
                   {"status": {"from": old, "to": new}, "closed_at": case.closed_at.isoformat()})
        elif old in TERMINAL and new in ACTIVE:
            if not admin:
                raise HTTPException(status_code=403, detail="Reopening a case requires admin.")
            case.status = new
            case.closed_at = None
            _audit(db, principal, tid, request, "case.reopen", case.id,
                   {"status": {"from": old, "to": new}})
        else:
            raise HTTPException(status_code=422, detail=f"Invalid status transition: {old} -> {new}")

    # campos operacionais (analyst+)
    changes = {}
    for f in ("title", "description", "severity"):
        if f in provided and provided[f] != getattr(case, f):
            changes[f] = {"from": getattr(case, f), "to": provided[f]}
            setattr(case, f, provided[f])

    case.updated_at = utcnow()
    db.commit()
    db.refresh(case)
    if changes:
        _audit(db, principal, tid, request, "case.update", case.id, {"changes": changes})
    return CaseOut.model_validate(case).model_dump()


# abrir case a partir de um finding
finding_router = APIRouter(prefix="/brands", tags=["cases"], dependencies=[Depends(require_viewer)])


@finding_router.post("/{brand_id}/findings/{finding_id}/case", status_code=201,
                     dependencies=[Depends(require_analyst)])
def open_case_from_finding(brand_id: int, finding_id: int, request: Request,
                           db: Session = Depends(get_db),
                           principal: Principal = Depends(require_analyst),
                           tid: int = Depends(current_tenant_id)):
    brand = db.get(Brand, brand_id)
    if brand is None or brand.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Brand not found.")
    f = db.get(BrandFinding, finding_id)
    if f is None or f.tenant_id != tid or f.brand_id != brand_id:
        raise HTTPException(status_code=404, detail="Finding not found.")

    existing = _active_case_for_finding(db, tid, finding_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail={
            "message": "An active investigation already exists for this finding.",
            "existing_case_id": existing.id})

    case = InvestigationCase(
        tenant_id=tid, brand_id=brand_id, finding_id=finding_id,
        finding_snapshot=_snapshot(f, brand),
        title=f"Investigation: {f.domain}",
        severity=_VERDICT_SEVERITY.get(f.verdict, "medio"), status="open",
        created_by_user_id=principal.user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "case.create", case.id,
           {"title": case.title, "severity": case.severity, "brand_id": brand_id,
            "finding_id": finding_id, "from_finding": True})
    return CaseOut.model_validate(case).model_dump()
