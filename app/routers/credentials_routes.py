"""Credential Intelligence — identity dossiers (tenant-scoped).

Aggregation of credential_exposure leaks per email: leak_count, unique passwords,
sources, stealer families, VIP link, max risk. E-mail masked by role (reuses the
exposure masking policy). NEVER exposes plaintext or password hashes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, exposure_ingest as ing
from app.auth import (Principal, current_tenant_id, require_analyst,
                      require_viewer)
from app.database import get_db
from app.models import (CredentialIdentity, ExposureFinding, InvestigationCase,
                        utcnow)
from app.schemas import CredentialIdentityOut, CredentialIdentityTriage

router = APIRouter(prefix="/credentials", tags=["credentials"],
                   dependencies=[Depends(require_viewer)])


def _audit(db, principal, tid, request, action, target_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="credential_identity", target_id=target_id,
                 request=request, detail=detail)


def _identity_out(ci: CredentialIdentity, principal: Principal) -> dict:
    out = CredentialIdentityOut.model_validate({
        "id": ci.id, "tenant_id": ci.tenant_id, "identity_hash": ci.identity_hash,
        "email": ci.email, "domain": ci.domain, "leak_count": ci.leak_count,
        "unique_passwords": len(ci.password_hashes or []),
        "sources": ci.sources or [], "stealer_families": ci.stealer_families or [],
        "first_seen": ci.first_seen, "last_seen": ci.last_seen,
        "vip_asset_id": ci.vip_asset_id, "max_risk": ci.max_risk, "status": ci.status,
        "created_at": ci.created_at,
    }).model_dump()
    out["email"] = ing.mask_value(out["email"], ing.PII, principal.effective_role(),
                                  config.EXPOSURE_PII_MASKING)
    return out


def _owned(db, ihash, tid) -> CredentialIdentity:
    ci = db.scalar(select(CredentialIdentity).where(
        CredentialIdentity.tenant_id == tid, CredentialIdentity.identity_hash == ihash))
    if ci is None:
        raise HTTPException(status_code=404, detail="Credential identity not found.")
    return ci


@router.get("/identities", dependencies=[Depends(require_viewer)])
def list_identities(db: Session = Depends(get_db),
                    principal: Principal = Depends(require_viewer),
                    tid: int = Depends(current_tenant_id),
                    domain: str | None = Query(None), status: str | None = Query(None),
                    vip: bool | None = Query(None)):
    stmt = select(CredentialIdentity).where(CredentialIdentity.tenant_id == tid)
    if domain:
        stmt = stmt.where(CredentialIdentity.domain == domain.strip().lower())
    if status:
        stmt = stmt.where(CredentialIdentity.status == status)
    if vip is True:
        stmt = stmt.where(CredentialIdentity.vip_asset_id.is_not(None))
    rows = db.scalars(stmt.order_by(CredentialIdentity.max_risk.desc(),
                                    CredentialIdentity.leak_count.desc(),
                                    CredentialIdentity.id.desc()))
    return [_identity_out(ci, principal) for ci in rows]


@router.get("/identities/{identity_hash}", dependencies=[Depends(require_viewer)])
def get_identity(identity_hash: str, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_viewer),
                 tid: int = Depends(current_tenant_id)):
    return _identity_out(_owned(db, identity_hash, tid), principal)


@router.get("/identities/{identity_hash}/findings", dependencies=[Depends(require_viewer)])
def identity_findings(identity_hash: str, db: Session = Depends(get_db),
                      principal: Principal = Depends(require_viewer),
                      tid: int = Depends(current_tenant_id)):
    ci = _owned(db, identity_hash, tid)
    rows = db.scalars(select(ExposureFinding).where(
        ExposureFinding.tenant_id == tid,
        ExposureFinding.exposure_type == "credential_exposure")
        .order_by(ExposureFinding.created_at.desc()))
    out = []
    for f in rows:
        if (f.detail or {}).get("email", "").strip().lower() == ci.email:
            det = ing.mask_detail(f.detail or {}, principal.effective_role(), config.EXPOSURE_PII_MASKING)
            out.append({"id": f.id, "source": f.source, "detail": det,
                        "risk_score": f.risk_score, "status": f.status,
                        "created_at": f.created_at.isoformat() if f.created_at else None})
    return out


@router.patch("/identities/{identity_hash}", dependencies=[Depends(require_analyst)])
def triage_identity(identity_hash: str, payload: CredentialIdentityTriage, request: Request,
                    db: Session = Depends(get_db),
                    principal: Principal = Depends(require_analyst),
                    tid: int = Depends(current_tenant_id)):
    ci = _owned(db, identity_hash, tid)
    if payload.status != ci.status:
        ci.status = payload.status
        db.commit()
        _audit(db, principal, tid, request, "credential.identity_triage", ci.id, {"status": ci.status})
    return _identity_out(ci, principal)


@router.post("/identities/{identity_hash}/case", status_code=201, dependencies=[Depends(require_analyst)])
def open_case(identity_hash: str, request: Request, db: Session = Depends(get_db),
              principal: Principal = Depends(require_analyst),
              tid: int = Depends(current_tenant_id)):
    ci = _owned(db, identity_hash, tid)
    snapshot = {"credential_identity_id": ci.id, "identity_hash": ci.identity_hash,
                "domain": ci.domain, "leak_count": ci.leak_count,
                "sources": ci.sources, "stealer_families": ci.stealer_families,
                "vip_asset_id": ci.vip_asset_id, "max_risk": ci.max_risk}
    sev = "critico" if ci.vip_asset_id else ("alto" if ci.max_risk >= 70 else "medio")
    case = InvestigationCase(
        tenant_id=tid, title=f"Credential exposure: {ci.email}"[:255],
        description=f"Opened from credential identity ({ci.leak_count} leaks).",
        severity=sev, status="open", finding_snapshot=snapshot,
        created_by_user_id=principal.user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "credential.case_opened", ci.id, {"case_id": case.id})
    return {"case_id": case.id, "status": case.status, "severity": case.severity}
