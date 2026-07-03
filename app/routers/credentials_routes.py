"""Credential Intelligence — identity dossiers (tenant-scoped).

Aggregation of credential_exposure leaks per email: leak_count, unique passwords,
sources, stealer families, VIP link, max risk. E-mail masked by role (reuses the
exposure masking policy). NEVER exposes plaintext or password hashes.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import alerts, audit, config, exposure_ingest as ing
from app.auth import (Principal, current_tenant_id, require_analyst,
                      require_viewer)
from app.database import get_db
from app.models import (CredentialIdentity, ExposureFinding, InvestigationCase,
                        MonitoredAsset, utcnow)
from app.schemas import CredentialIdentityOut, CredentialIdentityTriage

router = APIRouter(prefix="/credentials", tags=["credentials"],
                   dependencies=[Depends(require_viewer)])


def _audit(db, principal, tid, request, action, target_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="credential_identity", target_id=target_id,
                 request=request, detail=detail)


def _reuse_risk(reuse_count: int) -> int:
    return min(25, int(reuse_count) * 8)


def _identity_out(ci: CredentialIdentity, principal: Principal, reuse_count: int = 0) -> dict:
    out = CredentialIdentityOut.model_validate({
        "id": ci.id, "tenant_id": ci.tenant_id, "identity_hash": ci.identity_hash,
        "email": ci.email, "domain": ci.domain, "leak_count": ci.leak_count,
        "unique_passwords": len(ci.password_hashes or []),
        "sources": ci.sources or [], "stealer_families": ci.stealer_families or [],
        "first_seen": ci.first_seen, "last_seen": ci.last_seen,
        "vip_asset_id": ci.vip_asset_id, "max_risk": ci.max_risk, "status": ci.status,
        "created_at": ci.created_at, "reuse_count": reuse_count,
        "reuse_risk": _reuse_risk(reuse_count),
    }).model_dump()
    out["email"] = ing.mask_value(out["email"], ing.PII, principal.effective_role(),
                                  config.EXPOSURE_PII_MASKING)
    return out


def _reuse_index(db, tid):
    """Constrói mapa password_hash -> {identity_id} e id -> CredentialIdentity."""
    hash_to_ids, by_id = {}, {}
    for ci in db.scalars(select(CredentialIdentity).where(CredentialIdentity.tenant_id == tid)):
        by_id[ci.id] = ci
        for h in (ci.password_hashes or []):
            hash_to_ids.setdefault(h, set()).add(ci.id)
    return hash_to_ids, by_id


def _reuse_count_for(ci, hash_to_ids) -> int:
    partners = set()
    for h in (ci.password_hashes or []):
        partners |= hash_to_ids.get(h, set())
    partners.discard(ci.id)
    return len(partners)


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
    rows = list(db.scalars(stmt.order_by(CredentialIdentity.max_risk.desc(),
                                         CredentialIdentity.leak_count.desc(),
                                         CredentialIdentity.id.desc())))
    hash_to_ids, _ = _reuse_index(db, tid)
    return [_identity_out(ci, principal, _reuse_count_for(ci, hash_to_ids)) for ci in rows]


@router.get("/identities/{identity_hash}", dependencies=[Depends(require_viewer)])
def get_identity(identity_hash: str, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_viewer),
                 tid: int = Depends(current_tenant_id)):
    ci = _owned(db, identity_hash, tid)
    hash_to_ids, _ = _reuse_index(db, tid)
    return _identity_out(ci, principal, _reuse_count_for(ci, hash_to_ids))


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


@router.get("/reuse", dependencies=[Depends(require_viewer)])
def password_reuse(db: Session = Depends(get_db),
                   principal: Principal = Depends(require_viewer),
                   tid: int = Depends(current_tenant_id)):
    """Grupos de identidades que compartilham a MESMA senha (por password_sha256).

    Nunca expõe o hash completo nem plaintext: o group id é um prefixo do hash.
    """
    hash_to_ids, by_id = _reuse_index(db, tid)
    groups = []
    for h, ids in hash_to_ids.items():
        if len(ids) < 2:
            continue
        members = [by_id[i] for i in ids]
        groups.append({
            "group": h[:12],  # prefixo — identifica o grupo sem revelar o hash inteiro
            "identity_count": len(ids),
            "identities": [{
                "identity_hash": m.identity_hash,
                "email": ing.mask_value(m.email, ing.PII, principal.effective_role(), config.EXPOSURE_PII_MASKING),
                "domain": m.domain, "leak_count": m.leak_count, "max_risk": m.max_risk,
                "vip_asset_id": m.vip_asset_id,
            } for m in sorted(members, key=lambda x: x.id)],
        })
    groups.sort(key=lambda g: g["identity_count"], reverse=True)
    return groups


@router.get("/identities/{identity_hash}/related", dependencies=[Depends(require_viewer)])
def related_identities(identity_hash: str, db: Session = Depends(get_db),
                       principal: Principal = Depends(require_viewer),
                       tid: int = Depends(current_tenant_id)):
    """Identidades relacionadas por reuso de senha (compartilham password_sha256)."""
    ci = _owned(db, identity_hash, tid)
    hash_to_ids, by_id = _reuse_index(db, tid)
    partners = set()
    for h in (ci.password_hashes or []):
        partners |= hash_to_ids.get(h, set())
    partners.discard(ci.id)
    return [_identity_out(by_id[i], principal, _reuse_count_for(by_id[i], hash_to_ids))
            for i in sorted(partners)]


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


@router.post("/identities/{identity_hash}/alert", dependencies=[Depends(require_analyst)])
def resend_vip_alert(identity_hash: str, request: Request, db: Session = Depends(get_db),
                     principal: Principal = Depends(require_analyst),
                     tid: int = Depends(current_tenant_id)):
    """Reenvia o alerta prioritário de VIP credential leak (analyst+).

    409 se a identidade não estiver ligada a um VIP. Sem senha/plaintext; e-mail
    mascarado por role na resposta.
    """
    ci = _owned(db, identity_hash, tid)
    if not ci.vip_asset_id:
        raise HTTPException(status_code=409, detail="Identity is not linked to a VIP asset.")
    asset = db.get(MonitoredAsset, ci.vip_asset_id)
    if asset is None or asset.tenant_id != tid:
        raise HTTPException(status_code=404, detail="VIP asset not found.")
    summary = alerts.send_vip_credential_alert(asset, ci)
    _audit(db, principal, tid, request, "credential.vip_alert_resent", ci.id, {"asset_id": asset.id})
    summary = {**summary, "email": ing.mask_value(
        summary["email"], ing.PII, principal.effective_role(), config.EXPOSURE_PII_MASKING)}
    return summary


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
