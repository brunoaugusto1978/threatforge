"""Onboarding e perfil — agora multi-tenant.

- 1º acesso da plataforma: criar OPERADOR (público enquanto não há usuários).
- Operator creates tenants (see tenants_routes) and each tenant performs its own onboarding.
- Organization, scope, threat profile, seeds and audit are ALWAYS tenant-scoped.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, sectors
from app.auth import (
    Principal,
    current_tenant_id,
    get_principal,
    require_admin,
    require_viewer,
)
from app.database import get_db
from app.models import AuditLog, Brand, MonitoringSeed, Organization, User, utcnow
from app.routers.auth_routes import _set_session_cookie
from app.schemas import (
    AdminBootstrap,
    AuditOut,
    OrganizationIn,
    OrganizationOut,
    ScopeIn,
    SectorProfileOut,
    SeedOut,
    SetupStatus,
    TenantSetupStatus,
    ThreatProfileResult,
)
from app.security import create_token, hash_password

router = APIRouter(tags=["organization"])


def _user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


def _org(db: Session, tid: int) -> Organization | None:
    return db.scalar(select(Organization).where(Organization.tenant_id == tid))


# ---------- Status público (plataforma) ----------
@router.get("/setup/status", response_model=SetupStatus)
def setup_status(db: Session = Depends(get_db)):
    users = _user_count(db)
    return SetupStatus(needs_operator=(users == 0), has_users=(users > 0))


@router.post("/setup/operator", status_code=201)
def bootstrap_operator(payload: AdminBootstrap, request: Request, response: Response,
                       db: Session = Depends(get_db)):
    """Cria o primeiro usuário: o OPERADOR de plataforma. Público só enquanto
    não houver nenhum usuário."""
    if _user_count(db) > 0:
        raise HTTPException(status_code=409, detail="Platform already initialized.")
    op = User(email=payload.email, hashed_password=hash_password(payload.password),
              role="admin", is_operator=True, operator_role="platform_admin", tenant_id=None)
    db.add(op)
    db.commit()
    db.refresh(op)
    audit.record(db, actor=op.email, actor_role="platform_admin",
                 action="bootstrap_operator_created", target_type="user", target_id=op.id,
                 request=request)
    token = create_token(sub=str(op.id), role="admin", pwd_version=op.pwd_version)
    _set_session_cookie(response, token)
    return {"email": op.email, "is_operator": True}


# ---------- Status do tenant (autenticado) ----------
@router.get("/tenant/setup-status", response_model=TenantSetupStatus)
def tenant_setup_status(db: Session = Depends(get_db),
                        tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    completed = bool(org and org.setup_completed)
    return TenantSetupStatus(tenant_id=tid, has_organization=(org is not None),
                             setup_completed=completed, needs_setup=(not completed))


# ---------- Wizard do tenant ----------
@router.put("/organization", response_model=OrganizationOut)
def upsert_organization(payload: OrganizationIn, request: Request,
                        db: Session = Depends(get_db),
                        principal: Principal = Depends(require_admin),
                        tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    action = "organization.update" if org else "organization.create"
    if org is None:
        org = Organization(tenant_id=tid, **payload.model_dump())
        db.add(org)
    else:
        for k, v in payload.model_dump().items():
            setattr(org, k, v)
        org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action=action, target_type="organization", target_id=org.id,
                 request=request, detail={"organization": org.name})
    return org


@router.get("/organization", response_model=OrganizationOut | None,
            dependencies=[Depends(require_viewer)])
def get_organization(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    return _org(db, tid)


@router.put("/setup/scope", response_model=OrganizationOut)
def save_scope(payload: ScopeIn, request: Request, db: Session = Depends(get_db),
               principal: Principal = Depends(require_admin),
               tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    if org is None:
        raise HTTPException(status_code=400, detail="Configure a organização primeiro.")
    org.monitoring_scope = payload.monitoring_scope
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="setup.scope", target_type="organization", target_id=org.id,
                 request=request, detail={"scope": payload.monitoring_scope})
    return org


# ---------- Threat Profile (global catalog, seeds por tenant) ----------
@router.get("/sectors")
def list_sectors(_: Principal = Depends(require_viewer)):
    return {"sectors": sectors.list_sectors()}


@router.get("/sectors/{sector}/profile", response_model=SectorProfileOut,
            dependencies=[Depends(require_viewer)])
def sector_profile(sector: str):
    p = sectors.profile_public(sector)
    return SectorProfileOut(sector=sector, threats=p["threats"], keywords=p["keywords"],
                            ioc_categories=p["ioc_categories"], cve_watchlist=p["cve_watchlist"],
                            sources=p["sources"])


@router.post("/setup/threat-profile", response_model=ThreatProfileResult)
def apply_threat_profile(request: Request, db: Session = Depends(get_db),
                         principal: Principal = Depends(require_admin),
                         tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    if org is None:
        raise HTTPException(status_code=400, detail="Configure a organização primeiro.")
    brands = list(db.scalars(select(Brand).where(Brand.tenant_id == tid)))
    brand_payload = [{"name": b.name, "domains": b.domain_list()} for b in brands]

    seed_dicts = sectors.generate_seeds(org.sector, brand_payload)
    existing = {s.seed.lower() for s in db.scalars(
        select(MonitoringSeed).where(MonitoringSeed.tenant_id == tid))}
    created = 0
    for sd in seed_dicts:
        if sd["seed"].lower() in existing:
            continue
        bid = next((b.id for b in brands if b.name.lower() in sd["seed"].lower()), None)
        db.add(MonitoringSeed(
            tenant_id=tid, brand_id=bid, seed=sd["seed"], seed_type=sd["seed_type"],
            scope=sd["scope"], source_type=sd.get("source_type", "sector_profile"),
            sector=org.sector, status="candidate", confirmed=False, confidence=sd["confidence"],
        ))
        existing.add(sd["seed"].lower())
        created += 1
    db.commit()
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="setup.threat_profile", target_type="organization", target_id=org.id,
                 request=request, detail={"sector": org.sector, "seeds_created": created})
    return ThreatProfileResult(sector=org.sector, seeds_created=created)


@router.get("/seeds", response_model=list[SeedOut], dependencies=[Depends(require_viewer)])
def list_seeds(status: str | None = None, scope: str | None = None, limit: int = 1000,
               db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    stmt = (select(MonitoringSeed).where(MonitoringSeed.tenant_id == tid)
            .order_by(MonitoringSeed.scope, MonitoringSeed.id.desc()))
    if status:
        stmt = stmt.where(MonitoringSeed.status == status)
    if scope:
        stmt = stmt.where(MonitoringSeed.scope == scope)
    return list(db.scalars(stmt.limit(min(limit, 5000))))


# ---------- Reabrir / finalizar ----------
@router.post("/setup/reopen", response_model=OrganizationOut)
def reopen_setup(request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    if org is None:
        raise HTTPException(status_code=400, detail="Nenhuma organização para reabrir.")
    org.setup_completed = False
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="organization_setup_reopened", target_type="organization",
                 target_id=org.id, request=request)
    return org


@router.post("/setup/complete", response_model=OrganizationOut)
def complete_setup(request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require_admin),
                   tid: int = Depends(current_tenant_id)):
    org = _org(db, tid)
    if org is None or not (org.name or "").strip() or not (org.sector or "").strip():
        raise HTTPException(status_code=422, detail="Incomplete organization: provide name and sector.")
    if not org.monitoring_scope:
        raise HTTPException(status_code=422, detail="Selecione ao menos uma fonte no escopo.")
    brands = list(db.scalars(select(Brand).where(Brand.tenant_id == tid)))
    if not brands:
        raise HTTPException(status_code=422, detail="Cadastre ao menos uma marca.")
    if not any(b.domain_list() for b in brands):
        raise HTTPException(status_code=422, detail="Register at least one official domain.")
    org.setup_completed = True
    org.setup_completed_at = utcnow()
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="organization_setup_completed", target_type="organization",
                 target_id=org.id, request=request)
    return org


# ---------- Audit (tenant-scoped) ----------
@router.get("/audit", response_model=list[AuditOut], dependencies=[Depends(require_admin)])
def list_audit(action: str | None = None, actor: str | None = None, limit: int = 200,
               db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    stmt = (select(AuditLog).where(AuditLog.tenant_id == tid)
            .order_by(AuditLog.ts.desc()))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    return list(db.scalars(stmt.limit(min(limit, 1000))))
