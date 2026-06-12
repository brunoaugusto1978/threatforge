"""Onboarding obrigatório: 1º admin, Setup Wizard (org, marca, escopo, threat
profile, finalização), perfil da organização e trilha de auditoria."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, sectors
from app.auth import Principal, require_admin, require_viewer
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
    ThreatProfileResult,
)
from app.security import create_token, hash_password

router = APIRouter(tags=["organization"])


def _org(db: Session) -> Organization | None:
    return db.scalar(select(Organization).order_by(Organization.id).limit(1))


def _user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


# ---------- Status do onboarding ----------
@router.get("/setup/status", response_model=SetupStatus)
def setup_status(db: Session = Depends(get_db)):
    org = _org(db)
    users = _user_count(db)
    completed = bool(org and org.setup_completed)
    return SetupStatus(
        needs_admin=(users == 0),
        needs_setup=(not completed),
        setup_completed=completed,
        has_organization=(org is not None),
        has_users=(users > 0),
    )


# ---------- Passo 0: criar o primeiro admin ----------
@router.post("/setup/admin", status_code=201)
def bootstrap_admin(payload: AdminBootstrap, request: Request, response: Response,
                    db: Session = Depends(get_db)):
    """Cria o primeiro usuário (sempre admin). Público APENAS enquanto não houver
    nenhum usuário. Depois disso fica travado."""
    if _user_count(db) > 0:
        raise HTTPException(status_code=409, detail="Já existe um administrador.")
    admin = User(email=payload.email, hashed_password=hash_password(payload.password), role="admin")
    db.add(admin)
    db.commit()
    db.refresh(admin)
    audit.record(db, actor=admin.email, actor_role="admin", action="bootstrap_admin_created",
                 target_type="user", target_id=admin.id, request=request)
    token = create_token(sub=str(admin.id), role="admin", pwd_version=admin.pwd_version)
    _set_session_cookie(response, token)
    return {"email": admin.email, "role": "admin"}


# ---------- Wizard passo 1: organização ----------
@router.put("/organization", response_model=OrganizationOut)
def upsert_organization(payload: OrganizationIn, request: Request,
                        db: Session = Depends(get_db),
                        principal: Principal = Depends(require_admin)):
    org = _org(db)
    action = "organization.update" if org else "organization.create"
    if org is None:
        org = Organization(**payload.model_dump())
        db.add(org)
    else:
        for k, v in payload.model_dump().items():
            setattr(org, k, v)
        org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role, action=action,
                 target_type="organization", target_id=org.id, request=request,
                 detail={"organization": org.name})
    return org


@router.get("/organization", response_model=OrganizationOut | None,
            dependencies=[Depends(require_viewer)])
def get_organization(db: Session = Depends(get_db)):
    return _org(db)


# ---------- Wizard passo 3: escopo de monitoramento ----------
@router.put("/setup/scope", response_model=OrganizationOut)
def save_scope(payload: ScopeIn, request: Request, db: Session = Depends(get_db),
               principal: Principal = Depends(require_admin)):
    org = _org(db)
    if org is None:
        raise HTTPException(status_code=400, detail="Configure a organização primeiro.")
    org.monitoring_scope = payload.monitoring_scope
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role,
                 action="setup.scope", target_type="organization", target_id=org.id,
                 request=request, detail={"scope": payload.monitoring_scope})
    return org


# ---------- Threat Profile por setor ----------
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
                         principal: Principal = Depends(require_admin)):
    """Gera seeds de monitoramento (status candidate) a partir do setor da
    organização e das marcas cadastradas. NÃO cria findings."""
    org = _org(db)
    if org is None:
        raise HTTPException(status_code=400, detail="Configure a organização primeiro.")
    brands = list(db.scalars(select(Brand)))
    brand_payload = [{"name": b.name, "domains": b.domain_list()} for b in brands]

    seed_dicts = sectors.generate_seeds(org.sector, brand_payload)
    # evita duplicar seeds já existentes (case-insensitive) para o mesmo setor
    existing = {s.seed.lower() for s in db.scalars(
        select(MonitoringSeed).where(MonitoringSeed.sector == org.sector))}
    created = 0
    for sd in seed_dicts:
        if sd["seed"].lower() in existing:
            continue
        # vincula à marca cujo nome aparece no seed (se houver)
        bid = next((b.id for b in brands if b.name.lower() in sd["seed"].lower()), None)
        db.add(MonitoringSeed(
            brand_id=bid, seed=sd["seed"], seed_type=sd["seed_type"],
            scope=sd["scope"], source_type=sd.get("source_type", "sector_profile"),
            sector=org.sector, status="candidate", confirmed=False,
            confidence=sd["confidence"],
        ))
        existing.add(sd["seed"].lower())
        created += 1
    db.commit()
    audit.record(db, actor=principal.subject, actor_role=principal.role,
                 action="setup.threat_profile", target_type="organization", target_id=org.id,
                 request=request, detail={"sector": org.sector, "seeds_created": created})
    return ThreatProfileResult(sector=org.sector, seeds_created=created)


@router.get("/seeds", response_model=list[SeedOut], dependencies=[Depends(require_viewer)])
def list_seeds(status: str | None = None, scope: str | None = None,
               limit: int = 1000, db: Session = Depends(get_db)):
    stmt = select(MonitoringSeed).order_by(MonitoringSeed.scope, MonitoringSeed.id.desc())
    if status:
        stmt = stmt.where(MonitoringSeed.status == status)
    if scope:
        stmt = stmt.where(MonitoringSeed.scope == scope)
    return list(db.scalars(stmt.limit(min(limit, 5000))))


# ---------- Finalização do setup ----------
@router.post("/setup/reopen", response_model=OrganizationOut)
def reopen_setup(request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin)):
    """Reabre o wizard de configuração (admin), sem apagar dados. Volta a
    travar as abas até nova conclusão."""
    org = _org(db)
    if org is None:
        raise HTTPException(status_code=400, detail="Nenhuma organização para reabrir.")
    org.setup_completed = False
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role,
                 action="organization_setup_reopened", target_type="organization",
                 target_id=org.id, request=request)
    return org


@router.post("/setup/complete", response_model=OrganizationOut)
def complete_setup(request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require_admin)):
    org = _org(db)
    # validações que bloqueiam a conclusão do setup
    if org is None or not (org.name or "").strip() or not (org.sector or "").strip():
        raise HTTPException(status_code=422,
                            detail="Organização incompleta: informe nome e setor.")
    if not org.monitoring_scope:
        raise HTTPException(status_code=422,
                            detail="Selecione ao menos uma fonte no escopo de monitoramento.")
    brands = list(db.scalars(select(Brand)))
    if not brands:
        raise HTTPException(status_code=422, detail="Cadastre ao menos uma marca.")
    if not any(b.domain_list() for b in brands):
        raise HTTPException(status_code=422,
                            detail="Cadastre ao menos um domínio oficial em alguma marca.")

    org.setup_completed = True
    org.setup_completed_at = utcnow()
    org.updated_at = utcnow()
    db.commit()
    db.refresh(org)
    audit.record(db, actor=principal.subject, actor_role=principal.role,
                 action="organization_setup_completed", target_type="organization",
                 target_id=org.id, request=request)
    return org


# ---------- Auditoria ----------
@router.get("/audit", response_model=list[AuditOut], dependencies=[Depends(require_admin)])
def list_audit(action: str | None = None, actor: str | None = None,
               limit: int = 200, db: Session = Depends(get_db)):
    stmt = select(AuditLog).order_by(AuditLog.ts.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    return list(db.scalars(stmt.limit(min(limit, 1000))))
