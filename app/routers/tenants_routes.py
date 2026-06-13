"""Gestão de tenants, API keys e operadores.

Regras:
- Platform Admin: administra a plataforma (criar/bloquear/excluir tenants,
  criar operadores, gerar/revogar API keys, etc.).
- Support Operator/Viewer: presta suporte SOMENTE nos tenants atribuídos; sem
  ações destrutivas/administrativas.
"""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, invites
from app.auth import (
    Principal,
    operator_can_access_tenant,
    require_operator,
    require_platform_admin,
)
from app.database import get_db
from app.models import (
    ApiKey,
    OperatorTenantAccess,
    Tenant,
    TenantInvite,
    User,
    utcnow,
)
from app.schemas import (
    ApiKeyCreate,
    ApiKeyOut,
    InviteCreate,
    InviteOut,
    OperatorCreate,
    OperatorOut,
    OperatorUpdate,
    TenantAccessGrant,
    TenantAccessOut,
    TenantCreate,
    TenantOut,
)
from app.security import generate_api_key, generate_password, hash_password

router = APIRouter(tags=["tenants"], dependencies=[Depends(require_operator)])


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "tenant"


def _assert_tenant_access(db: Session, principal: Principal, tenant_id: int) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    if not operator_can_access_tenant(db, principal, tenant_id):
        raise HTTPException(status_code=403, detail="Operator has no access to this tenant.")
    return tenant


# ============ TENANTS ============
@router.post("/tenants", status_code=201)  # sem response_model: retorna link/convite extras
def create_tenant(payload: TenantCreate, request: Request, db: Session = Depends(get_db),
                  principal: Principal = Depends(require_platform_admin)):
    base = _slugify(payload.name)
    slug = base
    i = 2
    while db.scalar(select(Tenant).where(Tenant.slug == slug)):
        slug = f"{base}-{i}"
        i += 1
    if db.scalar(select(User).where(User.email == payload.admin_email)):
        raise HTTPException(status_code=409, detail="E-mail de admin já em uso.")

    tenant = Tenant(name=payload.name, slug=slug, status="active")
    db.add(tenant)
    db.flush()
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant.id,
                 operator_user_id=principal.user_id, action="tenant.create",
                 target_type="tenant", target_id=tenant.id, request=request,
                 detail={"name": tenant.name, "admin": payload.admin_email}, commit=False)

    if payload.admin_password:
        admin = User(email=payload.admin_email, hashed_password=hash_password(payload.admin_password),
                     role="admin", is_operator=False, tenant_id=tenant.id, is_active=True)
        db.add(admin)
        db.commit()
        db.refresh(tenant)
        return TenantOut.model_validate(tenant).model_dump()

    admin = User(email=payload.admin_email,
                 hashed_password=hash_password(generate_password(20)),
                 role="admin", is_operator=False, tenant_id=tenant.id, is_active=False)
    db.add(admin)
    db.commit()
    db.refresh(tenant)
    db.refresh(admin)
    inv = invites.create_invite(db, tenant=tenant, email=payload.admin_email, role="admin",
                                user=admin, invited_by=principal.subject, request=request)
    out = TenantOut.model_validate(tenant).model_dump()
    out["invite_link"] = inv["link"]
    out["invite_email_sent"] = inv["email_sent"]
    out["admin_email"] = payload.admin_email
    return out


@router.get("/tenants", response_model=list[TenantOut])
def list_tenants(db: Session = Depends(get_db), principal: Principal = Depends(require_operator)):
    stmt = select(Tenant).order_by(Tenant.id)
    if principal.operator_role != "platform_admin":
        # support: só os tenants atribuídos e ativos
        allowed = select(OperatorTenantAccess.tenant_id).where(
            OperatorTenantAccess.operator_user_id == principal.user_id,
            OperatorTenantAccess.is_active == True,  # noqa: E712
        )
        stmt = stmt.where(Tenant.id.in_(allowed))
    return list(db.scalars(stmt))


@router.patch("/tenants/{tenant_id}", response_model=TenantOut)
def set_tenant_status(tenant_id: int, request: Request, status: str,
                      db: Session = Depends(get_db),
                      principal: Principal = Depends(require_platform_admin)):
    """Ativar/bloquear tenant — apenas Platform Admin."""
    if status not in ("active", "suspended"):
        raise HTTPException(status_code=422, detail="status deve ser active|suspended.")
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    tenant.status = status
    db.commit()
    db.refresh(tenant)
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant_id,
                 operator_user_id=principal.user_id, action="tenant.set_status",
                 target_type="tenant", target_id=tenant_id, request=request,
                 detail={"status": status})
    return tenant


@router.get("/tenants/{tenant_id}/stats")
def tenant_stats(tenant_id: int, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_operator)):
    from app.models import Brand, BrandFinding, Observable

    tenant = _assert_tenant_access(db, principal, tenant_id)

    def c(model):
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.tenant_id == tenant_id)) or 0
    return {
        "tenant_id": tenant_id, "name": tenant.name, "status": tenant.status,
        "users": c(User), "brands": c(Brand), "observables": c(Observable),
        "findings": c(BrandFinding),
    }


# ============ CONVITES ============
@router.get("/tenants/{tenant_id}/invites", response_model=list[InviteOut])
def list_invites(tenant_id: int, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_operator)):
    _assert_tenant_access(db, principal, tenant_id)
    return list(db.query(TenantInvite).filter(TenantInvite.tenant_id == tenant_id)
                .order_by(TenantInvite.id.desc()))


@router.post("/tenants/{tenant_id}/invites")
def create_or_resend_invite(tenant_id: int, payload: InviteCreate, request: Request,
                            db: Session = Depends(get_db),
                            principal: Principal = Depends(require_operator)):
    # support pode reenviar convite ao admin do cliente (tenant atribuído)
    tenant = _assert_tenant_access(db, principal, tenant_id)
    other = db.query(User).filter(User.email == payload.email).first()
    if other is not None and other.tenant_id not in (None, tenant_id):
        raise HTTPException(status_code=409, detail="E-mail já pertence a outro tenant.")
    inv = invites.create_invite(db, tenant=tenant, email=payload.email, role=payload.role,
                                user=other, invited_by=principal.subject, request=request)
    return {"invite_id": inv["invite"].id, "email": payload.email,
            "invite_link": inv["link"], "email_sent": inv["email_sent"]}


@router.post("/tenants/{tenant_id}/invites/{invite_id}/revoke", status_code=204)
def revoke_invite(tenant_id: int, invite_id: int, request: Request,
                  db: Session = Depends(get_db),
                  principal: Principal = Depends(require_platform_admin)):
    inv = db.get(TenantInvite, invite_id)
    if inv is None or inv.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    if inv.status == "pending":
        inv.status = "revoked"
        db.commit()
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant_id,
                 operator_user_id=principal.user_id, action="invite.revoke",
                 target_type="invite", target_id=invite_id, request=request)


# ============ API KEYS ============
@router.post("/tenants/{tenant_id}/api-keys")
def create_api_key(tenant_id: int, payload: ApiKeyCreate, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_platform_admin)):
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    full, prefix, digest = generate_api_key()
    row = ApiKey(tenant_id=tenant_id, label=payload.label, prefix=prefix,
                 key_hash=digest, role=payload.role, active=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant_id,
                 operator_user_id=principal.user_id, action="apikey.create",
                 target_type="api_key", target_id=row.id, request=request,
                 detail={"label": payload.label, "role": payload.role})
    return {"id": row.id, "tenant_id": tenant_id, "label": row.label, "role": row.role,
            "api_key": full, "note": "Guarde agora — não será exibida de novo."}


@router.get("/tenants/{tenant_id}/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(tenant_id: int, db: Session = Depends(get_db),
                  principal: Principal = Depends(require_operator)):
    # support pode listar (sem segredo, só prefix) para troubleshooting
    _assert_tenant_access(db, principal, tenant_id)
    return list(db.scalars(select(ApiKey).where(ApiKey.tenant_id == tenant_id)
                           .order_by(ApiKey.id)))


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}", status_code=204)
def revoke_api_key(tenant_id: int, key_id: int, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_platform_admin)):
    row = db.get(ApiKey, key_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="API key não encontrada.")
    row.active = False
    db.commit()
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant_id,
                 operator_user_id=principal.user_id, action="apikey.revoke",
                 target_type="api_key", target_id=key_id, request=request)


# ============ OPERADORES (somente Platform Admin) ============
@router.post("/operators", response_model=OperatorOut, status_code=201)
def create_operator(payload: OperatorCreate, request: Request, db: Session = Depends(get_db),
                    principal: Principal = Depends(require_platform_admin)):
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="E-mail já em uso.")
    op = User(email=payload.email,
              hashed_password=hash_password(payload.password or generate_password(16)),
              role="admin", is_operator=True, operator_role=payload.operator_role,
              tenant_id=None, is_active=True)
    db.add(op)
    db.commit()
    db.refresh(op)
    audit.record(db, actor=principal.subject, actor_role="platform_admin",
                 operator_user_id=principal.user_id, action="operator.create",
                 target_type="user", target_id=op.id, request=request,
                 detail={"email": op.email, "operator_role": op.operator_role})
    return op


@router.get("/operators", response_model=list[OperatorOut],
            dependencies=[Depends(require_platform_admin)])
def list_operators(db: Session = Depends(get_db)):
    return list(db.scalars(select(User).where(User.is_operator == True)  # noqa: E712
                           .order_by(User.id)))


@router.patch("/operators/{operator_id}", response_model=OperatorOut)
def update_operator(operator_id: int, payload: OperatorUpdate, request: Request,
                    db: Session = Depends(get_db),
                    principal: Principal = Depends(require_platform_admin)):
    op = db.get(User, operator_id)
    if op is None or not op.is_operator:
        raise HTTPException(status_code=404, detail="Operator not found.")
    # proteção: não rebaixar/desativar a si mesmo (evita lockout do super admin)
    if principal.user_id == operator_id:
        if payload.operator_role and payload.operator_role != "platform_admin":
            raise HTTPException(status_code=400, detail="Não é possível rebaixar a própria conta.")
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="Não é possível desativar a própria conta.")
    if payload.operator_role is not None:
        op.operator_role = payload.operator_role
    if payload.is_active is not None:
        op.is_active = payload.is_active
        if not payload.is_active:
            op.pwd_version += 1  # encerra sessões
    db.commit()
    db.refresh(op)
    audit.record(db, actor=principal.subject, actor_role="platform_admin",
                 operator_user_id=principal.user_id, action="operator.update",
                 target_type="user", target_id=op.id, request=request,
                 detail={"operator_role": payload.operator_role, "is_active": payload.is_active})
    return op


# ---- acesso de operador a tenants ----
@router.get("/operators/{operator_id}/tenant-access", response_model=list[TenantAccessOut],
            dependencies=[Depends(require_platform_admin)])
def list_tenant_access(operator_id: int, db: Session = Depends(get_db)):
    return list(db.scalars(select(OperatorTenantAccess)
                           .where(OperatorTenantAccess.operator_user_id == operator_id)
                           .order_by(OperatorTenantAccess.id)))


@router.post("/operators/{operator_id}/tenant-access", response_model=TenantAccessOut, status_code=201)
def grant_tenant_access(operator_id: int, payload: TenantAccessGrant, request: Request,
                        db: Session = Depends(get_db),
                        principal: Principal = Depends(require_platform_admin)):
    op = db.get(User, operator_id)
    if op is None or not op.is_operator:
        raise HTTPException(status_code=404, detail="Operator not found.")
    if db.get(Tenant, payload.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    existing = db.scalar(select(OperatorTenantAccess).where(
        OperatorTenantAccess.operator_user_id == operator_id,
        OperatorTenantAccess.tenant_id == payload.tenant_id))
    if existing:
        existing.is_active = True
        existing.access_role = payload.access_role
        existing.revoked_at = None
        existing.revoked_by = None
        row = existing
    else:
        row = OperatorTenantAccess(operator_user_id=operator_id, tenant_id=payload.tenant_id,
                                   access_role=payload.access_role, is_active=True,
                                   created_by=principal.subject)
        db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, actor=principal.subject, actor_role="platform_admin",
                 tenant_id=payload.tenant_id, operator_user_id=principal.user_id,
                 action="operator.grant_access", target_type="user", target_id=operator_id,
                 request=request, detail={"tenant_id": payload.tenant_id, "role": payload.access_role})
    return row


@router.delete("/operators/{operator_id}/tenant-access/{tenant_id}", status_code=204)
def revoke_tenant_access(operator_id: int, tenant_id: int, request: Request,
                         db: Session = Depends(get_db),
                         principal: Principal = Depends(require_platform_admin)):
    row = db.scalar(select(OperatorTenantAccess).where(
        OperatorTenantAccess.operator_user_id == operator_id,
        OperatorTenantAccess.tenant_id == tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Access not found.")
    row.is_active = False
    row.revoked_at = utcnow()
    row.revoked_by = principal.subject
    db.commit()
    audit.record(db, actor=principal.subject, actor_role="platform_admin", tenant_id=tenant_id,
                 operator_user_id=principal.user_id, action="operator.revoke_access",
                 target_type="user", target_id=operator_id, request=request,
                 detail={"tenant_id": tenant_id})
