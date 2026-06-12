"""Gestão de tenants e API keys — restrito ao OPERADOR de plataforma."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, invites
from app.auth import Principal, require_operator
from app.database import get_db
from app.models import ApiKey, Tenant, TenantInvite, User
from app.schemas import (
    ApiKeyCreate,
    ApiKeyOut,
    InviteCreate,
    InviteOut,
    TenantCreate,
    TenantOut,
)
from app.security import generate_api_key, generate_password, hash_password

router = APIRouter(tags=["tenants"], dependencies=[Depends(require_operator)])


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "tenant"


@router.post("/tenants", status_code=201)  # sem response_model: retorna link/convite extras
def create_tenant(payload: TenantCreate, request: Request, db: Session = Depends(get_db),
                  principal: Principal = Depends(require_operator)):
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
    db.flush()  # obtém tenant.id
    audit.record(db, actor=principal.subject, actor_role="operator", tenant_id=tenant.id,
                 action="tenant.create", target_type="tenant", target_id=tenant.id,
                 request=request, detail={"name": tenant.name, "admin": payload.admin_email},
                 commit=False)

    if payload.admin_password:
        # caminho direto (compat/headless): admin ativo com senha definida
        admin = User(email=payload.admin_email, hashed_password=hash_password(payload.admin_password),
                     role="admin", is_operator=False, tenant_id=tenant.id, is_active=True)
        db.add(admin)
        db.commit()
        db.refresh(tenant)
        out = TenantOut.model_validate(tenant).model_dump()
        return out

    # caminho padrão: cria admin INATIVO + convite por e-mail
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
def list_tenants(db: Session = Depends(get_db)):
    return list(db.scalars(select(Tenant).order_by(Tenant.id)))


@router.get("/tenants/{tenant_id}/stats")
def tenant_stats(tenant_id: int, db: Session = Depends(get_db)):
    from app.models import Brand, BrandFinding, Observable

    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")

    def c(model):
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.tenant_id == tenant_id)) or 0
    return {
        "tenant_id": tenant_id, "name": tenant.name,
        "users": c(User), "brands": c(Brand), "observables": c(Observable),
        "findings": c(BrandFinding),
    }


@router.get("/tenants/{tenant_id}/invites", response_model=list[InviteOut])
def list_invites(tenant_id: int, db: Session = Depends(get_db)):
    return list(db.query(TenantInvite).filter(TenantInvite.tenant_id == tenant_id)
                .order_by(TenantInvite.id.desc()))


@router.post("/tenants/{tenant_id}/invites")
def create_or_resend_invite(tenant_id: int, payload: InviteCreate, request: Request,
                            db: Session = Depends(get_db),
                            principal: Principal = Depends(require_operator)):
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    # se já existe usuário com este e-mail em OUTRO tenant, bloqueia
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
                  principal: Principal = Depends(require_operator)):
    inv = db.get(TenantInvite, invite_id)
    if inv is None or inv.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Convite não encontrado.")
    if inv.status == "pending":
        inv.status = "revoked"
        db.commit()
    audit.record(db, actor=principal.subject, actor_role="operator", tenant_id=tenant_id,
                 action="invite.revoke", target_type="invite", target_id=invite_id,
                 request=request)


@router.post("/tenants/{tenant_id}/api-keys")
def create_api_key(tenant_id: int, payload: ApiKeyCreate, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_operator)):
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant não encontrado.")
    full, prefix, digest = generate_api_key()
    row = ApiKey(tenant_id=tenant_id, label=payload.label, prefix=prefix,
                 key_hash=digest, role=payload.role, active=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, actor=principal.subject, actor_role="operator", tenant_id=tenant_id,
                 action="apikey.create", target_type="api_key", target_id=row.id,
                 request=request, detail={"label": payload.label, "role": payload.role})
    # a chave completa só é exibida UMA vez
    return {"id": row.id, "tenant_id": tenant_id, "label": row.label, "role": row.role,
            "api_key": full, "note": "Guarde agora — não será exibida de novo."}


@router.get("/tenants/{tenant_id}/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(tenant_id: int, db: Session = Depends(get_db)):
    return list(db.scalars(select(ApiKey).where(ApiKey.tenant_id == tenant_id)
                           .order_by(ApiKey.id)))


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}", status_code=204)
def revoke_api_key(tenant_id: int, key_id: int, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_operator)):
    row = db.get(ApiKey, key_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="API key não encontrada.")
    row.active = False
    db.commit()
    audit.record(db, actor=principal.subject, actor_role="operator", tenant_id=tenant_id,
                 action="apikey.revoke", target_type="api_key", target_id=key_id,
                 request=request)
