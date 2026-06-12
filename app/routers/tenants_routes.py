"""Gestão de tenants e API keys — restrito ao OPERADOR de plataforma."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.auth import Principal, require_operator
from app.database import get_db
from app.models import ApiKey, Tenant, User
from app.schemas import (
    ApiKeyCreate,
    ApiKeyOut,
    TenantCreate,
    TenantOut,
)
from app.security import generate_api_key, generate_password, hash_password

router = APIRouter(tags=["tenants"], dependencies=[Depends(require_operator)])


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "tenant"


@router.post("/tenants", response_model=TenantOut, status_code=201)
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

    temp = payload.admin_password or generate_password(16)
    admin = User(email=payload.admin_email, hashed_password=hash_password(temp),
                 role="admin", is_operator=False, tenant_id=tenant.id)
    db.add(admin)
    db.commit()
    db.refresh(tenant)
    audit.record(db, actor=principal.subject, actor_role="operator", tenant_id=tenant.id,
                 action="tenant.create", target_type="tenant", target_id=tenant.id,
                 request=request, detail={"name": tenant.name, "admin": payload.admin_email})

    result = TenantOut.model_validate(tenant).model_dump()
    if not payload.admin_password:
        result["admin_temporary_password"] = temp
        result["admin_email"] = payload.admin_email
    return result


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
