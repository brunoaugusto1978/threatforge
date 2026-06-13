"""Autenticação, autorização e isolamento multi-tenant.

Princípios:
- Todo usuário pertence a um tenant (tenant_id), exceto o OPERADOR de plataforma
  (is_operator=True, tenant_id=None), que enxerga a visão da operação.
- Acesso via: sessão (cookie JWT) OU API key de tenant (header X-API-Key) OU a
  chave de plataforma do .env (API_KEY -> operador de serviço).
- `current_tenant_id` resolve o tenant EFETIVO de cada request. Toda query de
  dados sensíveis DEVE filtrar por esse tenant. Um tenant nunca acessa outro.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import ApiKey, OperatorTenantAccess, User, utcnow
from app.security import decode_token, hash_api_key

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

# papel efetivo de um operador quando atua DENTRO de um tenant (modo suporte)
OPERATOR_EFFECTIVE_ROLE = {
    "platform_admin": "admin",
    "support_operator": "analyst",
    "support_viewer": "viewer",
}


@dataclass
class Principal:
    subject: str
    role: str
    kind: str               # "user" | "service"
    is_operator: bool = False
    operator_role: str | None = None  # platform_admin|support_operator|support_viewer
    tenant_id: int | None = None
    user_id: int | None = None

    def effective_role(self) -> str:
        if self.is_operator:
            return OPERATOR_EFFECTIVE_ROLE.get(self.operator_role or "", "viewer")
        return self.role


def _from_platform_key(request: Request) -> Principal | None:
    api_key = request.headers.get("X-API-Key")
    if not api_key or not config.API_KEY:
        return None
    if hmac.compare_digest(api_key, config.API_KEY):
        # chave de plataforma do .env = super admin de serviço (cross-tenant total)
        return Principal(subject="platform-service", role="admin", kind="service",
                         is_operator=True, operator_role="platform_admin", tenant_id=None)
    return None


def _from_tenant_api_key(request: Request, db: Session) -> Principal | None:
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    digest = hash_api_key(api_key)
    row = db.scalar(select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.active == True))  # noqa: E712
    if row is None:
        return None
    row.last_used_at = utcnow()
    db.commit()
    return Principal(subject=f"apikey:{row.prefix}", role=row.role, kind="service",
                     is_operator=False, tenant_id=row.tenant_id)


def _from_cookie(request: Request, db: Session) -> Principal | None:
    token = request.cookies.get(config.COOKIE_NAME)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.is_active:
        return None
    if int(payload.get("pv", 0)) != user.pwd_version:
        return None
    return Principal(subject=user.email, role=user.role, kind="user",
                     is_operator=user.is_operator, operator_role=user.operator_role,
                     tenant_id=user.tenant_id, user_id=user.id)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    principal = (_from_platform_key(request) or _from_tenant_api_key(request, db)
                 or _from_cookie(request, db))
    if principal is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return principal


def require_role(minimum: str):
    min_rank = ROLE_RANK[minimum]

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        # papel efetivo respeita o papel do operador (support_viewer = só leitura)
        if ROLE_RANK.get(principal.effective_role(), 0) < min_rank:
            raise HTTPException(status_code=403,
                                detail=f"Acesso negado: requer papel '{minimum}' ou superior.")
        return principal

    return _dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


def require_operator(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_operator:
        raise HTTPException(status_code=403, detail="Access restricted to platform operators.")
    return principal


def require_platform_admin(principal: Principal = Depends(get_principal)) -> Principal:
    """Ações administrativas críticas: só Platform Admin / Super Admin."""
    if not (principal.is_operator and principal.operator_role == "platform_admin"):
        raise HTTPException(status_code=403,
                            detail="Action restricted to Platform Admin.")
    return principal


def operator_can_access_tenant(db: Session, principal: Principal, tenant_id: int) -> bool:
    if principal.operator_role == "platform_admin":
        return True
    # support_operator/support_viewer: precisa de acesso concedido e ativo
    row = db.scalar(select(OperatorTenantAccess).where(
        OperatorTenantAccess.operator_user_id == principal.user_id,
        OperatorTenantAccess.tenant_id == tenant_id,
        OperatorTenantAccess.is_active == True,  # noqa: E712
    ))
    return row is not None


def current_tenant_id(
    principal: Principal = Depends(get_principal),
    x_tenant_id: str | None = Header(default=None, alias=config.TENANT_HEADER),
    db: Session = Depends(get_db),
) -> int:
    """Tenant efetivo da request. Isolamento forte:
    - usuário/apikey de tenant: SEMPRE o próprio tenant_id (ignora header);
    - operador: indica o tenant via X-Tenant-Id E precisa ter acesso a ele
      (platform_admin acessa todos; support_* só os tenants atribuídos).
    """
    if not principal.is_operator:
        if principal.tenant_id is None:
            raise HTTPException(status_code=403, detail="Account has no associated tenant.")
        return principal.tenant_id
    if not x_tenant_id or not x_tenant_id.isdigit():
        raise HTTPException(status_code=400,
                            detail=f"Operator must provide the tenant in header {config.TENANT_HEADER}.")
    tid = int(x_tenant_id)
    if not operator_can_access_tenant(db, principal, tid):
        raise HTTPException(status_code=403,
                            detail="Operator has no access to this tenant.")
    return tid
