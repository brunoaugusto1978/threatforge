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
from app.models import ApiKey, User, utcnow
from app.security import decode_token, hash_api_key

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class Principal:
    subject: str
    role: str
    kind: str               # "user" | "service"
    is_operator: bool = False
    tenant_id: int | None = None
    user_id: int | None = None


def _from_platform_key(request: Request) -> Principal | None:
    api_key = request.headers.get("X-API-Key")
    if not api_key or not config.API_KEY:
        return None
    if hmac.compare_digest(api_key, config.API_KEY):
        # chave de plataforma do .env = operador de serviço (cross-tenant)
        return Principal(subject="platform-service", role="admin", kind="service",
                         is_operator=True, tenant_id=None)
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
                     is_operator=user.is_operator, tenant_id=user.tenant_id, user_id=user.id)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    principal = (_from_platform_key(request) or _from_tenant_api_key(request, db)
                 or _from_cookie(request, db))
    if principal is None:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    return principal


def require_role(minimum: str):
    min_rank = ROLE_RANK[minimum]

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        # operador passa em qualquer checagem de papel de tenant
        if not principal.is_operator and ROLE_RANK.get(principal.role, 0) < min_rank:
            raise HTTPException(status_code=403,
                                detail=f"Acesso negado: requer papel '{minimum}' ou superior.")
        return principal

    return _dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


def require_operator(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_operator:
        raise HTTPException(status_code=403, detail="Acesso restrito ao operador de plataforma.")
    return principal


def current_tenant_id(
    principal: Principal = Depends(get_principal),
    x_tenant_id: str | None = Header(default=None, alias=config.TENANT_HEADER),
) -> int:
    """Tenant efetivo da request. Isolamento forte:
    - usuário/apikey de tenant: SEMPRE o próprio tenant_id (ignora header);
    - operador: precisa indicar o tenant via header X-Tenant-Id para atuar nele.
    """
    if not principal.is_operator:
        if principal.tenant_id is None:
            raise HTTPException(status_code=403, detail="Conta sem tenant associado.")
        return principal.tenant_id
    # operador precisa escolher um tenant para operar dados de tenant
    if not x_tenant_id or not x_tenant_id.isdigit():
        raise HTTPException(status_code=400,
                            detail=f"Operador deve indicar o tenant no header {config.TENANT_HEADER}.")
    return int(x_tenant_id)
