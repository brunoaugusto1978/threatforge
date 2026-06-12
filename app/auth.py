"""Autenticação e autorização.

Dois modos de acesso:
  1. Sessão de usuário (cookie httpOnly com JWT) — usada pela interface web.
  2. API key de serviço (header X-API-Key) — para automação/cron, papel admin.

RBAC: viewer < analyst < admin. Dependências prontas:
  require_viewer, require_analyst, require_admin.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import User
from app.security import decode_token

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class Principal:
    subject: str
    role: str
    kind: str  # "user" | "service"
    user_id: int | None = None


def _from_api_key(request: Request) -> Principal | None:
    api_key = request.headers.get("X-API-Key")
    if not api_key or not config.API_KEY:
        return None
    if hmac.compare_digest(api_key, config.API_KEY):
        return Principal(subject="service", role="admin", kind="service")
    return None


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
    # senha trocada/resetada após emissão do token -> sessão inválida
    if int(payload.get("pv", 0)) != user.pwd_version:
        return None
    # papel atual do banco prevalece (revoga acesso se mudou)
    return Principal(subject=user.email, role=user.role, kind="user", user_id=user.id)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    principal = _from_api_key(request) or _from_cookie(request, db)
    if principal is None:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    return principal


def require_role(minimum: str):
    min_rank = ROLE_RANK[minimum]

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if ROLE_RANK.get(principal.role, 0) < min_rank:
            raise HTTPException(
                status_code=403,
                detail=f"Acesso negado: requer papel '{minimum}' ou superior.",
            )
        return principal

    return _dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
