"""Rotas de autenticação e gestão de usuários."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config
from app.auth import Principal, get_principal, require_admin
from app.database import get_db
from app.models import User, utcnow
from app.schemas import (
    LoginRequest,
    MeOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.security import create_token, hash_password, verify_password

router = APIRouter(tags=["auth"])

# limitador simples de tentativas de login por e-mail (em memória, best-effort)
_login_attempts: dict[str, list[float]] = {}
_MAX_ATTEMPTS = 5
_WINDOW = 300.0  # 5 min


def _rate_limited(key: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < _WINDOW]
    _login_attempts[key] = attempts
    return len(attempts) >= _MAX_ATTEMPTS


def _record_attempt(key: str) -> None:
    _login_attempts.setdefault(key, []).append(time.time())


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=config.COOKIE_NAME,
        value=token,
        max_age=config.JWT_TTL_SECONDS,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


@router.post("/auth/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    if _rate_limited(email):
        raise HTTPException(
            status_code=429, detail="Muitas tentativas. Aguarde alguns minutos."
        )

    user = db.scalar(select(User).where(User.email == email))
    # comparação sempre executa hash para mitigar timing/enumeração de usuário
    ok = bool(user) and user.is_active and verify_password(payload.password, user.hashed_password)
    if not ok:
        _record_attempt(email)
        # mensagem genérica: não revela se o e-mail existe
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")

    _login_attempts.pop(email, None)
    user.last_login_at = utcnow()
    db.commit()
    token = create_token(sub=str(user.id), role=user.role)
    _set_session_cookie(response, token)
    return {"email": user.email, "role": user.role}


@router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(config.COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/auth/me", response_model=MeOut)
def me(principal: Principal = Depends(get_principal)):
    return MeOut(subject=principal.subject, role=principal.role, kind=principal.kind)


# ---------- Gestão de usuários (somente admin) ----------
@router.post("/users", response_model=UserOut, status_code=201,
             dependencies=[Depends(require_admin)])
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="E-mail já cadastrado.")
    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=list[UserOut], dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db)):
    return list(db.scalars(select(User).order_by(User.id)))


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    # proteção: admin não pode rebaixar/desativar a si mesmo (evita lockout)
    if principal.user_id == user_id:
        if payload.role is not None and payload.role != "admin":
            raise HTTPException(status_code=400, detail="Não é possível rebaixar a própria conta.")
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="Não é possível desativar a própria conta.")

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password is not None:
        user.hashed_password = hash_password(payload.password)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if principal.user_id == user_id:
        raise HTTPException(status_code=400, detail="Não é possível excluir a própria conta.")
    # não deixa remover o último admin ativo
    if user.role == "admin":
        admins = db.scalar(
            select(func.count()).select_from(User).where(
                User.role == "admin", User.is_active == True  # noqa: E712
            )
        )
        if admins <= 1:
            raise HTTPException(status_code=400, detail="Não é possível remover o último admin.")
    db.delete(user)
    db.commit()
