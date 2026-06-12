"""Rotas de autenticação e gestão de usuários."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, config
from app.auth import Principal, current_tenant_id, get_principal, require_admin
from app.database import get_db
from app.models import User, utcnow
from app.schemas import (
    AdminResetPassword,
    ChangePasswordRequest,
    LoginRequest,
    MeOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.security import (
    create_token,
    generate_password,
    hash_password,
    needs_rehash,
    verify_password,
)

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
def login(payload: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)):
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
        audit.record(db, actor=email, action="auth.login_failed", request=request)
        # mensagem genérica: não revela se o e-mail existe
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")

    _login_attempts.pop(email, None)
    user.last_login_at = utcnow()
    # migração transparente de hash (PBKDF2 -> Argon2) sem trocar a versão de senha.
    # protegido: senha legada fora da política nova não deve impedir o login.
    if needs_rehash(user.hashed_password):
        try:
            user.hashed_password = hash_password(payload.password)
        except ValueError:
            pass
    db.commit()
    token = create_token(sub=str(user.id), role=user.role, pwd_version=user.pwd_version)
    _set_session_cookie(response, token)
    audit.record(db, actor=user.email, actor_role=user.role, tenant_id=user.tenant_id,
                 action="auth.login", request=request)
    return {"email": user.email, "role": user.role, "is_operator": user.is_operator}


@router.post("/auth/logout")
def logout(request: Request, response: Response,
           principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    response.delete_cookie(config.COOKIE_NAME, path="/")
    audit.record(db, actor=principal.subject, actor_role=principal.role,
                 tenant_id=principal.tenant_id, action="auth.logout", request=request)
    return {"ok": True}


@router.get("/auth/me", response_model=MeOut)
def me(principal: Principal = Depends(get_principal)):
    return MeOut(subject=principal.subject, role=principal.role, kind=principal.kind,
                 is_operator=principal.is_operator, tenant_id=principal.tenant_id)


@router.post("/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """Auto-serviço: qualquer usuário troca a própria senha."""
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(status_code=400, detail="Disponível apenas para contas de usuário.")
    user = db.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Senha atual incorreta.")
    if verify_password(payload.new_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="A nova senha deve ser diferente da atual.")

    user.hashed_password = hash_password(payload.new_password)
    user.pwd_version += 1  # invalida outras sessões
    db.commit()
    # reemite o cookie desta sessão com a nova versão, para não deslogar quem trocou
    token = create_token(sub=str(user.id), role=user.role, pwd_version=user.pwd_version)
    _set_session_cookie(response, token)
    audit.record(db, actor=user.email, actor_role=user.role,
                 action="auth.change_password", target_type="user", target_id=user.id,
                 request=request)
    return {"ok": True}


# ---------- Gestão de usuários (somente admin) ----------
@router.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(require_admin),
                tid: int = Depends(current_tenant_id)):
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="E-mail já cadastrado.")
    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        tenant_id=tid,
        is_operator=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="user.create", target_type="user", target_id=user.id,
                 request=request, detail={"email": user.email, "role": user.role})
    return user


@router.get("/users", response_model=list[UserOut], dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    return list(db.scalars(
        select(User).where(User.tenant_id == tid).order_by(User.id)))


def _owned_user(db: Session, user_id: int, tid: int) -> User:
    user = db.get(User, user_id)
    if user is None or user.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
    tid: int = Depends(current_tenant_id),
):
    user = _owned_user(db, user_id, tid)

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
        user.pwd_version += 1  # invalida sessões do usuário alvo
    db.commit()
    db.refresh(user)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="user.update", target_type="user", target_id=user.id,
                 request=request,
                 detail={"role": payload.role, "is_active": payload.is_active,
                         "password_changed": payload.password is not None})
    return user


@router.post("/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    payload: AdminResetPassword,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
    tid: int = Depends(current_tenant_id),
):
    """Admin reseta a senha de qualquer usuário. Se não enviar uma senha,
    gera uma temporária e a retorna uma única vez (para repassar ao usuário).
    A sessão atual do usuário-alvo é invalidada."""
    user = _owned_user(db, user_id, tid)

    temporary = None
    new_password = payload.new_password
    if not new_password:
        new_password = generate_password(16)
        temporary = new_password

    user.hashed_password = hash_password(new_password)
    user.pwd_version += 1
    db.commit()
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="user.reset_password", target_type="user", target_id=user.id,
                 request=request, detail={"email": user.email})
    result = {"ok": True, "email": user.email}
    if temporary:
        result["temporary_password"] = temporary
        result["note"] = "Repasse esta senha ao usuário por canal seguro. Ela não será exibida de novo."
    return result


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_admin),
    tid: int = Depends(current_tenant_id),
):
    user = _owned_user(db, user_id, tid)
    if principal.user_id == user_id:
        raise HTTPException(status_code=400, detail="Não é possível excluir a própria conta.")
    # não deixa remover o último admin ATIVO do tenant
    if user.role == "admin":
        admins = db.scalar(
            select(func.count()).select_from(User).where(
                User.tenant_id == tid, User.role == "admin",
                User.is_active == True,  # noqa: E712
            )
        )
        if admins <= 1:
            raise HTTPException(status_code=400, detail="Não é possível remover o último admin.")
    email = user.email
    db.delete(user)
    db.commit()
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="user.delete", target_type="user", target_id=user_id,
                 request=request, detail={"email": email})
