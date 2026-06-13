"""Tenant invitation logic: creation, link generation, e-mail delivery and acceptance."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy.orm import Session

from app import audit, config, mailer
from app.models import Tenant, TenantInvite, User, utcnow
from app.security import generate_invite_token, hash_password, hash_token


def _expired(expires_at: datetime) -> bool:
    """Comparação robusta: alguns bancos (SQLite) devolvem datetime naive."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < utcnow()


def build_accept_url(token: str) -> str:
    return f"{config.APP_BASE_URL}/invite/accept?token={token}"


def create_invite(
    db: Session, *, tenant: Tenant, email: str, role: str, user: User | None,
    invited_by: str, request: Request | None = None,
) -> dict:
    """Creates a pending invite, generates a token, stores its hash, sends e-mail and audits the event.
    Retorna dados + link (o link só é exibido aqui/no log; o token não é persistido)."""
    # invalida convites pendentes anteriores para o mesmo e-mail/tenant
    olds = db.query(TenantInvite).filter(
        TenantInvite.tenant_id == tenant.id, TenantInvite.email == email,
        TenantInvite.status == "pending",
    ).all()
    for o in olds:
        o.status = "revoked"

    token, token_hash = generate_invite_token()
    invite = TenantInvite(
        tenant_id=tenant.id, user_id=(user.id if user else None), email=email, role=role,
        token_hash=token_hash, status="pending",
        expires_at=utcnow() + timedelta(hours=config.INVITE_TTL_HOURS),
        invited_by=invited_by,
    )
    db.add(invite)
    db.commit()
    db.refresh(invite)

    link = build_accept_url(token)
    sent = mailer.send_invite(email, tenant.name, link)
    audit.record(db, actor=invited_by, actor_role="operator", tenant_id=tenant.id,
                 action="invite.create", target_type="invite", target_id=invite.id,
                 request=request, detail={"email": email, "email_sent": sent})
    audit.record(db, actor=invited_by, actor_role="operator", tenant_id=tenant.id,
                 action="invite.send", target_type="invite", target_id=invite.id,
                 request=request, detail={"email_sent": sent})
    return {"invite": invite, "link": link, "email_sent": sent}


def _resolve(db: Session, token: str) -> TenantInvite | None:
    return db.query(TenantInvite).filter(
        TenantInvite.token_hash == hash_token(token)).first()


def validate_token(db: Session, token: str) -> dict:
    invite = _resolve(db, token)
    if invite is None:
        return {"valid": False, "reason": "Invalid invite."}
    if invite.status == "accepted":
        return {"valid": False, "reason": "Invite already used."}
    if invite.status == "revoked":
        return {"valid": False, "reason": "Invite revoked."}
    if invite.status == "expired" or _expired(invite.expires_at):
        if invite.status == "pending":
            invite.status = "expired"
            db.commit()
        return {"valid": False, "reason": "Invite expired."}
    tenant = db.get(Tenant, invite.tenant_id)
    return {"valid": True, "email": invite.email,
            "tenant_name": tenant.name if tenant else None}


def accept(db: Session, token: str, password: str, request: Request | None = None) -> User:
    invite = _resolve(db, token)
    if invite is None:
        raise ValueError("Invalid invite.")
    if invite.status != "pending":
        raise ValueError("Invite already used or revoked.")
    if _expired(invite.expires_at):
        invite.status = "expired"
        db.commit()
        raise ValueError("Invite expired.")

    # ativa/cria o usuário vinculado AO TENANT do convite (cliente não escolhe tenant)
    user = db.get(User, invite.user_id) if invite.user_id else None
    if user is None:
        user = db.query(User).filter(User.email == invite.email).first()
    if user is None:
        user = User(email=invite.email, role=invite.role, is_operator=False,
                    tenant_id=invite.tenant_id)
        db.add(user)
    user.hashed_password = hash_password(password)
    user.role = invite.role
    user.tenant_id = invite.tenant_id  # forçado pelo convite
    user.is_operator = False
    user.is_active = True
    user.pwd_version += 1  # invalida qualquer sessão anterior

    invite.status = "accepted"
    invite.accepted_at = utcnow()
    invite.user_id = user.id if user.id else invite.user_id
    db.commit()
    db.refresh(user)
    audit.record(db, actor=user.email, actor_role=user.role, tenant_id=invite.tenant_id,
                 action="invite.accept", target_type="invite", target_id=invite.id,
                 request=request)
    return user
