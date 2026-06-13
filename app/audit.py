"""Audit trail for sensitive actions.

Never logs passwords, tokens or secrets — only action metadata.
"""
from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)

# chaves que jamais devem ser persistidas no detalhe do log
_REDACT = {"password", "current_password", "new_password", "temporary_password",
           "token", "api_key", "secret", "hashed_password"}


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def _user_agent(request: Request | None) -> str | None:
    if request is None:
        return None
    ua = request.headers.get("user-agent")
    return ua[:400] if ua else None


def _sanitize(detail: dict | None) -> dict | None:
    if not detail:
        return None
    return {k: ("***" if k.lower() in _REDACT else v) for k, v in detail.items()}


def record(
    db: Session,
    *,
    actor: str,
    actor_role: str | None = None,
    action: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    tenant_id: int | None = None,
    operator_user_id: int | None = None,
    request: Request | None = None,
    detail: dict | None = None,
    commit: bool = True,
) -> None:
    """Writes an audit event. Audit failure does not break the action."""
    try:
        entry = AuditLog(
            tenant_id=tenant_id,
            actor=actor[:255],
            actor_role=actor_role,
            operator_user_id=operator_user_id,
            action=action[:60],
            target_type=target_type,
            target_id=str(target_id)[:80] if target_id is not None else None,
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            detail=_sanitize(detail),
        )
        db.add(entry)
        if commit:
            db.commit()
    except Exception as exc:  # never interrupts the main flow
        logger.warning("Falha ao gravar audit log (%s): %s", action, type(exc).__name__)
        db.rollback()
