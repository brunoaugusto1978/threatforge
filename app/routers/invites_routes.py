"""Aceite de convite (público). Não exige autenticação — o token É a prova.

O cliente nunca escolhe o tenant: o vínculo vem do convite.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app import invites
from app.database import get_db
from app.routers.auth_routes import _set_session_cookie
from app.schemas import InviteAccept, InviteValidateOut
from app.security import create_token

router = APIRouter(tags=["invites"])


@router.get("/invites/validate", response_model=InviteValidateOut)
def validate_invite(token: str, db: Session = Depends(get_db)):
    if not token:
        return InviteValidateOut(valid=False, reason="Token ausente.")
    result = invites.validate_token(db, token)
    return InviteValidateOut(**result)


@router.post("/invites/accept")
def accept_invite(payload: InviteAccept, request: Request, response: Response,
                  db: Session = Depends(get_db)):
    try:
        user = invites.accept(db, payload.token, payload.password, request=request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # já autentica o usuário recém-ativado
    token = create_token(sub=str(user.id), role=user.role, pwd_version=user.pwd_version)
    _set_session_cookie(response, token)
    return {"email": user.email, "role": user.role, "tenant_id": user.tenant_id}
