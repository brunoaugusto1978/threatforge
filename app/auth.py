"""Autenticação por API key (header X-API-Key), comparação em tempo constante."""
import hmac

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app import config

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    if not config.API_KEY:
        raise HTTPException(
            status_code=503,
            detail="API_KEY não configurada no servidor. Defina a variável de ambiente API_KEY.",
        )
    if not api_key or not hmac.compare_digest(api_key, config.API_KEY):
        raise HTTPException(status_code=401, detail="API key inválida ou ausente.")
