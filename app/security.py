"""Segurança: hash de senha (PBKDF2-HMAC-SHA256) e JWT HS256 — só stdlib.

Sem dependências externas, reduzindo superfície de cadeia de suprimentos.
- Senhas: PBKDF2-HMAC-SHA256, salt por usuário, 240k iterações.
- Sessão: JWT HS256 assinado com JWT_SECRET, validação de exp, comparação
  de assinatura em tempo constante.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from app import config

PBKDF2_ITERATIONS = 240_000
PBKDF2_ALGO = "sha256"
SALT_BYTES = 16


# ---------- Senhas ----------
def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("senha deve ter ao menos 8 caracteres")
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{PBKDF2_ALGO}${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        algo = scheme.split("_", 1)[1]
        dk = hashlib.pbkdf2_hmac(
            algo, password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, IndexError):
        return False


# ---------- JWT HS256 ----------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _secret() -> bytes:
    if not config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET não configurado")
    return config.JWT_SECRET.encode()


def create_token(sub: str, role: str, pwd_version: int = 1, ttl_seconds: int | None = None) -> str:
    ttl = ttl_seconds or config.JWT_TTL_SECONDS
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub, "role": role, "pv": pwd_version,
        "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8),
    }
    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode()
    sig = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
    segments.append(_b64url(sig))
    return ".".join(segments)


def decode_token(token: str) -> dict | None:
    """Retorna o payload se válido (assinatura + exp), senão None."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
    try:
        provided = _b64url_decode(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected, provided):
        return None
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
