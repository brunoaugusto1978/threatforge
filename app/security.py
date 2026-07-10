"""Security: password hashing (PBKDF2-HMAC-SHA256) and JWT HS256 — stdlib only.

Sem dependências externas, reduzindo superfície de cadeia de suprimentos.
- Passwords: PBKDF2-HMAC-SHA256, per-user salt, 240k iterations.
- Session: JWT HS256 signed with JWT_SECRET, exp validation, comparison
  de assinatura em tempo constante.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

from app import config

PBKDF2_ITERATIONS = 240_000
PBKDF2_ALGO = "sha256"
SALT_BYTES = 16

# Argon2id is preferred; if the library is not installed, falls back to PBKDF2 (stdlib).
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError

    _ph = PasswordHasher()  # defaults secures (argon2id)
    _ARGON2 = True
except Exception:  # pragma: no cover - ambiente sem argon2-cffi
    _ARGON2 = False


# ---------- Política de password ----------
def check_password_strength(password: str) -> None:
    """Levanta ValueError se a password for fraca."""
    if not password or len(password) < 10:
        raise ValueError("password deve ter ao menos 10 caracteres")
    if len(password) > 256:
        raise ValueError("password muito longa (máx. 256)")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("password must accountin at least one letter and one number")


# ---------- Hash / verification ----------
def _pbkdf2_hash(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{PBKDF2_ALGO}${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def _pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        algo = scheme.split("_", 1)[1]
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, IndexError):
        return False


def hash_password(password: str) -> str:
    check_password_strength(password)
    if _ARGON2:
        return _ph.hash(password)
    return _pbkdf2_hash(password)


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("$argon2"):
        if not _ARGON2:
            return False
        try:
            return _ph.verify(stored, password)
        except (VerifyMismatchError, InvalidHashError, Exception):
            return False
    if stored.startswith("pbkdf2_"):
        return _pbkdf2_verify(password, stored)
    return False


def _server_secret_bytes() -> bytes:
    """Stable server-side secret used to protect high-entropy API keys at rest."""
    secret = getattr(config, "JWT_SECRET", "") or getattr(config, "API_KEY", "")
    if not secret:
        raise RuntimeError("JWT_SECRET or API_KEY must be configured for API key hashing.")
    return secret.encode("utf-8")


def _hmac_sha256(value: str, *, purpose: str) -> str:
    return hmac.new(
        _server_secret_bytes(),
        f"{purpose}:{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Gera uma API key de tenant. Retorna (chave_completa, prefix, hmac_sha256).

    The full key is displayed only once; the database stores prefix + keyed hash.
    Existing SHA-256-only API keys must be regenerated after this hardening.
    """
    secret = secrets.token_urlsafe(32)
    full = f"tfk_{secret}"
    prefix = full[:12]
    digest = hash_api_key(full)
    return full, prefix, digest


def hash_api_key(api_key: str) -> str:
    return f"hmac_sha256${_hmac_sha256(api_key, purpose='tenant-api-key')}"


def generate_invite_token() -> tuple[str, str]:
    """Returns (plaintext_token, sha256). Only the hash is stored."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_password(length: int = 16) -> str:
    """Gera password aleatória que sempre satisfaz check_password_strength."""
    import string

    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(max(12, length)))
        try:
            check_password_strength(pw)
            return pw
        except ValueError:
            continue


def needs_rehash(stored: str) -> bool:
    """True if the hash should be rewritten (PBKDF2->Argon2 migration or old parameters)."""
    if not _ARGON2:
        return False
    if not stored.startswith("$argon2"):
        return True
    try:
        return _ph.check_needs_rehash(stored)
    except Exception:
        return False


# ---------- JWT HS256 ----------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _secret() -> bytes:
    if not config.JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not configured")
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
    """Returns the payload if valid (signature + exp), otherwise None."""
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
