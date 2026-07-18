"""Secret Resolver — channel/connection secret classification (req #3, corrective C3).

The DB never stores real channel/connection secrets. This module decides what is
secret and must go to the Secret Resolver, versus what is genuinely non-secret
and may live in ``config_json``.

ALWAYS secret (residual req #3): full webhook URL when it contains a token; the
Telegram bot token; the SMTP password; keys; equivalent credentials.

Corrective C3 (fail-closed): classification does NOT depend on a closed list of
field names alone. **Every string value that parses as a URL is analysed** — a
URL embedding a token is secret regardless of the field name. Channel-type
schemas (:data:`CHANNEL_ALLOWED_CONFIG`) further restrict what may remain in
``config_json`` for known channel types: unknown fields fail closed to secret
handling instead of silently persisting.

The opaque references returned by the resolver are meant to be **persisted**
(``secret_refs`` column) so the authorised provider can later resolve the real
value. Values themselves are never persisted by Community.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

# Field names that are always secret regardless of channel type.
_SECRET_FIELD_NAMES: frozenset[str] = frozenset({
    "token", "bot_token", "telegram_bot_token", "api_key", "api_token",
    "secret", "webhook_secret", "password", "smtp_password", "client_secret",
    "auth_key", "private_key", "signing_key", "key", "passphrase",
})

# Per-channel-type allowlists of genuinely non-secret config fields (C3).
# A field NOT in the allowlist for a known channel type fails closed: it is
# routed to the Secret Resolver rather than persisted in config_json.
PROVIDER_ALLOWED_CONFIG: dict[str, frozenset[str]] = {
    # Connection-level, non-secret Telegram options. Unknown fields fail closed.
    "telegram": frozenset({"bot_username", "api_base_url",
                              "poll_timeout_seconds", "allowed_updates"}),
}

CHANNEL_ALLOWED_CONFIG: dict[str, frozenset[str]] = {
    "telegram": frozenset({"chat_id", "thread_id", "parse_mode", "bot_username"}),
    "webhook": frozenset({"method", "content_type", "timeout_seconds"}),
    "email": frozenset({"smtp_host", "smtp_port", "smtp_from", "smtp_to",
                        "starttls", "subject_prefix"}),
    "smtp": frozenset({"smtp_host", "smtp_port", "smtp_from", "smtp_to",
                       "starttls", "subject_prefix"}),
}

_TOKENISH_QUERY_KEYS = ("token", "key", "secret", "access_token", "hub.verify_token",
                        "auth", "signature", "sig", "apikey", "api_key")
_TELEGRAM_BOT_PATH = re.compile(r"/bot\d+:[A-Za-z0-9_-]+", re.IGNORECASE)
_LONG_TOKEN_SEG = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_URL_VALUE = re.compile(r"^\s*https?://", re.IGNORECASE)

ENV_SECRET_REF_PREFIX = "secretref://env/"
FILE_SECRET_REF_PREFIX = "secretref://file/"
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")


def validate_opaque_ref(ref: str) -> str:
    """Validate a supported opaque secret reference without resolving it.

    Phase 2A supports environment-backed refs for the controlled POC.  The
    variable name is non-secret, must use the ThreatForge namespace, and the
    referenced value is never returned by API serializers.
    """
    value = str(ref or "").strip()
    if value.startswith(ENV_SECRET_REF_PREFIX):
        env_name = value[len(ENV_SECRET_REF_PREFIX):]
        if not _ENV_NAME_RE.fullmatch(env_name) or not env_name.startswith("THREATFORGE_"):
            raise ValueError("invalid_environment_secret_reference")
        return value
    if value.startswith(FILE_SECRET_REF_PREFIX):
        name = value[len(FILE_SECRET_REF_PREFIX):]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,126}", name):
            raise ValueError("invalid_file_secret_reference")
        return value
    raise ValueError("unsupported_secret_reference")


def resolve_opaque_ref(ref: str) -> str | None:
    """Resolve a supported opaque reference through the configured resolver."""
    value = str(ref or "").strip()
    if value.startswith(ENV_SECRET_REF_PREFIX):
        try:
            validate_opaque_ref(value)
        except ValueError:
            return None
        return os.getenv(value[len(ENV_SECRET_REF_PREFIX):]) or None
    if value.startswith(FILE_SECRET_REF_PREFIX):
        try:
            validate_opaque_ref(value)
            root = Path(os.getenv("THREATFORGE_SECRET_DIR", "/run/secrets")).resolve()
            candidate = root / value[len(FILE_SECRET_REF_PREFIX):]
            if candidate.is_symlink():
                return None
            path = candidate.resolve()
            if path.parent != root or not path.is_file():
                return None
            if path.stat().st_size > 8192:
                return None
            return path.read_text(encoding="utf-8").strip() or None
        except (OSError, UnicodeError, ValueError):
            return None
    return get_resolver().get(value)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def looks_like_url(value: Any) -> bool:
    return isinstance(value, str) and bool(_URL_VALUE.match(value))


def webhook_url_is_secret(url: str) -> bool:
    """True if a webhook URL embeds a token/credential and must be treated secret.

    Fail-closed: an unparsable URL is treated as secret.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url.strip())
    except Exception:
        return True  # unparsable → fail closed
    if parts.username or parts.password:
        return True
    q = parts.query.lower()
    if any(f"{k}=" in q for k in _TOKENISH_QUERY_KEYS):
        return True
    if _TELEGRAM_BOT_PATH.search(parts.path or ""):
        return True
    for seg in (parts.path or "").split("/"):
        if _LONG_TOKEN_SEG.match(seg):
            return True
    return False


@dataclass(frozen=True)
class SecretRef:
    """Opaque reference to a value held by the Secret Resolver (not the value)."""
    name: str
    kind: str
    present: bool = True
    hint: str = "***"
    digest: str = ""  # sha256 of the value, change detection only


@dataclass
class ChannelSecretSplit:
    """Result of classifying a channel/connection payload."""
    config_json: dict[str, Any] = field(default_factory=dict)
    secret_refs: list[SecretRef] = field(default_factory=list)
    secret_values: dict[str, str] = field(default_factory=dict)  # transient, never persisted

    @property
    def secrets_metadata(self) -> dict[str, Any]:
        return {
            r.name: {"present": r.present, "kind": r.kind, "masked": r.hint}
            for r in self.secret_refs
        }


class SecretResolver(Protocol):
    def put(self, tenant_id: int, scope: str, name: str, value: str) -> str: ...
    def get(self, ref: str) -> str | None: ...
    def delete(self, ref: str) -> None: ...


class NullSecretResolver:
    """POC default: never persists a value; refs are write-only.

    Suitable only where real credentials are never used. Deployments needing
    later resolution must inject a real resolver via :func:`set_resolver`.
    """

    def put(self, tenant_id: int, scope: str, name: str, value: str) -> str:
        return f"secretref://null/{int(tenant_id)}/{scope}/{name}/{_sha256(value)[:12]}"

    def get(self, ref: str) -> str | None:
        return None

    def delete(self, ref: str) -> None:
        return None


class InMemorySecretResolver:
    """Process-memory resolver for tests/dev: refs resolve back to the value.

    Nothing touches disk or DB; the mapping dies with the process. This is the
    reference implementation of the "authorised provider can later resolve the
    secret via its stored ref" contract (corrective C3).
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._n = 0

    def put(self, tenant_id: int, scope: str, name: str, value: str) -> str:
        self._n += 1
        ref = f"secretref://mem/{int(tenant_id)}/{scope}/{name}/{self._n}"
        self._store[ref] = value
        return ref

    def get(self, ref: str) -> str | None:
        return self._store.get(ref)

    def delete(self, ref: str) -> None:
        self._store.pop(ref, None)


_resolver: SecretResolver = NullSecretResolver()


def set_resolver(resolver: SecretResolver) -> None:
    global _resolver
    _resolver = resolver


def get_resolver() -> SecretResolver:
    return _resolver


def classify_payload(payload: dict[str, Any],
                     channel_type: str | None = None,
                     provider: str | None = None) -> ChannelSecretSplit:
    """Split an incoming payload into non-secret config vs secrets (fail-closed).

    Order of rules per field:
      1. name in the always-secret list → secret;
      2. value is a URL embedding a token → secret (ANY field name — C3);
      3. known ``channel_type`` and field not in its allowlist → secret
         (fail closed rather than persisting an unknown field);
      4. otherwise → non-secret ``config_json``.
    """
    channel_key = (channel_type or "").strip().lower()
    provider_key = (provider or "").strip().lower()
    if channel_type is not None:
        # A declared but unknown channel type is fail-closed.
        allowed = CHANNEL_ALLOWED_CONFIG.get(channel_key, frozenset())
    elif provider is not None:
        # Connection payloads are also schema-bound by provider.
        allowed = PROVIDER_ALLOWED_CONFIG.get(provider_key, frozenset())
    else:
        # Backwards-compatible generic classifier: known secret names and
        # token-bearing URLs are still caught, but callers creating persisted
        # connection/channel records MUST pass provider/channel_type.
        allowed = None
    split = ChannelSecretSplit()
    for raw_key, value in (payload or {}).items():
        key = str(raw_key).strip().lower()
        if key in _SECRET_FIELD_NAMES:
            _add_secret(split, key, "credential", value)
            continue
        if looks_like_url(value) and webhook_url_is_secret(value):
            _add_secret(split, key, "webhook_url_with_token", value)
            continue
        if allowed is not None and key not in allowed:
            # fail closed: unknown field for a known channel type
            _add_secret(split, key, "unclassified_fail_closed", value)
            continue
        split.config_json[raw_key] = value
    return split


def _add_secret(split: ChannelSecretSplit, name: str, kind: str, value: Any) -> None:
    sval = "" if value is None else str(value)
    split.secret_values[name] = sval
    split.secret_refs.append(
        SecretRef(name=name, kind=kind, present=bool(sval),
                  digest=_sha256(sval) if sval else "")
    )


def persist_secrets(tenant_id: int, scope: str, split: ChannelSecretSplit) -> dict[str, str]:
    """Hand secret values to the resolver; return {name: opaque_ref}.

    The returned mapping MUST be persisted by the caller (``secret_refs``
    column) so the authorised provider can later resolve the values. Cleartext
    values are dropped from the split before returning.
    """
    refs: dict[str, str] = {}
    for name, value in split.secret_values.items():
        refs[name] = get_resolver().put(tenant_id, scope, name, value)
    split.secret_values.clear()
    return refs


def resolve_secret(secret_refs: dict[str, str], name: str) -> str | None:
    """Resolve one named secret through its stored opaque ref (authorised path)."""
    ref = (secret_refs or {}).get(name)
    if not ref:
        return None
    return resolve_opaque_ref(ref)
