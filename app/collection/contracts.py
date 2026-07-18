"""Provider-neutral collection contracts (v0.11.0).

These dataclasses / Protocols are the *only* surface a collection provider (e.g.
Telegram) exposes to Community. Community never imports a provider SDK; it works
against these types. The private Enterprise package implements them.

Design rules:
- Nothing here stores a real secret. Providers receive a ``SecretRef`` and
  resolve it through the Secret Resolver, never a cleartext token.
- Nothing here stores the original provider payload. Providers hand back a
  :class:`NormalizedUpdate` whose ``raw_fingerprint`` is a hash of the original,
  plus already-redacted text — see :mod:`app.collection.envelope`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ProviderIdentity:
    """Non-secret identity of a provider account (e.g. Telegram getMe result).

    ``account_ref`` is the stable, **non-secret** external id (Telegram numeric
    bot id) persisted to ``collection_connection.provider_account_ref``. It must
    never be the bot token. Uniqueness of an active identity across tenants is
    enforced by the service layer (residual req #7).
    """
    provider: str
    account_ref: str
    display_name: str = ""
    username: str = ""


@dataclass(frozen=True)
class NormalizedUpdate:
    """A validated + normalised provider update, provider-neutral.

    ``raw_fingerprint`` is the SHA-256 of the original update as received by the
    provider (computed provider-side). The original itself is **not** carried in
    the POC. ``normalized`` holds only structured, non-sensitive-by-policy fields;
    ``redacted_text`` is the operator-facing redacted content.
    """
    provider: str
    external_id: str
    kind: str
    occurred_at: str  # ISO-8601 UTC
    normalized: dict[str, Any]
    redacted_text: str
    raw_fingerprint: str
    redaction_profile: str = "default"
    content_version: int = 1
    is_control: bool = False
    control_nonce_hash: str = ""


@dataclass(frozen=True)
class RejectionRecord:
    """Sanitised dead-letter entry for an update that failed validation.

    Deliberately carries no sensitive content (residual req #8): only a reason
    code, the provider, a *hashed* external id and a short sanitised detail.
    """
    provider: str
    reason_code: str
    external_id_hash: str
    sanitized_detail: str = ""
    context: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class CollectionProvider(Protocol):
    """Contract a collection provider must implement (Enterprise-side)."""

    name: str

    def fetch_identity(self, secret_ref: str) -> ProviderIdentity:
        """Resolve the account identity (getMe) using a Secret Resolver ref."""
        ...

    def normalize(self, raw: dict[str, Any]) -> NormalizedUpdate:
        """Validate + normalise + redact a single raw update."""
        ...


@runtime_checkable
class IntentClassifier(Protocol):
    """Contract for the (Enterprise) intent classifier. Not run in Phase 1."""

    name: str

    def classify(self, envelope: Any) -> dict[str, Any]:
        ...


@runtime_checkable
class Correlator(Protocol):
    """Contract for the (Enterprise) correlator. Not run in Phase 1."""

    name: str

    def correlate(self, envelope: Any) -> dict[str, Any]:
        ...
