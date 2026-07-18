"""Provider-neutral collection contracts for ThreatForge v0.11.0.

Community owns these public shapes.  The private Enterprise package implements
structurally compatible providers without importing Community models or DB code.
Secrets cross the seam only as opaque references.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ProviderIdentity:
    provider: str
    account_ref: str
    display_name: str = ""
    username: str = ""


@dataclass(frozen=True)
class NormalizedUpdate:
    provider: str
    external_id: str
    kind: str
    occurred_at: str
    normalized: dict[str, Any]
    redacted_text: str
    raw_fingerprint: str
    redaction_profile: str = "default"
    content_version: int = 1
    is_control: bool = False
    control_nonce_hash: str = ""


@dataclass(frozen=True)
class RejectionRecord:
    provider: str
    reason_code: str
    external_id_hash: str
    sanitized_detail: str = ""
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderDiagnostic:
    code: str
    state: str = "degraded"
    retry_after_seconds: int | None = None
    http_status: int | None = None


@dataclass(frozen=True)
class ProviderHealth:
    state: str
    checked_at: str
    last_success_at: str = ""
    last_event_at: str = ""
    lag_seconds: int | None = None
    error_code: str = ""
    retry_after_seconds: int | None = None


@dataclass(frozen=True)
class ConnectionTestResult:
    ok: bool
    identity: ProviderIdentity | None
    health: ProviderHealth
    diagnostic: ProviderDiagnostic | None = None


@dataclass(frozen=True)
class CollectionBatch:
    """One bounded provider poll; raw updates are transient and never persisted."""

    updates: tuple[dict[str, Any], ...]
    next_cursor: str | None
    health: ProviderHealth


@runtime_checkable
class CollectionProvider(Protocol):
    name: str

    def fetch_identity(self, secret_ref: str) -> ProviderIdentity: ...

    def test_connection(
        self, secret_ref: str, config: dict[str, Any] | None = None
    ) -> ConnectionTestResult: ...

    def poll(
        self,
        secret_ref: str,
        cursor: str | None,
        config: dict[str, Any] | None = None,
    ) -> CollectionBatch: ...

    def source_ref(self, raw: dict[str, Any]) -> str: ...

    def normalize(self, raw: dict[str, Any]) -> NormalizedUpdate: ...


@runtime_checkable
class IntentClassifier(Protocol):
    name: str

    def classify(self, envelope: Any) -> dict[str, Any]: ...


@runtime_checkable
class Correlator(Protocol):
    name: str

    def correlate(self, envelope: Any) -> dict[str, Any]: ...
