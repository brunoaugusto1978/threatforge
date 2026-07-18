"""EvidenceEnvelope — the provider-neutral evidence unit (v0.11.0).

Residual requirement #10 (evidence-limit honesty). The envelope preserves:

  * a **cryptographic fingerprint** of the *normalised, versioned* update
    (``normalized_fingerprint``);
  * the **redacted content** used in the operation (``redacted_text``);
  * minimal non-sensitive metadata and provenance links.

It explicitly does **not** claim custody of the original provider payload. In the
POC ``original_custody`` is always ``False``. The isolated hash MUST NOT be
described as full preservation of the original evidence — see
:meth:`EvidenceEnvelope.custody_statement`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "evidence-envelope/1"
_FINGERPRINT_ALG = "sha256"

# The exact custody wording mandated by residual requirement #10. Surfaced by
# docs and UI; do NOT paraphrase into a stronger claim.
CUSTODY_STATEMENT_PT = (
    "O ThreatForge preserva uma impressão digital criptográfica do update "
    "normalizado e versionado, além do conteúdo redigido utilizado na operação. "
    "A POC não mantém custódia do payload original."
)


def canonical_json(data: Any) -> str:
    """Deterministic JSON used for hashing: sorted keys, tight separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint_normalized(normalized: dict[str, Any], content_version: int) -> str:
    """SHA-256 over the *versioned* normalised update.

    The version is folded into the hashed material so two structurally identical
    updates produced under different normalisation versions do not collide.
    """
    material = canonical_json({"v": int(content_version), "n": normalized})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceEnvelope:
    """Immutable evidence record handed between collection → analysis seams."""

    provider: str
    tenant_id: int
    source_ref: str
    normalized_fingerprint: str
    redacted_text: str
    content_version: int = 1
    redaction_profile: str = "default"
    fingerprint_alg: str = _FINGERPRINT_ALG
    schema_version: str = SCHEMA_VERSION
    occurred_at: str = ""
    raw_fingerprint: str = ""  # hash of original (provider-side); original not stored
    original_custody: bool = False  # POC: never true
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_normalized(
        cls,
        *,
        provider: str,
        tenant_id: int,
        source_ref: str,
        normalized: dict[str, Any],
        redacted_text: str,
        content_version: int = 1,
        redaction_profile: str = "default",
        occurred_at: str = "",
        raw_fingerprint: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "EvidenceEnvelope":
        return cls(
            provider=provider,
            tenant_id=int(tenant_id),
            source_ref=str(source_ref),
            normalized_fingerprint=fingerprint_normalized(normalized, content_version),
            redacted_text=redacted_text,
            content_version=int(content_version),
            redaction_profile=redaction_profile,
            occurred_at=occurred_at,
            raw_fingerprint=raw_fingerprint,
            original_custody=False,
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def custody_statement() -> str:
        """Mandated evidence-limit disclosure (residual req #10)."""
        return CUSTODY_STATEMENT_PT
