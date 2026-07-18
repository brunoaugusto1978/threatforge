"""Provider-neutral collection & analysis seams (ThreatForge v0.11.0).

NOTE: this package __init__ imports only the PURE submodules (no SQLAlchemy),
so the contracts/registry/envelope seams stay importable in minimal
environments. ``service``/``ingest``/``analysis``/``retention`` require
SQLAlchemy and are imported explicitly as submodules.

This package holds the *Community* half of the Telegram Intelligence feature:
provider-neutral contracts, registries, the EvidenceEnvelope, the Secret
Resolver, outbox idempotency, the TF-VERIFY control-message handling, the
ingestion transaction/cursor flow and the retention purge.

The real Telegram Bot API provider and the intent classifier are **not** here —
they live in the private ``threatforge-enterprise`` package and register
themselves through :mod:`app.collection.registry`. Community keeps no real
secrets and (in the POC) keeps no custody of the original provider payload;
see :mod:`app.collection.envelope`.
"""
from __future__ import annotations

from app.collection import states
from app.collection.contracts import (
    NormalizedUpdate,
    ProviderIdentity,
    RejectionRecord,
)
from app.collection.envelope import EvidenceEnvelope
from app.collection.registry import (
    classifiers,
    correlators,
    providers,
)

__all__ = [
    "states",
    "NormalizedUpdate",
    "ProviderIdentity",
    "RejectionRecord",
    "EvidenceEnvelope",
    "providers",
    "classifiers",
    "correlators",
]
