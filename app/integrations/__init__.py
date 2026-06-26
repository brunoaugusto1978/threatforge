"""Integration contract & registry (Community).

Community ships only **descriptors + public schemas + stubs**. The real
connectors (MISP/OpenCTI/...), API keys, scheduled sync, push/pull and the
required anti-SSRF validation live in ``threatforge-enterprise``, which calls
:func:`register_connector` to plug real implementations into this registry.

No outbound network calls, no SDKs (pymisp/pycti), and no secrets exist here —
keeping the open-source supply-chain/SSRF surface at zero.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, runtime_checkable

from app.features import EnterpriseFeatureRequired, Feature
from app.integrations import schemas


@dataclass(frozen=True)
class IntegrationDescriptor:
    name: str
    title: str
    feature: Feature
    capabilities: tuple[str, ...]
    config_schema: type
    premium: bool = True
    description: str = ""


@runtime_checkable
class Connector(Protocol):
    """Implemented in threatforge-enterprise; never in Community."""

    def test_connection(self, cfg) -> dict: ...

    def pull(self, cfg, since=None) -> Iterable[dict]: ...

    def push(self, cfg, items) -> dict: ...


REGISTRY: dict[str, IntegrationDescriptor] = {}
_IMPLS: dict[str, Connector] = {}


def register_descriptor(d: IntegrationDescriptor) -> None:
    REGISTRY[d.name] = d


def register_connector(name: str, impl: Connector) -> None:
    """Enterprise extension point: plug a real connector into the registry."""
    _IMPLS[name] = impl


def get_descriptor(name: str) -> IntegrationDescriptor | None:
    return REGISTRY.get(name)


def list_descriptors() -> list[IntegrationDescriptor]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def has_connector(name: str) -> bool:
    return name in _IMPLS


def get_connector(name: str) -> Connector:
    """Return the real connector or raise the gate if none is registered.

    In Community no connector is ever registered, so this always raises the
    Enterprise gate (the API layer blocks earlier with 402 anyway).
    """
    impl = _IMPLS.get(name)
    if impl is None:
        d = REGISTRY.get(name)
        raise EnterpriseFeatureRequired(d.feature if d else name)
    return impl


# --- Built-in descriptors (Community: stubs only) ---
register_descriptor(IntegrationDescriptor(
    name="misp", title="MISP", feature=Feature.INTEGRATION_MISP,
    capabilities=("pull_iocs", "push_iocs", "scheduled_sync"),
    config_schema=schemas.MispConfig,
    description="Sync indicators of compromise with a MISP instance."))

register_descriptor(IntegrationDescriptor(
    name="opencti", title="OpenCTI", feature=Feature.INTEGRATION_OPENCTI,
    capabilities=("pull_observables", "push_observables", "scheduled_sync"),
    config_schema=schemas.OpenctiConfig,
    description="Sync observables and indicators with an OpenCTI platform."))

register_descriptor(IntegrationDescriptor(
    name="generic", title="Generic / Webhook", feature=Feature.INTEGRATION_GENERIC,
    capabilities=("push_stix", "push_csv"),
    config_schema=schemas.GenericConfig,
    description="Push threat intel to a generic STIX/CSV endpoint."))
