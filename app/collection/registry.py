"""Provider-neutral registries for collection providers, classifiers, correlators.

Community ships these registries **empty**. The private ``threatforge-enterprise``
package populates them at import time via :func:`providers.register` (and the
classifier/correlator equivalents). This keeps Community provider-neutral: it can
enumerate and dispatch to whatever is registered without importing any provider
SDK. Registration is idempotent and thread-unaware (single-process POC).
"""
from __future__ import annotations

from typing import Generic, Iterator, TypeVar

T = TypeVar("T")


class _Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._items: dict[str, T] = {}

    def register(self, name: str, impl: T, *, replace: bool = False) -> T:
        key = str(name).strip().lower()
        if not key:
            raise ValueError(f"{self._kind} name must be non-empty")
        if key in self._items and not replace:
            raise ValueError(f"{self._kind} {key!r} already registered")
        self._items[key] = impl
        return impl

    def unregister(self, name: str) -> None:
        self._items.pop(str(name).strip().lower(), None)

    def get(self, name: str) -> T | None:
        return self._items.get(str(name).strip().lower())

    def require(self, name: str) -> T:
        impl = self.get(name)
        if impl is None:
            raise KeyError(f"no {self._kind} registered for {name!r}")
        return impl

    def names(self) -> list[str]:
        return sorted(self._items)

    def __contains__(self, name: object) -> bool:
        return str(name).strip().lower() in self._items

    def __iter__(self) -> Iterator[str]:
        return iter(self.names())

    def __len__(self) -> int:
        return len(self._items)


# Singletons imported across the app. Enterprise registers into these.
providers: _Registry = _Registry("collection provider")
classifiers: _Registry = _Registry("intent classifier")
correlators: _Registry = _Registry("correlator")
alert_channels: _Registry = _Registry("alert channel")


def _register_builtin_alert_channels() -> None:
    # Community already supports these delivery transports. Validation lives in
    # the registry so adding a new transport does not require a schema migration.
    for name in ("telegram", "webhook", "email", "smtp"):
        alert_channels.register(name, name, replace=True)


_register_builtin_alert_channels()


def reset_all() -> None:
    """Test helper — clears dynamic registries and restores built-in channels."""
    for reg in (providers, classifiers, correlators, alert_channels):
        reg._items.clear()
    _register_builtin_alert_channels()
