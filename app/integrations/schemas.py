"""Public configuration schemas for premium integrations (Community).

These are *display/contract* schemas — used by the UI to render the connection
form and by docs/interop. They intentionally contain **no secret fields**
(auth keys/tokens). Credentials and their encrypted storage live only in the
``threatforge-enterprise`` package, which extends these with secret fields.

The public secret *names* each connector expects are declared alongside as
:data:`SECRETS_SPEC` — the UI reads this to render the secret inputs and the
router uses it to enforce required-secret validation without ever persisting
the values (Community strips them; see ``app.routers.integrations_routes``).
"""
from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field


class MispConfig(BaseModel):
    base_url: str = Field(..., description="MISP base URL, e.g. https://misp.example.org")
    verify_tls: bool = Field(True, description="Verify TLS certificate of the MISP server")
    direction: str = Field("pull", description="pull | push | both")
    tags: list[str] = Field(default_factory=list, description="Filter/publish tags")
    sync_interval_minutes: int = Field(60, ge=5, description="Scheduled sync interval")


class OpenctiConfig(BaseModel):
    base_url: str = Field(..., description="OpenCTI base URL, e.g. https://opencti.example.org")
    verify_tls: bool = Field(True, description="Verify TLS certificate of the OpenCTI server")
    direction: str = Field("pull", description="pull | push | both")
    sync_interval_minutes: int = Field(60, ge=5, description="Scheduled sync interval")


class GenericConfig(BaseModel):
    endpoint_url: str = Field(..., description="Target endpoint that receives the intel")
    format: str = Field("stix2", description="stix2 | csv | json")
    direction: str = Field("push", description="push (Community contract is push-only)")


@dataclass(frozen=True)
class SecretSpec:
    """Public *names* of the secret fields a connector expects.

    Community never stores secret values — the router strips them before
    persistence — but it does need to know *which* secret names each connector
    expects so the UI can render inputs and so ``/connections`` can reject
    payloads that are missing a required secret (:class:`SecretSpec.required`).

    ``optional`` names are accepted if provided but never treated as required
    by :func:`app.routers.integrations_routes.is_ready`.
    """
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()

    def all_names(self) -> tuple[str, ...]:
        return self.required + self.optional


# Per-connector secret contract. The values here are *field names* — never
# secret values. Community strips whatever the caller sends under these keys
# and only records ``{"present": true, "masked": "***"}`` per name.
SECRETS_SPEC: dict[str, SecretSpec] = {
    "misp": SecretSpec(required=("api_key",)),
    "opencti": SecretSpec(required=("api_token",)),
    "generic": SecretSpec(optional=("token", "secret")),
}


def secrets_spec_for(name: str) -> SecretSpec:
    """Return the :class:`SecretSpec` for ``name`` or an empty one if unknown."""
    return SECRETS_SPEC.get(name, SecretSpec())
