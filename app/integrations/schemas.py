"""Public configuration schemas for premium integrations (Community).

These are *display/contract* schemas — used by the UI to render the connection
form and by docs/interop. They intentionally contain **no secret fields**
(auth keys/tokens). Credentials and their encrypted storage live only in the
``threatforge-enterprise`` package, which extends these with secret fields.
"""
from __future__ import annotations

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
