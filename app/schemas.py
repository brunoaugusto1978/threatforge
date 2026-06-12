"""Schemas Pydantic + validação/normalização de observáveis."""
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator

ObservableType = Literal["ip", "domain", "url", "hash", "email", "cve"]

_RE = {
    "ip": re.compile(
        r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    ),
    "domain": re.compile(
        r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    ),
    "url": re.compile(r"^https?://\S+$", re.IGNORECASE),
    "hash": re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$"),
    "email": re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}$"),
    "cve": re.compile(r"^CVE-\d{4}-\d{4,7}$"),
}


def refang(value: str) -> str:
    """Converte IOCs 'defanged' para a forma real."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = re.sub(r"^hxxps://", "https://", v, flags=re.IGNORECASE)
    v = re.sub(r"^hxxp://", "http://", v, flags=re.IGNORECASE)
    v = v.replace("[://]", "://").replace("[:]", ":").replace("[@]", "@")
    return v


def normalize(type_: str, value: str) -> str:
    v = refang(value)
    if type_ in ("domain", "hash", "email", "ip"):
        v = v.lower()
    if type_ == "cve":
        v = v.upper()
    return v


def validate_observable(type_: str, value: str) -> str:
    v = normalize(type_, value)
    pattern = _RE.get(type_)
    if pattern is None or not pattern.match(v):
        raise ValueError(f"valor inválido para o tipo '{type_}': {value!r}")
    return v


class ObservableCreate(BaseModel):
    type: ObservableType
    value: str

    @field_validator("value")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("value não pode ser vazio")
        if len(v) > 2048:
            raise ValueError("value excede 2048 caracteres")
        return v


class ScoreFactorOut(BaseModel):
    name: str
    points: int
    reason: str
    source: str


class EnrichmentOut(BaseModel):
    source: str
    data: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ObservableOut(BaseModel):
    id: int
    type: str
    value: str
    created_at: datetime
    last_enriched_at: datetime | None
    score: int
    verdict: str
    score_factors: list | None

    model_config = {"from_attributes": True}


class ObservableDetail(ObservableOut):
    enrichments: list[EnrichmentOut] = []


class SyncResult(BaseModel):
    source: str
    items: int
    status: str


# --- Brand ---
class BrandCreate(BaseModel):
    name: str
    official_domains: list[str]
    keywords: list[str] | None = None

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("name inválido (1–255 caracteres)")
        return v

    @field_validator("official_domains")
    @classmethod
    def _domains_ok(cls, v: list[str]) -> list[str]:
        cleaned = []
        for d in v:
            d = refang(d).lower().strip()
            if not _RE["domain"].match(d):
                raise ValueError(f"domínio oficial inválido: {d!r}")
            cleaned.append(d)
        if not cleaned:
            raise ValueError("informe ao menos um domínio oficial")
        return cleaned


class BrandOut(BaseModel):
    id: int
    name: str
    official_domains: str
    keywords: str | None
    created_at: datetime
    last_scan_at: datetime | None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    brand_id: int
    domain: str
    source: str
    similarity: int
    score: int
    verdict: str
    score_factors: list | None
    evidence: dict | None
    status: str
    alerted: bool
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: Literal["new", "triaging", "confirmed", "takedown_requested", "resolved", "false_positive"]


class ScanResult(BaseModel):
    brand: str | None = None
    candidates_generated: int | None = None
    checked: int | None = None
    new_findings: int | None = None
    updated_findings: int | None = None
    alerts_sent: int | None = None
    new_finding_ids: list[int] | None = None
    error: str | None = None


# --- Auth / usuários ---
Role = Literal["admin", "analyst", "viewer"]


class LoginRequest(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    email: str
    password: str
    role: Role = "viewer"

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if not _RE["email"].match(v):
            raise ValueError("e-mail inválido")
        return v

    @field_validator("password")
    @classmethod
    def _pw_ok(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("senha deve ter ao menos 8 caracteres")
        if len(v) > 256:
            raise ValueError("senha muito longa")
        return v


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None and (len(v) < 8 or len(v) > 256):
            raise ValueError("senha deve ter entre 8 e 256 caracteres")
        return v


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class MeOut(BaseModel):
    subject: str
    role: str
    kind: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _pw_ok(cls, v: str) -> str:
        if len(v) < 8 or len(v) > 256:
            raise ValueError("nova senha deve ter entre 8 e 256 caracteres")
        return v


class AdminResetPassword(BaseModel):
    # se vazio, o servidor gera uma senha temporária e a retorna uma única vez
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None and (len(v) < 8 or len(v) > 256):
            raise ValueError("senha deve ter entre 8 e 256 caracteres")
        return v
