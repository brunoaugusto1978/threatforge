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
    variations: list[str] | None = None
    aliases: list[str] | None = None
    products: list[str] | None = None
    subdomains: list[str] | None = None
    social_profiles: list[str] | None = None
    sensitive_terms: list[str] | None = None
    logo_url: str | None = None

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
    variations: list | None = None
    aliases: list | None = None
    products: list | None = None
    subdomains: list | None = None
    social_profiles: list | None = None
    sensitive_terms: list | None = None
    logo_url: str | None = None
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
        from app.security import check_password_strength
        check_password_strength(v)
        return v


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None:
            from app.security import check_password_strength
            check_password_strength(v)
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
        from app.security import check_password_strength
        check_password_strength(v)
        return v


class AdminResetPassword(BaseModel):
    # se vazio, o servidor gera uma senha temporária e a retorna uma única vez
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None:
            from app.security import check_password_strength
            check_password_strength(v)
        return v


# --- Organização / Setup ---
Criticality = Literal["baixo", "medio", "alto", "critico"]


class OrganizationIn(BaseModel):
    name: str
    trade_name: str | None = None
    legal_name: str | None = None
    tax_id: str | None = None
    sector: str | None = None
    subsector: str | None = None
    country: str | None = "Brasil"
    state: str | None = None
    city: str | None = None
    website: str | None = None
    security_email: str | None = None
    legal_email: str | None = None
    phone: str | None = None
    timezone: str | None = "America/Sao_Paulo"
    language: str | None = "pt-BR"
    criticality: Criticality = "medio"

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 255:
            raise ValueError("nome da organização é obrigatório (1–255)")
        return v


class OrganizationOut(OrganizationIn):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SetupRequest(BaseModel):
    organization: OrganizationIn
    admin_email: str
    admin_password: str

    @field_validator("admin_email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if not _RE["email"].match(v):
            raise ValueError("e-mail de admin inválido")
        return v

    @field_validator("admin_password")
    @classmethod
    def _pw_ok(cls, v: str) -> str:
        from app.security import check_password_strength
        check_password_strength(v)
        return v


class SetupStatus(BaseModel):
    needs_admin: bool        # nenhum usuário existe -> criar 1º admin
    needs_setup: bool        # org ausente ou setup não concluído -> wizard obrigatório
    setup_completed: bool
    has_organization: bool
    has_users: bool


class AdminBootstrap(BaseModel):
    email: str
    password: str

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
        from app.security import check_password_strength
        check_password_strength(v)
        return v


class ScopeIn(BaseModel):
    monitoring_scope: list[str]


class SectorProfileOut(BaseModel):
    sector: str
    threats: list[str]
    keywords: list[str]
    ioc_categories: list[str]
    cve_watchlist: list[str]
    sources: list[str]


class SeedOut(BaseModel):
    id: int
    brand_id: int | None
    seed: str
    seed_type: str
    source_type: str
    sector: str | None
    status: str
    confidence: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatProfileResult(BaseModel):
    sector: str | None
    seeds_created: int


class AuditOut(BaseModel):
    id: int
    ts: datetime
    actor: str
    actor_role: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    detail: dict | None

    model_config = {"from_attributes": True}
