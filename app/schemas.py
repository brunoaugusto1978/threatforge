"""Pydantic schemas plus observable validation/normalization."""
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
            raise ValueError("value cannot be empty")
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
                raise ValueError(f"invalid official domain: {d!r}")
            cleaned.append(d)
        if not cleaned:
            raise ValueError("provide at least one official domain")
        return cleaned


class BrandUpdate(BaseModel):
    """Edição parcial de marca (tenant-scoped). name e/ou official_domains."""
    name: str | None = None
    official_domains: list[str] | None = None

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("invalid name (1-255 chars)")
        return v

    @field_validator("official_domains")
    @classmethod
    def _domains_ok(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        cleaned = []
        for d in v:
            d = refang(d).lower().strip()
            if not _RE["domain"].match(d):
                raise ValueError(f"invalid official domain: {d!r}")
            if d not in cleaned:
                cleaned.append(d)
        if not cleaned:
            raise ValueError("provide at least one official domain")
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
    status: str = "active"
    archived_at: datetime | None = None
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


# --- Auth / users ---
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
    is_operator: bool = False
    operator_role: str | None = None
    tenant_id: int | None = None


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
    # if empty, the server generates a temporary password and returns it only once
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None:
            from app.security import check_password_strength
            check_password_strength(v)
        return v


# --- Organization / Setup ---
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
            raise ValueError("organization name is required (1–255)")
        return v


class OrganizationOut(OrganizationIn):
    id: int
    monitoring_scope: list | None = None
    setup_completed: bool = False
    setup_completed_at: datetime | None = None
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
    needs_operator: bool     # no users -> create platform operator
    has_users: bool


class TenantSetupStatus(BaseModel):
    tenant_id: int
    has_organization: bool
    setup_completed: bool
    needs_setup: bool


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
    scope: str
    source_type: str
    sector: str | None
    status: str
    confirmed: bool
    confidence: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatProfileResult(BaseModel):
    sector: str | None
    seeds_created: int


class TenantCreate(BaseModel):
    name: str
    admin_email: str
    admin_password: str | None = None  # if empty, generates a temporary password

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 255:
            raise ValueError("nome do tenant inválido (1–255)")
        return v

    @field_validator("admin_email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if not _RE["email"].match(v):
            raise ValueError("e-mail do admin inválido")
        return v

    @field_validator("admin_password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None:
            from app.security import check_password_strength
            check_password_strength(v)
        return v


class TenantOut(BaseModel):
    id: int
    name: str
    slug: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ApiKeyCreate(BaseModel):
    label: str = ""
    role: Literal["admin", "analyst", "viewer"] = "analyst"


# --- Invitations ---
class InviteCreate(BaseModel):
    email: str
    role: Literal["admin", "analyst", "viewer"] = "admin"

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if not _RE["email"].match(v):
            raise ValueError("e-mail inválido")
        return v


class InviteOut(BaseModel):
    id: int
    tenant_id: int
    email: str
    role: str
    status: str
    expires_at: datetime
    created_at: datetime
    accepted_at: datetime | None
    invited_by: str | None

    model_config = {"from_attributes": True}


class InviteValidateOut(BaseModel):
    valid: bool
    email: str | None = None
    tenant_name: str | None = None
    reason: str | None = None


class InviteAccept(BaseModel):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def _pw_ok(cls, v: str) -> str:
        from app.security import check_password_strength
        check_password_strength(v)
        return v


class ApiKeyOut(BaseModel):
    id: int
    tenant_id: int
    label: str
    prefix: str
    role: str
    active: bool
    created_at: datetime
    last_used_at: datetime | None

    model_config = {"from_attributes": True}


class AuditOut(BaseModel):
    id: int
    ts: datetime
    actor: str
    actor_role: str | None
    operator_user_id: int | None = None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    user_agent: str | None = None
    detail: dict | None

    model_config = {"from_attributes": True}


# --- Operators ---
OperatorRole = Literal["platform_admin", "support_operator", "support_viewer"]


class OperatorCreate(BaseModel):
    email: str
    password: str | None = None
    operator_role: OperatorRole = "support_operator"

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if not _RE["email"].match(v):
            raise ValueError("e-mail inválido")
        return v

    @field_validator("password")
    @classmethod
    def _pw_ok(cls, v: str | None) -> str | None:
        if v is not None:
            from app.security import check_password_strength
            check_password_strength(v)
        return v


class OperatorUpdate(BaseModel):
    operator_role: OperatorRole | None = None
    is_active: bool | None = None


class OperatorOut(BaseModel):
    id: int
    email: str
    operator_role: str | None
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantAccessGrant(BaseModel):
    tenant_id: int
    access_role: Literal["support_operator", "support_viewer"] = "support_operator"


class TenantAccessOut(BaseModel):
    id: int
    operator_user_id: int
    tenant_id: int
    access_role: str
    is_active: bool
    created_at: datetime
    created_by: str | None

    model_config = {"from_attributes": True}


# --- Investigation Cases ---
CaseSeverity = Literal["baixo", "medio", "alto", "critico"]
CaseStatus = Literal["open", "triage", "investigating", "contained", "closed", "false_positive"]


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    severity: CaseSeverity = "medio"
    brand_id: int | None = None
    finding_id: int | None = None
    assignee_user_id: int | None = None

    @field_validator("title")
    @classmethod
    def _title_ok(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 255:
            raise ValueError("title is required (1-255 chars)")
        return v


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    assignee_user_id: int | None = None

    @field_validator("title")
    @classmethod
    def _title_ok(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("invalid title (1-255 chars)")
        return v


class CaseOut(BaseModel):
    id: int
    tenant_id: int
    brand_id: int | None
    finding_id: int | None
    observable_id: int | None
    finding_snapshot: dict | None
    title: str
    description: str | None
    severity: str
    status: str
    assignee_user_id: int | None
    created_by_user_id: int | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

    model_config = {"from_attributes": True}


# --- Case notes ---
class NoteCreate(BaseModel):
    body: str
    is_internal: bool = True

    @field_validator("body")
    @classmethod
    def _body_ok(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("note body is required")
        if len(v) > 10000:
            raise ValueError("note too long (max 10000 chars)")
        return v


class NoteOut(BaseModel):
    id: int
    tenant_id: int
    case_id: int
    author_user_id: int | None
    body: str
    is_internal: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Evidence ---
class EvidenceOut(BaseModel):
    id: int
    tenant_id: int
    case_id: int
    finding_id: int | None
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    origin: str
    description: str | None
    stored: bool
    uploaded_by_user_id: int | None
    created_at: datetime
