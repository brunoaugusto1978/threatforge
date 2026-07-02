from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    Index,
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    """Isolation boundary. Each customer is a tenant; all sensitive data
    referencia tenant_id e toda query filtra por ele."""
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|suspended
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TenantInvite(Base):
    """Tenant access invitation. Token is stored as a hash; single use."""
    __tablename__ = "tenant_invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[str] = mapped_column(String(20), default="admin")
    token_hash: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    # pending | accepted | expired | revoked
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    invited_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class OperatorTenantAccess(Base):
    """Which tenants a support operator can access in support mode.
    platform_admin does not need a row here because it can access all tenants."""
    __tablename__ = "operator_tenant_access"
    __table_args__ = (
        UniqueConstraint("operator_user_id", "tenant_id", name="uq_operator_tenant"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    operator_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    access_role: Mapped[str] = mapped_column(String(20), default="support_operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ApiKey(Base):
    """API key per tenant for automation/integration. Only the hash is stored."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(120), default="")
    prefix: Mapped[str] = mapped_column(String(16), index=True)  # parte visível p/ identificar
    key_hash: Mapped[str] = mapped_column(String(128))           # sha256 do segredo
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), unique=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    trade_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    legal_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tax_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # CNPJ
    sector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    subsector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country: Mapped[str | None] = mapped_column(String(80), nullable=True)
    state: Mapped[str | None] = mapped_column(String(80), nullable=True)
    city: Mapped[str | None] = mapped_column(String(120), nullable=True)
    website: Mapped[str | None] = mapped_column(String(255), nullable=True)
    security_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    legal_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(60), nullable=True)
    language: Mapped[str | None] = mapped_column(String(10), nullable=True)
    criticality: Mapped[str] = mapped_column(String(10), default="medio")  # low/medium/high/critical stored as baixo/medio/alto/critico
    # escopo de monitoramento selecionado no wizard (lista de fontes)
    monitoring_scope: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # onboarding obrigatório
    setup_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    setup_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # null for platform actions where the operator has no tenant
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(255), index=True)  # email ou "service"
    actor_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # when the action is performed by an operator acting in support mode for a tenant
    operator_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin|analyst|viewer
    # platform operator: tenant_id is null and sees the operations view.
    # is_operator=true NÃO concede acesso irrestrito — depende de operator_role
    # e de operator_tenant_access (para support_operator/support_viewer).
    is_operator: Mapped[bool] = mapped_column(Boolean, default=False)
    operator_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # platform_admin | support_operator | support_viewer
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # incremented on each password change/reset to invalidate old JWT sessions
    pwd_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Observable(Base):
    __tablename__ = "observables"
    __table_args__ = (
        UniqueConstraint("tenant_id", "type", "value", name="uq_observable_tenant_type_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(20), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_enriched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    score_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)

    enrichments: Mapped[list["Enrichment"]] = relationship(
        back_populates="observable", cascade="all, delete-orphan"
    )


class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observable_id: Mapped[int] = mapped_column(
        ForeignKey("observables.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(50), index=True)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    observable: Mapped[Observable] = relationship(back_populates="enrichments")


class KEVEntry(Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(25), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_added: Mapped[str | None] = mapped_column(String(20), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    known_ransomware: Mapped[str | None] = mapped_column(String(20), nullable=True)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tactics: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)


class MonitoringSeed(Base):
    """Sector seed/watchlist entry. It is not a finding unless evidence is found."""
    __tablename__ = "monitoring_seeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("brands.id", ondelete="CASCADE"), nullable=True, index=True
    )
    seed: Mapped[str] = mapped_column(String(512), index=True)
    seed_type: Mapped[str] = mapped_column(String(30))  # keyword_combo|domain|slug|threat|cve_tech
    # taxonomia: global | sector | organization (finding com evidência fica em outra tabela)
    scope: Mapped[str] = mapped_column(String(20), default="sector", index=True)
    source_type: Mapped[str] = mapped_column(String(40), default="sector_profile")
    sector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="candidate", index=True)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(10), default="low")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SyncState(Base):
    __tablename__ = "sync_state"

    source: Mapped[str] = mapped_column(String(50), primary_key=True)
    last_sync_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    items: Mapped[int] = mapped_column(Integer, default=0)


class Brand(Base):
    __tablename__ = "brands"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_brand_tenant_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    # legitimate domains (allowlist) — comma-separated
    official_domains: Mapped[str] = mapped_column(Text, default="")
    # termos extras a vigiar (ex.: nome fantasia, app), separados por vírgula
    keywords: Mapped[str | None] = mapped_column(Text, nullable=True)
    # official brand assets (lists)
    variations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    aliases: Mapped[list | None] = mapped_column(JSON, nullable=True)  # siglas
    products: Mapped[list | None] = mapped_column(JSON, nullable=True)
    subdomains: Mapped[list | None] = mapped_column(JSON, nullable=True)
    social_profiles: Mapped[list | None] = mapped_column(JSON, nullable=True)
    sensitive_terms: Mapped[list | None] = mapped_column(JSON, nullable=True)
    logo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # ciclo de vida da marca: active | archived (archived para novos scans)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    findings: Mapped[list["BrandFinding"]] = relationship(
        back_populates="brand", cascade="all, delete-orphan"
    )

    def domain_list(self) -> list[str]:
        return [d.strip().lower() for d in (self.official_domains or "").split(",") if d.strip()]


class BrandFinding(Base):
    __tablename__ = "brand_findings"
    __table_args__ = (
        UniqueConstraint("brand_id", "domain", name="uq_finding_brand_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    brand_id: Mapped[int] = mapped_column(
        ForeignKey("brands.id", ondelete="CASCADE"), index=True
    )
    domain: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(30))  # typosquat | ct_log
    similarity: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(20), default="info", index=True)
    score_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    brand: Mapped[Brand] = relationship(back_populates="findings")


class InvestigationCase(Base):
    """Caso investigativo (tenant-scoped). Sobrevive a archive/delete/clear de
    brand/finding via ON DELETE SET NULL + finding_snapshot (cadeia de custódia)."""
    __tablename__ = "investigation_cases"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open','triage','investigating','contained','closed','false_positive')",
            name="ck_case_status"),
        CheckConstraint(
            "severity IN ('baixo','medio','alto','critico')", name="ck_case_severity"),
        Index("ix_cases_tenant_status", "tenant_id", "status"),
        Index("ix_cases_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("brands.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("brand_findings.id", ondelete="SET NULL"), nullable=True, index=True)
    observable_id: Mapped[int | None] = mapped_column(
        ForeignKey("observables.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(10), default="medio", index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    assignee_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseNote(Base):
    """Nota/comentário interno de investigação (append-only). Cai junto com o case."""
    __tablename__ = "case_notes"
    __table_args__ = (
        Index("ix_case_notes_tenant", "tenant_id"),
        Index("ix_case_notes_case", "case_id"),
        Index("ix_case_notes_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="CASCADE"), index=True)
    author_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    body: Mapped[str] = mapped_column(Text)
    is_internal: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)


class CaseEvidence(Base):
    """Anexo de evidência (append-only / cadeia de custódia). Hash calculado no servidor."""
    __tablename__ = "case_evidence"
    __table_args__ = (
        CheckConstraint(
            "origin IN ('manual_upload','authorized_export','whatsapp_intake',"
            "'telegram_public','email','other')", name="ck_evidence_origin"),
        CheckConstraint("storage_backend IN ('local','none')", name="ck_evidence_backend"),
        Index("ix_evidence_tenant", "tenant_id"),
        Index("ix_evidence_case", "case_id"),
        Index("ix_evidence_finding", "finding_id"),
        Index("ix_evidence_sha256", "sha256"),
        Index("ix_evidence_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("brand_findings.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(512))
    mime_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    origin: Mapped[str] = mapped_column(String(30), default="manual_upload")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_backend: Mapped[str] = mapped_column(String(20), default="local")
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    uploaded_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)


# ---------------------------------------------------------------------------
# Exposure Monitoring (DRP) — modelo único e extensível.
# MVP: identity_exposure + credential_exposure. Demais tipos previstos no enum,
# implementados em versões futuras. NENHUMA senha/segredo em claro no modelo.
# ---------------------------------------------------------------------------
EXPOSURE_TYPES = (
    "identity_exposure", "credential_exposure",   # MVP (Community)
    "brand_exposure", "infrastructure_exposure",  # previstos (futuro)
    "secret_exposure", "source_code_exposure",
)
EXPOSURE_MVP_TYPES = ("identity_exposure", "credential_exposure")
ASSET_TYPES = ("identity", "email", "domain", "keyword", "secret_pattern", "repo", "ip_range")
CRITICALITY = ("low", "medium", "high", "critical")
EXPOSURE_STATUS = ("new", "triaging", "confirmed", "mitigated", "closed", "false_positive", "duplicate")
EXPOSURE_TERMINAL = ("closed", "false_positive", "duplicate")
SOURCE_RELIABILITY = ("A", "B", "C", "D", "E", "F")   # Admiralty — fonte
INFO_CREDIBILITY = ("1", "2", "3", "4", "5", "6")     # Admiralty — informação


class MonitoredAsset(Base):
    """Alvo de monitoramento de exposição (VIP/identidade, domínio, keyword…)."""
    __tablename__ = "monitored_asset"
    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('identity','email','domain','keyword','secret_pattern','repo','ip_range')",
            name="ck_monitored_asset_type"),
        CheckConstraint(
            "criticality IN ('low','medium','high','critical')", name="ck_monitored_asset_crit"),
        Index("ix_monitored_asset_tenant", "tenant_id"),
        Index("ix_monitored_asset_hash", "value_hash"),
        Index("ix_monitored_asset_type", "asset_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    asset_type: Mapped[str] = mapped_column(String(30))
    label: Mapped[str] = mapped_column(String(200))
    value: Mapped[str] = mapped_column(String(512))
    value_hash: Mapped[str] = mapped_column(String(64), index=True)  # sha256 normalizado (match/dedup)
    criticality: Mapped[str] = mapped_column(String(10), default="medium")
    # consentimento p/ monitorar identidade de pessoa física (LGPD/GDPR)
    consent_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ExposureFinding(Base):
    """Achado de exposição (tabela única p/ todos os tipos). Sem segredo em claro:
    dados sensíveis (senha/token) vivem no JSON `detail` apenas como hash+máscara."""
    __tablename__ = "exposure_finding"
    __table_args__ = (
        CheckConstraint(
            "exposure_type IN ('identity_exposure','credential_exposure','brand_exposure',"
            "'infrastructure_exposure','secret_exposure','source_code_exposure')",
            name="ck_exposure_type"),
        CheckConstraint(
            "source_reliability IN ('A','B','C','D','E','F')", name="ck_exposure_reliability"),
        CheckConstraint(
            "info_credibility IN ('1','2','3','4','5','6')", name="ck_exposure_credibility"),
        CheckConstraint(
            "severity IN ('low','medium','high','critical')", name="ck_exposure_severity"),
        CheckConstraint(
            "status IN ('new','triaging','confirmed','mitigated','closed','false_positive','duplicate')",
            name="ck_exposure_status"),
        UniqueConstraint("tenant_id", "dedup_key", name="uq_exposure_dedup"),
        Index("ix_exposure_tenant", "tenant_id"),
        Index("ix_exposure_type", "exposure_type"),
        Index("ix_exposure_asset", "asset_id"),
        Index("ix_exposure_dedup", "dedup_key"),
        Index("ix_exposure_created", "created_at"),
        Index("ix_exposure_ingest", "ingest_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    exposure_type: Mapped[str] = mapped_column(String(40))
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitored_asset.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    source: Mapped[str] = mapped_column(String(60))
    source_reliability: Mapped[str] = mapped_column(String(1), default="F")
    info_credibility: Mapped[str] = mapped_column(String(1), default="6")
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # metadados; nunca senha/segredo em claro
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    # proveniência de ingestão (custódia / rollback / reprocessamento)
    ingest_id: Mapped[int | None] = mapped_column(
        ForeignKey("exposure_ingest_batch.id", ondelete="SET NULL"), nullable=True)
    record_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)


class ExposureIngestBatch(Base):
    """Lote de ingestão (proveniência): fingerprint do arquivo, parser, contagens.
    Permite rollback de um import (hard delete dos findings do lote)."""
    __tablename__ = "exposure_ingest_batch"
    __table_args__ = (
        CheckConstraint(
            "source IN ('manual_intake','authorized_upload','file_import')",
            name="ck_ingest_source"),
        CheckConstraint(
            "status IN ('processing','completed','rolled_back')", name="ck_ingest_status"),
        Index("ix_ingest_tenant", "tenant_id"),
        Index("ix_ingest_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(40))
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser: Mapped[str] = mapped_column(String(60))
    parser_version: Mapped[str] = mapped_column(String(20))
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    created_count: Mapped[int] = mapped_column(Integer, default=0)
    deduped_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="completed")
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)
