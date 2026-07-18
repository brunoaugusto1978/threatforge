from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
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
    key_hash: Mapped[str] = mapped_column(String(128))           # slow hash do segredo
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



class CaseReview(Base):
    """Histórico append-only de revisão operacional de um Investigation Case."""
    __tablename__ = "case_reviews"
    __table_args__ = (
        CheckConstraint(
            "review_status IN ('not_reviewed','in_review','needs_changes','approved','rejected')",
            name="ck_case_review_status"),
        Index("ix_case_reviews_tenant", "tenant_id"),
        Index("ix_case_reviews_case", "case_id"),
        Index("ix_case_reviews_status", "review_status"),
        Index("ix_case_reviews_reviewer", "reviewer_user_id"),
        Index("ix_case_reviews_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="CASCADE"), index=True)
    review_status: Mapped[str] = mapped_column(String(30), default="in_review", index=True)
    reviewer_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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


# ---------------------------------------------------------------------------
# Attack Surface Discovery (ASD) — ativos externos descobertos a partir de Brands.
# MVP: subdomain + ip + certificate. netblock/port/service previstos (Enterprise).
# ---------------------------------------------------------------------------
SURFACE_ASSET_TYPES = ("subdomain", "ip", "certificate", "netblock", "port", "service")
SURFACE_MVP_TYPES = ("subdomain", "ip", "certificate")
SURFACE_STATUS = ("new", "confirmed", "ignored", "resolved")
SURFACE_SOURCES = ("ct_log", "dns", "rdap", "tls", "manual_import", "active_scan")


class SurfaceAsset(Base):
    """Ativo de superfície de ataque (tenant-scoped). Descoberta passiva/import no
    Community; varredura ativa é Enterprise. Alimenta infrastructure_exposure."""
    __tablename__ = "surface_asset"
    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('subdomain','ip','certificate','netblock','port','service')",
            name="ck_surface_type"),
        CheckConstraint(
            "status IN ('new','confirmed','ignored','resolved')", name="ck_surface_status"),
        CheckConstraint(
            "source IN ('ct_log','dns','rdap','tls','manual_import','active_scan')",
            name="ck_surface_source"),
        UniqueConstraint("tenant_id", "dedup_key", name="uq_surface_dedup"),
        Index("ix_surface_tenant", "tenant_id"),
        Index("ix_surface_brand", "brand_id"),
        Index("ix_surface_type", "asset_type"),
        Index("ix_surface_hash", "value_hash"),
        Index("ix_surface_parent", "parent_id"),
        Index("ix_surface_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("brands.id", ondelete="SET NULL"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(512))
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("surface_asset.id", ondelete="SET NULL"), nullable=True)
    source: Mapped[str] = mapped_column(String(40), default="manual_import")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="new")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)


# ---------------------------------------------------------------------------
# Credential Intelligence — agregação por identidade (dossiê de e-mail).
# Materializado incrementalmente a partir de credential_exposure findings.
# ---------------------------------------------------------------------------
CREDENTIAL_IDENTITY_STATUS = ("new", "reviewing", "mitigated", "closed")


class CredentialIdentity(Base):
    """Consolida os leaks de um e-mail (tenant-scoped). Nunca senha em claro:
    guarda só os hashes de senha distintos (para contagem/reuso)."""
    __tablename__ = "credential_identity"
    __table_args__ = (
        CheckConstraint("status IN ('new','reviewing','mitigated','closed')",
                        name="ck_credid_status"),
        UniqueConstraint("tenant_id", "identity_hash", name="uq_credid_identity"),
        Index("ix_credid_tenant", "tenant_id"),
        Index("ix_credid_hash", "identity_hash"),
        Index("ix_credid_domain", "domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    identity_hash: Mapped[str] = mapped_column(String(64), index=True)  # sha256(tenant|email)
    email: Mapped[str] = mapped_column(String(320))
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    leak_count: Mapped[int] = mapped_column(Integer, default=0)
    password_hashes: Mapped[list] = mapped_column(JSON, default=list)  # sha256 distintos
    sources: Mapped[list] = mapped_column(JSON, default=list)
    stealer_families: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    vip_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitored_asset.id", ondelete="SET NULL"), nullable=True)
    max_risk: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="new")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True)


# ---------------------------------------------------------------------------
# Enterprise Integration Configuration (v0.9.2)
# Persists minimal, non-secret configuration for premium connectors
# (MISP / OpenCTI / Generic) when an Enterprise license unlocks the feature.
# Community never stores real secrets: incoming api_key / token / secret /
# password values are stripped before persistence and only presence metadata
# (masked hint) is kept in ``secrets_metadata``. Real connector I/O still
# lives in the private ``threatforge-enterprise`` package.
# ---------------------------------------------------------------------------
class IntegrationConnection(Base):
    """Persisted connector configuration, one row per (tenant, integration name).

    Fields:
      - ``config_json``  — non-secret configuration (base_url, direction, tags…);
        matches the descriptor's public ``config_schema`` shape.
      - ``secrets_metadata`` — dict keyed by secret field name with only masked
        presence info (e.g. ``{"api_key": {"present": true, "masked": "***"}}``).
        The real value is never persisted here.
      - ``enabled`` — whether the connection is active (default True on save).
    """
    __tablename__ = "integration_connections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_integration_conn_tenant_name"),
        Index("ix_integration_conn_tenant", "tenant_id"),
        Index("ix_integration_conn_name", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Note: no ``index=True`` on ``tenant_id`` or ``name`` — the indexes are
    # declared explicitly in ``__table_args__`` (``ix_integration_conn_tenant``
    # / ``ix_integration_conn_name``) so the ORM's ``create_all`` and the
    # Alembic migration agree on names and never emit a duplicate index.
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(60))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    secrets_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)



# ===========================================================================
# Telegram Intelligence — provider-neutral collection & alerting (v0.11.0)
# ---------------------------------------------------------------------------
# Community persists structure only. Real secrets live in the Secret Resolver
# (only opaque references are stored here — ``secret_refs``); in the POC no
# original provider payload is retained (see app/collection/envelope.py).
#
# Residual requirements + corrective audit findings encoded below:
#   #1  collection_connection.enabled (bool, default False) drives activation.
#   C1  the Bot API update cursor belongs to the CONNECTION (one per bot),
#       not to each source; sources under one connection share one cursor.
#   #2  alert_outbox → tenant_alert_channel by composite same-tenant FK.
#   #3/C3 config_json holds only non-secret parameters; ``secret_refs`` holds
#       opaque Secret Resolver references; ``secrets_metadata`` presence only.
#   #4  outbox delivery state lives only in columns.
#   #5  alert_outbox.dedup_key UNIQUE.
#   #6  collection_source_test_request stores the nonce hash, not the nonce.
#   #7  provider_account_ref exclusivity across tenants (partial unique).
#   C2  history preservation: no ON DELETE CASCADE on connection→source,
#       source→event, connection→test_request, channel→outbox — physical
#       deletes are RESTRICTed; lifecycle uses soft delete.
#   #9  soft delete + partial unique (deleted_at IS NULL).
#   #11 retention columns (redacted_text/context/purged_at/policy/legal_hold).
#   C8  analysis state machine columns on collection_event
#       (attempts/next_attempt_at/locked_by/locked_at/processed_at/error_code/
#        analysis_version/analysis_json).
# ===========================================================================
class CollectionConnection(Base):
    """A provider connection (e.g. one Telegram bot) owned by a tenant."""
    __tablename__ = "collection_connection"
    __table_args__ = (
        Index(
            "uq_coll_conn_tenant_name_live", "tenant_id", "name",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "uq_coll_conn_active_identity", "provider", "provider_account_ref",
            unique=True,
            sqlite_where=text("enabled = 1 AND deleted_at IS NULL AND provider_account_ref IS NOT NULL"),
            postgresql_where=text("enabled = true AND deleted_at IS NULL AND provider_account_ref IS NOT NULL"),
        ),
        UniqueConstraint("id", "tenant_id", name="uq_coll_conn_id_tenant"),
        Index("ix_coll_conn_tenant", "tenant_id"),
        Index("ix_coll_conn_provider", "provider"),
        CheckConstraint(
            "status IN ('pending','active','revoked')", name="ck_coll_conn_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    provider_account_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # C1 — the provider update cursor lives on the CONNECTION. All sources under
    # this connection share it; it advances in the same txn as event persistence.
    cursor: Mapped[str | None] = mapped_column(String(190), nullable=True)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # C3 — opaque Secret Resolver references ({name: ref}); never the values.
    secret_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    secrets_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class CollectionSource(Base):
    """A monitored source (channel/group/DM/test) under a connection."""
    __tablename__ = "collection_source"
    __table_args__ = (
        Index(
            "uq_coll_source_ref_live", "tenant_id", "connection_id", "source_ref",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # C2 — RESTRICT: physically deleting a connection that still has sources
        # is blocked; lifecycle is soft delete.
        ForeignKeyConstraint(
            ["connection_id", "tenant_id"],
            ["collection_connection.id", "collection_connection.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_source_conn_same_tenant",
        ),
        UniqueConstraint("id", "tenant_id", name="uq_coll_source_id_tenant"),
        UniqueConstraint("id", "connection_id", "tenant_id",
                         name="uq_coll_source_id_conn_tenant"),
        Index("ix_coll_source_tenant", "tenant_id"),
        Index("ix_coll_source_conn", "connection_id"),
        CheckConstraint(
            "status IN ('pending','active','paused','revoked')",
            name="ck_coll_source_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    connection_id: Mapped[int] = mapped_column(Integer)
    provider: Mapped[str] = mapped_column(String(40))
    source_ref: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(30), default="channel")
    name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # C2 — activation switch mirrors the connection contract (#1).
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class CollectionEvent(Base):
    """A normalised (or rejected) provider update. No original payload in POC."""
    __tablename__ = "collection_event"
    __table_args__ = (
        Index(
            "uq_coll_event_external", "tenant_id", "source_id", "external_id_hash",
            unique=True,
            sqlite_where=text("external_id_hash <> '' AND processing_state <> 'rejected'"),
            postgresql_where=text("external_id_hash <> '' AND processing_state <> 'rejected'"),
        ),
        Index("ix_coll_event_tenant", "tenant_id"),
        Index("ix_coll_event_source", "source_id"),
        Index("ix_coll_event_state", "processing_state"),
        Index("ix_coll_event_finding", "finding_id"),
        Index("ix_coll_event_next", "next_attempt_at"),
        Index("ix_coll_event_locked", "locked_at"),
        CheckConstraint(
            "processing_state IN ('received','normalized','control','rejected',"
            "'dead_letter','analyzing','analyzed','failed')",
            name="ck_coll_event_state"),
        CheckConstraint("attempts >= 0", name="ck_coll_event_attempts"),
        ForeignKeyConstraint(
            ["source_id", "tenant_id"],
            ["collection_source.id", "collection_source.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_event_source_same_tenant",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    # Tenant-scoped composite FK prevents cross-tenant source references.
    source_id: Mapped[int] = mapped_column(Integer)
    provider: Mapped[str] = mapped_column(String(40))
    external_id_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")
    processing_state: Mapped[str] = mapped_column(String(20), default="received")
    normalized_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    redaction_profile: Mapped[str] = mapped_column(String(40), default="default")
    redacted_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_json: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_control: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    control_nonce_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(String(60), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("exposure_finding.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigation_cases.id", ondelete="SET NULL"), nullable=True)
    # C8 — analysis state machine (per approved planning).
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    analysis_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    analysis_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # #11 — retention bookkeeping.
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    retention_policy: Mapped[str | None] = mapped_column(String(60), nullable=True)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectionSourceTestRequest(Base):
    """A TF-VERIFY test handshake. Stores the nonce hash, never the nonce (#6)."""
    __tablename__ = "collection_source_test_request"
    __table_args__ = (
        UniqueConstraint("tenant_id", "nonce_hash", name="uq_coll_test_nonce"),
        Index("ix_coll_test_tenant", "tenant_id"),
        Index("ix_coll_test_conn", "connection_id"),
        Index("ix_coll_test_status", "status"),
        CheckConstraint(
            "status IN ('pending','awaiting','verified','failed','expired')",
            name="ck_coll_test_status"),
        ForeignKeyConstraint(
            ["connection_id", "tenant_id"],
            ["collection_connection.id", "collection_connection.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_test_conn_same_tenant",
        ),
        ForeignKeyConstraint(
            ["source_id", "connection_id", "tenant_id"],
            ["collection_source.id", "collection_source.connection_id",
             "collection_source.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_test_source_same_scope",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    # Composite scope FKs prevent cross-tenant/cross-connection requests.
    connection_id: Mapped[int] = mapped_column(Integer)
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str] = mapped_column(String(40))
    nonce_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    telemetry_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TenantAlertChannel(Base):
    """A tenant's alert channel (telegram/webhook/email). Non-secret config (#3)."""
    __tablename__ = "tenant_alert_channel"
    __table_args__ = (
        Index(
            "uq_alert_channel_name_live", "tenant_id", "name",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
            postgresql_where=text("deleted_at IS NULL"),
        ),
        UniqueConstraint("id", "tenant_id", name="uq_alert_channel_id_tenant"),
        Index("ix_alert_channel_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(80))
    channel_type: Mapped[str] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # C3 — opaque Secret Resolver references ({name: ref}); never the values.
    secret_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    secrets_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class AlertOutbox(Base):
    """Durable outbox row for one notification. State lives in columns (#4).

    Bound to its channel by a composite same-tenant FK (#2) with RESTRICT (C2):
    deleting a channel cannot destroy delivery history. Idempotent by
    ``dedup_key`` UNIQUE (#5).
    """
    __tablename__ = "alert_outbox"
    __table_args__ = (
        UniqueConstraint("dedup_key", name="uq_alert_outbox_dedup"),
        ForeignKeyConstraint(
            ["alert_channel_id", "tenant_id"],
            ["tenant_alert_channel.id", "tenant_alert_channel.tenant_id"],
            ondelete="RESTRICT", name="fk_alert_outbox_channel_same_tenant",
        ),
        Index("ix_alert_outbox_tenant", "tenant_id"),
        Index("ix_alert_outbox_channel", "alert_channel_id"),
        Index("ix_alert_outbox_status", "status"),
        Index("ix_alert_outbox_next", "next_attempt_at"),
        CheckConstraint(
            "status IN ('pending','sending','delivered','failed','dead_letter')",
            name="ck_alert_outbox_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"))
    alert_channel_id: Mapped[int] = mapped_column(Integer)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("exposure_finding.id", ondelete="SET NULL"), nullable=True)
    external_channel_ref: Mapped[str | None] = mapped_column(String(190), nullable=True)
    template: Mapped[str] = mapped_column(String(80))
    template_version: Mapped[str] = mapped_column(String(40), default="1")
    dedup_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)
