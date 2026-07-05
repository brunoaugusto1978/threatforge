"""Exposure Monitoring (DRP) — Community.

Issue 1: modelo + monitored assets + leitura de findings.
Issue 2: intake manual/autorizado, import de arquivo (parser→normalize→fingerprint
→dedup→redact→persist), proveniência/rollback, triagem, abertura de case, e
masking de PII por role.

Segurança: senha/token/segredo NUNCA em claro — redigidos na ingestão (hash+máscara)
e nunca retornados em response, erro de validação ou audit.
Isolamento por tenant (cross-tenant -> 404). RBAC: viewer lê; analyst faz
intake/import/triagem/abre case; admin gerencia assets e faz rollback de import.
"""
import hashlib

from fastapi import (APIRouter, Depends, File, Form, HTTPException, Query,
                     Request, UploadFile)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, correlation, credential_intel, exposure_ingest as ing, risk
from app.auth import (Principal, current_tenant_id, require_admin,
                      require_analyst, require_viewer)
from app.database import get_db
from app.models import (ASSET_TYPES, EXPOSURE_MVP_TYPES, EXPOSURE_TYPES,
                        ExposureFinding, ExposureIngestBatch, InvestigationCase,
                        MonitoredAsset, utcnow)
from app.schemas import (ExposureFindingOut, ExposureIngestOut, ExposureIntake,
                         FindingTriage, MonitoredAssetCreate, MonitoredAssetOut,
                         MonitoredAssetUpdate)

router = APIRouter(prefix="/exposure", tags=["exposure"],
                   dependencies=[Depends(require_viewer)])

# defaults de confiabilidade (Admiralty) por fonte — analista pode sobrescrever
_SOURCE_DEFAULTS = {
    "stealer": ("B", "2"), "infostealer": ("B", "2"), "breach": ("B", "2"),
    "paste": ("C", "3"), "github": ("C", "2"), "repo": ("C", "2"),
    "osint": ("D", "4"), "manual_intake": ("C", "3"), "authorized_upload": ("C", "3"),
}
# exposure severity -> case severity (nomenclatura dos cases)
_SEV_TO_CASE = {"low": "baixo", "medium": "medio", "high": "alto", "critical": "critico"}


def _audit(db, principal, tid, request, action, target_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="exposure", target_id=target_id, request=request, detail=detail)


def _policy() -> str:
    return config.EXPOSURE_PII_MASKING


def _asset_out(a: MonitoredAsset, principal: Principal) -> dict:
    out = MonitoredAssetOut.model_validate(a).model_dump()
    cls = ing.PII if a.asset_type in ("identity", "email") else ing.PUBLIC
    out["value"] = ing.mask_value(out["value"], cls, principal.effective_role(), _policy())
    return out


def _finding_out(f: ExposureFinding, principal: Principal) -> dict:
    out = ExposureFindingOut.model_validate(f).model_dump()
    out["detail"] = ing.mask_detail(out.get("detail") or {}, principal.effective_role(), _policy())
    return out


def _owned_asset(db, asset_id, tid) -> MonitoredAsset:
    a = db.get(MonitoredAsset, asset_id)
    if a is None or a.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Monitored asset not found.")
    return a


def _owned_finding(db, finding_id, tid) -> ExposureFinding:
    f = db.get(ExposureFinding, finding_id)
    if f is None or f.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Exposure finding not found.")
    return f


def _owned_ingest(db, ingest_id, tid) -> ExposureIngestBatch:
    b = db.get(ExposureIngestBatch, ingest_id)
    if b is None or b.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Ingest batch not found.")
    return b


def _apply_risk(db, tid, f) -> None:
    """Recalcula risk_score + detail.risk_breakdown (determinístico)."""
    asset = None
    if f.asset_id:
        a = db.get(MonitoredAsset, f.asset_id)
        if a and a.tenant_id == tid:
            asset = a
    bd = risk.compute(f, asset)
    f.risk_score = bd["score"]
    f.detail = {**(f.detail or {}), "risk_breakdown": bd}


# ==================== monitored assets ====================
@router.post("/assets", status_code=201, dependencies=[Depends(require_admin)])
def create_asset(payload: MonitoredAssetCreate, request: Request,
                 db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    asset = MonitoredAsset(
        tenant_id=tid, asset_type=payload.asset_type, label=payload.label,
        value=payload.value, value_hash=ing.sha256_norm(payload.value),
        criticality=payload.criticality, consent_ref=payload.consent_ref,
        active=payload.active, created_by_user_id=principal.user_id)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    _audit(db, principal, tid, request, "exposure.asset_create", asset.id,
           {"asset_type": asset.asset_type, "criticality": asset.criticality})
    return _asset_out(asset, principal)


@router.get("/assets", dependencies=[Depends(require_viewer)])
def list_assets(db: Session = Depends(get_db), principal: Principal = Depends(require_viewer),
                tid: int = Depends(current_tenant_id),
                asset_type: str | None = Query(None), active: bool | None = Query(None)):
    stmt = select(MonitoredAsset).where(MonitoredAsset.tenant_id == tid)
    if asset_type:
        stmt = stmt.where(MonitoredAsset.asset_type == asset_type)
    if active is not None:
        stmt = stmt.where(MonitoredAsset.active == active)
    rows = db.scalars(stmt.order_by(MonitoredAsset.created_at.desc(), MonitoredAsset.id.desc()))
    return [_asset_out(a, principal) for a in rows]


@router.get("/assets/{asset_id}", dependencies=[Depends(require_viewer)])
def get_asset(asset_id: int, db: Session = Depends(get_db),
              principal: Principal = Depends(require_viewer),
              tid: int = Depends(current_tenant_id)):
    return _asset_out(_owned_asset(db, asset_id, tid), principal)


@router.patch("/assets/{asset_id}", dependencies=[Depends(require_admin)])
def update_asset(asset_id: int, payload: MonitoredAssetUpdate, request: Request,
                 db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    asset = _owned_asset(db, asset_id, tid)
    changes = {}
    for field in ("label", "criticality", "consent_ref", "active"):
        val = getattr(payload, field)
        if val is not None and val != getattr(asset, field):
            setattr(asset, field, val)
            changes[field] = val
    if changes:
        asset.updated_at = utcnow()
        db.commit()
        _audit(db, principal, tid, request, "exposure.asset_update", asset.id, {"changes": list(changes)})
    return _asset_out(asset, principal)


@router.delete("/assets/{asset_id}", status_code=204, dependencies=[Depends(require_admin)])
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    asset = _owned_asset(db, asset_id, tid)
    db.delete(asset)
    db.commit()
    _audit(db, principal, tid, request, "exposure.asset_delete", asset_id, {})
    return None


# ==================== findings: leitura ====================
@router.get("/findings", dependencies=[Depends(require_viewer)])
def list_findings(db: Session = Depends(get_db), principal: Principal = Depends(require_viewer),
                  tid: int = Depends(current_tenant_id),
                  exposure_type: str | None = Query(None), status: str | None = Query(None),
                  severity: str | None = Query(None), asset_id: int | None = Query(None),
                  ingest_id: int | None = Query(None)):
    stmt = select(ExposureFinding).where(ExposureFinding.tenant_id == tid)
    if exposure_type:
        stmt = stmt.where(ExposureFinding.exposure_type == exposure_type)
    if status:
        stmt = stmt.where(ExposureFinding.status == status)
    if severity:
        stmt = stmt.where(ExposureFinding.severity == severity)
    if asset_id is not None:
        stmt = stmt.where(ExposureFinding.asset_id == asset_id)
    if ingest_id is not None:
        stmt = stmt.where(ExposureFinding.ingest_id == ingest_id)
    rows = db.scalars(stmt.order_by(ExposureFinding.created_at.desc(), ExposureFinding.id.desc()))
    return [_finding_out(f, principal) for f in rows]


@router.get("/findings/{finding_id}", dependencies=[Depends(require_viewer)])
def get_finding(finding_id: int, db: Session = Depends(get_db),
                principal: Principal = Depends(require_viewer),
                tid: int = Depends(current_tenant_id)):
    return _finding_out(_owned_finding(db, finding_id, tid), principal)


@router.get("/findings/{finding_id}/risk", dependencies=[Depends(require_viewer)])
def get_finding_risk(finding_id: int, db: Session = Depends(get_db),
                     tid: int = Depends(current_tenant_id)):
    """Breakdown explicável do risk score (para a UI)."""
    f = _owned_finding(db, finding_id, tid)
    bd = (f.detail or {}).get("risk_breakdown")
    if not bd:
        asset = db.get(MonitoredAsset, f.asset_id) if f.asset_id else None
        bd = risk.compute(f, asset)
    return bd


# ==================== intake / import (Issue 2) ====================
def _reliability_for(source, rel, cred):
    d_rel, d_cred = _SOURCE_DEFAULTS.get((source or "").lower(), ("F", "6"))
    return (rel or d_rel), (cred or d_cred)


def _persist_record(db, tid, rec, *, source, principal, ingest=None):
    """Redige, calcula dedup e persiste (ou dedup). Retorna 'created'|'deduped'."""
    etype = rec["exposure_type"]
    detail = ing.redact_detail(rec.get("detail") or {})
    dkey = ing.dedup_key(tid, etype, detail)
    existing = db.scalar(select(ExposureFinding).where(
        ExposureFinding.tenant_id == tid, ExposureFinding.dedup_key == dkey))
    if existing is not None:
        existing.last_seen = utcnow()
        existing.detail = {**(existing.detail or {}),
                           "sightings": int((existing.detail or {}).get("sightings", 1)) + 1}
        _apply_risk(db, tid, existing)  # recomputa na deduplicação
        db.add(existing)
        if etype == "credential_exposure":
            credential_intel.update_identity(db, tid, existing, "deduped", principal)
        return "deduped", existing
    rel = rec.get("source_reliability")
    cred = rec.get("info_credibility")
    rel, cred = _reliability_for(source, rel, cred)
    f = ExposureFinding(
        tenant_id=tid, exposure_type=etype, asset_id=rec.get("asset_id"),
        title=rec.get("title") or f"{etype}", source=source,
        source_reliability=rel, info_credibility=cred,
        severity=rec.get("severity") or "medium", status="new",
        observed_at=rec.get("observed_at"),
        dedup_key=dkey, detail=detail, redacted=True,
        first_seen=utcnow(), last_seen=utcnow(),
        ingest_id=(ingest.id if ingest else None),
        record_number=rec.get("_line"),
        parser_version=(ingest.parser_version if ingest else None),
        created_by_user_id=principal.user_id)
    _apply_risk(db, tid, f)  # recomputa na ingestão
    db.add(f)
    if etype == "credential_exposure":
        credential_intel.update_identity(db, tid, f, "created", principal)
    return "created", f


@router.post("/findings/intake", status_code=201, dependencies=[Depends(require_analyst)])
def intake_finding(payload: ExposureIntake, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_analyst),
                   tid: int = Depends(current_tenant_id)):
    if payload.exposure_type not in EXPOSURE_MVP_TYPES:
        raise HTTPException(status_code=422, detail="exposure_type not supported in this edition.")
    if payload.asset_id is not None:
        _owned_asset(db, payload.asset_id, tid)  # 404 se cross-tenant
    rec = {"exposure_type": payload.exposure_type, "title": payload.title,
           "detail": payload.detail or {}, "asset_id": payload.asset_id,
           "severity": payload.severity, "observed_at": payload.observed_at,
           "source_reliability": payload.source_reliability,
           "info_credibility": payload.info_credibility}
    outcome, f = _persist_record(db, tid, rec, source=payload.source, principal=principal)
    db.commit()
    db.refresh(f)
    _audit(db, principal, tid, request, "exposure.intake", f.id,
           {"exposure_type": f.exposure_type, "outcome": outcome})  # sem segredos
    return _finding_out(f, principal)


@router.post("/import", status_code=201, dependencies=[Depends(require_analyst)])
def import_file(request: Request, file: UploadFile = File(...), parser: str = Form(...),
                db: Session = Depends(get_db),
                principal: Principal = Depends(require_analyst),
                tid: int = Depends(current_tenant_id)):
    if parser not in ing.PARSERS:
        raise HTTPException(status_code=422, detail="unknown parser.")
    if (file.content_type or "") not in config.EXPOSURE_IMPORT_ALLOWED_MIME:
        raise HTTPException(status_code=415, detail="unsupported file type.")
    raw = file.file.read(config.EXPOSURE_IMPORT_MAX_BYTES + 1)
    if len(raw) > config.EXPOSURE_IMPORT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="import file too large.")
    text = raw.decode("utf-8", errors="replace")
    file_hash = hashlib.sha256(raw).hexdigest()

    batch = ExposureIngestBatch(
        tenant_id=tid, source="file_import",
        original_filename=(file.filename or "")[:512], source_file_hash=file_hash,
        parser=parser, parser_version=ing.PARSER_VERSIONS[parser],
        status="processing", created_by_user_id=principal.user_id)
    db.add(batch)
    db.flush()  # obtém batch.id

    created = deduped = errors = total = 0
    for rec in ing.PARSERS[parser](text):
        total += 1
        if rec.get("_error"):
            errors += 1
            continue
        if rec.get("exposure_type") not in EXPOSURE_MVP_TYPES:
            errors += 1
            continue
        outcome, _f = _persist_record(db, tid, rec, source="file_import",
                                      principal=principal, ingest=batch)
        created += (outcome == "created")
        deduped += (outcome == "deduped")

    batch.record_count = total
    batch.created_count = created
    batch.deduped_count = deduped
    batch.error_count = errors
    batch.status = "completed"
    db.commit()
    db.refresh(batch)
    _audit(db, principal, tid, request, "exposure.import", batch.id,
           {"parser": parser, "source_file_hash": file_hash,
            "created": created, "deduped": deduped, "errors": errors})
    return ExposureIngestOut.model_validate(batch).model_dump()


# ==================== ingests (proveniência / rollback) ====================
@router.get("/ingests", dependencies=[Depends(require_viewer)])
def list_ingests(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    rows = db.scalars(select(ExposureIngestBatch).where(ExposureIngestBatch.tenant_id == tid)
                      .order_by(ExposureIngestBatch.created_at.desc(), ExposureIngestBatch.id.desc()))
    return [ExposureIngestOut.model_validate(b).model_dump() for b in rows]


@router.get("/ingests/{ingest_id}", dependencies=[Depends(require_viewer)])
def get_ingest(ingest_id: int, db: Session = Depends(get_db),
               tid: int = Depends(current_tenant_id)):
    return ExposureIngestOut.model_validate(_owned_ingest(db, ingest_id, tid)).model_dump()


@router.delete("/ingests/{ingest_id}", dependencies=[Depends(require_admin)])
def rollback_ingest(ingest_id: int, request: Request, db: Session = Depends(get_db),
                    principal: Principal = Depends(require_admin),
                    tid: int = Depends(current_tenant_id)):
    batch = _owned_ingest(db, ingest_id, tid)
    victims = list(db.scalars(select(ExposureFinding).where(
        ExposureFinding.tenant_id == tid, ExposureFinding.ingest_id == ingest_id)))
    removed = len(victims)
    for f in victims:
        db.delete(f)  # hard delete do import errado
    batch.status = "rolled_back"
    db.commit()
    _audit(db, principal, tid, request, "exposure.import_rollback", ingest_id,
           {"removed": removed})
    return {"ingest_id": ingest_id, "removed": removed, "status": "rolled_back"}


# ==================== triagem / abrir case ====================
@router.patch("/findings/{finding_id}", dependencies=[Depends(require_analyst)])
def triage_finding(finding_id: int, payload: FindingTriage, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_analyst),
                   tid: int = Depends(current_tenant_id)):
    f = _owned_finding(db, finding_id, tid)
    changes = {}
    for field in ("status", "severity", "source_reliability", "info_credibility"):
        val = getattr(payload, field)
        if val is not None and val != getattr(f, field):
            setattr(f, field, val)
            changes[field] = val
    if changes:
        _apply_risk(db, tid, f)  # recomputa na triagem
        db.commit()
        _audit(db, principal, tid, request, "exposure.finding_triage", f.id, {"changes": list(changes)})
    return _finding_out(f, principal)


def _unique_correlated_brand_id(db: Session, tid: int, finding_id: int) -> int | None:
    """If the finding's correlation graph points to exactly one brand, return
    its id. Returns None on zero or multiple candidate brands — never guesses
    among several possible brands."""
    graph = correlation.correlate(db, tid, "finding", finding_id)
    if not graph:
        return None
    brand_ids = {n["ref"]["id"] for n in graph.get("nodes", []) if n.get("kind") == "brand"}
    if len(brand_ids) == 1:
        return next(iter(brand_ids))
    return None


def _finding_context_description(db: Session, f: "ExposureFinding") -> str:
    """Human-readable case description carrying the operational context of the
    finding it was opened from (finding type, affected email/asset, source,
    risk score, import id when available)."""
    d = f.detail or {}
    affected = d.get("email") or d.get("domain") or d.get("url") or d.get("person_label")
    if not affected and f.asset_id:
        asset = db.get(MonitoredAsset, f.asset_id)
        affected = asset.label if asset else None

    lines = [f"Opened from exposure finding #{f.id} ({f.exposure_type})."]
    if affected:
        lines.append(f"Affected: {affected}")
    lines.append(f"Source: {f.source}")
    lines.append(f"Risk score: {f.risk_score}")
    if f.ingest_id:
        lines.append(f"Import id: {f.ingest_id}")
    return "\n".join(lines)


@router.post("/findings/{finding_id}/case", status_code=201, dependencies=[Depends(require_analyst)])
def open_case(finding_id: int, request: Request, db: Session = Depends(get_db),
              principal: Principal = Depends(require_analyst),
              tid: int = Depends(current_tenant_id)):
    f = _owned_finding(db, finding_id, tid)
    snapshot = {"exposure_finding_id": f.id, "exposure_type": f.exposure_type,
                "source": f.source, "source_reliability": f.source_reliability,
                "info_credibility": f.info_credibility, "dedup_key": f.dedup_key,
                "detail": f.detail}  # detail já redigido (sem segredo em claro)

    brand_id = _unique_correlated_brand_id(db, tid, f.id)
    # principal.user_id is None for operator/service-key principals, which do
    # not map to a tenant user row — the case is intentionally left unassigned
    # in that case rather than assigned to a nonexistent/wrong user.
    assignee_user_id = principal.user_id

    case = InvestigationCase(
        tenant_id=tid, brand_id=brand_id, title=(f.title or f"Exposure #{f.id}")[:255],
        description=_finding_context_description(db, f),
        severity=_SEV_TO_CASE.get(f.severity, "medio"), status="open",
        finding_snapshot=snapshot, created_by_user_id=principal.user_id,
        assignee_user_id=assignee_user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "exposure.case_opened", f.id,
           {"case_id": case.id, "brand_id": brand_id, "assignee_user_id": assignee_user_id})
    return {"case_id": case.id, "status": case.status, "severity": case.severity,
            "brand_id": case.brand_id, "assignee_user_id": case.assignee_user_id}


# ==================== catálogo de tipos ====================
@router.get("/types", dependencies=[Depends(require_viewer)])
def list_types():
    return [{"type": t, "mvp": t in EXPOSURE_MVP_TYPES} for t in EXPOSURE_TYPES]
