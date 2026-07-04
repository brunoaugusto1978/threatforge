"""Investigation Cases — tenant-scoped.

RBAC: viewer lê; analyst cria/edita campos e move entre estados ATIVOS;
assign/close/reopen são admin-only. Cross-tenant -> 404.
O case sobrevive a archive/delete/clear de brand/finding (FK SET NULL + snapshot).
"""
import json
import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, evidence_store, exporters, features
from app.auth import Principal, current_tenant_id, require_analyst, require_viewer
from app.database import get_db
from app.models import Brand, BrandFinding, CaseEvidence, CaseNote, InvestigationCase, User, utcnow
from app.schemas import CaseCreate, CaseOut, CaseUpdate, EvidenceOut, NoteCreate, NoteOut

router = APIRouter(prefix="/cases", tags=["cases"], dependencies=[Depends(require_viewer)])

ACTIVE = {"open", "triage", "investigating", "contained"}
TERMINAL = {"closed", "false_positive"}
_VERDICT_SEVERITY = {"malicious": "alto", "suspicious": "medio",
                     "low": "baixo", "no_known_threat": "baixo", "info": "baixo"}


def _owned_case(db: Session, case_id: int, tid: int) -> InvestigationCase:
    c = db.get(InvestigationCase, case_id)
    if c is None or c.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Case not found.")
    return c


def _is_admin(principal: Principal) -> bool:
    return principal.effective_role() == "admin"


def _validate_assignee(db: Session, tid: int, uid: int | None) -> None:
    if uid is None:
        return
    u = db.get(User, uid)
    if u is None or u.tenant_id != tid:
        raise HTTPException(status_code=422, detail="assignee_user_id must be a user of this tenant.")


def _snapshot(f: BrandFinding, brand: Brand | None) -> dict:
    return {
        "finding_id": f.id, "brand_id": f.brand_id,
        "brand_name": brand.name if brand else None,
        "domain": f.domain, "score": f.score, "verdict": f.verdict,
        "similarity": f.similarity, "source": f.source, "status": f.status,
        "captured_at": utcnow().isoformat(),
    }


def _active_case_for_finding(db: Session, tid: int, finding_id: int) -> InvestigationCase | None:
    return db.scalar(select(InvestigationCase).where(
        InvestigationCase.tenant_id == tid, InvestigationCase.finding_id == finding_id,
        InvestigationCase.status.in_(tuple(ACTIVE))))


def _audit(db, principal, tid, request, action, case_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="case", target_id=case_id, request=request, detail=detail)


@router.post("", status_code=201, dependencies=[Depends(require_analyst)])
def create_case(payload: CaseCreate, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(require_analyst),
                tid: int = Depends(current_tenant_id)):
    brand = None
    if payload.brand_id is not None:
        brand = db.get(Brand, payload.brand_id)
        if brand is None or brand.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Brand not found.")
    snapshot = None
    if payload.finding_id is not None:
        f = db.get(BrandFinding, payload.finding_id)
        if f is None or f.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Finding not found.")
        # consistência: finding deve pertencer à brand informada
        if brand is not None and f.brand_id != brand.id:
            raise HTTPException(status_code=422,
                                detail="finding_id does not belong to the given brand_id.")
        # duplicidade: já existe case ativo para o finding
        existing = _active_case_for_finding(db, tid, payload.finding_id)
        if existing is not None:
            raise HTTPException(status_code=409, detail={
                "message": "An active investigation already exists for this finding.",
                "existing_case_id": existing.id})
        snapshot = _snapshot(f, brand or db.get(Brand, f.brand_id))
        if brand is None:
            payload.brand_id = f.brand_id
    if payload.assignee_user_id is not None and not _is_admin(principal):
        raise HTTPException(status_code=403, detail="Assigning a case requires admin.")
    _validate_assignee(db, tid, payload.assignee_user_id)

    case = InvestigationCase(
        tenant_id=tid, brand_id=payload.brand_id, finding_id=payload.finding_id,
        finding_snapshot=snapshot, title=payload.title, description=payload.description,
        severity=payload.severity, status="open",
        assignee_user_id=payload.assignee_user_id, created_by_user_id=principal.user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "case.create", case.id,
           {"title": case.title, "severity": case.severity, "brand_id": case.brand_id,
            "finding_id": case.finding_id, "from_finding": False})
    return CaseOut.model_validate(case).model_dump()


@router.get("", dependencies=[Depends(require_viewer)])
def list_cases(status: str | None = None, severity: str | None = None,
               assignee_user_id: int | None = None, brand_id: int | None = None,
               q: str | None = None, limit: int = 100, offset: int = 0,
               db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    stmt = select(InvestigationCase).where(InvestigationCase.tenant_id == tid)
    if status:
        stmt = stmt.where(InvestigationCase.status == status)
    if severity:
        stmt = stmt.where(InvestigationCase.severity == severity)
    if assignee_user_id is not None:
        stmt = stmt.where(InvestigationCase.assignee_user_id == assignee_user_id)
    if brand_id is not None:
        stmt = stmt.where(InvestigationCase.brand_id == brand_id)
    if q:
        stmt = stmt.where(InvestigationCase.title.ilike(f"%{q}%"))
    stmt = stmt.order_by(InvestigationCase.created_at.desc()).limit(max(1, min(limit, 500))).offset(max(offset, 0))
    return [CaseOut.model_validate(c).model_dump() for c in db.scalars(stmt)]


@router.get("/{case_id}", dependencies=[Depends(require_viewer)])
def get_case(case_id: int, db: Session = Depends(get_db),
             tid: int = Depends(current_tenant_id)):
    return CaseOut.model_validate(_owned_case(db, case_id, tid)).model_dump()


@router.patch("/{case_id}", dependencies=[Depends(require_analyst)])
def update_case(case_id: int, payload: CaseUpdate, request: Request,
                db: Session = Depends(get_db),
                principal: Principal = Depends(require_analyst),
                tid: int = Depends(current_tenant_id)):
    case = _owned_case(db, case_id, tid)
    provided = payload.model_dump(exclude_unset=True)
    admin = _is_admin(principal)

    # assignee (admin-only)
    if "assignee_user_id" in provided:
        if not admin:
            raise HTTPException(status_code=403, detail="Assigning a case requires admin.")
        new_assignee = provided["assignee_user_id"]
        _validate_assignee(db, tid, new_assignee)
        if new_assignee != case.assignee_user_id:
            old = case.assignee_user_id
            case.assignee_user_id = new_assignee
            _audit(db, principal, tid, request, "case.assign", case.id,
                   {"assignee": {"from": old, "to": new_assignee}})

    # status transitions
    if "status" in provided and provided["status"] != case.status:
        old, new = case.status, provided["status"]
        if old in ACTIVE and new in ACTIVE:
            case.status = new
            _audit(db, principal, tid, request, "case.status_change", case.id,
                   {"status": {"from": old, "to": new}})
        elif old in ACTIVE and new in TERMINAL:
            if not admin:
                raise HTTPException(status_code=403, detail="Closing a case requires admin.")
            case.status = new
            case.closed_at = utcnow()
            _audit(db, principal, tid, request, "case.close", case.id,
                   {"status": {"from": old, "to": new}, "closed_at": case.closed_at.isoformat()})
        elif old in TERMINAL and new in ACTIVE:
            if not admin:
                raise HTTPException(status_code=403, detail="Reopening a case requires admin.")
            case.status = new
            case.closed_at = None
            _audit(db, principal, tid, request, "case.reopen", case.id,
                   {"status": {"from": old, "to": new}})
        else:
            raise HTTPException(status_code=422, detail=f"Invalid status transition: {old} -> {new}")

    # campos operacionais (analyst+)
    changes = {}
    for f in ("title", "description", "severity"):
        if f in provided and provided[f] != getattr(case, f):
            changes[f] = {"from": getattr(case, f), "to": provided[f]}
            setattr(case, f, provided[f])

    case.updated_at = utcnow()
    db.commit()
    db.refresh(case)
    if changes:
        _audit(db, principal, tid, request, "case.update", case.id, {"changes": changes})
    return CaseOut.model_validate(case).model_dump()


@router.post("/{case_id}/notes", status_code=201, dependencies=[Depends(require_analyst)])
def add_note(case_id: int, payload: NoteCreate, request: Request,
             db: Session = Depends(get_db),
             principal: Principal = Depends(require_analyst),
             tid: int = Depends(current_tenant_id)):
    """Adiciona nota interna ao case (append-only)."""
    case = _owned_case(db, case_id, tid)
    note = CaseNote(tenant_id=tid, case_id=case.id, author_user_id=principal.user_id,
                    body=payload.body, is_internal=payload.is_internal)
    db.add(note)
    db.commit()
    db.refresh(note)
    _audit(db, principal, tid, request, "case.note_added", case.id,
           {"note_id": note.id, "length": len(payload.body)})
    return NoteOut.model_validate(note).model_dump()


@router.get("/{case_id}/notes", dependencies=[Depends(require_viewer)])
def list_notes(case_id: int, db: Session = Depends(get_db),
               tid: int = Depends(current_tenant_id)):
    _owned_case(db, case_id, tid)
    rows = db.scalars(select(CaseNote).where(
        CaseNote.tenant_id == tid, CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.asc(), CaseNote.id.asc()))
    return [NoteOut.model_validate(n).model_dump() for n in rows]




def _evidence_out(e: CaseEvidence) -> dict:
    return {
        "id": e.id, "tenant_id": e.tenant_id, "case_id": e.case_id,
        "finding_id": e.finding_id, "filename": e.filename, "mime_type": e.mime_type,
        "size_bytes": e.size_bytes, "sha256": e.sha256, "origin": e.origin,
        "description": e.description,
        "stored": (e.storage_backend == "local" and bool(e.storage_key)),
        "uploaded_by_user_id": e.uploaded_by_user_id, "created_at": e.created_at,
    }


def _owned_evidence(db, case_id, ev_id, tid):
    e = db.get(CaseEvidence, ev_id)
    if e is None or e.tenant_id != tid or e.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return e


@router.post("/{case_id}/evidence", status_code=201, dependencies=[Depends(require_analyst)])
def add_evidence(case_id: int, request: Request, file: UploadFile = File(...),
                 origin: str = Form("manual_upload"), description: str | None = Form(None),
                 finding_id: int | None = Form(None),
                 db: Session = Depends(get_db),
                 principal: Principal = Depends(require_analyst),
                 tid: int = Depends(current_tenant_id)):
    case = _owned_case(db, case_id, tid)
    if origin not in config.EVIDENCE_ORIGINS:
        raise HTTPException(status_code=422, detail=f"invalid origin: {origin}")
    if (file.content_type or "") not in config.EVIDENCE_ALLOWED_MIME:
        raise HTTPException(status_code=415, detail=f"MIME type not allowed: {file.content_type}")
    if finding_id is not None:
        f = db.get(BrandFinding, finding_id)
        if f is None or f.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Finding not found.")
        # consistência evidência x case x finding/brand (mesmo tenant)
        if case.finding_id is not None and finding_id != case.finding_id:
            raise HTTPException(status_code=422,
                                detail="finding_id must match the case's finding.")
        if case.brand_id is not None and f.brand_id != case.brand_id:
            raise HTTPException(status_code=422,
                                detail="finding does not belong to the case's brand.")
    # sniff de conteúdo (anti content-type forjado)
    head = file.file.read(512)
    file.file.seek(0)
    if not evidence_store.sniff_ok(file.content_type or "", head):
        raise HTTPException(status_code=415,
                            detail="file content does not match the declared MIME type.")
    safe = os.path.basename(file.filename or "file")
    safe = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in safe)[:512] or "file"
    try:
        meta = evidence_store.save_stream(file, tid, case_id)
    except evidence_store.EvidenceTooLarge:
        raise HTTPException(status_code=413,
                            detail=f"file exceeds limit ({config.EVIDENCE_MAX_BYTES} bytes)")
    except evidence_store.EvidenceConfigError:
        raise HTTPException(status_code=500, detail="evidence storage is misconfigured.")
    ev = CaseEvidence(
        tenant_id=tid, case_id=case.id, finding_id=finding_id, filename=safe,
        mime_type=file.content_type, size_bytes=meta["size"], sha256=meta["sha256"],
        origin=origin, description=description, storage_backend=meta["backend"],
        storage_key=meta["storage_key"], uploaded_by_user_id=principal.user_id)
    try:
        db.add(ev)
        db.commit()
        db.refresh(ev)
    except Exception:
        db.rollback()
        evidence_store.delete_key(meta["storage_key"])  # remove órfão sem registro
        raise HTTPException(status_code=500, detail="failed to persist evidence record.")
    out = _evidence_out(ev)
    _audit(db, principal, tid, request, "evidence.add", case.id,
           {"evidence_id": ev.id, "filename": ev.filename, "mime_type": ev.mime_type,
            "size_bytes": ev.size_bytes, "sha256": ev.sha256, "origin": ev.origin,
            "stored": out["stored"]})
    return out


@router.get("/{case_id}/evidence", dependencies=[Depends(require_viewer)])
def list_evidence(case_id: int, db: Session = Depends(get_db),
                  tid: int = Depends(current_tenant_id)):
    _owned_case(db, case_id, tid)
    rows = db.scalars(select(CaseEvidence).where(
        CaseEvidence.tenant_id == tid, CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.created_at.asc(), CaseEvidence.id.asc()))
    return [_evidence_out(e) for e in rows]


@router.get("/{case_id}/evidence/{ev_id}", dependencies=[Depends(require_viewer)])
def get_evidence(case_id: int, ev_id: int, db: Session = Depends(get_db),
                 tid: int = Depends(current_tenant_id)):
    return _evidence_out(_owned_evidence(db, case_id, ev_id, tid))


@router.get("/{case_id}/evidence/{ev_id}/download")
def download_evidence(case_id: int, ev_id: int, request: Request,
                      db: Session = Depends(get_db),
                      principal: Principal = Depends(require_viewer),
                      tid: int = Depends(current_tenant_id)):
    e = _owned_evidence(db, case_id, ev_id, tid)
    if e.storage_backend != "local" or not e.storage_key:
        raise HTTPException(status_code=409,
                            detail="Binary not retained for this evidence (metadata-only).")
    path = evidence_store.path_for(e.storage_key)
    if not os.path.exists(path):
        raise HTTPException(status_code=410, detail="Stored file missing.")
    _audit(db, principal, tid, request, "evidence.download", case_id,
           {"evidence_id": e.id, "sha256": e.sha256})
    return FileResponse(path, media_type=e.mime_type or "application/octet-stream",
                        filename=e.filename)


# abrir case a partir de um finding
@router.get("/{case_id}/export.md", dependencies=[Depends(require_viewer)])
def export_case_markdown(case_id: int, request: Request,
                         db: Session = Depends(get_db),
                         principal: Principal = Depends(require_viewer),
                         tid: int = Depends(current_tenant_id)):
    """Export gratuito (Community) em Markdown. viewer+ que pode ler o case.

    Inclui metadados, snapshot do finding, notes e metadados de evidence.
    Nunca inclui binários, storage_key, caminhos locais ou segredos.
    """
    case = _owned_case(db, case_id, tid)  # tenant-scoped; cross-tenant -> 404
    notes = list(db.scalars(select(CaseNote).where(
        CaseNote.tenant_id == tid, CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.asc(), CaseNote.id.asc())))
    evidence = list(db.scalars(select(CaseEvidence).where(
        CaseEvidence.tenant_id == tid, CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.created_at.asc(), CaseEvidence.id.asc())))
    md = exporters.render_case_markdown(case, notes, evidence, edition=config.EDITION)
    _audit(db, principal, tid, request, "case.export", case.id,
           {"format": "markdown", "notes": len(notes), "evidence": len(evidence)})
    return Response(content=md, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="case-{case.id}.md"'})


@router.get("/{case_id}/export.stix.json", dependencies=[Depends(require_viewer)])
def export_case_stix(case_id: int, request: Request,
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_viewer),
                     tid: int = Depends(current_tenant_id)):
    """Export STIX 2.1 (partial) LOCAL do case. Community, gratuito.

    Indicadores do domínio do finding + hashes SHA-256 das evidências, mais um
    report do case. Interop offline (importar no MISP/OpenCTI do cliente). Sem
    rede, sem secrets, sem storage_key/paths. Push automático é Enterprise.
    """
    case = _owned_case(db, case_id, tid)  # tenant-scoped; cross-tenant -> 404
    evidence = list(db.scalars(select(CaseEvidence).where(
        CaseEvidence.tenant_id == tid, CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.created_at.asc(), CaseEvidence.id.asc())))
    bundle = exporters.render_case_stix_bundle(case, evidence)
    _audit(db, principal, tid, request, "case.export", case.id,
           {"format": "stix", "indicators": len(bundle["objects"]) - 2})
    return Response(content=json.dumps(bundle, ensure_ascii=False),
                    media_type="application/stix+json;version=2.1",
                    headers={"Content-Disposition": f'attachment; filename="case-{case.id}.stix.json"'})


@router.get("/{case_id}/export.pdf", dependencies=[Depends(require_viewer)])
def export_case_pdf(case_id: int, request: Request,
                    db: Session = Depends(get_db),
                    principal: Principal = Depends(require_viewer),
                    tid: int = Depends(current_tenant_id)):
    """PDF premium — bloqueado no Community.

    A geração real vive no pacote threatforge-enterprise (override de
    exporters.render_case_pdf). Aqui apenas expomos o adapter e recusamos com
    402, sem vazar detalhes do módulo Enterprise.
    """
    case = _owned_case(db, case_id, tid)  # tenant-scoped; cross-tenant -> 404
    try:
        pdf_bytes = exporters.render_case_pdf(case, edition=config.EDITION)
    except features.EnterpriseFeatureRequired as exc:
        _audit(db, principal, tid, request, "feature.denied", case.id,
               {"feature": exc.feature, "edition": config.EDITION})
        _audit(db, principal, tid, request, "case.export_pdf_denied", case.id,
               {"edition": config.EDITION})
        raise exc
    # Enterprise path (licensed): real bytes produced via the adapter.
    _audit(db, principal, tid, request, "feature.allowed", case.id,
           {"feature": features.Feature.EXPORT_PDF.value, "edition": config.EDITION})
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="case-{case.id}.pdf"'})


finding_router = APIRouter(prefix="/brands", tags=["cases"], dependencies=[Depends(require_viewer)])


@finding_router.post("/{brand_id}/findings/{finding_id}/case", status_code=201,
                     dependencies=[Depends(require_analyst)])
def open_case_from_finding(brand_id: int, finding_id: int, request: Request,
                           db: Session = Depends(get_db),
                           principal: Principal = Depends(require_analyst),
                           tid: int = Depends(current_tenant_id)):
    brand = db.get(Brand, brand_id)
    if brand is None or brand.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Brand not found.")
    f = db.get(BrandFinding, finding_id)
    if f is None or f.tenant_id != tid or f.brand_id != brand_id:
        raise HTTPException(status_code=404, detail="Finding not found.")

    existing = _active_case_for_finding(db, tid, finding_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail={
            "message": "An active investigation already exists for this finding.",
            "existing_case_id": existing.id})

    case = InvestigationCase(
        tenant_id=tid, brand_id=brand_id, finding_id=finding_id,
        finding_snapshot=_snapshot(f, brand),
        title=f"Investigation: {f.domain}",
        severity=_VERDICT_SEVERITY.get(f.verdict, "medio"), status="open",
        created_by_user_id=principal.user_id)
    db.add(case)
    db.commit()
    db.refresh(case)
    _audit(db, principal, tid, request, "case.create", case.id,
           {"title": case.title, "severity": case.severity, "brand_id": brand_id,
            "finding_id": finding_id, "from_finding": True})
    return CaseOut.model_validate(case).model_dump()
