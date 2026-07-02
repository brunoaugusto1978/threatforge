"""Exposure Monitoring (DRP) — Community: modelo + monitored assets + leitura de findings.

Isolamento por tenant (cross-tenant -> 404). RBAC: viewer lê catálogo/findings;
admin cria/edita/remove assets. Intake/dedup/redação de segredos vêm na Issue 2.
Segurança: nenhuma senha/token/segredo em claro — o modelo não tem coluna de
segredo; dados sensíveis futuros ficam em `detail` apenas como hash+máscara.
"""
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.auth import Principal, current_tenant_id, require_admin, require_viewer
from app.database import get_db
from app.models import (
    ASSET_TYPES,
    EXPOSURE_TYPES,
    ExposureFinding,
    MonitoredAsset,
    utcnow,
)
from app.schemas import (
    ExposureFindingOut,
    MonitoredAssetCreate,
    MonitoredAssetOut,
    MonitoredAssetUpdate,
)

router = APIRouter(prefix="/exposure", tags=["exposure"],
                   dependencies=[Depends(require_viewer)])


def _audit(db, principal, tid, request, action, target_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="exposure", target_id=target_id, request=request, detail=detail)


def _normalize(value: str) -> str:
    return (value or "").strip().lower()


def _value_hash(value: str) -> str:
    return hashlib.sha256(_normalize(value).encode("utf-8")).hexdigest()


def _owned_asset(db: Session, asset_id: int, tid: int) -> MonitoredAsset:
    a = db.get(MonitoredAsset, asset_id)
    if a is None or a.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Monitored asset not found.")
    return a


# ---------------- monitored assets ----------------
@router.post("/assets", status_code=201, dependencies=[Depends(require_admin)])
def create_asset(payload: MonitoredAssetCreate, request: Request,
                 db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    asset = MonitoredAsset(
        tenant_id=tid, asset_type=payload.asset_type, label=payload.label,
        value=payload.value, value_hash=_value_hash(payload.value),
        criticality=payload.criticality, consent_ref=payload.consent_ref,
        active=payload.active, created_by_user_id=principal.user_id)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    _audit(db, principal, tid, request, "exposure.asset_create", asset.id,
           {"asset_type": asset.asset_type, "criticality": asset.criticality})
    return MonitoredAssetOut.model_validate(asset).model_dump()


@router.get("/assets", dependencies=[Depends(require_viewer)])
def list_assets(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id),
                asset_type: str | None = Query(None), active: bool | None = Query(None)):
    stmt = select(MonitoredAsset).where(MonitoredAsset.tenant_id == tid)
    if asset_type:
        stmt = stmt.where(MonitoredAsset.asset_type == asset_type)
    if active is not None:
        stmt = stmt.where(MonitoredAsset.active == active)
    rows = db.scalars(stmt.order_by(MonitoredAsset.created_at.desc(), MonitoredAsset.id.desc()))
    return [MonitoredAssetOut.model_validate(a).model_dump() for a in rows]


@router.get("/assets/{asset_id}", dependencies=[Depends(require_viewer)])
def get_asset(asset_id: int, db: Session = Depends(get_db),
              tid: int = Depends(current_tenant_id)):
    return MonitoredAssetOut.model_validate(_owned_asset(db, asset_id, tid)).model_dump()


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
    return MonitoredAssetOut.model_validate(asset).model_dump()


@router.delete("/assets/{asset_id}", status_code=204, dependencies=[Depends(require_admin)])
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id)):
    asset = _owned_asset(db, asset_id, tid)
    db.delete(asset)
    db.commit()
    _audit(db, principal, tid, request, "exposure.asset_delete", asset_id, {})
    return None


# ---------------- exposure findings (leitura; intake = Issue 2) ----------------
@router.get("/findings", dependencies=[Depends(require_viewer)])
def list_findings(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id),
                  exposure_type: str | None = Query(None), status: str | None = Query(None),
                  severity: str | None = Query(None), asset_id: int | None = Query(None)):
    stmt = select(ExposureFinding).where(ExposureFinding.tenant_id == tid)
    if exposure_type:
        stmt = stmt.where(ExposureFinding.exposure_type == exposure_type)
    if status:
        stmt = stmt.where(ExposureFinding.status == status)
    if severity:
        stmt = stmt.where(ExposureFinding.severity == severity)
    if asset_id is not None:
        stmt = stmt.where(ExposureFinding.asset_id == asset_id)
    rows = db.scalars(stmt.order_by(ExposureFinding.created_at.desc(), ExposureFinding.id.desc()))
    return [ExposureFindingOut.model_validate(f).model_dump() for f in rows]


@router.get("/findings/{finding_id}", dependencies=[Depends(require_viewer)])
def get_finding(finding_id: int, db: Session = Depends(get_db),
                tid: int = Depends(current_tenant_id)):
    f = db.get(ExposureFinding, finding_id)
    if f is None or f.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Exposure finding not found.")
    return ExposureFindingOut.model_validate(f).model_dump()


# tipos suportados (catálogo público do enum; MVP marca o que está ativo)
@router.get("/types", dependencies=[Depends(require_viewer)])
def list_types():
    from app.models import EXPOSURE_MVP_TYPES
    return [{"type": t, "mvp": t in EXPOSURE_MVP_TYPES} for t in EXPOSURE_TYPES]
