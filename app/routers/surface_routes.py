"""Attack Surface Discovery (ASD) — Community: modelo + import manual + triagem.

Descoberta passiva (reuso do scanner de Brand) vem na PR 2; varredura ATIVA
(portas/serviços/feeds) é Enterprise, atrás do feature gate (PR posterior).

Isolamento por tenant (cross-tenant -> 404). RBAC: viewer lê; analyst importa e
faz triagem; admin (descoberta passiva/ativa nos PRs seguintes).
"""
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, surface_discovery
from app.auth import (Principal, current_tenant_id, require_admin,
                      require_analyst, require_viewer)
from app.database import get_db
from app.models import (SURFACE_ASSET_TYPES, SURFACE_MVP_TYPES, Brand,
                        SurfaceAsset, utcnow)
from app.schemas import SurfaceAssetOut, SurfaceImport, SurfaceTriage

router = APIRouter(prefix="/surface", tags=["surface"],
                   dependencies=[Depends(require_viewer)])


def _audit(db, principal, tid, request, action, target_id, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="surface", target_id=target_id, request=request, detail=detail)


def _norm(v: str) -> str:
    return (str(v or "")).strip().lower()


def _value_hash(asset_type: str, value: str) -> str:
    return hashlib.sha256(f"{asset_type}|{_norm(value)}".encode("utf-8")).hexdigest()


def _dedup_key(tid: int, asset_type: str, value: str) -> str:
    return hashlib.sha256(f"{tid}|{asset_type}|{_norm(value)}".encode("utf-8")).hexdigest()


def _owned(db, asset_id, tid) -> SurfaceAsset:
    a = db.get(SurfaceAsset, asset_id)
    if a is None or a.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Surface asset not found.")
    return a


def _out(a: SurfaceAsset) -> dict:
    return SurfaceAssetOut.model_validate(a).model_dump()


@router.post("/import", status_code=201, dependencies=[Depends(require_analyst)])
def import_surface(payload: SurfaceImport, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_analyst),
                   tid: int = Depends(current_tenant_id)):
    """Import manual/autorizado de ativos de superfície (subdomain/ip/certificate).

    Idempotente por (tenant, asset_type, value): repetição atualiza last_seen.
    """
    brand_id = payload.brand_id
    if brand_id is not None:
        b = db.get(Brand, brand_id)
        if b is None or b.tenant_id != tid:
            raise HTTPException(status_code=404, detail="Brand not found.")
    created = deduped = 0
    ids = []
    for item in payload.assets:
        if item.asset_type not in SURFACE_MVP_TYPES:
            raise HTTPException(status_code=422, detail=f"asset_type not supported: {item.asset_type}")
        b_id = item.brand_id if item.brand_id is not None else brand_id
        if b_id is not None:
            b = db.get(Brand, b_id)
            if b is None or b.tenant_id != tid:
                raise HTTPException(status_code=404, detail="Brand not found.")
        dkey = _dedup_key(tid, item.asset_type, item.value)
        existing = db.scalar(select(SurfaceAsset).where(
            SurfaceAsset.tenant_id == tid, SurfaceAsset.dedup_key == dkey))
        if existing is not None:
            existing.last_seen = utcnow()
            db.add(existing)
            deduped += 1
            ids.append(existing.id)
            continue
        a = SurfaceAsset(
            tenant_id=tid, brand_id=b_id, asset_type=item.asset_type,
            value=item.value.strip(), value_hash=_value_hash(item.asset_type, item.value),
            source="manual_import", detail=item.detail or {}, status="new",
            dedup_key=dkey, created_by_user_id=principal.user_id)
        db.add(a)
        db.flush()
        created += 1
        ids.append(a.id)
    db.commit()
    _audit(db, principal, tid, request, "surface.import", None,
           {"created": created, "deduped": deduped, "brand_id": brand_id})
    return {"created": created, "deduped": deduped, "asset_ids": ids}


@router.get("/assets", dependencies=[Depends(require_viewer)])
def list_surface(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id),
                 asset_type: str | None = Query(None), status: str | None = Query(None),
                 brand_id: int | None = Query(None)):
    stmt = select(SurfaceAsset).where(SurfaceAsset.tenant_id == tid)
    if asset_type:
        stmt = stmt.where(SurfaceAsset.asset_type == asset_type)
    if status:
        stmt = stmt.where(SurfaceAsset.status == status)
    if brand_id is not None:
        stmt = stmt.where(SurfaceAsset.brand_id == brand_id)
    rows = db.scalars(stmt.order_by(SurfaceAsset.created_at.desc(), SurfaceAsset.id.desc()))
    return [_out(a) for a in rows]


@router.get("/assets/{asset_id}", dependencies=[Depends(require_viewer)])
def get_surface(asset_id: int, db: Session = Depends(get_db),
                tid: int = Depends(current_tenant_id)):
    return _out(_owned(db, asset_id, tid))


@router.patch("/assets/{asset_id}", dependencies=[Depends(require_analyst)])
def triage_surface(asset_id: int, payload: SurfaceTriage, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_analyst),
                   tid: int = Depends(current_tenant_id)):
    a = _owned(db, asset_id, tid)
    if payload.status != a.status:
        a.status = payload.status
        db.commit()
        _audit(db, principal, tid, request, "surface.triage", a.id, {"status": a.status})
    return _out(a)


@router.post("/discover", status_code=201, dependencies=[Depends(require_admin)])
def discover(request: Request, brand_id: int = Query(...),
             db: Session = Depends(get_db),
             principal: Principal = Depends(require_admin),
             tid: int = Depends(current_tenant_id)):
    """Descoberta PASSIVA a partir das official_domains da brand (CT/DNS/RDAP/TLS).

    Materializa surface_assets (subdomain->ip->certificate). Sem varredura ativa
    (Enterprise). Idempotente por (tenant, type, value).
    """
    b = db.get(Brand, brand_id)
    if b is None or b.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Brand not found.")
    result = surface_discovery.discover_brand(db, tid, b)
    _audit(db, principal, tid, request, "surface.discover", brand_id,
           {"created": result["created"], "deduped": result["deduped"], "counts": result["counts"]})
    return result


@router.get("/types", dependencies=[Depends(require_viewer)])
def list_types():
    return [{"type": t, "mvp": t in SURFACE_MVP_TYPES} for t in SURFACE_ASSET_TYPES]
