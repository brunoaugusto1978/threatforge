from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.alerts import dispatch_new_findings, send_finding_alert
from app.auth import Principal, current_tenant_id, require_admin, require_analyst, require_viewer
from app.brand.scanner import scan_brand
from app.database import get_db
from app.models import Brand, BrandFinding
from app.schemas import (
    BrandCreate,
    BrandOut,
    BrandUpdate,
    FindingOut,
    FindingStatusUpdate,
    ScanResult,
)

router = APIRouter(prefix="/brands", tags=["brands"], dependencies=[Depends(require_viewer)])


def _owned_brand(db: Session, brand_id: int, tid: int) -> Brand:
    brand = db.get(Brand, brand_id)
    if brand is None or brand.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Brand not found.")
    return brand


def _owned_finding(db: Session, finding_id: int, tid: int) -> BrandFinding:
    f = db.get(BrandFinding, finding_id)
    if f is None or f.tenant_id != tid:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return f


@router.post("", response_model=BrandOut, status_code=201,
             dependencies=[Depends(require_analyst)])
def create_brand(payload: BrandCreate, db: Session = Depends(get_db),
                 tid: int = Depends(current_tenant_id)):
    if db.scalar(select(Brand).where(Brand.tenant_id == tid, Brand.name == payload.name)):
        raise HTTPException(status_code=409, detail="Brand already registered.")
    brand = Brand(
        tenant_id=tid,
        name=payload.name,
        official_domains=",".join(payload.official_domains),
        keywords=",".join(payload.keywords) if payload.keywords else None,
        variations=payload.variations or None,
        aliases=payload.aliases or None,
        products=payload.products or None,
        subdomains=payload.subdomains or None,
        social_profiles=payload.social_profiles or None,
        sensitive_terms=payload.sensitive_terms or None,
        logo_url=payload.logo_url or None,
    )
    db.add(brand)
    db.commit()
    db.refresh(brand)
    return brand


@router.get("", response_model=list[BrandOut])
def list_brands(db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    return list(db.scalars(
        select(Brand).where(Brand.tenant_id == tid).order_by(Brand.id.desc())))


@router.get("/{brand_id}", response_model=BrandOut)
def get_brand(brand_id: int, db: Session = Depends(get_db),
              tid: int = Depends(current_tenant_id)):
    return _owned_brand(db, brand_id, tid)


@router.patch("/{brand_id}", response_model=BrandOut,
              dependencies=[Depends(require_admin)])
def update_brand(brand_id: int, payload: BrandUpdate, request: Request,
                 db: Session = Depends(get_db),
                 principal: Principal = Depends(require_admin),
                 tid: int = Depends(current_tenant_id),
                 clear_findings: bool = False):
    """Edita name/official_domains da marca. Tenant-scoped + audit.
    platform_admin (via X-Tenant-Id) edita qualquer tenant; tenant_admin edita o
    proprio. support_operator/viewer e analyst nao editam (require_admin)."""
    brand = _owned_brand(db, brand_id, tid)
    changes: dict = {}
    if payload.name is not None and payload.name != brand.name:
        dup = db.scalar(select(Brand).where(
            Brand.tenant_id == tid, Brand.name == payload.name, Brand.id != brand_id))
        if dup is not None:
            raise HTTPException(status_code=409, detail="Brand already registered.")
        changes["name"] = {"from": brand.name, "to": payload.name}
        brand.name = payload.name
    if payload.official_domains is not None:
        new_csv = ",".join(payload.official_domains)
        if new_csv != (brand.official_domains or ""):
            changes["official_domains"] = {"from": brand.official_domains, "to": new_csv}
            brand.official_domains = new_csv
    cleared = 0
    if clear_findings and "official_domains" in changes:
        rows = db.query(BrandFinding).filter(
            BrandFinding.tenant_id == tid, BrandFinding.brand_id == brand_id).all()
        cleared = len(rows)
        for r in rows:
            db.delete(r)
    db.commit()
    db.refresh(brand)
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action="brand.update",
                 target_type="brand", target_id=brand_id, request=request,
                 detail={"changes": changes, "findings_cleared": cleared})
    return brand


@router.delete("/{brand_id}", status_code=204, dependencies=[Depends(require_admin)])
def delete_brand(brand_id: int, db: Session = Depends(get_db),
                 tid: int = Depends(current_tenant_id)):
    brand = _owned_brand(db, brand_id, tid)
    db.delete(brand)
    db.commit()


@router.post("/{brand_id}/scan", response_model=ScanResult)
def scan(brand_id: int, request: Request, deep: bool = True,
         db: Session = Depends(get_db),
         principal: Principal = Depends(require_analyst),
         tid: int = Depends(current_tenant_id)):
    brand = _owned_brand(db, brand_id, tid)

    result = scan_brand(brand, db, deep=deep)
    if result.get("error"):
        raise HTTPException(status_code=422, detail=result["error"])

    new = [db.get(BrandFinding, fid) for fid in result.get("new_finding_ids", [])]
    sent = dispatch_new_findings(brand, [f for f in new if f], db)
    result["alerts_sent"] = sent
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 action="brand.scan", target_type="brand", target_id=brand_id,
                 request=request,
                 detail={"deep": deep, "new_findings": result.get("new_findings"),
                         "alerts_sent": sent})
    return result


@router.get("/{brand_id}/findings", response_model=list[FindingOut])
def list_findings(
    brand_id: int,
    verdict: str | None = None,
    status: str | None = None,
    min_score: int = 0,
    db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
):
    _owned_brand(db, brand_id, tid)
    stmt = (
        select(BrandFinding)
        .where(BrandFinding.tenant_id == tid, BrandFinding.brand_id == brand_id,
               BrandFinding.score >= min_score)
        .order_by(BrandFinding.score.desc(), BrandFinding.last_seen.desc())
    )
    if verdict:
        stmt = stmt.where(BrandFinding.verdict == verdict)
    if status:
        stmt = stmt.where(BrandFinding.status == status)
    return list(db.scalars(stmt))


@router.patch("/findings/{finding_id}", response_model=FindingOut,
              dependencies=[Depends(require_analyst)])
def update_finding_status(
    finding_id: int, payload: FindingStatusUpdate, db: Session = Depends(get_db),
    tid: int = Depends(current_tenant_id),
):
    f = _owned_finding(db, finding_id, tid)
    f.status = payload.status
    db.commit()
    db.refresh(f)
    return f


@router.post("/findings/{finding_id}/alert", dependencies=[Depends(require_analyst)])
def resend_alert(finding_id: int, db: Session = Depends(get_db),
                 tid: int = Depends(current_tenant_id)):
    f = _owned_finding(db, finding_id, tid)
    brand = db.get(Brand, f.brand_id)
    summary = send_finding_alert(brand, f)
    f.alerted = True
    db.commit()
    return {"sent": True, "summary": summary}
