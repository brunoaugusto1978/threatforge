"""Correlation Engine API — logical graph across entities (tenant-scoped).

GET /correlation?entity=finding:{id}|asset:{id}|observable:{id}|email:{v}|domain:{v}|hash:{v}
Returns {seed, nodes, edges, identifiers}. Cross-tenant / unknown entity -> 404.
Read-only; investigations are opened via existing endpoints (e.g. exposure case).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import correlation
from app.auth import current_tenant_id, require_viewer
from app.database import get_db

router = APIRouter(prefix="/correlation", tags=["correlation"],
                   dependencies=[Depends(require_viewer)])

_ENTITY_KINDS = {"finding", "asset", "observable", "email", "domain", "hash", "ip"}


@router.get("")
def get_correlation(entity: str = Query(..., description="finding:{id} | asset:{id} | observable:{id} | email:{v} | domain:{v} | hash:{v}"),
                    db: Session = Depends(get_db), tid: int = Depends(current_tenant_id)):
    kind, sep, ref = entity.partition(":")
    if not sep or kind not in _ENTITY_KINDS or not ref:
        raise HTTPException(status_code=422, detail="invalid entity selector.")
    if kind in ("finding", "asset", "observable"):
        try:
            ref = int(ref)
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid entity id.")
    graph = correlation.correlate(db, tid, kind, ref)
    if graph is None:
        raise HTTPException(status_code=404, detail="entity not found.")
    return graph
