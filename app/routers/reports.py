from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Observable
from app.reporting import render_report

router = APIRouter(
    prefix="/reports", tags=["reports"], dependencies=[Depends(require_api_key)]
)


@router.get("/observable/{observable_id}", response_class=PlainTextResponse)
def report_observable(observable_id: int, db: Session = Depends(get_db)):
    obs = db.get(Observable, observable_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Observável não encontrado.")
    return PlainTextResponse(render_report(obs), media_type="text/markdown; charset=utf-8")
