import logging
import os

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config
from app.auth import require_viewer
from app.bootstrap import ensure_admin
from app.database import Base, engine, get_db
from app.models import Brand, BrandFinding, Observable, User
from app.routers import auth_routes, brands, intel, observables, org_routes, reports

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="ThreatForge",
    description="Open Source Cyber Threat Intelligence Platform",
    version="0.5.0",
)

Base.metadata.create_all(bind=engine)
ensure_admin()

if config.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # CSP restritiva: sem scripts externos, sem inline-script (UI usa arquivo .js)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


app.include_router(org_routes.router)
app.include_router(auth_routes.router)
app.include_router(observables.router)
app.include_router(intel.router)
app.include_router(reports.router)
app.include_router(brands.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "threatforge", "version": "0.5.0"}


@app.get("/stats", tags=["meta"])
def stats(_=Depends(require_viewer), db: Session = Depends(get_db)):
    def count(model):
        return db.scalar(select(func.count()).select_from(model)) or 0

    malicious_obs = db.scalar(
        select(func.count()).select_from(Observable).where(Observable.verdict == "malicious")
    ) or 0
    crit_findings = db.scalar(
        select(func.count()).select_from(BrandFinding).where(
            BrandFinding.verdict.in_(["malicious", "suspicious"])
        )
    ) or 0
    return {
        "observables": count(Observable),
        "observables_malicious": malicious_obs,
        "brands": count(Brand),
        "findings": count(BrandFinding),
        "findings_priority": crit_findings,
        "users": count(User),
    }


# --- Interface web (SPA single-file) ---
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/app.js", include_in_schema=False)
def app_js():
    return FileResponse(
        os.path.join(STATIC_DIR, "app.js"), media_type="application/javascript"
    )
