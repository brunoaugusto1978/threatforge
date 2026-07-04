import logging
import os

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config, features
from app.auth import current_tenant_id, require_viewer
from app.bootstrap import ensure_operator
from app.database import Base, engine, get_db
from app.models import Brand, BrandFinding, Observable, User
from app.routers import (
    cases_routes,
    credentials_routes,
    surface_routes,
    correlation_routes,
    timeline_routes,
    exposure_routes,
    auth_routes,
    brands,
    intel,
    invites_routes,
    observables,
    org_routes,
    reports,
    tenants_routes,
)

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="ThreatForge",
    description="Open Source Cyber Threat Intelligence Platform",
    version="0.6.0",
)


from fastapi import Request as _Request  # noqa: E402
from fastapi.responses import JSONResponse as _JSONResponse  # noqa: E402
from app.routers import integrations_routes
from app.routers import license_routes


@app.exception_handler(features.EnterpriseFeatureRequired)
async def _enterprise_feature_required(request: _Request, exc: features.EnterpriseFeatureRequired):
    # Recurso pago/licenciado sem licença ativa -> 402 com bloco de upgrade.
    return _JSONResponse(status_code=402, content=features.payment_required_detail(exc.feature))

Base.metadata.create_all(bind=engine)
ensure_operator()

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
app.include_router(tenants_routes.router)
app.include_router(invites_routes.router)
app.include_router(auth_routes.router)
app.include_router(observables.router)
app.include_router(intel.router)
app.include_router(reports.router)
app.include_router(brands.router)
app.include_router(cases_routes.router)
app.include_router(cases_routes.finding_router)
app.include_router(integrations_routes.router)
app.include_router(exposure_routes.router)
app.include_router(timeline_routes.router)
app.include_router(correlation_routes.router)
app.include_router(surface_routes.router)
app.include_router(credentials_routes.router)
app.include_router(license_routes.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "threatforge", "version": "0.6.0"}


@app.get("/stats", tags=["meta"])
def stats(_=Depends(require_viewer), db: Session = Depends(get_db),
          tid: int = Depends(current_tenant_id)):
    def count(model):
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.tenant_id == tid)) or 0

    malicious_obs = db.scalar(
        select(func.count()).select_from(Observable)
        .where(Observable.tenant_id == tid, Observable.verdict == "malicious")
    ) or 0
    crit_findings = db.scalar(
        select(func.count()).select_from(BrandFinding)
        .where(BrandFinding.tenant_id == tid,
               BrandFinding.verdict.in_(["malicious", "suspicious"]))
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


@app.get("/invite/accept", include_in_schema=False)
def invite_accept_page():
    # mesma SPA; o app.js detecta o token na URL e mostra a tela de aceite
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/app.js", include_in_schema=False)
def app_js():
    return FileResponse(
        os.path.join(STATIC_DIR, "app.js"), media_type="application/javascript"
    )
