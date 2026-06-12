import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.database import Base, engine
from app.routers import brands, intel, observables, reports

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="ThreatForge",
    description="Open Source Cyber Threat Intelligence Platform",
    version="0.2.0",
)

Base.metadata.create_all(bind=engine)

if config.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["X-API-Key", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(observables.router)
app.include_router(intel.router)
app.include_router(reports.router)
app.include_router(brands.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "threatforge", "version": "0.2.0"}
