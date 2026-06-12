"""Scanner de marca: gera candidatos, resolve DNS, consulta CT logs (crt.sh)
e idade do domínio (RDAP), pontua e persiste findings.

Tudo em fontes públicas e gratuitas. Sem scraping agressivo, sem dark web.
"""
from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.brand.scoring import score_finding
from app.brand.similarity import ratio
from app.brand.typosquat import generate, split_domain
from app.connectors.urlhaus import UrlhausConnector
from app.models import Brand, BrandFinding, utcnow

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"


def _resolves(domain: str) -> tuple[bool, list[str]]:
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos})
        return True, ips
    except (socket.gaierror, OSError):
        return False, []


def _has_mx(domain: str, client: httpx.Client) -> bool:
    """MX via DNS-over-HTTPS (Google) — evita dependência de lib DNS."""
    try:
        r = client.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            timeout=8.0,
        )
        return bool(r.json().get("Answer"))
    except Exception:
        return False


def _rdap_age_days(domain: str, client: httpx.Client) -> int | None:
    """Idade do registro via RDAP público. Retorna None se indisponível."""
    try:
        r = client.get(f"https://rdap.org/domain/{domain}", timeout=10.0)
        if r.status_code != 200:
            return None
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                ts = event.get("eventDate", "").replace("Z", "+00:00")
                reg = datetime.fromisoformat(ts)
                return max(0, (datetime.now(timezone.utc) - reg).days)
    except Exception:
        return None
    return None


def _ct_cert_age_days(domain: str, client: httpx.Client) -> int | None:
    """Idade do certificado mais recente em CT logs (crt.sh)."""
    try:
        r = client.get(CRTSH_URL, params={"q": domain, "output": "json"}, timeout=15.0)
        if r.status_code != 200 or not r.text.strip():
            return None
        entries = r.json()
        if not entries:
            return None
        newest = max(e.get("not_before", "") for e in entries)
        if not newest:
            return None
        issued = datetime.fromisoformat(newest).replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - issued).days)
    except Exception:
        return None


def ct_discover(brand_label: str, client: httpx.Client, limit: int = 200) -> list[str]:
    """Descobre domínios contendo a marca via CT logs (wildcard %marca%)."""
    try:
        r = client.get(
            CRTSH_URL, params={"q": f"%{brand_label}%", "output": "json"}, timeout=20.0
        )
        if r.status_code != 200 or not r.text.strip():
            return []
        domains: set[str] = set()
        for e in r.json():
            for name in (e.get("name_value", "") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if brand_label in name and "@" not in name:
                    domains.add(name)
        return sorted(domains)[:limit]
    except Exception as exc:
        logger.warning("crt.sh discover falhou: %s", type(exc).__name__)
        return []


def scan_brand(brand: Brand, db: Session, deep: bool = True) -> dict:
    """Executa a varredura completa. deep=False pula RDAP/CT por candidato
    (mais rápido; usa só resolução DNS e descoberta via CT)."""
    official = set(brand.domain_list())
    if not official:
        return {"error": "marca sem domínios oficiais cadastrados"}

    primary = next(iter(official))
    label, _ = split_domain(primary)

    typosquats: set[str] = set(generate(primary))
    candidates: set[str] = set(typosquats)
    new_findings: list[BrandFinding] = []
    updated = 0
    checked = 0

    uh = UrlhausConnector()
    with httpx.Client(
        headers={"User-Agent": "ThreatForge/0.2 (open-source CTI; brand-monitor)"},
        follow_redirects=True,
    ) as client:
        # descoberta por CT (pega domínios reais que mencionam a marca)
        for d in ct_discover(label, client):
            candidates.add(d)

        for domain in sorted(candidates):
            if domain in official:
                continue
            checked += 1
            resolves, ips = _resolves(domain)
            sim = round(ratio(domain, primary) * 100)

            # filtro: só investiga a fundo o que resolve OU é muito similar
            if not resolves and sim < 70:
                continue

            evidence: dict = {"resolves": resolves, "ips": ips, "similarity": sim}
            if deep:
                evidence["mx"] = _has_mx(domain, client) if resolves else False
                evidence["age_days"] = _rdap_age_days(domain, client)
                evidence["cert_age_days"] = _ct_cert_age_days(domain, client)
            # cruzamento com URLhaus (best-effort)
            try:
                uh_data = uh.enrich("domain", domain, db)
                evidence["urlhaus_listed"] = bool(uh_data and uh_data.get("listed"))
            except Exception:
                evidence["urlhaus_listed"] = False

            score, verdict, factors = score_finding(domain, sim, evidence)

            existing = db.scalar(
                select(BrandFinding).where(
                    BrandFinding.brand_id == brand.id, BrandFinding.domain == domain
                )
            )
            if existing:
                existing.similarity = sim
                existing.score = score
                existing.verdict = verdict
                existing.score_factors = factors
                existing.evidence = evidence
                existing.last_seen = utcnow()
                updated += 1
            else:
                f = BrandFinding(
                    brand_id=brand.id,
                    domain=domain,
                    source="typosquat" if domain in typosquats else "ct_log",
                    similarity=sim,
                    score=score,
                    verdict=verdict,
                    score_factors=factors,
                    evidence=evidence,
                    status="new",
                )
                db.add(f)
                new_findings.append(f)

    brand.last_scan_at = utcnow()
    db.commit()
    for f in new_findings:
        db.refresh(f)

    return {
        "brand": brand.name,
        "candidates_generated": len(candidates),
        "checked": checked,
        "new_findings": len(new_findings),
        "updated_findings": updated,
        "new_finding_ids": [f.id for f in new_findings],
    }
