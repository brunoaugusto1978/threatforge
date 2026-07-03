"""Attack Surface passive discovery (Community).

Reuses the same passive techniques as the Brand scanner — CT logs (crt.sh),
DNS resolution and RDAP — to materialize `surface_asset` rows from a brand's
official domains. NO active scanning here (ports/services are Enterprise).

The network helpers below are module-level so they can be monkeypatched in the
isolation selftest (deterministic, no real internet).
"""
from __future__ import annotations

import hashlib
import logging
import socket

import httpx
from sqlalchemy import select

from app.models import SurfaceAsset, utcnow

logger = logging.getLogger(__name__)
CRTSH_URL = "https://crt.sh/"


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _value_hash(asset_type: str, value: str) -> str:
    return hashlib.sha256(f"{asset_type}|{_norm(value)}".encode("utf-8")).hexdigest()


def _dedup_key(tid: int, asset_type: str, value: str) -> str:
    return hashlib.sha256(f"{tid}|{asset_type}|{_norm(value)}".encode("utf-8")).hexdigest()


# ---- network helpers (monkeypatchable in tests) ----
def _ct_subdomains(domain: str, client: httpx.Client, limit: int = 300) -> list[str]:
    """Subdomains covered by certificates for `domain` (crt.sh %.domain)."""
    try:
        r = client.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=20.0)
        if r.status_code != 200 or not r.text.strip():
            return []
        subs: set[str] = set()
        for e in r.json():
            for name in (e.get("name_value", "") or "").splitlines():
                n = name.strip().lower().lstrip("*.")
                if "@" in n or "*" in n:
                    continue
                if n == domain or n.endswith("." + domain):
                    subs.add(n)
        return sorted(subs)[:limit]
    except Exception as exc:
        logger.warning("ct_subdomains failed: %s", type(exc).__name__)
        return []


def _resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def _rdap(domain: str, client: httpx.Client) -> dict:
    try:
        r = client.get(f"https://rdap.org/domain/{domain}", timeout=10.0)
        if r.status_code != 200:
            return {}
        j = r.json()
        out = {"handle": j.get("handle")}
        for ev in j.get("events", []):
            if ev.get("eventAction") == "registration":
                out["registered"] = ev.get("eventDate")
        return {k: v for k, v in out.items() if v}
    except Exception:
        return {}


def _cert_info(domain: str, client: httpx.Client) -> dict | None:
    try:
        r = client.get(CRTSH_URL, params={"q": domain, "output": "json"}, timeout=15.0)
        if r.status_code != 200 or not r.text.strip():
            return None
        entries = r.json()
        if not entries:
            return None
        newest = max(entries, key=lambda e: e.get("not_before", ""))
        return {"issuer": newest.get("issuer_name"), "not_before": newest.get("not_before"),
                "not_after": newest.get("not_after"), "serial": newest.get("serial_number")}
    except Exception:
        return None


def _brand_domains(brand) -> list[str]:
    raw = getattr(brand, "official_domains", "") or ""
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def _upsert(db, tid, brand_id, asset_type, value, source, detail, parent_id):
    dkey = _dedup_key(tid, asset_type, value)
    existing = db.scalar(select(SurfaceAsset).where(
        SurfaceAsset.tenant_id == tid, SurfaceAsset.dedup_key == dkey))
    if existing is not None:
        existing.last_seen = utcnow()
        if detail:
            existing.detail = {**(existing.detail or {}), **detail}
        db.add(existing)
        return existing, False
    a = SurfaceAsset(
        tenant_id=tid, brand_id=brand_id, asset_type=asset_type, value=str(value),
        value_hash=_value_hash(asset_type, value), parent_id=parent_id, source=source,
        detail=detail or {}, status="new", dedup_key=dkey)
    db.add(a)
    db.flush()
    return a, True


def discover_brand(db, tid: int, brand, *, limit: int = 300) -> dict:
    """Passive discovery from a brand's official domains -> surface_assets.

    Chain: subdomain (ct_log) -> ip (dns) and certificate (tls), linked by parent_id.
    Idempotent via (tenant, type, value). Returns a summary.
    """
    domains = _brand_domains(brand)
    created = deduped = 0
    counts = {"subdomain": 0, "ip": 0, "certificate": 0}
    client = httpx.Client(follow_redirects=True)
    try:
        for domain in domains:
            subs = _ct_subdomains(domain, client, limit)
            if domain not in subs:
                subs = [domain] + subs
            rdap = _rdap(domain, client)
            for sub in subs:
                extra = {"apex": domain}
                if sub == domain and rdap:
                    extra["rdap"] = rdap
                sub_asset, is_new = _upsert(db, tid, brand.id, "subdomain", sub, "ct_log", extra, None)
                created += is_new; deduped += (not is_new); counts["subdomain"] += is_new
                for ip in _resolve_ips(sub):
                    _, new_ip = _upsert(db, tid, brand.id, "ip", ip, "dns", {"host": sub}, sub_asset.id)
                    created += new_ip; deduped += (not new_ip); counts["ip"] += new_ip
                if sub == domain:
                    ci = _cert_info(domain, client)
                    if ci:
                        cval = ci.get("serial") or f"cert:{domain}"
                        _, new_c = _upsert(db, tid, brand.id, "certificate", cval, "tls", ci, sub_asset.id)
                        created += new_c; deduped += (not new_c); counts["certificate"] += new_c
        db.commit()
    finally:
        client.close()
    return {"created": created, "deduped": deduped, "counts": counts, "domains": domains}
