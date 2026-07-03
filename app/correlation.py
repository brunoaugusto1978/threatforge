"""Correlation Engine — logical graph across IOCs, Exposure Findings, Monitored
Assets, Brands and Cases, linked by shared identifiers (email / domain / hash).

No new table: correlations are computed on demand by matching normalized
identifiers across the existing tenant-scoped tables. Returns a graph
{seed, nodes, edges, identifiers} the analyst can explore and act on.
"""
from __future__ import annotations

import re

from sqlalchemy import select

from app.models import (Brand, BrandFinding, ExposureFinding, InvestigationCase,
                        MonitoredAsset, Observable, SurfaceAsset)

_LIMIT = 1000  # bound por tabela (tenant-scoped)


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _domain_of_email(email: str):
    e = _norm(email)
    return e.split("@", 1)[1] if "@" in e else None


def _tokens_domains(text) -> set[str]:
    return {t.strip(".") for t in re.split(r"[^a-z0-9.\-]+", _norm(text))
            if "." in t and len(t.strip(".")) >= 4}


def _emails(text) -> set[str]:
    return set(re.findall(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", _norm(text)))


def _blank_ids():
    return {"emails": set(), "domains": set(), "hashes": set(), "ips": set()}


def _ids_from_exposure(f) -> dict:
    ids = _blank_ids()
    d = f.detail or {}
    if d.get("email"):
        ids["emails"].add(_norm(d["email"]))
        dom = _domain_of_email(d["email"])
        if dom:
            ids["domains"].add(dom)
    if d.get("domain"):
        ids["domains"].add(_norm(d["domain"]))
    if d.get("password_sha256"):
        ids["hashes"].add(_norm(d["password_sha256"]))
    if d.get("fingerprint"):
        ids["hashes"].add(_norm(d["fingerprint"]))
    if d.get("ip"):
        ids["ips"].add(_norm(d["ip"]))
    for k in ("subdomain", "host"):
        if d.get(k):
            ids["domains"].add(_norm(d[k]))
    return ids


def _ids_from_surface(a) -> dict:
    ids = _blank_ids()
    v = _norm(a.value)
    if a.asset_type == "subdomain":
        ids["domains"].add(v)
        apex = (a.detail or {}).get("apex")
        if apex:
            ids["domains"].add(_norm(apex))
    elif a.asset_type == "ip":
        ids["ips"].add(v)
    return ids


def _ids_from_asset(a) -> dict:
    ids = _blank_ids()
    v = _norm(a.value)
    if "@" in v:
        ids["emails"].add(v)
        dom = _domain_of_email(v)
        if dom:
            ids["domains"].add(dom)
    elif a.asset_type in ("domain",) or "." in v:
        ids["domains"].add(v)
    return ids


def _ids_from_observable(o) -> dict:
    ids = _blank_ids()
    v = _norm(o.value)
    t = _norm(o.type)
    if t == "email":
        ids["emails"].add(v)
        dom = _domain_of_email(v)
        if dom:
            ids["domains"].add(dom)
    elif t == "domain":
        ids["domains"].add(v)
    elif t == "hash":
        ids["hashes"].add(v)
    elif t == "ip":
        ids["ips"].add(v)
    return ids


def _node(kind, oid, label, risk=None) -> dict:
    return {"id": f"{kind}:{oid}", "kind": kind, "label": label,
            "ref": {"kind": kind, "id": oid}, "risk": risk}


def _overlap(a: dict, b: dict):
    """Retorna (tipo, valor) do primeiro identificador em comum, ou None."""
    for key in ("emails", "hashes", "domains", "ips"):
        common = a[key] & b[key]
        if common:
            return key[:-1], sorted(common)[0]
    return None


def _seed(db, tid, kind, ref):
    """Retorna (seed_node, identifiers, self_ref) ou (None, None, None)."""
    if kind == "finding":
        f = db.get(ExposureFinding, int(ref))
        if not f or f.tenant_id != tid:
            return None, None, None
        return _node("exposure_finding", f.id, f.title, f.risk_score), _ids_from_exposure(f), ("exposure_finding", f.id)
    if kind == "asset":
        a = db.get(MonitoredAsset, int(ref))
        if not a or a.tenant_id != tid:
            return None, None, None
        return _node("monitored_asset", a.id, a.label), _ids_from_asset(a), ("monitored_asset", a.id)
    if kind == "observable":
        o = db.get(Observable, int(ref))
        if not o or o.tenant_id != tid:
            return None, None, None
        return _node("observable", o.id, f"{o.type}:{o.value}"), _ids_from_observable(o), ("observable", o.id)
    if kind == "surface":
        a = db.get(SurfaceAsset, int(ref))
        if not a or a.tenant_id != tid:
            return None, None, None
        return _node("surface_asset", a.id, f"{a.asset_type}:{a.value}"), _ids_from_surface(a), ("surface_asset", a.id)
    if kind in ("email", "domain", "hash", "ip"):
        ids = _blank_ids()
        ids[kind + "s"].add(_norm(ref))
        if kind == "email":
            dom = _domain_of_email(ref)
            if dom:
                ids["domains"].add(dom)
        return _node("identifier", _norm(ref), f"{kind}:{_norm(ref)}"), ids, ("identifier", _norm(ref))
    return None, None, None


def correlate(db, tid: int, kind: str, ref) -> dict | None:
    seed, ids, self_ref = _seed(db, tid, kind, ref)
    if seed is None:
        return None

    nodes, edges = [], []
    seen = {seed["id"]}

    def add(node, via):
        if node["id"] in seen or node["id"] == seed["id"]:
            return
        seen.add(node["id"])
        nodes.append(node)
        edges.append({"source": seed["id"], "target": node["id"], "via": via})

    # Exposure findings (match em Python via detail)
    for f in db.scalars(select(ExposureFinding).where(ExposureFinding.tenant_id == tid).limit(_LIMIT)):
        if self_ref == ("exposure_finding", f.id):
            continue
        ov = _overlap(ids, _ids_from_exposure(f))
        if ov:
            add(_node("exposure_finding", f.id, f.title, f.risk_score), f"{ov[0]}:{ov[1]}")

    # Monitored assets
    for a in db.scalars(select(MonitoredAsset).where(MonitoredAsset.tenant_id == tid).limit(_LIMIT)):
        if self_ref == ("monitored_asset", a.id):
            continue
        ov = _overlap(ids, _ids_from_asset(a))
        if ov:
            add(_node("monitored_asset", a.id, a.label), f"{ov[0]}:{ov[1]}")

    # Observables (IOCs)
    for o in db.scalars(select(Observable).where(Observable.tenant_id == tid).limit(_LIMIT)):
        if self_ref == ("observable", o.id):
            continue
        ov = _overlap(ids, _ids_from_observable(o))
        if ov:
            add(_node("observable", o.id, f"{o.type}:{o.value}"), f"{ov[0]}:{ov[1]}")

    # Brands (official_domains) e BrandFindings (domain)
    for b in db.scalars(select(Brand).where(Brand.tenant_id == tid).limit(_LIMIT)):
        common = ids["domains"] & _tokens_domains(b.official_domains)
        if common:
            add(_node("brand", b.id, b.name), f"domain:{sorted(common)[0]}")
    if ids["domains"]:
        for bf in db.scalars(select(BrandFinding).where(BrandFinding.tenant_id == tid).limit(_LIMIT)):
            if _norm(bf.domain) in ids["domains"]:
                add(_node("brand_finding", bf.id, bf.domain, bf.score), f"domain:{_norm(bf.domain)}")

    # Surface assets (subdomain/ip) — fecha Brand <-> Subdomain <-> IP <-> Exposure
    for sa in db.scalars(select(SurfaceAsset).where(SurfaceAsset.tenant_id == tid).limit(_LIMIT)):
        if self_ref == ("surface_asset", sa.id):
            continue
        ov = _overlap(ids, _ids_from_surface(sa))
        if ov:
            add(_node("surface_asset", sa.id, f"{sa.asset_type}:{sa.value}"), f"{ov[0]}:{ov[1]}")
            if sa.brand_id is not None:
                b = db.get(Brand, sa.brand_id)
                if b is not None and b.tenant_id == tid:
                    add(_node("brand", b.id, b.name), "surface")

    # Cases (snapshot referencia exposure finding ou domínio)
    for c in db.scalars(select(InvestigationCase).where(InvestigationCase.tenant_id == tid).limit(_LIMIT)):
        snap = c.finding_snapshot or {}
        linked = False
        via = None
        if self_ref[0] == "exposure_finding" and snap.get("exposure_finding_id") == self_ref[1]:
            linked, via = True, "case-of-finding"
        else:
            snap_domains = _tokens_domains(snap.get("domain", ""))
            common = ids["domains"] & snap_domains
            if common:
                linked, via = True, f"domain:{sorted(common)[0]}"
        if linked:
            add(_node("case", c.id, f"Case #{c.id}: {c.title}", None), via)

    return {"seed": seed, "nodes": nodes, "edges": edges,
            "identifiers": {k: sorted(v) for k, v in ids.items() if v}}
