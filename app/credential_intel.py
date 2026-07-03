"""Credential Intelligence — aggregation per identity (email dossier).

Materialized incrementally from credential_exposure findings inside the existing
ingest pipeline. NEVER stores plaintext: only distinct password SHA-256 hashes
(for unique-password counting and, later, reuse detection).
"""
from __future__ import annotations

import hashlib

from sqlalchemy import select

from app.models import CredentialIdentity, MonitoredAsset, utcnow


def _norm(v) -> str:
    return str(v or "").strip().lower()


def identity_hash(tid: int, email: str) -> str:
    return hashlib.sha256(f"{tid}|{_norm(email)}".encode("utf-8")).hexdigest()


def _value_hash(v: str) -> str:
    return hashlib.sha256(_norm(v).encode("utf-8")).hexdigest()


def _add(lst, val):
    if val and val not in lst:
        lst = list(lst) + [val]
    return lst


def update_identity(db, tid: int, finding, outcome: str, principal=None) -> bool:
    """Atualiza (ou cria) o dossiê da identidade a partir de um credential finding."""
    detail = finding.detail or {}
    email = _norm(detail.get("email"))
    if not email or "@" not in email:
        return
    ihash = identity_hash(tid, email)
    ci = db.scalar(select(CredentialIdentity).where(
        CredentialIdentity.tenant_id == tid, CredentialIdentity.identity_hash == ihash))
    if ci is None:
        ci = CredentialIdentity(
            tenant_id=tid, identity_hash=ihash, email=email,
            domain=email.split("@", 1)[1], first_seen=utcnow(), last_seen=utcnow(),
            leak_count=0, password_hashes=[], sources=[], stealer_families=[], max_risk=0)
        db.add(ci)
        db.flush()

    if outcome == "created":
        ci.leak_count = int(ci.leak_count or 0) + 1
    pw = detail.get("password_sha256")
    if pw:
        ci.password_hashes = _add(ci.password_hashes or [], pw)
    ci.sources = _add(ci.sources or [], detail.get("source_kind") or finding.source)
    if detail.get("stealer_family"):
        ci.stealer_families = _add(ci.stealer_families or [], detail.get("stealer_family"))
    ci.last_seen = utcnow()
    ci.max_risk = max(int(ci.max_risk or 0), int(finding.risk_score or 0))

    # VIP hit: e-mail bate com um monitored_asset (identity/email)
    new_vip_hit = False
    if ci.vip_asset_id is None:
        vip = db.scalar(select(MonitoredAsset).where(
            MonitoredAsset.tenant_id == tid,
            MonitoredAsset.value_hash == _value_hash(email),
            MonitoredAsset.asset_type.in_(("identity", "email"))))
        if vip is not None:
            ci.vip_asset_id = vip.id
            new_vip_hit = True
    db.add(ci)
    db.flush()

    if new_vip_hit:
        _fire_vip_alert(db, tid, ci, principal)
    return new_vip_hit


def _fire_vip_alert(db, tid, ci, principal) -> None:
    """Dispara o alerta prioritário de VIP credential leak (best-effort) + audit."""
    from app import alerts, audit  # import local p/ evitar ciclos
    asset = db.get(MonitoredAsset, ci.vip_asset_id)
    if asset is None or asset.tenant_id != tid:
        return
    try:
        alerts.send_vip_credential_alert(asset, ci)
    except Exception:
        pass  # canais são best-effort; nunca quebram a ingestão
    audit.record(
        db, actor=(principal.subject if principal else "system"),
        actor_role=(principal.role if principal else None), tenant_id=tid,
        operator_user_id=(principal.user_id if principal else None),
        action="credential.vip_hit", target_type="credential_identity",
        target_id=ci.id, request=None, commit=False,
        detail={"asset_id": asset.id, "domain": ci.domain, "leak_count": ci.leak_count})
