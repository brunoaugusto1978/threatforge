"""Explainable Risk Score for exposure findings.

Deterministic 0–100 score built from transparent, weighted factors. Each factor
returns an intensity in [0,1]; points = round(intensity * weight). Weights live in
config.RISK_WEIGHTS (adjustable; env RISK_WEIGHTS_JSON overrides). The full
breakdown (factors + points + reasons) is returned for the UI and persisted in
`detail.risk_breakdown` for auditability.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app import config

_EXPOSURE_INTENSITY = {
    "credential_exposure": 0.90, "secret_exposure": 1.00,
    "identity_exposure": 0.50, "brand_exposure": 0.45,
    "infrastructure_exposure": 0.65, "source_code_exposure": 0.65,
}
_CRIT_INTENSITY = {"low": 0.20, "medium": 0.45, "high": 0.75, "critical": 1.00}
_VERIFY_INTENSITY = {
    "new": 0.30, "triaging": 0.45, "confirmed": 1.00, "mitigated": 0.50,
    "closed": 0.40, "duplicate": 0.20, "false_positive": 0.00,
}


def band_of(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _age_days(last_seen, now) -> float | None:
    if not last_seen:
        return None
    try:
        ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        return max(0.0, (now - ls).total_seconds() / 86400.0)
    except Exception:
        return None


def _freshness_intensity(age):
    if age is None:
        return 0.3, "unknown"
    if age <= 7:
        return 1.0, f"{age:.0f}d"
    if age <= 30:
        return 0.7, f"{age:.0f}d"
    if age <= 90:
        return 0.4, f"{age:.0f}d"
    return 0.15, f"{age:.0f}d"


def _sensitivity(detail: dict):
    d = detail or {}
    if "fingerprint" in d or "secret_masked" in d:
        return 1.0, "secret", "exposed secret/token fingerprint"
    if "password_sha256" in d or "password_masked" in d:
        return 0.85, "credential", "leaked credential"
    if "email" in d or "person_label" in d:
        return 0.40, "pii", "personal data (PII)"
    return 0.20, "generic", None


def _admiralty_intensity(rel, cred):
    rel_rank = "ABCDEF".find(rel or "F")
    if rel_rank < 0:
        rel_rank = 5
    try:
        cred_rank = int(cred) - 1
    except (TypeError, ValueError):
        cred_rank = 5
    intensity = max(0.0, 1.0 - (rel_rank + cred_rank) / 10.0)
    return intensity, f"{rel}{cred}"


def _factor(label, intensity, weight, value, reason=None):
    return {"label": label, "value": value, "points": int(round(intensity * weight)),
            "reason": reason}


def compute(finding, asset=None, now=None) -> dict:
    """Return {'score', 'band', 'factors': [...]} deterministically."""
    now = now or datetime.now(timezone.utc)
    w = config.RISK_WEIGHTS
    detail = finding.detail or {}
    factors = []

    # verificação primeiro (false_positive zera tudo)
    v_int = _VERIFY_INTENSITY.get(finding.status, 0.3)

    crit = getattr(asset, "criticality", None)
    c_int = _CRIT_INTENSITY.get(crit, 0.30)
    factors.append(_factor("Asset criticality", c_int, w["asset_criticality"],
                           crit or "n/a", "VIP asset" if crit == "critical" else None))

    e_int = _EXPOSURE_INTENSITY.get(finding.exposure_type, 0.5)
    factors.append(_factor("Exposure type", e_int, w["exposure_type"], finding.exposure_type))

    a_int, a_val = _admiralty_intensity(finding.source_reliability, finding.info_credibility)
    factors.append(_factor("Source reliability", a_int, w["admiralty"], a_val, "Admiralty code"))

    f_int, f_val = _freshness_intensity(_age_days(finding.last_seen, now))
    factors.append(_factor("Freshness", f_int, w["freshness"], f_val))

    factors.append(_factor("Verification", v_int, w["verification"], finding.status))

    s_int, s_val, s_reason = _sensitivity(detail)
    factors.append(_factor("Sensitivity", s_int, w["sensitivity"], s_val, s_reason))

    if finding.status == "false_positive":
        return {"score": 0, "band": "low",
                "factors": [{"label": "Verification", "value": "false_positive",
                             "points": 0, "reason": "marked as false positive"}]}

    raw = sum(f["points"] for f in factors)
    score = max(0, min(100, raw))
    return {"score": score, "band": band_of(score), "factors": factors}
