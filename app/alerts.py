"""Despacho de alertas nos principais canais: Telegram, webhook e e-mail SMTP.

Each channel is independent and best-effort: one channel failure does not block the
other channels nor the scan. Only configured channels (via env) are triggered.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from app import config
from app.models import Brand, BrandFinding, CredentialIdentity, MonitoredAsset

logger = logging.getLogger(__name__)

_VERDICT_RANK = {"info": 0, "low": 1, "suspicious": 2, "malicious": 3}
_VERDICT_EMOJI = {"malicious": "🔴", "suspicious": "🟠", "low": "🟡", "info": "⚪"}


def should_alert(verdict: str) -> bool:
    threshold = _VERDICT_RANK.get(config.ALERT_MIN_VERDICT, 2)
    return _VERDICT_RANK.get(verdict, 0) >= threshold


def _defang(domain: str) -> str:
    return domain.replace(".", "[.]")


def _summary(brand: Brand, f: BrandFinding) -> dict:
    ev = f.evidence or {}
    return {
        "brand": brand.name,
        "domain": _defang(f.domain),
        "verdict": f.verdict,
        "score": f.score,
        "similarity": f.similarity,
        "source": f.source,
        "resolves": ev.get("resolves"),
        "age_days": ev.get("age_days"),
        "urlhaus_listed": ev.get("urlhaus_listed"),
        "finding_id": f.id,
    }


def _telegram(text: str) -> None:
    if not (config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID):
        return
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        httpx.post(
            url,
            json={
                "chat_id": config.TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=15.0,
        ).raise_for_status()
    except Exception as exc:
        logger.warning("Alerta Telegram falhou: %s", type(exc).__name__)


def _webhook(payload: dict) -> None:
    if not config.ALERT_WEBHOOK_URL:
        return
    try:
        httpx.post(config.ALERT_WEBHOOK_URL, json=payload, timeout=15.0).raise_for_status()
    except Exception as exc:
        logger.warning("Alerta webhook falhou: %s", type(exc).__name__)


def _email(subject: str, body: str) -> None:
    if not (config.SMTP_HOST and config.SMTP_FROM and config.SMTP_TO):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM
    msg["To"] = ", ".join(config.SMTP_TO)
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20.0) as server:
            if config.SMTP_STARTTLS:
                server.starttls()
            if config.SMTP_USER:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as exc:
        logger.warning("Alerta e-mail falhou: %s", type(exc).__name__)


def send_finding_alert(brand: Brand, f: BrandFinding) -> dict:
    """Sends a finding alert to all configured channels."""
    s = _summary(brand, f)
    emoji = _VERDICT_EMOJI.get(f.verdict, "⚪")
    reasons = "; ".join(x["reason"] for x in (f.score_factors or [])[:4])

    text = (
        f"{emoji} <b>ThreatForge — Brand abuse</b>\n"
        f"Brand: <b>{brand.name}</b>\n"
        f"Domain: <code>{_defang(f.domain)}</code>\n"
        f"Veredito: <b>{f.verdict.upper()}</b> (score {f.score}/100, "
        f"{f.similarity}% similar)\n"
        f"Motivos: {reasons or 'n/d'}"
    )
    subject = f"[ThreatForge] {f.verdict.upper()} — brand abuse {brand.name}: {_defang(f.domain)}"
    body = (
        f"Possible brand abuse involving {brand.name}.\n\n"
        f"Domain: {_defang(f.domain)}\n"
        f"Veredito: {f.verdict} | Score: {f.score}/100 | Similaridade: {f.similarity}%\n"
        f"Origem: {f.source}\n\n"
        f"Fatores:\n" + "\n".join(f"- {x['reason']} ({x['source']})" for x in (f.score_factors or []))
        + f"\n\nFinding ID: {f.id}. Review it in the dashboard/API before taking any takedown action."
    )

    _telegram(text)
    _webhook({"type": "brand_abuse", **s, "factors": f.score_factors})
    _email(subject, body)
    return s


def dispatch_new_findings(brand: Brand, findings: list[BrandFinding], db) -> int:
    """Alerts findings that crossed the threshold and have not been alerted yet."""
    sent = 0
    for f in findings:
        if f.alerted or not should_alert(f.verdict):
            continue
        send_finding_alert(brand, f)
        f.alerted = True
        sent += 1
    if sent:
        db.commit()
    return sent


def send_vip_credential_alert(asset: MonitoredAsset, identity: CredentialIdentity) -> dict:
    """Alerta prioritário: uma identidade VIP monitorada apareceu em leak de credencial.

    Best-effort nos canais configurados. NUNCA inclui senha/plaintext — só o e-mail
    do VIP (destino é o canal da própria org), contagem de leaks, fontes e risco.
    """
    s = {
        "type": "vip_credential_leak",
        "vip": asset.label,
        "criticality": asset.criticality,
        "email": identity.email,
        "domain": identity.domain,
        "leak_count": identity.leak_count,
        "sources": list(identity.sources or []),
        "stealer_families": list(identity.stealer_families or []),
        "max_risk": identity.max_risk,
        "identity_hash": identity.identity_hash,
        "asset_id": asset.id,
    }
    text = (
        "🔴 <b>ThreatForge — VIP credential leak</b>\n"
        f"VIP: <b>{asset.label}</b> ({asset.criticality})\n"
        f"E-mail: <code>{identity.email}</code>\n"
        f"Leaks: <b>{identity.leak_count}</b> · risco {identity.max_risk}/100\n"
        f"Fontes: {', '.join(s['sources']) or 'n/d'}"
    )
    subject = f"[ThreatForge] VIP credential leak — {asset.label} ({identity.email})"
    body = (
        "A monitored VIP identity appeared in a credential leak.\n\n"
        f"VIP: {asset.label} ({asset.criticality})\n"
        f"E-mail: {identity.email}\n"
        f"Leaks: {identity.leak_count} | Max risk: {identity.max_risk}/100\n"
        f"Sources: {', '.join(s['sources'])}\n"
        f"Stealer families: {', '.join(s['stealer_families'])}\n\n"
        "No password is included by design. Review it in the dashboard/API."
    )
    _telegram(text)
    _webhook(s)
    _email(subject, body)
    return s
