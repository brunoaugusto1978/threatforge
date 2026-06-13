"""E-mail delivery through SMTP. In development without SMTP, content is only logged.

Reuses the SMTP_* variables already used by alerts.
"""
from __future__ import annotations

import logging
import smtplib
import re
from email.message import EmailMessage

from app import config

logger = logging.getLogger(__name__)


def smtp_configured() -> bool:
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def _redact_invite_tokens(text: str) -> str:
    """Redact invitation tokens before writing e-mail content to logs."""
    return re.sub(r"(?i)(token=)[A-Za-z0-9._~%-]+", r"\1<redacted>", text)


def send_email(to: str, subject: str, body: str) -> bool:
    """Send an e-mail. Returns True if sent through SMTP, False if only logged."""
    if not smtp_configured():
        log_body = _redact_invite_tokens(body)
        logger.warning(
            "\n--- E-MAIL (SMTP not configured, displaying in log) ---\n"
            "To: %s\nSubject: %s\n\n%s\n--- end ---", to, subject, log_body,
        )
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM
    msg["To"] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20.0) as server:
            if config.SMTP_STARTTLS:
                server.starttls()
            if config.SMTP_USER:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("Failed to send e-mail to %s: %s", to, type(exc).__name__)
        return False


def send_invite(to: str, tenant_name: str, accept_url: str) -> bool:
    subject = f"[ThreatForge] Access invitation — {tenant_name}"
    body = (
        f"You have been invited to access ThreatForge as administrator of tenant "
        f"'{tenant_name}'.\n\n"
        f"To set your password and activate access, open the link below "
        f"(single use, expires soon):\n\n{accept_url}\n\n"
        f"If you were not expecting this invitation, ignore this e-mail."
    )
    return send_email(to, subject, body)
