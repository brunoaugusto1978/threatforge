"""Envio de e-mail (SMTP). Em dev sem SMTP, apenas registra o conteúdo no log.

Reutiliza as variáveis SMTP_* já usadas pelos alertas.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from app import config

logger = logging.getLogger(__name__)


def smtp_configured() -> bool:
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def send_email(to: str, subject: str, body: str) -> bool:
    """Envia um e-mail. Retorna True se enviado por SMTP, False se só logado."""
    if not smtp_configured():
        logger.warning(
            "\n--- E-MAIL (SMTP não configurado, exibindo no log) ---\n"
            "Para: %s\nAssunto: %s\n\n%s\n--- fim ---", to, subject, body,
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
        logger.warning("Falha ao enviar e-mail para %s: %s", to, type(exc).__name__)
        return False


def send_invite(to: str, tenant_name: str, accept_url: str) -> bool:
    subject = f"[ThreatForge] Convite de acesso — {tenant_name}"
    body = (
        f"Você foi convidado a acessar o ThreatForge como administrador do tenant "
        f"'{tenant_name}'.\n\n"
        f"Para definir sua senha e ativar o acesso, abra o link abaixo "
        f"(uso único, expira em breve):\n\n{accept_url}\n\n"
        f"Se você não esperava este convite, ignore este e-mail."
    )
    return send_email(to, subject, body)
