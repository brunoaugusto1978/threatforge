"""Central configuration. Everything comes from environment variables — nothing hardcoded."""
import os

from dotenv import load_dotenv

load_dotenv()

API_KEY: str = os.environ.get("API_KEY", "")
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./threatforge.db")

# --- Auth / sessão ---
# Segredo para assinar JWT. Se vazio, cai no API_KEY (defina um próprio em prod).
JWT_SECRET: str = os.environ.get("JWT_SECRET", "") or os.environ.get("API_KEY", "")
JWT_TTL_SECONDS: int = int(os.environ.get("JWT_TTL_SECONDS", "28800") or "28800")  # 8h
# Cookie Secure (HTTPS). Default false para rodar em http://localhost no MVP.
COOKIE_SECURE: bool = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
COOKIE_NAME: str = "tf_session"
# Initial admin (created on startup if there are no users)
BOOTSTRAP_ADMIN_EMAIL: str = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "")
BOOTSTRAP_ADMIN_PASSWORD: str = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")

# Initial platform operator (multi-tenant). If both are defined, it is created
# on startup when there are no users. Otherwise, the create-operator screen handles it.
BOOTSTRAP_OPERATOR_EMAIL: str = os.environ.get("BOOTSTRAP_OPERATOR_EMAIL", "")
BOOTSTRAP_OPERATOR_PASSWORD: str = os.environ.get("BOOTSTRAP_OPERATOR_PASSWORD", "")
# Header usado pelo operador para atuar dentro de um tenant específico
TENANT_HEADER: str = "X-Tenant-Id"

# URL base para montar links (convites). Dev: http://localhost:8000 ; prod: HTTPS.
APP_BASE_URL: str = os.environ.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
# Validade do convite (horas)
INVITE_TTL_HOURS: int = int(os.environ.get("INVITE_TTL_HOURS", "168") or "168")  # 7 dias
ABUSECH_API_KEY: str = os.environ.get("ABUSECH_API_KEY", "")
CORS_ORIGINS: list[str] = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()
]

HTTP_TIMEOUT = 30.0

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
EPSS_API = "https://api.first.org/data/v1/epss"

# --- Alertas ---
# Minimum verdict required to trigger an alert: suspicious or malicious
ALERT_MIN_VERDICT: str = os.environ.get("ALERT_MIN_VERDICT", "suspicious")

# Telegram
TELEGRAM_BOT_TOKEN: str = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID: str = os.environ.get("TELEGRAM_CHAT_ID", "")

# Webhook genérico (Slack/Discord/Teams/SIEM) — recebe JSON via POST
ALERT_WEBHOOK_URL: str = os.environ.get("ALERT_WEBHOOK_URL", "")

# E-mail (SMTP)
SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER: str = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM: str = os.environ.get("SMTP_FROM", "")
SMTP_TO: list[str] = [
    e.strip() for e in os.environ.get("SMTP_TO", "").split(",") if e.strip()
]
SMTP_STARTTLS: bool = os.environ.get("SMTP_STARTTLS", "true").lower() == "true"


# --- Evidence attachments ---
EVIDENCE_STORAGE_BACKEND: str = os.environ.get("EVIDENCE_STORAGE_BACKEND", "local")  # local|none
EVIDENCE_STORAGE_DIR: str = os.environ.get("EVIDENCE_STORAGE_DIR", "/data/evidence")
EVIDENCE_MAX_BYTES: int = int(
    os.environ.get("EVIDENCE_MAX_BYTES", str(25 * 1024 * 1024)) or str(25 * 1024 * 1024))
EVIDENCE_ALLOWED_MIME: set[str] = {
    "image/png", "image/jpeg", "image/webp", "image/gif", "application/pdf",
    "text/plain", "text/csv", "application/json", "message/rfc822", "application/zip",
}
# Edição do produto: "community" (open source) ou "enterprise" (override externo).
# A geração real de PDF premium vive no pacote threatforge-enterprise.
EDITION: str = os.environ.get("THREATFORGE_EDITION", "community").strip().lower() or "community"

# Contatos comerciais p/ o CTA de upgrade Enterprise (bloco "upgrade" no 402).
THREATFORGE_ENTERPRISE_CONTACT_EMAIL: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_EMAIL", "to.brunoaugusto@yahoo.com.br")
THREATFORGE_ENTERPRISE_CONTACT_WHATSAPP: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_WHATSAPP", "+55 21 964946855")
THREATFORGE_ENTERPRISE_CONTACT_URL: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_URL", "https://cbgsecurity.com.br")
THREATFORGE_ENTERPRISE_CONTACT_MESSAGE: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_MESSAGE",
    "Contact the ThreatForge Enterprise team to enable premium features.")

EVIDENCE_ORIGINS: set[str] = {
    "manual_upload", "authorized_export", "whatsapp_intake", "telegram_public", "email", "other",
}

ENTERPRISE_CONTACT_EMAIL: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_EMAIL",
    "to.brunoaugusto@yahoo.com.br",
).strip()

ENTERPRISE_CONTACT_WHATSAPP: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_WHATSAPP",
    "+55 21 964946855",
).strip()

ENTERPRISE_CONTACT_URL: str = os.environ.get(
    "THREATFORGE_ENTERPRISE_CONTACT_URL",
    "https://cbgsecurity.com.br",
).strip()


def enterprise_license_message() -> str:
    lines = ["Premium PDF export requires a ThreatForge Enterprise license."]

    if ENTERPRISE_CONTACT_EMAIL:
        lines.append(f"Contact: {ENTERPRISE_CONTACT_EMAIL}")

    if ENTERPRISE_CONTACT_WHATSAPP:
        lines.append(f"WhatsApp: {ENTERPRISE_CONTACT_WHATSAPP}")

    if ENTERPRISE_CONTACT_URL:
        lines.append(f"More information: {ENTERPRISE_CONTACT_URL}")

    return "\n".join(lines)

