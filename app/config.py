"""Configuração central. Tudo vem de variáveis de ambiente — nada hardcoded."""
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
# Admin inicial (criado no startup se não houver nenhum usuário)
BOOTSTRAP_ADMIN_EMAIL: str = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "")
BOOTSTRAP_ADMIN_PASSWORD: str = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")

# Operador de plataforma inicial (multi-tenant). Se ambos definidos, é criado
# no startup quando não há usuários. Senão, a tela de criar operador cuida disso.
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
# Veredito mínimo para disparar alerta: suspicious ou malicious
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
