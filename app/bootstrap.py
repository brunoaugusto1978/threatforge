"""Bootstrap opcional do admin inicial (deploy headless).

O caminho padrão de primeiro acesso é o Setup Wizard (/setup), que cria a
organização e o primeiro admin pela interface. Este bootstrap só age se
AMBOS BOOTSTRAP_ADMIN_EMAIL e BOOTSTRAP_ADMIN_PASSWORD estiverem definidos —
útil para provisionamento automatizado sem interface.
"""
import logging

from sqlalchemy import func, select

from app import config
from app.database import SessionLocal
from app.models import User
from app.security import hash_password

logger = logging.getLogger(__name__)


def ensure_admin() -> None:
    db = SessionLocal()
    try:
        count = db.scalar(select(func.count()).select_from(User))
        if count and count > 0:
            return
        # caminho padrão: deixa o Setup Wizard (/setup) criar o primeiro admin.
        # só provisiona via env se AMBOS estiverem definidos (headless).
        if not (config.BOOTSTRAP_ADMIN_EMAIL and config.BOOTSTRAP_ADMIN_PASSWORD):
            logger.info("Nenhum usuário e sem BOOTSTRAP_ADMIN_*: aguardando Setup Wizard em /setup")
            return

        email = config.BOOTSTRAP_ADMIN_EMAIL.strip().lower()
        admin = User(
            email=email,
            hashed_password=hash_password(config.BOOTSTRAP_ADMIN_PASSWORD),
            role="admin",
        )
        db.add(admin)
        db.commit()
        logger.info("Admin inicial provisionado via env: %s", email)
    except Exception as exc:
        logger.warning("Bootstrap do admin falhou: %s", type(exc).__name__)
        db.rollback()
    finally:
        db.close()
