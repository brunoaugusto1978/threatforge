"""Bootstrap opcional do operador de plataforma (deploy headless).

O caminho padrão é a tela "criar operador" (/setup/operator). Este bootstrap só
age se AMBOS BOOTSTRAP_OPERATOR_EMAIL e BOOTSTRAP_OPERATOR_PASSWORD estiverem
definidos e não houver nenhum usuário — útil para provisionamento automatizado.
"""
import logging

from sqlalchemy import func, select

from app import config
from app.database import SessionLocal
from app.models import User
from app.security import hash_password

logger = logging.getLogger(__name__)


def ensure_operator() -> None:
    db = SessionLocal()
    try:
        count = db.scalar(select(func.count()).select_from(User))
        if count and count > 0:
            return
        email = config.BOOTSTRAP_OPERATOR_EMAIL or config.BOOTSTRAP_ADMIN_EMAIL
        password = config.BOOTSTRAP_OPERATOR_PASSWORD or config.BOOTSTRAP_ADMIN_PASSWORD
        if not (email and password):
            logger.info("Sem usuários e sem BOOTSTRAP_OPERATOR_*: aguardando /setup/operator")
            return
        op = User(email=email.strip().lower(), hashed_password=hash_password(password),
                  role="admin", is_operator=True, tenant_id=None)
        db.add(op)
        db.commit()
        logger.info("Operador de plataforma provisionado via env: %s", email)
    except Exception as exc:
        logger.warning("Bootstrap do operador falhou: %s", type(exc).__name__)
        db.rollback()
    finally:
        db.close()
