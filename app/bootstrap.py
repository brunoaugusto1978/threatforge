"""Optional platform operator bootstrap for headless deployments.

The default path is the "create operator" screen (/setup/operator). This bootstrap only
age se AMBOS BOOTSTRAP_OPERATOR_EMAIL e BOOTSTRAP_OPERATOR_PASSWORD estiverem
runs when both variables are defined and no user exists; useful for automated provisioning.
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
            logger.info("No users and no BOOTSTRAP_OPERATOR_* variables: waiting for /setup/operator")
            return
        op = User(email=email.strip().lower(), hashed_password=hash_password(password),
                  role="admin", is_operator=True, operator_role="platform_admin",
                  tenant_id=None)
        db.add(op)
        db.commit()
        logger.info("Operador de plataforma provisionado via env: %s", email)
    except Exception as exc:
        logger.warning("Operator bootstrap failed: %s", type(exc).__name__)
        db.rollback()
    finally:
        db.close()
