"""Bootstrap do admin inicial.

No startup, se não houver nenhum usuário, cria um admin:
- usa BOOTSTRAP_ADMIN_EMAIL/PASSWORD se definidos; ou
- gera um admin com senha aleatória e a imprime no log (uma única vez).
"""
import logging
import secrets

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

        email = (config.BOOTSTRAP_ADMIN_EMAIL or "admin@threatforge.local").strip().lower()
        password = config.BOOTSTRAP_ADMIN_PASSWORD
        generated = False
        if not password:
            password = secrets.token_urlsafe(16)
            generated = True

        admin = User(email=email, hashed_password=hash_password(password), role="admin")
        db.add(admin)
        db.commit()

        if generated:
            logger.warning(
                "\n========================================\n"
                " ADMIN INICIAL CRIADO\n"
                " e-mail: %s\n"
                " senha : %s\n"
                " (troque após o primeiro login — esta senha não será exibida de novo)\n"
                "========================================",
                email,
                password,
            )
        else:
            logger.info("Admin inicial criado: %s", email)
    finally:
        db.close()
