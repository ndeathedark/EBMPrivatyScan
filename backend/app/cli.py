"""Administración por línea de comandos.

Crear o promover un administrador (la contraseña se pide sin mostrarla en pantalla):
    docker compose -f backend/docker-compose.yml exec backend python -m app.cli create-admin correo@admi.cl
"""
import getpass
import sys

from fastapi import HTTPException

from .database import SessionLocal, init_db
from .models.audit import User
from .security import hash_password, normalize_email, validate_password_policy


def create_admin(email: str) -> None:
    init_db()
    try:
        email = normalize_email(email)
        password = getpass.getpass("Contraseña del administrador: ")
        if password != getpass.getpass("Repite la contraseña: "):
            sys.exit("Las contraseñas no coinciden.")
        validate_password_policy(password)
    except HTTPException as exc:
        sys.exit(exc.detail)
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.role, user.password_hash = "admin", hash_password(password)
        else:
            db.add(User(email=email, password_hash=hash_password(password), role="admin"))
        db.commit()
    print(f"Administrador listo: {email}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "create-admin":
        sys.exit("Uso: python -m app.cli create-admin <correo>")
    create_admin(sys.argv[2])
