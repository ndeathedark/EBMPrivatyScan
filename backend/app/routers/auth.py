"""Registro, inicio de sesión y gestión de la propia cuenta (HU04, RF14)."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.audit import User
from ..security import (
    _DUMMY_HASH,
    clear_session,
    client_ip,
    create_session,
    get_optional_user,
    hash_password,
    normalize_email,
    rate_limiter,
    require_user,
    validate_password_policy,
    verify_password,
)

logger = logging.getLogger("ebm.auth")
router = APIRouter(prefix="/api/v1/auth", tags=["autenticación"])


class RegisterRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)
    accept_privacy: bool = False


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


class DeleteAccountRequest(BaseModel):
    password: str = Field(max_length=128)


def user_public(user: User) -> dict:
    return {"id": user.id, "email": user.email, "role": user.role, "created_at": user.created_at}


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    rate_limiter.check(f"register:{client_ip(request)}", settings.login_rate_per_15min, 900)
    if not body.accept_privacy:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Debes aceptar la política de privacidad de la plataforma.")
    email = normalize_email(body.email)
    validate_password_policy(body.password)
    if db.query(User).filter(User.email == email).first():
        # Mensaje genérico: no confirma de forma explícita qué correos están registrados.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No fue posible crear la cuenta con esos datos.")
    user = User(email=email, password_hash=hash_password(body.password), role="user")
    db.add(user)
    db.commit()
    db.refresh(user)
    create_session(response, user)
    logger.info("Cuenta creada id=%s", user.id)
    return user_public(user)


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    rate_limiter.check(f"login:{ip}", settings.login_rate_per_15min, 900)
    email = (body.email or "").strip().lower()
    rate_limiter.check(f"login-account:{email}", settings.login_rate_per_15min, 900)
    user = db.query(User).filter(User.email == email).first()
    password_ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not password_ok or not user.is_active:
        logger.warning("Inicio de sesión fallido desde %s", ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Correo o contraseña incorrectos.")
    create_session(response, user)
    logger.info("Inicio de sesión id=%s rol=%s", user.id, user.role)
    return user_public(user)


@router.post("/logout")
def logout(response: Response):
    clear_session(response)
    return {"ok": True}


@router.get("/me")
def me(user: User | None = Depends(get_optional_user)):
    if user is None:
        return {"authenticated": False}
    return {"authenticated": True, "user": user_public(user)}


@router.delete("/me")
def delete_account(body: DeleteAccountRequest, response: Response,
                   user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Supresión de la cuenta y de todas sus auditorías (derecho de supresión)."""
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "La contraseña no es correcta.")
    db.delete(user)
    db.commit()
    clear_session(response)
    logger.info("Cuenta eliminada id=%s", user.id)
    return {"ok": True}
