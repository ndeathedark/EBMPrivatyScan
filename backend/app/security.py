"""Autenticación, autorización y controles anti-abuso de la plataforma."""
import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models.audit import AuditRecord, User

SESSION_COOKIE = "ebm_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "EBMPrivatyScan"
JWT_ALGORITHM = "HS256"
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "true").lower() in {"1", "true", "yes"}

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,63}$")

# ---------------------------------------------------------------------------
# Contraseñas: scrypt (biblioteca estándar, recomendado por OWASP) con sal única
# ---------------------------------------------------------------------------
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if algorithm != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=base64.b64decode(salt_b64),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe
# (evita enumerar cuentas midiendo tiempos).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def validate_password_policy(password: str) -> None:
    if len(password) < 10 or len(password) > 128:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La contraseña debe tener entre 10 y 128 caracteres.")
    if password.lower() == password or password.upper() == password or not re.search(r"\d", password):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "La contraseña debe combinar mayúsculas, minúsculas y al menos un número.",
        )


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El correo electrónico no tiene un formato válido.")
    return email


# ---------------------------------------------------------------------------
# Sesión: JWT firmado en cookie HttpOnly + SameSite=Strict
# ---------------------------------------------------------------------------
def create_session(response: Response, user: User) -> None:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "role": user.role,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
            "jti": secrets.token_hex(8),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.access_token_minutes * 60,
        httponly=True,              # inaccesible desde JavaScript (mitiga robo por XSS)
        secure=settings.cookie_secure,
        samesite="strict",          # no se envía en solicitudes de otros sitios (mitiga CSRF)
        path="/api",
    )


def clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/api", samesite="strict", secure=settings.cookie_secure, httponly=True)


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALGORITHM], options={"require": ["exp", "sub"]})
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def require_user(user: Optional[User] = Depends(get_optional_user)) -> User:
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Debes iniciar sesión para acceder a esta función.")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No tienes permisos para esta acción.")
    return user


# ---------------------------------------------------------------------------
# Acceso a auditorías: dueño, administrador o portador del token del informe
# ---------------------------------------------------------------------------
def hash_access_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_access_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hash_access_token(token)


def can_access_audit(audit: AuditRecord, user: Optional[User], token: Optional[str]) -> bool:
    if user is not None and (user.role == "admin" or audit.user_id == user.id):
        return True
    if token and hmac.compare_digest(hash_access_token(token), audit.access_token_hash):
        return True
    return False


# ---------------------------------------------------------------------------
# Limitador de tasa en memoria (ventana deslizante). Para varias réplicas se
# debe reemplazar por uno compartido (p. ej. Redis) o limitar en Nginx/WAF.
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                retry = int(window_seconds - (now - hits[0])) + 1
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Se alcanzó el límite de solicitudes. Intenta nuevamente más tarde.",
                    headers={"Retry-After": str(retry)},
                )
            hits.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "desconocido"
