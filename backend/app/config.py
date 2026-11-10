"""Configuración centralizada leída desde variables de entorno.

Ningún secreto se escribe en el código fuente: en desarrollo, si SECRET_KEY no
está definida se genera una clave aleatoria temporal (las sesiones se pierden al
reiniciar). En producción (APP_ENV=production) la clave es obligatoria.
"""
import os
import secrets
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development").lower())
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./sql_app.db"))

    # Sesiones
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    access_token_minutes: int = field(default_factory=lambda: _env_int("ACCESS_TOKEN_MINUTES", 60, 5))
    cookie_secure: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))

    # CORS: vacío = solo mismo origen (Nginx sirve frontend y API juntos)
    allowed_origins: list[str] = field(default_factory=lambda: _env_list("ALLOWED_ORIGINS"))

    # Límites de uso
    audit_rate_per_hour: int = field(default_factory=lambda: _env_int("AUDIT_RATE_PER_HOUR", 20, 1))
    login_rate_per_15min: int = field(default_factory=lambda: _env_int("LOGIN_RATE_PER_15MIN", 10, 1))
    email_rate_per_hour: int = field(default_factory=lambda: _env_int("EMAIL_RATE_PER_HOUR", 5, 1))
    max_concurrent_audits: int = field(default_factory=lambda: _env_int("MAX_CONCURRENT_AUDITS", 2, 1))
    audit_timeout_seconds: int = field(default_factory=lambda: _env_int("AUDIT_TIMEOUT_SECONDS", 45, 10))

    # Conservación de datos (Ley 21.719: limitación del plazo de conservación)
    guest_retention_hours: int = field(default_factory=lambda: _env_int("GUEST_RETENTION_HOURS", 24, 1))
    user_retention_days: int = field(default_factory=lambda: _env_int("USER_RETENTION_DAYS", 180, 1))

    # Correo (opcional). Si SMTP_HOST está vacío, el envío se informa como no disponible.
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587, 1))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.getenv("SMTP_FROM", ""))
    smtp_starttls: bool = field(default_factory=lambda: _env_bool("SMTP_STARTTLS", True))

    # Solo para pruebas automatizadas: permite destinos locales. Nunca en producción.
    allow_private_targets: bool = field(default_factory=lambda: _env_bool("ALLOW_PRIVATE_TARGETS", False))

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)


def _build_settings() -> Settings:
    settings = Settings()
    if settings.is_production:
        if len(settings.secret_key) < 32:
            raise RuntimeError("SECRET_KEY debe tener al menos 32 caracteres en producción.")
        if settings.allow_private_targets:
            raise RuntimeError("ALLOW_PRIVATE_TARGETS no puede activarse en producción.")
        if not settings.cookie_secure:
            raise RuntimeError("COOKIE_SECURE debe ser true en producción (HTTPS).")
    if not settings.secret_key:
        object.__setattr__(settings, "secret_key", secrets.token_urlsafe(48))
    return settings


settings = _build_settings()
