import logging
from typing import Generator

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models.audit import Base

logger = logging.getLogger(__name__)

_is_sqlite = settings.database_url.startswith("sqlite")

# check_same_thread solo existe en SQLite; pasarlo a PostgreSQL provoca error.
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,
)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        # SQLite no aplica claves foráneas (ni ON DELETE CASCADE) si no se activa.
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Crea las tablas y detecta bases antiguas del prototipo con otro esquema."""
    inspector = inspect(engine)
    if "audits" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("audits")}
        if "access_token_hash" not in columns:
            raise RuntimeError(
                "La base de datos usa el esquema antiguo del prototipo (tabla 'audits' sin "
                "usuarios ni hallazgos normalizados). Respalde y elimine sql_app.db, o use "
                "otra DATABASE_URL, y vuelva a iniciar el servicio."
            )
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
