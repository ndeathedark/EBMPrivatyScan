"""Modelo de datos alineado con el diagrama entidad-relación del informe
(USUARIO 1—N AUDITORIA 1—N HALLAZGO)."""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(254), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # "user" | "admin"
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    audits = relationship("AuditRecord", back_populates="owner", cascade="all, delete-orphan")


class AuditRecord(Base):
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    # Opcional: las auditorías de invitado no tienen dueño (FK nula).
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    url = Column(String(2048), nullable=False)
    final_url = Column(String(2048), nullable=True)
    risk_percentage = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="completed")
    dom_inspection = Column(JSON, nullable=True)
    # Hash SHA-256 de un token aleatorio que permite al invitado ver/descargar
    # su informe sin exponer los IDs secuenciales (evita IDOR).
    access_token_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    owner = relationship("User", back_populates="audits")
    findings = relationship(
        "Finding",
        back_populates="audit",
        cascade="all, delete-orphan",
        order_by="Finding.position",
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    position = Column(Integer, nullable=False, default=0)
    category = Column(String(80), nullable=False)
    status = Column(String(20), nullable=False)      # CUMPLE | BRECHA | ALERTA | NO_CONCLUYENTE | NO_APLICA
    severity = Column(String(10), nullable=False)    # alta | media | baja | info
    explanation = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    limitation = Column(Text, nullable=True)

    audit = relationship("AuditRecord", back_populates="findings")
