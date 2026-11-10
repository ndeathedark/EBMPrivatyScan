"""Eliminación automática de auditorías vencidas (minimización y plazo de conservación)."""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models.audit import AuditRecord

logger = logging.getLogger(__name__)


def purge_expired(db: Session) -> int:
    now = datetime.now(timezone.utc)
    expired = db.query(AuditRecord).filter(AuditRecord.expires_at < now).all()
    for audit in expired:
        db.delete(audit)  # elimina en cascada sus hallazgos
    if expired:
        db.commit()
        logger.info("Retención: %d auditoría(s) vencida(s) eliminada(s).", len(expired))
    return len(expired)
