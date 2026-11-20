"""Panel de administración: usuarios, páginas analizadas e historial completo.

El administrador ve el correo de cada usuario, sus análisis y los de los invitados.
Nunca se expone la contraseña ni su hash: los usuarios se serializan con una lista
cerrada de campos (user_admin_view), no con el modelo completo.
"""
import logging
import urllib.parse
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..models.audit import AuditRecord, User
from ..security import require_admin
from .audits import as_aware, serialize_audit

logger = logging.getLogger("ebm.admin")
router = APIRouter(prefix="/api/v1/admin", tags=["administración"])

GUEST_LABEL = "Invitado"
GUEST_FILTER = "guest"
OWNER_PATTERN = r"^(guest|\d{1,10})?$"


def site_of(url: str) -> str:
    host = (urllib.parse.urlsplit(url).hostname or url).lower()
    return host[4:] if host.startswith("www.") else host


def _active_audits(db: Session, search: str, owner: str = ""):
    """Análisis vigentes; search busca en la dirección y en el correo del usuario."""
    query = (db.query(AuditRecord).outerjoin(User, AuditRecord.user_id == User.id)
             .filter(AuditRecord.expires_at > datetime.now(timezone.utc)))
    term = search.strip().lower()
    if term:
        query = query.filter(or_(func.lower(AuditRecord.url).contains(term, autoescape=True),
                                 func.lower(User.email).contains(term, autoescape=True)))
    if owner == GUEST_FILTER:
        query = query.filter(AuditRecord.user_id.is_(None))
    elif owner:
        query = query.filter(AuditRecord.user_id == int(owner))
    return query


def user_admin_view(user: User, audits: int = 0, last_activity=None) -> dict:
    """Campos de un usuario visibles para el administrador (sin contraseña ni hash)."""
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": as_aware(user.created_at),
        "audits": audits,
        "last_activity": last_activity,
    }


def _with_owner(audit: AuditRecord) -> dict:
    data = serialize_audit(audit, full=False)
    data["site"] = site_of(audit.url)
    data["owner"] = audit.owner.email if audit.owner else GUEST_LABEL
    data["owner_id"] = audit.user_id
    return data


@router.get("/stats", dependencies=[Depends(require_admin)])
def stats(db: Session = Depends(get_db)):
    active = _active_audits(db, "")
    urls = [row[0] for row in active.with_entities(AuditRecord.url).all()]
    return {
        "audits": len(urls),
        "sites": len({site_of(u) for u in urls}),
        "guest_audits": active.filter(AuditRecord.user_id.is_(None)).count(),
        "users": db.query(func.count(User.id)).scalar(),
    }


@router.get("/audits")
def all_audits(q: str = Query(default="", max_length=200),
               owner: str = Query(default="", pattern=OWNER_PATTERN,
                                  description="Vacío = todos; 'guest' = invitados; número = id de usuario"),
               limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0, le=100_000),
               admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Historial completo: todos los análisis vigentes de todas las cuentas e invitados."""
    query = _active_audits(db, q, owner)
    total = query.count()
    items = (query.options(joinedload(AuditRecord.owner))
             .order_by(AuditRecord.created_at.desc()).offset(offset).limit(limit).all())
    logger.info("Administrador id=%s consultó el historial completo (q=%r, owner=%r)", admin.id, q[:50], owner)
    return {"total": total, "items": [_with_owner(a) for a in items]}


@router.get("/sites")
def analysed_sites(q: str = Query(default="", max_length=200),
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Páginas analizadas agrupadas por sitio, con su último resultado."""
    audits = _active_audits(db, q).order_by(AuditRecord.created_at.desc()).all()
    sites: dict[str, dict] = {}
    for audit in audits:  # ordenado del más reciente al más antiguo
        site = site_of(audit.url)
        entry = sites.get(site)
        if entry is None:
            sites[site] = {
                "site": site,
                "analyses": 1,
                "last_audit_id": audit.id,
                "last_url": audit.url,
                "last_risk": audit.risk_percentage,
                "last_analysed_at": serialize_audit(audit, full=False)["created_at"],
            }
        else:
            entry["analyses"] += 1
    logger.info("Administrador id=%s consultó los sitios analizados", admin.id)
    return {"total": len(sites), "items": list(sites.values())}


@router.get("/users")
def all_users(q: str = Query(default="", max_length=200),
              admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Usuarios registrados con la cantidad de análisis y su última actividad."""
    activity = (db.query(AuditRecord.user_id.label("user_id"),
                         func.count(AuditRecord.id).label("audits"),
                         func.max(AuditRecord.created_at).label("last_activity"))
                .filter(AuditRecord.expires_at > datetime.now(timezone.utc))
                .group_by(AuditRecord.user_id).subquery())
    query = (db.query(User, activity.c.audits, activity.c.last_activity)
             .outerjoin(activity, activity.c.user_id == User.id))
    term = q.strip().lower()
    if term:
        query = query.filter(func.lower(User.email).contains(term, autoescape=True))
    rows = query.order_by(User.created_at.desc()).all()
    logger.info("Administrador id=%s consultó el listado de usuarios", admin.id)
    items = [user_admin_view(user, audits or 0, as_aware(last)) for user, audits, last in rows]
    return {"total": len(items), "items": items}
