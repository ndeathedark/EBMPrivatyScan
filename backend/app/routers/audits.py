"""Auditorías: análisis, detalle, historial privado, PDF, correo y eliminación."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.audit import AuditRecord, Finding, User
from ..security import (
    can_access_audit,
    client_ip,
    get_optional_user,
    new_access_token,
    normalize_email,
    rate_limiter,
    require_user,
)
from ..services import dom_inspector
from ..services.dom_inspector import DomInspectionError
from ..services.mailer import MailDeliveryError, MailNotConfiguredError, send_report_email
from ..services.pdf_generator import generate_audit_pdf
from ..services.rules import build_findings
from ..services.tls_check import check_tls
from ..services.url_guard import UnsafeTargetError, validate_public_url

logger = logging.getLogger("ebm.audits")
router = APIRouter(prefix="/api/v1", tags=["auditorías"])

_audit_slots = asyncio.Semaphore(settings.max_concurrent_audits)


class AuditRequest(BaseModel):
    url: HttpUrl
    authorized: bool = Field(default=False, description="Declaración de autorización para analizar el sitio")


class EmailRequest(BaseModel):
    email: str = Field(max_length=254)


def _as_aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def serialize_audit(audit: AuditRecord, full: bool = True) -> dict:
    data = {
        "id": audit.id,
        "url": audit.url,
        "final_url": audit.final_url,
        "risk_percentage": audit.risk_percentage,
        "status": audit.status,
        "created_at": _as_aware(audit.created_at),
        "expires_at": _as_aware(audit.expires_at),
        "owned": audit.user_id is not None,
    }
    if full:
        data["findings"] = [
            {
                "category": f.category,
                "status": f.status,
                "severity": f.severity,
                "explanation": f.explanation,
                "evidence": f.evidence,
                "limitation": f.limitation,
            }
            for f in audit.findings
        ]
    return data


def _get_accessible_audit(audit_id: int, db: Session, user: Optional[User], token: Optional[str]) -> AuditRecord:
    audit = db.get(AuditRecord, audit_id)
    now = datetime.now(timezone.utc)
    # Respuesta idéntica para "no existe" y "sin permiso": no revela qué IDs existen.
    if audit is None or _as_aware(audit.expires_at) < now or not can_access_audit(audit, user, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Auditoría no encontrada.")
    if user is not None and user.role == "admin" and audit.user_id != user.id:
        logger.info("Acceso administrativo a auditoría id=%s por usuario id=%s", audit.id, user.id)
    return audit


@router.post("/audit/quick")
async def quick_audit(body: AuditRequest, request: Request,
                      user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    if not body.authorized:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Debes declarar que tienes autorización para analizar este sitio.")
    rate_key = f"audit:user:{user.id}" if user else f"audit:ip:{client_ip(request)}"
    rate_limiter.check(rate_key, settings.audit_rate_per_hour, 3600)

    url_str = str(body.url)
    try:
        target = await asyncio.to_thread(validate_public_url, url_str)
    except UnsafeTargetError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    try:
        await asyncio.wait_for(_audit_slots.acquire(), timeout=20)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "El servicio está ocupado con otros análisis. Intenta en un minuto.") from exc
    try:
        # HTTPS se comprueba siempre en 443, aunque la URL ingresada sea http.
        tls_task = asyncio.to_thread(check_tls, target["hostname"], target["addresses"], 443)
        dom_task = dom_inspector.inspect_website_dom(url_str, target)
        tls_result, dom_result = await asyncio.wait_for(
            asyncio.gather(tls_task, dom_task), timeout=settings.audit_timeout_seconds
        )
    except asyncio.TimeoutError as exc:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT,
                            "El análisis superó el tiempo máximo permitido y no se completó.") from exc
    except UnsafeTargetError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except DomInspectionError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    finally:
        _audit_slots.release()

    findings, risk = build_findings(tls_result, dom_result)
    token, token_hash = new_access_token()
    now = datetime.now(timezone.utc)
    retention = timedelta(days=settings.user_retention_days) if user else timedelta(hours=settings.guest_retention_hours)

    audit = AuditRecord(
        user_id=user.id if user else None,
        url=url_str,
        final_url=dom_result.get("final_url"),
        risk_percentage=risk,
        status="completed",
        dom_inspection={"tls": tls_result, "dom": dom_result},
        access_token_hash=token_hash,
        created_at=now,
        expires_at=now + retention,
        findings=[Finding(position=i, **f) for i, f in enumerate(findings)],
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)

    result = serialize_audit(audit)
    # El token se entrega una sola vez; en la base solo se guarda su hash.
    result["access_token"] = token
    return result


@router.get("/audit/{audit_id}")
def get_audit(audit_id: int, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db),
              x_audit_token: Optional[str] = Header(default=None, max_length=128)):
    return serialize_audit(_get_accessible_audit(audit_id, db, user, x_audit_token))


@router.get("/audit/{audit_id}/pdf")
def download_pdf(audit_id: int, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db),
                 x_audit_token: Optional[str] = Header(default=None, max_length=128)):
    audit = _get_accessible_audit(audit_id, db, user, x_audit_token)
    pdf = generate_audit_pdf(audit.url, audit.risk_percentage, serialize_audit(audit)["findings"],
                             created_at=audit.created_at, final_url=audit.final_url)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="informe_ley21719_{audit.id}.pdf"'},
    )


@router.post("/audit/{audit_id}/email")
async def email_report(audit_id: int, body: EmailRequest, request: Request,
                       user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db),
                       x_audit_token: Optional[str] = Header(default=None, max_length=128)):
    audit = _get_accessible_audit(audit_id, db, user, x_audit_token)
    rate_limiter.check(f"email:{client_ip(request)}", settings.email_rate_per_hour, 3600)
    to_address = normalize_email(body.email)
    pdf = generate_audit_pdf(audit.url, audit.risk_percentage, serialize_audit(audit)["findings"],
                             created_at=audit.created_at, final_url=audit.final_url)
    try:
        await asyncio.to_thread(send_report_email, to_address, audit.url, pdf, f"informe_ley21719_{audit.id}.pdf")
    except MailNotConfiguredError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except MailDeliveryError as exc:
        logger.warning("Fallo de envío de correo para auditoría id=%s", audit.id)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    # No se almacena la dirección de destino (minimización de datos).
    return {"ok": True, "message": "El informe fue enviado al correo indicado."}


@router.delete("/audit/{audit_id}")
def delete_audit(audit_id: int, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db),
                 x_audit_token: Optional[str] = Header(default=None, max_length=128)):
    audit = _get_accessible_audit(audit_id, db, user, x_audit_token)
    db.delete(audit)
    db.commit()
    return {"ok": True}


@router.get("/history")
def history(limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0, le=10_000),
            scope: str = Query(default="mine", pattern="^(mine|all)$"),
            user: User = Depends(require_user), db: Session = Depends(get_db)):
    query = db.query(AuditRecord).filter(AuditRecord.expires_at > datetime.now(timezone.utc))
    if scope == "all":
        if user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Solo un administrador puede ver todas las auditorías.")
        logger.info("Consulta administrativa del historial completo por usuario id=%s", user.id)
    else:
        query = query.filter(AuditRecord.user_id == user.id)
    total = query.count()
    items = query.order_by(AuditRecord.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [serialize_audit(a, full=False) for a in items]}
