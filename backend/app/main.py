import logging
import socket
import ssl

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from .database import get_db
from .models.audit import AuditRecord
from .services.dom_inspector import (
    DomInspectionError,
    UnsafeTargetError,
    inspect_website_dom,
    validate_public_url,
)
from .services.pdf_generator import generate_audit_pdf

logger = logging.getLogger(__name__)

app = FastAPI(
    title="EBMPrivatyScan API",
    description="Motor de diagnóstico de ciberseguridad y privacidad para sitios web (Ley 21.719).",
    version="1.0.0",
)

class AuditRequest(BaseModel):
    url: HttpUrl


@app.post("/api/v1/audit/quick")
async def quick_audit(request: AuditRequest, db: Session = Depends(get_db)):
    url_str = str(request.url)
    try:
        target = validate_public_url(url_str)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    has_ssl = False
    try:
        context = ssl.create_default_context()
        tls_port = target["port"] if target["scheme"] == "https" else 443
        with socket.create_connection((target["hostname"], tls_port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target["hostname"]):
                has_ssl = True
    except (OSError, ssl.SSLError) as exc:
        logger.warning("HTTPS check failed for %s: %s", target["hostname"], exc)
        has_ssl = False

    try:
        dom_results = await inspect_website_dom(url_str)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomInspectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    risk_score = 0
    findings = []

    if not has_ssl:
        risk_score += 25
        findings.append(
            {
                "category": "SSL/HTTPS",
                "status": "FAIL",
                "friendly_explanation": "El sitio no utiliza encriptación HTTPS, exponiendo los datos personales.",
            }
        )
    else:
        findings.append(
            {
                "category": "SSL/HTTPS",
                "status": "PASS",
                "friendly_explanation": "El sitio cuenta con un certificado de seguridad válido y encriptación activa.",
            }
        )

    if not dom_results["has_cookie_banner"]:
        risk_score += 25
        findings.append(
            {
                "category": "Cookies",
                "status": "FAIL",
                "friendly_explanation": "No se detectó un banner de cookies para consentimiento previo.",
            }
        )
    else:
        findings.append(
            {
                "category": "Cookies",
                "status": "PASS",
                "friendly_explanation": "Se identificaron elementos de gestión de cookies en el sitio.",
            }
        )

    if dom_results["has_contact_forms"]:
        if not dom_results["has_form_checkbox"]:
            risk_score += 20
            findings.append(
                {
                    "category": "Formularios de Contacto",
                    "status": "FAIL",
                    "friendly_explanation": "Los formularios detectados no tienen casilla de consentimiento explícito.",
                }
            )
        else:
            findings.append(
                {
                    "category": "Formularios de Contacto",
                    "status": "PASS",
                    "friendly_explanation": "Los formularios incluyen casilla de verificación para protección de datos.",
                }
            )
    else:
        findings.append(
            {
                "category": "Formularios de Contacto",
                "status": "PASS",
                "friendly_explanation": "No se encontraron formularios expuestos en la superficie principal.",
            }
        )

    if dom_results["has_whatsapp"]:
        findings.append(
            {
                "category": "Canal WhatsApp",
                "status": "ALERTA",
                "friendly_explanation": "Se detectó botón de WhatsApp; debe explicarse cómo se tratarán esas conversaciones.",
            }
        )

    if not dom_results["has_privacy_policy"]:
        risk_score += 30
        findings.append(
            {
                "category": "Políticas de Privacidad",
                "status": "FAIL",
                "friendly_explanation": "No se encontró enlace visible de Políticas de Privacidad.",
            }
        )
    else:
        findings.append(
            {
                "category": "Políticas de Privacidad",
                "status": "PASS",
                "friendly_explanation": "El sitio incluye enlaces a las políticas de privacidad.",
            }
        )

    final_risk = min(risk_score, 100)

    new_audit = AuditRecord(
        url=url_str,
        risk_percentage=final_risk,
        dom_inspection=dom_results,
        findings=findings,
    )
    db.add(new_audit)
    db.commit()
    db.refresh(new_audit)

    return {
        "id": new_audit.id,
        "url": url_str,
        "risk_percentage": final_risk,
        "dom_inspection": dom_results,
        "findings": findings,
        "created_at": new_audit.created_at,
    }


@app.get("/api/v1/history")
def get_audit_history(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    audits = (
        db.query(AuditRecord)
        .order_by(AuditRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    return audits


@app.get("/api/v1/audit/{audit_id}/pdf")
def download_audit_pdf(audit_id: int, db: Session = Depends(get_db)):
    """Genera y descarga el PDF de una auditoría registrada."""
    audit = db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
    if audit is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada")

    pdf_bytes = generate_audit_pdf(
        url=audit.url,
        risk_percentage=audit.risk_percentage,
        findings=audit.findings,
    )

    filename = f"reporte_ley21719_id_{audit.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
