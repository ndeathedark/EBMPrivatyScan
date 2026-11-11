"""Generación del informe PDF (RF12): URL, fecha de la auditoría, indicador,
hallazgos con evidencia y limitaciones, y nota sobre el carácter preliminar."""
import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

STATUS_LABELS = {
    "CUMPLE": ("Sin brechas observadas", "#0E7C66"),
    "BRECHA": ("Posible brecha", "#B3261E"),
    "ALERTA": ("Revisar", "#A85F00"),
    "NO_CONCLUYENTE": ("No concluyente", "#5B6B70"),
    "NO_APLICA": ("No aplica", "#5B6B70"),
    "INFORMATIVO": ("Informativo", "#2F5D8A"),
}
EVIDENCE_LABELS = {
    "estado_tls": "Estado TLS", "detalle": "Detalle", "version_tls": "Versión TLS", "emisor": "Emisor",
    "vence": "Vencimiento", "url_final": "URL final", "hsts": "HSTS",
}

try:
    LOCAL_TZ = ZoneInfo("America/Santiago")
except Exception:  # noqa: BLE001 - sin base de zonas horarias en la imagen
    LOCAL_TZ = timezone.utc


def _risk_color(risk: int) -> str:
    if risk > 50:
        return "#B3261E"
    if risk > 20:
        return "#A85F00"
    return "#0E7C66"


def _t(value, default: str = "") -> str:
    return escape(str(value if value is not None else default), {'"': "&quot;"})


def _evidence_text(evidence: dict) -> str:
    lines = []
    for key, value in (evidence or {}).items():
        if value in (None, "", [], {}):
            continue
        label = EVIDENCE_LABELS.get(key, key.replace("_", " ").capitalize())
        if isinstance(value, bool):
            value = "sí" if value else "no"
        elif isinstance(value, list):
            value = ", ".join(str(v) for v in value[:12]) + (" …" if len(value) > 12 else "")
        lines.append(f"<b>{_t(label)}:</b> {_t(str(value)[:400])}")
    return "<br/>".join(lines) or "Sin evidencia adicional."


def generate_audit_pdf(url: str, risk_percentage: int, findings: list, created_at: datetime | None = None,
                       final_url: str | None = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40,
                            title="Informe de diagnóstico preliminar — Ley N° 21.719", author="EBMPrivatyScan")
    styles = getSampleStyleSheet()
    ink = colors.HexColor("#1B2A2F")
    muted = colors.HexColor("#5B6B70")
    title = ParagraphStyle("t", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=19, textColor=ink, spaceAfter=4)
    sub = ParagraphStyle("s", parent=styles["Normal"], fontName="Helvetica", fontSize=10, textColor=muted, spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12.5, textColor=ink, spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("b", parent=styles["Normal"], fontName="Helvetica", fontSize=9.2, textColor=ink, leading=12.5)
    small = ParagraphStyle("sm", parent=body, fontSize=8, textColor=muted, leading=10.5)

    created = created_at or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    date_str = created.astimezone(LOCAL_TZ).strftime("%d/%m/%Y %H:%M")
    risk = max(0, min(int(risk_percentage or 0), 100))
    risk_color = _risk_color(risk)

    el = [
        Paragraph("EBMPrivatyScan", title),
        Paragraph("Diagnóstico preliminar de evidencias de privacidad web — Ley N° 21.719", sub),
        HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#C9D3D1"), spaceAfter=10),
    ]
    summary = [
        [Paragraph("<b>Sitio analizado</b>", body), Paragraph(_t(url), body)],
        [Paragraph("<b>URL final cargada</b>", body), Paragraph(_t(final_url or url), body)],
        [Paragraph("<b>Fecha del análisis</b>", body), Paragraph(_t(date_str) + " (hora de Chile)", body)],
        [Paragraph("<b>Indicador orientativo</b>", body),
         Paragraph(f"<font color='{risk_color}'><b>{risk}%</b></font> de riesgo según las comprobaciones aplicables", body)],
    ]
    table = Table(summary, colWidths=[140, 392])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F6F5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3E1")),
    ]))
    el += [table, Paragraph("Hallazgos", h2)]

    for item in findings or []:
        if not isinstance(item, dict):
            continue
        label, color = STATUS_LABELS.get(item.get("status"), ("Sin estado", "#5B6B70"))
        rows = [
            [Paragraph(f"<b>{_t(item.get('category'))}</b>", body),
             Paragraph(f"<font color='{color}'><b>{_t(label)}</b></font>", body)],
            [Paragraph(_t(item.get("explanation")), body), ""],
            [Paragraph(_evidence_text(item.get("evidence")), small), ""],
        ]
        if item.get("limitation"):
            rows.append([Paragraph("<i>Limitación: " + _t(item["limitation"]) + "</i>", small), ""])
        block = Table(rows, colWidths=[402, 130])
        block.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)), ("SPAN", (0, 2), (1, 2)), ("SPAN", (0, 3), (1, 3)) if len(rows) > 3 else ("SPAN", (0, 0), (0, 0)),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#C9D3D1")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(color)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        el += [KeepTogether([block]), Spacer(1, 6)]

    el += [
        Spacer(1, 10),
        Paragraph("Alcance y carácter del informe", h2),
        Paragraph(
            "Este informe es un diagnóstico automatizado y preliminar de la evidencia visible desde un navegador en la "
            "fecha indicada. No constituye certificación de cumplimiento ni asesoría jurídica, y no reemplaza una revisión "
            "legal ni una auditoría técnica integral. Las comprobaciones automáticas pueden producir falsos positivos o "
            "falsos negativos. El indicador de riesgo es orientativo: se calcula con pesos documentados sobre las "
            "comprobaciones aplicables y no mide la probabilidad de una sanción.", body),
    ]
    doc.build(el)
    return buffer.getvalue()
