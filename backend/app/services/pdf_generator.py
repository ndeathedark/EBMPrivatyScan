import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _safe_text(value, default: str = "") -> str:
    text = value if value is not None else default
    return escape(str(text), {'"': "&quot;"})


def _normalise_risk_percentage(value) -> int:
    try:
        risk = int(value)
    except (TypeError, ValueError):
        risk = 0
    return max(0, min(risk, 100))


def _status_cell(status: str) -> str:
    normalized = str(status or "").upper().strip()
    if normalized in {"PASS", "APROBADO"}:
        return "<font color='#059669'><b>APROBADO</b></font>"
    if normalized in {"ALERTA", "ALERT", "WARNING"}:
        return "<font color='#D97706'><b>ALERTA</b></font>"
    if normalized == "NO DETECTADO":
        return "<font color='#64748B'><b>NO DETECTADO</b></font>"
    if normalized == "NO APLICA":
        return "<font color='#64748B'><b>NO APLICA</b></font>"
    return "<font color='#DC2626'><b>FALLO</b></font>"


def generate_audit_pdf(url: str, risk_percentage: int, findings: list) -> bytes:
    """
    Genera un informe en PDF profesional con el resultado del escaneo
    de cumplimiento de la Ley N° 21.719.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Estilos personalizados
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=15,
    )

    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=10,
    )

    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=12,
    )

    elements = []

    # Encabezado principal
    elements.append(Paragraph("🛡️ EBMPrivatyScan", title_style))
    elements.append(
        Paragraph(
            "Informe de Diagnóstico de Privacidad y Ciberseguridad — Ley N° 21.719",
            subtitle_style,
        )
    )
    elements.append(
        HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#CBD5E1"),
            spaceAfter=15,
        )
    )

    # Resumen del Análisis
    date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    risk_value = _normalise_risk_percentage(risk_percentage)

    # Color del riesgo
    if risk_value > 50:
        risk_color = "#DC2626"
    elif risk_value > 20:
        risk_color = "#D97706"
    else:
        risk_color = "#059669"

    safe_url = _safe_text(url or "Sin URL disponible")
    summary_data = [
        [Paragraph("<b>Sitio Web Evaluado:</b>", body_style), Paragraph(safe_url, body_style)],
        [Paragraph("<b>Fecha del Escaneo:</b>", body_style), Paragraph(_safe_text(date_str), body_style)],
        [
            Paragraph("<b>Nivel de Riesgo Calculado:</b>", body_style),
            Paragraph(f"<font color='{risk_color}'><b>{risk_value}%</b></font>", body_style),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[150, 380])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("PADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ]
        )
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Sección de Detalles / Hallazgos
    elements.append(Paragraph("Detalle de Hallazgos y Evaluación", h2_style))

    table_data = [
        [
            Paragraph("<b>Categoría</b>", body_style),
            Paragraph("<b>Estado</b>", body_style),
            Paragraph("<b>Explicación / Diagnóstico</b>", body_style),
        ]
    ]

    if not findings:
        table_data.append(
            [
                Paragraph("<b>Sin hallazgos</b>", body_style),
                Paragraph(_status_cell("PASS"), body_style),
                Paragraph("No se registraron hallazgos para este análisis.", body_style),
            ]
        )
    else:
        for item in findings:
            if not isinstance(item, dict):
                continue

            category = _safe_text(item.get("category", "Sin categoría"))
            status = item.get("status", "N/A")
            explanation = _safe_text(item.get("friendly_explanation", "Sin detalle disponible"))

            table_data.append(
                [
                    Paragraph(f"<b>{category}</b>", body_style),
                    Paragraph(_status_cell(status), body_style),
                    Paragraph(explanation, body_style),
                ]
            )

    findings_table = Table(table_data, colWidths=[130, 80, 320])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    elements.append(findings_table)
    elements.append(Spacer(1, 20))

    # Pie de página o Nota legal
    footer_text = (
        "<i>Este informe fue generado automáticamente por EBMPrivatyScan. "
        "Proporciona una evaluación técnica de superficie sobre los requerimientos de la Ley N° 21.719 en Chile.</i>"
    )
    elements.append(Paragraph(footer_text, body_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()