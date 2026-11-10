"""Envío del informe por correo (RF13). Las credenciales se leen del entorno."""
import smtplib
import ssl
from email.message import EmailMessage

from ..config import settings


class MailNotConfiguredError(RuntimeError):
    pass


class MailDeliveryError(RuntimeError):
    pass


def send_report_email(to_address: str, audited_url: str, pdf_bytes: bytes, filename: str) -> None:
    if not settings.smtp_enabled:
        raise MailNotConfiguredError("El envío por correo no está configurado en este servidor.")

    msg = EmailMessage()
    msg["Subject"] = "Informe preliminar de privacidad web (Ley N° 21.719)"
    msg["From"] = settings.smtp_from
    msg["To"] = to_address
    msg.set_content(
        "Hola:\n\n"
        "Adjuntamos el informe preliminar generado por EBMPrivatyScan para el sitio:\n"
        f"{audited_url}\n\n"
        "El informe describe evidencia visible desde un navegador y es orientativo: no constituye "
        "certificación de cumplimiento ni asesoría jurídica.\n\n"
        "Si no solicitaste este correo, puedes ignorarlo.\n"
    )
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=filename)

    context = ssl.create_default_context()
    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
        with server:
            if settings.smtp_port != 465 and settings.smtp_starttls:
                server.starttls(context=context)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailDeliveryError("El servidor de correo rechazó o no completó el envío.") from exc
