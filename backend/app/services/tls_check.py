"""Comprobación observable de HTTPS/TLS del dominio auditado (RF03).

No constituye una auditoría criptográfica completa: solo verifica que exista una
conexión TLS en el puerto 443 con un certificado válido para el nombre de host.
"""
import socket
import ssl
from datetime import datetime, timezone

CONNECT_TIMEOUT = 6
MAX_ADDRESSES = 3


def _cert_name(entries) -> str:
    for rdn in entries or ():
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                return value
    return ""


def _empty_result() -> dict:
    return {
        "state": "unknown",      # valid | invalid_certificate | no_https | timeout | error
        "detail": "",
        "tls_version": None,
        "issuer": None,
        "not_after": None,
        "days_to_expiry": None,
        "checked_address": None,
    }


def _describe_certificate(cert: dict, tls_version: str | None) -> dict:
    info = {
        "state": "valid",
        "detail": "Conexión TLS establecida y certificado validado.",
        "tls_version": tls_version,
        "issuer": _cert_name(cert.get("issuer")),
    }
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        info["not_after"] = expiry.isoformat()
        info["days_to_expiry"] = (expiry - datetime.now(timezone.utc)).days
    return info


def _classify_error(exc: Exception) -> tuple[str, str]:
    """Traduce una excepción de red a (estado, detalle). Nunca la presenta como éxito."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "invalid_certificate", f"Certificado no válido: {getattr(exc, 'verify_message', None) or 'verificación fallida'}."
    if isinstance(exc, ssl.SSLError):
        return "invalid_certificate", f"Error en la negociación TLS ({getattr(exc, 'reason', None) or 'desconocido'})."
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return "no_https", "El servidor no acepta conexiones HTTPS en el puerto 443."
    if isinstance(exc, socket.timeout):
        return "timeout", "Tiempo de espera agotado al conectar por HTTPS."
    return "error", f"No se pudo conectar por HTTPS ({exc.__class__.__name__})."


def _probe(hostname: str, address: str, port: int, context: ssl.SSLContext) -> dict:
    """Conecta a una IP ya validada (no vuelve a resolver DNS) usando SNI."""
    with socket.create_connection((address, port), timeout=CONNECT_TIMEOUT) as sock, \
            context.wrap_socket(sock, server_hostname=hostname) as tls:
        return _describe_certificate(tls.getpeercert() or {}, tls.version())


def check_tls(hostname: str, addresses: list[str], port: int = 443) -> dict:
    result = _empty_result()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    for address in addresses[:MAX_ADDRESSES]:
        result["checked_address"] = address
        try:
            result.update(_probe(hostname, address, port, context))
            return result
        except OSError as exc:  # ssl.SSLError y los errores de socket heredan de OSError
            result["state"], result["detail"] = _classify_error(exc)
            if isinstance(exc, ssl.SSLCertVerificationError):
                return result  # un certificado inválido no mejora probando otra IP
    return result
