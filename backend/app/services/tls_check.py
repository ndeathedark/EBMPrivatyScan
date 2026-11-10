"""Comprobación observable de HTTPS/TLS del dominio auditado (RF03).

No constituye una auditoría criptográfica completa: solo verifica que exista una
conexión TLS en el puerto 443 con un certificado válido para el nombre de host.
"""
import socket
import ssl
from datetime import datetime, timezone

CONNECT_TIMEOUT = 6


def _cert_name(entries) -> str:
    for rdn in entries or ():
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                return value
    return ""


def check_tls(hostname: str, addresses: list[str], port: int = 443) -> dict:
    """Conecta a una IP ya validada (no vuelve a resolver DNS) usando SNI."""
    result = {
        "state": "unknown",      # valid | invalid_certificate | no_https | timeout | error
        "detail": "",
        "tls_version": None,
        "issuer": None,
        "not_after": None,
        "days_to_expiry": None,
        "checked_address": None,
    }
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    last_error = None
    for address in addresses[:3]:
        result["checked_address"] = address
        try:
            with socket.create_connection((address, port), timeout=CONNECT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert() or {}
                    result["state"] = "valid"
                    result["tls_version"] = tls.version()
                    result["issuer"] = _cert_name(cert.get("issuer"))
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
                        result["not_after"] = expiry.isoformat()
                        result["days_to_expiry"] = (expiry - datetime.now(timezone.utc)).days
                    result["detail"] = "Conexión TLS establecida y certificado validado."
                    return result
        except ssl.SSLCertVerificationError as exc:
            result["state"] = "invalid_certificate"
            result["detail"] = f"Certificado no válido: {exc.verify_message or 'verificación fallida'}."
            return result
        except ssl.SSLError as exc:
            last_error = ("invalid_certificate", f"Error en la negociación TLS ({exc.reason or 'desconocido'}).")
        except (ConnectionRefusedError, ConnectionResetError):
            last_error = ("no_https", "El servidor no acepta conexiones HTTPS en el puerto 443.")
        except socket.timeout:
            last_error = ("timeout", "Tiempo de espera agotado al conectar por HTTPS.")
        except OSError as exc:
            last_error = ("error", f"No se pudo conectar por HTTPS ({exc.__class__.__name__}).")

    if last_error:
        result["state"], result["detail"] = last_error
    return result
