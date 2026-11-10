"""Validación de destinos para prevenir SSRF (Server-Side Request Forgery).

Se aplica a la URL ingresada, a cada salto de redirección y a cada recurso que
el navegador automatizado intenta cargar.
"""
import ipaddress
import socket
import urllib.parse

from ..config import settings

ALLOWED_SCHEMES = {"http", "https"}
# Solo puertos web habituales: impide usar la herramienta para escanear
# servicios arbitrarios (SSH, bases de datos, paneles internos) en hosts públicos.
ALLOWED_PORTS = {80, 443, 8080, 8443}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".lan", ".home", ".corp", ".intranet")
MAX_URL_LENGTH = 2048


class UnsafeTargetError(ValueError):
    """La URL apunta a un destino no público o no soportado."""


def _is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_public_url(url: str, resolve: bool = True) -> dict:
    """Valida esquema, credenciales, puerto y que el host resuelva solo a IPs públicas.

    Devuelve un diccionario con el host y las direcciones validadas, para que las
    conexiones posteriores usen esas mismas IPs (reduce el riesgo de DNS rebinding).
    """
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeTargetError("La URL está vacía o supera el largo permitido.")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("La URL o el puerto no son válidos.") from exc

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError("La URL debe usar http o https.")
    if not hostname:
        raise UnsafeTargetError("La URL debe incluir un host válido.")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("No se permiten credenciales dentro de la URL.")

    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in ALLOWED_PORTS and not settings.allow_private_targets:
        raise UnsafeTargetError("Solo se permiten los puertos web 80, 443, 8080 y 8443.")

    host = hostname.rstrip(".").lower()
    if not settings.allow_private_targets and (
        host in {"localhost", "localhost.localdomain"} or host.endswith(BLOCKED_SUFFIXES) or "." not in host and ":" not in host
    ):
        raise UnsafeTargetError("No se permiten URLs locales o de red privada.")

    addresses: list[str] = []
    try:
        ipaddress.ip_address(host.strip("[]"))
        addresses = [host.strip("[]")]
    except ValueError:
        if resolve:
            try:
                resolved = socket.getaddrinfo(host, effective_port, type=socket.SOCK_STREAM)
            except (socket.gaierror, UnicodeError) as exc:
                raise UnsafeTargetError("No se pudo resolver el host indicado.") from exc
            addresses = sorted({item[4][0] for item in resolved})
            if not addresses:
                raise UnsafeTargetError("El host no resolvió a ninguna dirección.")

    if not settings.allow_private_targets and any(not _is_public_ip(a) for a in addresses):
        raise UnsafeTargetError("No se permiten direcciones que no sean públicas.")

    return {
        "url": url,
        "scheme": scheme,
        "hostname": host,
        "port": effective_port,
        "addresses": addresses,
    }


def registrable_domain(hostname: str) -> str:
    """Aproximación del dominio registrable (sin lista de sufijos públicos).

    Considera sufijos de dos niveles comunes en Chile y Latinoamérica (p. ej.
    gob.cl, com.ar). Es una heurística documentada como limitación.
    """
    parts = (hostname or "").lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    second_level = {"com", "gob", "gov", "org", "net", "edu", "co", "ac", "mil"}
    if parts[-2] in second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
