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
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain"}
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


def _parse(url: str) -> tuple[str, str, int]:
    """Devuelve (esquema, host, puerto efectivo) o lanza UnsafeTargetError."""
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeTargetError("La URL está vacía o supera el largo permitido.")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("La URL o el puerto no son válidos.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError("La URL debe usar http o https.")
    if not parsed.hostname:
        raise UnsafeTargetError("La URL debe incluir un host válido.")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("No se permiten credenciales dentro de la URL.")
    return scheme, parsed.hostname.rstrip(".").lower(), port or (443 if scheme == "https" else 80)


def _check_port(port: int) -> None:
    if port not in ALLOWED_PORTS:
        raise UnsafeTargetError("Solo se permiten los puertos web 80, 443, 8080 y 8443.")


def _check_hostname(host: str) -> None:
    is_single_label = "." not in host and ":" not in host
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES) or is_single_label:
        raise UnsafeTargetError("No se permiten URLs locales o de red privada.")


def _literal_ip(host: str) -> str | None:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _resolve(host: str, port: int) -> list[str]:
    try:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise UnsafeTargetError("No se pudo resolver el host indicado.") from exc
    addresses = sorted({item[4][0] for item in resolved})
    if not addresses:
        raise UnsafeTargetError("El host no resolvió a ninguna dirección.")
    return addresses


def validate_public_url(url: str, resolve: bool = True) -> dict:
    """Valida esquema, credenciales, puerto y que el host resuelva solo a IPs públicas.

    Devuelve un diccionario con el host y las direcciones validadas, para que las
    conexiones posteriores usen esas mismas IPs (reduce el riesgo de DNS rebinding).
    """
    scheme, host, port = _parse(url)
    strict = not settings.allow_private_targets
    if strict:
        _check_port(port)
        _check_hostname(host)

    literal = _literal_ip(host)
    if literal:
        addresses = [literal]
    elif resolve:
        addresses = _resolve(host, port)
    else:
        addresses = []

    if strict and not all(_is_public_ip(a) for a in addresses):
        raise UnsafeTargetError("No se permiten direcciones que no sean públicas.")

    return {"url": url, "scheme": scheme, "hostname": host, "port": port, "addresses": addresses}


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
