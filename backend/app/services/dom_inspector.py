import asyncio
import ipaddress
import socket
import urllib.parse

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright


class UnsafeTargetError(ValueError):
    """Raised when a URL resolves to a non-public or unsupported target."""


class DomInspectionError(RuntimeError):
    """Raised when the browser cannot complete a DOM inspection."""


def _is_public_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def validate_public_url(url: str):
    """Validates that a URL points to a public reachable host and is safe to inspect."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        port = parsed_url.port
    except ValueError as exc:
        raise UnsafeTargetError("La URL o el puerto no son válidos.") from exc

    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname

    if scheme not in {"http", "https"}:
        raise UnsafeTargetError("La URL debe usar http o https.")
    if not hostname:
        raise UnsafeTargetError("La URL debe incluir un host válido.")
    if parsed_url.username is not None or parsed_url.password is not None:
        raise UnsafeTargetError("No se permiten credenciales dentro de la URL.")

    host_lower = hostname.rstrip(".").lower()
    if (
        host_lower in {"localhost", "localhost.localdomain"}
        or host_lower.endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise UnsafeTargetError("No se permiten URLs locales o de red privada.")

    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTargetError("No se pudo resolver el host indicado.") from exc

        addresses = list({result[4][0] for result in resolved})
        if not addresses:
            raise UnsafeTargetError("El host no resolvió a ninguna dirección.")

    if any(not _is_public_ip(address) for address in addresses):
        raise UnsafeTargetError("No se permiten direcciones que no sean públicas.")

    return {
        "url": url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port or (443 if scheme == "https" else 80),
    }


async def inspect_website_dom(url: str):
    """
    Inspecciona la capa pública visible de un sitio web para verificar
    elementos exigidos por la Ley N° 21.719.
    """
    validate_public_url(url)

    analysis = {
        "has_cookie_banner": False,
        "has_whatsapp": False,
        "has_contact_forms": False,
        "has_form_checkbox": False,
        "has_privacy_policy": False,
    }

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
        except PlaywrightError as exc:
            raise DomInspectionError(
                "No se pudo iniciar Chromium. Verifica la instalación de los navegadores de Playwright."
            ) from exc

        try:
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            )
            page = await context.new_page()
            blocked_target = None

            async def validate_request(route):
                nonlocal blocked_target
                request_url = route.request.url
                request_scheme = urllib.parse.urlparse(request_url).scheme.lower()
                if request_scheme in {"data", "blob"}:
                    await route.continue_()
                    return
                try:
                    await asyncio.to_thread(validate_public_url, request_url)
                except UnsafeTargetError:
                    blocked_target = request_url
                    await route.abort()
                    return
                await route.continue_()

            await page.route("**/*", validate_request)
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            await page.wait_for_timeout(5000)

            consent_candidates = await page.locator(
                '[role="dialog"], [aria-modal="true"], [id*="cookie" i], '
                '[class*="cookie" i], [id*="consent" i], [class*="consent" i]'
            ).evaluate_all(
                """elements => elements.some(element => {
                    const style = window.getComputedStyle(element);
                    const visible = style.display !== "none" &&
                        style.visibility !== "hidden" &&
                        element.getClientRects().length > 0;
                    const text = (element.innerText || "").toLowerCase();
                    const hasCookieText = /cookie|consentimiento|consent/.test(text);
                    const hasChoice = element.querySelector(
                        'button, [role="button"], input[type="button"], input[type="submit"]'
                    );
                    return visible && hasCookieText && Boolean(hasChoice);
                })"""
            )
            analysis["has_cookie_banner"] = consent_candidates

            whatsapp_elements = await page.query_selector_all('a[href*="whatsapp"], a[href*="wa.me"], img[alt*="whatsapp"], div[class*="whatsapp"]')
            if len(whatsapp_elements) > 0:
                analysis["has_whatsapp"] = True

            forms = await page.query_selector_all('form')
            if len(forms) > 0:
                analysis["has_contact_forms"] = True
                checkboxes = await page.query_selector_all(
                    'form input[type="checkbox"]'
                )
                analysis["has_form_checkbox"] = len(checkboxes) > 0

            privacy_link = await page.locator("a").evaluate_all(
                """links => links.some(link => {
                    const text = (link.innerText || "").toLowerCase();
                    const href = (link.getAttribute("href") || "").toLowerCase();
                    return /pol[ií]ticas? de privacidad|aviso de privacidad|privacy policy/.test(text) ||
                        /privacy[-_/]?policy|politica[-_/]?privacidad/.test(href);
                })"""
            )
            analysis["has_privacy_policy"] = privacy_link

        except PlaywrightError as exc:
            if blocked_target:
                raise UnsafeTargetError(
                    "La página intentó navegar o cargar recursos desde un destino no público."
                ) from exc
            raise DomInspectionError(
                "No se pudo completar la inspección de la página."
            ) from exc
        finally:
            await browser.close()

    return analysis