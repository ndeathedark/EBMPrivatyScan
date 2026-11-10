"""Inspección de la superficie web pública con Playwright/Chromium.

Principios (RNF03 — carácter no invasivo):
  * Solo navega y lee el DOM. Nunca envía formularios ni escribe en campos.
  * La única interacción definida es pulsar, si existe, el botón "Rechazar" del
    banner de cookies para comparar los recursos cargados antes y después.
  * Cada solicitud del navegador (incluidas las redirecciones) se valida contra
    destinos no públicos para evitar SSRF.
"""
import asyncio
import logging
import re
import urllib.parse

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from .trackers import LIST_VERSION, match_tracker, match_tracking_cookie
from .url_guard import UnsafeTargetError, registrable_domain, validate_public_url

logger = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 EBMPrivatyScan/2.0 (diagnostico autorizado Ley 21.719)"
)
MAX_REQUESTS = 600
MAX_REDIRECTS = 10
NAV_TIMEOUT_MS = 20_000
POLICY_TIMEOUT_MS = 10_000


class DomInspectionError(RuntimeError):
    """El navegador no pudo completar la inspección."""


# ---------------------------------------------------------------------------
# Scripts que se ejecutan en la página (solo lectura del DOM)
# ---------------------------------------------------------------------------
BANNER_JS = r"""
() => {
  const cmpSelectors = [
    '#onetrust-banner-sdk', '#CybotCookiebotDialog', '.cky-consent-container',
    '#cookie-law-info-bar', '.cc-window', '[id^="didomi"]', '#cmplz-cookiebanner-container',
    '.cmplz-cookiebanner', '#moove_gdpr_cookie_info_bar', '#iubenda-cs-banner',
    '#cookie-notice', '#cookiescript_injected', '.termly-styles-root'
  ];
  const generic = '[role="dialog"], [aria-modal="true"], [id*="cookie" i], [class*="cookie" i], ' +
                  '[id*="consent" i], [class*="consent" i], [id*="gdpr" i], [class*="gdpr" i]';
  const visible = el => {
    const s = window.getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden' && parseFloat(s.opacity || '1') > 0 &&
           el.getClientRects().length > 0;
  };
  const textOf = el => (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().toLowerCase();
  const acceptRe = /^(aceptar|acepto|aceptar todo|aceptar todas|permitir todo|accept|accept all|allow all|ok|entendido|de acuerdo|estoy de acuerdo)/;
  const rejectRe = /(rechazar|rechazo|denegar|no acepto|s[oó]lo (las )?(necesarias|esenciales)|reject|decline|deny|only necessary|necessary only)/;
  const configRe = /(configurar|personalizar|preferencias|ajustes|gestionar|administrar|settings|preferences|customi[sz]e|manage)/;

  const candidates = [...new Set([...document.querySelectorAll(cmpSelectors.join(',')), ...document.querySelectorAll(generic)])];
  for (const el of candidates) {
    if (!visible(el)) continue;
    const text = textOf(el);
    if (!/cookie|consentimiento|consent|rastreo/.test(text)) continue;
    const buttons = [...el.querySelectorAll('button, [role="button"], a, input[type="button"]')]
      .filter(b => visible(b) && !b.closest('form'));
    if (!buttons.length) continue;
    let hasAccept = false, hasReject = false, hasConfig = false, marked = false;
    for (const b of buttons) {
      const t = textOf(b);
      if (rejectRe.test(t)) {
        hasReject = true;
        // Marca solo la copia local del DOM para poder pulsarlo; no altera el sitio.
        if (!marked) { b.setAttribute('data-ebm-reject', '1'); marked = true; }
      } else if (acceptRe.test(t)) { hasAccept = true; }
      else if (configRe.test(t)) { hasConfig = true; }
    }
    const cmp = cmpSelectors.find(sel => el.matches(sel)) || null;
    return { found: true, has_accept: hasAccept, has_reject: hasReject, has_configure: hasConfig,
             known_cmp: cmp, text_sample: text.slice(0, 220) };
  }
  return { found: false, has_accept: false, has_reject: false, has_configure: false, known_cmp: null, text_sample: '' };
}
"""

FORMS_JS = r"""
() => {
  const consentRe = /(privacidad|datos personales|tratamiento de (tus |sus |los )?datos|protecci[oó]n de datos|consentimiento|acepto|autorizo|privacy|personal data)/i;
  const personalTypes = ['email', 'tel', 'password'];
  const personalNameRe = /(nombre|name|apellido|rut|correo|mail|fono|phone|telefono|tel[eé]fono|direcci[oó]n|address|empresa|mensaje)/i;
  return [...document.querySelectorAll('form')].slice(0, 15).map(form => {
    const inputs = [...form.querySelectorAll('input, textarea, select')];
    const personalFields = inputs.filter(i => {
      const type = (i.getAttribute('type') || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'search', 'image', 'reset'].includes(type)) return false;
      const hint = [i.name, i.id, i.placeholder, i.getAttribute('autocomplete'), i.getAttribute('aria-label')].join(' ');
      return personalTypes.includes(type) || personalNameRe.test(hint) || i.tagName === 'TEXTAREA';
    });
    const checkboxes = [...form.querySelectorAll('input[type="checkbox"]')];
    const consentBoxes = checkboxes.filter(cb => {
      const byFor = cb.id ? document.querySelector(`label[for="${CSS.escape(cb.id)}"]`) : null;
      const label = (cb.closest('label')?.innerText || byFor?.innerText || cb.parentElement?.innerText || '');
      return consentRe.test(label);
    });
    const text = (form.innerText || '').slice(0, 4000);
    const action = form.getAttribute('action') || '';
    let actionUrl = '';
    try { actionUrl = new URL(action || location.href, location.href).href; } catch (e) {}
    const isSearch = (form.getAttribute('role') === 'search') ||
                     inputs.some(i => (i.getAttribute('type') || '').toLowerCase() === 'search') ||
                     /search|buscar|busqueda|búsqueda/i.test(form.id + ' ' + form.className + ' ' + action);
    return {
      personal_fields: personalFields.length,
      has_password: inputs.some(i => (i.getAttribute('type') || '').toLowerCase() === 'password'),
      checkboxes: checkboxes.length,
      consent_checkboxes: consentBoxes.length,
      consent_prechecked: consentBoxes.some(cb => cb.defaultChecked || cb.checked),
      has_privacy_text: consentRe.test(text),
      links_to_policy: [...form.querySelectorAll('a')].some(a => /privacidad|privacy|datos/i.test((a.innerText || '') + (a.getAttribute('href') || ''))),
      method: (form.getAttribute('method') || 'get').toLowerCase(),
      action_scheme: actionUrl ? actionUrl.split(':')[0] : '',
      is_search: isSearch,
    };
  });
}
"""

WHATSAPP_JS = r"""
() => {
  const els = document.querySelectorAll('a[href*="whatsapp" i], a[href*="wa.me" i], [class*="whatsapp" i], [id*="whatsapp" i], img[alt*="whatsapp" i]');
  const bodyText = (document.body?.innerText || '').toLowerCase();
  const noticeRe = /whatsapp[^.]{0,200}(privacidad|datos|tratamiento)|(privacidad|datos|tratamiento)[^.]{0,200}whatsapp/;
  return { count: els.length, has_visible_notice: noticeRe.test(bodyText) };
}
"""

POLICY_LINKS_JS = r"""
() => {
  const strong = /(pol[ií]tica[s]? de privacidad|aviso de privacidad|privacy policy|protecci[oó]n de datos|tratamiento de datos( personales)?|pol[ií]tica de datos)/i;
  const hrefRe = /(privacy|privacidad|proteccion-de-datos|datos-personales|tratamiento-de-datos|politica-de-datos)/i;
  const out = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const text = (a.innerText || a.getAttribute('aria-label') || '').trim();
    const href = a.href;
    if (!/^https?:/i.test(href)) continue;
    const score = (strong.test(text) ? 2 : 0) + (hrefRe.test(href) ? 1 : 0);
    if (score > 0) out.push({ text: text.slice(0, 120), href: href.slice(0, 2048), score });
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, 5);
}
"""

MONTHS = "enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|setiembre|octubre|noviembre|diciembre"
DATE_RE = re.compile(
    r"(actualiza\w*|última modificación|ultima modificacion|vigente desde|vigencia|fecha de (publicación|actualización))"
    rf"[^\n]{{0,60}}?(\d{{1,2}}[/.-]\d{{1,2}}[/.-]\d{{2,4}}|\d{{1,2}} de ({MONTHS}) (de |del )?\d{{4}}|({MONTHS}) (de |del )?\d{{4}}|\b20\d{{2}}\b)",
    re.IGNORECASE,
)
ORG_RE = re.compile(
    r"\b([A-ZÁÉÍÓÚÑ][A-Za-zÁÉÍÓÚÑáéíóúñ0-9&.\-]*(?:[ \t]+[A-Za-zÁÉÍÓÚÑáéíóúñ0-9&.\-]+){0,6}[ \t]+"
    r"(?:SpA|S\.p\.A\.|S\.A\.|Ltda\.?|Limitada|E\.I\.R\.L\.|EIRL))"
)
RUT_RE = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RIGHTS = {
    "acceso": r"\bacceso\b",
    "rectificación": r"rectificaci[oó]n",
    "supresión": r"supresi[oó]n|cancelaci[oó]n|eliminaci[oó]n",
    "oposición": r"oposici[oó]n",
    "portabilidad": r"portabilidad",
    "bloqueo": r"\bbloqueo\b",
}


def analyse_policy_text(text: str) -> dict:
    """Extrae solo datos explícitos de la política; no evalúa su suficiencia jurídica."""
    text = text or ""
    lowered = text.lower()
    date_match = DATE_RE.search(text)
    org_match = ORG_RE.search(text)
    return {
        "length_chars": len(text),
        "update_date_text": date_match.group(0)[:120] if date_match else None,
        "organization": org_match.group(1)[:120] if org_match else None,
        "has_rut": bool(RUT_RE.search(text)),
        "has_contact_email": bool(EMAIL_RE.search(text)),
        "mentions_law_21719": bool(re.search(r"21[.\s]?719", lowered)),
        "mentions_law_19628": bool(re.search(r"19[.\s]?628", lowered)),
        "rights_mentioned": [name for name, pattern in RIGHTS.items() if re.search(pattern, lowered)],
        "mentions_retention": bool(re.search(r"conservaci[oó]n|conservar[aá]n|conservamos|plazo|retenci[oó]n", lowered)),
        "mentions_third_parties": bool(re.search(r"tercer[oa]s|encargad[oa]s? del tratamiento|proveedores", lowered)),
    }


BLOCKED_RESOURCE_TYPES = {"image", "font", "media"}
EMPTY_BANNER = {"found": False, "has_accept": False, "has_reject": False, "has_configure": False,
                "known_cmp": None, "text_sample": ""}


async def _safe_eval(page, script: str, default):
    """Evalúa un script de lectura; si la página está navegando, reintenta una vez."""
    for attempt in range(2):
        try:
            return await page.evaluate(script)
        except PlaywrightError:
            if attempt == 0:
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=4_000)
                except PlaywrightError:
                    pass
    return default


def _is_main_frame(request) -> bool:
    try:
        return request.frame.parent_frame is None
    except PlaywrightError:
        return False


# ---------------------------------------------------------------------------
async def inspect_website_dom(url: str, target: dict) -> dict:
    """Inspecciona la página y devuelve evidencia estructurada y acotada."""
    target_domain = registrable_domain(target["hostname"])
    validated_hosts: dict[str, bool] = {}
    state = {"phase": "load", "requests": 0, "blocked": [], "redirects": [], "main_headers": {}, "main_blocked": False}
    third_party: dict[str, dict] = {}   # host -> {"phases": set, "tracker": (proveedor, finalidad) | None}

    async def host_is_allowed(request_url: str) -> bool:
        host = (urllib.parse.urlsplit(request_url).hostname or "").lower()
        if host in validated_hosts:
            return validated_hosts[host]
        try:
            await asyncio.to_thread(validate_public_url, request_url)
            validated_hosts[host] = True
        except UnsafeTargetError:
            validated_hosts[host] = False
        return validated_hosts[host]

    def record_request(request_url: str) -> None:
        host = (urllib.parse.urlsplit(request_url).hostname or "").lower()
        if not host or registrable_domain(host) == target_domain:
            return
        entry = third_party.setdefault(host, {"phases": set(), "tracker": None})
        entry["phases"].add(state["phase"])
        entry["tracker"] = entry["tracker"] or match_tracker(request_url)

    async def handle_route(route):
        request = route.request
        request_url = request.url
        scheme = urllib.parse.urlsplit(request_url).scheme.lower()
        if scheme in {"data", "blob", "about"}:
            await route.continue_()
            return
        state["requests"] += 1
        if state["requests"] > MAX_REQUESTS or request.resource_type in {"websocket", "eventsource"}:
            await route.abort()
            return
        is_main_nav = request.is_navigation_request() and _is_main_frame(request)
        if not await host_is_allowed(request_url):
            if len(state["blocked"]) < 20:
                state["blocked"].append(urllib.parse.urlsplit(request_url).hostname)
            state["main_blocked"] = state["main_blocked"] or is_main_nav
            await route.abort("blockedbyclient")
            return

        record_request(request_url)

        # Imágenes, fuentes y video no se descargan: no son necesarios para leer el DOM y
        # aceleran mucho la carga. La solicitud ya quedó registrada como evidencia de terceros.
        if request.resource_type in BLOCKED_RESOURCE_TYPES:
            await route.abort()
            return

        if is_main_nav:
            # Las redirecciones no vuelven a pasar por el filtro de rutas de Playwright;
            # por eso se resuelven aquí salto a salto (max_redirects=0) y el navegador
            # solicita cada nuevo destino, que vuelve a validarse en este mismo handler.
            state["hops"] = state.get("hops", 0) + 1
            if state["hops"] > MAX_REDIRECTS * 2:
                await route.abort()
                return
            try:
                response = await route.fetch(max_redirects=0, timeout=NAV_TIMEOUT_MS)
            except PlaywrightError as exc:
                logger.warning("Fallo al obtener %s: %s", request_url[:200], str(exc).splitlines()[0][:300])
                await route.abort()
                return
            if 300 <= response.status < 400 and state["phase"] != "policy":
                location = response.headers.get("location", "")
                state["redirects"].append(
                    {"status": response.status, "to": urllib.parse.urljoin(request_url, location)[:300]}
                )
            elif request.frame == page.main_frame:
                state["main_headers"] = {k.lower(): v[:300] for k, v in response.headers.items()}
            await route.fulfill(response=response)
            return

        await route.continue_()

    async with async_playwright() as p:
        launch_args = ["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
                       "--disable-background-networking", "--disable-sync", "--mute-audio"]
        ipv4 = [a for a in target.get("addresses", []) if ":" not in a]
        if ipv4:
            # Fija la IP ya validada para el host principal (mitiga DNS rebinding).
            launch_args.append(f"--host-resolver-rules=MAP {target['hostname']} {ipv4[0]}")
        try:
            browser = await p.chromium.launch(headless=True, args=launch_args)
        except PlaywrightError as exc:
            raise DomInspectionError("No se pudo iniciar Chromium. Verifica la instalación de Playwright.") from exc

        try:
            context = await browser.new_context(
                user_agent=USER_AGENT,
                locale="es-CL",
                timezone_id="America/Santiago",
                viewport={"width": 1366, "height": 900},
                service_workers="block",   # los service workers evadirían el filtro de rutas
                accept_downloads=False,
                ignore_https_errors=False,
            )
            context.set_default_timeout(8_000)
            await context.route("**/*", handle_route)
            context.on("page", lambda pg: pg.on("dialog", lambda d: asyncio.ensure_future(d.dismiss())))
            page = await context.new_page()

            partial_load = False
            try:
                await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            except PlaywrightTimeoutError as exc:
                if state["main_blocked"]:
                    raise UnsafeTargetError("La página redirigió o intentó navegar hacia un destino no público.") from exc
                if not state["main_headers"]:
                    raise DomInspectionError("El sitio no respondió dentro del tiempo límite.") from exc
                # El HTML principal llegó, pero la página no terminó de cargar (scripts lentos):
                # se analiza lo que alcanzó a cargar y se informa como limitación.
                partial_load = True
                logger.warning("Carga parcial de %s: se analiza el contenido disponible.", url[:200])
            except PlaywrightError as exc:
                logger.warning("Fallo al cargar %s: %s", url[:200], str(exc).splitlines()[0][:300])
                if state["main_blocked"]:
                    raise UnsafeTargetError("La página redirigió o intentó navegar hacia un destino no público.") from exc
                if isinstance(exc, PlaywrightTimeoutError):
                    raise DomInspectionError("El sitio tardó demasiado en responder (tiempo de espera agotado).") from exc
                raise DomInspectionError("No se pudo cargar la página indicada.") from exc

            try:
                await page.wait_for_load_state("networkidle", timeout=3_000 if partial_load else 6_000)
            except PlaywrightTimeoutError:
                pass  # sitios con conexiones persistentes: se continúa con lo cargado
            await page.wait_for_timeout(1_500)

            final_url = page.url
            cookies_before = await context.cookies()
            banner = await _safe_eval(page, BANNER_JS, dict(EMPTY_BANNER))

            # ---- Interacción definida: pulsar "Rechazar" y observar ------------
            interaction = {"attempted": False, "clicked": False, "error": None}
            cookies_after = None
            if banner.get("has_reject"):
                interaction["attempted"] = True
                state["phase"] = "after_reject"
                try:
                    await page.locator("[data-ebm-reject]").first.click(timeout=3_000, no_wait_after=True)
                    interaction["clicked"] = True
                    await page.wait_for_timeout(3_000)
                    cookies_after = await context.cookies()
                except PlaywrightError as exc:
                    interaction["error"] = "No fue posible pulsar el botón de rechazo."
                    logger.info("Reject click failed on %s: %s", target["hostname"], exc.__class__.__name__)
                state["phase"] = "post"

            forms = await _safe_eval(page, FORMS_JS, [])
            whatsapp = await _safe_eval(page, WHATSAPP_JS, {"count": 0, "has_visible_notice": False})
            policy_links = await _safe_eval(page, POLICY_LINKS_JS, [])

            # ---- Lectura de la política de privacidad (RF07) ---------------------
            policy = {"url": None, "link_text": None, "fetched": False, "error": None, "analysis": None}
            if policy_links:
                best = policy_links[0]
                policy["url"], policy["link_text"] = best["href"], best["text"]
                state["phase"] = "policy"
                policy_page = await context.new_page()
                try:
                    await policy_page.goto(best["href"], timeout=POLICY_TIMEOUT_MS, wait_until="domcontentloaded")
                    text = await policy_page.evaluate("() => (document.body ? document.body.innerText : '').slice(0, 200000)")
                    policy["fetched"] = True
                    policy["analysis"] = analyse_policy_text(text)
                except PlaywrightError:
                    policy["error"] = "No se pudo abrir la página de la política para leer su contenido."
                finally:
                    await policy_page.close()
        finally:
            await browser.close()

    def cookie_summary(cookies):
        if cookies is None:
            return None
        tracking = sorted({f"{c['name']} ({match_tracking_cookie(c['name'])})" for c in cookies if match_tracking_cookie(c["name"])})
        third = sorted({c["domain"].lstrip(".") for c in cookies if registrable_domain(c["domain"].lstrip(".")) != target_domain})
        return {"total": len(cookies), "tracking": tracking[:30], "third_party_domains": third[:30]}

    def trackers_in(phase):
        return sorted({f"{v['tracker'][0]} ({v['tracker'][1]})" for v in third_party.values() if v["tracker"] and phase in v["phases"]})

    return {
        "final_url": final_url[:2048],
        "partial_load": partial_load,
        "redirects": state["redirects"],
        "hsts_header": state["main_headers"].get("strict-transport-security"),
        "requests_observed": state["requests"],
        "blocked_non_public_hosts": sorted({h for h in state["blocked"] if h}),
        "cookie_banner": banner,
        "consent_interaction": interaction,
        "cookies_before_consent": cookie_summary(cookies_before),
        "cookies_after_reject": cookie_summary(cookies_after),
        "third_party_hosts_before_consent": sorted(h for h, v in third_party.items() if "load" in v["phases"])[:60],
        "trackers_before_consent": trackers_in("load"),
        "trackers_after_reject": trackers_in("after_reject"),
        "tracker_list_version": LIST_VERSION,
        "forms": forms,
        "whatsapp": whatsapp,
        "privacy_policy": policy,
    }