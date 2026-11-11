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
    r"\b([A-ZÁÉÍÓÚÑ][A-Za-zÁÉÍÓÚÑáéíóúñ0-9&.\-]{0,40}(?: [A-Za-zÁÉÍÓÚÑáéíóúñ0-9&.\-]{1,40}){0,6} "
    r"(?:SpA|S\.p\.A\.|S\.A\.|Ltda\.?|Limitada|E\.I\.R\.L\.|EIRL))"
)
RUT_RE = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}")
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


def _host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def _first_line(exc: Exception) -> str:
    return str(exc).splitlines()[0][:300] if str(exc) else exc.__class__.__name__


# ---------------------------------------------------------------------------
class _Inspection:
    """Estado y pasos de una inspección. Cada método cubre una etapa acotada."""

    def __init__(self, url: str, target: dict) -> None:
        self.url = url
        self.target = target
        self.target_domain = registrable_domain(target["hostname"])
        self.validated_hosts: dict[str, bool] = {}
        self.phase = "load"
        self.requests = 0
        self.hops = 0
        self.blocked: list[str] = []
        self.redirects: list[dict] = []
        self.main_headers: dict[str, str] = {}
        self.main_blocked = False
        self.third_party: dict[str, dict] = {}  # host -> {"phases": set, "tracker": (proveedor, finalidad) | None}
        self.page = None
        self.partial_load = False

    # ---- Filtro de red (anti-SSRF) -------------------------------------------
    async def _host_is_allowed(self, request_url: str) -> bool:
        host = _host_of(request_url)
        if host not in self.validated_hosts:
            try:
                await asyncio.to_thread(validate_public_url, request_url)
                self.validated_hosts[host] = True
            except UnsafeTargetError:
                self.validated_hosts[host] = False
        return self.validated_hosts[host]

    def _record_request(self, request_url: str) -> None:
        host = _host_of(request_url)
        if not host or registrable_domain(host) == self.target_domain:
            return
        entry = self.third_party.setdefault(host, {"phases": set(), "tracker": None})
        entry["phases"].add(self.phase)
        entry["tracker"] = entry["tracker"] or match_tracker(request_url)

    async def _block(self, route, request_url: str, is_main_nav: bool) -> None:
        if len(self.blocked) < 20:
            self.blocked.append(_host_of(request_url))
        self.main_blocked = self.main_blocked or is_main_nav
        await route.abort("blockedbyclient")

    async def _fetch_navigation(self, route, request) -> None:
        """Resuelve la navegación principal salto a salto.

        Las redirecciones no vuelven a pasar por el filtro de rutas de Playwright;
        por eso se piden con max_redirects=0 y el navegador solicita cada nuevo
        destino, que vuelve a validarse en handle_route.
        """
        self.hops += 1
        if self.hops > MAX_REDIRECTS * 2:
            await route.abort()
            return
        try:
            response = await route.fetch(max_redirects=0, timeout=NAV_TIMEOUT_MS)
        except PlaywrightError as exc:
            logger.warning("Fallo al obtener %s: %s", request.url[:200], _first_line(exc))
            await route.abort()
            return
        if 300 <= response.status < 400:
            if self.phase != "policy":
                location = urllib.parse.urljoin(request.url, response.headers.get("location", ""))
                self.redirects.append({"status": response.status, "to": location[:300]})
        elif self.page is not None and request.frame == self.page.main_frame:
            self.main_headers = {k.lower(): v[:300] for k, v in response.headers.items()}
        await route.fulfill(response=response)

    async def handle_route(self, route) -> None:
        request = route.request
        request_url = request.url
        if urllib.parse.urlsplit(request_url).scheme.lower() in {"data", "blob", "about"}:
            await route.continue_()
            return
        self.requests += 1
        if self.requests > MAX_REQUESTS or request.resource_type in {"websocket", "eventsource"}:
            await route.abort()
            return
        is_main_nav = request.is_navigation_request() and _is_main_frame(request)
        if not await self._host_is_allowed(request_url):
            await self._block(route, request_url, is_main_nav)
            return
        self._record_request(request_url)
        if is_main_nav:
            await self._fetch_navigation(route, request)
        elif request.resource_type in BLOCKED_RESOURCE_TYPES:
            # Imágenes, fuentes y video no se descargan: no hacen falta para leer el DOM
            # y aceleran la carga. La solicitud ya quedó registrada como evidencia.
            await route.abort()
        else:
            await route.continue_()

    # ---- Etapas de la inspección --------------------------------------------
    def _launch_args(self) -> list[str]:
        args = ["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
                "--disable-background-networking", "--disable-sync", "--mute-audio"]
        ipv4 = [a for a in self.target.get("addresses", []) if ":" not in a]
        if ipv4:
            # Fija la IP ya validada para el host principal (mitiga DNS rebinding).
            args.append(f"--host-resolver-rules=MAP {self.target['hostname']} {ipv4[0]}")
        return args

    async def load(self) -> None:
        try:
            await self.page.goto(self.url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        except PlaywrightTimeoutError as exc:
            if self.main_blocked:
                raise UnsafeTargetError("La página redirigió o intentó navegar hacia un destino no público.") from exc
            if not self.main_headers:
                raise DomInspectionError("El sitio no respondió dentro del tiempo límite.") from exc
            # El HTML principal llegó, pero la página no terminó de cargar (scripts lentos):
            # se analiza lo que alcanzó a cargar y se informa como limitación.
            self.partial_load = True
            logger.warning("Carga parcial de %s: se analiza el contenido disponible.", self.url[:200])
        except PlaywrightError as exc:
            logger.warning("Fallo al cargar %s: %s", self.url[:200], _first_line(exc))
            if self.main_blocked:
                raise UnsafeTargetError("La página redirigió o intentó navegar hacia un destino no público.") from exc
            raise DomInspectionError("No se pudo cargar la página indicada.") from exc

        try:
            await self.page.wait_for_load_state("networkidle", timeout=3_000 if self.partial_load else 6_000)
        except PlaywrightTimeoutError:
            logger.debug("Sin reposo de red en %s; se continúa con lo cargado.", self.url[:200])
        await self.page.wait_for_timeout(1_500)

    async def reject_cookies(self, context, banner: dict) -> tuple[dict, list | None]:
        """Única interacción definida: pulsar 'Rechazar' y observar lo que ocurre."""
        interaction = {"attempted": False, "clicked": False, "error": None}
        if not banner.get("has_reject"):
            return interaction, None
        interaction["attempted"] = True
        self.phase = "after_reject"
        cookies_after = None
        try:
            await self.page.locator("[data-ebm-reject]").first.click(timeout=3_000, no_wait_after=True)
            interaction["clicked"] = True
            await self.page.wait_for_timeout(3_000)
            cookies_after = await context.cookies()
        except PlaywrightError as exc:
            interaction["error"] = "No fue posible pulsar el botón de rechazo."
            logger.info("Reject click failed on %s: %s", self.target["hostname"], exc.__class__.__name__)
        self.phase = "post"
        return interaction, cookies_after

    async def read_policy(self, context, policy_links: list) -> dict:
        """Abre el enlace de política más probable y extrae solo datos explícitos (RF07)."""
        policy = {"url": None, "link_text": None, "fetched": False, "error": None, "analysis": None}
        if not policy_links:
            return policy
        best = policy_links[0]
        policy["url"], policy["link_text"] = best["href"], best["text"]
        self.phase = "policy"
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
        return policy

    # ---- Resumen ------------------------------------------------------------
    def cookie_summary(self, cookies: list | None) -> dict | None:
        if cookies is None:
            return None
        tracking = sorted({f"{c['name']} ({match_tracking_cookie(c['name'])})"
                           for c in cookies if match_tracking_cookie(c["name"])})
        third = sorted({c["domain"].lstrip(".") for c in cookies
                        if registrable_domain(c["domain"].lstrip(".")) != self.target_domain})
        return {"total": len(cookies), "tracking": tracking[:30], "third_party_domains": third[:30]}

    def trackers_in(self, phase: str) -> list[str]:
        return sorted({f"{v['tracker'][0]} ({v['tracker'][1]})"
                       for v in self.third_party.values() if v["tracker"] and phase in v["phases"]})

    def third_party_hosts(self, phase: str) -> list[str]:
        return sorted(h for h, v in self.third_party.items() if phase in v["phases"])[:60]

    async def run(self) -> dict:
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True, args=self._launch_args())
            except PlaywrightError as exc:
                raise DomInspectionError("No se pudo iniciar Chromium. Verifica la instalación de Playwright.") from exc
            try:
                return await self._inspect(browser)
            finally:
                await browser.close()

    async def _inspect(self, browser) -> dict:
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
        await context.route("**/*", self.handle_route)
        context.on("page", _dismiss_dialogs)
        self.page = await context.new_page()

        await self.load()
        final_url = self.page.url
        cookies_before = await context.cookies()
        banner = await _safe_eval(self.page, BANNER_JS, dict(EMPTY_BANNER))
        interaction, cookies_after = await self.reject_cookies(context, banner)
        forms = await _safe_eval(self.page, FORMS_JS, [])
        whatsapp = await _safe_eval(self.page, WHATSAPP_JS, {"count": 0, "has_visible_notice": False})
        policy_links = await _safe_eval(self.page, POLICY_LINKS_JS, [])
        policy = await self.read_policy(context, policy_links)

        return {
            "final_url": final_url[:2048],
            "partial_load": self.partial_load,
            "redirects": self.redirects,
            "hsts_header": self.main_headers.get("strict-transport-security"),
            "requests_observed": self.requests,
            "blocked_non_public_hosts": sorted({h for h in self.blocked if h}),
            "cookie_banner": banner,
            "consent_interaction": interaction,
            "cookies_before_consent": self.cookie_summary(cookies_before),
            "cookies_after_reject": self.cookie_summary(cookies_after),
            "third_party_hosts_before_consent": self.third_party_hosts("load"),
            "trackers_before_consent": self.trackers_in("load"),
            "trackers_after_reject": self.trackers_in("after_reject"),
            "tracker_list_version": LIST_VERSION,
            "forms": forms,
            "whatsapp": whatsapp,
            "privacy_policy": policy,
        }


_background_tasks: set = set()


def _dismiss_dialogs(page) -> None:
    def on_dialog(dialog) -> None:
        # Se guarda la referencia para que la tarea no sea recolectada antes de terminar.
        task = asyncio.ensure_future(dialog.dismiss())
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
    page.on("dialog", on_dialog)


async def inspect_website_dom(url: str, target: dict) -> dict:
    """Inspecciona la página y devuelve evidencia estructurada y acotada."""
    return await _Inspection(url, target).run()
