"""Motor de reglas: transforma la evidencia observada en hallazgos (RF09, RF10).

Cada hallazgo incluye estado, severidad, evidencia, explicación en lenguaje
sencillo y la limitación de la comprobación. Las explicaciones son neutrales:
describen lo observado y por qué conviene revisarlo, sin declarar infracciones.

Indicador de riesgo orientativo
-------------------------------
riesgo = Σ(peso × factor) / Σ(pesos aplicables) × 100
factor: BRECHA = 1 · ALERTA = 0,5 · NO_CONCLUYENTE = 0,25 · CUMPLE = 0
Las categorías NO_APLICA e INFORMATIVO no participan en el cálculo.
"""

CUMPLE, BRECHA, ALERTA, NO_CONCLUYENTE, NO_APLICA, INFORMATIVO = (
    "CUMPLE", "BRECHA", "ALERTA", "NO_CONCLUYENTE", "NO_APLICA", "INFORMATIVO",
)
STATUS_FACTOR = {BRECHA: 1.0, ALERTA: 0.5, NO_CONCLUYENTE: 0.25, CUMPLE: 0.0}

WEIGHTS = {
    "Conexión segura (HTTPS)": 25,
    "Política de privacidad": 25,
    "Rastreadores antes del consentimiento": 20,
    "Banner de consentimiento de cookies": 15,
    "Formularios y consentimiento": 15,
    "Respeto del rechazo de cookies": 10,
    "Canal WhatsApp": 5,
    "Recursos de terceros": 0,
}


def _finding(category, status, severity, explanation, evidence=None, limitation=None) -> dict:
    return {
        "category": category,
        "status": status,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence or {},
        "limitation": limitation,
    }


def _https(tls: dict, dom: dict) -> dict:
    cat = "Conexión segura (HTTPS)"
    final_scheme = (dom.get("final_url") or "").split(":", 1)[0]
    evidence = {
        "estado_tls": tls.get("state"),
        "detalle": tls.get("detail"),
        "version_tls": tls.get("tls_version"),
        "emisor": tls.get("issuer"),
        "vence": tls.get("not_after"),
        "url_final": dom.get("final_url"),
        "hsts": dom.get("hsts_header"),
    }
    limitation = "Se verifica la conexión y el certificado observables; no es una auditoría criptográfica completa."
    state = tls.get("state")
    if state == "valid":
        if final_scheme == "http":
            return _finding(cat, ALERTA, "media",
                            "El sitio tiene un certificado válido, pero la página se entregó sin cifrar (http). "
                            "Conviene redirigir siempre a https para que los datos viajen protegidos.", evidence, limitation)
        days = tls.get("days_to_expiry")
        if isinstance(days, int) and days < 15:
            return _finding(cat, ALERTA, "media",
                            f"El certificado es válido, pero vence en {days} días. Si expira, los navegadores "
                            "mostrarán advertencias y la conexión dejará de ser confiable.", evidence, limitation)
        return _finding(cat, CUMPLE, "info",
                        "La conexión usa HTTPS con un certificado válido: la información que envían los visitantes "
                        "viaja cifrada.", evidence, limitation)
    if state in {"invalid_certificate", "no_https"}:
        return _finding(cat, BRECHA, "alta",
                        "No se pudo establecer una conexión HTTPS confiable. Sin cifrado, los datos que las personas "
                        "ingresan (por ejemplo, en formularios) podrían ser interceptados.", evidence, limitation)
    return _finding(cat, NO_CONCLUYENTE, "media",
                    "No fue posible comprobar HTTPS (tiempo de espera o error de red). Este resultado no indica que el "
                    "sitio cumpla ni que incumpla; conviene repetir el análisis.", evidence, limitation)


def _tracking_evidence(dom: dict) -> tuple[list, list]:
    trackers = dom.get("trackers_before_consent") or []
    cookies = ((dom.get("cookies_before_consent") or {}).get("tracking")) or []
    return trackers, cookies


def _banner(dom: dict) -> dict:
    cat = "Banner de consentimiento de cookies"
    banner = dom.get("cookie_banner") or {}
    trackers, cookies = _tracking_evidence(dom)
    evidence = {
        "banner_detectado": banner.get("found"),
        "boton_aceptar": banner.get("has_accept"),
        "boton_rechazar": banner.get("has_reject"),
        "boton_configurar": banner.get("has_configure"),
        "plataforma_conocida": banner.get("known_cmp"),
        "texto_muestra": banner.get("text_sample"),
    }
    limitation = "La detección busca elementos visibles con texto sobre cookies; banners dentro de iframes o shadow DOM pueden no detectarse."
    if not banner.get("found"):
        if trackers or cookies:
            return _finding(cat, BRECHA, "alta",
                            "El sitio usa rastreadores o cookies de seguimiento, pero no se encontró un aviso que permita "
                            "aceptarlos o rechazarlos. Las personas deberían poder decidir antes de ser rastreadas.",
                            evidence, limitation)
        return _finding(cat, NO_APLICA, "info",
                        "No se detectó banner de cookies ni rastreadores conocidos. Si el sitio no usa cookies "
                        "opcionales, el banner podría no ser necesario.", evidence, limitation)
    if banner.get("has_reject") or banner.get("has_configure"):
        return _finding(cat, CUMPLE, "info",
                        "Se encontró un aviso de cookies con opción de rechazar o configurar, lo que permite a las "
                        "personas elegir.", evidence, limitation)
    return _finding(cat, ALERTA, "media",
                    "El aviso de cookies parece ofrecer solo la opción de aceptar. Para que la elección sea libre, "
                    "rechazar debería ser tan fácil como aceptar.", evidence, limitation)


def _trackers_before(dom: dict) -> dict:
    cat = "Rastreadores antes del consentimiento"
    trackers, cookies = _tracking_evidence(dom)
    evidence = {
        "rastreadores_detectados": trackers,
        "cookies_de_seguimiento": cookies,
        "version_lista_patrones": dom.get("tracker_list_version"),
    }
    limitation = "Solo se reconocen los proveedores incluidos en la lista documentada de patrones; otros rastreadores pueden pasar inadvertidos."
    if trackers or cookies:
        return _finding(cat, BRECHA, "alta",
                        "Antes de que la persona elija en el aviso de cookies, el sitio ya cargó servicios de analítica "
                        "o publicidad. Lo recomendable es activarlos solo después de obtener el consentimiento.",
                        evidence, limitation)
    return _finding(cat, CUMPLE, "info",
                    "No se observaron rastreadores conocidos ni cookies de seguimiento durante la carga inicial.",
                    evidence, limitation)


def _reject_respected(dom: dict) -> dict:
    cat = "Respeto del rechazo de cookies"
    interaction = dom.get("consent_interaction") or {}
    before = set(((dom.get("cookies_before_consent") or {}).get("tracking")) or [])
    after = set(((dom.get("cookies_after_reject") or {}).get("tracking")) or [])
    new_cookies = sorted(after - before)
    trackers_after = dom.get("trackers_after_reject") or []
    evidence = {
        "se_intento_rechazar": interaction.get("attempted"),
        "se_pulso_rechazar": interaction.get("clicked"),
        "rastreadores_despues_de_rechazar": trackers_after,
        "cookies_nuevas_despues_de_rechazar": new_cookies,
    }
    limitation = "Se observa solo un intervalo breve (unos segundos) después de pulsar 'Rechazar'."
    if not (dom.get("cookie_banner") or {}).get("found"):
        return _finding(cat, NO_APLICA, "info", "No hay banner de cookies sobre el cual probar el rechazo.", evidence, limitation)
    if not interaction.get("attempted"):
        return _finding(cat, NO_CONCLUYENTE, "media",
                        "No se encontró un botón de rechazo reconocible para probar si el sitio respeta esa elección.",
                        evidence, limitation)
    if not interaction.get("clicked"):
        return _finding(cat, NO_CONCLUYENTE, "media",
                        "No fue posible pulsar el botón de rechazo durante la prueba.", evidence, limitation)
    if trackers_after or new_cookies:
        return _finding(cat, BRECHA, "alta",
                        "Después de rechazar las cookies, el sitio siguió comunicándose con servicios de seguimiento. "
                        "Rechazar debería impedir que esos servicios se activen.", evidence, limitation)
    return _finding(cat, CUMPLE, "info",
                    "Tras pulsar 'Rechazar' no se observaron nuevas conexiones a rastreadores conocidos.",
                    evidence, limitation)


def _forms(dom: dict) -> dict:
    cat = "Formularios y consentimiento"
    forms = [f for f in (dom.get("forms") or []) if not f.get("is_search") and f.get("personal_fields", 0) > 0]
    evidence = {
        "formularios_totales": len(dom.get("forms") or []),
        "formularios_con_datos_personales": len(forms),
        "con_casilla_marcada_por_defecto": sum(1 for f in forms if f.get("consent_prechecked")),
        "sin_informacion_visible": sum(1 for f in forms if not (f.get("has_privacy_text") or f.get("links_to_policy") or f.get("consent_checkboxes"))),
        "envio_sin_cifrar": sum(1 for f in forms if f.get("action_scheme") == "http"),
    }
    limitation = ("No se envían formularios ni se evalúa la suficiencia jurídica de los textos; solo se observa si existe "
                  "información o casillas visibles. Formularios cargados en iframes externos pueden no analizarse.")
    if not forms:
        return _finding(cat, NO_APLICA, "info",
                        "No se encontraron formularios que soliciten datos personales en la página analizada.",
                        evidence, limitation)
    if evidence["envio_sin_cifrar"]:
        return _finding(cat, BRECHA, "alta",
                        "Al menos un formulario envía los datos por una conexión sin cifrar (http). Esa información "
                        "podría ser leída por terceros en tránsito.", evidence, limitation)
    if evidence["con_casilla_marcada_por_defecto"]:
        return _finding(cat, BRECHA, "media",
                        "Hay casillas de consentimiento que aparecen ya marcadas. El consentimiento debe ser una acción "
                        "de la persona, no una opción preseleccionada.", evidence, limitation)
    if evidence["sin_informacion_visible"]:
        return _finding(cat, ALERTA, "media",
                        "Algunos formularios piden datos personales sin mostrar información sobre su uso ni un enlace a "
                        "la política de privacidad. Conviene indicar para qué se usarán esos datos.", evidence, limitation)
    return _finding(cat, CUMPLE, "info",
                    "Los formularios que piden datos personales muestran información o una casilla sobre su uso.",
                    evidence, limitation)


def _whatsapp(dom: dict) -> dict:
    cat = "Canal WhatsApp"
    wa = dom.get("whatsapp") or {}
    evidence = {"elementos_detectados": wa.get("count", 0), "aviso_visible": wa.get("has_visible_notice")}
    limitation = "No se accede a conversaciones ni se verifican prácticas internas del proveedor o de la empresa."
    if not wa.get("count"):
        return _finding(cat, NO_APLICA, "info", "No se detectaron enlaces o botones de WhatsApp.", evidence, limitation)
    if wa.get("has_visible_notice"):
        return _finding(cat, CUMPLE, "info",
                        "Se detectó un canal de WhatsApp y un texto visible que relaciona ese canal con el tratamiento de datos.",
                        evidence, limitation)
    return _finding(cat, ALERTA, "baja",
                    "Hay un botón de WhatsApp, pero no se encontró un aviso sobre cómo se tratarán las conversaciones. "
                    "Conviene informarlo, por ejemplo en la política de privacidad.", evidence, limitation)


def _policy(dom: dict) -> dict:
    cat = "Política de privacidad"
    policy = dom.get("privacy_policy") or {}
    analysis = policy.get("analysis") or {}
    evidence = {
        "enlace": policy.get("url"),
        "texto_enlace": policy.get("link_text"),
        "contenido_leido": policy.get("fetched"),
        "fecha_actualizacion": analysis.get("update_date_text"),
        "organizacion_identificada": analysis.get("organization"),
        "menciona_ley_21719": analysis.get("mentions_law_21719"),
        "menciona_solo_ley_19628": bool(analysis.get("mentions_law_19628") and not analysis.get("mentions_law_21719")),
        "derechos_mencionados": analysis.get("rights_mentioned"),
        "correo_de_contacto": analysis.get("has_contact_email"),
    }
    limitation = ("Se extraen solo datos escritos de forma explícita. No se evalúa si el contenido es suficiente o "
                  "correcto desde el punto de vista jurídico.")
    if not policy.get("url"):
        return _finding(cat, BRECHA, "alta",
                        "No se encontró un enlace visible a una política de privacidad. Las personas deben poder "
                        "conocer quién trata sus datos, para qué y cómo ejercer sus derechos.", evidence, limitation)
    if not policy.get("fetched"):
        return _finding(cat, NO_CONCLUYENTE, "media",
                        "Se encontró un enlace a la política, pero no se pudo leer su contenido para revisarlo.",
                        evidence, limitation)
    gaps = []
    if not analysis.get("update_date_text"):
        gaps.append("no indica una fecha de actualización")
    if evidence["menciona_solo_ley_19628"]:
        gaps.append("menciona la Ley 19.628 pero no la Ley 21.719, por lo que podría estar desactualizada")
    if len(analysis.get("rights_mentioned") or []) < 3:
        gaps.append("menciona pocos derechos de las personas (acceso, rectificación, supresión, oposición, portabilidad)")
    if not analysis.get("has_contact_email"):
        gaps.append("no muestra un correo de contacto para consultas sobre datos")
    if gaps:
        return _finding(cat, ALERTA, "media",
                        "La política existe y se pudo leer, pero " + "; ".join(gaps) + ".", evidence, limitation)
    return _finding(cat, CUMPLE, "info",
                    "La política de privacidad es accesible e incluye fecha, derechos de las personas y un medio de contacto.",
                    evidence, limitation)


def _third_parties(dom: dict) -> dict:
    hosts = dom.get("third_party_hosts_before_consent") or []
    return _finding(
        "Recursos de terceros", INFORMATIVO, "info",
        f"Durante la carga inicial el navegador se conectó con {len(hosts)} dominio(s) externo(s). No todos son "
        "rastreadores (pueden ser fuentes tipográficas, mapas o CDN), pero cada uno recibe la dirección IP del visitante.",
        {"dominios": hosts[:40], "solicitudes_observadas": dom.get("requests_observed")},
        "Lista informativa; no se clasifica la finalidad de los dominios que no están en la lista de patrones.",
    )


def build_findings(tls: dict, dom: dict) -> tuple[list[dict], int]:
    findings = [
        _https(tls, dom),
        _policy(dom),
        _trackers_before(dom),
        _banner(dom),
        _reject_respected(dom),
        _forms(dom),
        _whatsapp(dom),
        _third_parties(dom),
    ]
    if dom.get("partial_load"):
        note = ("La página no terminó de cargar dentro del tiempo límite; el resultado se basa en lo que "
                "alcanzó a cargar y algunos elementos podrían no haberse detectado.")
        for f in findings:
            f["limitation"] = f"{f['limitation']} {note}" if f.get("limitation") else note
    applicable = [f for f in findings if f["status"] in STATUS_FACTOR and WEIGHTS.get(f["category"], 0) > 0]
    total = sum(WEIGHTS[f["category"]] for f in applicable)
    points = sum(WEIGHTS[f["category"]] * STATUS_FACTOR[f["status"]] for f in applicable)
    risk = round(100 * points / total) if total else 0
    return findings, max(0, min(100, risk))
