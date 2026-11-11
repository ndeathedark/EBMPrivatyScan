import copy

from app.services.dom_inspector import analyse_policy_text
from app.services.rules import build_findings

from .conftest import FAKE_DOM, FAKE_TLS


def by_cat(findings):
    return {f["category"]: f for f in findings}


def test_findings_and_risk():
    findings, risk = build_findings(FAKE_TLS, FAKE_DOM)
    f = by_cat(findings)
    assert f["Conexión segura (HTTPS)"]["status"] == "CUMPLE"
    assert f["Rastreadores antes del consentimiento"]["status"] == "BRECHA"
    assert f["Banner de consentimiento de cookies"]["status"] == "ALERTA"
    assert f["Formularios y consentimiento"]["status"] == "BRECHA"      # casilla premarcada
    assert f["Política de privacidad"]["status"] == "BRECHA"
    assert f["Canal WhatsApp"]["status"] == "ALERTA"
    assert all(item["explanation"] for item in findings)
    assert all(item["limitation"] for item in findings)
    assert 0 < risk <= 100


def test_clean_site_has_low_risk():
    dom = copy.deepcopy(FAKE_DOM)
    dom.update({
        "cookie_banner": {"found": False}, "trackers_before_consent": [],
        "cookies_before_consent": {"total": 0, "tracking": [], "third_party_domains": []},
        "forms": [], "whatsapp": {"count": 0},
        "privacy_policy": {"url": "https://ejemplo.cl/privacidad", "fetched": True, "analysis": analyse_policy_text(
            "Política actualizada el 3 de marzo de 2026. Ley 21.719. Derechos de acceso, rectificación, "
            "supresión, oposición y portabilidad. Contacto: datos@ejemplo.cl")},
    })
    findings, risk = build_findings(FAKE_TLS, dom)
    assert risk == 0
    assert by_cat(findings)["Política de privacidad"]["status"] == "CUMPLE"


def test_connection_error_is_not_success():
    findings, _ = build_findings({"state": "timeout", "detail": "x"}, FAKE_DOM)
    assert by_cat(findings)["Conexión segura (HTTPS)"]["status"] == "NO_CONCLUYENTE"


def test_policy_analysis_detects_outdated_law():
    a = analyse_policy_text("Conforme a la Ley 19.628, Comercial Sur SpA trata sus datos.")
    assert a["mentions_law_19628"]
    assert not a["mentions_law_21719"]
    assert a["organization"]
    assert a["organization"].endswith("SpA")


def test_partial_load_is_reported_as_limitation():
    dom = copy.deepcopy(FAKE_DOM)
    dom["partial_load"] = True
    findings, _ = build_findings(FAKE_TLS, dom)
    assert all("no terminó de cargar" in f["limitation"] for f in findings)
