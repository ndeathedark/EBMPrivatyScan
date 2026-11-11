import os
import sys
import tempfile
from pathlib import Path

import pytest

_DB_DIR = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_DIR}/test.db"
os.environ["APP_ENV"] = "test"
os.environ["SECRET_KEY"] = "clave-de-pruebas-solo-para-tests-0123456789"
os.environ["AUDIT_RATE_PER_HOUR"] = "1000"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.routers import audits as audits_router  # noqa: E402
from app.security import rate_limiter  # noqa: E402

CSRF = {"X-Requested-With": "EBMPrivatyScan"}

FAKE_TARGET = {"url": "https://ejemplo.cl/", "scheme": "https", "hostname": "ejemplo.cl", "port": 443,
               "addresses": ["93.184.215.14"]}
FAKE_TLS = {"state": "valid", "detail": "ok", "tls_version": "TLSv1.3", "issuer": "Test CA",
            "not_after": "2027-01-01T00:00:00+00:00", "days_to_expiry": 200, "checked_address": "93.184.215.14"}
FAKE_DOM = {
    "final_url": "https://ejemplo.cl/", "redirects": [], "hsts_header": "max-age=31536000",
    "requests_observed": 40, "blocked_non_public_hosts": [],
    "cookie_banner": {"found": True, "has_accept": True, "has_reject": False, "has_configure": False,
                      "known_cmp": None, "text_sample": "usamos cookies"},
    "consent_interaction": {"attempted": False, "clicked": False, "error": None},
    "cookies_before_consent": {"total": 3, "tracking": ["_ga (Google Analytics)"], "third_party_domains": []},
    "cookies_after_reject": None,
    "third_party_hosts_before_consent": ["www.googletagmanager.com"],
    "trackers_before_consent": ["Google Tag Manager (gestor de etiquetas)"],
    "trackers_after_reject": [], "tracker_list_version": "test",
    "forms": [{"personal_fields": 3, "has_password": False, "checkboxes": 1, "consent_checkboxes": 1,
               "consent_prechecked": True, "has_privacy_text": True, "links_to_policy": False,
               "method": "post", "action_scheme": "https", "is_search": False}],
    "whatsapp": {"count": 1, "has_visible_notice": False},
    "privacy_policy": {"url": None, "link_text": None, "fetched": False, "error": None, "analysis": None},
}


@pytest.fixture(autouse=True)
def _mock_network(monkeypatch):
    async def fake_dom(url, target):
        return FAKE_DOM

    def fake_validate(url, resolve=True):
        from app.services.url_guard import validate_public_url
        if "ejemplo.cl" in url:
            return FAKE_TARGET
        return validate_public_url(url, resolve=resolve)

    monkeypatch.setattr(audits_router.dom_inspector, "inspect_website_dom", fake_dom)
    monkeypatch.setattr(audits_router, "check_tls", lambda *a, **k: FAKE_TLS)
    monkeypatch.setattr(audits_router, "validate_public_url", fake_validate)
    rate_limiter.reset()


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c
