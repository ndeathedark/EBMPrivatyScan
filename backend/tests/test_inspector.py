import asyncio
import socket
import ssl
import time

from app.services import dom_inspector
from app.services.dom_inspector import _Inspection, analyse_policy_text
from app.services.tls_check import _classify_error

TARGET = {"hostname": "ejemplo.cl", "addresses": ["93.184.215.14"]}


class FakeFrame:
    parent_frame = None


class FakeRequest:
    def __init__(self, url, resource_type="script", navigation=False):
        self.url = url
        self.resource_type = resource_type
        self._navigation = navigation
        self.frame = FakeFrame()

    def is_navigation_request(self):
        return self._navigation


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.action = None

    async def continue_(self):
        self.action = "continue"

    async def abort(self, *_args):
        self.action = "abort"


def run_route(inspection, request):
    route = FakeRoute(request)
    asyncio.run(inspection.handle_route(route))
    return route.action


def test_private_destination_is_blocked():
    inspection = _Inspection("https://ejemplo.cl", TARGET)
    assert run_route(inspection, FakeRequest("http://127.0.0.1/admin")) == "abort"
    assert inspection.blocked == ["127.0.0.1"]


def test_third_party_tracker_is_recorded(monkeypatch):
    monkeypatch.setattr(dom_inspector, "validate_public_url", lambda url: {})
    inspection = _Inspection("https://ejemplo.cl", TARGET)
    action = run_route(inspection, FakeRequest("https://www.googletagmanager.com/gtm.js"))
    assert action == "continue"
    assert inspection.trackers_in("load") == ["Google Tag Manager (gestor de etiquetas)"]


def test_images_are_recorded_but_not_downloaded(monkeypatch):
    monkeypatch.setattr(dom_inspector, "validate_public_url", lambda url: {})
    inspection = _Inspection("https://ejemplo.cl", TARGET)
    action = run_route(inspection, FakeRequest("https://www.facebook.com/tr?id=1", resource_type="image"))
    assert action == "abort"
    assert "www.facebook.com" in inspection.third_party_hosts("load")


def test_policy_regexes_are_fast_on_hostile_input():
    hostile = "a" * 20000 + "@" + "b." * 5000 + " " + "Palabra " * 3000
    start = time.perf_counter()
    analyse_policy_text(hostile)
    assert time.perf_counter() - start < 2


def test_policy_extracts_email_and_organization():
    result = analyse_policy_text("Responsable: Servicios Maule SpA. Escríbenos a datos@maule.cl")
    assert result["has_contact_email"]
    assert result["organization"] == "Servicios Maule SpA"


def test_tls_errors_are_never_success():
    assert _classify_error(ConnectionRefusedError())[0] == "no_https"
    assert _classify_error(socket.timeout())[0] == "timeout"
    assert _classify_error(ssl.SSLError())[0] == "invalid_certificate"
