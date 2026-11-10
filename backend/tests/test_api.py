from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models.audit import AuditRecord, User
from app.security import hash_password
from app.services.retention import purge_expired

from .conftest import CSRF

AUDIT = {"url": "https://ejemplo.cl", "authorized": True}
STRONG = "ClaveSegura2026"


def guest_audit(client):
    r = client.post("/api/v1/audit/quick", json=AUDIT, headers=CSRF)
    assert r.status_code == 200, r.text
    return r.json()


def register(client, email):
    r = client.post("/api/v1/auth/register", json={"email": email, "password": STRONG, "accept_privacy": True},
                    headers=CSRF)
    assert r.status_code == 201, r.text


def test_csrf_header_required(client):
    assert client.post("/api/v1/audit/quick", json=AUDIT).status_code == 403


def test_authorization_declaration_required(client):
    r = client.post("/api/v1/audit/quick", json={"url": "https://ejemplo.cl"}, headers=CSRF)
    assert r.status_code == 400


def test_invalid_and_private_urls(client):
    assert client.post("/api/v1/audit/quick", json={"url": "not-a-url", "authorized": True}, headers=CSRF).status_code == 422
    r = client.post("/api/v1/audit/quick", json={"url": "http://127.0.0.1/", "authorized": True}, headers=CSRF)
    assert r.status_code == 400


def test_guest_report_requires_token(client):
    data = guest_audit(client)
    assert data["access_token"] and data["findings"]
    aid = data["id"]
    assert client.get(f"/api/v1/audit/{aid}").status_code == 404                     # sin token: no expone el ID
    assert client.get(f"/api/v1/audit/{aid}", headers={"X-Audit-Token": "falso"}).status_code == 404
    ok = client.get(f"/api/v1/audit/{aid}/pdf", headers={"X-Audit-Token": data["access_token"]})
    assert ok.status_code == 200 and ok.content.startswith(b"%PDF")
    assert client.get("/api/v1/history").status_code == 401                            # historial ya no es público


def test_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_weak_password_and_missing_consent(client):
    r = client.post("/api/v1/auth/register", json={"email": "a@b.cl", "password": "123", "accept_privacy": True}, headers=CSRF)
    assert r.status_code == 400
    r = client.post("/api/v1/auth/register", json={"email": "a@b.cl", "password": STRONG}, headers=CSRF)
    assert r.status_code == 400


def test_history_is_private_per_account(client):
    register(client, "ana@empresa.cl")
    mine = guest_audit(client)                               # con sesión: queda asociada a Ana
    assert client.get("/api/v1/history").json()["total"] == 1
    session_cookie = client.cookies.get("ebm_session")
    assert session_cookie
    client.post("/api/v1/auth/logout", headers=CSRF)
    client.cookies.clear()

    register(client, "bruno@empresa.cl")
    assert client.get("/api/v1/history").json()["total"] == 0
    assert client.get(f"/api/v1/audit/{mine['id']}").status_code == 404                # sin acceso cruzado
    assert client.get("/api/v1/history?scope=all").status_code == 403


def test_admin_can_see_all(client):
    with SessionLocal() as db:
        db.add(User(email="admin@admi.cl", password_hash=hash_password(STRONG), role="admin"))
        db.commit()
    guest_audit(client)
    r = client.post("/api/v1/auth/login", json={"email": "admin@admi.cl", "password": STRONG}, headers=CSRF)
    assert r.status_code == 200
    assert client.get("/api/v1/history?scope=all").json()["total"] >= 1


def test_login_rate_limit(client):
    codes = [client.post("/api/v1/auth/login", json={"email": "x@y.cl", "password": "Mala12345x"}, headers=CSRF).status_code
             for _ in range(12)]
    assert codes[0] == 401 and codes[-1] == 429


def test_delete_audit_and_account(client):
    register(client, "carla@empresa.cl")
    data = guest_audit(client)
    assert client.delete(f"/api/v1/audit/{data['id']}", headers=CSRF).status_code == 200
    guest_audit(client)
    r = client.request("DELETE", "/api/v1/auth/me", json={"password": STRONG}, headers=CSRF)
    assert r.status_code == 200
    with SessionLocal() as db:
        assert db.query(User).filter(User.email == "carla@empresa.cl").first() is None


def test_email_not_configured_is_reported(client):
    data = guest_audit(client)
    r = client.post(f"/api/v1/audit/{data['id']}/email", json={"email": "destino@empresa.cl"},
                    headers={**CSRF, "X-Audit-Token": data["access_token"]})
    assert r.status_code == 503


def test_retention_purge(client):
    data = guest_audit(client)
    with SessionLocal() as db:
        audit = db.get(AuditRecord, data["id"])
        audit.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        assert purge_expired(db) >= 1
        assert db.get(AuditRecord, data["id"]) is None
