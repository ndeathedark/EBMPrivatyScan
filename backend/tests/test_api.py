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


def test_guest_sees_only_risk(client):
    data = guest_audit(client)
    assert data["access_token"]
    assert data["details_locked"] is True
    assert "findings" not in data
    assert isinstance(data["risk_percentage"], int)
    aid, token = data["id"], {"X-Audit-Token": data["access_token"]}
    assert client.get(f"/api/v1/audit/{aid}").status_code == 404                     # sin token: no expone el ID
    assert client.get(f"/api/v1/audit/{aid}", headers={"X-Audit-Token": "falso"}).status_code == 404
    assert "findings" not in client.get(f"/api/v1/audit/{aid}", headers=token).json()
    assert client.get(f"/api/v1/audit/{aid}/pdf", headers=token).status_code == 401
    r = client.post(f"/api/v1/audit/{aid}/email", json={"email": "x@empresa.cl"}, headers={**CSRF, **token})
    assert r.status_code == 401
    assert client.get("/api/v1/history").status_code == 401                            # historial ya no es público


def test_registered_user_sees_details(client):
    register(client, "dora@empresa.cl")
    data = guest_audit(client)
    assert data["details_locked"] is False
    assert data["findings"]
    pdf = client.get(f"/api/v1/audit/{data['id']}/pdf")
    assert pdf.content.startswith(b"%PDF")


def test_guest_can_claim_after_registering(client):
    data = guest_audit(client)
    register(client, "elisa@empresa.cl")
    token = {**CSRF, "X-Audit-Token": data["access_token"]}
    claimed = client.post(f"/api/v1/audit/{data['id']}/claim", headers=token)
    assert claimed.status_code == 200
    assert claimed.json()["findings"]
    assert client.get("/api/v1/history").json()["total"] == 1
    # Otra cuenta no puede reclamar el mismo análisis aunque conozca el token.
    client.post("/api/v1/auth/logout", headers=CSRF)
    client.cookies.clear()
    register(client, "fede@empresa.cl")
    assert client.post(f"/api/v1/audit/{data['id']}/claim", headers=token).status_code == 404


def test_claim_requires_login_and_token(client):
    data = guest_audit(client)
    assert client.post(f"/api/v1/audit/{data['id']}/claim",
                       headers={**CSRF, "X-Audit-Token": data["access_token"]}).status_code == 401
    register(client, "gabi@empresa.cl")
    assert client.post(f"/api/v1/audit/{data['id']}/claim", headers=CSRF).status_code == 404


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
    assert client.get("/api/v1/admin/audits").status_code == 403


def test_anonymous_cannot_use_admin(client):
    assert client.get("/api/v1/admin/audits").status_code == 401
    assert client.get("/api/v1/admin/sites").status_code == 401
    assert client.get("/api/v1/admin/stats").status_code == 401


def test_admin_can_see_all(client):
    with SessionLocal() as db:
        db.add(User(email="admin@admi.cl", password_hash=hash_password(STRONG), role="admin"))
        db.commit()
    guest_audit(client)
    r = client.post("/api/v1/auth/login", json={"email": "admin@admi.cl", "password": STRONG}, headers=CSRF)
    assert r.status_code == 200
    audits = client.get("/api/v1/admin/audits").json()
    assert audits["total"] >= 1
    assert audits["items"][0]["owner"] == "Invitado"
    assert audits["items"][0]["site"] == "ejemplo.cl"
    sites = client.get("/api/v1/admin/sites?q=EJEMPLO").json()
    assert sites["items"][0]["site"] == "ejemplo.cl"
    assert client.get("/api/v1/admin/sites?q=noexiste").json()["total"] == 0
    stats = client.get("/api/v1/admin/stats").json()
    assert stats["sites"] >= 1
    # El administrador sí ve el detalle de cualquier análisis.
    detail = client.get(f"/api/v1/audit/{audits['items'][0]['id']}").json()
    assert detail["details_locked"] is False


def test_login_rate_limit(client):
    codes = [client.post("/api/v1/auth/login", json={"email": "x@y.cl", "password": "Mala12345x"}, headers=CSRF).status_code
             for _ in range(12)]
    assert codes[0] == 401
    assert codes[-1] == 429


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
    register(client, "hugo@empresa.cl")
    data = guest_audit(client)
    r = client.post(f"/api/v1/audit/{data['id']}/email", json={"email": "destino@empresa.cl"}, headers=CSRF)
    assert r.status_code == 503


def test_retention_purge(client):
    data = guest_audit(client)
    with SessionLocal() as db:
        audit = db.get(AuditRecord, data["id"])
        audit.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        assert purge_expired(db) >= 1
        assert db.get(AuditRecord, data["id"]) is None


def test_admin_sees_users_and_full_history_without_passwords(client):
    with SessionLocal() as db:
        db.add(User(email="jefa@admi.cl", password_hash=hash_password(STRONG), role="admin"))
        db.commit()
    register(client, "ivan@empresa.cl")
    guest_audit(client)                                   # análisis de la cuenta de Iván
    client.post("/api/v1/auth/logout", headers=CSRF)
    client.cookies.clear()
    guest_audit(client)                                   # análisis de un invitado
    client.post("/api/v1/auth/login", json={"email": "jefa@admi.cl", "password": STRONG}, headers=CSRF)

    users = client.get("/api/v1/admin/users?q=ivan").json()
    assert users["total"] == 1
    ivan = users["items"][0]
    assert ivan["email"] == "ivan@empresa.cl"
    assert ivan["audits"] == 1
    assert "password" not in str(users).lower()          # nunca se expone la contraseña ni su hash
    assert "scrypt" not in str(users)

    history = client.get(f"/api/v1/admin/audits?owner={ivan['id']}").json()
    assert history["total"] == 1
    assert history["items"][0]["owner"] == "ivan@empresa.cl"
    by_email = client.get("/api/v1/admin/audits?q=ivan@empresa").json()
    assert by_email["total"] == 1
    guests = client.get("/api/v1/admin/audits?owner=guest").json()
    assert all(item["owner"] == "Invitado" for item in guests["items"])
    assert client.get("/api/v1/admin/audits?owner=1%20OR%201=1").status_code == 422


def test_regular_user_cannot_list_users(client):
    register(client, "juan@empresa.cl")
    assert client.get("/api/v1/admin/users").status_code == 403
