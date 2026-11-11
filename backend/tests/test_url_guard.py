import pytest

from app.services.url_guard import UnsafeTargetError, registrable_domain, validate_public_url


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://0.0.0.0/", "http://intranet/", "http://servidor.local/", "ftp://ejemplo.cl/",
    "http://usuario:clave@93.184.215.14/", "http://93.184.215.14:22/", "http://100.64.0.1/",
])
def test_rejects_unsafe_targets(url):
    with pytest.raises(UnsafeTargetError):
        validate_public_url(url)


def test_accepts_public_ip_literal():
    result = validate_public_url("https://93.184.215.14/")
    assert result["addresses"] == ["93.184.215.14"]
    assert result["port"] == 443


def test_registrable_domain():
    assert registrable_domain("www.registrocivil.gob.cl") == "registrocivil.gob.cl"
    assert registrable_domain("static.admi.cl") == "admi.cl"
