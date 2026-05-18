# Tests for dashboard Flask auth routes
import pytest


@pytest.fixture
def app_client(monkeypatch, tmp_path, tmp_audit_dir):
    """Configure dashboard app with temp db/log paths and return a test client."""
    import os
    # DB_PATH is resolved at import time from env var; set before import
    os.environ["GRCX_DB_PATH"] = str(tmp_path / "users.db")

    import dashboard.app as app_module

    # Patch module-level attributes to the tmp paths
    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")

    # Re-init the db at the new path
    app_module.init_db()

    # Disable SMTP notifications
    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.app.config["TESTING"] = True
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", False)
    app_module.limiter.reset()

    client = app_module.app.test_client()
    return client


def _sign_up(client, email="test@corp.com", name="Test User", company="TestCo", password="password123"):
    return client.post("/sign-up", data={
        "email": email,
        "name": name,
        "company": company,
        "password": password,
    })


def test_sign_up_get_renders_form(app_client):
    resp = app_client.get("/sign-up")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "sign" in html.lower() or 'input' in html.lower()


def test_sign_up_creates_user_and_logs_in(app_client):
    resp = _sign_up(app_client)
    # Should redirect to dashboard
    assert resp.status_code == 302
    assert "/" in resp.headers.get("Location", "")

    # Follow redirect — should be 200 (user is logged in)
    resp2 = app_client.get("/", follow_redirects=True)
    assert resp2.status_code == 200


def test_sign_up_short_password_rejected(app_client):
    resp = _sign_up(app_client, password="abc")
    assert resp.status_code == 200
    html = resp.data.decode().lower()
    assert "8 characters" in html or "password" in html


def test_sign_up_missing_company_rejected(app_client):
    resp = _sign_up(app_client, company="")
    assert resp.status_code == 200
    html = resp.data.decode().lower()
    assert "company" in html


def test_sign_up_duplicate_email_rejected(app_client):
    # Create user first
    _sign_up(app_client, email="dup@corp.com")
    # Sign out
    app_client.get("/sign-out")
    # Try to create again with same email
    resp = _sign_up(app_client, email="dup@corp.com")
    assert resp.status_code == 200
    html = resp.data.decode().lower()
    assert "already exists" in html or "email" in html


def test_sign_in_with_valid_credentials(app_client):
    # Create user
    _sign_up(app_client, email="signin@corp.com", password="password123")
    # Sign out
    app_client.get("/sign-out")

    resp = app_client.post("/sign-in", data={
        "email": "signin@corp.com",
        "password": "password123",
    })
    assert resp.status_code == 302
    assert "/" in resp.headers.get("Location", "")


def test_sign_in_with_invalid_password_rejected(app_client):
    _sign_up(app_client, email="wrongpw@corp.com", password="correctpassword")
    app_client.get("/sign-out")

    resp = app_client.post("/sign-in", data={
        "email": "wrongpw@corp.com",
        "password": "wrongpassword",
    })
    assert resp.status_code == 200
    html = resp.data.decode().lower()
    assert "invalid" in html


def test_sign_out_requires_login_then_redirects(app_client):
    # Without login, should redirect to sign-in
    resp = app_client.get("/sign-out")
    assert resp.status_code == 302
    location = resp.headers.get("Location", "")
    assert "sign-in" in location

    # After login, sign-out should redirect to sign-in
    _sign_up(app_client, email="logout@corp.com")
    resp2 = app_client.get("/sign-out")
    assert resp2.status_code == 302
    location2 = resp2.headers.get("Location", "")
    assert "sign-in" in location2


def test_dashboard_requires_login(app_client):
    resp = app_client.get("/")
    assert resp.status_code == 302
    location = resp.headers.get("Location", "")
    assert "sign-in" in location
