"""UI structure snapshots. These do NOT test visual appearance — they pin the
presence of essential form elements and labels in rendered HTML so that template
changes (CSRF fields, error display refactors) can't silently break the
user-visible form."""
import re

import pytest


# ── shared fixture ────────────────────────────────────────────────────────────

@pytest.fixture
def ui_client(monkeypatch, tmp_path, tmp_audit_dir):
    """Configure dashboard app with temp db/log paths and return a test client.

    Mirrors the pattern used in tests/test_dashboard_auth.py.
    """
    import os
    os.environ["GRCX_DB_PATH"] = str(tmp_path / "users.db")

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")
    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.init_db()
    app_module.app.config["TESTING"] = True
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", False)
    app_module.limiter.reset()

    return app_module.app.test_client()


# ── helper ────────────────────────────────────────────────────────────────────

def _html(resp) -> str:
    return resp.data.decode("utf-8")


# ── sign-in page ──────────────────────────────────────────────────────────────

def test_sign_in_page_has_email_and_password_inputs(ui_client):
    """GET /sign-in must render email and password inputs and a submit button."""
    resp = ui_client.get("/sign-in")
    assert resp.status_code == 200
    html = _html(resp)
    assert 'name="email"' in html, "sign-in form is missing name=\"email\" input"
    assert 'name="password"' in html, "sign-in form is missing name=\"password\" input"
    assert 'type="submit"' in html, "sign-in form is missing a submit button"


def test_sign_in_page_renders_error_when_set(ui_client):
    """POST /sign-in with wrong credentials must render the error message."""
    resp = ui_client.post(
        "/sign-in",
        data={"email": "nobody@nowhere.com", "password": "wrongpass"},
    )
    assert resp.status_code == 200
    html = _html(resp)
    assert "Invalid email or password." in html, (
        "Expected error text 'Invalid email or password.' not found in sign-in response"
    )


def test_sign_in_form_uses_post_method(ui_client):
    """GET /sign-in: the form element must declare method=\"post\" (case-insensitive)."""
    resp = ui_client.get("/sign-in")
    assert resp.status_code == 200
    html = _html(resp)
    # Look for <form ... method="post"> or method="POST"
    assert re.search(r'<form[^>]+method=["\']post["\']', html, re.IGNORECASE), (
        "sign-in <form> is missing method=\"post\""
    )


# ── sign-up page ──────────────────────────────────────────────────────────────

def test_sign_up_page_has_required_fields(ui_client):
    """GET /sign-up must render email, name, company, and password inputs."""
    resp = ui_client.get("/sign-up")
    assert resp.status_code == 200
    html = _html(resp)
    for field in ("email", "name", "company", "password"):
        assert f'name="{field}"' in html, (
            f"sign-up form is missing name=\"{field}\" input"
        )


def test_sign_up_page_renders_validation_errors(ui_client):
    """POST /sign-up with a too-short password must include a validation error
    mentioning the minimum character requirement."""
    resp = ui_client.post(
        "/sign-up",
        data={
            "email": "user@corp.com",
            "name": "Test User",
            "company": "TestCo",
            "password": "abc",  # too short
        },
    )
    assert resp.status_code == 200
    html = _html(resp)
    assert re.search(r"8 characters", html, re.IGNORECASE), (
        "Expected password-length validation message containing '8 characters' "
        f"but it was absent. Error area: "
        + ("".join(re.findall(r'class="error"[^>]*>.*?</div>', html, re.DOTALL)) or "(none)")
    )


def test_sign_up_form_uses_post_method(ui_client):
    """GET /sign-up: the form element must declare method=\"post\" (case-insensitive)."""
    resp = ui_client.get("/sign-up")
    assert resp.status_code == 200
    html = _html(resp)
    assert re.search(r'<form[^>]+method=["\']post["\']', html, re.IGNORECASE), (
        "sign-up <form> is missing method=\"post\""
    )


# ── dashboard (authenticated) ─────────────────────────────────────────────────

def test_dashboard_renders_for_logged_in_user(ui_client):
    """After sign-up and login, GET / should render the dashboard.

    The dashboard template does not embed the user's company name, so we pin
    on structural markers that are only present in the authenticated dashboard
    view: the 'Publications processed' stat label and the sign-out link.
    """
    # Sign up (also logs in automatically)
    sign_up_resp = ui_client.post(
        "/sign-up",
        data={
            "email": "dash@corp.com",
            "name": "Dashboard User",
            "company": "DashCorp",
            "password": "password123",
        },
    )
    assert sign_up_resp.status_code == 302, (
        f"Sign-up should redirect; got {sign_up_resp.status_code}"
    )

    resp = ui_client.get("/", follow_redirects=True)
    assert resp.status_code == 200
    html = _html(resp)

    # The dashboard stat cards always contain this label
    assert "Publications processed" in html, (
        "Expected 'Publications processed' label in dashboard HTML — "
        "may not be authenticated or template changed"
    )
    # The sign-out link is present in the header for all authenticated users
    assert "/sign-out" in html, (
        "Expected /sign-out link in dashboard HTML — user may not be authenticated"
    )
