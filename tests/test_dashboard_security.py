# Tests for web-app security: SQL injection, XSS, and session hardening.
import json
import os
import sqlite3

import pytest


# ---------------------------------------------------------------------------
# Fixture: shared test client (mirrors test_dashboard_auth.py pattern)
# ---------------------------------------------------------------------------

@pytest.fixture
def app_env(monkeypatch, tmp_path, tmp_audit_dir):
    """Return (client, db_path, log_path) with a fresh in-memory-equivalent setup."""
    db_path = tmp_path / "users.db"
    log_path = tmp_audit_dir / "grcx.log.jsonl"

    os.environ["GRCX_DB_PATH"] = str(db_path)

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", db_path)
    monkeypatch.setattr(app_module, "LOG_PATH", log_path)
    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.init_db()

    app_module.app.config["TESTING"] = True
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", False)
    app_module.limiter.reset()

    client = app_module.app.test_client()
    return client, db_path, log_path


def _sign_up(client, email="test@corp.com", name="Test User", company="TestCo", password="password123"):
    return client.post("/sign-up", data={
        "email": email,
        "name": name,
        "company": company,
        "password": password,
    })


# ---------------------------------------------------------------------------
# SQL injection tests
# ---------------------------------------------------------------------------

def test_signup_email_with_sql_injection_safely_stored(app_env):
    """Parametrised INSERT must survive a classic injection in the email field."""
    client, db_path, _ = app_env
    evil_email = "x@y.com'; DROP TABLE users; --"
    resp = _sign_up(client, email=evil_email)
    # Either a redirect (accepted) or 200 (rejected by validation) — not a 500.
    assert resp.status_code in (200, 302)

    # The users table MUST still exist.
    conn = sqlite3.connect(str(db_path))
    count = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()[0]
    conn.close()
    assert count == 1, "users table was dropped — SQL injection succeeded"


def test_signup_email_with_apostrophes_stored_correctly(app_env):
    """Apostrophes are legal in email local-parts and must survive a round-trip."""
    client, db_path, _ = app_env
    email = "o'brien@example.com"
    resp = _sign_up(client, email=email)
    assert resp.status_code == 302, "expected sign-up to succeed"

    # Sign out then sign back in with the apostrophe email.
    client.get("/sign-out")
    resp2 = client.post("/sign-in", data={"email": email, "password": "password123"})
    assert resp2.status_code == 302, "sign-in with apostrophe email should succeed"


def test_signup_company_with_sql_string_terminator(app_env):
    """Company field with embedded SQL string terminators must be stored verbatim."""
    client, db_path, _ = app_env
    evil_company = "Acme', '', '', 'pwned"
    resp = _sign_up(client, email="victim@example.com", company=evil_company)
    assert resp.status_code == 302

    conn = sqlite3.connect(str(db_path))
    row = conn.execute(
        "SELECT company FROM users WHERE email = ?", ("victim@example.com",)
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == evil_company, f"company stored as '{row[0]}', expected verbatim value"


def test_signup_password_hashed_not_stored_plaintext(app_env):
    """Passwords must be stored as a werkzeug hash, never plaintext."""
    client, db_path, _ = app_env
    plaintext = "mySecret123"
    _sign_up(client, email="hashcheck@example.com", password=plaintext)

    conn = sqlite3.connect(str(db_path))
    row = conn.execute(
        "SELECT password_hash FROM users WHERE email = ?", ("hashcheck@example.com",)
    ).fetchone()
    conn.close()
    assert row is not None
    pw_hash = row[0]
    assert pw_hash != plaintext, "password was stored in plaintext"
    # werkzeug hashes begin with the algorithm name
    assert pw_hash.startswith("scrypt:") or pw_hash.startswith("pbkdf2:"), (
        f"unexpected hash prefix: {pw_hash[:20]}"
    )


# ---------------------------------------------------------------------------
# XSS / output-encoding tests
# ---------------------------------------------------------------------------

def _write_log_entry(log_path, entry: dict):
    """Append a raw JSON entry to the audit log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _get_dashboard_html(client, app_env_tuple):
    """Sign up, log in, and return the dashboard HTML."""
    client_obj, db_path, log_path = app_env_tuple
    _sign_up(client_obj, email="xss_tester@example.com")
    resp = client_obj.get("/", follow_redirects=True)
    assert resp.status_code == 200
    return resp.data.decode("utf-8")


def test_dashboard_renders_xss_title_escaped(app_env):
    """Script tags in publication titles must be HTML-escaped by Jinja2."""
    client, db_path, log_path = app_env

    xss_title = "<script>alert(1)</script>"
    entry = {
        "id": "test-xss-title",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "regulatory.new_publication",
        "severity": "info",
        "summary": xss_title,
        "jurisdiction": "TEST",
        "source": "https://example.com",
        "detail": {
            "fingerprint": "abcdef0123456789",
            "published": "2026-01-01",
            "summary": "test",
        },
        "prev_hash": "genesis",
        "entry_hash": "test",
    }
    _write_log_entry(log_path, entry)

    html = _get_dashboard_html(client, (client, db_path, log_path))
    assert "&lt;script&gt;" in html or "&#x3C;script&#x3E;" in html, (
        "XSS payload in title was not escaped"
    )
    assert "<script>alert" not in html, "raw <script> tag present — XSS vulnerability"


def test_dashboard_renders_xss_in_recommended_action_escaped(app_env):
    """HTML in recommended_action must be escaped, not rendered raw."""
    client, db_path, log_path = app_env

    xss_action = "<img src=x onerror=alert(1)>"
    pub_fp = "deadbeef12345678"

    pub_entry = {
        "id": "pub-xss-action",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "regulatory.new_publication",
        "severity": "info",
        "summary": "XSS action test publication",
        "jurisdiction": "TEST",
        "source": "https://example.com",
        "detail": {
            "fingerprint": pub_fp,
            "published": "2026-01-01",
            "summary": "test",
        },
        "prev_hash": "genesis",
        "entry_hash": "test-pub",
    }
    assessment_entry = {
        "id": "asm-xss-action",
        "timestamp": "2026-01-01T00:01:00+00:00",
        "event_type": "resolver.assessment",
        "severity": "warning",
        "summary": "XSS action assessment",
        "jurisdiction": "TEST",
        "source": "https://example.com",
        "detail": {
            "fingerprint": pub_fp,
            "framework": "iso27001",
            "affected_controls": ["5.1"],
            "recommended_action": xss_action,
            "rationale": "test rationale",
            "publication_title": "XSS action test publication",
        },
        "prev_hash": "test-pub",
        "entry_hash": "test-asm",
    }
    _write_log_entry(log_path, pub_entry)
    _write_log_entry(log_path, assessment_entry)

    html = _get_dashboard_html(client, (client, db_path, log_path))
    assert "&lt;img" in html or "&#x3C;img" in html, (
        "XSS payload in recommended_action was not escaped"
    )
    assert "<img src=x onerror=" not in html, "raw <img onerror=> present — XSS vulnerability"


def test_dashboard_renders_unicode_title_correctly(app_env):
    """Unicode characters in titles must render without mojibake."""
    client, db_path, log_path = app_env

    unicode_title = "Reglement EUR 1M — Basel III Update"
    entry = {
        "id": "test-unicode-title",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "regulatory.new_publication",
        "severity": "info",
        "summary": unicode_title,
        "jurisdiction": "TEST",
        "source": "https://example.com",
        "detail": {
            "fingerprint": "unicode0123456789",
            "published": "2026-01-01",
            "summary": "unicode test",
        },
        "prev_hash": "genesis",
        "entry_hash": "unicode-test",
    }
    _write_log_entry(log_path, entry)

    html = _get_dashboard_html(client, (client, db_path, log_path))
    # Either the literal string is present or Jinja2 HTML-entity encoded it —
    # both are acceptable; what is not acceptable is missing content or garbled bytes.
    assert "Reglement" in html, "unicode title not found in dashboard output"
    assert "1M" in html, "title suffix not found"
    # Check that the response was decoded without encoding errors (no replacement chars)
    assert "�" not in html, "unicode replacement character present — possible mojibake"


# ---------------------------------------------------------------------------
# Session / cookie tests
# ---------------------------------------------------------------------------

def test_session_cookie_marked_httponly(app_env):
    """Flask session cookie must be HttpOnly to prevent JS access."""
    client, db_path, log_path = app_env
    resp = _sign_up(client, email="cookie_test@example.com")
    assert resp.status_code == 302

    # The Set-Cookie header for the session cookie should include HttpOnly.
    set_cookie_headers = resp.headers.getlist("Set-Cookie")
    session_cookies = [h for h in set_cookie_headers if "session" in h.lower()]
    assert session_cookies, "No session cookie found in sign-up response"

    for cookie_header in session_cookies:
        assert "HttpOnly" in cookie_header or "httponly" in cookie_header.lower(), (
            f"Session cookie missing HttpOnly flag: {cookie_header}"
        )
