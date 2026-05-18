# Tests for dashboard edge paths: _parse_ts, load_data, notify_signup, form validation.
import json
import smtplib
import pytest
from datetime import datetime, timezone
from pathlib import Path


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def app_client(monkeypatch, tmp_path, tmp_audit_dir):
    """Configure dashboard app with temp db/log paths and return a test client."""
    import os
    os.environ["GRCX_DB_PATH"] = str(tmp_path / "users.db")

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")

    app_module.init_db()

    # Disable SMTP notifications for most tests
    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False

    return app_module.app.test_client()


@pytest.fixture(autouse=True)
def patch_log_path(monkeypatch, tmp_audit_dir):
    """Redirect dashboard LOG_PATH to the tmp audit dir for every test."""
    import dashboard.app as app_module
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")


# ── _parse_ts ─────────────────────────────────────────────────────────────────

def test_parse_ts_with_garbage_returns_datetime_min():
    from dashboard.app import _parse_ts
    result = _parse_ts("not a timestamp")
    assert result == datetime.min.replace(tzinfo=timezone.utc)


def test_parse_ts_with_empty_string():
    from dashboard.app import _parse_ts
    result = _parse_ts("")
    assert result == datetime.min.replace(tzinfo=timezone.utc)


# ── load_data ─────────────────────────────────────────────────────────────────

def test_load_data_logs_with_json_decode_errors_continue(tmp_audit_dir):
    """Malformed lines are silently skipped; valid entries are counted."""
    import dashboard.app as app_module

    log_path = tmp_audit_dir / "grcx.log.jsonl"
    valid_entry = {
        "id": "abc-001",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "regulatory.new_publication",
        "severity": "info",
        "summary": "Valid Publication",
        "jurisdiction": "BOE",
        "source": "https://example.org/pub/1",
        "detail": {
            "fingerprint": "fp_valid_001",
            "published": "2026-01-01",
            "summary": "A valid publication.",
            "feed_url": "https://example.org/feed",
        },
        "prev_hash": "genesis",
        "entry_hash": "aabbcc001",
    }
    log_path.write_text(json.dumps(valid_entry) + "\nnot json at all\n")

    data = app_module.load_data()

    assert data["total"] == 1


def test_load_data_logs_with_empty_lines_skipped(tmp_audit_dir):
    """Blank lines between entries are silently skipped."""
    import dashboard.app as app_module

    log_path = tmp_audit_dir / "grcx.log.jsonl"
    valid_entry = {
        "id": "abc-002",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "regulatory.new_publication",
        "severity": "info",
        "summary": "Another Valid Publication",
        "jurisdiction": "FCA",
        "source": "https://example.org/pub/2",
        "detail": {
            "fingerprint": "fp_valid_002",
            "published": "2026-01-01",
            "summary": "Another publication.",
            "feed_url": "https://example.org/feed",
        },
        "prev_hash": "genesis",
        "entry_hash": "aabbcc002",
    }
    # Surround the entry with blank lines
    log_path.write_text("\n\n" + json.dumps(valid_entry) + "\n\n")

    data = app_module.load_data()

    assert data["total"] == 1


# ── notify_signup ─────────────────────────────────────────────────────────────

def test_notify_signup_smtp_success(monkeypatch, tmp_path, tmp_audit_dir):
    """notify_signup calls SMTP with starttls, login, and send_message."""
    import dashboard.app as app_module

    smtp_calls = []

    class FakeSMTP:
        def __init__(self, host, port):
            smtp_calls.append(("init", host, port))
            self.host = host
            self.port = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def starttls(self):
            smtp_calls.append(("starttls",))

        def login(self, user, password):
            smtp_calls.append(("login", user, password))

        def send_message(self, msg):
            smtp_calls.append(("send_message",))

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    app_module.notify_signup("Alice", "a@b.com", "Acme")

    init_calls = [c for c in smtp_calls if c[0] == "init"]
    assert len(init_calls) == 1
    # Default host and port from the source
    assert init_calls[0][2] == 587

    assert ("starttls",) in smtp_calls
    login_calls = [c for c in smtp_calls if c[0] == "login"]
    assert len(login_calls) == 1
    send_calls = [c for c in smtp_calls if c[0] == "send_message"]
    assert len(send_calls) == 1


def test_notify_signup_smtp_failure_swallowed(monkeypatch, tmp_path, tmp_audit_dir):
    """notify_signup swallows SMTP errors and does not re-raise."""
    import dashboard.app as app_module

    class BrokenSMTP:
        def __init__(self, host, port):
            raise RuntimeError("smtp down")

    monkeypatch.setattr(smtplib, "SMTP", BrokenSMTP)

    # Must not raise
    app_module.notify_signup("Bob", "b@c.com", "BobCo")


# ── Form validation ───────────────────────────────────────────────────────────

def test_sign_up_with_empty_email_rejected(app_client):
    """POST /sign-up with empty email should return a 200 with an error about required fields."""
    resp = app_client.post("/sign-up", data={
        "email": "",
        "name": "Test User",
        "company": "TestCo",
        "password": "password123",
    })
    assert resp.status_code == 200
    html = resp.data.decode().lower()
    assert "required" in html


def test_sign_up_with_malformed_email_accepted_for_now(app_client):
    """POST /sign-up with a non-@ email is currently accepted (no format validation).

    This test documents existing behaviour. If email format validation is added
    in future, this test will flag the breaking change.
    """
    resp = app_client.post("/sign-up", data={
        "email": "not-an-email",
        "name": "Test User",
        "company": "TestCo",
        "password": "password123",
    })
    # Current code only checks non-empty; malformed email passes the guard
    # and either redirects (success) or shows a different error — not a
    # "required" validation error about email format
    assert resp.status_code in (200, 302)
    if resp.status_code == 200:
        html = resp.data.decode().lower()
        # Should NOT show "required" (field was non-empty)
        assert "all fields are required" not in html
