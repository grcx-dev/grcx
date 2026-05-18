"""
These tests assert the post-fix target state of security findings in SECURITY_REVIEW.md.
Each is marked xfail(strict=True) so the suite stays green today but tests automatically
flip to XPASS when a fix lands, signalling the xfail marker should be removed.

Finding references are to the numbered findings in SECURITY_REVIEW.md.
"""
import importlib
import os

import pytest


# ---------------------------------------------------------------------------
# Shared test-client fixture (mirrors test_dashboard_auth.py setup)
# ---------------------------------------------------------------------------

@pytest.fixture
def security_app_client(monkeypatch, tmp_path, tmp_audit_dir):
    """
    Dashboard test client with temp DB and log paths.

    Intentionally does NOT set WTF_CSRF_ENABLED=False, so CSRF tests reflect
    real post-fix behaviour (the CSRF-related tests handle this themselves).
    """
    os.environ["GRCX_DB_PATH"] = str(tmp_path / "users.db")

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")

    app_module.init_db()

    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.app.config["TESTING"] = True
    # Explicitly enable CSRF — guard against earlier tests leaving it disabled.
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", True)

    return app_module.app.test_client()


@pytest.fixture
def csrf_disabled_app_client(monkeypatch, tmp_path, tmp_audit_dir):
    """
    Dashboard test client with CSRF disabled — for rate-limiting and cookie tests
    that need to successfully submit forms to set up state, not test CSRF.
    """
    os.environ["GRCX_DB_PATH"] = str(tmp_path / "users.db")

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(app_module, "LOG_PATH", tmp_audit_dir / "grcx.log.jsonl")

    app_module.init_db()

    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.app.config["TESTING"] = True
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", False)

    return app_module.app.test_client()


# ===========================================================================
# Section 1: FLASK_SECRET_KEY fail-closed (finding #1)
# ===========================================================================

def test_dashboard_refuses_to_load_without_secret_key(monkeypatch):
    """
    After the fix: importing/reloading dashboard.app without FLASK_SECRET_KEY in
    the environment must raise RuntimeError (fail-closed).

    Today: the module falls back to a known-public default string and starts
    normally, which means any attacker who read the source can forge sessions.
    """
    # Pre-cache the module before removing the env var, then reload without it
    import dashboard.app as app_module  # noqa: F401 — ensures module is in sys.modules
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

    with pytest.raises((RuntimeError, SystemExit)):
        importlib.reload(app_module)

    # The failed reload partially re-executed the module, creating a new Flask
    # app object before the RuntimeError fired — that object has no routes.
    # Restore the module to a healthy state so subsequent tests see a working app.
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-key-not-for-production")
    importlib.reload(app_module)


# ===========================================================================
# Section 2: CSRF protection (finding #2)
# ===========================================================================

def test_signup_post_without_csrf_token_rejected(security_app_client):
    """
    POST /sign-up without a CSRF token must be rejected with 400 or 403.
    Flask-WTF CSRFProtect returns 400 by default.
    """
    resp = security_app_client.post("/sign-up", data={
        "email": "attacker@evil.com",
        "name": "Attacker",
        "company": "EvilCorp",
        "password": "password123",
        # csrf_token is intentionally absent
    })
    assert resp.status_code in (400, 403), (
        f"Expected 400 or 403 when no CSRF token is sent, got {resp.status_code}"
    )


def test_signin_post_without_csrf_token_rejected(security_app_client):
    """
    POST /sign-in without a CSRF token must be rejected with 400 or 403.
    """
    resp = security_app_client.post("/sign-in", data={
        "email": "user@corp.com",
        "password": "somepassword",
        # csrf_token is intentionally absent
    })
    assert resp.status_code in (400, 403), (
        f"Expected 400 or 403 when no CSRF token is sent, got {resp.status_code}"
    )


# ===========================================================================
# Section 3: SSRF blocking (finding #3)
# ===========================================================================

def _make_httpx_mock(monkeypatch, html="<title>Test Page</title>"):
    """
    Patch httpx.get in the imap_email module to return a controlled response,
    preventing real outbound network requests during tests.
    """
    class _FakeResponse:
        status_code = 200
        text = html

        def raise_for_status(self):
            pass

    def _fake_get(url, **kwargs):
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _fake_get)
    return _fake_get


@pytest.mark.xfail(strict=True, reason="Pending fix: #3 SSRF via fetch_page_title — AWS metadata URL 169.254.169.254 should be blocked")
def test_fetch_page_title_blocks_aws_metadata(monkeypatch):
    """
    After the fix: fetch_page_title must return None (or raise a security
    exception) for the AWS/GCP/Azure instance-metadata IP without making a
    real HTTP request.

    httpx is mocked so this test doesn't trigger a real outbound request even
    today (before the fix). We assert that the SSRF check fires *before* httpx
    is called — i.e., the function must refuse the URL at the validation layer.
    """
    blocked_urls = []

    class _FakeResponse:
        status_code = 200
        text = "<title>AWS METADATA LEAKED</title>"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        blocked_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("http://169.254.169.254/latest/meta-data/")

    # After fix: the function must return None (blocked) without calling httpx.get
    assert result is None, f"Expected None for blocked SSRF URL, got: {result!r}"
    assert len(blocked_urls) == 0, (
        "httpx.get was called for a blocked SSRF URL — SSRF protection is not in place"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: #3 SSRF via fetch_page_title — localhost URL should be blocked")
def test_fetch_page_title_blocks_localhost(monkeypatch):
    """
    After the fix: fetch_page_title must return None for localhost URLs and
    must not call httpx.get.
    """
    blocked_urls = []

    class _FakeResponse:
        status_code = 200
        text = "<title>Internal Admin Panel</title>"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        blocked_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("http://127.0.0.1:8080/admin")

    assert result is None, f"Expected None for blocked localhost URL, got: {result!r}"
    assert len(blocked_urls) == 0, (
        "httpx.get was called for a localhost URL — SSRF protection is not in place"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: #3 SSRF via fetch_page_title — private 192.168.x.x URL should be blocked")
def test_fetch_page_title_blocks_private_192_168(monkeypatch):
    """
    After the fix: fetch_page_title must return None for private RFC-1918
    addresses (192.168.0.0/16) without calling httpx.get.
    """
    blocked_urls = []

    class _FakeResponse:
        status_code = 200
        text = "<title>Router Admin</title>"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        blocked_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("http://192.168.1.1/")

    assert result is None, f"Expected None for blocked private-IP URL, got: {result!r}"
    assert len(blocked_urls) == 0, (
        "httpx.get was called for a private 192.168.x.x URL — SSRF protection not in place"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: #3 SSRF via fetch_page_title — link-local 169.254.x.x URL should be blocked")
def test_fetch_page_title_blocks_link_local(monkeypatch):
    """
    After the fix: fetch_page_title must return None for any 169.254.0.0/16
    address (link-local range; includes all cloud metadata endpoints).
    """
    blocked_urls = []

    class _FakeResponse:
        status_code = 200
        text = "<title>Link-local resource</title>"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        blocked_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("http://169.254.1.1/")

    assert result is None, f"Expected None for blocked link-local URL, got: {result!r}"
    assert len(blocked_urls) == 0, (
        "httpx.get was called for a 169.254.x.x link-local URL — SSRF protection not in place"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: #3 SSRF via fetch_page_title — file:// scheme should be blocked before httpx call")
def test_fetch_page_title_blocks_file_scheme(monkeypatch):
    """
    After the fix: fetch_page_title must return None for file:// URIs and must
    not attempt to pass them to httpx (which would read local files).
    """
    blocked_urls = []

    class _FakeResponse:
        status_code = 200
        text = "root:x:0:0:root:/root:/bin/bash"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        blocked_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("file:///etc/passwd")

    assert result is None, f"Expected None for file:// URL, got: {result!r}"
    assert len(blocked_urls) == 0, (
        "httpx.get was called for a file:// URL — scheme blocking is not in place"
    )


def test_fetch_page_title_allows_known_regulator(monkeypatch):
    """
    Confirms that a legitimate regulator URL (Bank of England) is NOT blocked.
    The function should proceed to call httpx.get and return a title.

    This test must pass both today AND after the SSRF fix is applied.
    DO NOT mark xfail — this guards against an overly-aggressive allowlist.
    """
    call_log = []

    class _FakeResponse:
        status_code = 200
        text = "<title>Supervisory Statement | Bank of England</title>"

        def raise_for_status(self):
            pass

    def _spy_get(url, **kwargs):
        call_log.append(url)
        return _FakeResponse()

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.httpx.get", _spy_get)

    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    result = fetch_page_title("https://www.bankofengland.co.uk/some/path")

    # httpx.get should have been called (legitimate domain not blocked)
    assert len(call_log) == 1, (
        f"Expected httpx.get to be called for a regulator URL, "
        f"but it was called {len(call_log)} time(s)"
    )
    # Should have extracted a title from the mock response
    assert result is not None, "Expected a title to be returned for a known-good regulator URL"


# ===========================================================================
# Section 4: Rate limiting (finding #4)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="Pending fix: #4 No rate limiting on /sign-in — 6th attempt should return 429")
def test_signin_rate_limited_after_5_attempts(csrf_disabled_app_client):
    """
    After the fix: the 6th POST to /sign-in (regardless of credentials) within
    a short window must return HTTP 429 Too Many Requests.

    Today: all requests succeed (return 200 with invalid-credentials error),
    because flask-limiter is not installed or configured.
    """
    client = csrf_disabled_app_client
    data = {"email": "bruteforce@corp.com", "password": "wrong"}

    for attempt in range(5):
        resp = client.post("/sign-in", data=data)
        # Each of the first 5 should not be rate-limited
        assert resp.status_code != 429, (
            f"Attempt {attempt + 1} returned 429 too early — rate limit threshold may be wrong"
        )

    # The 6th attempt should be rate-limited
    resp6 = client.post("/sign-in", data=data)
    assert resp6.status_code == 429, (
        f"Expected 429 on 6th sign-in attempt, got {resp6.status_code}"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: #4 No rate limiting on /sign-up — 4th attempt should return 429")
def test_signup_rate_limited_after_3_attempts(csrf_disabled_app_client):
    """
    After the fix: the 4th POST to /sign-up within a short window must return
    HTTP 429 Too Many Requests.

    Today: all requests proceed normally; no rate limit exists.
    """
    client = csrf_disabled_app_client

    for attempt in range(3):
        # Use unique email each time to avoid the "already exists" short-circuit
        data = {
            "email": f"attacker{attempt}@evil.com",
            "name": "Spammer",
            "company": "SpamCorp",
            "password": "password123",
        }
        resp = client.post("/sign-up", data=data)
        assert resp.status_code != 429, (
            f"Attempt {attempt + 1} returned 429 too early"
        )

    # 4th attempt should be rate-limited
    data4 = {
        "email": "attacker3@evil.com",
        "name": "Spammer",
        "company": "SpamCorp",
        "password": "password123",
    }
    resp4 = client.post("/sign-up", data=data4)
    assert resp4.status_code == 429, (
        f"Expected 429 on 4th sign-up attempt, got {resp4.status_code}"
    )


# ===========================================================================
# Section 5: Secure cookie flags
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="Pending fix: session cookie must have the Secure flag set to prevent transmission over plain HTTP")
def test_session_cookie_has_secure_flag(csrf_disabled_app_client):
    """
    After the fix: the session cookie set after a successful sign-in must
    include the Secure attribute.

    Today: Flask does not set Secure by default on test clients (and the app
    doesn't configure SESSION_COOKIE_SECURE=True).
    """
    client = csrf_disabled_app_client

    # Create user and sign in
    client.post("/sign-up", data={
        "email": "cookietest@corp.com",
        "name": "Cookie Tester",
        "company": "TestCorp",
        "password": "password123",
    })
    client.get("/sign-out")

    resp = client.post("/sign-in", data={
        "email": "cookietest@corp.com",
        "password": "password123",
    })

    set_cookie_headers = resp.headers.getlist("Set-Cookie")
    assert set_cookie_headers, "No Set-Cookie header found in sign-in response"

    # At least one cookie header must contain the Secure attribute
    secure_present = any("Secure" in h for h in set_cookie_headers)
    assert secure_present, (
        f"Session cookie does not have the Secure flag. "
        f"Set-Cookie headers: {set_cookie_headers}"
    )


@pytest.mark.xfail(strict=True, reason="Pending fix: session cookie must have a SameSite attribute (Strict or Lax) to mitigate CSRF — Flask does not set this by default without SESSION_COOKIE_SAMESITE configured")
def test_session_cookie_has_samesite_strict_or_lax(csrf_disabled_app_client):
    """
    After the fix: the session cookie must include SameSite=Strict or
    SameSite=Lax to provide an additional layer of CSRF mitigation.

    Confirmed on 2026-05-18: Flask does not set SameSite by default.
    SESSION_COOKIE_SAMESITE must be set to 'Lax' or 'Strict' in the app config.
    """
    client = csrf_disabled_app_client

    client.post("/sign-up", data={
        "email": "samesitetest@corp.com",
        "name": "SameSite Tester",
        "company": "TestCorp",
        "password": "password123",
    })
    client.get("/sign-out")

    resp = client.post("/sign-in", data={
        "email": "samesitetest@corp.com",
        "password": "password123",
    })

    set_cookie_headers = resp.headers.getlist("Set-Cookie")
    assert set_cookie_headers, "No Set-Cookie header found in sign-in response"

    samesite_present = any("SameSite" in h for h in set_cookie_headers)
    assert samesite_present, (
        f"Session cookie does not have a SameSite attribute. "
        f"Set-Cookie headers: {set_cookie_headers}"
    )


# ===========================================================================
# Section 6: AuditLog sign parameter cleanup (finding #5)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="Pending fix: #5 AuditLog(sign=True) accepted but silently ignored — after fix: either parameter is removed (TypeError) OR entries have a 'signature' field")
def test_audit_log_sign_parameter_either_works_or_removed(tmp_audit_dir):
    """
    After the fix, exactly ONE of these must be true:

    Option A — parameter removed:
        AuditLog(log_dir=..., sign=True) raises TypeError because 'sign' no
        longer exists. This is the honest option per SECURITY_REVIEW finding #5.

    Option B — signing implemented:
        AuditLog(log_dir=..., sign=True) is accepted AND each written entry
        contains a 'signature' field with a non-empty value.

    Today: sign=True is silently accepted and entries have no 'signature' field
    — neither option A nor option B is true. The parameter is a lie.
    """
    from grcx.audit.log import AuditLog

    try:
        log = AuditLog(log_dir=str(tmp_audit_dir), sign=True)
    except TypeError:
        # Option A: parameter has been removed. Fix is in place.
        return

    # If we reach here, sign=True was accepted.
    # Option B: verify that the entry actually has a 'signature' field.
    entry = log.write("test.signing", "testing sign=True behaviour")

    assert "signature" in entry and entry["signature"], (
        "sign=True was accepted but the written entry has no 'signature' field. "
        "Either remove the 'sign' parameter (Option A) or implement Ed25519 signing "
        "so that sign=True produces real signatures (Option B). "
        "Today neither is true — the parameter is accepted and silently ignored."
    )


# ===========================================================================
# Section 7: Process-safety lock (finding #2 in TEST_REPORT, security-relevant)
# ===========================================================================

@pytest.mark.xfail(strict=True, reason="Pending fix: two AuditLog instances on the same directory break the hash chain — writes must be serialised or the second writer must be blocked")
def test_second_audit_log_writer_blocked_or_serialised(tmp_audit_dir):
    """
    After the fix, exactly ONE of these must be true when two AuditLog
    instances write to the same log directory:

    Option A — second writer blocked:
        The second AuditLog instance raises a "log is locked" (or similar)
        exception when write() is called, because the first instance holds
        an exclusive file lock.

    Option B — writes are serialised:
        Both writers succeed but the resulting log chain is valid (i.e.,
        AuditLog.verify() returns True with no errors), because an advisory
        lock or other serialisation mechanism ensures entries are appended
        in a consistent order.

    Today: both instances are created and write freely. The hash chain breaks
    because each instance initialises _last_hash from the on-disk state at
    construction time and then races to append entries — the second writer's
    prev_hash points to the wrong predecessor.
    """
    from grcx.audit.log import AuditLog

    log1 = AuditLog(log_dir=str(tmp_audit_dir))
    log2 = AuditLog(log_dir=str(tmp_audit_dir))

    second_writer_raised = False
    try:
        log1.write("event.first", "written by log1")
        log2.write("event.second", "written by log2")  # may raise if locked
        log1.write("event.third", "written by log1 again")
    except Exception as exc:
        # Option A: second writer was blocked with a locking exception
        exc_type_name = type(exc).__name__.lower()
        assert any(k in exc_type_name or k in str(exc).lower()
                   for k in ("lock", "block", "exclusive", "concurrent", "serial")), (
            f"A second AuditLog writer raised an unexpected exception "
            f"({type(exc).__name__}: {exc}). "
            "If blocking the second writer, raise a clear 'LogLocked' or similar exception."
        )
        second_writer_raised = True

    if not second_writer_raised:
        # Option B: both writers completed — verify the chain is still intact
        is_valid, errors = log1.verify()
        assert is_valid, (
            "Two concurrent AuditLog writers produced an invalid hash chain. "
            f"Errors: {errors}. "
            "Either implement file locking to serialise writes (Option B) or "
            "raise an exception when a second writer opens the same log (Option A)."
        )
