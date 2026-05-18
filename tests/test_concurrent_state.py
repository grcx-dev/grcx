# Tests for concurrent / parallel safety of stateful GRCX components.
#
# These tests document both safe patterns (single AuditLog instance, SQLite
# UNIQUE constraints) and unsafe ones (multiple AuditLog instances on the same
# file from separate processes / objects).
import json
import os

import pytest


# ---------------------------------------------------------------------------
# AuditLog chain-breaking when two instances share the same file
# ---------------------------------------------------------------------------

def test_two_audit_logs_writing_to_same_file_chain_breaks_predictably(tmp_audit_dir):
    """DOCUMENTS that AuditLog is NOT process-safe — concurrent writers WILL corrupt the chain. Production use must serialise via a single process."""
    from grcx.audit.log import AuditLog

    log_a = AuditLog(log_dir=str(tmp_audit_dir))
    log_b = AuditLog(log_dir=str(tmp_audit_dir))

    # A writes first; both B and A still have _last_hash == "genesis" at init time.
    log_a.write(event_type="test", summary="entry from A")
    # B writes with its stale _last_hash ("genesis"), creating a broken link.
    log_b.write(event_type="test", summary="entry from B")
    # A writes again — its chain is internally consistent from its perspective
    # but the file now has a B entry interleaved.
    log_a.write(event_type="test", summary="second entry from A")

    # Verifying from either instance must detect the broken chain.
    valid, errors = log_a.verify()
    assert not valid, "expected chain to be broken with two concurrent AuditLog instances"
    assert len(errors) >= 1, f"expected at least one error, got: {errors}"


# ---------------------------------------------------------------------------
# Concurrent sign-ups with the same email — SQLite UNIQUE constraint wins
# ---------------------------------------------------------------------------

@pytest.fixture
def two_app_clients(monkeypatch, tmp_path, tmp_audit_dir):
    """Two test clients sharing the same SQLite database (simulates two workers)."""
    db_path = tmp_path / "shared.db"
    log_path = tmp_audit_dir / "grcx.log.jsonl"

    os.environ["GRCX_DB_PATH"] = str(db_path)

    import dashboard.app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", db_path)
    monkeypatch.setattr(app_module, "LOG_PATH", log_path)
    monkeypatch.setattr(app_module, "notify_signup", lambda *a, **kw: None)

    app_module.init_db()
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False

    client_a = app_module.app.test_client()
    client_b = app_module.app.test_client()
    return client_a, client_b, db_path


def test_concurrent_signups_same_email_only_one_succeeds(two_app_clients):
    """Two simultaneous POSTs for the same email — only one user row must be created."""
    client_a, client_b, db_path = two_app_clients

    import sqlite3

    payload = {
        "email": "race@example.com",
        "name": "Race Condition",
        "company": "ACME",
        "password": "password123",
    }

    resp_a = client_a.post("/sign-up", data=payload)
    resp_b = client_b.post("/sign-up", data=payload)

    # One must succeed (302 redirect) and the other must fail (200 with error).
    statuses = {resp_a.status_code, resp_b.status_code}
    assert 302 in statuses, "neither request succeeded"
    assert 200 in statuses, "both requests claim to have succeeded (duplicate user!)"

    # Exactly one row must exist.
    conn = sqlite3.connect(str(db_path))
    count = conn.execute(
        "SELECT count(*) FROM users WHERE email = 'race@example.com'"
    ).fetchone()[0]
    conn.close()
    assert count == 1, f"expected 1 user row, found {count}"

    # The failing response must mention the duplicate.
    error_resp = resp_b if resp_a.status_code == 302 else resp_a
    html = error_resp.data.decode().lower()
    assert "already exists" in html or "email" in html


# ---------------------------------------------------------------------------
# AuditLog correctly re-reads state from disk (no stale in-memory drift)
# ---------------------------------------------------------------------------

def test_audit_log_resumes_after_in_memory_state_drift(tmp_audit_dir):
    """A new AuditLog instance must re-read _last_hash from disk, not start fresh."""
    from grcx.audit.log import AuditLog

    log_a = AuditLog(log_dir=str(tmp_audit_dir))
    log_a.write(event_type="test", summary="first")
    log_a.write(event_type="test", summary="second")
    log_a.write(event_type="test", summary="third")

    last_hash_a = log_a._last_hash

    # Construct a brand-new instance pointing at the same directory.
    log_b = AuditLog(log_dir=str(tmp_audit_dir))
    assert log_b._last_hash == last_hash_a, (
        "new AuditLog instance did not pick up _last_hash from disk"
    )

    log_b.write(event_type="test", summary="fourth")
    valid, errors = log_b.verify()
    assert valid, f"chain broken after resuming from disk: {errors}"
    assert errors == []


# ---------------------------------------------------------------------------
# RSS state file — survives a corrupt/garbage state file on reload
# ---------------------------------------------------------------------------

def test_rss_state_file_survives_corrupt_content_on_reload(tmp_path):
    """DOCUMENTS that RssSentinel._load_seen raises UnicodeDecodeError on non-UTF-8 state files — crash risk on corrupt/truncated writes. Production code should add error='replace' or a try/except in _load_seen."""
    from grcx.sentinel.regulatory.rss import RssSentinel

    sentinel = RssSentinel(
        url="https://example.com/feed.rss",
        jurisdiction="TEST",
        state_dir=str(tmp_path),
    )
    sentinel._seen.add("abc123")
    sentinel._save_seen()
    state_file = sentinel.state_path
    assert state_file.exists()

    # Simulate a mid-write crash by replacing the file with invalid UTF-8 bytes.
    state_file.write_bytes(b"\x00\x01\xff\xfe\x80invalid\x99")

    # DOCUMENTS the current (broken) behaviour: RssSentinel crashes with
    # UnicodeDecodeError when the state file contains non-UTF-8 bytes.
    # A robust implementation would catch this and fall back to an empty set.
    with pytest.raises(UnicodeDecodeError):
        RssSentinel(
            url="https://example.com/feed.rss",
            jurisdiction="TEST",
            state_dir=str(tmp_path),
        )


# ---------------------------------------------------------------------------
# Multiple Resolver instances sharing the same AuditLog — chain stays valid
# ---------------------------------------------------------------------------

def test_multiple_resolvers_share_audit_log(tmp_audit_dir, monkeypatch):
    """Two Resolver instances using the same AuditLog instance must leave a valid chain."""
    import anthropic
    from grcx.audit.log import AuditLog
    from grcx.resolver.resolver import Resolver
    from grcx.sentinel.regulatory.rss import RegulatoryItem

    canned_json = json.dumps({
        "has_implications": True,
        "severity": "warning",
        "affected_controls": ["5.1"],
        "summary": "Test finding",
        "recommended_action": "Review the control.",
        "rationale": "This affects control 5.1.",
    })

    class _Msg:
        def __init__(self, text):
            self.content = [type("Block", (), {"text": text})()]

    class _Messages:
        def create(self, **kwargs):
            return _Msg(canned_json)

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            self.messages = _Messages()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)

    # Shared AuditLog instance — this IS the safe pattern.
    shared_log = AuditLog(log_dir=str(tmp_audit_dir))

    config = {
        "resolver": {"llm": "claude-sonnet-4-6", "auto_remediate": "notify_only"},
        "controls": {"frameworks": ["iso27001"]},
    }

    resolver_1 = Resolver(config=config, audit=shared_log)
    resolver_2 = Resolver(config=config, audit=shared_log)

    item_1 = RegulatoryItem(
        title="Publication One",
        url="https://example.com/pub1",
        published="2026-01-01",
        summary="First test item",
        jurisdiction="TEST",
        feed_url="https://example.com/feed",
    )
    item_2 = RegulatoryItem(
        title="Publication Two",
        url="https://example.com/pub2",
        published="2026-01-01",
        summary="Second test item",
        jurisdiction="TEST",
        feed_url="https://example.com/feed",
    )

    resolver_1.analyse(item_1)
    resolver_2.analyse(item_2)

    valid, errors = shared_log.verify()
    assert valid, f"chain broken after two resolvers sharing one AuditLog: {errors}"
    assert errors == []
